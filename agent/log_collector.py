"""Collect logs for actual failed tasks using the Airflow 3.1.7 public API.

From the project root: python -m agent.log_collector --task-id process_data
Uses the same AIRFLOW_API_USERNAME / AIRFLOW_API_PASSWORD environment variables
as failure_detector. No dependencies or local Airflow installation are needed.
"""

import argparse
import json
import os
import sys
from urllib.parse import quote, urlencode

from agent.failure_detector import inspect_failures, request_json


def collect_task_logs(dag_id, dag_run_id, task_id, try_number, *, token, map_index=-1):
    """Fetch one failed task attempt; the caller selects actual FAILED tasks.

    map_index is -1 for our demo. It also lets us address individual mapped
    task instances later. The authentication token is never part of the result.
    """
    if not isinstance(try_number, int) or try_number < 1:
        raise ValueError("try_number must be a positive integer for a task attempt.")

    # Encode each identifier separately: run IDs often contain '+' and ':'.
    path = (
        f"/api/v2/dags/{quote(dag_id, safe='')}/dagRuns/"
        f"{quote(dag_run_id, safe='')}/taskInstances/"
        f"{quote(task_id, safe='')}/logs/{try_number}"
    )
    params = {"map_index": map_index, "full_content": "true"}
    lines = []
    seen_tokens = set()
    # A bound prevents an unexpectedly non-terminating log stream from hanging
    # this small, one-shot collector. Never silently return a truncated result.
    for _ in range(1000):
        page = request_json(f"{path}?{urlencode(params)}", token=token)
        content = page.get("content")
        if not isinstance(content, list):
            raise RuntimeError("Unexpected Airflow log response: content must be a list.")
        for entry in content:
            # Airflow 3 returns structured log entries. Keep the entire entry,
            # including exception fields, rather than extracting only a message.
            lines.append(entry if isinstance(entry, str) else json.dumps(entry, ensure_ascii=False))

        continuation = page.get("continuation_token")
        if not continuation:
            break
        if continuation in seen_tokens:
            raise RuntimeError("Airflow repeated a log continuation token; collection stopped.")
        seen_tokens.add(continuation)
        # This is a log pagination token, separate from the JWT auth token.
        params["token"] = continuation
    else:
        raise RuntimeError("Log pagination exceeded 1000 pages; collection is incomplete.")

    log_text = "\n".join(lines)
    # Never echo our authentication material even if it appears in task output.
    # This is not a general secret scanner; task code must also avoid logging secrets.
    for secret in (token, os.environ.get("AIRFLOW_API_PASSWORD")):
        if secret:
            log_text = log_text.replace(secret, "[REDACTED]")
            log_text = log_text.replace(json.dumps(secret)[1:-1], "[REDACTED]")
    return {
        "dag_id": dag_id,
        "dag_run_id": dag_run_id,
        "task_id": task_id,
        "try_number": try_number,
        "map_index": map_index,
        "log_text": log_text,
    }


def collect_failed_task_logs(token, task_id=None):
    """Use the detector's report; never request logs for upstream failures."""
    report = inspect_failures(token)
    logs = []
    for run in report["runs"]:
        for task in run["failed_tasks"]:
            # Check the exact state as well, so blocked tasks cannot slip in.
            if task["state"] != "failed":
                continue
            if task_id is not None and task["task_id"] != task_id:
                continue
            logs.append(collect_task_logs(
                task["dag_id"], task["dag_run_id"], task["task_id"],
                task["try_number"], token=token, map_index=task["map_index"],
            ))
    return {
        "dag_id": report["dag_id"],
        "failed_runs_inspected": report["failed_runs_inspected"],
        "logs_collected": len(logs),
        "task_logs": logs,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task-id", help="Only collect this task's failed attempts.")
    args = parser.parse_args()
    username = os.environ.get("AIRFLOW_API_USERNAME")
    password = os.environ.get("AIRFLOW_API_PASSWORD")
    if not username or not password:
        print("Set AIRFLOW_API_USERNAME and AIRFLOW_API_PASSWORD in your shell.", file=sys.stderr)
        return 1
    try:
        # Reuse the detector's HTTP helper and the existing FAB JWT login flow.
        auth = request_json("/auth/token", payload={"username": username, "password": password})
        token = auth.get("access_token")
        if not token:
            raise RuntimeError("Authentication response did not include an access token.")
        print(json.dumps(collect_failed_task_logs(token, args.task_id), indent=2))
        return 0
    except (RuntimeError, ValueError) as exc:
        print(f"Log collector: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
