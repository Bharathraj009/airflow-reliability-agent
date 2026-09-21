"""Inspect failed runs with Airflow 3.1.7's public REST API.

Run from the project root: python -m agent.failure_detector
Set AIRFLOW_API_USERNAME and AIRFLOW_API_PASSWORD in your shell first.
This script reads environment variables; it does not automatically load .env.
Only Python's standard library is needed (no local Airflow installation).
"""

import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


BASE_URL = "http://localhost:8090"
DAG_ID = "reliability_demo"
RECENT_RUN_LIMIT = 10  # "Recent" means the latest 10 failed runs by start date.
TIMEOUT_SECONDS = 15


def request_json(path, token=None, payload=None):
    """Send a GET, or a POST when a JSON payload is supplied."""
    headers = {"Accept": "application/json"}
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode("utf-8")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = Request(BASE_URL + path, data=data, headers=headers)
    try:
        with urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return json.load(response)
    except HTTPError as exc:
        # Do not print request headers, credentials, or server response bodies.
        hints = {
            401: "Check your username/password; the token may also have expired.",
            403: "This user needs permission to read DAG runs and task instances.",
            404: "Check the API endpoint and that reliability_demo exists.",
        }
        hint = hints.get(exc.code, "Check the Airflow API server logs.")
        raise RuntimeError(f"Airflow returned HTTP {exc.code}. {hint}") from None
    except (URLError, TimeoutError, OSError):
        raise RuntimeError(
            f"Cannot reach Airflow at {BASE_URL}. Check Docker and port 8090."
        ) from None
    except ValueError:
        raise RuntimeError("Airflow returned an invalid JSON response.") from None


def get_items(path, collection_key, token, filters=None, max_items=None):
    """Follow offset/limit pages so task instances are not silently omitted."""
    items = []
    while max_items is None or len(items) < max_items:
        limit = 100 if max_items is None else min(100, max_items - len(items))
        params = dict(filters or {})
        params.update(limit=limit, offset=len(items))
        page = request_json(f"{path}?{urlencode(params)}", token=token)
        batch = page[collection_key]
        items.extend(batch)
        if not batch or len(items) >= page["total_entries"]:
            break
    return items


def inspect_failures(token):
    """Report task states without changing runs, retrying tasks, or reading logs."""
    runs_path = f"/api/v2/dags/{quote(DAG_ID, safe='')}/dagRuns"
    runs = get_items(
        runs_path,
        "dag_runs",
        token,
        filters={"state": "failed", "order_by": "-start_date"},
        max_items=RECENT_RUN_LIMIT,
    )
    report = {
        "dag_id": DAG_ID,
        "recent_failed_run_limit": RECENT_RUN_LIMIT,
        "failed_runs_inspected": len(runs),
        "runs": [],
    }
    for run in runs:
        run_id = run["dag_run_id"]
        # Run IDs contain timestamps and punctuation: encode them as URL paths.
        tasks = get_items(
            f"{runs_path}/{quote(run_id, safe='')}/taskInstances",
            "task_instances",
            token,
        )
        result = {
            "dag_run_id": run_id,
            "failed_tasks": [],
            "upstream_failed_tasks": [],
        }
        for task in tasks:
            state = task["state"]
            # FAILED is an actual task failure. UPSTREAM_FAILED means a task
            # was blocked by an upstream dependency; it is not the failing task.
            if state not in ("failed", "upstream_failed"):
                continue
            details = {
                "dag_id": DAG_ID,
                "dag_run_id": run_id,
                "task_id": task["task_id"],
                "state": state,
                "try_number": task["try_number"],
                "start_date": task["start_date"],
                "end_date": task["end_date"],
                "map_index": task["map_index"],
            }
            # Preserve null dates for tasks that never started. map_index is
            # usually -1 here, but identifies individual mapped tasks if added.
            result[f"{state}_tasks"].append(details)
        report["runs"].append(result)
    # An empty runs list is a valid result: no failed DAG runs were found.
    return report


def main():
    username = os.environ.get("AIRFLOW_API_USERNAME")
    password = os.environ.get("AIRFLOW_API_PASSWORD")
    if not username or not password:
        print(
            "Set AIRFLOW_API_USERNAME and AIRFLOW_API_PASSWORD in your shell.",
            file=sys.stderr,
        )
        return 1
    try:
        # FAB exchanges credentials for a JWT. Subsequent GET requests use
        # Bearer authentication, not HTTP Basic authentication. Never log it.
        auth = request_json(
            "/auth/token", payload={"username": username, "password": password}
        )
        token = auth.get("access_token")
        if not token:
            raise RuntimeError("Authentication response did not include an access token.")
        print(json.dumps(inspect_failures(token), indent=2))
        return 0
    except RuntimeError as exc:
        print(f"Failure detector: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
