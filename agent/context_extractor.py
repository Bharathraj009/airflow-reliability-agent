"""Reduce collected Airflow logs to failure evidence, without AI analysis.

Run: python -m agent.context_extractor --task-id process_data
Uses the same shell credentials as the detector and collector.
"""

import argparse
import json
import os
from pathlib import Path
import re
import sys

from agent.failure_detector import request_json
from agent.log_collector import collect_failed_task_logs


def safe_text(value, secrets=()):
    """Keep short scalar evidence; redact known credentials and common formats.

    This is defense in depth, not a universal secret detector. Task code must
    still avoid writing sensitive data to logs in the first place.
    """
    if not isinstance(value, str):
        return None
    # Include configured secrets without exposing or copying environment values
    # into the result. The live CLI also supplies its temporary JWT explicitly.
    known = list(secrets) + [
        value for name, value in os.environ.items()
        if any(word in name.upper() for word in ("PASSWORD", "SECRET", "TOKEN", "API_KEY", "FERNET_KEY"))
    ]
    for secret in sorted(filter(None, known), key=len, reverse=True):
        value = value.replace(secret, "[REDACTED]")
    value = re.sub(r"\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[REDACTED]", value)
    value = re.sub(r"(?i)\bBearer\s+\S+", "Bearer [REDACTED]", value)
    value = re.sub(r"(://)[^\s/@]+:[^\s/@]+@", r"\1[REDACTED]@", value)
    value = re.sub(
        r'''(?i)(\b(?:password|passwd|secret|token|api[_-]?key|authorization)\b["']?\s*[:=]\s*)("[^"\n]*"|'[^'\n]*'|[^\s,;]+)''',
        r"\1[REDACTED]", value,
    )
    # No multi-line traceback or unbounded exception payload in the context.
    return value.splitlines()[0][:1000] if value else value


def is_project_frame(frame):
    """Recognize our mounted code and workspace, not Airflow installation files."""
    filename = frame.get("filename")
    if not isinstance(filename, str):
        return False
    path = filename.replace("\\", "/").lower()
    if "/site-packages/" in path or "/dist-packages/" in path:
        return False
    workspace = Path(__file__).resolve().parent.parent.as_posix().lower() + "/"
    return path.startswith((
        "/opt/airflow/dags/", "/opt/airflow/plugins/", workspace,
        "dags/", "plugins/", "agent/",
    ))


def exception_details(details):
    """Handle a normal exception chain and nested exception-group entries."""
    if isinstance(details, dict):
        details = [details]
    if not isinstance(details, list):
        return
    for detail in details:
        if isinstance(detail, dict):
            yield detail
            yield from exception_details(detail.get("exceptions"))


def extract_failure_context(task_log, *, secrets=()):
    """Accept one collect_task_logs() result and return a small evidence object."""
    context = {
        key: safe_text(task_log.get(key), secrets)
        for key in ("dag_id", "dag_run_id", "task_id")
    }
    attempt = task_log.get("try_number")
    context["try_number"] = attempt if type(attempt) is int else None
    context.update(dict.fromkeys((
        "exception_type", "exception_message", "source_file", "source_line",
        "failed_function", "error_timestamp",
    )))

    best = None
    best_score = (-1, -1)
    log_text = task_log.get("log_text")
    if not isinstance(log_text, str):
        return context
    # The collector preserves Airflow's structured entries as JSON lines.
    # Plain text, malformed JSON, and normal entries without error_detail are
    # safely skipped. We do not guess exception values using message regexes.
    for line in log_text.splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if not isinstance(entry, dict):
            continue
        for detail in exception_details(entry.get("error_detail")):
            if not (detail.get("exc_type") or detail.get("exc_value")):
                continue
            frames = detail.get("frames")
            frames = [frame for frame in frames if isinstance(frame, dict)] if isinstance(frames, list) else []
            project_frames = [frame for frame in frames if is_project_frame(frame)]
            # Python frames run from outermost to innermost. Choose the last
            # project frame; fall back to the innermost available framework frame.
            frame = (project_frames or frames or [{}])[-1]
            score = (bool(project_frames), entry.get("event") == "Task failed with exception")
            # Prefer evidence from our code and the task-failure event. For tied
            # entries keep the latest log entry, but preserve chain order within it.
            if score > best_score or (score == best_score and best[0] is not entry):
                best = (entry, detail, frame)
                best_score = score

    if best:
        entry, detail, frame = best
        context.update({
            "exception_type": safe_text(detail.get("exc_type"), secrets),
            "exception_message": safe_text(detail.get("exc_value"), secrets),
            "source_file": safe_text(frame.get("filename"), secrets),
            "source_line": frame.get("lineno") if type(frame.get("lineno")) is int else None,
            "failed_function": safe_text(frame.get("name"), secrets),
            "error_timestamp": safe_text(entry.get("timestamp"), secrets),
        })
    return context


def extract_failure_contexts(collected, *, secrets=()):
    """Accept the collector CLI's full result, or a single collected task."""
    tasks = collected.get("task_logs", [collected])
    return [extract_failure_context(task, secrets=secrets) for task in tasks]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task-id", help="Only inspect this failed task, e.g. process_data.")
    args = parser.parse_args()
    username = os.environ.get("AIRFLOW_API_USERNAME")
    password = os.environ.get("AIRFLOW_API_PASSWORD")
    if not username or not password:
        print("Set AIRFLOW_API_USERNAME and AIRFLOW_API_PASSWORD in your shell.", file=sys.stderr)
        return 1
    try:
        auth = request_json("/auth/token", payload={"username": username, "password": password})
        token = auth.get("access_token")
        if not token:
            raise RuntimeError("Authentication response did not include an access token.")
        # The collector calls the detector and requests only actual FAILED logs.
        # Nothing is written back to Airflow, and raw logs are not printed here.
        collected = collect_failed_task_logs(token, args.task_id)
        contexts = extract_failure_contexts(collected, secrets=(token, password))
        print(json.dumps(contexts, indent=2))
        return 0
    except (RuntimeError, ValueError) as exc:
        print(f"Context extractor: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
