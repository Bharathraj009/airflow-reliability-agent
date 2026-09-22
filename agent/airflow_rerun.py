"""One controlled new demo run, followed by bounded REST evidence collection.

No retries of the POST: an ambiguous network failure must not create duplicates.
Current approval metadata must come from the live pipeline, never memory.
"""

from datetime import datetime, timedelta, timezone
import json
import math
import time
from urllib.parse import quote

from agent.approval_gate import validate_record
from agent.failure_detector import request_json
from agent.policy_engine import evaluate_policy
from agent.remediation_playbooks import (
    PLAYBOOK, CONTROL_RELATIVE, identify_playbook, build_playbook_proposal, _control_path,
)
from agent.post_action_validator import assess_airflow_health


def rerun_and_verify(context, attempt, *, token, current_approval_id, verification_run_id,
                     now, timeout=120, poll_interval=2, monotonic=time.monotonic, sleep=time.sleep):
    evidence = dict(original_dag_run_id=context.get("dag_run_id"),
                    verification_dag_run_id=verification_run_id, dag_id="reliability_demo",
                    trigger_status="NOT_TRIGGERED", dag_run_state=None, task_states={},
                    repair_verified=False, verification_status="INCONCLUSIVE",
                    reason="Current remediation authorization could not be verified.")
    try:
        if (not token or identify_playbook(context) != PLAYBOOK
                or not isinstance(verification_run_id, str) or not verification_run_id.startswith("manual__reliability_")
                or verification_run_id == context["dag_run_id"] or not context["dag_run_id"]):
            return evidence
        approval = validate_record(attempt["approval"])
        proposal = build_playbook_proposal(context)
        policy = evaluate_policy(proposal)
        if (attempt["playbook"] != PLAYBOOK or attempt["proposal"] != proposal
                or attempt["policy"] != policy or attempt["repair_verified"] is not False
                or attempt["error"] is not None or approval["status"] != "APPROVED"
                or not current_approval_id or approval["approval_id"] != current_approval_id
                or any(approval[key] != context[key] for key in ("dag_id", "dag_run_id", "task_id"))
                or approval["proposed_action"] != proposal["proposed_action"]
                or approval["action_type"] != proposal["action_type"]
                or approval["calculated_risk"] != policy["calculated_risk"]
                or approval["policy_decision"] != "require_approval"
                or policy["decision"] != "require_approval" or PLAYBOOK not in policy["allowed_actions"]):
            return evidence
        if now.utcoffset() is None or not timedelta(0) <= now - datetime.fromisoformat(approval["decision_timestamp"]) <= timedelta(minutes=15):
            return evidence
        result = attempt["execution"]
        expected_change = {"target": CONTROL_RELATIVE, "before": {"simulate_failure": True}, "after": {"simulate_failure": False}}
        if (result["status"] != "COMPLETED" or result["playbook"] != PLAYBOOK
                or result["dag_id"] != context["dag_id"] or result["task_id"] != context["task_id"]
                or result["changes"] != [expected_change]):
            return evidence
        control = json.loads(_control_path().read_text(encoding="utf-8"))
        if set(control) != {"simulate_failure"} or control["simulate_failure"] is not False:
            return evidence
        if any(type(value) not in (int, float) or not math.isfinite(value) or value <= 0 for value in (timeout, poll_interval)):
            return evidence
    except (RuntimeError, ValueError, KeyError, TypeError, AttributeError, OSError):
        return evidence

    deadline = monotonic() + timeout
    def call(path, payload=None):
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise TimeoutError
        return request_json(path, token=token, payload=payload, timeout=min(15, remaining))

    base = "/api/v2/dags/reliability_demo/dagRuns"
    run_path = base + "/" + quote(verification_run_id, safe="")
    def check_run(run):
        if run["dag_id"] != "reliability_demo" or run["dag_run_id"] != verification_run_id:
            raise ValueError("Wrong verification run returned.")

    try:
        evidence["trigger_status"] = "UNKNOWN"  # POST may succeed before a network error.
        created = call(base, {"dag_run_id": verification_run_id, "logical_date": None, "conf": {}})
        check_run(created)
        evidence["trigger_status"] = "CREATED"
        # Explicit iteration bound also protects tests with a stationary fake clock.
        for _ in range(math.ceil(timeout / poll_interval) + 1):
            run = call(run_path)
            check_run(run)
            evidence["dag_run_state"] = run["state"]
            if run["state"] in ("success", "failed"):
                break
            if run["state"] not in ("queued", "running"):
                raise ValueError("Unexpected run state.")
            sleep(min(poll_interval, max(0, deadline - monotonic())))
        else:
            raise TimeoutError
        # Read all task pages within the same deadline; reject duplicate/mapped
        # instances rather than letting a success overwrite contradictory data.
        offset = 0
        for _ in range(100):
            page = call(f"{run_path}/taskInstances?limit=100&offset={offset}")
            tasks = page["task_instances"]
            if not isinstance(tasks, list) or type(page["total_entries"]) is not int:
                raise ValueError
            for task in tasks:
                if (task["dag_id"] != "reliability_demo" or task["dag_run_id"] != verification_run_id
                        or task["map_index"] != -1 or task["task_id"] in evidence["task_states"]):
                    raise ValueError
                evidence["task_states"][task["task_id"]] = task["state"]
            offset += len(tasks)
            if offset == page["total_entries"]:
                break
            if not tasks or offset > page["total_entries"]:
                raise ValueError
        else:
            raise ValueError
        evidence.update(assess_airflow_health(evidence))
    except TimeoutError:
        evidence.update(verification_status="TIMEOUT", reason="Verification deadline expired; health not established.")
    except Exception:
        evidence.update(verification_status="INCONCLUSIVE", reason="Airflow API evidence was unavailable or inconsistent; no trigger retry attempted.")
    return evidence
