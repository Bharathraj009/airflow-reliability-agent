"""Offline execution boundary v1: accept an approved read-only investigation.

The core is offline; the optional CLI obtains a proposal through the existing
pipeline and prompts through the approval gate. COMPLETED means acceptance, not that
the failure was repaired or that the proposed_action text was carried out.
"""

import argparse
from datetime import datetime, timezone
import json
import sys

from agent.approval_gate import validate_record
from agent.policy_engine import evaluate_policy


ALLOWED_OPERATION = "read_only_investigation"


def execute_approved_operation(
    approval, proposal, policy, context, *, operation=ALLOWED_OPERATION,
    execution_id, started_at, completed_at,
):
    """Return a structured result without mutating inputs or external systems.

    Supply an execution ID and timezone-aware datetimes explicitly. Identical
    inputs produce identical results, without clock, environment, or UUID reads.
    Approval is local authorization metadata, not a signature or replay guard.
    """
    def timestamp(value):
        if not isinstance(value, datetime) or value.utcoffset() is None:
            return None
        return value.astimezone(timezone.utc).isoformat()

    # Do not echo arbitrary operation/approval text in refusal messages.
    record = approval if isinstance(approval, dict) else {}
    result = {
        "execution_id": execution_id if isinstance(execution_id, str) else None,
        "approval_id": None,
        "operation": operation if operation == ALLOWED_OPERATION else None,
        "status": "REFUSED",
        "dag_id": None, "dag_run_id": None, "task_id": None,
        "started_at": timestamp(started_at),
        "completed_at": timestamp(completed_at),
        "result": {"message": "Execution refused.", "mutations_performed": False},
    }

    def refuse(message):
        result["result"]["message"] = message
        return result

    if (not isinstance(execution_id, str) or not execution_id.strip()
            or result["started_at"] is None or result["completed_at"] is None
            or completed_at < started_at):
        return refuse("A nonempty execution ID and ordered timezone-aware timestamps are required.")
    try:
        validate_record(approval)
    except (RuntimeError, TypeError, ValueError):
        return refuse("Malformed or inconsistent approval record.")
    for key in ("approval_id", "dag_id", "dag_run_id", "task_id"):
        result[key] = record[key]
    if record["status"] != "APPROVED":
        return refuse("Only an explicitly APPROVED record is eligible.")
    if operation != ALLOWED_OPERATION:
        return refuse("Requested operation is not allowlisted.")
    if record["action_type"] != "investigation":
        return refuse("Approved action does not map to read_only_investigation.")

    # Re-run only the deterministic policy function on the entire proposal.
    # proposed_action is compared/scanned as data; it is never interpreted.
    try:
        expected_policy = evaluate_policy(proposal)
    except (RuntimeError, TypeError, ValueError):
        return refuse("Invalid remediation proposal.")
    if not isinstance(policy, dict) or policy != expected_policy:
        return refuse("Policy result does not match the proposal.")
    if (policy["decision"] != "require_approval"
            or policy["calculated_risk"] != "low"
            or policy["requires_human_approval"] is not True
            or policy["blocked_actions"]
            or ALLOWED_OPERATION not in policy["allowed_actions"]):
        return refuse("Policy does not permit the allowlisted investigation.")
    if (record["action_type"] != proposal["action_type"]
            or record["proposed_action"] != proposal["proposed_action"]
            or record["policy_decision"] != policy["decision"]
            or record["calculated_risk"] != policy["calculated_risk"]):
        return refuse("Approval does not match the proposed action and policy.")
    if not isinstance(context, dict) or any(
        context.get(key) != record[key] for key in ("dag_id", "dag_run_id", "task_id")
    ):
        return refuse("Approval and failure context identify different incidents.")
    if datetime.fromisoformat(record["decision_timestamp"]) > started_at:
        return refuse("Approval must precede execution.")

    # The single fixed operation only checks existing metadata in memory.
    # There is no dispatch based on model text and no external effect to perform.
    result["status"] = "COMPLETED"
    result["result"]["message"] = (
        "Approved read-only investigation accepted; incident identifiers, approval, "
        "and policy were checked in memory. No proposed instructions were executed."
    )
    return result


def main():
    """Thin orchestration only; the core independently enforces its allowlist."""
    import os
    from uuid import uuid4
    from agent.approval_gate import create_approval_record, prompt_for_approval
    from agent.context_extractor import extract_failure_contexts
    from agent.failure_detector import request_json
    from agent.log_collector import collect_failed_task_logs
    from agent.rca_analyzer import analyze_context, compact_context
    from agent.remediation_planner import propose_remediation

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task-id", help="Only inspect this failed task, e.g. process_data.")
    args = parser.parse_args()
    try:
        if not os.environ.get("GROQ_API_KEY", "").strip():
            raise RuntimeError("Set GROQ_API_KEY for the existing AI pipeline.")
        username = os.environ.get("AIRFLOW_API_USERNAME")
        password = os.environ.get("AIRFLOW_API_PASSWORD")
        if not username or not password:
            raise RuntimeError("Set AIRFLOW_API_USERNAME and AIRFLOW_API_PASSWORD in your shell.")
        auth = request_json("/auth/token", payload={"username": username, "password": password})
        token = auth.get("access_token")
        if not token:
            raise RuntimeError("Airflow authentication response did not include an access token.")
        collected = collect_failed_task_logs(token, args.task_id)
        contexts = extract_failure_contexts(collected, secrets=(token, password))
        if not contexts:
            print("No matching failed tasks found; no approval or execution requested.")
        for context in contexts:
            context = compact_context(context)
            print("Failure Context:", flush=True)
            print(json.dumps(context, indent=2), flush=True)
            rca = analyze_context(context)
            print("AI RCA:", flush=True)
            print(json.dumps(rca, indent=2), flush=True)
            proposal = propose_remediation(context, rca)
            policy = evaluate_policy(proposal)
            print("Remediation Proposal:")
            print(json.dumps(proposal, indent=2))
            print("Policy Decision:")
            print(json.dumps(policy, indent=2))
            approval = create_approval_record(context, proposal, policy, approval_id=str(uuid4()))
            # The existing gate prints the summary and never prompts for BLOCKED.
            approval = prompt_for_approval(approval)
            # Non-approved records are passed only for the core's safe REFUSED
            # result. Proposed text never selects or defines an operation.
            started_at = datetime.now(timezone.utc)
            result = execute_approved_operation(
                approval, proposal, policy, context, operation=ALLOWED_OPERATION,
                execution_id=str(uuid4()), started_at=started_at,
                completed_at=datetime.now(timezone.utc),
            )
            print("Controlled Execution Result:")
            print(json.dumps(result, indent=2))
            if result["status"] != "COMPLETED":
                return 0  # Stop after refusal, rejection, or interrupted approval.
        return 0
    except RuntimeError as exc:
        print(f"Controlled executor: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
