"""Offline execution boundary v1: accept an approved read-only investigation.

No CLI pipeline, network requests, commands, file writes, or task reruns exist
here. COMPLETED means the metadata-only investigation was accepted, not that
the failure was repaired or that the proposed_action text was carried out.
"""

from datetime import datetime, timezone

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
