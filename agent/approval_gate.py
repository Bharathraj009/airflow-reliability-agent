"""Human authorization metadata only; this module never executes remediation.

Run: python -m agent.approval_gate --task-id process_data
The CLI reuses the existing AI pipeline, but the gate functions are offline.
Records are printed, not persisted or treated as tamper-proof execution grants.
"""

import argparse
from datetime import datetime, timezone
import getpass
import json
import sys
from uuid import uuid4

from agent.policy_engine import ACTION_POLICY, evaluate_policy


RECORD_FIELDS = {
    "approval_id", "status", "dag_id", "dag_run_id", "task_id", "action_type",
    "calculated_risk", "proposed_action", "policy_decision", "approved_by",
    "decision_timestamp",
}


def validate_record(record):
    """Reject malformed state rather than accidentally authorizing it."""
    if not isinstance(record, dict) or set(record) != RECORD_FIELDS:
        raise RuntimeError("Invalid approval record fields.")
    for key in RECORD_FIELDS - {"approved_by", "decision_timestamp"}:
        if not isinstance(record[key], str) or not record[key].strip():
            raise RuntimeError("Approval record requires nonempty text fields.")
    if (record["policy_decision"] not in ("allow", "require_approval", "block")
            or record["calculated_risk"] not in ("low", "medium", "high")
            or record["action_type"] not in ACTION_POLICY
            or record["status"] not in ("PENDING_APPROVAL", "APPROVED", "REJECTED", "BLOCKED")):
        raise RuntimeError("Invalid approval record state or classification.")
    if (record["policy_decision"] == "block") != (record["status"] == "BLOCKED"):
        raise RuntimeError("Blocked policy decisions must remain BLOCKED.")
    if record["status"] in ("PENDING_APPROVAL", "BLOCKED"):
        if record["approved_by"] is not None or record["decision_timestamp"] is not None:
            raise RuntimeError("Undecided/blocked records cannot contain a human decision.")
    else:
        if not isinstance(record["approved_by"], str) or not record["approved_by"].strip():
            raise RuntimeError("A human decision requires a local reviewer label.")
        try:
            timestamp = datetime.fromisoformat(record["decision_timestamp"])
            if timestamp.utcoffset() != timezone.utc.utcoffset(timestamp):
                raise ValueError
        except (ValueError, TypeError):
            raise RuntimeError("A human decision requires a UTC ISO 8601 timestamp.") from None
    return record


def create_approval_record(context, proposal, policy, *, approval_id):
    """Create a pending/blocked record; caller supplies an ID for determinism.

    Recompute policy locally to ensure the supplied decision matches this exact
    proposal. This does not contact Airflow, Groq, or any execution service.
    """
    if policy != evaluate_policy(proposal):
        raise RuntimeError("Policy result does not match the remediation proposal.")
    if not isinstance(context, dict):
        raise RuntimeError("Expected failure context identifiers.")
    record = {
        "approval_id": approval_id,
        "status": "BLOCKED" if policy["decision"] == "block" else "PENDING_APPROVAL",
        "dag_id": context.get("dag_id"),
        "dag_run_id": context.get("dag_run_id"),
        "task_id": context.get("task_id"),
        "action_type": proposal["action_type"],
        "calculated_risk": policy["calculated_risk"],
        "proposed_action": proposal["proposed_action"],
        "policy_decision": policy["decision"],
        "approved_by": None,
        "decision_timestamp": None,
    }
    return validate_record(record)


def apply_human_decision(record, decision, *, reviewer, decided_at):
    """Apply an explicitly supplied human command to a copy of a pending record.

    Only the caller's trusted human-input interface should invoke this function.
    Passing model output here would violate the approval boundary. Reviewer and
    time are explicit inputs so the state transition is deterministic and testable.
    """
    validate_record(record)
    if record["status"] != "PENDING_APPROVAL" or decision not in ("approve", "reject"):
        return dict(record)  # No defaults, normalization, or implicit approval.
    if not isinstance(reviewer, str) or not reviewer.strip():
        raise RuntimeError("A local reviewer label is required.")
    if not isinstance(decided_at, datetime) or decided_at.utcoffset() is None:
        raise RuntimeError("An explicit timezone-aware decision time is required.")
    result = dict(record)
    result.update(
        status="APPROVED" if decision == "approve" else "REJECTED",
        approved_by=reviewer,
        decision_timestamp=decided_at.astimezone(timezone.utc).isoformat(),
    )
    return validate_record(result)


def prompt_for_approval(record):
    """CLI boundary: read one exact human command, never model-generated text."""
    validate_record(record)
    summary = {key: record[key] for key in (
        "dag_id", "dag_run_id", "task_id", "proposed_action", "action_type",
        "calculated_risk", "policy_decision",
    )}
    print("Approval Summary:")
    print(json.dumps(summary, indent=2))
    if record["status"] != "PENDING_APPROVAL":
        print(record["status"])
        return dict(record)  # In particular, BLOCKED never prompts.
    try:
        command = input("Type 'approve' to approve or 'reject' to reject: ")
    except (EOFError, KeyboardInterrupt):
        print("\nNo decision received. Status remains PENDING_APPROVAL.")
        return dict(record)
    if command not in ("approve", "reject"):
        print("Unsupported input. Status remains PENDING_APPROVAL.")
        return dict(record)
    # A local account name only; do not request email, credentials, or identity
    # documents. This is a development label, not authenticated identity proof.
    try:
        reviewer = getpass.getuser()
    except (OSError, KeyError):
        raise RuntimeError("Could not identify the local CLI user; approval remains pending.") from None
    return apply_human_decision(
        record, command, reviewer=reviewer, decided_at=datetime.now(timezone.utc),
    )


def main():
    # Existing network/model calls are confined to obtaining the proposal.
    import os
    from agent.context_extractor import extract_failure_contexts
    from agent.failure_detector import request_json
    from agent.log_collector import collect_failed_task_logs
    from agent.rca_analyzer import analyze_context, compact_context
    from agent.remediation_planner import propose_remediation

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task-id", help="Only review this failed task, e.g. process_data.")
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
            print("No matching failed tasks found; no approval requested.")
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
            record = create_approval_record(context, proposal, policy, approval_id=str(uuid4()))
            record = prompt_for_approval(record)
            print("Approval Record (metadata only; nothing executed):")
            print(json.dumps(record, indent=2))
            if record["status"] in ("BLOCKED", "PENDING_APPROVAL"):
                return 0  # Do not offer a different approval after a block/interrupt.
        return 0
    except RuntimeError as exc:
        print(f"Approval gate: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
