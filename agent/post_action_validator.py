"""Offline evidence checks, not remediation or an Airflow health check.

Execution-only validation never produces VERIFIED_HEALTHY. The separate
assess_airflow_health function requires independent new-run REST observations.
NOT_REPAIRED means this read-only operation performed no repair,
not that we have queried the current live state of the incident.
"""

from datetime import datetime, timezone


EXECUTION_FIELDS = {
    "execution_id", "approval_id", "operation", "status", "dag_id",
    "dag_run_id", "task_id", "started_at", "completed_at", "result",
}
INCIDENT_FIELDS = ("dag_id", "dag_run_id", "task_id")
VALIDATION_STATUSES = (
    "VERIFIED_HEALTHY", "NOT_REPAIRED", "INCONCLUSIVE", "EXECUTION_FAILED",
)


def assess_airflow_health(evidence):
    """Derive health from NEW-run REST observations, never approval/AI claims."""
    outcome = dict(repair_verified=False, verification_status="INCONCLUSIVE",
                   reason="Independent new-run health evidence is incomplete.")
    if (evidence.get("dag_id") != "reliability_demo" or evidence.get("trigger_status") != "CREATED"
            or not isinstance(evidence.get("verification_dag_run_id"), str)
            or not evidence["verification_dag_run_id"] or not evidence.get("original_dag_run_id")
            or evidence["verification_dag_run_id"] == evidence["original_dag_run_id"]):
        return outcome
    tasks = evidence.get("task_states")
    if not isinstance(tasks, dict):
        return outcome
    if evidence.get("dag_run_state") == "failed" or any(state in ("failed", "upstream_failed") for state in tasks.values()):
        return dict(repair_verified=False, verification_status="VERIFICATION_FAILED", reason="The new DAG run or a task failed.")
    required = {"start", "process_data", "data_quality_check", "end"}
    if (evidence.get("dag_run_state") == "success" and required <= set(tasks)
            and all(state == "success" for state in tasks.values())):
        return dict(repair_verified=True, verification_status="VERIFIED_HEALTHY",
                    reason="New DAG run and all required tasks succeeded, including the data quality check.")
    return outcome


def nonempty_text(value):
    return isinstance(value, str) and bool(value.strip())


def utc_timestamp(value):
    """Parse a timezone-aware UTC ISO timestamp without guessing a timezone."""
    if not isinstance(value, str):
        raise ValueError("Expected a UTC timestamp.")
    parsed = datetime.fromisoformat(value)
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError("Expected a UTC timestamp.")
    return parsed


def validate_post_action(execution, context, *, validation_id, validated_at):
    """Return only conclusions supported by this execution and incident context.

    The caller supplies an ID and timezone-aware datetime for reproducibility.
    Invalid caller metadata raises ValueError; malformed execution/context
    evidence returns INCONCLUSIVE with unknown booleans represented as null.
    Inputs are not mutated. No environment, clock, network, or model is consulted.
    """
    if not nonempty_text(validation_id):
        raise ValueError("A nonempty validation_id is required.")
    if not isinstance(validated_at, datetime) or validated_at.utcoffset() is None:
        raise ValueError("validated_at must be a timezone-aware datetime.")
    validated_at = validated_at.astimezone(timezone.utc)
    output = {
        "validation_id": validation_id,
        "execution_id": None,
        "dag_id": None, "dag_run_id": None, "task_id": None,
        "validation_status": "INCONCLUSIVE",
        "execution_completed": None,
        "mutations_performed": None,
        "repair_verified": False,
        "reason": "Execution evidence is incomplete or inconsistent.",
        "validated_at": validated_at.isoformat(),
    }

    def inconclusive(reason):
        output["reason"] = reason  # Fixed messages; never echo arbitrary log text.
        return output

    if not isinstance(context, dict) or not all(nonempty_text(context.get(key)) for key in INCIDENT_FIELDS):
        return inconclusive("Original failure context lacks valid incident identifiers.")
    for key in INCIDENT_FIELDS:
        output[key] = context[key]
    if not isinstance(execution, dict) or set(execution) != EXECUTION_FIELDS:
        return inconclusive("Execution result has missing or unexpected fields.")
    if not nonempty_text(execution["execution_id"]):
        return inconclusive("Execution result lacks a valid execution identifier.")
    output["execution_id"] = execution["execution_id"]
    if execution["status"] not in ("COMPLETED", "REFUSED", "FAILED"):
        return inconclusive("Execution result contains an unsupported status.")
    if not all(nonempty_text(execution[key]) and execution[key] == context[key] for key in INCIDENT_FIELDS):
        return inconclusive("Execution and failure context do not identify the same incident.")
    # REFUSED may have no approval ID/operation (the executor rejected malformed
    # approval or an unallowlisted request). Completed/failed attempts need both.
    for key in ("approval_id", "operation"):
        if not nonempty_text(execution[key]) and not (
            execution["status"] == "REFUSED" and execution[key] is None
        ):
            return inconclusive("Execution result lacks required operation or approval metadata.")
    details = execution["result"]
    if (not isinstance(details, dict) or set(details) != {"message", "mutations_performed"}
            or not nonempty_text(details["message"])
            or type(details["mutations_performed"]) is not bool):
        return inconclusive("Execution result details are malformed.")
    try:
        started = utc_timestamp(execution["started_at"])
        completed = utc_timestamp(execution["completed_at"])
    except (ValueError, TypeError):
        return inconclusive("Execution timestamps are not valid UTC ISO timestamps.")
    if not started <= completed <= validated_at:
        return inconclusive("Execution and validation timestamps are out of order.")
    mutations = details["mutations_performed"]
    if execution["operation"] == "read_only_investigation" and mutations:
        return inconclusive("Read-only investigation contradicts its reported mutations.")
    if execution["status"] == "REFUSED" and mutations:
        return inconclusive("Refused execution contradicts its reported mutations.")

    output["execution_completed"] = execution["status"] == "COMPLETED"
    output["mutations_performed"] = mutations
    if execution["status"] in ("REFUSED", "FAILED"):
        output["validation_status"] = "EXECUTION_FAILED"
        output["reason"] = "Execution was refused or failed; repair has not been verified."
    elif execution["operation"] == "read_only_investigation" and mutations is False:
        output["validation_status"] = "NOT_REPAIRED"
        output["reason"] = "Read-only investigation completed, but no remediation was performed."
    else:
        output["reason"] = "Operation completion is not independent health evidence; repair cannot be verified."
    return output
