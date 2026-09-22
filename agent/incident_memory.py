"""Local, single-writer JSONL history. Historical text is data, never authority.

No model/network/execution calls. IDs, timestamps, and known secret values are
supplied by the caller. Retrieval scores are lexical matches, not semantic AI.
"""

from datetime import datetime, timezone
import json
import math
from pathlib import Path
import re


DEFAULT_STORE = Path(__file__).resolve().parent.parent / "runtime" / "incidents.jsonl"
SECTIONS = {
    "failure": ("exception_type", "exception_message", "source_file", "source_line", "failed_function"),
    "rca": ("summary", "root_cause", "confidence"),
    "remediation": ("action_type", "proposed_action", "risk_level"),
    "policy": ("decision", "calculated_risk"),
    "approval": ("status", "approved_by", "decision_timestamp"),
    "execution": ("operation", "status", "mutations_performed"),
    "validation": ("validation_status", "repair_verified", "reason"),
}
BASE_FIELDS = {"incident_id", "recorded_at", "dag_id", "dag_run_id", "task_id", "historical_only"}


def redact(value, secrets=()):
    """Redact explicit known secrets and common credential formats recursively.

    Unknown unlabelled secrets cannot be identified universally. Callers must
    supply known secret values, and producers must avoid logging sensitive data.
    No environment is read or stored by this module.
    """
    if isinstance(value, dict):
        return {key: redact(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item, secrets) for item in value]
    if not isinstance(value, str):
        return value
    for secret in sorted((item for item in secrets if isinstance(item, str) and item), key=len, reverse=True):
        value = value.replace(secret, "[REDACTED]")
    value = re.sub(r"\b(?:gsk_|sk-)[A-Za-z0-9_-]+\b", "[REDACTED]", value)
    value = re.sub(r"\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[REDACTED]", value)
    value = re.sub(r"(?i)\bbearer\s+\S+", "Bearer [REDACTED]", value)
    value = re.sub(r"(://)[^\s/@]+:[^\s/@]+@", r"\1[REDACTED]@", value)
    value = re.sub(
        r'''(?i)(\b[\w-]*(?:password|passwd|secret|token|api[_-]?key|authorization|credential)[\w-]*\b["']?\s*[:=]\s*)("[^"\n]*"|'[^'\n]*'|[^\s,;]+)''',
        r"\1[REDACTED]", value,
    )
    value = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", "[REDACTED]", value, flags=re.DOTALL)
    return value[:4000]


def _utc(value):
    parsed = datetime.fromisoformat(value)
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError
    return parsed


def validate_incident(record):
    """Strict allowlisted schema; reject extra fields rather than storing secrets."""
    try:
        if not isinstance(record, dict) or set(record) - {"playbook_attempt", "verification", "final_outcome"} != BASE_FIELDS | set(SECTIONS):
            raise ValueError
        if record["historical_only"] is not True:
            raise ValueError
        for key in BASE_FIELDS - {"historical_only"}:
            if not isinstance(record[key], str) or not record[key].strip():
                raise ValueError
        _utc(record["recorded_at"])
        for section, fields in SECTIONS.items():
            data = record[section]
            if not isinstance(data, dict) or set(data) != set(fields):
                raise ValueError
            for key, value in data.items():
                if key in ("confidence", "source_line", "repair_verified", "mutations_performed"):
                    continue
                optional = section == "failure" or key in ("approved_by", "decision_timestamp", "operation")
                if not (optional and value is None) and not (isinstance(value, str) and value.strip()):
                    raise ValueError
        confidence = record["rca"]["confidence"]
        if type(confidence) not in (int, float) or not 0 <= confidence <= 1 or not math.isfinite(confidence):
            raise ValueError
        line = record["failure"]["source_line"]
        if line is not None and (type(line) is not int or line < 0):
            raise ValueError
        for section, field, values in (
            ("remediation", "action_type", ("investigation", "code_change", "configuration_change", "data_correction", "no_change")),
            ("remediation", "risk_level", ("low", "medium", "high")),
            ("policy", "calculated_risk", ("low", "medium", "high")),
            ("policy", "decision", ("allow", "require_approval", "block")),
            ("approval", "status", ("PENDING_APPROVAL", "APPROVED", "REJECTED", "BLOCKED")),
            ("execution", "status", ("COMPLETED", "REFUSED", "FAILED")),
            ("validation", "validation_status", ("VERIFIED_HEALTHY", "NOT_REPAIRED", "INCONCLUSIVE", "EXECUTION_FAILED")),
        ):
            if record[section][field] not in values:
                raise ValueError
        approval = record["approval"]
        if approval["status"] in ("APPROVED", "REJECTED"):
            if not approval["approved_by"] or _utc(approval["decision_timestamp"]) > _utc(record["recorded_at"]):
                raise ValueError
        elif approval["approved_by"] is not None or approval["decision_timestamp"] is not None:
            raise ValueError
        execution, validation = record["execution"], record["validation"]
        if type(execution["mutations_performed"]) is not bool or type(validation["repair_verified"]) is not bool:
            raise ValueError
        if validation["repair_verified"] != (validation["validation_status"] == "VERIFIED_HEALTHY"):
            raise ValueError
        if execution["operation"] == "read_only_investigation":
            if execution["mutations_performed"] or validation["repair_verified"]:
                raise ValueError
        if execution["status"] == "COMPLETED" and approval["status"] != "APPROVED":
            raise ValueError
        if validation["repair_verified"] and execution["status"] != "COMPLETED":
            raise ValueError
        if record["policy"]["decision"] == "block" and approval["status"] != "BLOCKED":
            raise ValueError
        if "playbook_attempt" in record:
            _validate_playbook_attempt(record)
        if "verification" in record or "final_outcome" in record:
            _validate_verification(record)
    except (KeyError, TypeError, ValueError, OverflowError):
        raise ValueError("Malformed or inconsistent historical incident record.") from None
    return record


def _validate_verification(record):
    from agent.post_action_validator import assess_airflow_health
    evidence = record["verification"]
    if set(evidence) != {"original_dag_run_id", "verification_dag_run_id", "dag_id", "trigger_status", "dag_run_state", "task_states", "repair_verified", "verification_status", "reason"}:
        raise ValueError
    if (evidence["original_dag_run_id"] != record["dag_run_id"] or evidence["dag_id"] != record["dag_id"]
            or not isinstance(evidence["verification_dag_run_id"], str)
            or type(evidence["repair_verified"]) is not bool
            or not isinstance(evidence["reason"], str) or not isinstance(evidence["task_states"], dict)
            or not all(isinstance(key, str) and (value is None or isinstance(value, str)) for key, value in evidence["task_states"].items())
            or evidence["verification_status"] not in ("VERIFIED_HEALTHY", "VERIFICATION_FAILED", "TIMEOUT", "INCONCLUSIVE")
            or evidence["trigger_status"] not in ("NOT_TRIGGERED", "UNKNOWN", "CREATED")):
        raise ValueError
    attempt = record["playbook_attempt"]
    if not attempt["execution"] or attempt["execution"]["status"] != "COMPLETED":
        raise ValueError
    derived = assess_airflow_health(evidence)
    if evidence["repair_verified"] != (evidence["verification_status"] == "VERIFIED_HEALTHY"):
        raise ValueError
    if evidence["repair_verified"] and not derived["repair_verified"]:
        raise ValueError
    if record["final_outcome"] != {"state": evidence["verification_status"], "repair_verified": evidence["repair_verified"]}:
        raise ValueError


def _validate_playbook_attempt(record):
    """Optional historical section; does not change old records or grant authority."""
    from agent.approval_gate import validate_record
    from agent.remediation_planner import validate_proposal
    from agent.remediation_playbooks import PLAYBOOK, CONTROL_RELATIVE

    attempt = record["playbook_attempt"]
    fields = {"playbook", "proposal", "policy", "approval", "execution", "final_state", "repair_verified", "error"}
    if not isinstance(attempt, dict) or set(attempt) != fields:
        raise ValueError
    if attempt["playbook"] != PLAYBOOK or attempt["repair_verified"] is not False:
        raise ValueError
    if attempt["error"] is not None and not isinstance(attempt["error"], str):
        raise ValueError
    try:
        validate_proposal(attempt["proposal"])
        approval = attempt["approval"]
        if approval is not None:
            validate_record(approval)
            if any(approval[key] != record[key] for key in ("dag_id", "dag_run_id", "task_id")):
                raise ValueError
            if approval["proposed_action"] != attempt["proposal"]["proposed_action"]:
                raise ValueError
    except RuntimeError:
        raise ValueError from None
    policy = attempt["policy"]
    if not isinstance(policy, dict) or set(policy) != {
        "decision", "calculated_risk", "reasons", "allowed_actions", "blocked_actions", "requires_human_approval",
    }:
        raise ValueError
    if (policy["decision"] not in ("block", "require_approval")
            or policy["calculated_risk"] not in ("medium", "high")
            or policy["requires_human_approval"] is not True):
        raise ValueError
    for key in ("reasons", "allowed_actions", "blocked_actions"):
        if not isinstance(policy[key], list) or not all(isinstance(item, str) for item in policy[key]):
            raise ValueError
    execution = attempt["execution"]
    if execution is not None:
        if not isinstance(execution, dict) or set(execution) != {"playbook", "status", "dag_id", "task_id", "changes", "message"}:
            raise ValueError
        if (execution["playbook"] != PLAYBOOK or execution["status"] not in ("COMPLETED", "REFUSED", "FAILED")
                or any(execution[key] != record[key] for key in ("dag_id", "task_id"))
                or not isinstance(execution["message"], str) or not isinstance(execution["changes"], list)):
            raise ValueError
        expected_change = {"target": CONTROL_RELATIVE, "before": {"simulate_failure": True}, "after": {"simulate_failure": False}}
        if execution["changes"] not in ([], [expected_change]):
            raise ValueError
        if execution["status"] == "COMPLETED":
            if (not approval or approval["status"] != "APPROVED" or policy["decision"] != "require_approval"
                    or PLAYBOOK not in policy["allowed_actions"] or execution["changes"] != [expected_change]
                    or attempt["final_state"] != "REMEDIATION_APPLIED_PENDING_VALIDATION"):
                raise ValueError
    if attempt["final_state"] not in ("NOT_REPAIRED", "INCONCLUSIVE", "REMEDIATION_APPLIED_PENDING_VALIDATION"):
        raise ValueError
    if attempt["final_state"] == "REMEDIATION_APPLIED_PENDING_VALIDATION" and (not execution or execution["status"] != "COMPLETED"):
        raise ValueError


def build_incident_record(context, rca, remediation, policy, approval, execution, validation, *, incident_id, recorded_at, secrets=()):
    """Project stage results onto a small schema; never persist raw logs/headers."""
    if not isinstance(recorded_at, datetime) or recorded_at.utcoffset() is None:
        raise ValueError("recorded_at must be a timezone-aware datetime.")
    try:
        for stage in (approval, execution, validation):
            if any(stage.get(key) != context.get(key) for key in ("dag_id", "dag_run_id", "task_id")):
                raise ValueError("Stage incident identifiers do not match.")
        if execution.get("approval_id") != approval.get("approval_id") or validation.get("execution_id") != execution.get("execution_id"):
            raise ValueError("Stage reference identifiers do not match.")
        record = dict(incident_id=incident_id, recorded_at=recorded_at.astimezone(timezone.utc).isoformat(), historical_only=True)
        record.update({key: context.get(key) for key in ("dag_id", "dag_run_id", "task_id")})
        stages = dict(failure=context, rca=rca, remediation=remediation, policy=policy, approval=approval,
                      execution=dict(execution, mutations_performed=execution["result"]["mutations_performed"]), validation=validation)
        for name, fields in SECTIONS.items():
            record[name] = {field: stages[name].get(field) for field in fields}
    except (AttributeError, KeyError, TypeError):
        raise ValueError("Malformed incident cycle inputs.") from None
    validate_incident(record)
    return validate_incident(redact(record, tuple(secrets)))


def append_incident(record, path=DEFAULT_STORE, *, secrets=()):
    """Append one validated UTF-8 object. Single writer only; never truncate."""
    validate_incident(record)
    safe = validate_incident(redact(record, tuple(secrets)))
    encoded = (json.dumps(safe, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab+") as stream:
        # Separate a partial/corrupt final line so later valid records survive.
        stream.seek(0, 2)
        if stream.tell():
            stream.seek(-1, 2)
            if stream.read(1) != b"\n":
                stream.write(b"\n")
        stream.write(encoded)


def load_incidents(path=DEFAULT_STORE, *, secrets=()):
    """Skip corrupt/missing lines; never evaluate or execute stored text."""
    records = []
    try:
        stream = Path(path).open("rb")
    except FileNotFoundError:
        return records
    with stream:
        for line in stream:
            try:
                record = validate_incident(json.loads(line.decode("utf-8")))
                records.append(validate_incident(redact(record, tuple(secrets))))
            except (ValueError, UnicodeError, RecursionError):
                continue
    return records


def find_similar_incidents(context, incidents, *, limit=5):
    """Rank exact fields plus message word overlap; ties retain storage order.

    Scores do not imply repair effectiveness. VERIFIED_HEALTHY is historical
    reporting only, never fresh health evidence or authorization for an action.
    """
    if not isinstance(context, dict) or type(limit) is not int or limit < 0:
        raise ValueError("Expected a context object and nonnegative integer limit.")
    matches = []
    for record in incidents:
        try:
            validate_incident(record)
        except ValueError:
            continue
        score, fields = 0.0, []
        for field, weight in (("dag_id", 2), ("task_id", 3), ("exception_type", 3)):
            previous = record["failure"].get(field) if field == "exception_type" else record[field]
            if context.get(field) and context[field] == previous:
                score += weight
                fields.append(field)
        current = set(re.findall(r"\w+", str(context.get("exception_message") or "").casefold()))
        previous = set(re.findall(r"\w+", str(record["failure"]["exception_message"] or "").casefold()))
        overlap = len(current & previous) / len(current | previous) if current or previous else 0
        if overlap:
            score += 4 * overlap
            fields.append("exception_message_word_overlap")
        if score:
            matches.append({"incident": redact(record), "match_score": round(score, 4), "matched_fields": fields,
                            "repair_verified": record.get("final_outcome", record["validation"])["repair_verified"], "historical_only": True})
    return sorted(matches, key=lambda item: -item["match_score"])[:limit]
