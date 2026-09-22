"""Coordinate the existing reliability stages without adding execution powers.

Run: python -m agent.orchestrator --task-id process_data
Historical records are display-only. Every new proposal needs a fresh approval.
"""

import argparse
from datetime import datetime, timezone
import json
import os
import sys
from uuid import uuid4

from agent.approval_gate import create_approval_record, prompt_for_approval, validate_record
from agent.context_extractor import extract_failure_contexts
from agent.controlled_executor import ALLOWED_OPERATION, execute_approved_operation
from agent.failure_detector import request_json
from agent.incident_memory import (
    DEFAULT_STORE, append_incident, build_incident_record, find_similar_incidents,
    load_incidents, redact,
)
from agent.log_collector import collect_failed_task_logs
from agent.policy_engine import evaluate_policy
from agent.post_action_validator import validate_post_action
from agent.rca_analyzer import analyze_context, compact_context, validate_rca
from agent.remediation_planner import propose_remediation, validate_proposal
from agent.remediation_playbooks import identify_playbook, build_playbook_proposal, run_playbook
from agent.airflow_rerun import rerun_and_verify


def utc_now():
    return datetime.now(timezone.utc)


def new_id():
    return str(uuid4())


def offer_playbook(context, investigation_approval, *, clock, id_factory, secrets):
    """A separate authorization lifecycle. History and investigation cannot approve it."""
    playbook = identify_playbook(context)
    if playbook is None:
        return None
    proposal = build_playbook_proposal(context)
    policy = evaluate_policy(proposal)
    attempt = dict(playbook=playbook, proposal=proposal, policy=policy, approval=None,
                   execution=None, final_state="NOT_REPAIRED", repair_verified=False, error=None)
    display("Known Remediation Playbook Available", {
        "playbook": playbook, "target": proposal["target"],
        "proposed_action": proposal["proposed_action"],
        "calculated_risk": policy["calculated_risk"], "policy_decision": policy["decision"],
    }, secrets)
    invoked = False
    try:
        approval_id = id_factory()
        if approval_id == investigation_approval["approval_id"]:
            raise ValueError("A separate approval ID is required.")
        initial = create_approval_record(context, proposal, policy, approval_id=approval_id)
        attempt["approval"] = initial
        if policy["decision"] == "block":
            display("Playbook BLOCKED; no approval offered.", initial, secrets)
            return attempt
        print("A predefined remediation can modify the synthetic demo control.\n"
              "The next approval applies only to this exact playbook; reject to stop.")
        approval = prompt_for_approval(dict(initial))
        validate_record(approval)
        if any(approval[key] != initial[key] for key in initial if key not in (
            "status", "approved_by", "decision_timestamp",
        )):
            raise ValueError("Playbook approval target changed.")
        attempt["approval"] = approval
        if approval["status"] != "APPROVED":
            return attempt
        # Authorization/freshness/state checks remain in the existing playbook.
        invoked = True
        result = run_playbook(context, proposal, policy, approval,
                              current_approval_id=approval_id, now=clock())
        attempt["execution"] = result
        if result["status"] == "COMPLETED":
            attempt["final_state"] = "REMEDIATION_APPLIED_PENDING_VALIDATION"
        elif result["status"] == "FAILED":
            attempt["final_state"] = "INCONCLUSIVE"
        display("Controlled Remediation Result", result, secrets)
    except Exception:
        attempt["error"] = "Playbook stage failed safely; no retry attempted."
        # After invocation an exception cannot prove that no change occurred.
        attempt["final_state"] = "INCONCLUSIVE" if invoked else "NOT_REPAIRED"
    return attempt


def display(label, value, secrets=()):
    print(label, flush=True)
    # Redact recursively before serialization; memory's helper handles dicts.
    def clean(item):
        if isinstance(item, list):
            return [clean(child) for child in item]
        if isinstance(item, dict):
            return {key: clean(child) for key, child in item.items()}
        return redact(item, secrets)
    print(json.dumps(clean(value), indent=2, ensure_ascii=False), flush=True)


def process_incident(context, *, memory_path=DEFAULT_STORE, secrets=(), clock=utc_now, id_factory=new_id, airflow_token=None):
    """Process one compact context. Dependency functions can be mocked offline.

    Return a report even if a stage fails. Incomplete cycles are not fabricated
    into memory records; persistence failure is explicitly reported as unstored.
    """
    report = {
        "incident_id": id_factory(), "incident": context,
        "rca": None, "remediation": None, "policy": None, "approval": None,
        "execution": None, "validation": None,
        "memory": {"incident_stored": False, "similar_historical_incidents_found": 0},
        "final_incident_state": "INCONCLUSIVE", "error": None,
    }
    stage = "context"
    try:
        context = compact_context(context)
        report["incident"] = context
        display("Failure Context:", context, secrets)
        stage = "historical lookup"
        history = load_incidents(memory_path, secrets=secrets)
        matches = find_similar_incidents(context, history)
        report["memory"]["similar_historical_incidents_found"] = len(matches)
        if matches:
            display("Historical Incidents (advisory only):", matches, secrets)
        else:
            print("Historical Incidents:\nNo similar historical incidents found.")

        stage = "AI RCA"
        rca = validate_rca(analyze_context(context))
        report["rca"] = rca
        display("AI RCA:", rca, secrets)
        stage = "remediation proposal"
        proposal = validate_proposal(propose_remediation(context, rca))
        report["remediation"] = proposal
        display("Remediation Proposal:", proposal, secrets)
        stage = "policy"
        policy = evaluate_policy(proposal)
        report["policy"] = policy
        display("Policy Decision:", policy, secrets)
        stage = "approval"
        initial = create_approval_record(context, proposal, policy, approval_id=id_factory())
        if policy["decision"] == "block":
            approval = initial
            display("Approval Summary (BLOCKED; no approval offered):", approval, secrets)
        else:
            approval = prompt_for_approval(initial)
        validate_record(approval)
        # The gate may change only decision metadata, never the approved target.
        if any(approval[key] != initial[key] for key in initial if key not in (
            "status", "approved_by", "decision_timestamp",
        )):
            raise ValueError("Approval target changed.")
        report["approval"] = approval

        stage = "execution"
        started = clock()
        execution_id = id_factory()
        if approval["status"] == "APPROVED":
            execution = execute_approved_operation(
                approval, proposal, policy, context, operation=ALLOWED_OPERATION,
                execution_id=execution_id, started_at=started, completed_at=clock(),
            )
        else:
            # Record a skipped attempt, without calling the executor. This allows
            # the existing validator/memory to preserve blocked/rejected cycles.
            execution = {
                "execution_id": execution_id, "approval_id": approval["approval_id"],
                "operation": ALLOWED_OPERATION, "status": "REFUSED",
                **{key: context[key] for key in ("dag_id", "dag_run_id", "task_id")},
                "started_at": started.isoformat(), "completed_at": clock().isoformat(),
                "result": {"message": "Executor was not called: no current human approval.",
                           "mutations_performed": False},
            }
        report["execution"] = execution
        display("Controlled Execution Result:", execution, secrets)
        stage = "post-action validation"
        validation = validate_post_action(execution, context, validation_id=id_factory(), validated_at=clock())
        report["validation"] = validation
        display("Post-Action Validation:", validation, secrets)
        if approval["status"] in ("BLOCKED", "REJECTED"):
            report["final_incident_state"] = approval["status"]
        elif approval["status"] == "PENDING_APPROVAL":
            report["final_incident_state"] = "INCONCLUSIVE"
        else:
            report["final_incident_state"] = validation["validation_status"]

        if (execution["status"] == "COMPLETED"
                and execution["operation"] == ALLOWED_OPERATION
                and validation["validation_status"] == "NOT_REPAIRED"):
            stage = "known remediation playbook"
            attempt = offer_playbook(context, approval, clock=clock, id_factory=id_factory, secrets=secrets)
            if attempt is not None:
                report["playbook_attempt"] = attempt
                report["final_incident_state"] = attempt["final_state"]
                if (airflow_token and attempt["error"] is None
                        and attempt["approval"] is not None and attempt["approval"]["status"] == "APPROVED"
                        and attempt["execution"] is not None and attempt["execution"]["status"] == "COMPLETED"):
                    stage = "Airflow rerun verification"
                    verification = rerun_and_verify(
                        context, attempt, token=airflow_token,
                        current_approval_id=attempt["approval"]["approval_id"],
                        verification_run_id="manual__reliability_" + id_factory(), now=clock(),
                    )
                    report["verification"] = verification
                    report["repair_verified"] = verification["repair_verified"]
                    report["final_incident_state"] = verification["verification_status"]
                    display("Independent Airflow Verification:", verification, secrets)

        stage = "incident persistence"
        record = build_incident_record(
            context, rca, proposal, policy, approval, execution, validation,
            incident_id=report["incident_id"], recorded_at=clock(), secrets=secrets,
        )
        if "playbook_attempt" in report:
            record["playbook_attempt"] = report["playbook_attempt"]
        if "verification" in report:
            record["verification"] = report["verification"]
            record["final_outcome"] = {"state": report["final_incident_state"], "repair_verified": report["repair_verified"]}
        append_incident(record, memory_path, secrets=secrets)
        report["memory"]["incident_stored"] = True
    except Exception:
        # No raw exception/model/server text: it may contain credentials. Stop
        # this lifecycle; never retry approval or advance after a failing stage.
        report["error"] = f"Stage failed safely: {stage}. No further stages were attempted."
    display("=== AIRFLOW RELIABILITY AGENT REPORT ===", report, secrets)
    return report


def run_workflow(task_id=None, *, memory_path=DEFAULT_STORE):
    """Authenticate/collect once, then coordinate each matching failed task."""
    username = os.environ.get("AIRFLOW_API_USERNAME")
    password = os.environ.get("AIRFLOW_API_PASSWORD")
    if not username or not password:
        raise RuntimeError("Set AIRFLOW_API_USERNAME and AIRFLOW_API_PASSWORD.")
    auth = request_json("/auth/token", payload={"username": username, "password": password})
    token = auth.get("access_token")
    if not token:
        raise RuntimeError("Airflow authentication did not return a token.")
    secrets = tuple(value for name, value in os.environ.items() if value and any(
        word in name.upper() for word in ("PASSWORD", "SECRET", "TOKEN", "API_KEY", "FERNET_KEY")
    )) + (token, password)
    collected = collect_failed_task_logs(token, task_id)
    contexts = extract_failure_contexts(collected, secrets=secrets)
    if not contexts:
        print("No matching failed tasks found; no incident created or approval requested.")
        return []
    if not os.environ.get("GROQ_API_KEY", "").strip():
        raise RuntimeError("Set GROQ_API_KEY for the existing AI pipeline.")
    reports = []
    for context in contexts:
        report = process_incident(context, memory_path=memory_path, secrets=secrets, airflow_token=token)
        reports.append(report)
        if report["error"] or report["approval"]["status"] in ("BLOCKED", "REJECTED", "PENDING_APPROVAL"):
            break
        if "playbook_attempt" in report:
            break  # One demo mutation offer per CLI invocation, never retry older runs.
    return reports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task-id", help="Only process this failed task, e.g. process_data.")
    args = parser.parse_args()
    try:
        reports = run_workflow(args.task_id)
        return 1 if any(report["error"] for report in reports) else 0
    except Exception:
        print("Orchestrator could not obtain failure contexts. Check credentials and service availability.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
