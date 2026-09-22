"""One synthetic-demo mutation, never a general editor or command runner.

Preparation (manual): copy config/reliability_demo_control.example.json to
config/reliability_demo_control.json. No playbook is run on import or via CLI.
Selection and authorization use current trusted pipeline inputs, not history.
Local approval metadata is not cryptographic authentication; the caller must
provide the current approval ID from its live approval gate, not incident memory.
"""

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import tempfile


PLAYBOOK = "restore_customer_id_demo_source"
ALLOWLIST = frozenset({PLAYBOOK})
PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONTROL_RELATIVE = "config/reliability_demo_control.json"
PROPOSED_ACTION = "Restore the synthetic customer_id demo source by setting simulate_failure to false."
FAILURE_SIGNATURE = 'Source data validation failed: required source field "customer_id" is missing.'


def identify_playbook(context):
    """Only the exact demo identifiers/error prefix qualify; ignore AI fields."""
    if not isinstance(context, dict):
        return None
    message = context.get("exception_message")
    if (context.get("dag_id") == "reliability_demo"
            and context.get("task_id") == "process_data"
            and context.get("exception_type") == "ValueError"
            and isinstance(message, str) and message.startswith(FAILURE_SIGNATURE)):
        return PLAYBOOK
    return None


def build_playbook_proposal(context):
    """Fixed human-reviewable proposal compatible with the existing policy/gate."""
    if identify_playbook(context) is None:
        raise ValueError("Failure does not match the allowlisted demo playbook.")
    return {
        "incident_summary": "Synthetic demo source reports a missing customer_id field.",
        "proposed_action": PROPOSED_ACTION,
        "action_type": "configuration_change", "target": CONTROL_RELATIVE,
        "reason": "The exact synthetic demo failure signature matches the predefined playbook.",
        "risk_level": "medium", "confidence": 1.0, "requires_human_approval": True,
        "validation_steps": ["Confirm the demo control contains simulate_failure=false.",
                             "A separately authorized future run must verify task and data-quality success."],
        "rollback_plan": "A human can restore the saved failing control value true and verify its contents.",
    }


def _control_path():
    """No path parameter. Refuse redirected directories, links, and hard links."""
    root = PROJECT_ROOT.resolve(strict=True)
    parent = root / "config"
    path = root / CONTROL_RELATIVE
    for entry in (parent, path):
        if entry.is_symlink() or (hasattr(entry, "is_junction") and entry.is_junction()):
            raise ValueError("Redirected demo control path.")
    if parent.resolve(strict=True) != parent or path.resolve(strict=True) != path:
        raise ValueError("Unexpected demo control location.")
    if not path.is_file() or path.stat().st_nlink != 1:
        raise ValueError("Demo control must be a regular unlinked file.")
    return path


def run_playbook(context, proposal, policy, approval, *, current_approval_id, now):
    """Authorize a single fixed true -> false change; never rerun Airflow.

    now and current_approval_id come from the trusted current approval session.
    Approval expires after 15 minutes. Single-writer local-demo use only.
    """
    from agent.approval_gate import validate_record
    from agent.policy_engine import evaluate_policy

    output = {"playbook": PLAYBOOK, "status": "REFUSED", "dag_id": "reliability_demo",
              "task_id": "process_data", "changes": [], "message": "Playbook refused."}
    try:
        if identify_playbook(context) not in ALLOWLIST:
            raise ValueError
        validate_record(approval)
        if (approval["status"] != "APPROVED" or not current_approval_id
                or approval["approval_id"] != current_approval_id
                or any(approval[key] != context.get(key) for key in ("dag_id", "dag_run_id", "task_id"))):
            raise ValueError
        if not isinstance(now, datetime) or now.utcoffset() is None:
            raise ValueError
        decided = datetime.fromisoformat(approval["decision_timestamp"])
        if not timedelta(0) <= now.astimezone(timezone.utc) - decided <= timedelta(minutes=15):
            raise ValueError
        expected = build_playbook_proposal(context)
        if proposal != expected or policy != evaluate_policy(expected):
            raise ValueError
        if (policy["decision"] != "require_approval" or policy["calculated_risk"] != "medium"
                or policy["requires_human_approval"] is not True or PLAYBOOK not in policy["allowed_actions"]
                or policy["blocked_actions"] or approval["policy_decision"] != policy["decision"]
                or approval["calculated_risk"] != policy["calculated_risk"]
                or approval["action_type"] != expected["action_type"]
                or approval["proposed_action"] != expected["proposed_action"]):
            raise ValueError
    except (RuntimeError, ValueError, TypeError, KeyError):
        output["message"] = "Current demo signature, approval, or playbook-specific policy did not match."
        return output

    temporary = None
    changed = False
    try:
        path = _control_path()
        before = path.read_bytes()
        control = json.loads(before)
        if (not isinstance(control, dict) or set(control) != {"simulate_failure"}
                or control["simulate_failure"] is not True):
            raise ValueError
        # Write a complete replacement beside the fixed control for atomic replace.
        # Neither model text nor caller paths influence the target or file contents.
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".demo-control-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write('{"simulate_failure": false}\n')
        if _control_path() != path or path.read_bytes() != before:
            raise ValueError
        os.replace(temporary, path)
        temporary = None
        changed = True
        output["changes"] = [{"target": CONTROL_RELATIVE,
                              "before": {"simulate_failure": True}, "after": {"simulate_failure": False}}]
        if json.loads(path.read_text(encoding="utf-8")) != {"simulate_failure": False}:
            raise ValueError
        output.update(status="COMPLETED", message="Synthetic demo control restored and verified. No Airflow rerun performed; incident repair is not verified.")
    except (OSError, ValueError, TypeError):
        output.update(status="FAILED" if changed else "REFUSED",
                      message="Demo control verification failed after modification." if changed else "Expected safe failing demo control was not present; no control change performed.")
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return output
