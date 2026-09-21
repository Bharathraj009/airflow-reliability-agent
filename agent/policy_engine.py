"""Deterministic, advisory policy evaluation. No actions are executed.

evaluate_policy(proposal) works offline, without credentials or network calls.
The optional CLI obtains a proposal through the existing AI pipeline first:
python -m agent.policy_engine --task-id process_data
"""

import argparse
import json
import re
import sys
import unicodedata

from agent.remediation_planner import TEXT_FIELDS, validate_proposal


# These risks are policy decisions, independent of the model's risk/confidence.
ACTION_POLICY = {
    "investigation": ("low", "require_approval", "read_only_investigation"),
    "code_change": ("medium", "require_approval", "code_change"),
    "configuration_change": ("medium", "require_approval", "configuration_change"),
    "data_correction": ("high", "require_approval", "data_correction"),
    "no_change": ("low", "allow", "no_change"),
}

# Search every text field, including rollback and validation instructions.
# Rules are intentionally conservative: even quoted/negated dangerous operations
# are flagged for review. This is not a SQL parser or a shell security sandbox.
DANGEROUS_RULES = (
    ("drop_database_objects", r"\bdrop\s+(?:table|database|schema)\b",
     "Dropping tables, databases, or schemas is prohibited."),
    ("delete_operation", r"\b(?:delete|deleting|deletion)\b",
     "Deletion requested or mentioned; free-text scope does not establish a safe deletion bound."),
    ("truncate_data", r"\btruncate\b",
     "Truncating data is prohibited."),
    ("destroy_resources", r"\b(?:destroy\w*|wipe\w*|purge\w*|erase\w*|tear\s+down)\b",
     "Destroying or wiping resources is prohibited."),
    ("remove_protected_resources", r"\bremov\w*\b.{0,160}\b(?:infrastructure|resources?|volumes?|containers?|dags?|pipelines?|production|data|records?|rows?|tables?|databases?)\b",
     "Removing data, DAGs, or infrastructure resources is prohibited."),
    ("disable_security", r"\b(?:disabl\w*|bypass\w*|turn\s+off|remov\w*)\b.{0,160}\b(?:security|auth\w*|access\s+control|permission\w*|encryption|tls|ssl|firewall|audit\w*|logging|validation|checks?)\b",
     "Disabling or bypassing security/validation controls is prohibited."),
    ("expose_secrets", r"\b(?:show|print|display|expos\w*|request\w*|send|share|reveal|extract|dump|obtain|fetch|read|log|upload|provide|retrieve)\b.{0,160}\b(?:credentials?|secrets?|passwords?|tokens?|api[ _-]?keys?|private[ _-]?keys?|\.env)\b",
     "Requesting or exposing credentials or secrets is prohibited."),
    ("bypass_approval", r"\b(?:bypass\w*|skip\w*|ignor\w*|without|avoid\w*|disabl\w*|no\s+need\s+for)\b.{0,100}\b(?:approval|review|confirmation)\b|\bauto(?:matic(?:ally)?)?[ _-]?approv\w*\b",
     "Bypassing human approval or automatically approving actions is prohibited."),
    ("shell_execution", r"\b(?:shell|bash|powershell|cmd\.exe|subprocess|os\.system|eval|exec)\b|\b(?:sh|cmd)\s+[-/][ck]\b|\bcurl\b.{0,160}\|",
     "Arbitrary shell or code execution is prohibited."),
    ("destructive_system_operation", r"\brm\s+-|\brmdir\b|\bremove-item\b|\bmkfs\b|\bdd\s+|\bformat\s+[a-z]:|\b(?:shutdown|reboot)\b|\bchmod\s+777\b|\bgit\s+(?:reset\s+--hard|clean\s+-)",
     "Destructive filesystem or system commands are prohibited."),
    ("destructive_docker_operation", r"\bdocker\b.{0,120}\b(?:down|rm|rmi|prune|kill|stop)\b|\bterraform\s+destroy\b|\bkubectl\s+delete\b",
     "Destructive Docker or infrastructure operations are prohibited."),
)


def normalize_text(text):
    """Normalize common casing, whitespace, and SQL-comment evasions."""
    text = unicodedata.normalize("NFKC", text).casefold()
    text = "".join(char for char in text if unicodedata.category(char) != "Cf")
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return " ".join(text.split())


def evaluate_policy(proposal):
    """Validate and classify a proposal; never call a model or execute anything.

    allowed_actions are policy-eligible categories only, NOT execution grants.
    Invalid proposals raise RuntimeError. No decision is issued for invalid input.
    """
    validate_proposal(proposal)
    texts = [normalize_text(proposal[key]) for key in TEXT_FIELDS]
    texts.extend(normalize_text(step) for step in proposal["validation_steps"])
    blocked = []
    reasons = []
    for action, pattern, reason in DANGEROUS_RULES:
        if any(re.search(pattern, text) for text in texts):
            blocked.append(action)
            reasons.append(reason)

    action_type = proposal["action_type"]
    # Do not accept a read-only/no-op label as permission for a write operation.
    # Classify only the CURRENT proposed action. Validation steps may describe
    # checks after a future, separately approved remediation. They still pass
    # through all dangerous-operation rules above.
    current_action = normalize_text(proposal["proposed_action"])
    mutation = r"\b(?:modify|update|insert|alter|write|overwrite|replace|patch|deploy|restart|rerun|trigger|execute|apply|create|enable|disable)\b|\b(?:change|set|fix|correct)\s+(?:the\s+)?(?:code|data|configuration|config|source|schema|value|flag)\b"
    if action_type in ("investigation", "no_change") and re.search(mutation, current_action):
        blocked.append("action_type_mismatch")
        reasons.append("Read-only/no-change classification conflicts with possible modifying instructions.")

    if blocked:
        return {
            "decision": "block", "calculated_risk": "high", "reasons": reasons,
            "allowed_actions": [], "blocked_actions": blocked,
            "requires_human_approval": True,
        }
    risk, decision, eligible_action = ACTION_POLICY[action_type]
    reasons = [f"Policy classifies {action_type} as {risk} risk, independently of the AI risk rating."]
    if action_type == "no_change":
        reasons.append("No change is proposed. Allow means a no-op, not permission to execute anything.")
    else:
        reasons.append("Human approval is required before any future action; no execution is authorized here.")
    reasons.append("Human approval remains mandatory for every decision in this development phase.")
    return {
        "decision": decision, "calculated_risk": risk, "reasons": reasons,
        "allowed_actions": [eligible_action], "blocked_actions": [],
        "requires_human_approval": True,
    }


def main():
    # Network/model functions belong exclusively to CLI orchestration, never to
    # evaluate_policy(). Reuse the existing components without changing them.
    import os
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
            raise RuntimeError("Set GROQ_API_KEY for the CLI's existing AI pipeline.")
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
            print("No matching failed tasks found; no Groq requests were made.")
        for context in contexts:
            context = compact_context(context)
            print("Failure Context:", flush=True)
            print(json.dumps(context, indent=2), flush=True)
            rca = analyze_context(context)
            print("AI RCA:", flush=True)
            print(json.dumps(rca, indent=2), flush=True)
            proposal = propose_remediation(context, rca)
            decision = evaluate_policy(proposal)
            print("Remediation Proposal:", flush=True)
            print(json.dumps(proposal, indent=2), flush=True)
            print("Policy Decision:")
            print(json.dumps(decision, indent=2))
        return 0
    except RuntimeError as exc:
        print(f"Policy engine: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
