"""Playbook orchestration tests use only a temporary synthetic control."""

from contextlib import ExitStack, redirect_stdout
from datetime import datetime, timedelta, timezone
import io
import itertools
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from agent import orchestrator as o
from agent import remediation_playbooks as p
from agent.approval_gate import apply_human_decision
from agent.incident_memory import load_incidents, append_incident
from agent.remediation_planner import NO_CHANGE_ROLLBACK


class OrchestratorPlaybookTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(TemporaryDirectory()))
        self.control = self.root / p.CONTROL_RELATIVE
        self.control.parent.mkdir()
        self.control.write_text('{"simulate_failure": true}', encoding="utf-8")
        self.path = self.root / "incidents.jsonl"
        self.stack.enter_context(patch.object(p, "PROJECT_ROOT", self.root))
        self.stack.enter_context(patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("No network")))
        self.context = dict(dag_id="reliability_demo", dag_run_id="current-run", task_id="process_data", exception_type="ValueError", exception_message=p.FAILURE_SIGNATURE)
        rca = dict(summary="Missing field", root_cause="Synthetic failure", evidence=["Missing field"], recommended_action="Inspect source", risk_level="low", confidence=0.8, requires_human_approval=True)
        proposal = dict(incident_summary="Missing field", proposed_action="Inspect upstream schema", action_type="investigation", target="Source", reason="Missing field", risk_level="low", confidence=0.8, requires_human_approval=True, validation_steps=["Confirm fields exist."], rollback_plan=NO_CHANGE_ROLLBACK)
        self.stack.enter_context(patch.object(o, "analyze_context", return_value=rca))
        self.stack.enter_context(patch.object(o, "propose_remediation", return_value=proposal))
        self.prompt = self.stack.enter_context(patch("builtins.input", side_effect=["approve", "approve"]))
        self.stack.enter_context(patch("agent.approval_gate.getpass.getuser", return_value="tester"))
        self.playbook = self.stack.enter_context(patch.object(o, "run_playbook", wraps=p.run_playbook))
        self.output = self.stack.enter_context(redirect_stdout(io.StringIO()))
        self.ids = itertools.count()

    def cycle(self):
        return o.process_incident(self.context, memory_path=self.path, id_factory=lambda: f"id-{next(self.ids)}")

    def test_success_requires_two_approvals_and_stores_pending_validation(self):
        report = self.cycle()
        self.assertIsNone(report["error"])
        self.assertEqual(self.prompt.call_count, 2)
        attempt = report["playbook_attempt"]
        self.assertNotEqual(attempt["approval"]["approval_id"], report["approval"]["approval_id"])
        self.assertEqual(self.playbook.call_args.kwargs["current_approval_id"], attempt["approval"]["approval_id"])
        self.assertEqual(report["final_incident_state"], "REMEDIATION_APPLIED_PENDING_VALIDATION")
        self.assertFalse(attempt["repair_verified"])
        self.assertFalse(report["validation"]["repair_verified"])
        self.assertEqual(json.loads(self.control.read_text()), {"simulate_failure": False})
        stored = load_incidents(self.path)[0]
        self.assertEqual(stored["playbook_attempt"]["execution"]["status"], "COMPLETED")
        self.assertEqual(stored["execution"]["operation"], "read_only_investigation")
        self.assertIn("Known Remediation Playbook Available", self.output.getvalue())
        self.assertIn("Controlled Remediation Result", self.output.getvalue())

    def test_unrelated_keeps_original_behavior(self):
        self.context["exception_message"] = "Unrelated failure"
        report = self.cycle()
        self.playbook.assert_not_called()
        self.assertNotIn("playbook_attempt", report)
        self.assertEqual(report["final_incident_state"], "NOT_REPAIRED")
        self.assertEqual(self.prompt.call_count, 1)

    def test_reject_invalid_and_interrupt_leave_control_unchanged(self):
        for command in ("reject", "", "yes", EOFError(), KeyboardInterrupt()):
            with self.subTest(command=command):
                self.prompt.side_effect = ["approve", command]
                report = self.cycle()
                self.assertIsNone(report["error"])
                self.assertEqual(report["final_incident_state"], "NOT_REPAIRED")
                self.assertTrue(report["memory"]["incident_stored"])
                self.assertTrue(json.loads(self.control.read_text())["simulate_failure"])
        self.playbook.assert_not_called()

    def test_old_investigation_record_cannot_authorize_mutation(self):
        saved = []
        def stale_gate(initial):
            if saved:
                return saved[0]
            saved.append(apply_human_decision(initial, "approve", reviewer="tester", decided_at=datetime.now(timezone.utc)))
            return saved[0]
        with patch.object(o, "prompt_for_approval", side_effect=stale_gate):
            report = self.cycle()
        self.playbook.assert_not_called()
        self.assertEqual(report["final_incident_state"], "NOT_REPAIRED")
        self.assertTrue(report["memory"]["incident_stored"])

    def test_blocked_policy_never_prompts_or_runs_playbook(self):
        original = o.evaluate_policy
        def block_playbook(proposal):
            if proposal["action_type"] == "configuration_change":
                return dict(decision="block", calculated_risk="high", reasons=["Blocked by test policy"], allowed_actions=[], blocked_actions=[p.PLAYBOOK], requires_human_approval=True)
            return original(proposal)
        with patch.object(o, "evaluate_policy", side_effect=block_playbook), patch("agent.approval_gate.evaluate_policy", side_effect=block_playbook):
            report = self.cycle()
        self.playbook.assert_not_called()
        self.assertEqual(self.prompt.call_count, 1)
        self.assertEqual(report["final_incident_state"], "NOT_REPAIRED")
        self.assertTrue(report["memory"]["incident_stored"])

    def test_expired_approval_is_refused_by_existing_playbook(self):
        original = o.prompt_for_approval
        def expired(initial):
            if initial["action_type"] == "configuration_change":
                return apply_human_decision(initial, "approve", reviewer="tester", decided_at=datetime.now(timezone.utc) - timedelta(hours=1))
            return original(initial)
        with patch.object(o, "prompt_for_approval", side_effect=expired):
            report = self.cycle()
        self.assertEqual(report["playbook_attempt"]["execution"]["status"], "REFUSED")
        self.assertEqual(report["final_incident_state"], "NOT_REPAIRED")
        self.assertTrue(json.loads(self.control.read_text())["simulate_failure"])

    def test_historical_approval_never_skips_second_prompt(self):
        self.cycle()
        self.control.write_text('{"simulate_failure": true}')
        self.prompt.side_effect = ["approve", "reject"]
        self.playbook.reset_mock()
        report = self.cycle()
        self.playbook.assert_not_called()
        self.assertGreater(report["memory"]["similar_historical_incidents_found"], 0)
        self.assertEqual(report["final_incident_state"], "NOT_REPAIRED")

    def test_memory_rejects_false_healthy_claim_and_redacts_nested_details(self):
        self.cycle()
        record = load_incidents(self.path)[0]
        record["playbook_attempt"]["repair_verified"] = True
        with self.assertRaises(ValueError):
            append_incident(record, self.path)
        record["playbook_attempt"]["repair_verified"] = False
        record["playbook_attempt"]["proposal"]["validation_steps"] = ["password=private-value"]
        append_incident(record, self.path)
        self.assertNotIn("private-value", self.path.read_text())

    def test_playbook_exception_is_not_retried_or_claimed_repaired(self):
        self.playbook.side_effect = RuntimeError("private-error")
        report = self.cycle()
        self.assertEqual(self.playbook.call_count, 1)
        self.assertEqual(report["final_incident_state"], "INCONCLUSIVE")
        self.assertTrue(report["memory"]["incident_stored"])
        self.assertNotIn("private-error", self.output.getvalue())


if __name__ == "__main__":
    unittest.main()
