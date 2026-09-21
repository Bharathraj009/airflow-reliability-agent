"""Offline approval-state tests. Never invoke the live AI/Airflow pipeline."""

from contextlib import redirect_stdout
from datetime import datetime, timezone
import io
import unittest
from unittest.mock import patch

from agent.approval_gate import (
    apply_human_decision, create_approval_record, prompt_for_approval,
)
from agent.policy_engine import evaluate_policy
from agent.remediation_planner import NO_CHANGE_ROLLBACK


class ApprovalGateTests(unittest.TestCase):
    def setUp(self):
        # Fail the test if gate evaluation accidentally attempts network I/O.
        network = patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("Network forbidden"))
        network.start()
        self.addCleanup(network.stop)
        self.context = {"dag_id": "demo", "dag_run_id": "run-1", "task_id": "process_data"}
        self.proposal = {
            "incident_summary": "Missing field", "proposed_action": "Inspect upstream schema",
            "action_type": "investigation", "target": "Source schema", "reason": "Missing field reported",
            "risk_level": "low", "confidence": 0.8, "requires_human_approval": True,
            "validation_steps": ["Confirm required fields are present."],
            "rollback_plan": NO_CHANGE_ROLLBACK,
        }
        self.time = datetime(2026, 9, 21, 12, 30, tzinfo=timezone.utc)

    def record(self):
        return create_approval_record(
            self.context, self.proposal, evaluate_policy(self.proposal), approval_id="test-approval-1",
        )

    def decide(self, record, command):
        return apply_human_decision(record, command, reviewer="local-tester", decided_at=self.time)

    def test_require_approval_initially_pending(self):
        record = self.record()
        self.assertEqual(record["status"], "PENDING_APPROVAL")
        self.assertIsNone(record["approved_by"])
        self.assertIsNone(record["decision_timestamp"])

    def test_explicit_approve(self):
        initial = self.record()
        approved = self.decide(initial, "approve")
        self.assertEqual(approved["status"], "APPROVED")
        self.assertEqual(approved["approved_by"], "local-tester")
        self.assertEqual(approved["decision_timestamp"], "2026-09-21T12:30:00+00:00")
        self.assertEqual(initial["status"], "PENDING_APPROVAL")

    def test_explicit_reject(self):
        rejected = self.decide(self.record(), "reject")
        self.assertEqual(rejected["status"], "REJECTED")
        self.assertEqual(rejected["approved_by"], "local-tester")
        self.assertEqual(rejected["decision_timestamp"], self.time.isoformat())
        self.assertEqual(self.decide(rejected, "approve"), rejected)

    def test_invalid_input_never_approves(self):
        record = self.record()
        for command in ("", "yes", "y", "APPROVE", " approve", "approve ", "anything", None):
            with self.subTest(command=command):
                self.assertEqual(self.decide(record, command), record)

    def test_blocked_cannot_be_approved_or_prompted(self):
        self.proposal["proposed_action"] = "DROP TABLE customers"
        record = self.record()
        self.assertEqual(record["status"], "BLOCKED")
        self.assertEqual(self.decide(record, "approve"), record)
        with patch("builtins.input", side_effect=AssertionError("Must not prompt")), redirect_stdout(io.StringIO()):
            self.assertEqual(prompt_for_approval(record), record)

    def test_allow_still_requires_human(self):
        self.proposal.update(action_type="no_change", proposed_action="No change is proposed.")
        record = self.record()
        self.assertEqual(record["policy_decision"], "allow")
        self.assertEqual(record["status"], "PENDING_APPROVAL")
        self.assertEqual(self.decide(record, "approve")["status"], "APPROVED")

    def test_cli_explicit_commands_and_interruptions(self):
        record = self.record()
        for command, status in (("approve", "APPROVED"), ("reject", "REJECTED"), ("yes", "PENDING_APPROVAL"), ("", "PENDING_APPROVAL")):
            with self.subTest(command=command), patch("builtins.input", return_value=command), patch("agent.approval_gate.getpass.getuser", return_value="local-tester"), redirect_stdout(io.StringIO()):
                self.assertEqual(prompt_for_approval(record)["status"], status)
        for interruption in (EOFError, KeyboardInterrupt):
            with patch("builtins.input", side_effect=interruption), redirect_stdout(io.StringIO()):
                self.assertEqual(prompt_for_approval(record), record)

    def test_mismatched_policy_and_malformed_context_rejected(self):
        policy = evaluate_policy(self.proposal)
        with self.assertRaises(RuntimeError):
            create_approval_record(self.context, self.proposal, dict(policy, decision="allow"), approval_id="test")
        with self.assertRaises(RuntimeError):
            create_approval_record({}, self.proposal, policy, approval_id="test")

    def test_decision_requires_identity_and_aware_time(self):
        for reviewer, timestamp in (("", self.time), ("local-tester", datetime(2026, 9, 21))):
            with self.assertRaises(RuntimeError):
                apply_human_decision(self.record(), "approve", reviewer=reviewer, decided_at=timestamp)


if __name__ == "__main__":
    unittest.main()
