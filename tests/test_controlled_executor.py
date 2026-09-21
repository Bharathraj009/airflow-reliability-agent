"""Offline boundary tests; no live Airflow/Groq pipeline is used."""

import copy
from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch

from agent.approval_gate import create_approval_record, apply_human_decision
from agent.controlled_executor import execute_approved_operation
from agent.policy_engine import evaluate_policy
from agent.remediation_planner import NO_CHANGE_ROLLBACK


class ControlledExecutorTests(unittest.TestCase):
    def setUp(self):
        network = patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("Network forbidden"))
        network.start()
        self.addCleanup(network.stop)
        self.time = datetime(2026, 9, 21, 12, tzinfo=timezone.utc)
        self.context = {"dag_id": "demo", "dag_run_id": "run-1", "task_id": "process_data"}
        self.proposal = {
            "incident_summary": "Missing field", "proposed_action": "Inspect upstream schema",
            "action_type": "investigation", "target": "Source schema", "reason": "Missing field",
            "risk_level": "low", "confidence": 0.8, "requires_human_approval": True,
            "validation_steps": ["Confirm required fields are present."],
            "rollback_plan": NO_CHANGE_ROLLBACK,
        }
        self.refresh_approval()

    def refresh_approval(self, decision="approve"):
        self.policy = evaluate_policy(self.proposal)
        pending = create_approval_record(self.context, self.proposal, self.policy, approval_id="approval-1")
        self.approval = apply_human_decision(pending, decision, reviewer="local-tester", decided_at=self.time)

    def run_operation(self, **overrides):
        args = dict(approval=self.approval, proposal=self.proposal, policy=self.policy,
                    context=self.context, execution_id="execution-1",
                    started_at=self.time, completed_at=self.time + timedelta(seconds=1))
        args.update(overrides)
        return execute_approved_operation(**args)

    def assert_refused(self, **overrides):
        result = self.run_operation(**overrides)
        self.assertEqual(result["status"], "REFUSED")
        self.assertIs(result["result"]["mutations_performed"], False)

    def test_approved_read_only_completes_without_mutation(self):
        before = copy.deepcopy((self.approval, self.proposal, self.policy, self.context))
        result = self.run_operation()
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["operation"], "read_only_investigation")
        self.assertEqual(result["approval_id"], "approval-1")
        self.assertIs(result["result"]["mutations_performed"], False)
        self.assertEqual(result, self.run_operation())
        self.assertEqual(before, (self.approval, self.proposal, self.policy, self.context))

    def test_pending_rejected_and_blocked_refused(self):
        for decision in ("", "reject"):
            with self.subTest(decision=decision):
                self.refresh_approval(decision)
                self.assert_refused()
        self.proposal["proposed_action"] = "DROP TABLE customers"
        self.refresh_approval()
        self.assertEqual(self.approval["status"], "BLOCKED")
        self.assert_refused()

    def test_approved_other_action_types_refused(self):
        for action in ("code_change", "configuration_change", "data_correction", "no_change"):
            with self.subTest(action=action):
                self.proposal["action_type"] = action
                self.refresh_approval()
                self.assertEqual(self.approval["status"], "APPROVED")
                self.assert_refused()
                self.assert_refused(operation=action)

    def test_unallowlisted_operations_refused(self):
        for operation in ("arbitrary_command", "DROP TABLE customers", "rerun_task", None, []):
            with self.subTest(operation=operation):
                self.assert_refused(operation=operation)

    def test_shell_sql_text_cannot_be_executed(self):
        for text in ("bash -c 'touch sentinel'", "DROP TABLE customers", "powershell Remove-Item data"):
            with self.subTest(text=text):
                proposal = dict(self.proposal, proposed_action=text)
                approval = dict(self.approval, proposed_action=text)
                self.assert_refused(proposal=proposal, approval=approval, policy=evaluate_policy(proposal))

    def test_malformed_and_tampered_approvals_refused(self):
        for approval in (None, {}, dict(self.approval, approved_by=None),
                         dict(self.approval, decision_timestamp="bad"),
                         dict(self.approval, policy_decision="allow"),
                         dict(self.approval, calculated_risk="high"),
                         dict(self.approval, proposed_action="Inspect a different schema"),
                         dict(self.approval, task_id="other_task")):
            with self.subTest(approval=approval):
                self.assert_refused(approval=approval)

    def test_policy_context_and_timing_mismatches_refused(self):
        self.assert_refused(policy=dict(self.policy, allowed_actions=[]))
        self.assert_refused(context=dict(self.context, dag_run_id="other_run"))
        self.assert_refused(proposal={})
        self.assert_refused(started_at=self.time - timedelta(seconds=1))
        self.assert_refused(completed_at=self.time - timedelta(seconds=1))
        self.assert_refused(started_at=datetime(2026, 9, 21))


if __name__ == "__main__":
    unittest.main()
