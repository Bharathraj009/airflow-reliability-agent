"""Use temporary roots only; never modify the real demo control."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from agent import remediation_playbooks as p
from agent.approval_gate import create_approval_record, apply_human_decision
from agent.policy_engine import evaluate_policy


class DemoPlaybookTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.path = self.root / p.CONTROL_RELATIVE
        self.path.parent.mkdir()
        self.path.write_text('{"simulate_failure": true}', encoding="utf-8")
        for target, kwargs in (("agent.remediation_playbooks.PROJECT_ROOT", {"new": self.root}),
                               ("urllib.request.OpenerDirector.open", {"side_effect": AssertionError("No network")})):
            guard = patch(target, **kwargs)
            guard.start()
            self.addCleanup(guard.stop)
        self.context = dict(dag_id="reliability_demo", dag_run_id="current-run", task_id="process_data",
                            exception_type="ValueError", exception_message=p.FAILURE_SIGNATURE)
        self.proposal = p.build_playbook_proposal(self.context)
        self.policy = evaluate_policy(self.proposal)
        self.now = datetime(2026, 9, 21, 12, tzinfo=timezone.utc)
        self.pending = create_approval_record(self.context, self.proposal, self.policy, approval_id="current-approval")
        self.approval = apply_human_decision(self.pending, "approve", reviewer="tester", decided_at=self.now)

    def run_playbook(self, **kwargs):
        args = dict(context=self.context, proposal=self.proposal, policy=self.policy, approval=self.approval,
                    current_approval_id="current-approval", now=self.now)
        args.update(kwargs)
        return p.run_playbook(**args)

    def test_exact_selection_and_nonmatches(self):
        self.assertEqual(p.identify_playbook(self.context), p.PLAYBOOK)
        for field, value in (("dag_id", "production"), ("task_id", "other"), ("exception_type", "KeyError"), ("exception_message", "customer_id unrelated error")):
            self.assertIsNone(p.identify_playbook(dict(self.context, **{field: value})))
        self.assertIsNone(p.identify_playbook(None))

    def test_approved_current_fixed_change(self):
        self.assertEqual(self.policy["calculated_risk"], "medium")
        self.assertEqual(self.policy["allowed_actions"], [p.PLAYBOOK])
        result = self.run_playbook()
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(json.loads(self.path.read_text()), {"simulate_failure": False})
        self.assertEqual(result["changes"][0]["target"], p.CONTROL_RELATIVE)
        self.assertEqual(self.run_playbook()["status"], "REFUSED")

    def test_nonapproved_and_historical_refused(self):
        rejected = apply_human_decision(self.pending, "reject", reviewer="tester", decided_at=self.now)
        for approval in (self.pending, rejected, dict(self.pending, status="BLOCKED", policy_decision="block"),
                         dict(self.approval, dag_run_id="old-run"), dict(self.approval, approval_id="old-approval"),
                         {"status": "APPROVED", "historical_only": True}):
            with self.subTest(approval=approval):
                self.assertEqual(self.run_playbook(approval=approval)["status"], "REFUSED")
                self.assertTrue(json.loads(self.path.read_text())["simulate_failure"])
        self.assertEqual(self.run_playbook(now=self.now + timedelta(hours=1))["status"], "REFUSED")

    def test_ai_text_and_paths_cannot_control_target(self):
        unrelated = self.root / "other.json"
        unrelated.write_text("untouched")
        for proposal in (dict(self.proposal, target=str(unrelated)), dict(self.proposal, proposed_action="Write arbitrary file elsewhere")):
            self.assertEqual(self.run_playbook(proposal=proposal)["status"], "REFUSED")
        self.assertEqual(unrelated.read_text(), "untouched")
        with self.assertRaises(TypeError):
            self.run_playbook(path=unrelated)

    def test_unexpected_states_refused_without_modification(self):
        for contents in ('{"simulate_failure": false}', '{}', 'broken', '{"simulate_failure": 1}', '{"simulate_failure": true, "extra": 1}'):
            self.path.write_text(contents)
            self.assertEqual(self.run_playbook()["status"], "REFUSED")
            self.assertEqual(self.path.read_text(), contents)
        self.path.unlink()
        self.assertEqual(self.run_playbook()["status"], "REFUSED")
        self.assertFalse(self.path.exists())

    def test_forged_policy_and_mismatched_approval_refused(self):
        self.assertEqual(self.run_playbook(policy=dict(self.policy, allowed_actions=["configuration_change"]))["status"], "REFUSED")
        self.assertEqual(self.run_playbook(approval=dict(self.approval, proposed_action="Different action"))["status"], "REFUSED")

    def test_dangerous_policy_rules_still_override_named_permission(self):
        proposal = dict(self.proposal, validation_steps=["DROP TABLE customers"])
        self.assertEqual(evaluate_policy(proposal)["decision"], "block")

    def test_final_verification_failure_is_reported(self):
        with patch.object(Path, "read_text", return_value='{"simulate_failure": true}'):
            result = self.run_playbook()
        self.assertEqual(result["status"], "FAILED")
        self.assertTrue(result["changes"])


if __name__ == "__main__":
    unittest.main()
