"""Offline regression tests: no Airflow, Groq, or remediation execution."""

import unittest

from agent.policy_engine import evaluate_policy
from agent.remediation_planner import NO_CHANGE_ROLLBACK


class PolicyClassificationTests(unittest.TestCase):
    def proposal(self, action="Inspect upstream schema", steps=None):
        return {
            "incident_summary": "Required source field is missing.",
            "proposed_action": action,
            "action_type": "investigation",
            "target": "Upstream schema",
            "reason": "Determine whether the required field is present.",
            "risk_level": "low",
            "confidence": 0.8,
            "requires_human_approval": True,
            "validation_steps": steps or ["Confirm required fields are present."],
            "rollback_plan": NO_CHANGE_ROLLBACK,
        }

    def check_decision(self, proposal, decision, risk):
        result = evaluate_policy(proposal)
        self.assertEqual(result["decision"], decision)
        self.assertEqual(result["calculated_risk"], risk)
        self.assertIs(result["requires_human_approval"], True)
        return result

    def test_read_only_investigation(self):
        self.check_decision(self.proposal(), "require_approval", "low")

    def test_current_modification_is_blocked(self):
        result = self.check_decision(
            self.proposal(action="Update production schema"), "block", "high"
        )
        self.assertIn("action_type_mismatch", result["blocked_actions"])

    def test_future_validation_does_not_reclassify_current_action(self):
        for instruction in ("correct source data", "update schema", "rerun the task", "trigger the DAG"):
            with self.subTest(instruction=instruction):
                proposal = self.proposal(steps=[
                    f"After a future separately approved remediation, {instruction} and confirm success."
                ])
                self.check_decision(proposal, "require_approval", "low")
                proposal.update(action_type="no_change", proposed_action="No change is proposed.")
                self.check_decision(proposal, "allow", "low")

    def test_dangerous_validation_steps_remain_blocked(self):
        for instruction in (
            "DROP TABLE customers", "DELETE FROM customers", "TRUNCATE customers",
            "Expose API keys", "Bypass approval", "Execute arbitrary shell code",
            "docker compose down --volumes", "Destroy infrastructure",
        ):
            with self.subTest(instruction=instruction):
                result = self.check_decision(
                    self.proposal(steps=[instruction]), "block", "high"
                )
                self.assertNotIn("action_type_mismatch", result["blocked_actions"])
                self.assertTrue(result["blocked_actions"])


if __name__ == "__main__":
    unittest.main()
