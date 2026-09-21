"""CLI wiring tests using the real approval gate/core and mocked data sources."""

from contextlib import ExitStack, redirect_stdout
import io
import json
import unittest
from unittest.mock import patch

from agent.controlled_executor import main
from agent.remediation_planner import NO_CHANGE_ROLLBACK


class ControlledExecutorCliTests(unittest.TestCase):
    def run_cli(self, command="approve", action_type="investigation", action="Inspect upstream schema", empty=False):
        context = {"dag_id": "demo", "dag_run_id": "run-1", "task_id": "process_data"}
        proposal = {
            "incident_summary": "Missing field", "proposed_action": action,
            "action_type": action_type, "target": "Source schema", "reason": "Missing field",
            "risk_level": "low", "confidence": 0.8, "requires_human_approval": True,
            "validation_steps": ["Confirm required fields are present."],
            "rollback_plan": NO_CHANGE_ROLLBACK,
        }
        with ExitStack() as stack:
            stack.enter_context(patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("Live network forbidden")))
            stack.enter_context(patch.dict("os.environ", {"GROQ_API_KEY": "test", "AIRFLOW_API_USERNAME": "user", "AIRFLOW_API_PASSWORD": "password"}))
            stack.enter_context(patch("sys.argv", ["executor", "--task-id", "process_data"]))
            stack.enter_context(patch("agent.failure_detector.request_json", return_value={"access_token": "token"}))
            collect = stack.enter_context(patch("agent.log_collector.collect_failed_task_logs", return_value={}))
            stack.enter_context(patch("agent.context_extractor.extract_failure_contexts", return_value=[] if empty else [context]))
            analyze = stack.enter_context(patch("agent.rca_analyzer.analyze_context", return_value={"summary": "test RCA"}))
            stack.enter_context(patch("agent.remediation_planner.propose_remediation", return_value=proposal))
            prompt = stack.enter_context(patch("builtins.input", side_effect=command if isinstance(command, type) else None, return_value=command))
            stack.enter_context(patch("agent.approval_gate.getpass.getuser", return_value="local-tester"))
            output = stack.enter_context(redirect_stdout(io.StringIO()))
            self.assertEqual(main(), 0)
            collect.assert_called_once_with("token", "process_data")
            return output.getvalue(), prompt.call_count, analyze.call_count

    def test_approved_investigation_completes_and_displays_pipeline(self):
        text, prompts, _ = self.run_cli()
        headings = ["Failure Context:", "AI RCA:", "Remediation Proposal:", "Policy Decision:", "Approval Summary:", "Controlled Execution Result:"]
        positions = [text.index(heading) for heading in headings]
        self.assertEqual(positions, sorted(positions))
        result = json.loads(text.split("Controlled Execution Result:\n")[1])
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["operation"], "read_only_investigation")
        self.assertIs(result["result"]["mutations_performed"], False)
        self.assertEqual(prompts, 1)

    def test_rejected_invalid_and_interrupted_are_refused(self):
        for command in ("reject", "", "yes", "APPROVE", EOFError, KeyboardInterrupt):
            with self.subTest(command=command):
                text, _, _ = self.run_cli(command)
                result = json.loads(text.split("Controlled Execution Result:\n")[1])
                self.assertEqual(result["status"], "REFUSED")

    def test_blocked_never_prompts(self):
        text, prompts, _ = self.run_cli(action="DROP TABLE customers")
        self.assertEqual(prompts, 0)
        self.assertIn('"status": "REFUSED"', text)

    def test_approved_code_change_still_refused(self):
        text, prompts, _ = self.run_cli(action_type="code_change")
        self.assertEqual(prompts, 1)
        self.assertIn('"status": "REFUSED"', text)

    def test_no_context_does_not_prompt_or_analyze(self):
        text, prompts, analyses = self.run_cli(empty=True)
        self.assertEqual((prompts, analyses), (0, 0))
        self.assertIn("No matching failed tasks", text)

    def test_help_works_without_credentials_or_network(self):
        with patch("sys.argv", ["executor", "--help"]), patch.dict("os.environ", {}, clear=True), redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(SystemExit) as exit_info:
                main()
            self.assertEqual(exit_info.exception.code, 0)
            self.assertIn("--task-id", output.getvalue())


if __name__ == "__main__":
    unittest.main()
