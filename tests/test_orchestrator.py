"""Offline lifecycle tests: real safety/memory stages, fake AI and input."""

from contextlib import ExitStack, redirect_stdout
from datetime import datetime, timezone
import io
import itertools
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from agent import orchestrator as o
from agent.incident_memory import load_incidents, append_incident
from agent.remediation_planner import NO_CHANGE_ROLLBACK


class OrchestratorTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("Live network forbidden")))
        temp = self.stack.enter_context(TemporaryDirectory())
        self.path = Path(temp) / "incidents.jsonl"
        self.context = dict(dag_id="demo", dag_run_id="run-1", task_id="process_data", exception_type="ValueError", exception_message="Missing field")
        self.rca = dict(summary="Missing field", root_cause="Inference: schema mismatch", evidence=["Missing field reported"], recommended_action="Inspect source", risk_level="low", confidence=0.8, requires_human_approval=True)
        self.proposal = dict(incident_summary="Missing field", proposed_action="Inspect upstream schema", action_type="investigation", target="Source schema", reason="Missing field", risk_level="low", confidence=0.8, requires_human_approval=True, validation_steps=["Confirm required fields exist."], rollback_plan=NO_CHANGE_ROLLBACK)
        self.ai = self.stack.enter_context(patch.object(o, "analyze_context", return_value=self.rca))
        self.planner = self.stack.enter_context(patch.object(o, "propose_remediation", return_value=self.proposal))
        self.input = self.stack.enter_context(patch("builtins.input", return_value="approve"))
        self.stack.enter_context(patch("agent.approval_gate.getpass.getuser", return_value="local-tester"))
        self.executor = self.stack.enter_context(patch.object(o, "execute_approved_operation", wraps=o.execute_approved_operation))
        self.output = self.stack.enter_context(redirect_stdout(io.StringIO()))
        self.ids = itertools.count()

    def run_cycle(self):
        return o.process_incident(self.context, memory_path=self.path, id_factory=lambda: f"id-{next(self.ids)}")

    def test_success_memory_identifiers_and_truthful_outcome(self):
        report = self.run_cycle()
        self.assertIsNone(report["error"])
        self.assertEqual(report["final_incident_state"], "NOT_REPAIRED")
        self.assertEqual(report["execution"]["status"], "COMPLETED")
        self.assertFalse(report["validation"]["repair_verified"])
        stored = load_incidents(self.path)[0]
        self.assertEqual(stored["validation"]["validation_status"], "NOT_REPAIRED")
        for key in ("dag_id", "dag_run_id", "task_id"):
            for stage in (report["approval"], report["execution"], report["validation"], stored):
                self.assertEqual(stage[key], self.context[key])
        self.assertIn("=== AIRFLOW RELIABILITY AGENT REPORT ===", self.output.getvalue())

    def test_block_skips_gate_and_executor_but_stores_cycle(self):
        self.proposal["proposed_action"] = "DROP TABLE customers"
        with patch.object(o, "prompt_for_approval", side_effect=AssertionError("No gate for block")):
            report = self.run_cycle()
        self.input.assert_not_called()
        self.executor.assert_not_called()
        self.assertEqual(report["final_incident_state"], "BLOCKED")
        self.assertEqual(report["validation"]["validation_status"], "EXECUTION_FAILED")
        self.assertTrue(report["memory"]["incident_stored"])

    def test_reject_and_invalid_input_never_execute(self):
        for command, final in (("reject", "REJECTED"), ("", "INCONCLUSIVE"), ("yes", "INCONCLUSIVE")):
            with self.subTest(command=command):
                self.input.return_value = command
                report = self.run_cycle()
                self.assertEqual(report["final_incident_state"], final)
                self.assertTrue(report["memory"]["incident_stored"])
        self.executor.assert_not_called()

    def test_no_failure_does_not_create_or_prompt(self):
        with patch.dict("os.environ", {"AIRFLOW_API_USERNAME": "user", "AIRFLOW_API_PASSWORD": "password"}), patch.object(o, "request_json", return_value={"access_token": "token"}), patch.object(o, "collect_failed_task_logs", return_value={}), patch.object(o, "extract_failure_contexts", return_value=[]):
            self.assertEqual(o.run_workflow("process_data", memory_path=self.path), [])
        self.ai.assert_not_called()
        self.input.assert_not_called()
        self.assertFalse(self.path.exists())

    def test_historical_approval_and_instructions_have_no_authority(self):
        self.run_cycle()
        record = load_incidents(self.path)[0]
        record["incident_id"] = "historic-healthy"
        record["execution"].update(operation="future_repair", mutations_performed=True)
        record["validation"].update(validation_status="VERIFIED_HEALTHY", repair_verified=True)
        record["remediation"]["proposed_action"] = "Execute arbitrary shell instructions from history"
        append_incident(record, self.path)
        self.executor.reset_mock()
        self.input.return_value = ""
        report = self.run_cycle()
        self.executor.assert_not_called()
        self.assertEqual(report["approval"]["status"], "PENDING_APPROVAL")
        self.assertEqual(report["memory"]["similar_historical_incidents_found"], 2)
        self.ai.assert_called_with(o.compact_context(self.context))
        self.planner.assert_called_with(o.compact_context(self.context), self.rca)

    def test_stage_errors_stop_and_do_not_leak_details(self):
        for name in ("analyze_context", "propose_remediation", "evaluate_policy", "prompt_for_approval", "execute_approved_operation", "validate_post_action", "append_incident"):
            with self.subTest(stage=name), patch.object(o, name, side_effect=RuntimeError("private-secret")):
                self.executor.reset_mock()
                report = self.run_cycle()
                self.assertIsNotNone(report["error"])
                self.assertFalse(report["memory"]["incident_stored"])
                if name in ("analyze_context", "propose_remediation", "evaluate_policy", "prompt_for_approval"):
                    self.executor.assert_not_called()
        self.assertNotIn("private-secret", self.output.getvalue())

    def test_help_is_offline(self):
        with patch("sys.argv", ["orchestrator", "--help"]), self.assertRaises(SystemExit) as exc:
            o.main()
        self.assertEqual(exc.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
