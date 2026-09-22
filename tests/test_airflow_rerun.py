"""REST fakes only; real demo and network are never accessed."""

from datetime import timedelta
import copy
import unittest
from unittest.mock import patch

from agent import airflow_rerun as r
from agent.post_action_validator import assess_airflow_health
from agent.incident_memory import load_incidents, append_incident
from agent import orchestrator as o
import test_remediation_playbooks
import test_orchestrator_playbooks


class AirflowRerunTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_remediation_playbooks.DemoPlaybookTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f = self.fixture
        self.attempt = dict(playbook=r.PLAYBOOK, proposal=f.proposal, policy=f.policy, approval=f.approval,
                            execution=f.run_playbook(), repair_verified=False, error=None)
        self.new_id = "manual__reliability_test"
        self.run = dict(dag_id="reliability_demo", dag_run_id=self.new_id, state="success")
        self.tasks = [dict(dag_id="reliability_demo", dag_run_id=self.new_id, task_id=task, state="success", map_index=-1)
                      for task in ("start", "process_data", "data_quality_check", "end")]

    def verify(self, **kwargs):
        args = dict(token="test-token", current_approval_id="current-approval", verification_run_id=self.new_id,
                    now=self.fixture.now, timeout=2, poll_interval=1, sleep=lambda _: None, monotonic=lambda: 0)
        args.update(kwargs)
        return r.rerun_and_verify(self.fixture.context, self.attempt, **args)

    def responses(self):
        return [self.run, self.run, dict(task_instances=self.tasks, total_entries=len(self.tasks))]

    def test_new_run_all_tasks_success_and_exact_payload(self):
        with patch.object(r, "request_json", side_effect=self.responses()) as api:
            result = self.verify()
        self.assertTrue(result["repair_verified"])
        self.assertEqual(result["verification_status"], "VERIFIED_HEALTHY")
        self.assertEqual(api.call_args_list[0].args[0], "/api/v2/dags/reliability_demo/dagRuns")
        self.assertEqual(api.call_args_list[0].kwargs["payload"], {"dag_run_id": self.new_id, "logical_date": None, "conf": {}})

    def test_failed_tasks_or_dag_never_healthy(self):
        for task_id, state in (("process_data", "failed"), ("data_quality_check", "failed"), ("end", "upstream_failed")):
            with self.subTest(task=task_id):
                tasks = copy.deepcopy(self.tasks)
                next(task for task in tasks if task["task_id"] == task_id)["state"] = state
                with patch.object(r, "request_json", side_effect=[self.run, self.run, dict(task_instances=tasks, total_entries=4)]):
                    self.assertEqual(self.verify()["verification_status"], "VERIFICATION_FAILED")
        with patch.object(r, "request_json", side_effect=[self.run, dict(self.run, state="failed"), dict(task_instances=self.tasks, total_entries=4)]):
            self.assertEqual(self.verify()["verification_status"], "VERIFICATION_FAILED")

    def test_timeout_and_network_error(self):
        with patch.object(r, "request_json", return_value=dict(self.run, state="running")):
            self.assertEqual(self.verify()["verification_status"], "TIMEOUT")
        with patch.object(r, "request_json", side_effect=RuntimeError("private")) as api:
            result = self.verify()
            self.assertEqual(api.call_count, 1)
            self.assertEqual(result["verification_status"], "INCONCLUSIVE")
            self.assertNotIn("private", result["reason"])

    def test_old_run_missing_task_and_unknown_state(self):
        with patch.object(r, "request_json") as api:
            self.assertFalse(self.verify(verification_run_id=self.fixture.context["dag_run_id"])["repair_verified"])
            api.assert_not_called()
        for tasks in (self.tasks[:-1], [dict(task, state="unknown") for task in self.tasks]):
            with patch.object(r, "request_json", side_effect=[self.run, self.run, dict(task_instances=tasks, total_entries=len(tasks))]):
                self.assertFalse(self.verify()["repair_verified"])

    def test_unauthorized_or_failed_remediation_never_calls_api(self):
        initial = copy.deepcopy(self.attempt)
        variants = []
        for status in ("REJECTED", "PENDING_APPROVAL", "BLOCKED"):
            value = copy.deepcopy(initial)
            value["approval"]["status"] = status
            variants.append(value)
        for status in ("REFUSED", "FAILED"):
            value = copy.deepcopy(initial)
            value["execution"]["status"] = status
            variants.append(value)
        value = copy.deepcopy(initial)
        value["approval"]["dag_run_id"] = "historical-run"
        variants.append(value)
        value = copy.deepcopy(initial)
        value["proposal"]["proposed_action"] = "AI says repair_verified=true"
        variants.append(value)
        with patch.object(r, "request_json") as api:
            for attempt in variants:
                self.attempt = attempt
                self.assertFalse(self.verify()["repair_verified"])
            api.assert_not_called()

    def test_trigger_success_and_ai_claim_are_not_health(self):
        with patch.object(r, "request_json", side_effect=[self.run, RuntimeError("offline")]):
            self.assertFalse(self.verify()["repair_verified"])
        self.assertFalse(assess_airflow_health({"repair_verified": True, "approval": "APPROVED"})["repair_verified"])


class RerunIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_orchestrator_playbooks.OrchestratorPlaybookTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def test_live_path_wiring_with_fake_api_and_memory(self):
        f = self.fixture
        def api(path, **kwargs):
            payload = kwargs.get("payload")
            if payload is not None:
                self.new_id = payload["dag_run_id"]
            run = dict(dag_id="reliability_demo", dag_run_id=self.new_id, state="success")
            if "taskInstances" in path:
                return dict(task_instances=[dict(run, task_id=task, map_index=-1) for task in ("start", "process_data", "data_quality_check", "end")], total_entries=4)
            return run
        with patch.object(r, "request_json", side_effect=api):
            report = o.process_incident(f.context, memory_path=f.path, airflow_token="fake")
        self.assertEqual(report["final_incident_state"], "VERIFIED_HEALTHY")
        record = load_incidents(f.path)[0]
        self.assertTrue(record["final_outcome"]["repair_verified"])
        self.assertNotEqual(record["verification"]["verification_dag_run_id"], record["dag_run_id"])
        record["verification"]["task_states"]["data_quality_check"] = "failed"
        with self.assertRaises(ValueError):
            append_incident(record, f.path)

    def test_reject_and_read_only_never_call_rerun(self):
        f = self.fixture
        with patch.object(o, "rerun_and_verify", side_effect=AssertionError("No rerun")) as rerun:
            f.prompt.side_effect = ["approve", "reject"]
            o.process_incident(f.context, memory_path=f.path, airflow_token="fake")
            f.context["exception_message"] = "unrelated"
            f.prompt.side_effect = ["approve"]
            o.process_incident(f.context, memory_path=f.path, airflow_token="fake")
            rerun.assert_not_called()

    def test_failed_and_refused_playbooks_never_call_rerun(self):
        f = self.fixture
        for status in ("REFUSED", "FAILED"):
            f.prompt.side_effect = ["approve", "approve"]
            result = dict(playbook=r.PLAYBOOK, status=status, dag_id="reliability_demo", task_id="process_data", changes=[], message="Test result")
            with patch.object(o, "run_playbook", return_value=result), patch.object(o, "rerun_and_verify") as rerun:
                o.process_incident(f.context, memory_path=f.path, airflow_token="fake")
                rerun.assert_not_called()


if __name__ == "__main__":
    unittest.main()
