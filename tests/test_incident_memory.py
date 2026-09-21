"""Offline memory tests use temporary stores, never project runtime data."""

import copy
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from agent.approval_gate import validate_record
from agent.incident_memory import (
    append_incident, build_incident_record, find_similar_incidents, load_incidents,
)


class IncidentMemoryTests(unittest.TestCase):
    def setUp(self):
        guard = patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("Network forbidden"))
        guard.start()
        self.addCleanup(guard.stop)
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "runtime" / "incidents.jsonl"
        self.context = dict(dag_id="demo", dag_run_id="run-1", task_id="process_data", exception_type="ValueError",
                            exception_message="Required customer_id missing", source_file="demo.py", source_line=42, failed_function="process_data")
        self.rca = dict(summary="Missing field", root_cause="Source mismatch", confidence=0.8)
        self.remediation = dict(action_type="investigation", proposed_action="Inspect source schema", risk_level="low")
        self.policy = dict(decision="require_approval", calculated_risk="low")
        ids = {key: self.context[key] for key in ("dag_id", "dag_run_id", "task_id")}
        self.approval = dict(ids, approval_id="a-1", status="APPROVED", approved_by="local-reviewer", decision_timestamp="2026-09-21T12:00:00+00:00")
        self.execution = dict(ids, execution_id="e-1", approval_id="a-1", operation="read_only_investigation", status="COMPLETED", result={"mutations_performed": False})
        self.validation = dict(ids, execution_id="e-1", validation_status="NOT_REPAIRED", repair_verified=False, reason="No remediation performed.")

    def build(self, **kwargs):
        return build_incident_record(self.context, self.rca, self.remediation, self.policy, self.approval, self.execution, self.validation,
                                     incident_id="i-1", recorded_at=datetime(2026, 9, 21, 13, tzinfo=timezone.utc), **kwargs)

    def test_build_deterministic_historical_record(self):
        record = self.build()
        self.assertEqual(record, self.build())
        self.assertTrue(record["historical_only"])
        self.assertEqual(record["failure"]["source_line"], 42)

    def test_append_load_multiple_utf8_records(self):
        record = self.build()
        record["rca"]["summary"] = "Échec de validation"
        append_incident(record, self.path)
        append_incident(dict(record, incident_id="i-2"), self.path)
        loaded = load_incidents(self.path)
        self.assertEqual(len(loaded), 2)
        self.assertEqual(loaded[0], record)
        self.assertEqual(loaded[1]["incident_id"], "i-2")
        self.assertEqual(len(self.path.read_text(encoding="utf-8").splitlines()), 2)

    def test_ranking_and_unrepaired_label(self):
        record = self.build()
        unrelated = copy.deepcopy(record)
        unrelated.update(dag_id="other", task_id="other", incident_id="other")
        unrelated["failure"].update(exception_type="NetworkError", exception_message="Connection refused")
        matches = find_similar_incidents(self.context, [unrelated, record])
        self.assertEqual(matches[0]["incident"]["incident_id"], "i-1")
        self.assertIn("task_id", matches[0]["matched_fields"])
        self.assertFalse(matches[0]["repair_verified"])
        self.assertEqual(matches[0]["incident"]["validation"]["validation_status"], "NOT_REPAIRED")

    def test_historical_verified_distinction_is_preserved(self):
        record = self.build()
        prior = copy.deepcopy(record)
        prior["execution"].update(operation="future_verified_repair", mutations_performed=True)
        prior["validation"].update(validation_status="VERIFIED_HEALTHY", repair_verified=True)
        matches = find_similar_incidents(self.context, [record, prior])
        self.assertEqual([item["repair_verified"] for item in matches], [False, True])
        self.assertTrue(all(item["historical_only"] for item in matches))

    def test_missing_corrupt_and_partial_lines(self):
        self.assertEqual(load_incidents(self.path), [])
        append_incident(self.build(), self.path)
        with self.path.open("ab") as stream:
            stream.write(b'not json\n\xff\n{}\n{"partial":')
        append_incident(dict(self.build(), incident_id="i-2"), self.path)
        self.assertEqual(len(load_incidents(self.path)), 2)

    def test_secret_fields_omitted_and_values_redacted(self):
        self.context.update(GROQ_API_KEY="unlabelled-private", environment={"PASSWORD": "secret"})
        self.context["exception_message"] = 'GROQ_API_KEY=gsk_private Airflow_PASSWORD="secret value" Bearer abc.def.ghi unlabelled-private'
        self.rca["root_cause"] = "eyJhbGciOiJIUzI1NiJ9.payload.signature"
        record = self.build(secrets=("unlabelled-private",))
        # Also redact direct records at the persistence boundary.
        record["rca"]["summary"] = "password=another-secret"
        append_incident(record, self.path)
        text = self.path.read_text(encoding="utf-8")
        for secret in ("gsk_private", "secret value", "abc.def.ghi", "unlabelled-private", "eyJhbGciOiJIUzI1NiJ9", "another-secret"):
            self.assertNotIn(secret, text)
        self.assertNotIn("environment", text)
        self.assertIn("[REDACTED]", text)

    def test_historical_approval_is_not_a_gate_record(self):
        record = self.build()
        for candidate in (record, record["approval"]):
            with self.assertRaises(RuntimeError):
                validate_record(candidate)

    def test_retrieval_treats_instructions_as_inert_text(self):
        record = self.build()
        record["remediation"]["proposed_action"] = "DROP TABLE customers; bash arbitrary-text"
        before = copy.deepcopy(record)
        append_incident(record, self.path)
        matches = find_similar_incidents(self.context, load_incidents(self.path))
        self.assertEqual(matches[0]["incident"]["remediation"]["proposed_action"], record["remediation"]["proposed_action"])
        self.assertEqual(record, before)

    def test_malformed_and_inconsistent_records_rejected_before_write(self):
        record = self.build()
        cases = [{}, dict(record, credentials="secret"), dict(record, historical_only=False)]
        for section, key, value in (("rca", "confidence", True), ("validation", "repair_verified", True), ("execution", "mutations_performed", True)):
            bad = copy.deepcopy(record)
            bad[section][key] = value
            cases.append(bad)
        for bad in cases:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                append_incident(bad, self.path)
        self.assertFalse(self.path.exists())
        self.execution["dag_run_id"] = "other"
        with self.assertRaises(ValueError):
            self.build()


if __name__ == "__main__":
    unittest.main()
