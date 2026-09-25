"""
testbed/runner/test_batch.py
============================
Unit tests for automated PCAP generation & batch orchestration (Fix #4).

Tests:
1. Matrix classification counts across all 126 scenarios (91 / 5 / 11 / 19).
2. Deterministic scenario ordering preserving canonical matrix sequence.
3. Dependency-aware preflight without requiring mailtest-mitm for standard runs.
4. Dependency-aware preflight requiring mailtest-mitm when MITM scenarios selected.
5. Pre-classification stale artifact cleanup for blocked/unresolvable scenarios.
6. Non-selected scenario artifacts remain untouched.
7. Stale artifact cleanup failure raises and records CLEANUP_FAILED.
8. Coherent batch resume strictly tied to unique run_id and manifest hashes.
9. Resume rejects altered, corrupted, or incomplete artifacts.
10. Complete artifact set validation (PCAP >0 bytes, all 3 schemas, evidence object).
11. Scenario-local failure isolation (batch continues to next scenario).
12. Comprehensive batch report generation (batch_report.json and batch_report.md).
"""

from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from testbed.runner.batch import (
    BatchExecutionCategory,
    BatchOrchestrator,
    PreflightError,
    ResumeError,
    ScenarioBatchRecord,
    ScenarioExecutionState,
    check_preflight,
    classify_scenario,
    compute_file_sha256,
    verify_scenario_artifacts,
)
from testbed.runner.runner import (
    ScenarioExecutionResult,
    StaleArtifactCleanupError,
    cleanup_scenario_artifacts,
)
from testbed.runner.scenario_contract import GenerationMode, ScenarioContract
from testbed.runner.spec import ScenarioSpec


class TestBatchOrchestration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.orchestrator = BatchOrchestrator()

    def test_01_matrix_classification_counts(self):
        """
        Verify exact classification counts across all 126 scenario matrix rows:
        - 91 Executable Standard (85 configurable candidate selected + 6 cleartext not applicable)
        - 5 Blocked by daemon limitation (PCAP-009, PCAP-028, PCAP-047, PCAP-077, PCAP-090)
        - 11 Unresolvable (matrix oracle inconsistent)
        - 19 Special Harness (dedicated harnesses)
        Total: 126
        """
        specs = self.orchestrator.select_scenarios()
        self.assertEqual(len(specs), 126)

        counts = {
            BatchExecutionCategory.EXECUTABLE_STANDARD: 0,
            BatchExecutionCategory.BLOCKED: 0,
            BatchExecutionCategory.UNRESOLVABLE: 0,
            BatchExecutionCategory.SPECIAL_HARNESS: 0,
        }
        blocked_ids = []

        for spec in specs:
            contract = self.orchestrator.contracts[spec.scenario_id]
            classification = classify_scenario(spec, contract, self.orchestrator.resolver)
            counts[classification.category] += 1
            if classification.category == BatchExecutionCategory.BLOCKED:
                blocked_ids.append(spec.scenario_id)

        self.assertEqual(counts[BatchExecutionCategory.EXECUTABLE_STANDARD], 91)
        self.assertEqual(counts[BatchExecutionCategory.BLOCKED], 5)
        self.assertEqual(counts[BatchExecutionCategory.UNRESOLVABLE], 11)
        self.assertEqual(counts[BatchExecutionCategory.SPECIAL_HARNESS], 19)
        self.assertEqual(
            sorted(blocked_ids),
            ["PCAP-009", "PCAP-028", "PCAP-047", "PCAP-077", "PCAP-090"],
        )

    def test_02_deterministic_scenario_order(self):
        """
        Arbitrary or shuffled input order must be strictly sorted according to canonical matrix sequence.
        """
        shuffled = ["PCAP-043", "PCAP-005", "PCAP-024", "PCAP-004"]
        selected = self.orchestrator.select_scenarios(shuffled)
        ordered_ids = [s.scenario_id for s in selected]
        self.assertEqual(ordered_ids, ["PCAP-004", "PCAP-005", "PCAP-024", "PCAP-043"])

    @patch("shutil.which")
    @patch("subprocess.run")
    @patch("testbed.runner.batch.discover_docker_bridge")
    def test_03_dependency_aware_preflight_no_mitm(self, mock_bridge, mock_run, mock_which):
        """
        Standard batch (only SMTP / IMAP / POP3 standard scenarios) must NOT require mailtest-mitm.
        """
        mock_which.side_effect = lambda cmd: f"/usr/bin/{cmd}"
        mock_bridge.return_value = "br-test123456"
        # Only Postfix and Dovecot running, MITM not running
        mock_proc = MagicMock()
        mock_proc.stdout = "mailtest-postfix\nmailtest-dovecot\n"
        mock_run.return_value = mock_proc

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            captures_dir = tmp_path / "captures"
            active_dir = tmp_path / "active"

            # Select standard scenarios
            specs = [self.orchestrator.specs_by_id["PCAP-004"], self.orchestrator.specs_by_id["PCAP-024"]]
            info = check_preflight(
                selected_specs=specs,
                contracts=self.orchestrator.contracts,
                captures_dir=captures_dir,
                active_dir=active_dir,
            )
            self.assertIn("mailtest-postfix", info["required_services"])
            self.assertIn("mailtest-dovecot", info["required_services"])
            self.assertNotIn("mailtest-mitm", info["required_services"])

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_04_dependency_aware_preflight_mitm_required_when_selected(self, mock_run, mock_which):
        """
        When a scenario requiring MITM harness is selected, preflight must require mailtest-mitm.
        """
        mock_which.side_effect = lambda cmd: f"/usr/bin/{cmd}"
        # Only Postfix running; MITM missing
        mock_proc = MagicMock()
        mock_proc.stdout = "mailtest-postfix\n"
        mock_run.return_value = mock_proc

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            captures_dir = tmp_path / "captures"
            active_dir = tmp_path / "active"

            # Synthetic contract requiring mitm_proxy
            synthetic_spec = self.orchestrator.specs_by_id["PCAP-004"]
            synthetic_contract = ScenarioContract(
                scenario_id="PCAP-004",
                generation_mode=GenerationMode.DEDICATED_HARNESS,
                cipher_mode=self.orchestrator.contracts["PCAP-004"].cipher_mode,
                special_harness="mitm_starttls_strip",
                harness_status="NOT_IMPLEMENTED",
            )
            contracts = {"PCAP-004": synthetic_contract}

            with self.assertRaises(PreflightError) as ctx:
                check_preflight(
                    selected_specs=[synthetic_spec],
                    contracts=contracts,
                    captures_dir=captures_dir,
                    active_dir=active_dir,
                )
            self.assertIn("mailtest-mitm", str(ctx.exception))

    def test_05_stale_artifacts_cleaned_before_classification(self):
        """
        Blocked and unresolvable scenarios must have pre-existing generation artifacts
        cleaned before classification so no stale files remain.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            captures_dir = Path(tmp_dir)

            # Create dummy stale files for PCAP-009 (BLOCKED)
            for suffix in (".pcap", ".expected.json", ".observed.json", ".comparison.json", ".evidence.json", ".batch.json"):
                (captures_dir / f"PCAP-009{suffix}").write_text("stale_content")

            # Verify files exist
            self.assertTrue((captures_dir / "PCAP-009.pcap").exists())

            # Cleanup helper
            cleanup_scenario_artifacts(captures_dir, "PCAP-009")

            # Verify all files removed
            for suffix in (".pcap", ".expected.json", ".observed.json", ".comparison.json", ".evidence.json", ".batch.json"):
                self.assertFalse((captures_dir / f"PCAP-009{suffix}").exists())

    def test_06_unselected_scenarios_untouched(self):
        """
        Scenarios not selected in the current run must remain completely untouched.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            captures_dir = Path(tmp_dir)

            # Files for PCAP-001 (unselected) and PCAP-004 (selected)
            (captures_dir / "PCAP-001.pcap").write_text("keep_this")
            (captures_dir / "PCAP-004.pcap").write_text("clean_this")

            # Clean selected scenario PCAP-004 only
            cleanup_scenario_artifacts(captures_dir, "PCAP-004")

            # PCAP-001 must still exist untouched
            self.assertTrue((captures_dir / "PCAP-001.pcap").exists())
            self.assertEqual((captures_dir / "PCAP-001.pcap").read_text(), "keep_this")
            # PCAP-004 must be removed
            self.assertFalse((captures_dir / "PCAP-004.pcap").exists())

    def test_07_cleanup_failure_raises_and_reports(self):
        """
        Deletion failures must not be swallowed with pass; StaleArtifactCleanupError must be raised.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            captures_dir = Path(tmp_dir)
            stale_file = captures_dir / "PCAP-004.pcap"
            stale_file.write_text("cannot_delete")

            # Mock Path.unlink to raise OSError
            with patch.object(Path, "unlink", side_effect=OSError("Permission denied")):
                with self.assertRaises(StaleArtifactCleanupError) as ctx:
                    cleanup_scenario_artifacts(captures_dir, "PCAP-004")
                self.assertIn("Permission denied", str(ctx.exception))

    def test_08_resume_tied_to_coherent_run_id(self):
        """
        Resume must only skip a scenario when its complete artifact set is verifiably
        associated with the exact prior run_id and manifest hashes.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            captures_dir = Path(tmp_dir)
            orig_captures = self.orchestrator.captures_dir
            self.orchestrator.captures_dir = captures_dir
            try:
                sid = "PCAP-004"

                # Create mock valid artifacts
                pcap = captures_dir / f"{sid}.pcap"
                pcap.write_bytes(b"\x00" * 64)

                expected_data = self.orchestrator.specs_by_id[sid].to_expected_dict(selected_cipher=None)
                (captures_dir / f"{sid}.expected.json").write_text(json.dumps(expected_data))

                observed_data = {
                    "schema_version": "1.0",
                    "scenario_id": sid,
                    "sessions": {
                        "0": {
                            "stream_id": 0,
                            "protocol": "SMTP",
                            "starttls": {"executed": False, "status": "none"},
                            "tls": {"negotiated": False},
                            "handshake": None,
                            "certificate": None,
                        }
                    },
                }
                (captures_dir / f"{sid}.observed.json").write_text(json.dumps(observed_data))

                comparison_data = {
                    "schema_version": "1.0",
                    "scenario_id": sid,
                    "status": "PASS",
                    "fields": {
                        "protocol": {"status": "PASS", "expected": "SMTP", "observed": "SMTP"}
                    },
                    "mismatches": [],
                    "unknowns": [],
                }
                (captures_dir / f"{sid}.comparison.json").write_text(json.dumps(comparison_data))
                (captures_dir / f"{sid}.evidence.json").write_text(json.dumps({"summary": "ok"}))

                # Compute genuine hashes
                valid, err, true_hashes = verify_scenario_artifacts(
                    captures_dir=captures_dir,
                    scenario_id=sid,
                    expected_schema=self.orchestrator.expected_schema,
                    observed_schema=self.orchestrator.observed_schema,
                    comparison_schema=self.orchestrator.comparison_schema,
                )
                self.assertTrue(valid, msg=err)

                # Case A: Artifacts exist, but .batch.json has a DIFFERENT run_id
                wrong_run_id = "batch_20260101_000000_11111111"
                (captures_dir / f"{sid}.batch.json").write_text(
                    json.dumps({"run_id": wrong_run_id, "scenario_id": sid, "artifact_hashes": true_hashes})
                )
                prior_manifest = {
                    "run_id": "batch_20260924_120000_22222222",
                    "scenarios": {
                        sid: {"scenario_id": sid, "execution_state": "GENERATED", "artifact_hashes": true_hashes}
                    },
                }

                eligible, _ = self.orchestrator._verify_resume_eligibility(
                    scenario_id=sid,
                    resume_run_id="batch_20260924_120000_22222222",
                    resume_manifest=prior_manifest,
                )
                # Must reject because run_id in .batch.json does not match resume_run_id
                self.assertFalse(eligible)

                # Case B: .batch.json matches resume_run_id AND hashes match
                correct_run_id = "batch_20260924_120000_22222222"
                (captures_dir / f"{sid}.batch.json").write_text(
                    json.dumps({"run_id": correct_run_id, "scenario_id": sid, "artifact_hashes": true_hashes})
                )

                eligible, hashes = self.orchestrator._verify_resume_eligibility(
                    scenario_id=sid,
                    resume_run_id=correct_run_id,
                    resume_manifest=prior_manifest,
                )
                self.assertTrue(eligible)
                self.assertEqual(hashes, true_hashes)
            finally:
                self.orchestrator.captures_dir = orig_captures

    def test_09_resume_rejects_incomplete_or_altered_artifacts(self):
        """
        If an artifact was altered (hash mismatch) or deleted, resume must reject it.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            captures_dir = Path(tmp_dir)
            orig_captures = self.orchestrator.captures_dir
            self.orchestrator.captures_dir = captures_dir
            try:
                sid = "PCAP-004"
                run_id = "batch_20260924_120000_22222222"

                pcap = captures_dir / f"{sid}.pcap"
                pcap.write_bytes(b"\x00" * 32)
                expected_data = self.orchestrator.specs_by_id[sid].to_expected_dict(selected_cipher=None)
                (captures_dir / f"{sid}.expected.json").write_text(json.dumps(expected_data))
                (captures_dir / f"{sid}.observed.json").write_text(json.dumps({
                    "schema_version": "1.0",
                    "scenario_id": sid,
                    "sessions": {
                        "0": {
                            "stream_id": 0, "protocol": "SMTP",
                            "starttls": {"executed": False, "status": "none"},
                            "tls": {"negotiated": False}, "handshake": None, "certificate": None
                        }
                    }
                }))
                (captures_dir / f"{sid}.comparison.json").write_text(json.dumps({
                    "schema_version": "1.0", "scenario_id": sid, "status": "PASS",
                    "fields": {"protocol": {"status": "PASS", "expected": "SMTP", "observed": "SMTP"}},
                    "mismatches": [], "unknowns": []
                }))
                (captures_dir / f"{sid}.evidence.json").write_text(json.dumps({"summary": "ok"}))

                valid, err, initial_hashes = verify_scenario_artifacts(
                    captures_dir, sid,
                    self.orchestrator.expected_schema,
                    self.orchestrator.observed_schema,
                    self.orchestrator.comparison_schema,
                )
                self.assertTrue(valid)

                # Record initial hashes in manifest and .batch.json
                (captures_dir / f"{sid}.batch.json").write_text(
                    json.dumps({"run_id": run_id, "scenario_id": sid, "artifact_hashes": initial_hashes})
                )
                manifest = {
                    "run_id": run_id,
                    "scenarios": {sid: {"scenario_id": sid, "execution_state": "GENERATED", "artifact_hashes": initial_hashes}},
                }

                # Now alter the PCAP file
                pcap.write_bytes(b"\xff" * 64)

                # Resume must detect hash mismatch and reject
                eligible, _ = self.orchestrator._verify_resume_eligibility(sid, run_id, manifest)
                self.assertFalse(eligible)
            finally:
                self.orchestrator.captures_dir = orig_captures

    def test_10_success_requires_complete_artifact_set(self):
        """
        Validator must reject 0-byte PCAP or missing/invalid JSON artifacts.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            captures_dir = Path(tmp_dir)
            sid = "PCAP-004"

            # 1. 0-byte PCAP
            (captures_dir / f"{sid}.pcap").write_bytes(b"")
            valid, err, _ = verify_scenario_artifacts(
                captures_dir, sid,
                self.orchestrator.expected_schema,
                self.orchestrator.observed_schema,
                self.orchestrator.comparison_schema,
            )
            self.assertFalse(valid)
            self.assertIn("empty", str(err))

            # 2. Valid PCAP but missing JSON files
            (captures_dir / f"{sid}.pcap").write_bytes(b"\x01\x02\x03")
            valid, err, _ = verify_scenario_artifacts(
                captures_dir, sid,
                self.orchestrator.expected_schema,
                self.orchestrator.observed_schema,
                self.orchestrator.comparison_schema,
            )
            self.assertFalse(valid)
            self.assertIn("does not exist", str(err))

            # 3. Empty evidence dictionary must fail
            expected_data = self.orchestrator.specs_by_id[sid].to_expected_dict(selected_cipher=None)
            (captures_dir / f"{sid}.expected.json").write_text(json.dumps(expected_data))
            (captures_dir / f"{sid}.observed.json").write_text(json.dumps({"schema_version": "1.0", "scenario_id": sid, "sessions": {}}))
            (captures_dir / f"{sid}.comparison.json").write_text(json.dumps({"schema_version": "1.0", "scenario_id": sid, "status": "PASS", "fields": {}, "mismatches": [], "unknowns": []}))
            (captures_dir / f"{sid}.evidence.json").write_text("{}")
            valid, err, _ = verify_scenario_artifacts(
                captures_dir, sid,
                self.orchestrator.expected_schema,
                self.orchestrator.observed_schema,
                self.orchestrator.comparison_schema,
            )
            self.assertFalse(valid)
            self.assertIn("non-empty", str(err))

            # 4. Valid non-empty evidence dictionary must pass
            (captures_dir / f"{sid}.evidence.json").write_text(json.dumps({"0": {"protocol": "SMTP"}}))
            valid, err, _ = verify_scenario_artifacts(
                captures_dir, sid,
                self.orchestrator.expected_schema,
                self.orchestrator.observed_schema,
                self.orchestrator.comparison_schema,
            )
            self.assertTrue(valid)
            self.assertIsNone(err)

    def test_11_batch_continues_after_scenario_local_failure(self):
        """
        A local failure in one scenario must not crash or terminate the batch orchestrator.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            captures_dir = Path(tmp_dir)
            records = {}

            # Simulate PCAP-004 failing, PCAP-005 succeeding
            records["PCAP-004"] = ScenarioBatchRecord(
                scenario_id="PCAP-004",
                protocol="SMTP",
                category=BatchExecutionCategory.EXECUTABLE_STANDARD.value,
                execution_state=ScenarioExecutionState.FAILED.value,
                error="Staging failed",
            )
            records["PCAP-005"] = ScenarioBatchRecord(
                scenario_id="PCAP-005",
                protocol="SMTP",
                category=BatchExecutionCategory.EXECUTABLE_STANDARD.value,
                execution_state=ScenarioExecutionState.GENERATED.value,
                comparison_status="PASS",
                duration_seconds=1.23,
            )

            report = self.orchestrator.generate_reports(
                run_id="batch_test_failure_isolation",
                start_time=datetime.now(timezone.utc),
                end_time=datetime.now(timezone.utc),
                total_duration=2.5,
                preflight_info={"bridge_interface": "br-test", "active_containers": []},
                records=records,
                selected_ids=["PCAP-004", "PCAP-005"],
            )

            self.assertEqual(report["summary"]["total_selected"], 2)
            self.assertEqual(report["summary"]["failed"], 1)
            self.assertEqual(report["summary"]["generated"], 1)

    def test_12_batch_report_completeness(self):
        """
        Batch report generation produces complete batch_report.json and batch_report.md
        with all selected scenarios and accurate summary metrics.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            captures_dir = Path(tmp_dir)
            # Temporarily point orchestrator captures_dir to tmp_dir
            orig_captures = self.orchestrator.captures_dir
            self.orchestrator.captures_dir = captures_dir

            try:
                records = {
                    "PCAP-004": ScenarioBatchRecord(
                        scenario_id="PCAP-004",
                        protocol="SMTP",
                        category=BatchExecutionCategory.EXECUTABLE_STANDARD.value,
                        execution_state=ScenarioExecutionState.GENERATED.value,
                        comparison_status="PASS",
                        duration_seconds=1.1,
                    ),
                    "PCAP-009": ScenarioBatchRecord(
                        scenario_id="PCAP-009",
                        protocol="SMTP",
                        category=BatchExecutionCategory.BLOCKED.value,
                        execution_state=ScenarioExecutionState.BLOCKED.value,
                        error="DAEMON_CANNOT_ENFORCE",
                    ),
                }

                report = self.orchestrator.generate_reports(
                    run_id="batch_test_report_complete",
                    start_time=datetime.now(timezone.utc),
                    end_time=datetime.now(timezone.utc),
                    total_duration=5.0,
                    preflight_info={"bridge_interface": "br-test", "active_containers": ["mailtest-postfix"]},
                    records=records,
                    selected_ids=["PCAP-004", "PCAP-009"],
                )

                json_file = captures_dir / "batch_report.json"
                md_file = captures_dir / "batch_report.md"

                self.assertTrue(json_file.exists())
                self.assertTrue(md_file.exists())

                loaded_json = json.loads(json_file.read_text())
                self.assertEqual(loaded_json["run_id"], "batch_test_report_complete")
                self.assertEqual(loaded_json["summary"]["generated"], 1)
                self.assertEqual(loaded_json["summary"]["blocked"], 1)

                md_text = md_file.read_text()
                self.assertIn("# Batch Generation Report: `batch_test_report_complete`", md_text)
                self.assertIn("PCAP-004", md_text)
                self.assertIn("PCAP-009", md_text)
            finally:
                self.orchestrator.captures_dir = orig_captures

    def test_13_implemented_special_harness_dispatches_to_runner(self):
        """
        Scenarios classified as SPECIAL_HARNESS with harness_status='IMPLEMENTED'
        must be dispatched to runner.run_scenario rather than skipped.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            orig_captures = self.orchestrator.captures_dir
            orig_runner = self.orchestrator.runner
            self.orchestrator.captures_dir = tmp_path

            mock_runner = MagicMock()
            mock_result = MagicMock()
            mock_result.execution_success = True
            mock_result.comparison_status = "PASS"
            mock_runner.run_scenario.return_value = mock_result
            self.orchestrator.runner = mock_runner

            try:
                # Mock artifact verification to return True with valid dummy hashes
                dummy_hashes = {
                    "pcap": "sha256:aaa",
                    "expected": "sha256:bbb",
                    "observed": "sha256:ccc",
                    "comparison": "sha256:ddd",
                    "evidence": "sha256:eee",
                }
                with patch("testbed.runner.batch.verify_scenario_artifacts", return_value=(True, None, dummy_hashes)), \
                     patch("testbed.runner.batch.check_preflight", return_value={"bridge_interface": "br-test", "active_containers": []}):

                    report = self.orchestrator.run_batch(requested_ids=["PCAP-121"])
                    self.assertEqual(report["summary"]["generated"], 1)
                    mock_runner.run_scenario.assert_called_once()
                    self.assertEqual(mock_runner.run_scenario.call_args[0][0].scenario_id, "PCAP-121")
            finally:
                self.orchestrator.captures_dir = orig_captures
                self.orchestrator.runner = orig_runner

    def test_14_unimplemented_special_harness_skips_execution(self):
        """
        Scenarios classified as SPECIAL_HARNESS with harness_status='NOT_IMPLEMENTED'
        must be skipped and recorded as SPECIAL_HARNESS without invoking runner.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            orig_captures = self.orchestrator.captures_dir
            orig_runner = self.orchestrator.runner
            self.orchestrator.captures_dir = tmp_path

            mock_runner = MagicMock()
            self.orchestrator.runner = mock_runner

            try:
                unimpl_contract = replace(self.orchestrator.contracts["PCAP-106"], harness_status="NOT_IMPLEMENTED")
                with patch.dict(self.orchestrator.contracts, {"PCAP-106": unimpl_contract}):
                    with patch("testbed.runner.batch.check_preflight", return_value={"bridge_interface": "br-test", "active_containers": []}):
                        report = self.orchestrator.run_batch(requested_ids=["PCAP-106"])
                        self.assertEqual(report["summary"]["special_harness"], 1)
                        mock_runner.run_scenario.assert_not_called()
                        rec = report["scenarios"][0]
                        self.assertEqual(rec["execution_state"], ScenarioExecutionState.SPECIAL_HARNESS.value)
                        self.assertIn("NOT_IMPLEMENTED", rec["error"])
            finally:
                self.orchestrator.captures_dir = orig_captures
                self.orchestrator.runner = orig_runner


if __name__ == "__main__":
    unittest.main()
