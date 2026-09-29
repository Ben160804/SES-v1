"""Tests for atomic storage and independent retrieval of rule and ML results."""

import tempfile
import unittest
import sqlite3
from contextlib import closing
from pathlib import Path

from analysis.report_store import ReportStore


class TestReportStore(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store = ReportStore(Path(self.temp_dir.name) / "reports.sqlite")
        self.report = {
            "total_streams": 1,
            "stream_reports": {
                "7": {
                    "stream_id": 7,
                    "protocol": "SMTP",
                    "policy_results": {"NIST-52R2": [{"verdict": "FAIL"}]},
                    "observations": [{"obs_id": "OBS-STARTTLS", "detected": True}],
                    "ml_results": {
                        "smtp_configuration_anomaly": {"status": "COMPLETED_EXPLORATORY", "score": 0.3}
                    },
                    "posture_assessment": {"status": "ASSESSED", "score": 80, "tier": "MODERATE"},
                    "input_snapshot": {"tls_version": "TLSv1.2"},
                }
            },
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_round_trip_keeps_rule_and_ml_fields_separate(self):
        run_id = self.store.save_report(self.report, "/captures/case.pcap")
        self.assertEqual(self.store.list_runs()[0]["source_name"], "case.pcap")
        self.assertEqual(self.store.get_run(run_id), self.report)
        stream = self.store.get_stream(run_id, 7)
        self.assertEqual(stream["policy_results"], {"NIST-52R2": [{"verdict": "FAIL"}]})
        self.assertEqual(stream["ml_results"]["smtp_configuration_anomaly"]["score"], 0.3)
        self.assertEqual(stream["posture_assessment"]["score"], 80)

    def test_invalid_report_is_rejected_before_insert(self):
        with self.assertRaises(ValueError):
            self.store.save_report({"total_streams": 0}, "bad.pcap")
        self.assertEqual(self.store.list_runs(), [])

    def test_run_limit_is_bounded(self):
        with self.assertRaises(ValueError):
            self.store.list_runs(501)

    def test_v1_database_migrates_posture_assessment_column(self):
        old_path = Path(self.temp_dir.name) / "old.sqlite"
        with closing(sqlite3.connect(old_path)) as db:
            with db:
                db.executescript("""
                    CREATE TABLE analysis_runs (
                        run_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, source_name TEXT NOT NULL,
                        total_streams INTEGER NOT NULL, report_json TEXT NOT NULL
                    );
                    CREATE TABLE stream_reports (
                        run_id TEXT NOT NULL, stream_id INTEGER NOT NULL, protocol TEXT NOT NULL,
                        rule_results_json TEXT NOT NULL, observations_json TEXT NOT NULL,
                        ml_results_json TEXT NOT NULL, input_snapshot_json TEXT NOT NULL,
                        PRIMARY KEY (run_id, stream_id)
                    );
                    PRAGMA user_version = 1;
                """)
        ReportStore(old_path)
        with closing(sqlite3.connect(old_path)) as db:
            columns = {row[1] for row in db.execute("PRAGMA table_info(stream_reports)")}
            self.assertIn("posture_assessment_json", columns)
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 2)


if __name__ == "__main__":
    unittest.main()
