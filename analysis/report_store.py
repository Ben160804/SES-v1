"""SQLite persistence for completed SecureMailScope forensic analyses."""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 2


class ReportStore:
    """Store serialized evidence without mixing ML output into rule findings."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @contextmanager
    def _connection(self):
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS analysis_runs (
                    run_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    source_name TEXT NOT NULL,
                    total_streams INTEGER NOT NULL,
                    report_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS stream_reports (
                    run_id TEXT NOT NULL REFERENCES analysis_runs(run_id) ON DELETE CASCADE,
                    stream_id INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    rule_results_json TEXT NOT NULL,
                    observations_json TEXT NOT NULL,
                    ml_results_json TEXT NOT NULL,
                    posture_assessment_json TEXT NOT NULL DEFAULT '{}',
                    input_snapshot_json TEXT NOT NULL,
                    PRIMARY KEY (run_id, stream_id)
                );
                CREATE INDEX IF NOT EXISTS idx_stream_reports_protocol
                    ON stream_reports(protocol);
                """
            )
            columns = {
                row["name"] for row in db.execute("PRAGMA table_info(stream_reports)").fetchall()
            }
            if "posture_assessment_json" not in columns:
                db.execute(
                    "ALTER TABLE stream_reports ADD COLUMN posture_assessment_json TEXT NOT NULL DEFAULT '{}'"
                )
            db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    @staticmethod
    def _json(value: Any) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)

    def save_report(self, report: Any, source_name: str) -> str:
        """Persist a SessionReport (or its dictionary representation) atomically."""
        payload = report.to_dict() if hasattr(report, "to_dict") else report
        if not isinstance(payload, dict) or not isinstance(payload.get("stream_reports"), dict):
            raise ValueError("report must contain a stream_reports object")
        run_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()
        streams = payload["stream_reports"]
        with self._connection() as db:
            db.execute(
                "INSERT INTO analysis_runs VALUES (?, ?, ?, ?, ?)",
                (run_id, created_at, Path(source_name).name, len(streams), self._json(payload)),
            )
            for stream_key, stream in streams.items():
                stream_id = int(stream.get("stream_id", stream_key))
                db.execute(
                    """INSERT INTO stream_reports
                       (run_id, stream_id, protocol, rule_results_json, observations_json,
                        ml_results_json, posture_assessment_json, input_snapshot_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        run_id,
                        stream_id,
                        str(stream.get("protocol", "Unknown")),
                        self._json(stream.get("policy_results", {})),
                        self._json(stream.get("observations", [])),
                        self._json(stream.get("ml_results", {})),
                        self._json(stream.get("posture_assessment", {})),
                        self._json(stream.get("input_snapshot", {})),
                    ),
                )
        return run_id

    def list_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        if limit < 1 or limit > 500:
            raise ValueError("limit must be between 1 and 500")
        with self._connection() as db:
            rows = db.execute(
                """SELECT run_id, created_at, source_name, total_streams
                   FROM analysis_runs ORDER BY created_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def dashboard_summary(self) -> dict[str, Any]:
        """Aggregate observed evidence across all saved runs for the overview UI."""
        with self._connection() as db:
            runs = db.execute(
                "SELECT run_id, created_at FROM analysis_runs ORDER BY created_at DESC"
            ).fetchall()
            if not runs:
                return {
                    "capture_count": 0, "stream_count": 0, "captures_by_day": {},
                    "protocol_counts": {}, "tls_version_counts": {}, "certificate_counts": {},
                    "rule_verdicts": {}, "rule_severities": {}, "ml_statuses": {},
                    "posture_tiers": {},
                }
            streams = db.execute(
                """SELECT protocol, rule_results_json, input_snapshot_json,
                           ml_results_json, posture_assessment_json
                    FROM stream_reports"""
            ).fetchall()

        def count(target: dict[str, int], key: Any) -> None:
            name = str(key or "Unknown")
            target[name] = target.get(name, 0) + 1

        captures_by_day: dict[str, int] = {}
        for run in runs:
            day = str(run["created_at"])[:10]
            count(captures_by_day, day)
        protocol_counts: dict[str, int] = {}
        tls_version_counts: dict[str, int] = {}
        certificate_counts: dict[str, int] = {}
        rule_verdicts: dict[str, int] = {}
        rule_severities: dict[str, int] = {}
        ml_statuses: dict[str, int] = {}
        posture_tiers: dict[str, int] = {}
        for row in streams:
            count(protocol_counts, row["protocol"])
            snapshot = json.loads(row["input_snapshot_json"])
            tls = snapshot.get("tls") if isinstance(snapshot.get("tls"), dict) else snapshot
            version = tls.get("tls_version") or tls.get("selected_version") or tls.get("version")
            count(tls_version_counts, version or "TLS not observed")
            cert = snapshot.get("certificate") if isinstance(snapshot.get("certificate"), dict) else snapshot
            observed = cert.get("observable", cert.get("certificate_observed", cert.get("observed", False)))
            if isinstance(observed, str):
                observed = observed.strip().lower() in {"true", "yes", "observed", "present"}
            if not observed and isinstance(cert.get("leaf_cert"), dict):
                observed = True
            count(certificate_counts, "Observed" if observed else "Not observed")

            rules = json.loads(row["rule_results_json"])
            if isinstance(rules, dict):
                for items in rules.values():
                    if not isinstance(items, list):
                        continue
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                        verdict = str(item.get("verdict") or "UNKNOWN").upper()
                        count(rule_verdicts, verdict)
                        if verdict == "FAIL":
                            count(rule_severities, item.get("severity") or "UNSPECIFIED")

            ml = json.loads(row["ml_results_json"])
            if isinstance(ml, dict):
                for result in ml.values():
                    if isinstance(result, dict):
                        count(ml_statuses, str(result.get("status") or "UNKNOWN").upper())
            posture = json.loads(row["posture_assessment_json"])
            if isinstance(posture, dict):
                tier = posture.get("tier") or posture.get("risk_tier") or posture.get("band")
                if tier:
                    count(posture_tiers, str(tier).upper())

        return {
            "capture_count": len(runs), "stream_count": len(streams),
            "captures_by_day": dict(sorted(captures_by_day.items())),
            "protocol_counts": protocol_counts, "tls_version_counts": tls_version_counts,
            "certificate_counts": certificate_counts, "rule_verdicts": rule_verdicts,
            "rule_severities": rule_severities, "ml_statuses": ml_statuses,
            "posture_tiers": posture_tiers,
        }

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self._connection() as db:
            row = db.execute(
                "SELECT report_json FROM analysis_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
        return json.loads(row["report_json"]) if row else None

    def delete_run(self, run_id: str) -> bool:
        """Delete a persisted analysis and its normalized stream rows."""
        with self._connection() as db:
            cursor = db.execute("DELETE FROM analysis_runs WHERE run_id = ?", (run_id,))
        return cursor.rowcount > 0

    def get_stream(self, run_id: str, stream_id: int) -> dict[str, Any] | None:
        with self._connection() as db:
            row = db.execute(
                """SELECT stream_id, protocol, rule_results_json, observations_json,
                          ml_results_json, posture_assessment_json, input_snapshot_json
                   FROM stream_reports WHERE run_id = ? AND stream_id = ?""",
                (run_id, stream_id),
            ).fetchone()
        if row is None:
            return None
        return {
            "stream_id": row["stream_id"],
            "protocol": row["protocol"],
            "policy_results": json.loads(row["rule_results_json"]),
            "observations": json.loads(row["observations_json"]),
            "ml_results": json.loads(row["ml_results_json"]),
            "posture_assessment": json.loads(row["posture_assessment_json"]),
            "input_snapshot": json.loads(row["input_snapshot_json"]),
        }
