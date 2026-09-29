"""Tests for independent-of-Rule-Engine real ZGrab rubric training."""

from __future__ import annotations

import csv
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "datasets" / "ml"))

from train_zgrab_evidence_risk_classifier import DATA, LABELS, _features, _risk_label  # noqa: E402


class TestZGrabEvidenceRiskClassifier(unittest.TestCase):
    def test_risk_rubric_ignores_existing_rule_flag_columns(self):
        with DATA.open(newline="", encoding="utf-8") as stream:
            row = next(r for r in csv.DictReader(stream) if r["tls_observation_state"] == "HANDSHAKE_SUCCEEDED")
        original = _risk_label(row)
        changed = dict(row)
        for field in tuple(changed):
            if field.startswith("rule_flag_"):
                changed[field] = "1" if changed[field] != "1" else "0"
        self.assertEqual(_risk_label(changed), original)
        features = _features(row)
        self.assertFalse(any(name.startswith("rule_flag_") for name in features))
        self.assertFalse({"record_id", "country", "source_file", "source_row"} & set(features))

    def test_training_cohort_uses_real_successful_servers_and_coarsened_labels(self):
        with DATA.open(newline="", encoding="utf-8") as stream:
            rows = list(csv.DictReader(stream))
        labels = [_risk_label(row) for row in rows]
        evaluable = [label for label in labels if label is not None]
        self.assertEqual(set(evaluable), set(LABELS))
        self.assertEqual(len(rows), 1600)
        self.assertEqual(len(evaluable), 1524)
        # Only one row has medium-only evidence, so it is intentionally merged
        # into LOW_OR_MEDIUM instead of pretending to support a separate tier.
        self.assertEqual(evaluable.count("LOW_OR_MEDIUM"), 468)
        self.assertEqual(evaluable.count("HIGH"), 62)
        self.assertEqual(evaluable.count("CRITICAL"), 994)


if __name__ == "__main__":
    unittest.main()
