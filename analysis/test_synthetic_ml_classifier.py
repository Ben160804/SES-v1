"""Contract tests for the expected-scenario synthetic classifier."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "datasets" / "ml"))

from train_synthetic_email_risk_classifier import LABELS, _risk_label, _rows, _split  # noqa: E402


class TestSyntheticEmailRiskRubric(unittest.TestCase):
    def test_rubric_covers_expected_risk_conditions_without_rule_engine_outputs(self):
        self.assertEqual(_risk_label({"tls_presence": "none"}), "CRITICAL")
        self.assertEqual(_risk_label({"tls_presence": "implicit-TLS", "tls_version": "1.0", "cipher_strength": "HIGH"}), "HIGH")
        self.assertEqual(_risk_label({"tls_presence": "implicit-TLS", "tls_version": "1.3", "cipher_strength": "BROKEN"}), "CRITICAL")
        self.assertEqual(_risk_label({"tls_presence": "implicit-TLS", "tls_version": "1.2", "cipher_strength": "MEDIUM"}), "MEDIUM")
        self.assertEqual(_risk_label({"tls_presence": "implicit-TLS", "tls_version": "1.3", "cipher_strength": "HIGH"}), "LOW")

    def test_training_rows_and_split_are_family_disjoint(self):
        rows = _rows()
        train, validation, test = _split(rows)
        self.assertEqual({row["risk_tier"] for row in rows}, set(LABELS))
        group_sets = [{rows[i]["family_id"] for i in part} for part in (train, validation, test)]
        self.assertFalse(group_sets[0] & group_sets[1])
        self.assertFalse(group_sets[0] & group_sets[2])
        self.assertFalse(group_sets[1] & group_sets[2])
        certificate_sets = [
            {rows[i]["certificate_group_id"] for i in part if rows[i]["certificate_group_id"] != "UNOBSERVED"}
            for part in (train, validation, test)
        ]
        self.assertFalse(certificate_sets[0] & certificate_sets[1])
        self.assertFalse(certificate_sets[0] & certificate_sets[2])
        self.assertFalse(certificate_sets[1] & certificate_sets[2])
        for part in (train, validation, test):
            self.assertEqual({rows[i]["risk_tier"] for i in part}, set(LABELS))
        forbidden = {"risk_tier", "rule_flag_legacy_tls", "risk_legacy_tls", "scenario_id", "family_id"}
        for row in rows:
            self.assertFalse(forbidden & set(row["features"]))


if __name__ == "__main__":
    unittest.main()
