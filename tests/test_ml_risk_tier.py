"""Regression tests for the auditable ZGrab risk-tier proxy target and schema."""

from __future__ import annotations

import csv
import json
import sys
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "datasets" / "ml"))

from label_zgrab_risk_tier import FINDINGS, OUTPUT, assign_tier  # noqa: E402
from train_zgrab_runtime_proxy_classifier import CATEGORICAL, NUMERIC, _features  # noqa: E402


class TestRiskTierProxyContract(unittest.TestCase):
    def test_tier_rubric_is_deterministic_and_merges_unsupported_critical(self):
        self.assertEqual(assign_tier([]), ("LOW", "no_current_rule_flag"))
        self.assertEqual(assign_tier(["rule_flag_cbc_cipher"]), ("MEDIUM", "single_nonlegacy_rule_flag"))
        self.assertEqual(
            assign_tier(["rule_flag_legacy_tls"])[0],
            "HIGH",
        )
        self.assertEqual(
            assign_tier(["rule_flag_cbc_cipher", "rule_flag_sha1_certificate"])[0],
            "HIGH",
        )

    def test_risk_tier_label_distribution_matches_tls_handshake_cohort(self):
        with OUTPUT.open(newline="", encoding="utf-8") as stream:
            rows = list(csv.DictReader(stream))
        labeled = [row for row in rows if row["label_status"] == "LABELED_RULE_RUBRIC_PROXY"]
        counts = Counter(row["risk_tier_proxy"] for row in labeled)
        self.assertEqual(counts, {"LOW": 469, "MEDIUM": 41, "HIGH": 20})
        self.assertEqual(sum(row["label_status"] == "NOT_EVALUABLE" for row in rows), 1070)

    def test_training_features_exclude_ids_targets_and_deterministic_flags(self):
        feature_row = {
            "tls_version": "TLSv1.2",
            "tls_selected_version": "TLSv1.2",
            "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "key_exchange": "x25519",
            "country": "test-country",
            "record_id": "not-a-feature",
            "rule_flag_legacy_tls": "1",
            "risk_tier_proxy": "HIGH",
        }
        features = _features(feature_row)
        self.assertEqual(len(CATEGORICAL) + len(NUMERIC), 33)
        self.assertEqual(features["tls_negotiated_version"], "TLSv1.2")
        self.assertNotIn("country", features)
        self.assertNotIn("record_id", features)
        self.assertFalse(set(FINDINGS) & set(features))
        self.assertNotIn("risk_tier_proxy", features)

    def test_model_artifact_has_grouped_holdout_and_per_class_metrics(self):
        metadata_path = ROOT / "datasets" / "ml" / "models" / "zgrab_runtime_risk_tier_v1.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        groups = metadata["split_countries"]
        self.assertFalse(set(groups["train"]) & set(groups["validation"]))
        self.assertFalse(set(groups["train"]) & set(groups["test"]))
        self.assertFalse(set(groups["validation"]) & set(groups["test"]))
        self.assertEqual(metadata["test_metrics"]["sample_count"], 94)
        self.assertEqual(metadata["test_metrics"]["confusion_matrix_labels"], ["LOW", "MEDIUM", "HIGH"])
        self.assertEqual(set(metadata["test_metrics"]["per_class"]), {"LOW", "MEDIUM", "HIGH"})
        self.assertIn("not independent", metadata["target_semantics"])


if __name__ == "__main__":
    unittest.main()
