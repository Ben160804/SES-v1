"""Integrity tests for the 10k programmatic synthetic feature cohort."""

import csv
import json
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COHORT = ROOT / "datasets/ml/synthetic/synthetic_email_research_cohort_v1.csv"
PROFILES = ROOT / "datasets/ml/synthetic/synthetic_email_research_profiles_v1.csv"
METADATA = ROOT / "datasets/ml/synthetic/synthetic_email_research_cohort_v1.json"


class TestSyntheticEmailResearchCohort(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with COHORT.open(newline="", encoding="utf-8") as source:
            cls.rows = list(csv.DictReader(source))
        with PROFILES.open(newline="", encoding="utf-8") as source:
            cls.profiles = list(csv.DictReader(source))
        cls.metadata = json.loads(METADATA.read_text(encoding="utf-8"))

    def test_exact_size_provenance_and_protocol_coverage(self):
        self.assertEqual(len(self.rows), 10_000)
        self.assertEqual(len(self.profiles), 2_000)
        self.assertTrue(all(row["data_source"] == "synthetic_simulation" for row in self.rows))
        self.assertEqual(self.metadata["is_real_observation"], False)
        self.assertEqual(set(row["protocol"] for row in self.rows), {"SMTP", "IMAP", "POP3"})
        self.assertEqual(Counter(row["target"] for row in self.rows), {
            "LOW": 2_500, "MEDIUM": 2_500, "HIGH": 2_500, "CRITICAL": 2_500,
        })

    def test_feature_rows_exclude_identity_and_rule_output_fields(self):
        forbidden = {"sample_id", "server_id", "configuration_group_id", "profile_family", "country", "ip", "rule_flag"}
        for row in self.rows[::137]:
            features = json.loads(row["features_json"])
            self.assertFalse(forbidden & set(features))
            self.assertEqual(features["protocol"], row["protocol"])

    def test_endpoint_configuration_groups_do_not_cross_splits(self):
        groups = {
            split: {row["configuration_group_id"] for row in self.rows if row["split"] == split}
            for split in ("train", "validation", "test")
        }
        self.assertFalse(groups["train"] & groups["validation"])
        self.assertFalse(groups["train"] & groups["test"])
        self.assertFalse(groups["validation"] & groups["test"])
        self.assertEqual(sum(len(values) for values in groups.values()), len(set().union(*groups.values())))

    def test_each_sample_has_canonical_runtime_features(self):
        from analysis.ml_runtime import EMAIL_RISK_CATEGORICAL, EMAIL_RISK_NUMERIC

        expected = set(EMAIL_RISK_CATEGORICAL)
        for field in EMAIL_RISK_NUMERIC:
            expected.update((field, f"{field}__missing"))
        for row in self.rows[::113]:
            self.assertEqual(set(json.loads(row["features_json"])), expected)


if __name__ == "__main__":
    unittest.main()
