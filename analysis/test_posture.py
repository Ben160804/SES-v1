"""Tests for the separate, documented deterministic posture rubric."""

import unittest

from analysis.posture import assess_posture


class TestPostureRubric(unittest.TestCase):
    def test_policy_family_penalty_is_not_duplicated_across_profiles(self):
        policies = {
            "NIST-52R2": [{"verdict": "FAIL", "rule_id": "N52-TLS-01", "name": "Legacy TLS"}],
            "MOZ-MODERN": [{"verdict": "FAIL", "rule_id": "MM-TLS-01", "name": "TLS profile"}],
        }
        result = assess_posture(policies, [])
        self.assertEqual(result["score"], 75)
        self.assertEqual(result["tier"], "MODERATE")
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(len(result["findings"][0]["evidence"]), 2)

    def test_cleartext_auth_is_critical_and_recommendation_is_evidence_linked(self):
        observation = {
            "obs_id": "OBS-SEC-PLAINTEXT-AUTH",
            "name": "Cleartext Authentication Transmission",
            "detected": True,
            "description": "Credentials observed outside TLS.",
            "evidence": [{"field": "plaintext_auth_attempted", "value": True}],
        }
        result = assess_posture({}, [observation])
        self.assertEqual(result["score"], 40)
        self.assertEqual(result["tier"], "CRITICAL")
        self.assertEqual(result["findings"][0]["evidence"][0]["obs_id"], observation["obs_id"])
        self.assertIn("Immediately disable authentication", result["findings"][0]["recommendation"])

    def test_insufficient_observations_abstain(self):
        result = assess_posture({"NIST-52R2": [{"verdict": "NOT_OBSERVABLE"}]}, [])
        self.assertIsNone(result["score"])
        self.assertEqual(result["tier"], "NOT_EVALUABLE")


if __name__ == "__main__":
    unittest.main()
