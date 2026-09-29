"""Tests for safe abstention and task/cohort separation in optional ML output."""

import unittest

from analysis.ml_runtime import _certificate_features, _risk_proxy_features, _session_facts, _smtp_feature_dict, analyze_ml_session


class TestMLSessionRuntime(unittest.TestCase):
    def test_non_smtp_does_not_receive_smtp_model_score(self):
        result = analyze_ml_session({"protocol": "IMAP", "tls": None, "certificate": None})
        self.assertEqual(result["smtp_configuration_anomaly"]["status"], "NOT_APPLICABLE")
        self.assertEqual(result["smtp_configuration_rarity"]["status"], "NOT_APPLICABLE")
        self.assertEqual(result["classifier"]["status"], "NOT_APPLICABLE")
        self.assertEqual(result["classifier_risk_tier"]["status"], "NOT_APPLICABLE")
        self.assertNotEqual(result["synthetic_email_risk_classifier"]["status"], "NOT_APPLICABLE")
        self.assertEqual(result["zgrab_evidence_risk_classifier"]["status"], "NOT_APPLICABLE")
        self.assertIsNone(result["ml_assessment"]["predicted_tier_proxy"])

    def test_smtp_without_negotiated_tls_abstains(self):
        result = analyze_ml_session({
            "protocol": "SMTP",
            "tls": None,
            "certificate": None,
            "starttls": {"status": "CLEARTEXT_NO_ENCRYPTION"},
        })
        self.assertEqual(result["smtp_configuration_anomaly"]["status"], "NOT_EVALUABLE")
        self.assertEqual(result["smtp_configuration_rarity"]["status"], "NOT_EVALUABLE")
        self.assertEqual(result["certificate_novelty"]["status"], "NOT_EVALUABLE")
        self.assertEqual(result["classifier"]["status"], "NOT_EVALUABLE")
        self.assertEqual(result["classifier_risk_tier"]["status"], "NOT_EVALUABLE")
        self.assertEqual(result["synthetic_email_risk_classifier"]["status"], "NOT_APPLICABLE")
        evidence_model = result["zgrab_evidence_risk_classifier"]
        self.assertEqual(evidence_model["status"], "COMPLETED_ADVISORY_RUBRIC_ESTIMATE")
        self.assertEqual(evidence_model["prediction"], "CRITICAL")
        self.assertEqual(evidence_model["data_source"], "zgrab_real")
        self.assertIn("not a probability", evidence_model["score_semantics"])

    def test_synthetic_risk_classifier_is_routed_to_imap_and_pop3(self):
        for protocol in ("IMAP", "POP3"):
            with self.subTest(protocol=protocol):
                result = analyze_ml_session({
                    "protocol": protocol,
                    "starttls": {"status": "CLEARTEXT_NO_ENCRYPTION"},
                    "tls": None,
                    "certificate": None,
                })["synthetic_email_risk_classifier"]
                self.assertEqual(result["model_id"], "synthetic_email_posture_classifier_v2")
                self.assertEqual(result["status"], "COMPLETED_EXPERIMENTAL_NOT_VALIDATED")
                self.assertEqual(result["data_source"], "synthetic_simulation")
        smtp = analyze_ml_session({"protocol": "SMTP", "tls": None, "certificate": None})
        self.assertEqual(smtp["synthetic_email_risk_classifier"]["status"], "NOT_APPLICABLE")

    def test_proxy_classifier_is_exposed_as_advisory_and_never_as_policy(self):
        from unittest.mock import patch

        class FakeModel:
            model_id = "zgrab_runtime_rule_flag_proxy_v2"
            metadata = {
                "target_semantics": "Agreement with deterministic rule flags only.",
                "evaluation": "Leave-one-country-out CV",
                "macro_f1": 0.8,
                "sample_count": 530,
                "limitations": ["Proxy target"],
                "categorical_features": [
                    "tls_negotiated_version", "cipher_suite", "cert_key_algorithm",
                    "cert_signature_algorithm", "cert_self_signed", "cert_is_ca",
                    "cert_server_auth", "cert_digital_signature",
                ],
                "numeric_features": [
                    "cert_rsa_key_size", "cert_san_count", "cert_validity_days", "cert_chain_length",
                ],
                "runtime_feature_observability": {"p05_training_fraction": 0.0},
            }
            payload = type("Pipeline", (), {
                "classes_": ["HAS_RULE_FLAGGED_ISSUE", "NO_CURRENT_RULE_FLAG"],
                "predict": lambda self, rows: ["HAS_RULE_FLAGGED_ISSUE"],
                "predict_proba": lambda self, rows: [[0.72, 0.28]],
            })()

        session = {
            "protocol": "SMTP",
            "tls": {"tls_version": "TLS 1.2", "cipher_name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
            "handshake": {},
            "certificate": {"chain_length": 2, "leaf_cert": {
                "public_key_algorithm": "RSA", "public_key_size": 2048,
                "signature_algorithm_name": "sha256WithRSAEncryption",
                "not_before": "2024-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z",
                "san_dns": ["mail.example.test"], "san_ip": [],
                "basic_constraints": {"ca": False}, "key_usage": {"digital_signature": True},
                "extended_key_usage": ["serverAuth"],
            }},
        }
        with patch("analysis.ml_runtime._model", return_value=FakeModel()):
            analyzed = analyze_ml_session(session)
        result = analyzed["classifier"]
        self.assertEqual(result["status"], "COMPLETED_EXPLORATORY_PROXY_ESTIMATE", result)
        self.assertEqual(result["predicted_class"], "HAS_RULE_FLAGGED_ISSUE")
        self.assertEqual(result["proxy_issue_score"], 0.72)
        self.assertIn("not probability", result["score_semantics"])
        self.assertEqual(result["cross_cohort_transfer_status"], "NOT_VALIDATED")
        self.assertGreater(result["feature_observability"]["fraction"], 0)
        self.assertIn("remain authoritative", result["authority_note"])

    def test_classifier_abstains_below_training_observability_floor(self):
        from unittest.mock import patch

        class SparseModel:
            model_id = "zgrab_runtime_rule_flag_proxy_v2"
            metadata = {
                "categorical_features": ["tls_negotiated_version", "cipher_suite", "cert_signature_algorithm"],
                "numeric_features": ["cert_rsa_key_size"],
                "runtime_feature_observability": {"p05_training_fraction": 0.76},
                "target_semantics": "rule-flag proxy",
            }
            payload = object()

        session = {
            "protocol": "SMTP",
            "tls": {"tls_version": "TLS 1.2", "cipher_name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
            "handshake": {},
            "certificate": {"leaf_cert": {"signature_algorithm_name": "sha256WithRSAEncryption"}},
        }
        with patch("analysis.ml_runtime._model", return_value=SparseModel()):
            result = analyze_ml_session(session)["classifier"]
        self.assertEqual(result["status"], "NOT_EVALUABLE_LOW_FEATURE_COVERAGE", result)
        self.assertNotIn("predicted_class", result)
        self.assertEqual(result["feature_observability"]["training_p05_floor"], 0.76)

    def test_risk_tier_classifier_returns_uncalibrated_proxy_tier_separately(self):
        from unittest.mock import patch

        class TierModel:
            model_id = "zgrab_runtime_risk_tier_v1"
            metadata = {
                "model_version": "1.0",
                "feature_schema_version": "zgrab_smtp_runtime_risk_tier_v1",
                "categorical_features": ["tls_negotiated_version", "cipher_suite", "cert_key_algorithm"],
                "numeric_features": ["cert_rsa_key_size"],
                "runtime_feature_observability": {"p05_training_fraction": 0.0},
                "target_semantics": "Rule-rubric tier proxy only.",
                "sample_count": 530,
                "limitations": ["Proxy label"],
            }
            payload = {"model": type("Estimator", (), {
                "classes_": ["HIGH", "LOW", "MEDIUM"],
                "predict": lambda self, rows: ["HIGH"],
                "predict_proba": lambda self, rows: [[0.7, 0.1, 0.2]],
            })()}

        session = {
            "protocol": "SMTP",
            "tls": {"tls_version": "TLS 1.2", "cipher_name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
            "handshake": {},
            "certificate": {"chain_length": 2, "leaf_cert": {
                "public_key_algorithm": "RSA", "public_key_size": 2048,
                "signature_algorithm_name": "sha256WithRSAEncryption",
                "not_before": "2024-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z",
                "san_dns": ["mail.example.test"], "san_ip": [],
                "basic_constraints": {"ca": False}, "key_usage": {"digital_signature": True},
                "extended_key_usage": ["serverAuth"],
            }},
        }
        with patch("analysis.ml_runtime._model", return_value=TierModel()):
            analyzed = analyze_ml_session(session)
        result = analyzed["classifier_risk_tier"]
        self.assertEqual(result["status"], "COMPLETED_EXPLORATORY_TIER_PROXY")
        self.assertEqual(result["predicted_tier_proxy"], "HIGH")
        self.assertEqual(result["prediction"], "HIGH")
        self.assertEqual(result["class_scores_uncalibrated"]["HIGH"], 0.7)
        self.assertEqual(result["confidence_score_uncalibrated"], 0.7)
        self.assertGreater(result["feature_coverage"], 0)
        self.assertIn("not calibrated", result["score_semantics"])
        self.assertEqual(result["cross_cohort_transfer_status"], "NOT_VALIDATED")
        self.assertEqual(analyzed["ml_assessment"]["predicted_tier_proxy"], "HIGH")
        self.assertIsNone(analyzed["ml_assessment"]["combined_risk_score"])

    def test_observed_false_certificate_bits_are_not_treated_as_missing(self):
        features, _ = _certificate_features({"self_signed": False, "is_ca": False, "san_count": 0})
        self.assertEqual(features["self_signed"], "False")
        self.assertEqual(features["is_ca"], "False")
        self.assertEqual(features["san_count"], 0.0)
        self.assertEqual(features["san_count__missing"], 0.0)

    def test_certificate_feature_mapping_distinguishes_ocsp_from_issuer_aia(self):
        features = _risk_proxy_features({}, {
            "ocsp_url_count": 0,
            "issuer_url_count": 1,
            "has_certificate_policies": False,
        })
        self.assertEqual(features["cert_has_ocsp"], "False")
        self.assertEqual(features["cert_has_certificate_policy"], "False")
        self.assertEqual(features["cert_ocsp_url_count"], 0.0)
        self.assertEqual(features["cert_issuer_url_count"], 1.0)

    def test_selected_tls_version_overrides_tls13_legacy_version(self):
        facts, _ = _session_facts({
            "protocol": "SMTP",
            "tls": {"raw_version": "0x0303", "tls_version": "TLS 1.2", "cipher_name": "TLS_AES_128_GCM_SHA256"},
            "handshake": {"server_negotiation": {"selected_tls_version": "TLS 1.3"}},
        })
        self.assertEqual(facts["tls_version"], "TLSv1.2")
        self.assertEqual(facts["tls_selected_version"], "TLSv1.3")
        self.assertEqual(facts["tls_negotiated_version"], "TLSv1.3")
        self.assertEqual(_smtp_feature_dict(facts)["tls_negotiated_version"], "TLSv1.3")

    def test_synthetic_cohort_novelty_has_explicit_reference_support_fields(self):
        from unittest.mock import patch

        class FakeModel:
            model_id = "zgrab_smtp_negotiation_anomaly_v1"
            metadata = {
                "feature_schema_version": "zgrab_smtp_negotiation_v2",
                "features": ["tls_negotiated_version", "cipher_suite", "key_exchange"],
                "reference_count": 10,
                "reference_configuration_count": 1,
                "rarity_reference_counts": [],
                "limitations": [],
            }
            payload = {
                "vectorizer": type("Vectorizer", (), {"transform": lambda self, rows: rows})(),
                "model": type("Model", (), {
                    "decision_function": lambda self, matrix: [-0.2],
                    "predict": lambda self, matrix: [-1],
                })(),
            }

        session = {
            "protocol": "SMTP",
            "tls": {"tls_version": "TLS 1.2", "cipher_name": "cipher-x", "key_exchange": "x25519"},
            "handshake": {},
            "certificate": {},
        }
        with patch("analysis.ml_runtime._model", return_value=FakeModel()):
            analyzed = analyze_ml_session(session)
        result = analyzed["smtp_configuration_anomaly"]
        rarity = analyzed["smtp_configuration_rarity"]
        self.assertEqual(result["reference_support_status"], "UNSEEN_CONFIGURATION")
        self.assertEqual(rarity["status"], "COMPLETED_EXPLORATORY")
        self.assertEqual(rarity["support_status"], "UNSEEN_CONFIGURATION")
        self.assertEqual(rarity["configuration_count"], 0)
        self.assertIn("not evidence", rarity["semantics"])
        self.assertEqual(result["cross_cohort_transfer_status"], "NOT_VALIDATED")
        self.assertEqual(result["feature_schema_version"], "zgrab_smtp_negotiation_v2")
        self.assertGreater(result["anomaly_score"], 0)
        self.assertEqual(result["isolation_forest_score"], 0.2)
        self.assertTrue(result["anomaly_flag"])
        self.assertTrue(result["isolation_forest_flag"])
        self.assertEqual(result["prediction"], "NOVEL_CONFIGURATION")
        self.assertEqual(result["cohort"], "zgrab_real_smtp_tls")
        self.assertGreater(result["feature_coverage"], 0)
        self.assertIn("cohort novelty", result["interpretation_note"])

    def test_seen_configuration_is_not_primary_anomaly_even_if_isolation_forest_flags(self):
        from unittest.mock import patch

        class FakeModel:
            model_id = "zgrab_smtp_negotiation_anomaly_v1"
            metadata = {
                "feature_schema_version": "zgrab_smtp_negotiation_v2",
                "features": ["tls_negotiated_version", "cipher_suite", "key_exchange"],
                "reference_count": 10,
                "reference_configuration_count": 1,
                "rarity_reference_counts": [{
                    "configuration": ["TLSv1.2", "cipher-x", "x25519"], "count": 4,
                }],
                "limitations": [],
            }
            payload = {
                "vectorizer": type("Vectorizer", (), {"transform": lambda self, rows: rows})(),
                "model": type("Model", (), {
                    "decision_function": lambda self, matrix: [-0.2],
                    "predict": lambda self, matrix: [-1],
                })(),
            }

        session = {
            "protocol": "SMTP",
            "tls": {"tls_version": "TLS 1.2", "cipher_name": "cipher-x", "key_exchange": "x25519"},
            "handshake": {}, "certificate": {},
        }
        with patch("analysis.ml_runtime._model", return_value=FakeModel()):
            result = analyze_ml_session(session)["smtp_configuration_anomaly"]
        self.assertEqual(result["reference_support_status"], "SEEN_CONFIGURATION")
        self.assertFalse(result["anomaly_flag"])
        self.assertTrue(result["isolation_forest_flag"])
        self.assertEqual(result["prediction"], "WITHIN_REFERENCE")
