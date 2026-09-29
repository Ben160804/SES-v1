"""
SecureMailScope Rule Engine — Comprehensive Verification Test Suite.

Verifies all 52 cryptographic policy rules and forensic observations across:
- NIST SP 800-52 Rev. 2 (24+ rules)
- NIST SP 800-131A Rev. 2 (5 rules)
- Mozilla TLS Guidelines 6.0 Modern Profile (6 rules)
- Mozilla TLS Guidelines 6.0 Intermediate Profile (5 rules)
- Policy-Neutral Forensic Observations (12 observations)
- Epistemological layer decoupling, capture-time provenance, directional alerts,
  and end-to-end PCAP evaluation.
"""

import unittest
from datetime import datetime, timezone
import os

from analysis.rule_engine import (
    RuleEngine,
    InputBuilder,
    build_rule_input,
    EvidenceItem,
    PolicyResult,
    ObservationResult,
)
from analysis.rule_engine.input_builder import (
    add_calendar_years,
    check_lifespan_3_calendar_years,
)


class TestRuleEngineUnit(unittest.TestCase):
    """Synthetic unit tests evaluating exact rule semantics."""

    def setUp(self):
        self.engine_gov = RuleEngine(mode="gov_only")
        self.engine_cit = RuleEngine(mode="citizen_facing")

    # ── 1. Directional Alert Resolution ──────────────────────────────────────
    def test_directional_alerts(self):
        session_client_alert = {
            "stream_id": 1,
            "handshake": {
                "flight": {
                    "alerts": [{"frame": 10, "level": "FATAL", "description": "HandshakeFailure", "sender": "client"}]
                }
            }
        }
        r_in = build_rule_input(session_client_alert)
        self.assertTrue(r_in["client_aborted_with_alert"])
        self.assertFalse(r_in["server_aborted_with_alert"])

        session_server_alert = {
            "stream_id": 2,
            "handshake": {
                "flight": {
                    "alerts": [{"frame": 12, "level": "FATAL", "description": "InternalError", "sender": "server"}]
                }
            }
        }
        r_in = build_rule_input(session_server_alert)
        self.assertFalse(r_in["client_aborted_with_alert"])
        self.assertTrue(r_in["server_aborted_with_alert"])

    # ── 2. N52-CLIENT-HOSTNAME-01 Semantics (5-case logic) ───────────────────
    def test_n52_client_hostname_01_all_cases(self):
        # Case A: No SNI offered -> NOT_APPLICABLE
        r_in_a = {"stream_id": 1, "hostname_match": "SKIPPED_NO_SNI"}
        res_a = self.engine_gov.nist_52r2.eval_n52_client_hostname_01(r_in_a)
        self.assertEqual(res_a.verdict, "NOT_APPLICABLE")

        # Case B: Mismatch + Client Application Data observed -> FAIL
        r_in_b = {
            "stream_id": 2,
            "hostname_match": "MISMATCH",
            "application_data_observed": True,
            "client_aborted_with_alert": False,
        }
        res_b = self.engine_gov.nist_52r2.eval_n52_client_hostname_01(r_in_b)
        self.assertEqual(res_b.verdict, "FAIL")

        # Case C: Mismatch + Client Fatal Alert -> NOT_OBSERVABLE
        r_in_c = {
            "stream_id": 3,
            "hostname_match": "MISMATCH",
            "application_data_observed": False,
            "client_aborted_with_alert": True,
        }
        res_c = self.engine_gov.nist_52r2.eval_n52_client_hostname_01(r_in_c)
        self.assertEqual(res_c.verdict, "NOT_OBSERVABLE")

        # Case D: Mismatch + Other Termination (no client app data) -> NOT_OBSERVABLE
        r_in_d = {
            "stream_id": 4,
            "hostname_match": "MISMATCH",
            "application_data_observed": "NOT_DETERMINABLE",
            "client_aborted_with_alert": False,
        }
        res_d = self.engine_gov.nist_52r2.eval_n52_client_hostname_01(r_in_d)
        self.assertEqual(res_d.verdict, "NOT_OBSERVABLE")

        # Case E: Hostname Matched -> NOT_OBSERVABLE
        r_in_e = {
            "stream_id": 5,
            "hostname_match": "MATCHED",
            "application_data_observed": True,
            "client_aborted_with_alert": False,
        }
        res_e = self.engine_gov.nist_52r2.eval_n52_client_hostname_01(r_in_e)
        self.assertEqual(res_e.verdict, "NOT_OBSERVABLE")

    # ── 3. Analyzer Trust Failure vs Client Compliance Decoupling ─────────────
    def test_analyzer_trust_failure_decoupling(self):
        # Analyzer trust store failed (e.g. self-signed root not installed in analyzer)
        session = {
            "stream_id": 1,
            "certificate": {
                "active_trust_store": "production",
                "active_trust_store_description": "Mozilla CA Bundle (150 roots)",
                "anchored_in_active_store": False,
                "path_verification_error": "self-signed certificate in certificate chain",
                "leaf_cert": {
                    "subject_dn": "CN=mail.example.gov",
                    "issuer_dn": "CN=Example Root CA",
                    "public_key_algorithm": "RSA",
                    "public_key_size": 2048,
                    "san_dns": ["mail.example.gov"],
                    "has_san": True,
                    "extended_key_usage": ["serverAuth"],
                    "has_server_auth_eku": True,
                    "has_any_eku": False,
                    "not_before": "2024-01-01T00:00:00Z",
                    "not_after": "2025-01-01T00:00:00Z",
                },
                "full_chain": [{
                    "subject_dn": "CN=mail.example.gov",
                    "issuer_dn": "CN=Example Root CA",
                    "public_key_algorithm": "RSA",
                    "public_key_size": 2048,
                    "not_before": "2024-01-01T00:00:00Z",
                    "not_after": "2025-01-01T00:00:00Z",
                }],
            },
            "tls": {
                "tls_version": "TLS 1.2",
                "cipher_name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            },
            "handshake": {
                "handshake_time_epoch": 1717200000.0,  # June 2024
            }
        }
        report = self.engine_gov.evaluate_stream(session)

        # Analyzer trust status must record failure as observation
        trust_obs = next(o for o in report.observations if o.obs_id == "OBS-ANALYZER-TRUST-STATUS")
        self.assertTrue(trust_obs.detected)
        self.assertIn("self-signed certificate", trust_obs.description)

        # NIST-52R2 rules must NOT fail for trust failure
        nist_verdicts = {r.rule_id: r.verdict for r in report.policy_results["NIST-52R2"]}
        self.assertEqual(nist_verdicts["N52-CERT-01"], "PASS")  # 2048-bit RSA passed
        self.assertEqual(nist_verdicts["N52-CERT-05"], "PASS")  # Valid at capture time
        self.assertEqual(nist_verdicts["N52-CERT-08"], "PASS")  # SAN present

    # ── 4. Government-Only vs Citizen-Facing TLS 1.0 ─────────────────────────
    def test_gov_only_vs_citizen_facing_tls10(self):
        r_in = {"stream_id": 1, "tls_version": "TLS 1.0"}
        res_gov = self.engine_gov.nist_52r2.eval_n52_tls_01(r_in)
        self.assertEqual(res_gov.verdict, "FAIL")
        self.assertEqual(res_gov.applicability_scope, "NIST-GOV-ONLY")

        res_cit = self.engine_cit.nist_52r2.eval_n52_tls_01(r_in)
        self.assertEqual(res_cit.verdict, "OBSERVATION")
        self.assertEqual(res_cit.applicability_scope, "NIST-CITIZEN-FACING")

    # ── 5. Capture-Time Certificate Validity ─────────────────────────────────
    def test_capture_time_certificate_validity(self):
        # 1. Valid at capture time
        r_in_valid = {
            "stream_id": 1,
            "cert_observable": True,
            "capture_time": datetime(2024, 6, 1, tzinfo=timezone.utc),
            "non_anchor_cert_facts": {
                "any_cert_expired_at_capture": False,
                "any_cert_not_yet_valid_at_capture": False,
            }
        }
        res_exp = self.engine_gov.nist_52r2.eval_n52_cert_05(r_in_valid)
        res_nyv = self.engine_gov.nist_52r2.eval_n52_cert_06(r_in_valid)
        self.assertEqual(res_exp.verdict, "PASS")
        self.assertEqual(res_nyv.verdict, "PASS")

        # 2. Expired at capture time
        r_in_expired = {
            "stream_id": 2,
            "cert_observable": True,
            "capture_time": datetime(2024, 6, 1, tzinfo=timezone.utc),
            "non_anchor_cert_facts": {
                "any_cert_expired_at_capture": True,
                "any_cert_not_yet_valid_at_capture": False,
            }
        }
        self.assertEqual(self.engine_gov.nist_52r2.eval_n52_cert_05(r_in_expired).verdict, "FAIL")

        # 3. Not yet valid at capture time
        r_in_future = {
            "stream_id": 3,
            "cert_observable": True,
            "capture_time": datetime(2024, 6, 1, tzinfo=timezone.utc),
            "non_anchor_cert_facts": {
                "any_cert_expired_at_capture": False,
                "any_cert_not_yet_valid_at_capture": True,
            }
        }
        self.assertEqual(self.engine_gov.nist_52r2.eval_n52_cert_06(r_in_future).verdict, "FAIL")

        # 4. Missing capture time -> NOT_OBSERVABLE (never substitute now)
        r_in_no_time = {
            "stream_id": 4,
            "cert_observable": True,
            "capture_time": None,
            "non_anchor_cert_facts": {
                "any_cert_expired_at_capture": None,
                "any_cert_not_yet_valid_at_capture": None,
            }
        }
        self.assertEqual(self.engine_gov.nist_52r2.eval_n52_cert_05(r_in_no_time).verdict, "NOT_OBSERVABLE")
        self.assertEqual(self.engine_gov.nist_52r2.eval_n52_cert_06(r_in_no_time).verdict, "NOT_OBSERVABLE")

    # ── 6. Root Anchor Exclusion in Path Aggregation ─────────────────────────
    def test_root_anchor_exclusion(self):
        session = {
            "stream_id": 1,
            "certificate": {
                "active_trust_store": "testbed",
                "anchored_in_active_store": True,
                "resolved_path": [
                    {"serial": "100", "subject": "CN=leaf", "issuer": "CN=intermediate"},
                    {"serial": "200", "subject": "CN=intermediate", "issuer": "CN=root"},
                    {"serial": "300", "subject": "CN=root", "issuer": "CN=root"},  # Self-signed root anchor
                ],
                "leaf_cert": {
                    "subject_dn": "CN=leaf",
                    "issuer_dn": "CN=intermediate",
                    "public_key_algorithm": "RSA",
                    "public_key_size": 2048,
                    "signature_hash_algorithm": "sha256",
                },
                "full_chain": [
                    {
                        "serial_number": "100",
                        "subject_dn": "CN=leaf",
                        "issuer_dn": "CN=intermediate",
                        "public_key_algorithm": "RSA",
                        "public_key_size": 2048,
                        "signature_hash_algorithm": "sha256",
                    },
                    {
                        "serial_number": "200",
                        "subject_dn": "CN=intermediate",
                        "issuer_dn": "CN=root",
                        "public_key_algorithm": "RSA",
                        "public_key_size": 4096,
                        "signature_hash_algorithm": "sha256",
                        "basic_constraints": {"ca": True},
                    },
                    {
                        "serial_number": "300",
                        "subject_dn": "CN=root",
                        "issuer_dn": "CN=root",
                        "public_key_algorithm": "RSA",
                        "public_key_size": 1024,  # Legacy 1024-bit root anchor
                        "signature_hash_algorithm": "sha1",  # Legacy SHA-1 root anchor
                    },
                ],
            }
        }
        r_in = build_rule_input(session)
        facts = r_in["non_anchor_cert_facts"]
        self.assertEqual(facts["path_basis"], "VALIDATED_PATH")
        # Root anchor (300) must be excluded
        self.assertEqual(facts["min_rsa_key_size"], 2048)
        self.assertEqual(facts["weak_signature_hashes"], [])

    # ── 7. Three-Calendar-Year Comparison with Leap Years ────────────────────
    def test_calendar_3_year_lifespan(self):
        # Leap year handling: Feb 29, 2024 + 3 years -> Feb 28, 2027
        dt_leap = datetime(2024, 2, 29, 12, 0, tzinfo=timezone.utc)
        self.assertEqual(add_calendar_years(dt_leap, 3), datetime(2027, 2, 28, 12, 0, tzinfo=timezone.utc))

        # Within 3 years
        self.assertFalse(check_lifespan_3_calendar_years(
            datetime(2024, 2, 29, 0, 0, tzinfo=timezone.utc),
            datetime(2027, 2, 28, 0, 0, tzinfo=timezone.utc),
        ))

        # Exceeds 3 years
        self.assertTrue(check_lifespan_3_calendar_years(
            datetime(2024, 2, 29, 0, 0, tzinfo=timezone.utc),
            datetime(2027, 3, 1, 0, 0, tzinfo=timezone.utc),
        ))

    # ── 8. Four-Suite NIST TLS 1.3 Exactness ──────────────────────────────────
    def test_nist_tls13_ciphers_exactness(self):
        # 4 approved suites
        for c in [
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_AES_128_CCM_SHA256",
            "TLS_AES_128_CCM_8_SHA256",
        ]:
            r_in = {"stream_id": 1, "tls_version": "TLS 1.3", "cipher_name": c}
            res = self.engine_gov.nist_52r2.eval_n52_cipher_05(r_in)
            self.assertEqual(res.verdict, "PASS")

        # ChaCha20 is standard in Mozilla Modern, but DISALLOWED under NIST SP 800-52 §3.3.1.2
        r_in_chacha = {"stream_id": 1, "tls_version": "TLS 1.3", "cipher_name": "TLS_CHACHA20_POLY1305_SHA256"}
        self.assertEqual(self.engine_gov.nist_52r2.eval_n52_cipher_05(r_in_chacha).verdict, "FAIL")

    # ── 9. Static RSA Key Transport Post-2023 Disallowance ───────────────────
    def test_static_rsa_key_transport_post_2023(self):
        r_in = {
            "stream_id": 1,
            "tls_version": "TLS 1.2",
            "cipher_name": "TLS_RSA_WITH_AES_128_CBC_SHA256",
        }
        res_131a = self.engine_gov.nist_131a.eval_n131a_rsa_01(r_in)
        self.assertEqual(res_131a.verdict, "FAIL")

        # Under NIST-52r2 Appendix D, it is an OBSERVATION (transitional list)
        res_52 = self.engine_gov.nist_52r2.eval_n52_cipher_06(r_in)
        self.assertEqual(res_52.verdict, "OBSERVATION")

    # ── 10. TLS 1.3 Outer Record 23 Unobservability ──────────────────────────
    def test_tls13_outer_record_23_unobservability(self):
        session = {
            "stream_id": 1,
            "tls": {"tls_version": "TLS 1.3"},
            "handshake": {
                "flight": {
                    "application_data_observed": "NOT_DETERMINABLE",
                    "outer_record_23_observed": True,
                }
            }
        }
        r_in = build_rule_input(session)
        self.assertEqual(r_in["application_data_observed"], "NOT_DETERMINABLE")

    # ── 11. Mozilla Modern and Intermediate Rules ────────────────────────────
    def test_mozilla_modern_and_intermediate(self):
        # Modern fails on TLS 1.2
        r_in_12 = {"stream_id": 1, "tls_version": "TLS 1.2", "cipher_name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}
        self.assertEqual(self.engine_gov.moz_modern.eval_mm_tls_01(r_in_12).verdict, "FAIL")

        # Intermediate passes on TLS 1.2
        self.assertEqual(self.engine_gov.moz_interm.eval_mi_tls_01(r_in_12).verdict, "PASS")
        self.assertEqual(self.engine_gov.moz_interm.eval_mi_cipher_01(r_in_12).verdict, "PASS")

        # Modern fails on RSA cert
        r_in_rsa_cert = {
            "stream_id": 1,
            "cert_observable": True,
            "leaf_cert": {"public_key_algorithm": "RSA", "lifespan_days": 60, "signature_algorithm_name": "sha256WithRSAEncryption"}
        }
        self.assertEqual(self.engine_gov.moz_modern.eval_mm_cert_02(r_in_rsa_cert).verdict, "FAIL")

        # Modern fails on > 90 day cert
        r_in_long_cert = {
            "stream_id": 1,
            "cert_observable": True,
            "leaf_cert": {"public_key_algorithm": "EC", "lifespan_days": 180, "signature_algorithm_name": "ecdsa-with-SHA256"}
        }
        self.assertEqual(self.engine_gov.moz_modern.eval_mm_cert_01(r_in_long_cert).verdict, "FAIL")

    # ── 12. Forensic Observations Layer ──────────────────────────────────────
    def test_observations_triggers(self):
        # Plaintext auth
        r_in_auth = {"stream_id": 1, "plaintext_auth_attempted": True, "tls_version": None}
        obs_auth = self.engine_gov.observations.eval_obs_sec_plaintext_auth(r_in_auth)
        self.assertTrue(obs_auth.detected)

        # Advertised not used
        r_in_adv = {"stream_id": 1, "starttls_offered": True, "tls_version": None}
        obs_adv = self.engine_gov.observations.eval_obs_starttls_advertised_not_used(r_in_adv)
        self.assertTrue(obs_adv.detected)

        # Rejected
        r_in_rej = {"stream_id": 1, "starttls_rejected": True}
        obs_rej = self.engine_gov.observations.eval_obs_starttls_03(r_in_rej)
        self.assertTrue(obs_rej.detected)

        # HRR
        r_in_hrr = {"stream_id": 1, "hello_retry_request": True}
        obs_hrr = self.engine_gov.observations.eval_obs_proto_01(r_in_hrr)
        self.assertTrue(obs_hrr.detected)

        # Downgrade sentinel
        r_in_ds = {"stream_id": 1, "downgrade_sentinel": {"detected": True, "type": "TLS12"}}
        obs_ds = self.engine_gov.observations.eval_obs_proto_03(r_in_ds)
        self.assertTrue(obs_ds.detected)

        # TLS 1.3 encrypted cert
        r_in_enc = {"stream_id": 1, "cert_observable": False, "tls_version": "TLS 1.3"}
        obs_enc = self.engine_gov.observations.eval_obs_cert_01(r_in_enc)
        self.assertTrue(obs_enc.detected)


class TestRuleEngineLivePCAPs(unittest.TestCase):
    """End-to-end integration tests on repository PCAPs."""

    def test_evaluate_tls12_pcap(self):
        engine = RuleEngine()
        pcap = "tls12_only.pcap"
        if not os.path.exists(pcap):
            self.skipTest(f"{pcap} not found")
        report = engine.evaluate_pcap(pcap)
        self.assertGreater(report.total_streams, 0)
        srep = report.stream_reports[0]
        self.assertEqual(len(srep.policy_results["NIST-52R2"]), 25)
        self.assertEqual(len(srep.policy_results["NIST-131A"]), 5)
        self.assertEqual(len(srep.policy_results["MOZ-MODERN"]), 6)
        self.assertEqual(len(srep.policy_results["MOZ-INTERM"]), 5)
        self.assertEqual(len(srep.observations), 12)

    def test_evaluate_cleartext_pcap(self):
        engine = RuleEngine()
        pcap = "smtp_cleartext_insecure.pcap"
        if not os.path.exists(pcap):
            self.skipTest(f"{pcap} not found")
        report = engine.evaluate_pcap(pcap)
        self.assertGreater(report.total_streams, 0)
        srep = report.stream_reports[0]
        # Plaintext auth observation must be detected on this pcap
        obs_auth = next(o for o in srep.observations if o.obs_id == "OBS-SEC-PLAINTEXT-AUTH")
        self.assertTrue(obs_auth.detected)


class TestRuleEngineMLSeparation(unittest.TestCase):
    def test_ml_context_is_separate_and_never_changes_policy_verdicts(self):
        session = {
            "stream_id": 77,
            "protocol": "SMTP",
            "tls": {
                "raw_version": "0x0301",
                "tls_version": "TLS 1.0",
                "cipher_name": "TLS_RSA_WITH_AES_128_CBC_SHA",
                "key_exchange": "RSA",
            },
            "starttls": {"status": "UPGRADED", "tls_active": True},
        }
        enabled = RuleEngine(enable_ml=True).evaluate_stream(session)
        disabled = RuleEngine(enable_ml=False).evaluate_stream(session)

        verdicts_enabled = {
            name: [(item.rule_id, item.verdict) for item in results]
            for name, results in enabled.policy_results.items()
        }
        verdicts_disabled = {
            name: [(item.rule_id, item.verdict) for item in results]
            for name, results in disabled.policy_results.items()
        }
        self.assertEqual(verdicts_enabled, verdicts_disabled)
        self.assertEqual(disabled.ml_results, {"status": "DISABLED"})
        self.assertEqual(enabled.ml_results["classifier"]["status"], "NOT_EVALUABLE")
        self.assertIn("smtp_configuration_anomaly", enabled.ml_results)
        self.assertIn("ml_results", enabled.to_dict())
        self.assertEqual(enabled.posture_assessment, disabled.posture_assessment)
        self.assertIn("posture_assessment", enabled.to_dict())


if __name__ == "__main__":
    unittest.main()
