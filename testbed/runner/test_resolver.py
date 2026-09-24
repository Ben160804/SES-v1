"""
testbed/runner/test_resolver.py
===============================
Authoritative Test Suite for Executable Scenario Contracts & Deterministic Resolution.

Verifies:
  1. Class constraints resolve to deterministic selected ciphers.
  2. Exact cipher mode resolves to exact selected cipher.
  3. Empty candidate pools resolve to UNRESOLVABLE.
  4. Matrix contradictions remain UNRESOLVABLE with explicit telemetry.
  5. Repeated resolution produces byte-identical results.
  6. Leaf key is strictly decoupled from CA certificate signature algorithm.
  7. TLS 1.2 RSA ciphers derive RSA leaf compatibility.
  8. TLS 1.2 ECDSA ciphers derive ECDSA leaf compatibility.
  9. TLS 1.3 does not receive a fabricated ECDSA default.
 10. Dedicated phenomena resolve to DEDICATED_HARNESS.
 11. Zero PROVEN_* bypasses remain in code.
 12. Full 126-row scenario matrix resolves with 0 MULTIPLE_CANDIDATES.
"""

import json
from pathlib import Path
import sys
import unittest

# Ensure mailtest root is on path
_here = Path(__file__).resolve().parent
_project_root = _here.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from analysis.ciphers import load_iana_cipher_database
from testbed.runner.scenario_contract import (
    load_scenario_contracts,
    validate_scenario_contracts,
    ScenarioContract,
    GenerationMode,
    CipherMode,
)
from testbed.runner.spec import load_matrix, parse_scenario_row
from testbed.runner.resolver import (
    TLSCipherResolver,
    ResolutionStatus,
    RuntimeStatus,
    SelectionBasis,
    StaticRuntimeInspector,
)
from testbed.runner.stager import derive_client_tls_config, SMTPStager, IMAPStager, POP3Stager


class TestTLSCipherResolver(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.iana_db = load_iana_cipher_database()
        cls.contracts = load_scenario_contracts()
        cls.specs = load_matrix()
        cls.smtp_specs = [s for s in cls.specs if s.protocol == "smtp"]
        cls.resolver = TLSCipherResolver(iana_db=cls.iana_db, contracts=cls.contracts)

    def test_all_126_contracts_validated(self):
        """Validate that all 126 scenario contracts satisfy schema invariants."""
        errors = validate_scenario_contracts(self.contracts)
        self.assertEqual(errors, [], f"Contract validation failed: {errors}")
        self.assertEqual(len(self.contracts), 126)

    def test_class_constraint_deterministic_selection(self):
        """Standard class-constrained scenarios resolve deterministically to a concrete cipher."""
        spec_005 = [s for s in self.smtp_specs if s.scenario_id == "PCAP-005"][0]
        res_005 = self.resolver.resolve(spec_005)
        self.assertEqual(res_005.cipher_resolution_status, ResolutionStatus.CONFIGURABLE_CANDIDATE_SELECTED)
        self.assertIsNotNone(res_005.selected_cipher)
        self.assertEqual(res_005.selected_cipher, "TLS_AES_256_GCM_SHA384")
        self.assertEqual(res_005.selection_rank, 1)
        self.assertEqual(res_005.selection_basis, SelectionBasis.UNIQUE)

    def test_exact_cipher_selection(self):
        """Exact cipher mode resolves to exact requested cipher, or UNRESOLVABLE if unsupported."""
        # Valid exact cipher
        contract_exact = ScenarioContract(
            scenario_id="EXACT-001",
            generation_mode=GenerationMode.STANDARD,
            cipher_mode=CipherMode.EXACT,
            exact_cipher_suite="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        )
        custom_resolver = TLSCipherResolver(
            iana_db=self.iana_db,
            contracts={"EXACT-001": contract_exact},
        )
        spec = {
            "scenario_id": "EXACT-001",
            "tls_presence": "STARTTLS-upgraded",
            "tls_version": "1.2",
            "cipher_strength": "HIGH",
            "tls12_kex_type": "ECDHE",
        }
        res = custom_resolver.resolve(spec)
        self.assertEqual(res.cipher_resolution_status, ResolutionStatus.RESOLVED)
        self.assertEqual(res.selected_cipher, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
        self.assertEqual(res.selection_basis, SelectionBasis.EXACT_CONTRACT)

        # Unsupported exact cipher (not in runtime)
        contract_unsupported = ScenarioContract(
            scenario_id="EXACT-UNSUPPORTED",
            generation_mode=GenerationMode.STANDARD,
            cipher_mode=CipherMode.EXACT,
            exact_cipher_suite="TLS_AEGIS_256_SHA512",
        )
        custom_resolver_unsupported = TLSCipherResolver(
            iana_db=self.iana_db,
            contracts={"EXACT-UNSUPPORTED": contract_unsupported},
        )
        spec_unsupp = {
            "scenario_id": "EXACT-UNSUPPORTED",
            "tls_presence": "STARTTLS-upgraded",
            "tls_version": "1.3",
            "cipher_strength": "HIGH",
        }
        res_unsupp = custom_resolver_unsupported.resolve(spec_unsupp)
        self.assertEqual(res_unsupp.cipher_resolution_status, ResolutionStatus.UNRESOLVABLE)
        self.assertIsNone(res_unsupp.selected_cipher)

    def test_class_candidate_pool_empty_unresolvable(self):
        """When candidate pool is empty under runtime/protocol constraints, returns UNRESOLVABLE."""
        # Mock inspector with empty cipher set
        mock_resolver = TLSCipherResolver(
            iana_db=self.iana_db,
            runtime_supported_hex=set(),
        )
        spec_005 = [s for s in self.smtp_specs if s.scenario_id == "PCAP-005"][0]
        res = mock_resolver.resolve(spec_005)
        self.assertEqual(res.cipher_resolution_status, ResolutionStatus.UNRESOLVABLE)
        self.assertIsNone(res.selected_cipher)
        self.assertEqual(res.selection_basis, SelectionBasis.NONE)

    def test_oracle_contradiction_unresolvable(self):
        """All 11 MATRIX_ORACLE_INCONSISTENT scenarios remain strictly UNRESOLVABLE."""
        inconsistent_sids = [
            "PCAP-006", "PCAP-007", "PCAP-025", "PCAP-026",
            "PCAP-044", "PCAP-045", "PCAP-073", "PCAP-078",
            "PCAP-094", "PCAP-096", "PCAP-112",
        ]
        by_id = {s.scenario_id: s for s in self.specs}
        for sid in inconsistent_sids:
            spec = by_id[sid]
            res = self.resolver.resolve(spec)
            self.assertEqual(
                res.cipher_resolution_status,
                ResolutionStatus.UNRESOLVABLE,
                f"Scenario {sid} should be UNRESOLVABLE",
            )
            self.assertIsNone(
                res.selected_cipher,
                f"Scenario {sid} selected cipher despite oracle inconsistency",
            )
            self.assertEqual(res.selection_basis, SelectionBasis.NONE)
            self.assertIn("MATRIX_ORACLE_INCONSISTENT", res.reason)

    def test_repeated_resolution_identical_result(self):
        """Repeated resolution produces 100% byte-identical serialized JSON results."""
        for spec in self.specs:
            run1 = self.resolver.resolve(spec)
            run2 = self.resolver.resolve(spec)
            d1 = json.dumps(run1.to_dict(), sort_keys=True)
            d2 = json.dumps(run2.to_dict(), sort_keys=True)
            self.assertEqual(
                d1, d2,
                f"Scenario {spec.scenario_id} did not produce byte-identical results across runs",
            )

    def test_leaf_key_independent_from_cert_signature(self):
        """Certificate signature algorithm is strictly independent from leaf key algorithm."""
        # PCAP-001 (cert_sig_algo = ECDSA) resolves leaf_key_algo = rsa in TLS 1.3
        spec_001 = [s for s in self.specs if s.scenario_id == "PCAP-001"][0]
        res_001 = self.resolver.resolve(spec_001)
        self.assertEqual(res_001.leaf_key_algorithm, "rsa")
        self.assertEqual(res_001.leaf_key_size, 2048)

        # PCAP-018 (cert_sig_algo = RSA-SHA256) also resolves leaf_key_algo = rsa in TLS 1.3
        spec_018 = [s for s in self.specs if s.scenario_id == "PCAP-018"][0]
        res_018 = self.resolver.resolve(spec_018)
        self.assertEqual(res_018.leaf_key_algorithm, "rsa")
        self.assertEqual(res_018.leaf_key_size, 2048)

    def test_tls12_rsa_cipher_rsa_leaf_compatibility(self):
        """When an RSA cipher suite is selected in TLS <= 1.2, leaf key is RSA."""
        # PCAP-081 is TLS 1.0 DHE_RSA -> selects DHE_RSA cipher -> RSA leaf
        spec_081 = [s for s in self.specs if s.scenario_id == "PCAP-081"][0]
        res_081 = self.resolver.resolve(spec_081)
        self.assertEqual(res_081.cipher_resolution_status, ResolutionStatus.RESOLVED)
        self.assertIn("RSA", res_081.selected_cipher)
        self.assertEqual(res_081.leaf_key_algorithm, "rsa")
        self.assertEqual(res_081.leaf_key_size, 2048)

        # Also test with explicit server_leaf_key_type="RSA" on TLS 1.2
        spec_rsa = {
            "scenario_id": "TEST-RSA-12",
            "tls_presence": "STARTTLS-upgraded",
            "tls_version": "1.2",
            "cipher_strength": "HIGH",
            "server_leaf_key_type": "RSA",
        }
        res_rsa = self.resolver.resolve(spec_rsa)
        self.assertEqual(res_rsa.cipher_resolution_status, ResolutionStatus.RESOLVED)
        self.assertIn("RSA", res_rsa.selected_cipher)
        self.assertEqual(res_rsa.leaf_key_algorithm, "rsa")
        self.assertEqual(res_rsa.leaf_key_size, 2048)

    def test_tls12_ecdsa_cipher_ecdsa_leaf_compatibility(self):
        """When an ECDSA cipher suite is selected in TLS 1.2, leaf key is ECDSA."""
        # PCAP-082 is TLS 1.2 ECDHE -> selects ECDHE_ECDSA cipher -> ECDSA leaf
        spec_082 = [s for s in self.specs if s.scenario_id == "PCAP-082"][0]
        res_082 = self.resolver.resolve(spec_082)
        self.assertEqual(res_082.cipher_resolution_status, ResolutionStatus.RESOLVED)
        self.assertIn("ECDSA", res_082.selected_cipher)
        self.assertEqual(res_082.leaf_key_algorithm, "ecdsa")
        self.assertEqual(res_082.leaf_key_size, 256)

    def test_tls13_does_not_implicitly_force_ecdsa_leaf(self):
        """TLS 1.3 does not receive a fabricated ECDSA default leaf key."""
        spec_005 = [s for s in self.specs if s.scenario_id == "PCAP-005"][0]
        res_005 = self.resolver.resolve(spec_005)
        self.assertEqual(res_005.tls_version, "1.3")
        self.assertEqual(res_005.leaf_key_algorithm, "rsa")
        self.assertEqual(res_005.leaf_key_size, 2048)

    def test_dedicated_phenomenon_dedicated_harness(self):
        """Dedicated phenomena resolve to SPECIAL_HARNESS with explicit harness parameters."""
        by_id = {s.scenario_id: s for s in self.specs}

        # PCAP-121: Fatal Alert
        res_121 = self.resolver.resolve(by_id["PCAP-121"])
        self.assertEqual(res_121.cipher_resolution_status, ResolutionStatus.SPECIAL_HARNESS)
        self.assertEqual(res_121.special_harness, "server_sends_fatal_alert")

        # PCAP-064: MITM STARTTLS Strip
        res_064 = self.resolver.resolve(by_id["PCAP-064"])
        self.assertEqual(res_064.cipher_resolution_status, ResolutionStatus.SPECIAL_HARNESS)
        self.assertEqual(res_064.special_harness, "mitm_starttls_strip")

        # PCAP-108: HelloRetryRequest
        res_108 = self.resolver.resolve(by_id["PCAP-108"])
        self.assertEqual(res_108.cipher_resolution_status, ResolutionStatus.SPECIAL_HARNESS)
        self.assertEqual(res_108.special_harness, "hello_retry_request")
        self.assertIn("client_initial_key_share", res_108.special_harness_parameters)
        self.assertIn("server_required_group", res_108.special_harness_parameters)

        # PCAP-109: Downgrade Sentinel
        res_109 = self.resolver.resolve(by_id["PCAP-109"])
        self.assertEqual(res_109.cipher_resolution_status, ResolutionStatus.SPECIAL_HARNESS)
        self.assertEqual(res_109.special_harness, "downgrade_sentinel")

        # PCAP-114: Extension 50
        res_114 = self.resolver.resolve(by_id["PCAP-114"])
        self.assertEqual(res_114.cipher_resolution_status, ResolutionStatus.SPECIAL_HARNESS)
        self.assertEqual(res_114.special_harness, "custom_extension_50")

        # PCAP-119: Multi-Issuer PKI
        res_119 = self.resolver.resolve(by_id["PCAP-119"])
        self.assertEqual(res_119.cipher_resolution_status, ResolutionStatus.SPECIAL_HARNESS)
        self.assertEqual(res_119.special_harness, "dag_pki")

    def test_no_proven_bypass_remains(self):
        """Assert zero PROVEN_* allowlists or bypass sets exist in code."""
        stager_src = (_project_root / "testbed" / "runner" / "stager.py").read_text()
        resolver_src = (_project_root / "testbed" / "runner" / "resolver.py").read_text()
        runner_src = (_project_root / "testbed" / "runner" / "runner.py").read_text()

        for src, name in [(stager_src, "stager.py"), (resolver_src, "resolver.py"), (runner_src, "runner.py")]:
            self.assertNotIn("PROVEN_BASELINES", src, f"PROVEN_BASELINES found in {name}")
            self.assertNotIn("PROVEN_IMAP_BASELINES", src, f"PROVEN_IMAP_BASELINES found in {name}")
            self.assertNotIn("PROVEN_POP3_BASELINES", src, f"PROVEN_POP3_BASELINES found in {name}")

    def test_stager_renders_resolved_ciphers_without_bypasses(self):
        """Stager renders exact resolved ciphers directly for SMTP, IMAP, and POP3."""
        by_id = {s.scenario_id: s for s in self.specs}

        # SMTP (PCAP-005: TLS 1.3 - Postfix delegates to OpenSSL default preference, main.cf enforces high)
        smtp_stager = SMTPStager()
        main_cf = smtp_stager.render_main_cf(by_id["PCAP-005"], has_pki=True)
        self.assertIn("smtpd_tls_ciphers = high", main_cf)
        self.assertIn("smtpd_tls_mandatory_ciphers = high", main_cf)

        # SMTP (PCAP-081: TLS 1.0 - Postfix renders tls_high_cipherlist)
        main_cf_081 = smtp_stager.render_main_cf(by_id["PCAP-081"], has_pki=True)
        self.assertIn("tls_high_cipherlist = DHE-RSA-AES128-SHA", main_cf_081)

        # IMAP (PCAP-024: TLS 1.3 - Dovecot natively configures ssl_cipher_suites)
        imap_stager = IMAPStager()
        dovecot_imap = imap_stager.render_dovecot_conf(by_id["PCAP-024"], has_pki=True)
        self.assertIn("ssl_cipher_suites = TLS_AES_128_GCM_SHA256", dovecot_imap)

        # POP3 (PCAP-043: TLS 1.3 - Dovecot natively configures ssl_cipher_suites)
        pop3_stager = POP3Stager()
        dovecot_pop3 = pop3_stager.render_dovecot_conf(by_id["PCAP-043"], has_pki=True)
        self.assertIn("ssl_cipher_suites = TLS_AES_128_GCM_SHA256", dovecot_pop3)

    def test_zero_multiple_candidates_across_matrix(self):
        """Entire 126-row scenario matrix has 0 MULTIPLE_CANDIDATES."""
        counts = {}
        for s in self.specs:
            res = self.resolver.resolve(s)
            st = res.cipher_resolution_status.value
            counts[st] = counts.get(st, 0) + 1

        self.assertEqual(counts.get("MULTIPLE_CANDIDATES", 0), 0)
        self.assertEqual(counts.get("CONFIGURABLE_CANDIDATE_SELECTED"), 83)
        self.assertEqual(counts.get("DAEMON_CANNOT_ENFORCE"), 5)
        self.assertEqual(counts.get("SPECIAL_HARNESS"), 19)
        self.assertEqual(counts.get("UNRESOLVABLE"), 13)
        self.assertEqual(counts.get("NOT_APPLICABLE"), 6)
        self.assertEqual(sum(counts.values()), 126)

    def test_four_tier_candidate_counts(self):
        """Verify explicit 4-tier candidate counts on representative scenarios."""
        by_id = {s.scenario_id: s for s in self.specs}

        # PCAP-005 (SMTP TLS 1.3 HIGH): 6 IANA, 3 Runtime, 1 Daemon configurable (TLS_AES_256_GCM_SHA384)
        res_005 = self.resolver.resolve(by_id["PCAP-005"])
        self.assertEqual(res_005.iana_candidate_count, 6)
        self.assertEqual(res_005.runtime_candidate_count, 3)
        self.assertEqual(res_005.daemon_configurable_candidate_count, 1)
        self.assertEqual(res_005.selected_cipher, "TLS_AES_256_GCM_SHA384")

        # PCAP-024 (IMAP TLS 1.3 HIGH): 6 IANA, 3 Runtime, 3 Daemon configurable (Dovecot supports ssl_cipher_suites)
        res_024 = self.resolver.resolve(by_id["PCAP-024"])
        self.assertEqual(res_024.iana_candidate_count, 6)
        self.assertEqual(res_024.runtime_candidate_count, 3)
        self.assertEqual(res_024.daemon_configurable_candidate_count, 3)
        self.assertEqual(res_024.selected_cipher, "TLS_AES_128_GCM_SHA256")

    def test_daemon_cannot_enforce_tls13_weak(self):
        """Scenarios with unconfigurable/unsupported runtime suites resolve to DAEMON_CANNOT_ENFORCE."""
        by_id = {s.scenario_id: s for s in self.specs}
        for sid in ["PCAP-009", "PCAP-028", "PCAP-047"]:
            res = self.resolver.resolve(by_id[sid])
            self.assertEqual(
                res.cipher_resolution_status,
                ResolutionStatus.DAEMON_CANNOT_ENFORCE,
                f"Scenario {sid} should be DAEMON_CANNOT_ENFORCE",
            )
            self.assertIsNone(res.selected_cipher)
            self.assertEqual(res.daemon_configurable_candidate_count, 0)


if __name__ == "__main__":
    unittest.main()
