"""
analysis/test_pkix_backtracking.py
===================================
Unit tests for RFC 4158 / RFC 5280 PKIX path building with depth-first search
and backtracking.

Validates the 6 Core Requirements + Explicit Acceptance Criteria:
  1. First candidate fails (untrusted root), second candidate succeeds (trusted root)
     -> proves backtracking and produces TRUSTED_CHAIN using the alternate issuer.
  2. First candidate succeeds (standard linear chain)
     -> proves standard non-branching chains do not regress.
  3. All candidate branches fail
     -> returns failure with informative multi-branch diagnostic; never returns false TRUSTED_CHAIN.
  4. Loop protection
     -> cyclic candidate graphs terminate cleanly without recursion depth errors or duplicate certs.
  5. AKI/SKI preference is an exploration order, not a permanent exclusion
     -> AKI-preferred candidate is tried first; when it fails, alternate candidate completes the path.
  6. Arbitrary certificate ordering (Determinism)
     -> candidate pool permutations produce byte-identical resolved paths.
  7. Precedence between structural violations and trust failures
     -> CA_CONSTRAINT_VIOLATION and INVALID_SIGNATURE_IN_CHAIN preserve expected validator semantics.
"""

import datetime
import itertools
import os
import shutil
import struct
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from analysis.cert_validator import (
    classify_path_failure,
    extract_certificates,
    resolve_prospective_path,
    verify_pkix_path,
)
from analysis.parser import PCAPAnalyzer
from analysis.trust_store import TrustStoreManager


class TestPKIXBacktracking(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.now = datetime.datetime.now(datetime.timezone.utc)
        cls.temp_dir = tempfile.mkdtemp(prefix="pkix_test_")

        # -------------------------------------------------------------------
        # PKI Topologies Generation
        # -------------------------------------------------------------------
        # 1. Root CA A (Untrusted Root)
        cls.root_a_key = ec.generate_private_key(ec.SECP256R1())
        cls.root_a_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA A")])
        cls.root_a = (
            x509.CertificateBuilder()
            .subject_name(cls.root_a_name)
            .issuer_name(cls.root_a_name)
            .public_key(cls.root_a_key.public_key())
            .serial_number(100)
            .not_valid_before(cls.now - datetime.timedelta(days=1))
            .not_valid_after(cls.now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(cls.root_a_key, hashes.SHA256())
        )

        # 2. Root CA B (Trusted Root in Trust Store)
        cls.root_b_key = ec.generate_private_key(ec.SECP256R1())
        cls.root_b_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA B")])
        cls.root_b = (
            x509.CertificateBuilder()
            .subject_name(cls.root_b_name)
            .issuer_name(cls.root_b_name)
            .public_key(cls.root_b_key.public_key())
            .serial_number(200)
            .not_valid_before(cls.now - datetime.timedelta(days=1))
            .not_valid_after(cls.now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(cls.root_b_key, hashes.SHA256())
        )

        # Save Root B to trust store PEM
        cls.ca_b_path = os.path.join(cls.temp_dir, "trust_store_b.pem")
        with open(cls.ca_b_path, "wb") as f:
            f.write(cls.root_b.public_bytes(serialization.Encoding.PEM))
        cls.ts_b = TrustStoreManager(ca_path=cls.ca_b_path)

        # 3. Intermediate CA (Shared Subject & Key across Cross-Certs A and B)
        cls.inter_key = ec.generate_private_key(ec.SECP256R1())
        cls.inter_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate CA")])

        # Cross-cert A: Intermediate CA signed by Root A (serial 1 -> sorted first)
        cls.cross_a = (
            x509.CertificateBuilder()
            .subject_name(cls.inter_name)
            .issuer_name(cls.root_a_name)
            .public_key(cls.inter_key.public_key())
            .serial_number(1)
            .not_valid_before(cls.now - datetime.timedelta(days=1))
            .not_valid_after(cls.now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(cls.root_a_key, hashes.SHA256())
        )

        # Cross-cert B: Intermediate CA signed by Root B (serial 2)
        cls.cross_b = (
            x509.CertificateBuilder()
            .subject_name(cls.inter_name)
            .issuer_name(cls.root_b_name)
            .public_key(cls.inter_key.public_key())
            .serial_number(2)
            .not_valid_before(cls.now - datetime.timedelta(days=1))
            .not_valid_after(cls.now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(cls.root_b_key, hashes.SHA256())
        )

        # Leaf Certificate: Signed by Intermediate CA
        cls.leaf_key = ec.generate_private_key(ec.SECP256R1())
        cls.leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mail.test.local")])
        cls.leaf = (
            x509.CertificateBuilder()
            .subject_name(cls.leaf_name)
            .issuer_name(cls.inter_name)
            .public_key(cls.leaf_key.public_key())
            .serial_number(50)
            .not_valid_before(cls.now - datetime.timedelta(days=1))
            .not_valid_after(cls.now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(cls.inter_key, hashes.SHA256())
        )

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_01_first_candidate_fails_second_succeeds_backtracking(self):
        """
        Acceptance Test: Multi-issuer cross-certification topology where candidate A is
        tried first, leads to an untrusted root, triggers backtracking, and candidate B
        completes a valid path to Root B.
        """
        # Pool contains cross_a (serial 1), cross_b (serial 2), and root_a (untrusted)
        pool = [self.cross_a, self.cross_b, self.root_a]

        path, err, is_self_signed = resolve_prospective_path(
            self.leaf, pool, trust_store_manager=self.ts_b
        )

        self.assertIsNone(err, f"Expected successful path resolution, got error: {err}")
        self.assertGreaterEqual(len(path), 2)
        # Leaf is first
        self.assertEqual(path[0].serial_number, self.leaf.serial_number)
        # Immediate issuer MUST be Cross-cert B (serial 2), proving Cross-cert A (serial 1) was backtracked
        self.assertEqual(
            path[1].serial_number,
            self.cross_b.serial_number,
            "Resolver failed to backtrack: selected cross_a instead of trusted cross_b",
        )
        # Full OpenSSL PKIX path validation against Trust Store B must succeed
        pkix_ok, pkix_err = verify_pkix_path(path[0], path[1:], ca_path=self.ca_b_path)
        self.assertTrue(pkix_ok, f"Path with cross_b failed PKIX verification: {pkix_err}")

    def test_02_first_candidate_succeeds_standard_chain(self):
        """
        Standard linear chain: leaf -> intermediate -> trusted_root passes cleanly
        without backtracking, proving ordinary chains do not regress.
        """
        pool = [self.cross_b, self.root_b]
        path, err, is_self_signed = resolve_prospective_path(
            self.leaf, pool, trust_store_manager=self.ts_b
        )
        self.assertIsNone(err)
        self.assertEqual(len(path), 3)
        self.assertEqual(path[0].serial_number, self.leaf.serial_number)
        self.assertEqual(path[1].serial_number, self.cross_b.serial_number)
        self.assertEqual(path[2].serial_number, self.root_b.serial_number)
        self.assertTrue(is_self_signed)

        pkix_ok, pkix_err = verify_pkix_path(path[0], path[1:], ca_path=self.ca_b_path)
        self.assertTrue(pkix_ok, f"Standard chain PKIX failed: {pkix_err}")

    def test_03_all_candidate_branches_fail(self):
        """
        Multiple plausible candidate issuers, none of which reach a trusted anchor.
        Must report failure (UNKNOWN_ROOT_CA) with informative multi-branch diagnostic.
        Must never return a false TRUSTED_CHAIN.
        """
        # Create a trust store containing an unrelated root CA C (neither Root A nor Root B)
        root_c_key = ec.generate_private_key(ec.SECP256R1())
        root_c_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Unrelated Root CA C")])
        root_c = (
            x509.CertificateBuilder()
            .subject_name(root_c_name)
            .issuer_name(root_c_name)
            .public_key(root_c_key.public_key())
            .serial_number(888)
            .not_valid_before(self.now - datetime.timedelta(days=1))
            .not_valid_after(self.now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(root_c_key, hashes.SHA256())
        )
        ca_c_path = os.path.join(self.temp_dir, "unrelated_ca_c.pem")
        with open(ca_c_path, "wb") as f:
            f.write(root_c.public_bytes(serialization.Encoding.PEM))
        ts_c = TrustStoreManager(ca_path=ca_c_path)

        pool = [self.cross_a, self.cross_b, self.root_a, self.root_b]
        path, err, is_self_signed = resolve_prospective_path(
            self.leaf, pool, trust_store_manager=ts_c
        )

        self.assertIsNotNone(err, "Expected failure when all branches fail, got None")
        self.assertEqual(err[0], "UNKNOWN_ROOT_CA")
        # Diagnostic must clearly articulate the attempted branches
        self.assertIn("All 2 candidate branch(es) failed", err[1])
        self.assertIn("Root CA A", err[1])
        self.assertIn("Root CA B", err[1])

        # Verify classify_path_failure also reports UNKNOWN_ROOT_CA
        status, details = classify_path_failure(
            path[-1], ts_c._store_certs, ts_c.trust_store_type, err[1], leaf_obj=self.leaf
        )
        self.assertEqual(status, "UNKNOWN_ROOT_CA")
        self.assertNotEqual(status, "TRUSTED_CHAIN")

    def test_04_loop_protection(self):
        """
        Cyclic candidate graph (Cert 1 issues Cert 2, Cert 2 issues Cert 1).
        Verifies RFC 5280 / RFC 4158 loop protection terminates safely without
        recursion errors and no certificate appears twice.
        """
        key_1 = ec.generate_private_key(ec.SECP256R1())
        key_2 = ec.generate_private_key(ec.SECP256R1())
        name_1 = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Loop CA 1")])
        name_2 = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Loop CA 2")])

        # cert_1: Subject CA 1, Issuer CA 2, signed by key_2
        cert_1 = (
            x509.CertificateBuilder()
            .subject_name(name_1)
            .issuer_name(name_2)
            .public_key(key_1.public_key())
            .serial_number(301)
            .not_valid_before(self.now - datetime.timedelta(days=1))
            .not_valid_after(self.now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key_2, hashes.SHA256())
        )

        # cert_2: Subject CA 2, Issuer CA 1, signed by key_1
        cert_2 = (
            x509.CertificateBuilder()
            .subject_name(name_2)
            .issuer_name(name_1)
            .public_key(key_2.public_key())
            .serial_number(302)
            .not_valid_before(self.now - datetime.timedelta(days=1))
            .not_valid_after(self.now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key_1, hashes.SHA256())
        )

        # leaf issued by CA 1
        leaf_loop = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "loop.leaf.local")]))
            .issuer_name(name_1)
            .public_key(self.leaf_key.public_key())
            .serial_number(303)
            .not_valid_before(self.now - datetime.timedelta(days=1))
            .not_valid_after(self.now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key_1, hashes.SHA256())
        )

        pool = [cert_1, cert_2]
        path, err, is_self_signed = resolve_prospective_path(leaf_loop, pool)

        # Path must terminate cleanly without infinite recursion
        self.assertEqual(len(path), 3)
        self.assertEqual(len(path), len(set(path)), "Certificate appeared more than once in path (loop)")
        self.assertIsNotNone(err)

    def test_05_aki_ski_preference_is_only_a_preference(self):
        """
        AKI/SKI preference is an exploration order, not an exclusion:
        Preferred candidate (matching AKI) leads to untrusted root A.
        Alternate candidate (missing SKI) leads to trusted root B.
        Resolver tries preferred candidate first, backtracks when untrusted,
        and successfully resolves through alternate candidate.
        """
        # cross_a has SKI = KEY_ID_A (matches leaf_with_aki's AKI) -> Rank 0
        ski_a = x509.SubjectKeyIdentifier(b"KEY_IDENTIFIER_A\x00\x01\x02\x03")
        cross_a_aki = (
            x509.CertificateBuilder()
            .subject_name(self.inter_name)
            .issuer_name(self.root_a_name)
            .public_key(self.inter_key.public_key())
            .serial_number(902)  # higher serial number
            .not_valid_before(self.now - datetime.timedelta(days=1))
            .not_valid_after(self.now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(ski_a, critical=False)
            .sign(self.root_a_key, hashes.SHA256())
        )

        # cross_b has NO SKI extension -> Rank 2 (lower priority despite lower serial number)
        cross_b_no_ski = (
            x509.CertificateBuilder()
            .subject_name(self.inter_name)
            .issuer_name(self.root_b_name)
            .public_key(self.inter_key.public_key())
            .serial_number(901)  # lower serial number
            .not_valid_before(self.now - datetime.timedelta(days=1))
            .not_valid_after(self.now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(self.root_b_key, hashes.SHA256())
        )

        # leaf has AKI pointing to ski_a
        aki_leaf = x509.AuthorityKeyIdentifier(b"KEY_IDENTIFIER_A\x00\x01\x02\x03", None, None)
        leaf_with_aki = (
            x509.CertificateBuilder()
            .subject_name(self.leaf_name)
            .issuer_name(self.inter_name)
            .public_key(self.leaf_key.public_key())
            .serial_number(900)
            .not_valid_before(self.now - datetime.timedelta(days=1))
            .not_valid_after(self.now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(aki_leaf, critical=False)
            .sign(self.inter_key, hashes.SHA256())
        )

        # Pass pool with cross_b first in list: AKI ranking forces cross_a to be explored first
        pool = [cross_b_no_ski, cross_a_aki, self.root_a]
        path, err, is_self_signed = resolve_prospective_path(
            leaf_with_aki, pool, trust_store_manager=self.ts_b
        )

        self.assertIsNone(err)
        # Must resolve to cross_b_no_ski (serial 901), proving backtracking from preferred cross_a_aki
        self.assertEqual(path[1].serial_number, 901)
        pkix_ok, pkix_err = verify_pkix_path(path[0], path[1:], ca_path=self.ca_b_path)
        self.assertTrue(pkix_ok)

    def test_06_arbitrary_certificate_ordering(self):
        """
        Shuffling candidate pool across all permutations produces 100% byte-identical
        resolved paths, proving wire transmission order never influences the outcome.
        """
        pool_base = [self.cross_a, self.cross_b, self.root_a, self.root_b]
        baseline_serials = None

        for perm in itertools.permutations(pool_base):
            path, err, is_self_signed = resolve_prospective_path(
                self.leaf, list(perm), trust_store_manager=self.ts_b
            )
            self.assertIsNone(err)
            serials = tuple(c.serial_number for c in path)
            if baseline_serials is None:
                baseline_serials = serials
            else:
                self.assertEqual(
                    serials,
                    baseline_serials,
                    f"Candidate pool permutation {perm} produced divergent path: {serials} != {baseline_serials}",
                )

        self.assertEqual(len(list(itertools.permutations(pool_base))), 24)

    def test_07_ca_constraint_violation_precedence(self):
        """
        When intermediate candidate asserts basicConstraints ca=False,
        resolver rejects candidate and classifies failure as CA_CONSTRAINT_VIOLATION.
        """
        bad_inter = (
            x509.CertificateBuilder()
            .subject_name(self.inter_name)
            .issuer_name(self.root_b_name)
            .public_key(self.inter_key.public_key())
            .serial_number(501)
            .not_valid_before(self.now - datetime.timedelta(days=1))
            .not_valid_after(self.now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(self.root_b_key, hashes.SHA256())
        )

        pool = [bad_inter, self.root_b]
        path, err, is_self_signed = resolve_prospective_path(
            self.leaf, pool, trust_store_manager=self.ts_b
        )
        self.assertIsNotNone(err)
        self.assertEqual(err[0], "CA_CONSTRAINT_VIOLATION")

    def test_08_invalid_signature_in_chain_precedence(self):
        """
        When intermediate candidate signature verification fails,
        resolver rejects candidate and classifies failure as INVALID_SIGNATURE_IN_CHAIN.
        """
        wrong_key = ec.generate_private_key(ec.SECP256R1())
        bad_sig_inter = (
            x509.CertificateBuilder()
            .subject_name(self.inter_name)
            .issuer_name(self.root_b_name)
            .public_key(self.inter_key.public_key())
            .serial_number(502)
            .not_valid_before(self.now - datetime.timedelta(days=1))
            .not_valid_after(self.now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(wrong_key, hashes.SHA256())
        )

        pool = [bad_sig_inter, self.root_b]
        path, err, is_self_signed = resolve_prospective_path(
            self.leaf, pool, trust_store_manager=self.ts_b
        )
        self.assertIsNotNone(err)
        self.assertEqual(err[0], "INVALID_SIGNATURE_IN_CHAIN")

    @staticmethod
    def _build_pcap_with_certs(cert_list, filename):
        """Constructs a deterministic synthetic PCAP containing a TLS Certificate message on port 465."""
        items = b""
        for c in cert_list:
            der = c.public_bytes(serialization.Encoding.DER)
            items += struct.pack("!I", len(der))[1:] + der
        certs_bytes = struct.pack("!I", len(items))[1:] + items
        hs_payload = struct.pack("!B", 11) + struct.pack("!I", len(certs_bytes))[1:] + certs_bytes
        tls_rec = struct.pack("!BHH", 22, 0x0303, len(hs_payload)) + hs_payload

        def make_pcap_frame(src_port, dst_port, seq, ack, flags, payload):
            src_mac = b"\x00\x0c\x29\x6b\x8a\x11"
            dst_mac = b"\x00\x0c\x29\x3e\x5d\x22"
            eth = dst_mac + src_mac + b"\x08\x00"
            src_ip = struct.pack("!BBBB", 172, 28, 0, 10)
            dst_ip = struct.pack("!BBBB", 172, 28, 0, 1)
            tcp_hdr = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, (5 << 4), flags, 64240, 0, 0)
            tcp_seg = tcp_hdr + payload
            total_len = 20 + len(tcp_seg)
            ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 1234, 0x4000, 64, 6, 0, src_ip, dst_ip)
            packet = eth + ip_hdr + tcp_seg
            hdr = struct.pack("!IIII", 1725900000, 0, len(packet), len(packet))
            return hdr + packet

        pcap_hdr = struct.pack("!IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        frame = make_pcap_frame(465, 49152, 1000, 2000, 0x18, tls_rec)
        with open(filename, "wb") as f:
            f.write(pcap_hdr + frame)

    def test_09_wire_end_to_end_multi_issuer_fixture(self):
        """
        Wire / End-to-End Verification (RFC 4158 Backtracking via actual PCAPAnalyzer):
          1. Generate deterministic multi-issuer TLS Certificate fixture containing:
             [Leaf, Cross-cert A, Cross-cert B, Root A, Root B]
             where Trust Store contains Root B only.
          2. Run the actual PCAP analyzer (PCAPAnalyzer.extract_certificate()).
          3. Confirm certificate extraction succeeded and candidate pool contains all expected certs.
          4. Confirm final trust status == TRUSTED_CHAIN and anchored_in_active_store is True.
          5. Confirm actual analyzer result contains resolved_path:
             - resolved_path contains Cross-cert B (serial 2)
             - resolved_path terminates at Root B (serial 200)
             - Cross-cert A (serial 1) and Root A (serial 100) are NOT in selected path
          6. Confirm shuffling certificate order in the wire fixture produces identical resolved path
             using stable identifiers (serial numbers and DER SHA-256 fingerprints).
        """
        if not shutil.which("tshark"):
            self.skipTest("tshark is unavailable in this environment (environment-blocked)")

        pcap1 = os.path.join(self.temp_dir, "multi_issuer_wire_1.pcap")
        # Step 1: Wire fixture containing Leaf, Cross-cert A, Cross-cert B, Root A, Root B
        # Note: cross_a has serial 1, cross_b has serial 2, root_a has serial 100, root_b has serial 200
        wire_certs_1 = [self.leaf, self.cross_a, self.cross_b, self.root_a, self.root_b]
        self._build_pcap_with_certs(wire_certs_1, pcap1)

        # Step 2: Run actual PCAP analyzer
        analyzer1 = PCAPAnalyzer(pcap1, trust_store_manager=self.ts_b)
        res1 = analyzer1.extract_certificate()

        # Step 3: Confirm certificate extraction succeeded
        self.assertIn(0, res1, "Expected TCP stream 0 to contain extracted certificate telemetry")
        cinfo1 = res1[0]
        self.assertEqual(cinfo1["chain_length"], 5, "Expected all 5 certs extracted into wire telemetry")
        extracted_serials = [int(c["serial_number"]) for c in cinfo1["full_chain"]]
        self.assertEqual(extracted_serials, [50, 1, 2, 100, 200])

        # Confirm candidate pool contains expected multi-issuer certificates
        candidate_pool_serials = [int(c["serial_number"]) for c in cinfo1["full_chain"][1:]]
        self.assertEqual(
            candidate_pool_serials,
            [
                self.cross_a.serial_number,
                self.cross_b.serial_number,
                self.root_a.serial_number,
                self.root_b.serial_number,
            ],
        )

        # Step 4: Confirm final trust status == TRUSTED_CHAIN
        self.assertEqual(cinfo1["trust_status"], "TRUSTED_CHAIN")
        self.assertTrue(cinfo1["anchored_in_active_store"])
        self.assertIsNone(cinfo1["path_verification_error"])

        # Step 5: Verify resolved_path directly from actual analyzer result
        path1 = cinfo1.get("resolved_path", [])
        self.assertEqual(len(path1), 3, "Expected resolved path: Leaf -> Cross-cert B -> Root B")

        # Leaf at index 0
        self.assertEqual(path1[0]["serial"], str(self.leaf.serial_number))
        self.assertEqual(path1[0]["subject"], self.leaf_name.rfc4514_string())

        # Selected path contains Cross-cert B at index 1
        self.assertEqual(
            path1[1]["serial"],
            str(self.cross_b.serial_number),
            "Analyzer must select Cross-cert B, not Cross-cert A",
        )
        self.assertEqual(path1[1]["subject"], self.inter_name.rfc4514_string())
        self.assertEqual(path1[1]["issuer"], self.root_b_name.rfc4514_string())

        # Selected path terminates at Root B at index 2
        self.assertEqual(
            path1[2]["serial"],
            str(self.root_b.serial_number),
            "Analyzer selected path must terminate at Root B",
        )
        self.assertEqual(path1[2]["subject"], self.root_b_name.rfc4514_string())
        self.assertEqual(path1[2]["issuer"], self.root_b_name.rfc4514_string())

        # Cross-cert A and Root A are NOT in the selected path
        selected_serials_1 = [node["serial"] for node in path1]
        self.assertNotIn(str(self.cross_a.serial_number), selected_serials_1)
        self.assertNotIn(str(self.root_a.serial_number), selected_serials_1)

        # Step 6: Shuffled certificate order in wire fixture
        pcap2 = os.path.join(self.temp_dir, "multi_issuer_wire_2.pcap")
        wire_certs_2 = [self.leaf, self.cross_b, self.root_b, self.root_a, self.cross_a]
        self._build_pcap_with_certs(wire_certs_2, pcap2)

        analyzer2 = PCAPAnalyzer(pcap2, trust_store_manager=self.ts_b)
        res2 = analyzer2.extract_certificate()
        self.assertIn(0, res2)
        cinfo2 = res2[0]
        self.assertEqual(cinfo2["chain_length"], 5)
        self.assertEqual(cinfo2["trust_status"], "TRUSTED_CHAIN")
        self.assertTrue(cinfo2["anchored_in_active_store"])
        self.assertIsNone(cinfo2["path_verification_error"])

        path2 = cinfo2.get("resolved_path", [])
        self.assertEqual(len(path2), 3)

        # Invariant: original order vs shuffled order produce identical selected path
        # Compare stable serial numbers:
        selected_serials_2 = [node["serial"] for node in path2]
        self.assertEqual(selected_serials_1, selected_serials_2)
        self.assertEqual(selected_serials_1, ["50", "2", "200"])

        # Compare stable DER SHA-256 fingerprints:
        expected_fps = [
            self.leaf.fingerprint(hashes.SHA256()).hex(),
            self.cross_b.fingerprint(hashes.SHA256()).hex(),
            self.root_b.fingerprint(hashes.SHA256()).hex(),
        ]
        fps_1 = [node["sha256_fingerprint"] for node in path1]
        fps_2 = [node["sha256_fingerprint"] for node in path2]
        self.assertEqual(fps_1, expected_fps)
        self.assertEqual(fps_2, expected_fps)
        self.assertEqual(fps_1, fps_2)


if __name__ == "__main__":
    unittest.main()


