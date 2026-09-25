"""
NIST SP 800-131A Rev. 2 Policy Pack (NIST-131A).

Implements 5 normative cryptographic transition rules evaluating key lengths,
hash functions, and key transport algorithms.
"""

from ..schema import RuleInput, PolicyResult, EvidenceItem


class NIST131aEvaluator:
    """Evaluates RuleInput against NIST SP 800-131A Rev. 2."""

    def evaluate_all(self, r_in: RuleInput) -> list[PolicyResult]:
        return [
            self.eval_n131a_sym_01(r_in),
            self.eval_n131a_sig_01(r_in),
            self.eval_n131a_hash_01(r_in),
            self.eval_n131a_dh_01(r_in),
            self.eval_n131a_rsa_01(r_in),
        ]

    def eval_n131a_sym_01(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        c_name = r_in.get("cipher_name")
        ev = [EvidenceItem(sid, "cipher_name", c_name, "TLS Session -> Negotiated Cipher")]

        if not c_name:
            return PolicyResult(
                policy="NIST-131A",
                rule_id="N131A-SYM-01",
                name="Symmetric Key Encryption Algorithms",
                source_id="SP800-131A-S02",
                source_section="2",
                source_text="Two-key TDEA, Three-key TDEA, and SKIPJACK are disallowed for encryption.",
                normative_term="DISALLOWED",
                applicability_scope="NIST-131A-GENERAL",
                verdict="NOT_APPLICABLE",
                evidence=ev,
            )

        c_upper = c_name.upper()
        if "3DES" in c_upper or "DES_EDE" in c_upper or "SKIPJACK" in c_upper:
            return PolicyResult(
                policy="NIST-131A",
                rule_id="N131A-SYM-01",
                name="Symmetric Key Encryption Algorithms",
                source_id="SP800-131A-S02",
                source_section="2",
                source_text="Two-key TDEA, Three-key TDEA, and SKIPJACK are disallowed for encryption.",
                normative_term="DISALLOWED",
                applicability_scope="NIST-131A-GENERAL",
                verdict="FAIL",
                evidence=ev,
                finding=f"Disallowed symmetric encryption algorithm negotiated: {c_name}.",
            )

        return PolicyResult(
            policy="NIST-131A",
            rule_id="N131A-SYM-01",
            name="Symmetric Key Encryption Algorithms",
            source_id="SP800-131A-S02",
            source_section="2",
            source_text="Two-key TDEA, Three-key TDEA, and SKIPJACK are disallowed for encryption.",
            normative_term="DISALLOWED",
            applicability_scope="NIST-131A-GENERAL",
            verdict="PASS",
            evidence=ev,
        )

    def eval_n131a_sig_01(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        if not r_in.get("cert_observable"):
            return PolicyResult(
                policy="NIST-131A",
                rule_id="N131A-SIG-01",
                name="Digital Signature Key Lengths",
                source_id="SP800-131A-S03",
                source_section="3",
                source_text="RSA modulus < 2048 bits or ECDSA/EdDSA order < 224 bits disallowed for signature generation.",
                normative_term="DISALLOWED",
                applicability_scope="NIST-131A-GENERAL",
                verdict="NOT_OBSERVABLE",
                evidence=[EvidenceItem(sid, "cert_observable", False, "Certificate Pipeline")],
                finding="Certificate material unobservable on wire.",
            )

        facts = r_in.get("non_anchor_cert_facts") or {}
        min_rsa = facts.get("min_rsa_key_size")
        min_ec = facts.get("min_ec_key_size")
        ev = [
            EvidenceItem(sid, "non_anchor_cert_facts.min_rsa_key_size", min_rsa, "X.509 Non-Anchor Cert Set"),
            EvidenceItem(sid, "non_anchor_cert_facts.min_ec_key_size", min_ec, "X.509 Non-Anchor Cert Set"),
        ]

        if min_rsa is None and min_ec is None:
            return PolicyResult(
                policy="NIST-131A",
                rule_id="N131A-SIG-01",
                name="Digital Signature Key Lengths",
                source_id="SP800-131A-S03",
                source_section="3",
                source_text="RSA modulus < 2048 bits or ECDSA/EdDSA order < 224 bits disallowed for signature generation.",
                normative_term="DISALLOWED",
                applicability_scope="NIST-131A-GENERAL",
                verdict="NOT_APPLICABLE",
                evidence=ev,
                finding="No RSA or EC public keys found in non-anchor certificate set.",
            )

        if (min_rsa is not None and min_rsa < 2048) or (min_ec is not None and min_ec < 224):
            reasons = []
            if min_rsa is not None and min_rsa < 2048:
                reasons.append(f"RSA key size {min_rsa} bits < 2048")
            if min_ec is not None and min_ec < 224:
                reasons.append(f"EC key size {min_ec} bits < 224")
            return PolicyResult(
                policy="NIST-131A",
                rule_id="N131A-SIG-01",
                name="Digital Signature Key Lengths",
                source_id="SP800-131A-S03",
                source_section="3",
                source_text="RSA modulus < 2048 bits or ECDSA/EdDSA order < 224 bits disallowed for signature generation.",
                normative_term="DISALLOWED",
                applicability_scope="NIST-131A-GENERAL",
                verdict="FAIL",
                evidence=ev,
                finding=f"Disallowed key length in non-anchor certificate set: {'; '.join(reasons)}.",
            )

        return PolicyResult(
            policy="NIST-131A",
            rule_id="N131A-SIG-01",
            name="Digital Signature Key Lengths",
            source_id="SP800-131A-S03",
            source_section="3",
            source_text="RSA modulus < 2048 bits or ECDSA/EdDSA order < 224 bits disallowed for signature generation.",
            normative_term="DISALLOWED",
            applicability_scope="NIST-131A-GENERAL",
            verdict="PASS",
            evidence=ev,
        )

    def eval_n131a_hash_01(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        if not r_in.get("cert_observable"):
            return PolicyResult(
                policy="NIST-131A",
                rule_id="N131A-HASH-01",
                name="Digital Signature Hash Functions",
                source_id="SP800-131A-S09",
                source_section="9",
                source_text="SHA-1 and MD5 are disallowed for digital signature generation.",
                normative_term="DISALLOWED",
                applicability_scope="NIST-131A-GENERAL",
                verdict="NOT_OBSERVABLE",
                evidence=[EvidenceItem(sid, "cert_observable", False, "Certificate Pipeline")],
                finding="Certificate material unobservable on wire.",
            )

        facts = r_in.get("non_anchor_cert_facts") or {}
        weak = facts.get("weak_signature_hashes") or []
        ev = [EvidenceItem(sid, "non_anchor_cert_facts.weak_signature_hashes", weak, "X.509 Non-Anchor Cert Set")]

        if weak:
            return PolicyResult(
                policy="NIST-131A",
                rule_id="N131A-HASH-01",
                name="Digital Signature Hash Functions",
                source_id="SP800-131A-S09",
                source_section="9",
                source_text="SHA-1 and MD5 are disallowed for digital signature generation.",
                normative_term="DISALLOWED",
                applicability_scope="NIST-131A-GENERAL",
                verdict="FAIL",
                evidence=ev,
                finding=f"Disallowed hash function(s) used for signature generation in non-anchor cert set: {', '.join(weak)}.",
            )

        return PolicyResult(
            policy="NIST-131A",
            rule_id="N131A-HASH-01",
            name="Digital Signature Hash Functions",
            source_id="SP800-131A-S09",
            source_section="9",
            source_text="SHA-1 and MD5 are disallowed for digital signature generation.",
            normative_term="DISALLOWED",
            applicability_scope="NIST-131A-GENERAL",
            verdict="PASS",
            evidence=ev,
        )

    def eval_n131a_dh_01(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        kex_type = r_in.get("tls12_kex_type")
        dh_bits = r_in.get("tls12_dh_prime_bits")
        ev = [
            EvidenceItem(sid, "tls12_kex_type", kex_type, "ServerKeyExchange -> Key Exchange Type"),
            EvidenceItem(sid, "tls12_dh_prime_bits", dh_bits, "ServerKeyExchange -> DH Prime Bits"),
        ]

        if kex_type != "DHE":
            return PolicyResult(
                policy="NIST-131A",
                rule_id="N131A-DH-01",
                name="Diffie-Hellman Key Agreement Parameter Size",
                source_id="SP800-131A-S05",
                source_section="5",
                source_text="Diffie-Hellman with prime modulus length < 2048 bits is disallowed.",
                normative_term="DISALLOWED",
                applicability_scope="NIST-131A-GENERAL",
                verdict="NOT_APPLICABLE",
                evidence=ev,
                finding="DHE key exchange not negotiated.",
            )

        if dh_bits is None:
            return PolicyResult(
                policy="NIST-131A",
                rule_id="N131A-DH-01",
                name="Diffie-Hellman Key Agreement Parameter Size",
                source_id="SP800-131A-S05",
                source_section="5",
                source_text="Diffie-Hellman with prime modulus length < 2048 bits is disallowed.",
                normative_term="DISALLOWED",
                applicability_scope="NIST-131A-GENERAL",
                verdict="NOT_OBSERVABLE",
                evidence=ev,
                finding="DHE parameters unobservable on wire.",
            )

        if dh_bits < 2048:
            return PolicyResult(
                policy="NIST-131A",
                rule_id="N131A-DH-01",
                name="Diffie-Hellman Key Agreement Parameter Size",
                source_id="SP800-131A-S05",
                source_section="5",
                source_text="Diffie-Hellman with prime modulus length < 2048 bits is disallowed.",
                normative_term="DISALLOWED",
                applicability_scope="NIST-131A-GENERAL",
                verdict="FAIL",
                evidence=ev,
                finding=f"DH prime modulus length ({dh_bits} bits) is less than the required 2048 bits.",
            )

        return PolicyResult(
            policy="NIST-131A",
            rule_id="N131A-DH-01",
            name="Diffie-Hellman Key Agreement Parameter Size",
            source_id="SP800-131A-S05",
            source_section="5",
            source_text="Diffie-Hellman with prime modulus length < 2048 bits is disallowed.",
            normative_term="DISALLOWED",
            applicability_scope="NIST-131A-GENERAL",
            verdict="PASS",
            evidence=ev,
        )

    def eval_n131a_rsa_01(self, r_in: RuleInput) -> PolicyResult:
        sid = r_in.get("stream_id", 0)
        c_name = r_in.get("cipher_name") or ""
        tls_ver = r_in.get("tls_version")
        ev = [
            EvidenceItem(sid, "tls_version", tls_ver, "TLS Session -> Negotiated Version"),
            EvidenceItem(sid, "cipher_name", c_name or None, "TLS Session -> Negotiated Cipher"),
        ]

        if not c_name or not tls_ver:
            return PolicyResult(
                policy="NIST-131A",
                rule_id="N131A-RSA-01",
                name="RSA Key Transport Disallowance Post-2023",
                source_id="SP800-131A-S06",
                source_section="6",
                source_text="Static RSA key transport (PKCS#1 v1.5 padding) is disallowed after Dec 31, 2023.",
                normative_term="DISALLOWED",
                applicability_scope="NIST-131A-GENERAL",
                verdict="NOT_APPLICABLE",
                evidence=ev,
            )

        if tls_ver in {"TLS 1.0", "TLS 1.1", "TLS 1.2"} and c_name.startswith("TLS_RSA_"):
            return PolicyResult(
                policy="NIST-131A",
                rule_id="N131A-RSA-01",
                name="RSA Key Transport Disallowance Post-2023",
                source_id="SP800-131A-S06",
                source_section="6",
                source_text="Static RSA key transport (PKCS#1 v1.5 padding) is disallowed after Dec 31, 2023.",
                normative_term="DISALLOWED",
                applicability_scope="NIST-131A-GENERAL",
                verdict="FAIL",
                evidence=ev,
                finding=f"Static RSA key transport cipher '{c_name}' negotiated with {tls_ver}; disallowed post-2023 per NIST SP 800-131A §6.",
            )

        return PolicyResult(
            policy="NIST-131A",
            rule_id="N131A-RSA-01",
            name="RSA Key Transport Disallowance Post-2023",
            source_id="SP800-131A-S06",
            source_section="6",
            source_text="Static RSA key transport (PKCS#1 v1.5 padding) is disallowed after Dec 31, 2023.",
            normative_term="DISALLOWED",
            applicability_scope="NIST-131A-GENERAL",
            verdict="PASS",
            evidence=ev,
        )
