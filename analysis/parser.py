import os
import subprocess
import warnings
import ipaddress
from datetime import datetime, timezone
from cryptography import x509
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec, ed25519, ed448
from cryptography.x509.verification import Store, PolicyBuilder
from ciphers import get_cipher_info

# Filter non-compliant root CA serial number warning from legacy bundle certs per RFC 5280
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

# Standard TLS Handshake Version lookup table
TLS_VERSION_MAP = {
    "0x0301": "TLS 1.0",
    "0x0302": "TLS 1.1",
    "0x0303": "TLS 1.2",
    "0x0304": "TLS 1.3",
}

# TLS 1.3 NamedGroup → human-readable name (RFC 8446 §4.2.7, RFC 7919, RFC 8422)
# tshark emits tls.handshake.extensions_key_share_selected_group as FT_UINT16 BASE_DEC,
# so the keys here are decimal integers as strings (the form tshark's -T fields produces).
#
# WHY THIS MAP EXISTS:
#   In TLS 1.3, the cipher suite (e.g. TLS_AES_256_GCM_SHA384) specifies ONLY the symmetric
#   AEAD algorithm and the HKDF hash. The actual key exchange group (x25519, P-256, etc.)
#   is negotiated independently via the key_share extension (RFC 8446 §4.2.7). The server
#   picks one group from the client's offered key_share entries and puts its own share in
#   the ServerHello key_share extension. Without decoding this extension, you cannot
#   determine the actual DH group used — cipher_suite → kex gives you "TLS13_EPHEMERAL"
#   which is accurate but informationally incomplete.
#
# GROUP CATEGORIES:
#   Elliptic curve Diffie-Hellman ephemeral (ECDHE):
#     x25519 (29), x448 (30)           — Bernstein curves, RFC 7748
#     secp256r1 / P-256 (23)           — NIST prime curve, FIPS 186-4
#     secp384r1 / P-384 (24)           — NIST prime curve, FIPS 186-4
#     secp521r1 / P-521 (25)           — NIST prime curve, FIPS 186-4
#     brainpoolP* (26-28)              — BSI/ECC Brainpool curves, RFC 5639
#   Finite-field Diffie-Hellman ephemeral (FFDHE):
#     ffdhe2048–ffdhe8192 (256–260)    — RFC 7919 standardised FFDHE groups
#   Post-quantum / hybrid (provisional):
#     ML-KEM / Kyber entries (4587+)   — IETF drafts; not yet standardised
TLS13_GROUP_MAP = {
    # ECDHE — NIST curves (RFC 8422)
    "23": "secp256r1",
    "24": "secp384r1",
    "25": "secp521r1",
    # ECDHE — Brainpool curves (RFC 7027, RFC 8734)
    "26": "brainpoolP256r1",
    "27": "brainpoolP384r1",
    "28": "brainpoolP512r1",
    # ECDHE — Bernstein curves (RFC 7748, RFC 8446 §4.2.7)
    "29": "x25519",
    "30": "x448",
    # FFDHE — finite-field groups (RFC 7919) — still ephemeral, still PFS
    "256": "ffdhe2048",
    "257": "ffdhe3072",
    "258": "ffdhe4096",
    "259": "ffdhe6144",
    "260": "ffdhe8192",
}

# TLS 1.3 PSK key exchange mode → description (RFC 8446 §4.2.9)
# tshark field: tls.extension.psk_ke_mode, emitted as FT_UINT8 BASE_DEC.
#
# WHY PSK MODE MATTERS FOR SECURITY ASSESSMENT:
#   psk_ke  (0): PSK-ONLY. The resumed session uses only the PSK for key derivation.
#                No (EC)DHE is performed. This means the session key is NOT forward-secret
#                beyond what the original PSK provides. If the PSK is later compromised,
#                past sessions can be decrypted. This is the weaker resumption mode.
#   psk_dhe_ke (1): PSK + (EC)DHE. A new ephemeral DH exchange is performed alongside
#                the PSK. Forward secrecy of the resumed session is maintained because
#                the session key includes fresh DH entropy. RFC 8446 §C.4 recommends
#                this mode. This is the stronger resumption mode.
#
# Note: psk_ke_mode is only present in ClientHello (tshark HandshakeType 1). The server's
# ServerHello does NOT echo this extension — the server signals PSK acceptance via the
# pre_shared_key extension's selected_identity field. Mode presence = session resumption
# was attempted; we determine which mode was accepted by whether key_share was also sent.
TLS13_PSK_MODE_MAP = {
    "0": "psk_ke (PSK-only, no forward secrecy beyond PSK lifetime)",
    "1": "psk_dhe_ke (PSK + (EC)DHE, forward secrecy maintained)",
}


def verify_certificate_signature(child_cert, issuer_cert):
    """
    CRYPTOGRAPHIC SIGNATURE VERIFICATION (RFC 5280 §4.1.1.3, RFC 4055, RFC 8410):
    -------------------------------------------------------------------------------
    PURPOSE:
      Verify that 'issuer_cert' actually signed 'child_cert' by checking the
      cryptographic signature, not just comparing string names.

    WHY tbs_certificate_bytes AND NOT the full DER?
      RFC 5280 §4.1.1.3 defines the signed data as the TBSCertificate structure
      ('To Be Signed'). The outer Certificate structure wraps TBSCertificate +
      signatureAlgorithm + signatureValue. The signature covers ONLY the DER
      encoding of the TBSCertificate. Using the full cert DER would be wrong.
      python-cryptography exposes this correctly as cert.tbs_certificate_bytes.

    WHY WE BRANCH ON ISSUER KEY TYPE AND NOT ON THE OID STRING:
      The cryptography library's verify() API is type-dispatched — different
      key types have different method signatures (e.g., RSA takes padding+hash,
      ECDSA takes an ECDSA() object, Ed25519 takes nothing extra). Branching on
      isinstance() is therefore the only correct approach. Branching on an OID
      string and then calling a single generic .verify() would raise a TypeError
      at runtime.

    WHY RSA HAS TWO BRANCHES (PKCS#1 v1.5 vs PSS):
      RSA supports two different signature schemes that share the same key type
      but use completely different padding and verification procedures:
        - PKCS#1 v1.5 (RFC 3279):    Deterministic, legacy, still dominant in TLS 1.2
        - RSASSA-PSS   (RFC 4055):    Probabilistic, salt-based, required by TLS 1.3
      The signature scheme in use is declared via the cert's SignatureAlgorithm
      AlgorithmIdentifier parameters field. python-cryptography surfaces this as
      cert.signature_algorithm_parameters. If it is a padding.PSS instance, we
      must pass it directly to verify() as the padding argument; otherwise we
      default to padding.PKCS1v15() because that is the overwhelmingly dominant
      legacy scheme and the cryptography library requires an explicit padding object.
      Using getattr() with None default guards against older cert objects that
      may not expose the attribute at all.

    WHY Ed25519 / Ed448 TAKE NO HASH ARGUMENT:
      Per RFC 8032, Edwards-curve signatures (Ed25519 / Ed448) internally perform
      their own two-pass hashing (SHA-512 or SHAKE256) as part of the signing
      algorithm itself. There is no separate, user-configurable hash. Passing a
      hash algorithm to these verify() calls would raise a TypeError. These are
      the only current key types where signature_hash_algorithm returns None from
      python-cryptography, which is consistent with RFC 8032.

    WHY THIS FUNCTION EXISTS AT ALL (not delegated to cryptography's verifier):
      cryptography.x509.verification.ServerVerifier implicitly verifies all hop
      signatures as part of path building. However, for the SELF-SIGNED case
      (Case 1 below), ServerVerifier / ClientVerifier cannot be used because a
      self-signed cert has no issuer in the path — it IS the trust anchor. We
      must verify it independently to distinguish a genuine trusted self-signed
      root from one whose signature has been tampered with.

    Returns: (True, None) on success, or (False, error_description_str) on failure.
    """
    issuer_public_key = issuer_cert.public_key()
    try:
        if isinstance(issuer_public_key, rsa.RSAPublicKey):
            # Inspect the AlgorithmIdentifier parameters to distinguish PSS from PKCS#1 v1.5.
            # getattr() guard: older cryptography versions may not expose signature_algorithm_parameters.
            sig_params = getattr(child_cert, "signature_algorithm_parameters", None)
            if isinstance(sig_params, padding.PSS):
                # RSASSA-PSS: pass the PSS object directly as the padding — it already encodes
                # the MGF, salt length, and trailer byte per RFC 4055 §3.1.
                issuer_public_key.verify(
                    child_cert.signature,
                    child_cert.tbs_certificate_bytes,
                    sig_params,                             # padding.PSS with embedded MGF + salt
                    child_cert.signature_hash_algorithm     # e.g. SHA-256, SHA-384
                )
            else:
                # PKCS#1 v1.5: standard deterministic RSA signature per RFC 3279 §2.3.1.
                # We construct PKCS1v15() here — there are no parameters to extract.
                issuer_public_key.verify(
                    child_cert.signature,
                    child_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    child_cert.signature_hash_algorithm     # e.g. SHA-256
                )

        elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            # ECDSA (RFC 3279 §2.2.3): wrap the cert's declared hash in an ECDSA() object.
            # The curve parameters come from the issuer's public key itself.
            issuer_public_key.verify(
                child_cert.signature,
                child_cert.tbs_certificate_bytes,
                ec.ECDSA(child_cert.signature_hash_algorithm)
            )

        elif isinstance(issuer_public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            # Ed25519 / Ed448 (RFC 8032, RFC 8410): NO separate hash argument.
            # The hashing is baked into the signing algorithm (PureEdDSA mode).
            # signature_hash_algorithm returns None for these key types in python-cryptography.
            issuer_public_key.verify(
                child_cert.signature,
                child_cert.tbs_certificate_bytes
            )

        else:
            # Unknown/unsupported key algorithm. Surface the class name for forensic diagnostics.
            return False, f"Unsupported key type: {issuer_public_key.__class__.__name__}"

        return True, None

    except Exception as e:
        # Any exception from .verify() means the signature is cryptographically invalid
        # (wrong key, tampered data, wrong algorithm, etc.).
        return False, f"Signature verification failed: {type(e).__name__}: {e}"


def check_hostname_match(claimed_sni, san_dns, leaf_cn):
    """
    RFC 6125 HOSTNAME MATCHING (Section 6.4):
    -------------------------------------------------------------------------------
    PURPOSE:
      Determine whether the server's certificate identity matches what the client
      actually intended to reach (the Server Name Indication extension from
      ClientHello, RFC 6066 §3). This is independent of cryptographic path
      validation — a certificate can be cryptographically valid but still be for
      the wrong server.

    WHY SNI IS THE REFERENCE IDENTITY (not something we generate ourselves):
      RFC 6125 §6.1 defines the 'reference identifier' as the value the client
      independently established before initiating the connection — in practice,
      the SNI hostname the client sent in ClientHello. We MUST NOT derive the
      reference identity from the certificate's own attributes (SAN or CN),
      because that would make the check circular: a certificate would trivially
      match itself, proving nothing about whether this is the right server.

    WHY SAN TAKES ABSOLUTE PRECEDENCE OVER CN (RFC 6125 §6.4.4):
      The Common Name field (OID 2.5.4.3) was historically abused as the primary
      hostname identifier before the Subject Alternative Name extension existed.
      RFC 6125 §6.4.4 explicitly mandates that if ANY dNSName SAN is present, the
      client MUST use SAN and MUST NOT also check CN. Mixing SAN + CN would both
      be non-compliant and allow a cert with a malicious CN to appear to match a
      different hostname by accident.
      CA/Browser Forum Baseline Requirements §7.1.4.2 additionally prohibited
      issuing certs that rely solely on CN (without SAN) since 2017.

    WHY WE LOWERCASE BOTH SIDES:
      RFC 6125 §6.4.1 and RFC 5280 §7.2 specify that DNS name comparisons MUST
      be case-insensitive. Lower-casing both strings before comparison is the
      canonical way to enforce this without a case-folding library.

    WILDCARD MATCHING RULES (RFC 6125 §6.4.3):
      - A wildcard '*' is only permitted in the leftmost label: *.example.com
      - It matches exactly ONE label: *.example.com matches 'mail.example.com'
        but does NOT match 'a.mail.example.com' (two labels on the left).
      - We enforce the single-level constraint by comparing dot counts:
          target.count('.') == cand.count('.')
        If the target has more dots than the wildcard pattern, it has more labels
        on the left side and cannot match.
      - Partial wildcards (f*.example.com) are prohibited by CA/Browser Forum
        Baseline Requirements §11.3.1.3 (since 2012) and are not handled here.

    RETURN VALUES:
      'MATCHED'                   — Reference identity matched a SAN or CN entry
      'MISMATCH'                  — Reference identity did NOT match any entry
      'SKIPPED_NO_SNI'            — No reference identity available in PCAP; skip
      'SKIPPED_NO_CERT_IDENTIFIER'— Cert has no usable SAN and no CN; cannot check
    """
    if not claimed_sni:
        # No SNI in the ClientHello means we have no reference identity from the
        # client's connection context. Per RFC 6125 §6.1, without a reference
        # identifier we cannot perform hostname validation — skipping is correct.
        return "SKIPPED_NO_SNI"

    # Case-normalize per RFC 6125 §6.4.1
    target = claimed_sni.strip().lower()

    # RFC 6125 §6.4.4: SAN (dNSName) takes absolute priority over CN.
    # We only fall through to CN if there are literally zero dNSName SANs.
    if san_dns:
        candidates = [name.strip().lower() for name in san_dns]
    elif leaf_cn and leaf_cn != "Unknown":
        # Fallback: use CN only when no SAN is present at all.
        # "Unknown" means we could not extract a CN OID — treat as missing.
        candidates = [leaf_cn.strip().lower()]
    else:
        return "SKIPPED_NO_CERT_IDENTIFIER"

    for cand in candidates:
        # Exact match (case-normalized above already)
        if cand == target:
            return "MATCHED"

        # RFC 6125 §6.4.3: Wildcard left-label matching.
        # The wildcard character '*' is only legal as the ENTIRE leftmost label.
        if cand.startswith("*."):
            # cand[1:] gives e.g. ".example.com" (we keep the leading dot).
            # We use this dot-prefixed suffix rather than cand[2:] ("example.com")
            # so that target.endswith(suffix) won't falsely match "notexample.com".
            # The leading '.' means the suffix must start at a real label boundary.
            suffix = cand[1:]  # e.g. ".example.com"

            # Single-level enforcement:
            # *.example.com has 2 dots. target "mail.example.com" also has 2 dots → MATCH.
            # target "a.mail.example.com" has 3 dots → NOT a match (would cross two labels).
            # Comparing dot counts is the minimal correct implementation of this rule.
            if target.endswith(suffix) and target.count(".") == cand.count("."):
                return "MATCHED"

    return "MISMATCH"


class PCAPAnalyzer:
    def __init__(self, pcap_path, trust_store="testbed"):
        """
        TRUST STORE DESIGN (Swappable at Construction Time):
        -----------------------------------------------------------------------
        WHY 'testbed' IS THE DEFAULT:
          All PCAPs in this project are synthetic lab captures signed by our own
          generated root CA (data/test_root_ca.pem). Using 'production' (Mozilla
          bundle) would classify every test cert as UNTRUSTED_SELF_SIGNED, which
          is misleading during development. The default is 'testbed' so running
          the parser against lab captures gives accurate trust signals.
          For real production mail server captures, pass trust_store='production'.

        WHY WE STORE _store_certs AS A SEPARATE LIST:
          cryptography.x509.verification.Store is an opaque object — you cannot
          iterate or introspect its contents after construction. For the self-signed
          case (Case 1 in extract_certificate()), we need to check whether the cert
          is a member of the active trust store by object equality. We therefore
          keep _store_certs as the raw list of x509.Certificate objects alongside
          the Store so we can do:
              any(leaf_obj == root for root in self._store_certs)

        TRUST STORE MODES:
          - 'production': Mozilla CA root bundle (certifi.where()). Use for
            analyzing real-world email traffic from external mail servers.
          - 'testbed':    Local lab root CA (data/test_root_ca.pem). Use for
            analyzing synthetic captures generated by our own test CA.
          - custom:       A pre-built cryptography.x509.verification.Store object.
            Allows callers to supply their own enterprise or national trust bundle.
        """
        self.pcap_path = pcap_path

        # Store the trust_store parameter as a string ('testbed', 'production')
        # OR a pre-built Store object for custom use.
        self.trust_store_type = trust_store

        # Lazy-loaded on first call to _get_trust_store() — not loaded at construction
        # time because many operations (protocol, STARTTLS) don't need it.
        self._loaded_store = None
        self._store_certs = []        # Parallel list of Certificate objects for introspection
        self.trust_store_description = ""  # Human-readable label for output/reporting

    def _get_trust_store(self):
        """
        LAZY TRUST STORE LOADER:
        -----------------------------------------------------------------------
        WHY LAZY-LOAD AND NOT LOAD IN __init__:
          Loading the Mozilla CA bundle (300+ certs) or parsing PEM files is
          non-trivial I/O. Methods like detect_protocol() and detect_starttls()
          never touch the trust store. Lazy-loading avoids paying this cost for
          callers who never invoke extract_certificate().

        WHY load_pem_x509_certificates (plural):
          Both the certifi bundle and our testbed PEM may contain multiple
          concatenated PEM blocks. x509.load_pem_x509_certificates() iterates
          all of them and returns a list, which we then pass to Store().
        """
        if self._loaded_store is not None:
            # Already loaded on a previous call — return cached store immediately.
            return self._loaded_store

        self._store_certs = []

        if self.trust_store_type == "production":
            # certifi.where() returns the path to Mozilla's curated CA bundle.
            # This is the same bundle used by Python's ssl module and pip.
            # Appropriate for validating real external mail server certificates.
            import certifi
            with open(certifi.where(), "rb") as f:
                self._store_certs = x509.load_pem_x509_certificates(f.read())
            self._loaded_store = Store(self._store_certs)
            self.trust_store_description = (
                f"production (Mozilla CA bundle via certifi, {len(self._store_certs)} roots)"
            )

        elif self.trust_store_type == "testbed":
            # Our own generated root CA, created specifically for these lab PCAPs.
            # Path is relative to this script's directory to make it portable
            # regardless of the working directory the script is called from.
            ca_path = os.path.join(os.path.dirname(__file__), "..", "data", "test_root_ca.pem")
            if os.path.exists(ca_path):
                with open(ca_path, "rb") as f:
                    self._store_certs = x509.load_pem_x509_certificates(f.read())
                self._loaded_store = Store(self._store_certs)
                self.trust_store_description = (
                    f"testbed ({os.path.abspath(ca_path)}, {len(self._store_certs)} root(s))"
                )
            else:
                # Degrade gracefully: empty store means nothing will be trusted,
                # but the parser won't crash. The description surfaces the warning.
                self._loaded_store = Store([])
                self._store_certs = []
                self.trust_store_description = (
                    f"testbed (WARNING: {ca_path} not found, empty store)"
                )

        else:
            # Caller passed a pre-built Store object directly (custom enterprise bundle).
            # We cannot introspect it for _store_certs, so Case 1 self-signed check
            # (object-equality membership test) will always return False for custom stores.
            self._loaded_store = self.trust_store_type
            self.trust_store_description = "custom user-provided Store"

        return self._loaded_store

    @staticmethod
    def _get_x509_subject(identifier_str):
        """
        CONVERT SNI STRING → x509 SUBJECT TYPE FOR ServerVerifier (RFC 6066, RFC 5280):
        -----------------------------------------------------------------------
        PURPOSE:
          cryptography's PolicyBuilder.build_server_verifier() requires a typed
          Subject object, either x509.DNSName or x509.IPAddress. It does not
          accept a raw string. This method performs that conversion.

        WHY WE TRY IP ADDRESS FIRST:
          An SNI value (RFC 6066 §3) is typically a hostname, but clients CAN
          technically send an IP address literal as the SNI (though RFC 6066 §3
          explicitly says implementations MUST NOT send it for IP addresses —
          some clients violate this). By trying ipaddress.ip_address() first,
          we correctly classify '192.168.1.1' as x509.IPAddress (which is matched
          against iPAddress SAN entries per RFC 5280 §4.2.1.6) rather than as
          an x509.DNSName (which would never match).

        WHY WE LOWERCASE DNSName:
          RFC 5280 §7.2 and RFC 6125 §6.4.1 both specify that DNS name comparison
          is case-insensitive. python-cryptography's ServerVerifier performs
          case-insensitive comparison internally, but lowercasing at input prevents
          any edge-case normalisation surprises.

        WHY THIS NEVER USES THE CERTIFICATE'S OWN SAN/CN:
          This method is called with 'claimed_sni' only — the hostname the client
          declared in ClientHello. We never call it with the cert's own Subject CN
          or SAN values. Doing so would violate RFC 6125 §6.1 (reference identity
          must come from the connection context, not from the certificate itself).

        Returns: x509.DNSName or x509.IPAddress on success, None if unparseable.
        """
        if not identifier_str or identifier_str == "Unknown":
            return None
        clean_str = identifier_str.strip()

        # Try IP address first (covers both IPv4 and IPv6).
        # ipaddress.ip_address() raises ValueError for non-IP strings,
        # so the except branch handles the normal hostname case.
        try:
            return x509.IPAddress(ipaddress.ip_address(clean_str))
        except ValueError:
            # Hostname path: wrap in x509.DNSName, lower-cased per RFC 6125 §6.4.1.
            try:
                return x509.DNSName(clean_str.lower())
            except Exception:
                # Malformed hostname (e.g. contains illegal characters).
                # Return None so callers fall back to SNI-absent behaviour.
                return None

    def _verify_pkix_path(self, leaf_cert, candidate_intermediates):
        """
        RAW RFC 5280 PKIX PATH VALIDATION WITHOUT HOSTNAME BINDING:
        -----------------------------------------------------------------------
        PURPOSE:
          Validate the certificate chain cryptographically against the active
          trust store WITHOUT any hostname check. This is the fallback used when
          SNI is absent (RFC 6125 §6.1 forbids manufacturing a reference identity
          from the cert's own attributes) or when ServerVerifier has already failed
          and we need to distinguish WHY it failed (hostname mismatch vs missing
          intermediate vs genuine path failure).

        WHY NOT USE cryptography's ServerVerifier HERE:
          cryptography.x509.verification.ServerVerifier ALWAYS requires a Subject
          (x509.DNSName or x509.IPAddress) and checks hostname identity as part of
          path validation. There is no public API in this library for subject-free
          PKIX path validation — it wraps the 'webpki' Rust crate, which is
          designed for TLS and always evaluates the server's identity.
          When SNI is absent, we have no legitimate reference identity to give it.
          Passing the cert's own SAN/CN would be circular (RFC 6125 §6.1 violation).

        WHY NOT USE cryptography's ClientVerifier:
          ClientVerifier enforces the clientAuth EKU (OID 1.3.6.1.5.5.7.3.2).
          Mail servers present serverAuth certs. ClientVerifier would always fail
          with 'required EKU not found' regardless of path validity.

        WHY 'openssl verify' IS THE RIGHT TOOL HERE:
          'openssl verify' performs full RFC 5280 §6.1 path validation:
            - Signature verification at every hop
            - Validity period checks
            - basicConstraints (cA=TRUE required for intermediates)
            - pathLenConstraint enforcement
            - Chain anchoring to the trust store (-CAfile)
          Importantly, it does NOT check hostname/SAN by default (no -verify_hostname
          flag), making it exactly the path-only validator we need.
          OpenSSL 3.x is the reference implementation of RFC 5280 path processing.

        WHY TEMP FILES INSTEAD OF STDIN OR PIPES:
          'openssl verify' expects a file path as the final argument; it does not
          accept cert data on stdin. Writing to NamedTemporaryFiles with delete=False
          gives us real filesystem paths. We clean up in the 'finally' block to
          ensure no temp file leaks even if subprocess raises.

        COMMAND STRUCTURE:
          openssl verify -CAfile <trust_anchor.pem> [-untrusted <intermediates.pem>] <leaf.pem>
            -CAfile:    Trust anchor(s) — only certs in this file are treated as roots.
            -untrusted: Candidate intermediates — NOT trusted directly; only used to
                        build the chain from leaf to a root in -CAfile.
            <leaf.pem>: The end-entity certificate to validate.

        WHY -untrusted AND NOT -CAfile FOR INTERMEDIATES:
          If we put intermediates in -CAfile, openssl would trust them as roots
          and any leaf signed by them would be considered valid WITHOUT needing
          the actual root. -untrusted is the correct flag: the certs are provided
          as candidates for path construction but are not themselves trusted.

        RETURN VALUES:
          (True, None)         — Path valid, chain anchors to trust store
          (False, diagnostic)  — Path invalid; diagnostic is a filtered stderr string
        """
        import tempfile
        from cryptography.hazmat.primitives import serialization

        # Resolve the trust anchor file path for the active trust store mode.
        # We need the file path (not the in-memory Store object) because openssl
        # reads from disk via -CAfile.
        if self.trust_store_type == "testbed":
            ca_path = os.path.join(os.path.dirname(__file__), "..", "data", "test_root_ca.pem")
            if not os.path.exists(ca_path):
                return False, f"Testbed trust anchor file not found: {ca_path}"
        elif self.trust_store_type == "production":
            import certifi
            ca_path = certifi.where()
        else:
            # Custom Store objects are in-memory only — we have no file path to give openssl.
            # This is an intentional limitation for the SNI-absent path: callers using a
            # custom store should supply SNI so ServerVerifier can be used instead.
            return False, "Custom Store path validation without reference identity not supported"

        temp_files = []
        try:
            # Write the leaf certificate to a temp PEM file.
            # NamedTemporaryFile with delete=False: the file stays after close()
            # so we can pass its path to subprocess. We delete manually in 'finally'.
            with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f_leaf:
                f_leaf.write(leaf_cert.public_bytes(serialization.Encoding.PEM))
                leaf_path = f_leaf.name
                temp_files.append(leaf_path)

            # Start building the openssl verify command.
            cmd = ["openssl", "verify", "-CAfile", ca_path]

            if candidate_intermediates:
                # Bundle all candidate intermediates into a single PEM file.
                # RFC 8446 §4.4.2: intermediates may arrive in ANY order from the server.
                # openssl verify handles arbitrary ordering — it constructs the path itself.
                # We write them all sequentially; openssl's path engine picks the right ones.
                with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f_int:
                    for inter in candidate_intermediates:
                        f_int.write(inter.public_bytes(serialization.Encoding.PEM))
                    int_path = f_int.name
                    temp_files.append(int_path)
                # -untrusted: provide as path-building candidates, NOT as roots.
                cmd.extend(["-untrusted", int_path])

            cmd.append(leaf_path)

            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode == 0:
                # returncode 0: "OK" — chain is valid and anchored.
                return True, None
            else:
                # returncode != 0: chain failed. Extract the meaningful error line(s).
                # OpenSSL emits errors to stderr in the format:
                #   "error NN at N depth lookup: <description>"
                # We filter for lines containing 'error' to strip the OK confirmation
                # lines that openssl also emits even on failure.
                err_raw = res.stderr.strip() or res.stdout.strip()
                lines = [l.strip() for l in err_raw.splitlines() if "error" in l.lower()]
                diagnostic = "; ".join(lines) if lines else err_raw
                return False, diagnostic

        except Exception as e:
            return False, f"PKIX path verification error: {type(e).__name__}: {e}"

        finally:
            # Always clean up temp files, even if subprocess raised.
            # OSError guard: handles the rare case where the file was already deleted.
            for p in temp_files:
                try:
                    os.unlink(p)
                except OSError:
                    pass


    def extract_tls_info(self):
        """
        TLS SESSION PARAMETER EXTRACTION (RFC 5246, RFC 8446):
        -----------------------------------------------------------------------
        WHY WE PARSE TWO SEPARATE VERSION FIELDS (RFC 8446 §4.2.1 Middlebox Lie):
          In TLS 1.3, the ServerHello 'legacy_version' field is intentionally
          hardcoded to 0x0303 (TLS 1.2) to prevent middleboxes from dropping the
          connection. The true negotiated version is in the 'supported_versions'
          extension. We check that first and fall back to the legacy field for
          genuine TLS 1.2.

        TLS 1.3 KEY EXCHANGE — WHY THE CIPHER SUITE IS NOT ENOUGH (RFC 8446 §4.2.7):
          In TLS 1.2, the cipher suite encodes everything:
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 → kex=ECDHE, auth=RSA, cipher=AES-256-GCM

          In TLS 1.3, the cipher suite encodes ONLY the symmetric AEAD and HKDF hash:
            TLS_AES_256_GCM_SHA384 → cipher=AES-256-GCM, hash=SHA-384
          The key exchange and PSK mode are negotiated via separate ServerHello extensions.

        TLS 1.3 KEY EXCHANGE MODE — DERIVED FROM SERVERHELLO EXTENSIONS ONLY (RFC 8446 §4.2.9):
          The correct source for what was ACTUALLY SELECTED is the ServerHello alone:

            key_share present,  pre_shared_key absent  → ECDHE     (fresh full handshake)
            key_share absent,   pre_shared_key present → PSK_ONLY  (resumption, no new DH)
            key_share present,  pre_shared_key present → PSK_DHE   (resumption + new DH)

          WHY NOT THE CLIENTHELLO psk_key_exchange_modes:
            That extension declares what modes the CLIENT WILL ACCEPT. It is a negotiation
            offer, not a selection. The server makes the actual selection and signals it by
            including or omitting key_share and pre_shared_key in the ServerHello.
            Reading the ClientHello mode and calling it the selected mode is wrong — the
            client may offer both psk_ke and psk_dhe_ke; only the server's response
            tells you which one was actually used.

        FORWARD SECRECY CORRECTION FOR PSK_ONLY (RFC 8446 §C.4):
          Forward secrecy is NOT guaranteed for all TLS 1.3 modes. Specifically:
            ECDHE:    True  — ephemeral DH key material is fresh and discarded after handshake
            PSK_DHE:  True  — PSK + fresh ephemeral DH; FS is preserved for resumed sessions
            PSK_ONLY: False — session key derived purely from PSK; if PSK is later leaked,
                              past sessions encrypted under that PSK can be decrypted
          RFC 8446 §C.4 explicitly calls out the PSK-only weakness:
            "without DHE, the forward secrecy properties of the prior connection are lost".

        FIELDS EMITTED:
          Standard (TLS 1.2 and 1.3):
            tls_version        — True negotiated version
            cipher_name        — Full IANA cipher suite name
            key_exchange       — Cipher-suite label (ECDHE/RSA_STATIC/TLS13_EPHEMERAL…)
            forward_secrecy    — Corrected boolean (False for PSK_ONLY)
            cipher_strength    — HIGH / MEDIUM / WEAK / BROKEN
          TLS 1.3 only (None for TLS 1.2):
            tls13_key_exchange_group  — Actual (EC)DHE group (x25519, secp256r1, ffdhe2048…)
            tls13_psk_selected        — True if ServerHello contains pre_shared_key (resumption)
            tls13_key_exchange_mode   — ECDHE / PSK_DHE / PSK_ONLY (derived from ServerHello)
        """
        # ── ServerHello tshark pass ───────────────────────────────────────────────────
        # HandshakeType 2 = ServerHello. We extract the TLS 1.3 key-exchange indicators
        # from the ServerHello in a single tshark invocation:
        #
        #   tls.handshake.extensions_key_share_group
        #     FT_UINT16 BASE_DEC — the group inside the ServerHello's key_share entry
        #     (RFC 8446 §4.2.7). This carries the server's chosen DH group (e.g. 29 for x25519).
        #
        #   tls.handshake.extensions_key_share_selected_group
        #     FT_UINT16 BASE_DEC — used in HelloRetryRequest when the server asks the
        #     client to retry with a specific group. Handled as fallback.
        #
        #   tls.handshake.extensions.psk.identity.selected
        #     Present (any value) iff the server's ServerHello includes the pre_shared_key
        #     extension — the direct wire-level evidence that PSK was selected (RFC 8446 §4.2.9).
        command = [
            "tshark",
            "-r", self.pcap_path,
            "-Y", "tls.handshake.type == 2",
            "-T", "fields",
            "-e", "tcp.stream",
            "-e", "tls.handshake.version",
            "-e", "tls.handshake.extensions.supported_version",
            "-e", "tls.handshake.ciphersuite",
            # TLS 1.3: ServerHello key_share entry group (Wireshark dissector uses extensions_key_share_group)
            "-e", "tls.handshake.extensions_key_share_group",
            # Fallback/HelloRetryRequest: selected group field
            "-e", "tls.handshake.extensions_key_share_selected_group",
            # TLS 1.3: server PSK selected identity index. Non-empty = PSK accepted.
            "-e", "tls.handshake.extensions.psk.identity.selected",
        ]

        result = subprocess.run(command, capture_output=True, text=True)
        if not result.stdout.strip():
            return {}

        lines = result.stdout.strip().split('\n')

        # Keyed by stream_id (int) for O(1) downstream correlation with cert/protocol/STARTTLS.
        sessions = {}

        for line in lines:
            parts = line.split('\t')
            # Pad to 7 columns: TLS 1.2 sessions produce empty strings for the last three fields.
            while len(parts) < 7:
                parts.append("")
            if not parts[0].isdigit():
                continue

            stream_id   = parts[0]
            hs_ver      = parts[1]
            supp_ver    = parts[2]
            ciphersuite = parts[3]
            ks_group    = parts[4].strip()  # key_share group in ServerHello — decimal string or ""
            ks_sel_grp  = parts[5].strip()  # key_share selected group (HRR)   — decimal string or ""
            psk_sel     = parts[6].strip()  # PSK selected identity            — any value or ""

            effective_ks_group = ks_group if ks_group else ks_sel_grp

            sid = int(stream_id)

            # WHY WE PREFER supp_ver OVER hs_ver (RFC 8446 §4.2.1 Middlebox Lie):
            # TLS 1.3 ServerHello sets legacy_version = 0x0303 to avoid being dropped by
            # old middleboxes. The true version is in the supported_versions extension.
            # Defensive .split(",")[0] handles cases where tshark outputs comma-separated values.
            supp_ver_first = supp_ver.split(",")[0].strip().lower() if supp_ver.strip() else ""
            true_ver_hex = supp_ver_first if supp_ver_first else hs_ver.strip().lower()
            is_tls13 = (true_ver_hex == "0x0304")

            cs_clean = ciphersuite.strip().lower()
            cipher_info = get_cipher_info(cs_clean)

            # ── TLS 1.3 KEY EXCHANGE GROUP ────────────────────────────────────────────
            # tshark emits the NamedGroup as a decimal uint16 (e.g. "29" = x25519).
            # Empty for TLS 1.2 (where kex is encoded in the cipher suite name) and for
            # PSK-only TLS 1.3 sessions (no key_share extension in those ServerHellos).
            tls13_key_exchange_group = None
            if is_tls13 and effective_ks_group:
                tls13_key_exchange_group = TLS13_GROUP_MAP.get(effective_ks_group, f"unknown_group_{effective_ks_group}")

            # ── TLS 1.3 PSK SELECTION INDICATOR ──────────────────────────────────────
            # Non-empty psk.identity.selected = the ServerHello carried a pre_shared_key
            # extension, which is the direct wire-level signal that the server selected PSK
            # (RFC 8446 §4.2.9). This is the ONLY authoritative source; we do not infer
            # resumption from ClientHello fields.
            tls13_psk_selected = bool(psk_sel) if is_tls13 else None

            # ── TLS 1.3 KEY EXCHANGE MODE — SERVER-SIDE INFERENCE (RFC 8446 §4.2.7/9) ─
            # Derived exclusively from what the ServerHello actually contains:
            #
            #   key_share present  + pre_shared_key absent  → ECDHE      (fresh handshake)
            #   key_share absent   + pre_shared_key present → PSK_ONLY   (resumption, no DHE)
            #   key_share present  + pre_shared_key present → PSK_DHE    (resumption + DHE)
            #
            # This is the correct RFC 8446 interpretation. We do NOT use the ClientHello
            # psk_key_exchange_modes extension because that encodes what the client offers,
            # not what the server selected. Only the ServerHello is authoritative.
            tls13_key_exchange_mode = None
            if is_tls13:
                has_ks  = bool(effective_ks_group)
                has_psk = bool(psk_sel)
                if has_ks and not has_psk:
                    tls13_key_exchange_mode = "ECDHE"
                elif has_psk and not has_ks:
                    tls13_key_exchange_mode = "PSK_ONLY"
                elif has_psk and has_ks:
                    tls13_key_exchange_mode = "PSK_DHE"
                # Both absent: malformed/incomplete capture; leave None.

            # ── FORWARD SECRECY CORRECTION ────────────────────────────────────────────
            # The cipher_info from ciphers.py sets forward_secrecy=True for all TLS 1.3
            # suites because "TLS13_EPHEMERAL" implies ephemeral keys. That is correct
            # for ECDHE and PSK_DHE, but WRONG for PSK_ONLY.
            #
            # RFC 8446 §C.4: "without a fresh (EC)DHE exchange, the forward secrecy
            # properties of the prior connection are lost." PSK-only key derivation uses
            # only the PSK as input. If the PSK is later compromised, every session
            # established with PSK_ONLY can be decrypted from the ciphertext.
            #
            # We override the cipher_info value for PSK_ONLY to accurately reflect this.
            forward_secrecy = cipher_info["forward_secrecy"]
            if tls13_key_exchange_mode == "PSK_ONLY":
                forward_secrecy = False

            sessions[sid] = {
                "stream":           sid,
                "raw_version":      true_ver_hex,
                "tls_version":      TLS_VERSION_MAP.get(true_ver_hex, f"Unknown ({true_ver_hex})"),
                "raw_cipher_suite": ciphersuite,
                "cipher_name":      cipher_info["name"],
                # key_exchange: cipher-suite label. For TLS 1.3 this is always
                # 'TLS13_EPHEMERAL'; see tls13_key_exchange_mode for the actual mode.
                "key_exchange":     cipher_info["kex"],
                # Corrected: False for PSK_ONLY (RFC 8446 §C.4).
                "forward_secrecy":  forward_secrecy,
                "cipher_strength":  cipher_info["strength"],
                # ── TLS 1.3-specific fields (None for TLS 1.2) ───────────────────────
                "tls13_key_exchange_group": tls13_key_exchange_group,
                "tls13_psk_selected":       tls13_psk_selected,
                "tls13_key_exchange_mode":  tls13_key_exchange_mode,
            }

        return sessions

    def extract_certificate(self):
        """
        X.509 CERTIFICATE EXTRACTION, FEATURE TELEMETRY & TRUST VALIDATION:
        -----------------------------------------------------------------------
        PURPOSE:
          For each TCP stream that contains a TLS Certificate handshake message
          (HandshakeType 11), decode the transmitted certificate chain, extract
          comprehensive RFC 5280 telemetry fields, and evaluate path trust and
          hostname identity.

        OVERALL DESIGN — TWO INDEPENDENT EVALUATIONS:
          Certificate analysis is deliberately split into two orthogonal concerns:
            A) PATH VALIDATION (cryptographic): Is this chain rooted in a trusted CA?
               → Handled by ServerVerifier (SNI available) or _verify_pkix_path (no SNI).
            B) HOSTNAME MATCHING (identity): Does the cert identify the right server?
               → Handled by check_hostname_match() using the SNI as reference identity.
          These two questions have separate, named output fields ('trust_status' and
          'hostname_match') because a cert CAN be cryptographically valid but for the
          wrong hostname (common with misconfigured servers), or conversely the hostname
          can match but the chain can be broken.

        FIELD COVERAGE (Problem Statement Phase 1 deliverables):
          • X.509 chain extraction (all certs transmitted in TLS Certificate message)
          • RFC 4514 Distinguished Names (issuer_dn, subject_dn, issuer_cn, subject_cn)
          • RFC 6125 Subject Alternative Names — DNS names + IP addresses (typed)
          • Signature algorithm OID + parameters (distinguishes RSA-PSS from PKCS#1 v1.5)
          • Public key algorithm and key size (RSA, EC, Ed25519, Ed448)
          • basicConstraints: ca + pathLenConstraint (RFC 5280 §4.2.1.9)
          • keyUsage bits (RFC 5280 §4.2.1.3)
          • extendedKeyUsage OIDs (RFC 5280 §4.2.1.12)
          • Subject Key Identifier + Authority Key Identifier (RFC 5280 §4.2.1.1-2)
          • Critical extensions list (RFC 5280 §4.2)
          • Validity period + is_expired + not_yet_valid (UTC-aware, RFC 5280 §4.1.2.5)
          • Trust path validation with correct 3-case dispatch
          • Hostname match via RFC 6125 SNI reference identity
          • Honest revocation declaration (passive offline — no OCSP/CRL)

        TLS 1.3 LIMITATION:
          TLS 1.3 (RFC 8446 §5.2) encrypts the Certificate message under the
          handshake traffic key inside application_data records. tshark cannot
          decode encrypted records without the session key log (SSLKEYLOGFILE).
          For TLS 1.3 captures without a keylog, this method returns {} because
          no plaintext Certificate frames exist. This is a protocol constraint,
          not a parser bug.
        """
        # tshark filter: HandshakeType 11 = Certificate message (RFC 5246 §7.4.2 / RFC 8446 §4.4.2).
        # The 'or tls.handshake.certificate' alternative catches some tshark versions that
        # dissect the field differently from the type filter alone.
        command = [
            "tshark",
            "-r", self.pcap_path,
            "-Y", "tls.handshake.type == 11 or tls.handshake.certificate",
            "-T", "fields",
            "-e", "tcp.stream",                     # Field 0: TCP conversation index (keying by stream)
            "-e", "tls.handshake.certificate"       # Field 1: Raw DER hex (comma-separated for a chain)
        ]

        result = subprocess.run(command, capture_output=True, text=True)
        if not result.stdout.strip():
            return {}

        # -----------------------------------------------------------------------
        # SNI EXTRACTION (RFC 6066 §3 — Server Name Indication):
        # -----------------------------------------------------------------------
        # WHY A SEPARATE TSHARK PASS FOR SNI:
        #   tshark's Certificate filter (type==11) only captures ServerHello packets,
        #   not ClientHello. SNI is a ClientHello extension (type==0 in ExtensionType),
        #   so we must separately query HandshakeType 1 (ClientHello) frames.
        #   We correlate by tcp.stream so each stream's SNI lines up with its cert.
        #
        # WHY SNI IS THE REFERENCE IDENTITY AND NOTHING ELSE:
        #   RFC 6125 §6.1: The reference identifier MUST be derived from the client's
        #   independently established connection intent — not from the certificate itself.
        #   If we used the cert's own CN/SAN as the reference identity, the check would
        #   be circular (a certificate always matches its own name, proving nothing).
        #   We extract SNI here and pass it as `claimed_sni` throughout; the cert's own
        #   attributes are NEVER used to manufacture the expected identity.
        sni_command = [
            "tshark",
            "-r", self.pcap_path,
            "-Y", "tls.handshake.type == 1",               # ClientHello frames only
            "-T", "fields",
            "-e", "tcp.stream",
            "-e", "tls.handshake.extensions_server_name"   # The SNI hostname string
        ]
        sni_result = subprocess.run(sni_command, capture_output=True, text=True)
        sni_by_stream = {}
        if sni_result.stdout.strip():
            for line in sni_result.stdout.strip().split('\n'):
                parts = line.split('\t')
                # Guard: only store if both stream ID and SNI are present and non-empty.
                if len(parts) >= 2 and parts[0].isdigit() and parts[1].strip():
                    sni_by_stream[int(parts[0])] = parts[1].strip()

        lines = result.stdout.strip().split('\n')
        sessions_certs = {}
        # UTC 'now' is computed once and reused for all validity comparisons in this call.
        # Using timezone.utc is mandatory — cryptography's not_valid_before/after_utc
        # attributes are always UTC-aware datetimes; a naive datetime comparison would
        # raise a TypeError in Python 3.
        now = datetime.now(timezone.utc)

        for line in lines:
            parts = line.split('\t')
            if len(parts) < 2:
                continue

            stream_id, raw_certs = parts[0], parts[1]
            if not stream_id.isdigit():
                continue

            sid = int(stream_id)
            claimed_sni = sni_by_stream.get(sid, None)

            # -----------------------------------------------------------------------
            # DER CHAIN PARSING:
            # -----------------------------------------------------------------------
            # tshark emits multiple certs in a single Certificate message comma-separated.
            # RFC 8446 §4.4.2 (TLS 1.3) and RFC 5246 §7.4.2 (TLS 1.2) define the
            # Certificate message as a list of ASN.1 DER-encoded objects.
            # tshark formats the hex with possible colons (30:82:...) which we strip.
            cert_hex_list = raw_certs.strip().split(',')
            parsed_chain = []       # Human-readable field dicts for each cert
            raw_cert_objs = []      # x509.Certificate objects for cryptographic operations
            parse_errors = []       # Capture individual cert parse failures for transparency

            for idx, cert_hex in enumerate(cert_hex_list):
                try:
                    # Strip colon delimiters (e.g. 30:82:04:b3:...) and whitespace.
                    # tshark may emit either colon-separated or plain hex depending on version.
                    clean_hex = cert_hex.strip().replace(":", "").replace(" ", "")
                    if not clean_hex:
                        continue
                    der_bytes = bytes.fromhex(clean_hex)
                    cert = x509.load_der_x509_certificate(der_bytes, default_backend())
                    raw_cert_objs.append(cert)

                    # ── 1. DISTINGUISHED NAMES (RFC 5280 §4.1.2.4, RFC 4514) ──────────────
                    # rfc4514_string() is the canonical RFC-compliant DN string representation.
                    # We also extract CN separately for hostname fallback (when SAN is absent).
                    issuer_dn = cert.issuer.rfc4514_string()
                    subject_dn = cert.subject.rfc4514_string()

                    issuer_attrs = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                    subject_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                    issuer_cn = issuer_attrs[0].value if issuer_attrs else "Unknown"
                    subject_cn = subject_attrs[0].value if subject_attrs else "Unknown"

                    # ── 2. SUBJECT ALTERNATIVE NAME (RFC 5280 §4.2.1.6, RFC 6125) ─────────
                    # We extract both dNSName and iPAddress SAN types.
                    # Per RFC 6125 §6.4.4, if ANY dNSName SAN exists, it takes precedence
                    # over CN for hostname matching — this extraction feeds check_hostname_match().
                    san_dns = []
                    san_ip = []
                    try:
                        san_ext = cert.extensions.get_extension_for_oid(
                            x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                        ).value
                        san_dns = san_ext.get_values_for_type(x509.DNSName)
                        # str() converts IPv4Address/IPv6Address to human-readable notation.
                        san_ip = [str(ip) for ip in san_ext.get_values_for_type(x509.IPAddress)]
                    except x509.ExtensionNotFound:
                        san_dns = []
                        san_ip = []

                    # ── 3. SIGNATURE ALGORITHM (RFC 5280 §4.1.1.2 AlgorithmIdentifier) ────
                    # WHY OID DIRECTLY INSTEAD OF A LOOKUP TABLE:
                    #   Manual dictionaries (e.g. {OID: "sha256WithRSAEncryption"}) are
                    #   incomplete and require maintenance. Using the library's own OID
                    #   .dotted_string and ._name gives us the authoritative identification
                    #   without any manual mapping. python-cryptography exposes ._name as
                    #   the human-readable name registered in its OID database.
                    sig_oid = cert.signature_algorithm_oid.dotted_string
                    sig_algo_name = (
                        getattr(cert.signature_algorithm_oid, "_name", None)
                        or getattr(cert.signature_algorithm_oid, "name", sig_oid)
                    )
                    # signature_hash_algorithm returns None for Ed25519/Ed448 (see verify_certificate_signature).
                    sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None

                    # Expose the padding/scheme type (PSS vs PKCS1v15) as a human-readable string.
                    # This distinguishes RSA-PSS (RFC 4055) from RSASSA-PKCS1-v1.5 (RFC 3279)
                    # at a glance in the output without exposing internal cryptography objects.
                    sig_params_desc = None
                    try:
                        if cert.signature_algorithm_parameters is not None:
                            sig_params_desc = cert.signature_algorithm_parameters.__class__.__name__
                    except Exception:
                        sig_params_desc = None

                    # ── 4. PUBLIC KEY ALGORITHM & SIZE ──────────────────────────────────────
                    # WHY CLASS NAME DISPATCH INSTEAD OF OID:
                    #   python-cryptography returns different typed key objects. We need a
                    #   stable string ('RSA', 'EC', ...) for downstream feature extraction
                    #   and ML features (Phase 2). Class name matching is more robust than
                    #   OID lookup because the library may use different internal class names
                    #   across versions, but all RSA types contain "RSA" in their name.
                    pub_key = cert.public_key()
                    class_name = pub_key.__class__.__name__
                    if "RSA" in class_name:
                        pk_algo = "RSA"
                    elif "EllipticCurve" in class_name or "EC" in class_name:
                        pk_algo = "EC"
                    elif "Ed25519" in class_name:
                        pk_algo = "Ed25519"
                    elif "Ed448" in class_name:
                        pk_algo = "Ed448"
                    else:
                        pk_algo = "Unknown"

                    # WHY SPECIAL-CASE Ed25519/Ed448 KEY SIZES:
                    #   Ed25519 and Ed448 public keys have FIXED bit sizes (256 and 448 bits
                    #   respectively per RFC 8032). They do not expose a .key_size attribute
                    #   because their size is not a parameter — it is intrinsic to the curve.
                    #   hasattr() guard prevents AttributeError for these types.
                    if hasattr(pub_key, "key_size"):
                        key_size = pub_key.key_size
                    elif pk_algo == "Ed25519":
                        key_size = 256      # RFC 8032 §5.1: Ed25519 uses a 256-bit key
                    elif pk_algo == "Ed448":
                        key_size = 448      # RFC 8032 §5.2: Ed448 uses a 448-bit key
                    else:
                        key_size = "Unknown"

                    # ── 5. BASIC CONSTRAINTS (RFC 5280 §4.2.1.9) ──────────────────────────
                    # ca=True: this cert is authorised to sign other certs (is a CA).
                    # path_length: maximum number of intermediate CAs below this cert.
                    #   None means unlimited depth (only valid when ca=True).
                    # This extension is critical for path validation — any cert with
                    # ca=False MUST NOT be used to sign other certs.
                    basic_constraints = None
                    try:
                        bc_ext = cert.extensions.get_extension_for_oid(
                            x509.ExtensionOID.BASIC_CONSTRAINTS
                        ).value
                        basic_constraints = {
                            "ca": bc_ext.ca,
                            "path_length": bc_ext.path_length
                        }
                    except x509.ExtensionNotFound:
                        basic_constraints = None

                    # ── 6. KEY USAGE (RFC 5280 §4.2.1.3) ─────────────────────────────────
                    # RFC 5280 §4.2.1.3 defines exactly 9 key usage bits:
                    #   digital_signature:  cert may verify digital signatures (TLS handshake auth, etc.)
                    #   content_commitment: non-repudiation / commitment of signed data
                    #   key_encipherment:   cert public key used to encipher keys (RSA key exchange)
                    #   data_encipherment:  cert public key used to encipher raw user data directly
                    #   key_agreement:      cert public key used for key agreement (DH / ECDH)
                    #   key_cert_sign:      cert public key used to verify signatures on other certs (CA)
                    #   crl_sign:           cert public key used to verify signatures on CRLs
                    #   encipher_only:      with key_agreement, enciphers data while performing agreement
                    #   decipher_only:      with key_agreement, deciphers data while performing agreement
                    #
                    # WHY DEFENSIVE ACCESS FOR encipher_only / decipher_only:
                    #   In python-cryptography, accessing ku_ext.encipher_only or ku_ext.decipher_only
                    #   raises ValueError if key_agreement is False ("undefined unless key_agreement is true").
                    #   Similarly, getattr(ku_ext, "key_agreement", False) handles older cryptography versions.
                    key_usage = None
                    try:
                        ku_ext = cert.extensions.get_extension_for_oid(
                            x509.ExtensionOID.KEY_USAGE
                        ).value

                        encipher_only = False
                        decipher_only = False
                        if getattr(ku_ext, "key_agreement", False):
                            try:
                                encipher_only = bool(ku_ext.encipher_only)
                            except (ValueError, AttributeError):
                                encipher_only = False
                            try:
                                decipher_only = bool(ku_ext.decipher_only)
                            except (ValueError, AttributeError):
                                decipher_only = False

                        key_usage = {
                            "digital_signature":  bool(ku_ext.digital_signature),
                            "content_commitment": bool(getattr(ku_ext, "content_commitment", False)),
                            "key_encipherment":   bool(ku_ext.key_encipherment),
                            "data_encipherment":  bool(getattr(ku_ext, "data_encipherment", False)),
                            "key_agreement":      bool(getattr(ku_ext, "key_agreement", False)),
                            "key_cert_sign":      bool(ku_ext.key_cert_sign),
                            "crl_sign":           bool(ku_ext.crl_sign),
                            "encipher_only":      encipher_only,
                            "decipher_only":      decipher_only,
                        }
                    except x509.ExtensionNotFound:
                        key_usage = None

                    # ── 7. EXTENDED KEY USAGE (RFC 5280 §4.2.1.12) ────────────────────────
                    # EKU OIDs declare the specific application contexts the cert is authorised for.
                    # For mail server TLS: 'serverAuth' (OID 1.3.6.1.5.5.7.3.1) is required.
                    # WHY WE PREVIOUSLY HAD A BUG WITH ClientVerifier:
                    #   cryptography's ClientVerifier enforces the 'clientAuth' EKU
                    #   (OID 1.3.6.1.5.5.7.3.2). Mail servers present 'serverAuth' certs.
                    #   Using ClientVerifier would always fail with 'required EKU not found'.
                    #   ServerVerifier (used in the trust evaluation block below) is correct
                    #   because it validates 'serverAuth', which is what mail servers present.
                    # WHY UNKNOWN OIDs FALL THROUGH TO dotted_string:
                    #   An unknown EKU OID is not an error — it just means a non-standard
                    #   application context. We report the dotted OID so it is visible in
                    #   forensic output rather than silently dropped.
                    extended_key_usage = []
                    try:
                        eku_ext = cert.extensions.get_extension_for_oid(
                            x509.ExtensionOID.EXTENDED_KEY_USAGE
                        ).value
                        for oid in eku_ext:
                            if oid == x509.ExtendedKeyUsageOID.SERVER_AUTH:
                                extended_key_usage.append("serverAuth")
                            elif oid == x509.ExtendedKeyUsageOID.CLIENT_AUTH:
                                extended_key_usage.append("clientAuth")
                            elif oid == x509.ExtendedKeyUsageOID.CODE_SIGNING:
                                extended_key_usage.append("codeSigning")
                            elif oid == x509.ExtendedKeyUsageOID.EMAIL_PROTECTION:
                                extended_key_usage.append("emailProtection")
                            else:
                                extended_key_usage.append(oid.dotted_string)
                    except x509.ExtensionNotFound:
                        extended_key_usage = []

                    # ── 8. KEY IDENTIFIERS (RFC 5280 §4.2.1.1 AKI, §4.2.1.2 SKI) ─────────
                    # SKI (Subject Key Identifier): SHA-1 hash of the subject's public key BitString.
                    #   Allows other certs' AKI to point to this cert's key without name matching.
                    # AKI (Authority Key Identifier): Points to the issuer's key (usually = issuer's SKI).
                    #   Enables unambiguous identification of the signing CA when multiple CA certs
                    #   share the same DN but have different keys (e.g. after CA key rollover).
                    ski = None
                    try:
                        ski_ext = cert.extensions.get_extension_for_oid(
                            x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER
                        ).value
                        ski = ski_ext.digest.hex()
                    except x509.ExtensionNotFound:
                        ski = None

                    aki = None
                    try:
                        aki_ext = cert.extensions.get_extension_for_oid(
                            x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER
                        ).value
                        # key_identifier may be None if only authorityCertIssuer/SerialNumber forms are used.
                        aki = aki_ext.key_identifier.hex() if aki_ext.key_identifier else None
                    except x509.ExtensionNotFound:
                        aki = None

                    # ── 9. CRITICAL EXTENSIONS TRACKING (RFC 5280 §4.2) ──────────────────
                    # A critical extension that a verifier does not recognise means the cert
                    # MUST be rejected (RFC 5280 §4.2 ¶4). We surface all critical OIDs so
                    # a downstream analyser can flag unknown critical extensions as anomalies.
                    critical_extensions = [
                        ext.oid.dotted_string for ext in cert.extensions if ext.critical
                    ]

                    # ── 10. VALIDITY PERIOD (RFC 5280 §4.1.2.5) ──────────────────────────
                    # WHY not_valid_before/after_utc (not not_valid_before/after):
                    #   python-cryptography deprecated the naive-datetime variants in 42.x.
                    #   The _utc variants return timezone-aware datetimes (UTC), which are
                    #   safe to compare against datetime.now(timezone.utc) without TypeError.
                    not_before = cert.not_valid_before_utc
                    not_after  = cert.not_valid_after_utc

                    parsed_chain.append({
                        "serial_number":                str(cert.serial_number),
                        "issuer_dn":                    issuer_dn,
                        "subject_dn":                   subject_dn,
                        "issuer_cn":                    issuer_cn,
                        "subject_cn":                   subject_cn,
                        "san_dns":                      san_dns,
                        "san_ip":                       san_ip,
                        "signature_algorithm_oid":      sig_oid,
                        "signature_algorithm_name":     sig_algo_name,
                        "signature_algorithm_parameters": sig_params_desc,
                        "signature_hash_algorithm":     sig_hash,
                        "public_key_algorithm":         pk_algo,
                        "public_key_size":              key_size,
                        "basic_constraints":            basic_constraints,
                        "key_usage":                    key_usage,
                        "extended_key_usage":           extended_key_usage,
                        "subject_key_identifier":       ski,
                        "authority_key_identifier":     aki,
                        "critical_extensions":          critical_extensions,
                        "not_before":                   str(not_before),
                        "not_after":                    str(not_after),
                        "is_expired":                   now > not_after,
                        "not_yet_valid":                now < not_before
                    })

                except Exception as e:
                    # Record the failure with enough context for forensic triage,
                    # then continue to process any remaining certs in the chain.
                    parse_errors.append(f"Cert #{idx} parse error: {type(e).__name__}: {e}")
                    continue

            # If no certs parsed at all, record the errors and skip to next stream.
            if not parsed_chain:
                if parse_errors:
                    sessions_certs[sid] = {
                        "stream": sid,
                        "trust_status": "CERT_PARSE_ERROR",
                        "parse_errors": parse_errors
                    }
                continue

            # WHY raw_cert_objs[0] IS THE LEAF:
            #   RFC 8446 §4.4.2 (TLS 1.3): "The sender's certificate MUST come in the
            #   first CertificateEntry in the list." RFC 5246 §7.4.2 (TLS 1.2) has the
            #   same ordering requirement: the sender's cert is first.
            #   raw_cert_objs[1:] are intermediates (in arbitrary order per RFC 8446;
            #   path building must not assume they are sorted).
            leaf_obj  = raw_cert_objs[0]
            leaf_dict = parsed_chain[0]

            # ── HOSTNAME MATCHING (evaluated independently of path validation) ──────────
            # This is a separate, independent check from cryptographic path validation.
            # A cert can be path-valid but for the wrong host (TRUSTED_CHAIN_HOSTNAME_MISMATCH).
            hostname_match_status = check_hostname_match(
                claimed_sni, leaf_dict["san_dns"], leaf_dict["subject_cn"]
            )

            # ═══════════════════════════════════════════════════════════════════════════
            # RFC 5280 PATH VALIDATION & TRUST EVALUATION — THREE CASES
            # ═══════════════════════════════════════════════════════════════════════════
            active_store = self._get_trust_store()
            trust_status      = "UNKNOWN"
            trust_details     = ""
            is_self_signed    = False
            is_anchored       = False
            verification_error = None

            # REFERENCE IDENTITY RESOLUTION (RFC 6125 §6.1):
            # The reference identity — the name the client expected the server to have —
            # MUST come from the client's independently observed connection context.
            # In a TLS connection, that is the SNI extension in ClientHello (RFC 6066 §3).
            #
            # CRITICAL: We never call _get_x509_subject(leaf_dict['subject_cn']) or any
            # cert-derived attribute here. That would be circular — the cert would always
            # pass a hostname check against itself, proving nothing about server identity.
            reference_identity = self._get_x509_subject(claimed_sni) if claimed_sni else None

            # PolicyBuilder is the entry point to cryptography's PKIX verification engine.
            # .store() anchors it to our active trust bundle.
            # .time(now) sets the validation time for validity period checks (RFC 5280 §6.1.3).
            builder = PolicyBuilder().store(active_store).time(now)

            # ───────────────────────────────────────────────────────────────────────────
            # CASE 1: SELF-SIGNED CERTIFICATE (issuer DN == subject DN, single cert)
            # ───────────────────────────────────────────────────────────────────────────
            # WHY SPECIAL-CASE SELF-SIGNED:
            #   A self-signed cert has no issuing CA to verify against — it IS the root.
            #   ServerVerifier cannot be used because it would try to build a chain to
            #   a root, but this cert IS the root (or purports to be). The correct check
            #   is: (a) verify the cert's signature against its own public key to confirm
            #   it wasn't tampered with, then (b) check if it is explicitly installed in
            #   our trust store.
            #
            # WHY OBJECT EQUALITY (leaf_obj == root) FOR STORE MEMBERSHIP:
            #   python-cryptography's Store is opaque — we cannot iterate it. We kept
            #   _store_certs as a parallel list precisely for this check. Object equality
            #   on x509.Certificate objects compares the full DER encoding, so this is a
            #   true cryptographic identity check, not just a name comparison.
            if len(raw_cert_objs) == 1 and leaf_obj.issuer == leaf_obj.subject:
                valid_self_sig, err = verify_certificate_signature(leaf_obj, leaf_obj)
                if valid_self_sig:
                    is_self_signed = True
                    # Object equality check: is this exact cert in our trust store?
                    is_anchored = any(leaf_obj == root for root in self._store_certs)
                    if is_anchored:
                        trust_status = "TRUSTED_SELF_SIGNED"
                        trust_details = (
                            f"Cryptographically verified self-signed certificate. "
                            f"Explicitly installed and trusted as root anchor in active '{self.trust_store_type}' store."
                        )
                    else:
                        trust_status = "UNTRUSTED_SELF_SIGNED"
                        trust_details = (
                            f"Cryptographically verified self-signed certificate. "
                            f"Untrusted: not present in active '{self.trust_store_type}' store."
                        )
                else:
                    # issuer == subject (claims to be self-signed) but the signature
                    # does not verify — the cert has been tampered with or is malformed.
                    trust_status = "SELF_SIGNED_SIGNATURE_INVALID"
                    trust_details = (
                        f"Issuer matches Subject as self-signed, but cryptographic "
                        f"signature verification failed: {err}"
                    )
                    is_anchored = False
                    verification_error = err

            # ───────────────────────────────────────────────────────────────────────────
            # CASE 2: SINGLE LEAF CERTIFICATE (issuer != subject, only one cert sent)
            # ───────────────────────────────────────────────────────────────────────────
            # The server sent only a leaf certificate. This is common with:
            #   - Certs directly signed by a root in our store (no intermediates needed)
            #   - Misconfigured servers that omit required intermediates
            # We check expiry first because an expired cert is definitively invalid
            # before any path validation attempt is worthwhile.
            elif len(raw_cert_objs) == 1:
                if now > leaf_obj.not_valid_after_utc:
                    # Expiry check: RFC 5280 §6.1.3(a)(1) requires validity period check
                    # before any other path validation step.
                    trust_status = "EXPIRED"
                    trust_details = f"Certificate is expired (expired on {leaf_obj.not_valid_after_utc})."
                    is_anchored = False
                elif now < leaf_obj.not_valid_before_utc:
                    trust_status = "NOT_YET_VALID"
                    trust_details = f"Certificate is not yet valid (valid from {leaf_obj.not_valid_before_utc})."
                    is_anchored = False
                else:
                    if reference_identity is not None:
                        # ── Case 2A: SNI available — use ServerVerifier (path + hostname) ──
                        # ServerVerifier.verify(leaf, intermediates=[]) performs:
                        #   1. Build a path from leaf to a root in the active Store
                        #   2. Verify every hop's signature (leaf signed by CA)
                        #   3. Validate basicConstraints, pathLen, validity at every hop
                        #   4. Check the server's hostname against the reference identity
                        # Passing [] as intermediates is correct for a single leaf cert.
                        try:
                            verifier = builder.build_server_verifier(reference_identity)
                            verifier.verify(leaf_obj, [])
                            trust_status = "TRUSTED_CHAIN"
                            trust_details = (
                                f"Single leaf certificate verified for SNI '{claimed_sni}' "
                                f"and directly anchored to root CA in {self.trust_store_type} store."
                            )
                            is_anchored = True
                        except Exception as e_sni:
                            # ServerVerifier failed — could be hostname mismatch OR path failure.
                            # We use _verify_pkix_path() as a tiebreaker to distinguish the two.
                            pkix_ok, pkix_err = self._verify_pkix_path(leaf_obj, [])
                            if pkix_ok:
                                # Path is cryptographically valid; only the hostname check failed.
                                # The server's cert is trusted but does not identify the right host.
                                trust_status = "TRUSTED_CHAIN_HOSTNAME_MISMATCH"
                                trust_details = (
                                    f"Single leaf certificate directly anchored to root CA in "
                                    f"{self.trust_store_type} store, but does NOT match claimed SNI '{claimed_sni}'."
                                )
                                is_anchored = True
                            else:
                                # Path itself is invalid — missing intermediate (server sent only
                                # the leaf, not the full chain). This is NOT a cryptographic failure
                                # of the cert itself; the chain is simply incomplete.
                                # PREVIOUSLY WRONG: this was labelled INVALID_PATH_CRYPTOGRAPHIC.
                                # CORRECTED: the cert may be perfectly valid; it's the chain that's
                                # missing intermediate links. openssl verify error 20 = 'unable to
                                # get local issuer certificate', which means missing intermediate.
                                trust_status = "INCOMPLETE_CHAIN_MISSING_INTERMEDIATE"
                                trust_details = (
                                    f"Incomplete chain: server presented a single leaf certificate "
                                    f"issued by '{leaf_dict['issuer_dn']}', but intermediate CA "
                                    f"certificates were not transmitted in the TLS handshake."
                                )
                                is_anchored = False
                                verification_error = pkix_err or str(e_sni)
                    else:
                        # ── Case 2B: No SNI — raw PKIX path validation only ──────────────
                        # RFC 6125 §6.1: Without a reference identity from the connection
                        # context, hostname validation MUST be skipped. We must not build
                        # a reference identity from the cert's own SAN/CN.
                        # Use _verify_pkix_path() which shells to 'openssl verify' — the
                        # only available path-only validator (cryptography's ServerVerifier
                        # always requires a subject for hostname binding).
                        hostname_match_status = "SKIPPED_NO_SNI"
                        pkix_ok, pkix_err = self._verify_pkix_path(leaf_obj, [])
                        if pkix_ok:
                            trust_status = "TRUSTED_CHAIN"
                            trust_details = (
                                f"Single leaf certificate verified and directly anchored to root CA "
                                f"in {self.trust_store_type} store. Hostname verification skipped: "
                                f"no SNI or client reference identity observed in PCAP (RFC 6125)."
                            )
                            is_anchored = True
                        else:
                            trust_status = "INCOMPLETE_CHAIN_MISSING_INTERMEDIATE"
                            trust_details = (
                                f"Incomplete chain: server presented a single leaf certificate "
                                f"issued by '{leaf_dict['issuer_dn']}', but intermediate CA "
                                f"certificates were not transmitted in the TLS handshake."
                            )
                            is_anchored = False
                            verification_error = pkix_err

            # ───────────────────────────────────────────────────────────────────────────
            # CASE 3: MULTI-CERTIFICATE CHAIN (leaf + one or more intermediates)
            # ───────────────────────────────────────────────────────────────────────────
            # raw_cert_objs[0]  = leaf (end-entity) certificate — mandated first by RFC 8446 §4.4.2
            # raw_cert_objs[1:] = candidate intermediates in ARBITRARY order.
            #
            # WHY ARBITRARY ORDER:
            #   RFC 8446 §4.4.2 says each cert "should directly certify the one preceding it"
            #   but ALSO says "implementations MUST tolerate... any ordering". The cert order
            #   in the TLS Certificate message is advisory. We pass them as unordered candidates
            #   to the path engine (ServerVerifier / openssl verify), which constructs the
            #   correct path from leaf to root regardless of ordering.
            elif len(raw_cert_objs) > 1:
                # Scan the ENTIRE chain for validity issues before attempting path validation.
                # A single expired cert anywhere in the chain invalidates the whole chain
                # (RFC 5280 §6.1.3(a)(1) applies to each cert in the path).
                expired_cert = next(
                    (c for c in raw_cert_objs if now > c.not_valid_after_utc), None
                )
                not_yet_valid_cert = next(
                    (c for c in raw_cert_objs if now < c.not_valid_before_utc), None
                )

                if expired_cert:
                    trust_status = "EXPIRED"
                    trust_details = (
                        f"Certificate in chain ({expired_cert.subject.rfc4514_string()}) "
                        f"is expired (expired on {expired_cert.not_valid_after_utc})."
                    )
                    is_anchored = False
                elif not_yet_valid_cert:
                    trust_status = "NOT_YET_VALID"
                    trust_details = (
                        f"Certificate in chain ({not_yet_valid_cert.subject.rfc4514_string()}) "
                        f"is not yet valid (valid from {not_yet_valid_cert.not_valid_before_utc})."
                    )
                    is_anchored = False
                else:
                    # All certs are within their validity windows. Attempt path validation.
                    candidate_intermediates = raw_cert_objs[1:]

                    # ── Case 3A: SNI available ─────────────────────────────────────────
                    if reference_identity is not None:
                        # ServerVerifier.verify(leaf, candidate_intermediates):
                        #   - Constructs the path from leaf through intermediates to a root
                        #     in the active Store (arbitrary intermediate order is handled).
                        #   - Verifies signatures at every hop.
                        #   - Validates basicConstraints and pathLenConstraint.
                        #   - Checks the leaf's SAN/CN against the reference identity (SNI).
                        try:
                            verifier = builder.build_server_verifier(reference_identity)
                            verifier.verify(leaf_obj, candidate_intermediates)
                            trust_status = "TRUSTED_CHAIN"
                            trust_details = (
                                f"Certificate chain cryptographically authentic, verified for "
                                f"SNI '{claimed_sni}', and anchored to {self.trust_store_type} trust store."
                            )
                            is_anchored = True
                        except Exception as e_sni:
                            # ServerVerifier failed. Distinguish hostname mismatch from path failure.
                            pkix_ok, pkix_err = self._verify_pkix_path(leaf_obj, candidate_intermediates)
                            if pkix_ok:
                                # Chain is cryptographically valid, path anchors correctly —
                                # only the hostname check failed.
                                trust_status = "TRUSTED_CHAIN_HOSTNAME_MISMATCH"
                                trust_details = (
                                    f"Certificate chain cryptographically authentic and anchored to "
                                    f"{self.trust_store_type} store, but does NOT match claimed SNI '{claimed_sni}'."
                                )
                                is_anchored = True
                            else:
                                # Both ServerVerifier and raw PKIX failed — genuine path failure.
                                # Could be wrong trust store, tampered cert, or chain that doesn't
                                # include all necessary intermediates.
                                trust_status = "PATH_VALIDATION_FAILED"
                                trust_details = (
                                    f"Path validation failed against {self.trust_store_type} store: "
                                    f"{pkix_err or e_sni}"
                                )
                                is_anchored = False
                                verification_error = pkix_err or str(e_sni)

                    # ── Case 3B: No SNI — raw PKIX only ───────────────────────────────
                    else:
                        # Same rationale as Case 2B: without a reference identity from the
                        # client's connection context, we cannot check hostname. We fall back
                        # to pure path validation using openssl verify.
                        hostname_match_status = "SKIPPED_NO_SNI"
                        pkix_ok, pkix_err = self._verify_pkix_path(leaf_obj, candidate_intermediates)
                        if pkix_ok:
                            trust_status = "TRUSTED_CHAIN"
                            trust_details = (
                                f"Certificate chain cryptographically authentic and anchored to "
                                f"{self.trust_store_type} store. Hostname verification skipped: "
                                f"no SNI or client reference identity observed in PCAP (RFC 6125)."
                            )
                            is_anchored = True
                        else:
                            trust_status = "PATH_VALIDATION_FAILED"
                            trust_details = (
                                f"Path validation failed against {self.trust_store_type} store: {pkix_err}"
                            )
                            is_anchored = False
                            verification_error = pkix_err

            # ── OUTPUT RECORD ──────────────────────────────────────────────────────────
            # WHY revocation_status IS ALWAYS NOT_CHECKED:
            #   OCSP and CRL revocation checks require live network requests or CRL file
            #   downloads. In a passive offline PCAP analysis we have no network access
            #   at validation time, and the PCAP itself may be historical. Claiming
            #   'VALID' for revocation without actually checking would be misleading.
            #   The honest answer is NOT_CHECKED, which tells downstream consumers they
            #   must run their own revocation check if they need that assurance.
            sessions_certs[sid] = {
                "stream":                        sid,
                "chain_length":                  len(parsed_chain),
                "is_self_signed":                is_self_signed,
                "trust_status":                  trust_status,
                "trust_details":                 trust_details,
                "path_verification_error":       verification_error,
                "active_trust_store":            self.trust_store_type,
                "active_trust_store_description": self.trust_store_description,
                "anchored_in_active_store":      is_anchored,
                "claimed_sni":                   claimed_sni,
                "hostname_match":                hostname_match_status,
                "revocation_status":             "NOT_CHECKED (PASSIVE_OFFLINE_ANALYSIS)",
                "leaf_cert":                     leaf_dict,
                "full_chain":                    parsed_chain,
                "parse_errors":                  parse_errors
            }

        return sessions_certs



    def detect_protocol(self):
        """
        Deep Packet Inspection (DPI) protocol classifier per TCP stream.
        Inspects application-layer banners and commands:
        - SMTP (RFC 5321): '220', 'EHLO', 'HELO', 'ESMTP'
        - IMAP (RFC 3501): '* OK', 'CAPABILITY', 'LOGIN', tag commands
        - POP3 (RFC 1939): '+OK', 'USER', 'PASS', 'STAT', 'CAPA'
        Falls back to standard well-known IANA email ports if payload is encrypted (Implicit TLS).
        
        Returns: Dict mapping stream_id (int) -> protocol name (str)
        """
        command = [
            "tshark",
            "-r", self.pcap_path,
            "-Y", "tcp.payload",           # Only inspect packets that actually carry data
            "-T", "fields",
            "-e", "tcp.stream",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "tcp.payload"
        ]

        result = subprocess.run(command, capture_output=True, text=True)
        if not result.stdout.strip():
            return {}

        lines = result.stdout.strip().split('\n')
        streams_payloads = {}
        streams_ports = {}

        for line in lines:
            parts = line.split('\t')
            if len(parts) < 4:
                continue

            stream_str, src_port, dst_port, payload_hex = parts[0], parts[1], parts[2], parts[3]
            if not stream_str.isdigit():
                continue

            sid = int(stream_str)
            if sid not in streams_payloads:
                streams_payloads[sid] = []
                streams_ports[sid] = set()

            if src_port.isdigit():
                streams_ports[sid].add(int(src_port))
            if dst_port.isdigit():
                streams_ports[sid].add(int(dst_port))

            if payload_hex.strip():
                try:
                    text = bytes.fromhex(payload_hex.strip()).decode('latin1', errors='ignore')
                    streams_payloads[sid].append(text)
                except Exception:
                    pass

        results = {}
        for sid, payloads in streams_payloads.items():
            detected = None
            for text in payloads:
                text_upper = text.upper()
                # SMTP DPI
                if text.startswith("220") or "ESMTP" in text_upper or "SMTP" in text_upper or text_upper.startswith("EHLO") or text_upper.startswith("HELO"):
                    detected = "SMTP"
                    break
                # IMAP DPI
                elif text_upper.startswith("* OK") or "IMAP" in text_upper:
                    detected = "IMAP"
                    break
                # POP3 DPI
                elif text_upper.startswith("+OK") or "POP" in text_upper:
                    detected = "POP3"
                    break

            if not detected:
                # Port-based fallback
                ports = streams_ports.get(sid, set())
                if ports.intersection({25, 465, 587, 2525}):
                    detected = "SMTP"
                elif ports.intersection({143, 993}):
                    detected = "IMAP"
                elif ports.intersection({110, 995}):
                    detected = "POP3"
                else:
                    detected = "Unknown"

            results[sid] = detected

        return results


    def detect_starttls(self):
        """
        Stream-level STARTTLS state machine tracking protocol transition per TCP stream:
        1. Advertisement: Server announces upgrade capability (250-STARTTLS per RFC 3207, STLS per RFC 2595)
        2. Client Command: Client issues upgrade verb ('STARTTLS', 'STLS')
        3. Server Response: Server grants upgrade ('220' per RFC 3207, '+OK' per RFC 2595)
        4. TLS Handshake: TLS session negotiated on the wire
        5. Cleartext Inspection: Detects plaintext credentials in unencrypted packets (AUTH, USER/PASS, LOGIN)
        
        Returns: Dict mapping stream_id (int) -> STARTTLS state dictionary
        """
        command = [
            "tshark",
            "-r", self.pcap_path,
            "-Y", "tcp.payload",
            "-T", "fields",
            "-e", "tcp.stream",
            "-e", "tcp.payload"
        ]

        result = subprocess.run(command, capture_output=True, text=True)
        tls_sessions = self.extract_tls_info()

        streams_lines = {}
        if result.stdout.strip():
            for line in result.stdout.strip().split('\n'):
                parts = line.split('\t')
                if len(parts) < 2:
                    continue
                stream_str, payload_hex = parts[0], parts[1]
                if not stream_str.isdigit():
                    continue
                sid = int(stream_str)
                if sid not in streams_lines:
                    streams_lines[sid] = []
                if payload_hex.strip():
                    try:
                        text = bytes.fromhex(payload_hex.strip()).decode('latin1', errors='ignore')
                        streams_lines[sid].append(text)
                    except Exception:
                        pass

        # Also ensure any TLS streams without observed cleartext TCP payloads (e.g. Implicit TLS) are tracked
        all_stream_ids = sorted(set(list(streams_lines.keys()) + list(tls_sessions.keys())))
        results = {}

        for sid in all_stream_ids:
            payloads = streams_lines.get(sid, [])
            starttls_offered = False
            starttls_requested = False
            starttls_accepted = False
            plaintext_auth_attempted = False

            for text in payloads:
                text_upper = text.upper()
                cleaned_line = text_upper.strip()

                # 1. Did server advertise STARTTLS / STLS capability?
                # RFC 3207 (SMTP): 250-STARTTLS or 250 STARTTLS
                # RFC 2595 (POP3): STLS in CAPA response (+OK)
                # RFC 3501 (IMAP): * CAPABILITY ... STARTTLS
                if ((text.startswith("250") and "STARTTLS" in text_upper) or
                    (text.startswith("+OK") and "STLS" in text_upper) or
                    ("CAPABILITY" in text_upper and "STARTTLS" in text_upper) or
                    (cleaned_line == "STLS" and not starttls_requested)):
                    starttls_offered = True
                elif "STARTTLS" in text_upper and (text.startswith("250") or text.startswith("*")):
                    starttls_offered = True

                # 2. Did client issue upgrade command?
                # Client command is strictly 'STARTTLS' (SMTP, RFC 3207) or 'STLS' (POP3, RFC 2595)
                # Evaluated before Step 3 so state transitions in proper chronological sequence.
                if cleaned_line in ("STARTTLS", "STLS"):
                    starttls_requested = True

                # 3. Did server accept previously requested STARTTLS?
                # RFC 3207 §4.2 (SMTP): 220 2.0.0 Ready to start TLS
                # RFC 2595 §4 (POP3/IMAP): +OK Begin TLS negotiation or OK Begin TLS negotiation
                if starttls_requested and not starttls_accepted:
                    if text.startswith("220") or text.startswith("+OK") or " OK " in text_upper:
                        starttls_accepted = True

                # 4. Check for plaintext authentication in cleartext packets:
                # - RFC 4954 (SMTP AUTH): AUTH PLAIN, AUTH LOGIN
                # - RFC 1939 (POP3): USER, PASS
                # - RFC 3501 (IMAP): LOGIN
                if (cleaned_line.startswith("AUTH ") or 
                    cleaned_line.startswith("USER ") or 
                    cleaned_line.startswith("PASS ") or 
                    " LOGIN " in text_upper):
                    plaintext_auth_attempted = True

            tls_active = sid in tls_sessions

            if starttls_requested and starttls_accepted and tls_active:
                status = "UPGRADED"
                details = "STARTTLS successfully negotiated and encrypted session established."
            elif starttls_offered and not tls_active:
                status = "DOWNGRADE_OR_STRIPPED"
                details = "Server advertised STARTTLS, but session remained in plaintext! Potential stripping attack or insecure client."
            elif tls_active and not starttls_requested:
                status = "IMPLICIT_TLS"
                details = "Session used direct implicit TLS without plaintext upgrade (e.g. SMTPS/IMAPS/POP3S)."
            else:
                status = "CLEARTEXT_NO_ENCRYPTION"
                details = "Session conducted completely in plaintext with no TLS."

            results[sid] = {
                "stream": sid,
                "starttls_offered": starttls_offered,
                "starttls_requested": starttls_requested,
                "starttls_accepted": starttls_accepted,
                "tls_active": tls_active,
                "plaintext_auth_attempted": plaintext_auth_attempted,
                "status": status,
                "details": details
            }

        return results


    def analyze(self):
        """
        Unified PCAP Forensic Analysis Pipeline.
        Correlates TLS handshake parameters, X.509 certificates, protocol classification,
        and STARTTLS state machines across all observed TCP streams into a single
        structured session dictionary.
        
        Returns: Dict mapping stream_id (int) -> unified session analysis object.
        """
        tls_info = self.extract_tls_info()
        cert_info = self.extract_certificate()
        protocol_info = self.detect_protocol()
        starttls_info = self.detect_starttls()

        all_stream_ids = sorted(set(
            list(tls_info.keys()) +
            list(cert_info.keys()) +
            list(protocol_info.keys()) +
            list(starttls_info.keys())
        ))

        sessions = {}
        for sid in all_stream_ids:
            sessions[sid] = {
                "stream_id": sid,
                "protocol": protocol_info.get(sid, "Unknown"),
                "starttls": starttls_info.get(sid, {
                    "stream": sid,
                    "starttls_offered": False,
                    "starttls_requested": False,
                    "starttls_accepted": False,
                    "tls_active": sid in tls_info,
                    "plaintext_auth_attempted": False,
                    "status": "IMPLICIT_TLS" if sid in tls_info else "CLEARTEXT_NO_ENCRYPTION",
                    "details": "Implicit TLS session" if sid in tls_info else "Cleartext session"
                }),
                "tls": tls_info.get(sid, None),
                "certificate": cert_info.get(sid, None)
            }

        return sessions


if __name__ == "__main__":
    # This block executes when running 'python3 parser.py' directly.
    # It is skipped when parser.py is imported as a library.
    import json
    import sys

    target_pcap = sys.argv[1] if len(sys.argv) > 1 else "../tls12_only.pcap"
    
    print("\n" + "=" * 80)
    print(f" SECUREMAILSCOPE FORENSIC TELEMETRY ENGINE")
    print(f" Target PCAP: {os.path.abspath(target_pcap)}")
    print("=" * 80)

    # 1. Primary Analysis: Testbed Trust Store (Default for lab/synthetic captures)
    analyzer = PCAPAnalyzer(target_pcap, trust_store="testbed")
    analyzer._get_trust_store()
    print(f"\n[ACTIVE TRUST STORE] {analyzer.trust_store_description}")

    print("\n" + "-" * 40 + " [1] UNIFIED SESSION RECONSTRUCTION " + "-" * 40)
    unified_sessions = analyzer.analyze()
    print(json.dumps(unified_sessions, indent=2))

    print("\n" + "-" * 40 + " [2] TLS SESSION PARAMETERS " + "-" * 40)
    tls_sessions = analyzer.extract_tls_info()
    print(json.dumps(tls_sessions, indent=2))

    print("\n" + "-" * 40 + " [3] X.509 CERTIFICATE TELEMETRY & TRUST VALIDATION " + "-" * 40)
    cert_sessions = analyzer.extract_certificate()
    print(json.dumps(cert_sessions, indent=2))

    print("\n" + "-" * 40 + " [4] PROTOCOL DETECTION " + "-" * 40)
    protocol = analyzer.detect_protocol()
    print(json.dumps(protocol, indent=2))

    print("\n" + "-" * 40 + " [5] STARTTLS STATE MACHINE " + "-" * 40)
    starttls_state = analyzer.detect_starttls()
    print(json.dumps(starttls_state, indent=2))

    # 2. Forensic Trust Store Comparison: Testbed vs Production (Mozilla CA Bundle)
    print("\n" + "=" * 80)
    print(" FORENSIC TRUST STORE COMPARISON (Testbed CA vs Mozilla Production CA)")
    print("=" * 80)
    analyzer_prod = PCAPAnalyzer(target_pcap, trust_store="production")
    analyzer_prod._get_trust_store()
    cert_prod = analyzer_prod.extract_certificate()

    for sid in cert_sessions:
        tb_stream = cert_sessions[sid]
        prod_stream = cert_prod.get(sid, {})
        if "leaf_cert" not in tb_stream:
            print(f"\n[Stream {sid}] Certificate Parse Diagnostics:")
            print(f"  Status: {tb_stream.get('trust_status')}")
            print(f"  Errors: {tb_stream.get('parse_errors')}")
            continue
        print(f"\n[Stream {sid}] Subject: {tb_stream['leaf_cert']['subject_cn']}")
        print(f"  • Under 'testbed' store    : {tb_stream['trust_status']} | Anchored: {tb_stream['anchored_in_active_store']}")
        print(f"    Details: {tb_stream['trust_details']}")
        print(f"  • Under 'production' store : {prod_stream.get('trust_status')} | Anchored: {prod_stream.get('anchored_in_active_store')}")
        print(f"    Details: {prod_stream.get('trust_details')}")

    print("\n" + "=" * 80 + "\n")
    


