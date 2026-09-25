import os
import sys
_pkg_dir = os.path.dirname(os.path.abspath(__file__))
if _pkg_dir not in sys.path:
    sys.path.insert(0, _pkg_dir)
import os
import subprocess
import warnings
import ipaddress
from datetime import datetime, timezone
from cryptography import x509
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec, ed25519, ed448
from cryptography.x509.verification import PolicyBuilder

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

try:
    from .trust_store import TrustStoreManager
except ImportError:
    from trust_store import TrustStoreManager


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


def check_hostname_match(claimed_sni, san_dns, leaf_cn, san_ip=None):
    """
    RFC 9525 / RFC 6125 SERVICE IDENTITY & HOSTNAME MATCHING (Section 4 / Section 6.4):
    -------------------------------------------------------------------------------
    PURPOSE:
      Determine whether the server's certificate identity matches what the client
      actually intended to reach (the reference identifier). This is independent
      of cryptographic path validation — a certificate can be cryptographically
      valid but still be issued for a different endpoint or host.

    REFERENCE IDENTIFIER CONTEXT & TLS SNI (RFC 9525 §3, RFC 6066 §3):
      RFC 9525 §3 and RFC 6066 §3 explicitly specify that standard TLS SNI
      (Server Name Indication) HostName syntax conveys only fully qualified domain
      names, not IP address literals. However, in passive network forensics,
      synthetic testbeds (such as PCAP-116), or non-compliant client traffic,
      the client reference identity ('claimed_sni') may be presented as an IP
      address. We treat 'claimed_sni' as the connection reference identifier.
      We MUST NOT derive the reference identity from the certificate's own
      attributes (SAN or CN), because that would make the check circular (RFC 9525 §4.1).

    IP-ID MATCHING RULES (RFC 9525 §4.4, RFC 5280 §4.2.1.6):
      - If the reference identifier is an IP address (IP-ID), the client MUST
        compare it ONLY against iPAddress entries in the Subject Alternative Name
        extension (RFC 5280 §4.2.1.6).
      - The comparison MUST be octet-for-octet (evaluated here via Python's typed
        ipaddress.ip_address objects, which normalizes IPv4 and IPv6 notations).
      - An IP reference identity MUST NEVER be compared against dNSName SAN entries.
      - An IP reference identity MUST NEVER be matched against the Common Name (CN).
      - Wildcards CANNOT match an IP-ID (RFC 9525 §4.3 / RFC 6125 §6.4.3). Wildcard
        expansion is strictly invalid for IP addresses.
      - Typed validation: Only valid IP candidates in san_ip are compared; malformed
        strings are ignored and never matched via fallback string equality.

    DNS-ID MATCHING RULES (RFC 9525 §4.2 - §4.3, RFC 6125 §6.4):
      - SAN (dNSName) takes absolute precedence over CN (RFC 9525 §4.2.1, RFC 6125 §6.4.4).
        If ANY dNSName SAN is present, the client MUST NOT check CN.
      - Case-normalization: DNS comparisons MUST be case-insensitive (RFC 9525 §4.2).
      - Wildcard rules (RFC 9525 §4.3): A wildcard '*' is only permitted in the
        leftmost label (*.example.com) and matches exactly one label level.

    RETURN VALUES:
      'MATCHED'                   — Reference identity matched an iPAddress SAN, dNSName SAN, or CN
      'MISMATCH'                  — Reference identity did NOT match any appropriate entry
      'SKIPPED_NO_SNI'            — No reference identity available in PCAP; skip
      'SKIPPED_NO_CERT_IDENTIFIER'— Cert has no usable SAN (DNS/IP) and no CN; cannot check
    """
    if not claimed_sni:
        # No reference identifier in the client connection context.
        # Per RFC 9525 §4.1 / RFC 6125 §6.1, validation cannot proceed without a reference identity.
        return "SKIPPED_NO_SNI"

    target_str = claimed_sni.strip()

    # ponytail: Strip optional IPv6 bracket notation if present (e.g. "[2001:db8::1]" -> "2001:db8::1")
    ip_cand_str = target_str[1:-1] if target_str.startswith("[") and target_str.endswith("]") else target_str
    target_ip = None
    try:
        # ponytail: stdlib ipaddress cleanly detects and parses both IPv4 and IPv6 reference IDs
        target_ip = ipaddress.ip_address(ip_cand_str)
    except ValueError:
        target_ip = None

    # ───────────────────────────────────────────────────────────────────────────
    # BRANCH A: IP-ID REFERENCE IDENTITY (RFC 9525 §4.4 & RFC 5280 §4.2.1.6)
    # ─────────────────────────────────────────────────────────────────────────
    if target_ip is not None:
        # RFC 9525 §4.4:
        # "If the reference identifier is an IP-ID, the client MUST compare that IP-ID
        # against the iPAddress contents of the subjectAltName extension... The client
        # MUST NOT compare an IP-ID against the dNSName contents of the subjectAltName
        # extension, and the client MUST NOT compare an IP-ID against the CN component."
        #
        # First check if the certificate has zero usable identifiers of any type.
        if not san_ip and not san_dns and (not leaf_cn or leaf_cn == "Unknown"):
            return "SKIPPED_NO_CERT_IDENTIFIER"

        # Strictly typed comparison per RFC 9525 §4.4:
        # Loop through san_ip candidates, parse as ipaddress objects, and compare octet-by-octet.
        # Malformed entries raise ValueError and are ignored (no literal string fallback).
        for candidate in san_ip or []:
            try:
                # ponytail: typed ipaddress comparison handles IPv4/IPv6 normalization strictly
                if target_ip == ipaddress.ip_address(str(candidate).strip()):
                    return "MATCHED"
            except ValueError:
                # Discard non-IP candidate strings; do not allow fallback string matching
                continue

        # If san_ip contains no matching IP (or is empty while cert had DNS/CN identifiers),
        # return MISMATCH. Wildcard and CN matching are strictly forbidden for IP-IDs.
        return "MISMATCH"

    # ───────────────────────────────────────────────────────────────────────────
    # BRANCH B: DNS-ID REFERENCE IDENTITY (RFC 9525 §4.2 - §4.3)
    # ───────────────────────────────────────────────────────────────────────────
    # Case-normalize per RFC 9525 §4.2 / RFC 6125 §6.4.1
    target = target_str.lower()

    # RFC 9525 §4.2.1 / RFC 6125 §6.4.4: SAN (dNSName) takes absolute priority over CN.
    # We only fall through to CN if there are literally zero dNSName SANs.
    if san_dns:
        candidates = [name.strip().lower() for name in san_dns]
    elif leaf_cn and leaf_cn != "Unknown":
        # Fallback: use CN only when no dNSName SAN is present at all.
        candidates = [leaf_cn.strip().lower()]
    elif not san_ip:
        # Cert has no SAN (DNS or IP) and no usable CN
        return "SKIPPED_NO_CERT_IDENTIFIER"
    else:
        # Cert has only iPAddress SANs, but client requested a DNS-ID (RFC 9525 §4.4)
        return "MISMATCH"

    for cand in candidates:
        # Exact match (case-normalized above)
        if cand == target:
            return "MATCHED"

        # RFC 9525 §4.3 / RFC 6125 §6.4.3: Wildcard left-label matching.
        # The wildcard character '*' is only legal as the ENTIRE leftmost label.
        if cand.startswith("*."):
            suffix = cand[1:]  # e.g. ".example.com"
            # Single-level enforcement:
            # *.example.com has 2 dots; mail.example.com has 2 dots -> MATCH.
            # a.mail.example.com has 3 dots -> NOT a match (cannot cross multiple labels).
            if target.endswith(suffix) and target.count(".") == cand.count("."):
                return "MATCHED"

    return "MISMATCH"



def get_x509_subject(identifier_str):
    """
    CONVERT REFERENCE IDENTIFIER STRING → x509 SUBJECT TYPE FOR ServerVerifier (RFC 9525, RFC 5280):
    ------------------------------------------------------------------------------------------------
    PURPOSE:
      cryptography's PolicyBuilder.build_server_verifier() requires a typed
      Subject object, either x509.DNSName or x509.IPAddress. It does not
      accept a raw string. This method converts the client's reference identity
      into the appropriate typed subject object.

    REFERENCE IDENTIFIER CONTEXT & TLS SNI (RFC 9525 §3, RFC 6066 §3):
      RFC 9525 §3 and RFC 6066 §3 explicitly specify that standard TLS SNI
      (Server Name Indication) HostName syntax conveys only fully qualified
      domain names, not IP address literals. When a client establishes an
      IP-ID reference identity (e.g. connecting directly by IP address), standard
      TLS omits the SNI extension entirely.
      However, in forensic analysis of synthetic testbeds (such as PCAP-116),
      higher-layer connection metadata, or non-compliant client traffic, the
      caller supplies an IP reference identity in 'claimed_sni' / 'identifier_str'.
      By testing ipaddress.ip_address() first, we classify an IP reference
      identity (such as '172.28.0.10') as an x509.IPAddress (which is matched
      strictly against iPAddress SAN entries per RFC 9525 §4.4 and RFC 5280 §4.2.1.6)
      rather than misclassifying it as an x509.DNSName.

    WHY WE LOWERCASE DNSName:
      RFC 5280 §7.2 and RFC 9525 §4.2 specify that DNS name comparisons MUST
      be case-insensitive. python-cryptography's ServerVerifier performs
      case-insensitive comparison internally, but lowercasing at input prevents
      any edge-case normalisation surprises.

    WHY THIS NEVER USES THE CERTIFICATE'S OWN SAN/CN:
      This method is called with connection reference identities only (e.g. 'claimed_sni').
      We never call it with the certificate's own Subject CN or SAN values, which
      would violate RFC 9525 §4.1 (reference identity must be established independently
      from connection context, not derived from the presented certificate).

    Returns: x509.DNSName or x509.IPAddress on success, None if unparseable.
    """
    if not identifier_str or identifier_str == "Unknown":
        return None
    clean_str = identifier_str.strip()

    # ponytail: Strip optional IPv6 bracket notation if present (e.g. "[2001:db8::1]" -> "2001:db8::1")
    ip_str = clean_str[1:-1] if clean_str.startswith("[") and clean_str.endswith("]") else clean_str

    # Try IP address first (covers both IPv4 and IPv6 per RFC 9525 §4.4).
    # ipaddress.ip_address() raises ValueError for non-IP strings,
    # so the except branch handles the domain name case.
    try:
        return x509.IPAddress(ipaddress.ip_address(ip_str))
    except ValueError:
        # Domain name path: wrap in x509.DNSName, lower-cased per RFC 9525 §4.2.
        try:
            return x509.DNSName(clean_str.lower())
        except Exception:
            # Malformed hostname (e.g. contains illegal characters).
            # Return None so callers fall back to reference-identity-absent behaviour.
            return None

def verify_pkix_path(leaf_cert, candidate_intermediates, ca_path=None, **kwargs):
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

    SINGLE SOURCE OF TRUTH:
      ca_path is provided directly by TrustStoreManager.get_ca_file_path().
      This function does not resolve or guess fallback paths.

    EMPTY PEM HANDLING:
      If ca_path points to an empty file (0 bytes or whitespace only), path validation
      immediately returns (False, diagnostic) without spawning openssl verify.

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

    COMMAND STRUCTURE:
      openssl verify -CAfile <trust_anchor.pem> [-untrusted <intermediates.pem>] <leaf.pem>
        -CAfile:    Trust anchor(s) — only certs in this file are treated as roots.
        -untrusted: Candidate intermediates — NOT trusted directly; only used to
                    build the chain from leaf to a root in -CAfile.
        <leaf.pem>: The end-entity certificate to validate.

    RETURN VALUES:
      (True, None)         — Path valid, chain anchors to trust store
      (False, diagnostic)  — Path invalid; diagnostic is a filtered stderr string
    """
    import tempfile
    from cryptography.hazmat.primitives import serialization

    # ponytail: TrustStoreManager is the single source of truth for ca_path.
    if not ca_path:
        return False, "No trust anchor CA file path provided for PKIX validation"

    if not os.path.exists(ca_path):
        return False, f"Trust anchor file not found: {ca_path}"

    # ponytail: handle empty PEM (0 bytes or whitespace only) cleanly without spawning openssl.
    # Used by self_signed_untrusted scenarios.
    if os.path.getsize(ca_path) == 0:
        return False, "Trust store file is empty (no trusted root anchors installed)"

    try:
        with open(ca_path, "rb") as f_check:
            if not f_check.read().strip():
                return False, "Trust store file is empty (no trusted root anchors installed)"
    except Exception as e:
        return False, f"Cannot read trust anchor file {ca_path}: {e}"

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



def resolve_prospective_path(leaf_obj, candidate_pool, trust_store_manager=None, ca_path=None):
    """
    RFC 4158 / RFC 5280 §6.1 / RFC 8446 §4.4.2 PROSPECTIVE CERTIFICATION PATH RESOLUTION:
    ======================================================================================
    Reconstructs the prospective certification path starting from the target
    leaf certificate through the captured candidate issuer pool using depth-first
    search (DFS) with backtracking.

    KEY RFC 4158 & RFC 5280 PRINCIPLES:
      • Backtracking (RFC 4158 §2.4): When multiple plausible issuer candidates exist
        (e.g., cross-certification, multi-issuer DAGs, CA key rollover), the resolver
        must not greedily stop at the first locally valid issuer. If a candidate branch
        leads to an untrusted anchor or dead end, the resolver backtracks and explores
        alternate candidate branches until a trusted path is found or all viable branches
        are exhausted.
      • Trust Anchor Awareness: A self-signed root is a successful trust anchor only when
        it is anchored in the active trust store. A self-signed root not in the active
        store is an untrusted branch and triggers backtracking.
      • Loop Detection (RFC 5280 §6.1 / RFC 4158 §3.4.1): A certificate cannot appear
        more than once in the path to prevent cyclic chaining attacks.
      • Deterministic Exploration (RFC 5280 §4.2.1.1-2 / RFC 4158 §3.5):
        Authority Key Identifier (AKI) and Subject Key Identifier (SKI) are used strictly
        as an exploration order preference, not a hard exclusion. Plausible candidates
        are sorted deterministically by (aki_rank, serial_number, DER) so that candidate
        pool ordering on the wire never alters the resulting path.
      • Cryptographic & CA Invariants: Each candidate hop must have
        candidate.subject == current.issuer, candidate.public_key verifies current.signature,
        and candidate.basicConstraints.ca == True.

    Returns:
      tuple: (resolved_path, path_error_tuple, is_terminating_self_signed)
        - resolved_path: list of x509.Certificate [leaf, intermediate_1, ..., terminating_ca]
        - path_error_tuple: None (on success) or (error_code, error_details)
        - is_terminating_self_signed: bool indicating if the final cert in path is a verified self-signed CA
    """
    from cryptography.hazmat.primitives import serialization

    # Resolve active trust store context if available
    store_certs = None
    store_type = "testbed"
    resolved_ca_path = ca_path

    if trust_store_manager is not None:
        trust_store_manager.get_store()
        store_certs = getattr(trust_store_manager, "_store_certs", None)
        store_type = getattr(trust_store_manager, "trust_store_type", "testbed")
        if not resolved_ca_path:
            resolved_ca_path = trust_store_manager.get_ca_file_path()

    def evaluate_path_trust(path):
        """
        Evaluates whether a prospective path successfully anchors to the active trust store.
        Returns: (is_anchored: bool, error_code: Optional[str], error_detail: Optional[str])
        """
        terminating_cert = path[-1]
        is_self_signed = (terminating_cert.issuer == terminating_cert.subject)

        if is_self_signed:
            sig_ok, sig_err = verify_certificate_signature(terminating_cert, terminating_cert)
            if not sig_ok:
                return False, "SELF_SIGNED_SIGNATURE_INVALID", (
                    f"Terminating root CA '{terminating_cert.subject.rfc4514_string()}' claims "
                    f"self-signature but cryptographic verification failed: {sig_err}"
                )

            if store_certs is not None or resolved_ca_path:
                in_store = False
                if store_certs and any(terminating_cert == root for root in store_certs):
                    in_store = True
                elif resolved_ca_path and os.path.exists(resolved_ca_path) and os.path.getsize(resolved_ca_path) > 0:
                    pkix_ok, _ = verify_pkix_path(path[0], path[1:], ca_path=resolved_ca_path)
                    if pkix_ok:
                        in_store = True

                if in_store:
                    return True, None, None
                else:
                    return False, "UNKNOWN_ROOT_CA", (
                        f"Terminating root CA '{terminating_cert.subject.rfc4514_string()}' is self-signed "
                        f"but not present in active '{store_type}' store."
                    )
            else:
                # No trust store provided: verified self-signed root is a valid prospective termination
                return True, None, None
        else:
            # Terminating cert is NOT self-signed (root omitted from wire)
            if store_certs is not None or resolved_ca_path:
                if resolved_ca_path and os.path.exists(resolved_ca_path) and os.path.getsize(resolved_ca_path) > 0:
                    pkix_ok, pkix_err = verify_pkix_path(path[0], path[1:], ca_path=resolved_ca_path)
                    if pkix_ok:
                        return True, None, None
                    else:
                        issuer_in_store = store_certs and any(root.subject == terminating_cert.issuer for root in store_certs)
                        if issuer_in_store:
                            if pkix_err and "signature" in pkix_err.lower():
                                return False, "INVALID_SIGNATURE_IN_CHAIN", (
                                    f"Signature verification failed for intermediate certificate "
                                    f"'{terminating_cert.subject.rfc4514_string()}' against root CA: {pkix_err}"
                                )
                            return False, "PATH_VALIDATION_FAILED", (
                                f"Path validation failed against '{store_type}' store: {pkix_err}"
                            )
                        else:
                            err_code = "INCOMPLETE_CHAIN_MISSING_INTERMEDIATE" if len(path) == 1 else "UNKNOWN_ROOT_CA"
                            return False, err_code, (
                                f"Certificate chain terminates at {'leaf certificate' if len(path) == 1 else 'intermediate CA'} "
                                f"'{terminating_cert.subject.rfc4514_string()}' issued by '{terminating_cert.issuer.rfc4514_string()}', "
                                f"but issuing CA is not present in active '{store_type}' store."
                            )
                elif store_certs:
                    matching_roots = [r for r in store_certs if r.subject == terminating_cert.issuer]
                    if matching_roots:
                        for root in matching_roots:
                            s_ok, _ = verify_certificate_signature(terminating_cert, root)
                            if s_ok:
                                return True, None, None
                        return False, "INVALID_SIGNATURE_IN_CHAIN", (
                            f"Signature verification failed for intermediate '{terminating_cert.subject.rfc4514_string()}' against matching root."
                        )
                    else:
                        err_code = "INCOMPLETE_CHAIN_MISSING_INTERMEDIATE" if len(path) == 1 else "UNKNOWN_ROOT_CA"
                        return False, err_code, (
                            f"Issuing CA '{terminating_cert.issuer.rfc4514_string()}' not present in '{store_type}' store."
                        )

            return False, "INCOMPLETE_CHAIN_MISSING_INTERMEDIATE" if len(path) == 1 else "UNKNOWN_ROOT_CA", (
                f"Path terminates at intermediate '{terminating_cert.subject.rfc4514_string()}' without self-signed root."
            )

    attempted_branches = []

    def dfs(current_path, remaining_pool):
        current = current_path[-1]

        # 1. Check if current certificate is self-signed
        if current.issuer == current.subject:
            is_anchored, err_code, err_detail = evaluate_path_trust(current_path)
            if is_anchored:
                return list(current_path), None, True
            else:
                attempted_branches.append({
                    "path": list(current_path),
                    "error_code": err_code,
                    "details": err_detail,
                    "is_self_signed": True
                })
                # Backtrack: untrusted self-signed root must not terminate the search
                return None

        # 2. Find plausible candidate issuers in remaining_pool:
        # Loop prevention (RFC 5280 §6.1 / RFC 4158 §3.4.1): candidate must not be in current_path
        name_matching_cands = [
            c for c in remaining_pool
            if c.subject == current.issuer and c not in current_path
        ]

        if not name_matching_cands:
            # No candidates in pool can extend current.
            # Check if current directly anchors to trust store (e.g. root omitted from wire)
            is_anchored, err_code, err_detail = evaluate_path_trust(current_path)
            if is_anchored:
                return list(current_path), None, False
            else:
                attempted_branches.append({
                    "path": list(current_path),
                    "error_code": err_code,
                    "details": err_detail,
                    "is_self_signed": False
                })
                return None

        # 4. Disambiguation using AKI / SKI (RFC 5280 §4.2.1.1 / RFC 4158 §3.5):
        current_aki = None
        try:
            aki_ext = current.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value
            current_aki = aki_ext.key_identifier
        except Exception:
            current_aki = None

        def candidate_sort_key(cand):
            # AKI ranking: 0 = match, 1 = mismatch, 2 = missing SKI
            rank = 0
            if current_aki is not None:
                try:
                    cand_ski = cand.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest
                    rank = 0 if cand_ski == current_aki else 1
                except Exception:
                    rank = 2
            # Deterministic tie-breaker: serial number, then DER bytes
            return (rank, cand.serial_number, cand.public_bytes(serialization.Encoding.DER))

        sorted_candidates = sorted(name_matching_cands, key=candidate_sort_key)

        cand_failures = []
        for cand in sorted_candidates:
            # Verify cryptographic hop: cand's public key must verify current's signature
            sig_ok, sig_err = verify_certificate_signature(current, cand)
            if not sig_ok:
                cand_failures.append({
                    "cand": cand,
                    "error_code": "INVALID_SIGNATURE_IN_CHAIN",
                    "details": f"Candidate '{cand.subject.rfc4514_string()}' (serial {cand.serial_number}) signature check failed: {sig_err}"
                })
                continue

            # Verify basicConstraints CA flag on issuing candidate (RFC 5280 §4.2.1.9)
            try:
                bc_ext = cand.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS).value
                if not bc_ext.ca:
                    cand_failures.append({
                        "cand": cand,
                        "error_code": "CA_CONSTRAINT_VIOLATION",
                        "details": f"Issuing candidate '{cand.subject.rfc4514_string()}' has basicConstraints with ca=False"
                    })
                    continue
            except x509.ExtensionNotFound:
                cand_failures.append({
                    "cand": cand,
                    "error_code": "CA_CONSTRAINT_VIOLATION",
                    "details": f"Issuing candidate '{cand.subject.rfc4514_string()}' is missing mandatory basicConstraints extension"
                })
                continue

            # Candidate is plausible! Recurse.
            next_remaining = [c for c in remaining_pool if c != cand]
            res = dfs(current_path + [cand], next_remaining)
            if res is not None:
                return res  # Trusted path found!

            # Backtrack: this candidate did not yield a trusted path, try next candidate in sorted_candidates!

        # If all candidates for current were rejected by crypto/CA checks:
        if cand_failures and not any(b["path"][:len(current_path)] == current_path for b in attempted_branches):
            primary_err = "CA_CONSTRAINT_VIOLATION" if any(f["error_code"] == "CA_CONSTRAINT_VIOLATION" for f in cand_failures) else "INVALID_SIGNATURE_IN_CHAIN"
            err_msg = "; ".join(f["details"] for f in cand_failures)
            attempted_branches.append({
                "path": list(current_path),
                "error_code": primary_err,
                "details": err_msg,
                "is_self_signed": False
            })

        return None

    res = dfs([leaf_obj], list(candidate_pool))
    if res is not None:
        return res

    # ── AGGREGATE FAILURE RESOLUTION (DETERMINISTIC) ─────────────────────────
    # If all branches failed, select the failure classification deterministically
    # according to validator semantics, independent of candidate input ordering.
    if not attempted_branches:
        error_code = "INCOMPLETE_CHAIN_MISSING_INTERMEDIATE"
        diag = (
            f"Incomplete chain: path terminates at leaf '{leaf_obj.subject.rfc4514_string()}' "
            f"issued by '{leaf_obj.issuer.rfc4514_string()}', but issuing intermediate CA "
            f"certificate was not transmitted and is not present in active '{store_type}' store."
        )
        return [leaf_obj], (error_code, diag), False

    # Precedence among failure types (Priority 1 -> 4):
    # 1. Structural violations: CA_CONSTRAINT_VIOLATION, INVALID_SIGNATURE_IN_CHAIN, SELF_SIGNED_SIGNATURE_INVALID
    # 2. Untrusted root: UNKNOWN_ROOT_CA
    # 3. Path constraints: PATH_VALIDATION_FAILED
    # 4. Incomplete intermediate: INCOMPLETE_CHAIN_MISSING_INTERMEDIATE
    priority_order = [
        "CA_CONSTRAINT_VIOLATION",
        "INVALID_SIGNATURE_IN_CHAIN",
        "SELF_SIGNED_SIGNATURE_INVALID",
        "UNKNOWN_ROOT_CA",
        "PATH_VALIDATION_FAILED",
        "INCOMPLETE_CHAIN_MISSING_INTERMEDIATE",
    ]

    selected_error_code = "UNKNOWN_ROOT_CA"
    for err_type in priority_order:
        if any(b["error_code"] == err_type for b in attempted_branches):
            selected_error_code = err_type
            break

    matching_branches = [b for b in attempted_branches if b["error_code"] == selected_error_code]
    if not matching_branches:
        matching_branches = attempted_branches
    best_branch = max(matching_branches, key=lambda b: (len(b["path"]), b["path"][-1].serial_number))

    if len(attempted_branches) > 1:
        branch_summaries = []
        for i, b in enumerate(attempted_branches, 1):
            path_str = " -> ".join(c.subject.rfc4514_string() for c in b["path"])
            branch_summaries.append(f"Branch {i} [{path_str}]: {b['error_code']} ({b['details']})")
        aggregate_diag = (
            f"All {len(attempted_branches)} candidate branch(es) failed trust verification: " +
            "; ".join(branch_summaries)
        )
    else:
        aggregate_diag = best_branch["details"]

    return best_branch["path"], (selected_error_code, aggregate_diag), best_branch.get("is_self_signed", False)



def classify_path_failure(terminating_cert, store_certs, store_type, failure_err, leaf_obj=None):
    """
    RFC 5280 §6.1 / RFC 8446 §4.4.2 PATH FAILURE CLASSIFICATION:
    ============================================================
    Evaluates an unanchored certification path against trust policies and distinguishes
    missing wire certificates from unrecognized trust anchors.

    RFC REFERENCES & DESIGN CHOICES (THE "WHY"):
      • RFC 5280 §6.1 / §6.1.1: The trust anchor is an external input provided to the
        path validation algorithm by the local policy domain, NOT a fixed property of the cert.
      • Problem Solved: Previously, any validation failure against the active store was
        blindly tagged as PATH_VALIDATION_FAILED (Case 3) or INCOMPLETE_CHAIN (Case 2).
        This produced false alarms when an enterprise server transmitted a complete,
        cryptographically flawless certificate chain that simply anchored to a private CA.
      • UNKNOWN_ROOT_CA:
        Either the chain includes a self-signed root CA absent from the trust store,
        or the chain terminates at an intermediate CA whose issuing root is absent from
        the active trust store (standard TLS behavior where servers omit root CAs).
      • INCOMPLETE_CHAIN_MISSING_INTERMEDIATE:
        The transmitted path terminates at the leaf certificate itself (depth 0), meaning
        the server failed to transmit the required intermediate CA certificate(s).
      • PATH_VALIDATION_FAILED:
        The terminating root CA IS present in the active trust store, but PKIX path
        validation failed due to constraint violations, name constraints, or unverified hop signatures.
    """
    if terminating_cert.issuer == terminating_cert.subject:
        sig_ok, sig_err = verify_certificate_signature(terminating_cert, terminating_cert)
        if sig_ok:
            if any(terminating_cert == root for root in store_certs):
                return "PATH_VALIDATION_FAILED", (
                    f"Path validation failed against {store_type} store: {failure_err}"
                )
            else:
                return "UNKNOWN_ROOT_CA", (
                    f"Certificate chain is internally cryptographically authentic and terminates at "
                    f"self-signed root CA '{terminating_cert.subject.rfc4514_string()}', "
                    f"but root anchor is not present in active '{store_type}' store."
                )
        else:
            return "SELF_SIGNED_SIGNATURE_INVALID", (
                f"Terminating root CA '{terminating_cert.subject.rfc4514_string()}' claims self-signature, "
                f"but cryptographic verification failed: {sig_err}"
            )
    else:
        # Non-self-signed terminating certificate:
        # If the path terminated at the leaf certificate itself (depth 0), the server
        # failed to transmit the intermediate CA certificate that issued the leaf.
        if leaf_obj is not None and terminating_cert == leaf_obj:
            return "INCOMPLETE_CHAIN_MISSING_INTERMEDIATE", (
                f"Incomplete chain: path terminates at leaf certificate "
                f"'{terminating_cert.subject.rfc4514_string()}' issued by '{terminating_cert.issuer.rfc4514_string()}', "
                f"but issuing intermediate CA certificate was not transmitted in TLS handshake "
                f"and is not present in active '{store_type}' store."
            )

        # ponytail: direct linear scan over store_certs subject matching.
        # Minimal and dependency-free; index by subject DN if trust store exceeds 10k roots.
        issuer_in_store = any(root.subject == terminating_cert.issuer for root in store_certs)
        if issuer_in_store:
            # The root CA exists in the trust store, but validation failed
            if failure_err and "signature" in failure_err.lower():
                return "INVALID_SIGNATURE_IN_CHAIN", (
                    f"Signature verification failed for intermediate certificate "
                    f"'{terminating_cert.subject.rfc4514_string()}' against root CA: {failure_err}"
                )
            return "PATH_VALIDATION_FAILED", (
                f"Path validation failed against {store_type} store for intermediate "
                f"'{terminating_cert.subject.rfc4514_string()}': {failure_err}"
            )
        else:
            # The issuing root CA is not present in the active trust store
            return "UNKNOWN_ROOT_CA", (
                f"Certificate chain terminates at intermediate CA "
                f"'{terminating_cert.subject.rfc4514_string()}' issued by '{terminating_cert.issuer.rfc4514_string()}', "
                f"but issuing root CA is not present in active '{store_type}' store."
            )


def extract_certificates(pcap_path, trust_store_manager=None, trust_store_type="testbed"):
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

    TLS 1.3 PASSIVE CAPTURE BOUNDARY:
      TLS 1.3 (RFC 8446 §5.2) encrypts the Certificate message under the
      handshake traffic key inside application_data records (TLSCiphertext).
      Under passive wire inspection without session keys, no plaintext
      Certificate frames exist on the wire. This method returns {} for
      TLS 1.3 streams by design, reflecting production key-blind visibility.
    """
    if trust_store_manager is None:
        trust_store_manager = TrustStoreManager(trust_store=trust_store_type)
    active_store = trust_store_manager.get_store()
    store_certs = trust_store_manager._store_certs
    store_type = trust_store_manager.trust_store_type
    store_description = trust_store_manager.trust_store_description

    # tshark filter: HandshakeType 11 = Certificate message (RFC 5246 §7.4.2 / RFC 8446 §4.4.2).
    # The 'or tls.handshake.certificate' alternative catches some tshark versions that
    # dissect the field differently from the type filter alone.
    command = [
        "tshark",
        "-r", pcap_path,
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
        "-r", pcap_path,
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
                extended_key_usage_present = False
                try:
                    eku_ext = cert.extensions.get_extension_for_oid(
                        x509.ExtensionOID.EXTENDED_KEY_USAGE
                    ).value
                    extended_key_usage_present = True
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
                    extended_key_usage_present = False

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
                    "extended_key_usage_present":   extended_key_usage_present,
                    "has_extended_key_usage":       extended_key_usage_present,
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
        # ponytail: pass san_ip to check_hostname_match for RFC 9525 §4.4 iPAddress matching
        hostname_match_status = check_hostname_match(
            claimed_sni,
            leaf_dict["san_dns"],
            leaf_dict["subject_cn"],
            leaf_dict.get("san_ip", []),
        )

        # ═══════════════════════════════════════════════════════════════════════════
        # RFC 5280 / RFC 6125 / RFC 8446 PATH VALIDATION & TRUST DISPATCH
        # ═══════════════════════════════════════════════════════════════════════════
        # ARCHITECTURAL DISPATCH (THREE CASES):
        #   CASE 1: Single Self-Signed Certificate (len == 1, issuer DN == subject DN)
        #   CASE 2: Single Leaf Certificate (len == 1, issuer DN != subject DN)
        #   CASE 3: Multi-Certificate Chain (len > 1, leaf + intermediates/root)
        #
        # RFC PRINCIPLES & DESIGN RATIONALE (THE "WHY"):
        #   • RFC 5280 §6.1.3(a)(1): Validity period check (now vs not_before / not_after)
        #     MUST occur before cryptographic path construction or trust evaluation.
        #   • Telemetry Fidelity: For self-signed certificates, 'is_self_signed = True'
        #     must be set immediately so telemetry accurately reflects the certificate
        #     type even if expired or untrusted.
        #   • RFC 5280 §6.1 / RFC 8446 §4.4.2: The trust anchor is an external input.
        #     When path validation against the active store fails:
        #       - If the chain terminates in a verified self-signed root -> UNKNOWN_ROOT_CA
        #         (full chain sent, but root is not in active trust store).
        #       - If no self-signed cert is present in what was actually transmitted ->
        #         INCOMPLETE_CHAIN_MISSING_INTERMEDIATE (chain missing intermediate/root).
        #       - If terminating root is in active store but path constraints failed ->
        #         PATH_VALIDATION_FAILED.
        trust_status       = "UNKNOWN"
        trust_details      = ""
        is_self_signed     = False
        is_anchored        = False
        verification_error = None
        actual_resolved_path = [leaf_obj]

        # REFERENCE IDENTITY RESOLUTION (RFC 6125 §6.1):
        # Reference identity MUST come from independently observed connection context (SNI).
        reference_identity = get_x509_subject(claimed_sni) if claimed_sni else None
        builder = PolicyBuilder().store(active_store).time(now) if active_store is not None else None

        # ───────────────────────────────────────────────────────────────────────────
        # CASE 1: SELF-SIGNED CERTIFICATE (issuer DN == subject DN, single cert)
        # ───────────────────────────────────────────────────────────────────────────
        if len(raw_cert_objs) == 1 and leaf_obj.issuer == leaf_obj.subject:
            is_self_signed = True

            # Step 1: Validity period check (RFC 5280 §6.1.3(a)(1))
            # Checked at the top of Case 1 before signature or store checks so that
            # expired / not-yet-valid self-signed test certs are flagged immediately
            # while preserving is_self_signed = True in telemetry.
            if now > leaf_obj.not_valid_after_utc:
                trust_status = "EXPIRED"
                trust_details = (
                    f"Self-signed certificate ({leaf_obj.subject.rfc4514_string()}) "
                    f"is expired (expired on {leaf_obj.not_valid_after_utc})."
                )
                is_anchored = False
            elif now < leaf_obj.not_valid_before_utc:
                trust_status = "NOT_YET_VALID"
                trust_details = (
                    f"Self-signed certificate ({leaf_obj.subject.rfc4514_string()}) "
                    f"is not yet valid (valid from {leaf_obj.not_valid_before_utc})."
                )
                is_anchored = False
            else:
                # Step 2: Cryptographic self-signature verification
                valid_self_sig, err = verify_certificate_signature(leaf_obj, leaf_obj)
                if valid_self_sig:
                    # Step 3: Active trust store membership check (RFC 5280 §6.1.1)
                    is_anchored = any(leaf_obj == root for root in store_certs)
                    if is_anchored:
                        trust_status = "TRUSTED_SELF_SIGNED"
                        trust_details = (
                            f"Cryptographically verified self-signed certificate. "
                            f"Explicitly installed and trusted as root anchor in active '{store_type}' store."
                        )
                    else:
                        trust_status = "UNTRUSTED_SELF_SIGNED"
                        trust_details = (
                            f"Cryptographically verified self-signed certificate. "
                            f"Untrusted: not present in active '{store_type}' store."
                        )
                else:
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
        elif len(raw_cert_objs) == 1:
            # Step 1: Validity period check (RFC 5280 §6.1.3(a)(1))
            if now > leaf_obj.not_valid_after_utc:
                trust_status = "EXPIRED"
                trust_details = (
                    f"Certificate ({leaf_obj.subject.rfc4514_string()}) "
                    f"is expired (expired on {leaf_obj.not_valid_after_utc})."
                )
                is_anchored = False
            elif now < leaf_obj.not_valid_before_utc:
                trust_status = "NOT_YET_VALID"
                trust_details = (
                    f"Certificate ({leaf_obj.subject.rfc4514_string()}) "
                    f"is not yet valid (valid from {leaf_obj.not_valid_before_utc})."
                )
                is_anchored = False
            else:
                # Step 2: PKIX path validation against active trust store
                pkix_ok = False
                pkix_err = None

                if reference_identity is not None and builder is not None:
                    try:
                        verifier = builder.build_server_verifier(reference_identity)
                        verifier.verify(leaf_obj, [])
                        trust_status = "TRUSTED_CHAIN"
                        trust_details = (
                            f"Single leaf certificate verified for SNI '{claimed_sni}' "
                            f"and directly anchored to root CA in {store_type} store."
                        )
                        is_anchored = True
                        pkix_ok = True
                    except Exception as e_sni:
                        pkix_ok, pkix_err = verify_pkix_path(
                            leaf_obj, [],
                            ca_path=trust_store_manager.get_ca_file_path(),
                            trust_store_type=store_type, base_dir=trust_store_manager.base_dir
                        )
                        if pkix_ok:
                            if hostname_match_status == "MISMATCH":
                                trust_status = "TRUSTED_CHAIN_HOSTNAME_MISMATCH"
                                trust_details = (
                                    f"Single leaf certificate directly anchored to root CA in "
                                    f"{store_type} store, but does NOT match claimed SNI '{claimed_sni}'."
                                )
                            else:
                                trust_status = "TRUSTED_CHAIN"
                                trust_details = (
                                    f"Single leaf certificate cryptographically authentic, verified for "
                                    f"SNI '{claimed_sni}', and anchored to {store_type} store via PKIX validation."
                                )
                            is_anchored = True
                        else:
                            pkix_err = pkix_err or str(e_sni)
                else:
                    hostname_match_status = "SKIPPED_NO_SNI"
                    pkix_ok, pkix_err = verify_pkix_path(
                        leaf_obj, [],
                        ca_path=trust_store_manager.get_ca_file_path(),
                        trust_store_type=store_type, base_dir=trust_store_manager.base_dir
                    )
                    if pkix_ok:
                        trust_status = "TRUSTED_CHAIN"
                        trust_details = (
                            f"Single leaf certificate verified and directly anchored to root CA "
                            f"in {store_type} store. Hostname verification skipped: "
                            f"no SNI or client reference identity observed in PCAP (RFC 6125)."
                        )
                        is_anchored = True

                if not pkix_ok:
                    # Case 2 Failure Branch: check terminating cert (leaf_obj)
                    trust_status, trust_details = classify_path_failure(
                        leaf_obj, store_certs, store_type, pkix_err, leaf_obj=leaf_obj
                    )
                    is_anchored = False
                    verification_error = pkix_err

        # ───────────────────────────────────────────────────────────────────────────
        # CASE 3: MULTI-CERTIFICATE CHAIN (leaf + one or more intermediates/roots)
        # ───────────────────────────────────────────────────────────────────────────
        elif len(raw_cert_objs) > 1:
            # Step 1: Scan entire chain for validity period issues (RFC 5280 §6.1.3(a)(1))
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
                # Step 2: Prospective path resolution with backtracking (RFC 4158 / RFC 5280 §6.1 / RFC 8446 §4.4.2)
                candidate_pool = raw_cert_objs[1:]
                resolved_path, path_error, is_terminating_self_signed = resolve_prospective_path(
                    leaf_obj,
                    candidate_pool,
                    trust_store_manager=trust_store_manager,
                    ca_path=trust_store_manager.get_ca_file_path()
                )
                actual_resolved_path = resolved_path

                if path_error:
                    trust_status = path_error[0]
                    trust_details = path_error[1]
                    is_anchored = False
                    verification_error = path_error[1]
                else:
                    intermediates_for_pkix = resolved_path[1:]
                    terminating_ca = resolved_path[-1]

                    # Step 3: PKIX path validation against active trust store
                    pkix_ok = False
                    pkix_err = None

                    if reference_identity is not None and builder is not None:
                        try:
                            verifier = builder.build_server_verifier(reference_identity)
                            verifier.verify(leaf_obj, intermediates_for_pkix)
                            trust_status = "TRUSTED_CHAIN"
                            trust_details = (
                                f"Certificate chain cryptographically authentic, verified for "
                                f"SNI '{claimed_sni}', and anchored to {store_type} trust store."
                            )
                            is_anchored = True
                            pkix_ok = True
                        except Exception as e_sni:
                            pkix_ok, pkix_err = verify_pkix_path(
                                leaf_obj, intermediates_for_pkix,
                                ca_path=trust_store_manager.get_ca_file_path(),
                                trust_store_type=store_type, base_dir=trust_store_manager.base_dir
                            )
                            if pkix_ok:
                                if hostname_match_status == "MISMATCH":
                                    trust_status = "TRUSTED_CHAIN_HOSTNAME_MISMATCH"
                                    trust_details = (
                                        f"Certificate chain cryptographically authentic and anchored to "
                                        f"{store_type} store, but does NOT match claimed SNI '{claimed_sni}'."
                                    )
                                else:
                                    trust_status = "TRUSTED_CHAIN"
                                    trust_details = (
                                        f"Certificate chain cryptographically authentic, verified for "
                                        f"SNI '{claimed_sni}', and anchored to {store_type} trust store via PKIX validation."
                                    )
                                is_anchored = True
                            else:
                                pkix_err = pkix_err or str(e_sni)
                    else:
                        hostname_match_status = "SKIPPED_NO_SNI"
                        pkix_ok, pkix_err = verify_pkix_path(
                            leaf_obj, intermediates_for_pkix,
                            ca_path=trust_store_manager.get_ca_file_path(),
                            trust_store_type=store_type, base_dir=trust_store_manager.base_dir
                        )
                        if pkix_ok:
                            trust_status = "TRUSTED_CHAIN"
                            trust_details = (
                                f"Certificate chain cryptographically authentic and anchored to "
                                f"{store_type} store. Hostname verification skipped: "
                                f"no SNI or client reference identity observed in PCAP (RFC 6125)."
                            )
                            is_anchored = True

                    if not pkix_ok:
                        # Case 3 Failure Branch (RFC 5280 §6.1 / RFC 8446 §4.4.2):
                        # Evaluates whether terminating CA is self-signed and verified:
                        #   - Verified self-signed root -> UNKNOWN_ROOT_CA (if not in store)
                        #   - Intermediate / unanchored cert -> INCOMPLETE_CHAIN_MISSING_INTERMEDIATE
                        #   - Root in store but constraint failed -> PATH_VALIDATION_FAILED
                        trust_status, trust_details = classify_path_failure(
                            terminating_ca, store_certs, store_type, pkix_err, leaf_obj=leaf_obj
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
        path_summary = [
            {
                "serial": str(c.serial_number),
                "serial_number": str(c.serial_number),
                "subject": c.subject.rfc4514_string(),
                "issuer": c.issuer.rfc4514_string(),
                "sha256_fingerprint": c.fingerprint(hashes.SHA256()).hex(),
            }
            for c in actual_resolved_path
        ]

        sessions_certs[sid] = {
            "stream":                        sid,
            "chain_length":                  len(parsed_chain),
            "is_self_signed":                is_self_signed,
            "trust_status":                  trust_status,
            "trust_details":                 trust_details,
            "path_verification_error":       verification_error,
            "active_trust_store":            store_type,
            "active_trust_store_description": store_description,
            "anchored_in_active_store":      is_anchored,
            "claimed_sni":                   claimed_sni,
            "hostname_match":                hostname_match_status,
            "revocation_status":             "NOT_CHECKED (PASSIVE_OFFLINE_ANALYSIS)",
            "resolved_path":                 path_summary,
            "leaf_cert":                     leaf_dict,
            "full_chain":                    parsed_chain,
            "parse_errors":                  parse_errors
        }

    return sessions_certs



# Backward compatibility alias
_get_x509_subject = get_x509_subject
_verify_pkix_path = verify_pkix_path
extract_certificate = extract_certificates
