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



def get_x509_subject(identifier_str):
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

def verify_pkix_path(leaf_cert, candidate_intermediates, trust_store_type="testbed", base_dir=None):
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
    if trust_store_type == "testbed":
        ca_dir = base_dir or os.path.dirname(os.path.abspath(__file__))
        ca_path = os.path.join(ca_dir, "..", "data", "test_root_ca.pem")
        if not os.path.exists(ca_path):
            return False, f"Testbed trust anchor file not found: {ca_path}"
    elif trust_store_type == "production":
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



def resolve_prospective_path(leaf_obj, candidate_pool):
    """
    RFC 5280 §6.1 / RFC 8446 §4.4.2 PROSPECTIVE CERTIFICATION PATH RESOLUTION:
    ==========================================================================
    Reconstructs the prospective certification path starting from the target
    leaf certificate through the captured candidate issuer pool.

    RFC REFERENCES & DESIGN PRINCIPLES (THE "WHY"):
      • RFC 8446 §4.4.2: The sender's certificate MUST come first (leaf),
        while implementations MUST tolerate arbitrary ordering of the
        remaining certificates in the Certificate message.
      • RFC 5280 §6.1: A prospective certification path is an ordered sequence
        of certificates (C_0, C_1, ..., C_n) where C_0 is the end-entity,
        and each C_{i+1} certifies C_i (C_i.issuer == C_{i+1}.subject and
        C_{i+1}'s public key cryptographically verifies C_i's signature).
      • Loop Detection (RFC 5280 §6.1): A certificate cannot appear more than
        once in the path to prevent cyclic chaining attacks.
      • AKI / SKI Disambiguation (RFC 5280 §4.2.1.1-2):
        Authority Key Identifier (AKI) and Subject Key Identifier (SKI) are used
        strictly as OPTIONAL disambiguation when multiple candidate issuers share
        the same Subject DN (e.g. during CA key rollover). Per RFC 5280, AKI/SKI is
        NOT a mandatory linking condition, and its absence MUST NOT cause a valid
        path to be rejected.
      • basicConstraints CA Flag (RFC 5280 §4.2.1.9): Intermediate issuing
        certificates MUST assert ca=True.
      • Non-Duplication of PKIX Engine: RFC 5280 explicitly notes that the
        procedure for obtaining the certificate sequence is outside the scope of
        RFC 5280. This resolver prepares and orders the prospective candidate
        path from captured wire evidence before handing it to the full PKIX
        validator (ServerVerifier / openssl verify) for policy, name constraints,
        path length constraints, and trust anchor binding.

    Returns:
      tuple: (resolved_path, path_error_tuple, is_terminating_self_signed)
        - resolved_path: list of x509.Certificate [leaf, intermediate_1, ..., terminating_ca]
        - path_error_tuple: None or (error_code, error_details)
        - is_terminating_self_signed: bool indicating if the final cert in path is a verified self-signed CA
    """
    current = leaf_obj
    resolved_path = [current]
    remaining_candidates = list(candidate_pool)
    seen_certs = {current}

    while True:
        # Check if current cert is self-signed (issuer DN == subject DN)
        if current.issuer == current.subject:
            # Cryptographic verification of self-signature
            sig_ok, sig_err = verify_certificate_signature(current, current)
            if sig_ok:
                # Reached a cryptographically verified self-signed root CA
                return resolved_path, None, True
            else:
                return resolved_path, (
                    "SELF_SIGNED_SIGNATURE_INVALID",
                    f"Certificate '{current.subject.rfc4514_string()}' claims self-signature but cryptographic verification failed: {sig_err}"
                ), False

        # Current is not self-signed. Search remaining candidates for its issuer.
        # Primary filter: candidate.subject == current.issuer
        name_matching_cands = [c for c in remaining_candidates if c.subject == current.issuer]

        if not name_matching_cands:
            # No candidate in the captured pool has the subject DN matching current.issuer.
            # The captured path terminates here without a self-signed root.
            return resolved_path, None, False

        # Disambiguation using AKI / SKI (RFC 5280 §4.2.1.1):
        # Used as an optional ranking aid when multiple candidates share the same Subject DN.
        # RFC 5280: AKI/SKI is NOT a mandatory linking condition.
        current_aki = None
        try:
            aki_ext = current.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value
            current_aki = aki_ext.key_identifier
        except Exception:
            current_aki = None

        if len(name_matching_cands) > 1 and current_aki is not None:
            def aki_rank(cand):
                try:
                    cand_ski = cand.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest
                    return 0 if cand_ski == current_aki else 1
                except Exception:
                    return 2
            name_matching_cands.sort(key=aki_rank)

        valid_issuer = None
        cand_errors = []

        for cand in name_matching_cands:
            if cand in seen_certs:
                # Loop prevention (RFC 5280 §6.1): certificate cannot appear twice in path
                continue

            # Verify cryptographic hop: cand's public key must verify current's signature
            sig_ok, sig_err = verify_certificate_signature(current, cand)
            if not sig_ok:
                cand_errors.append(f"Candidate '{cand.subject.rfc4514_string()}' signature check failed: {sig_err}")
                continue

            # Verify basicConstraints CA flag on issuing candidate (RFC 5280 §4.2.1.9)
            try:
                bc_ext = cand.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS).value
                if not bc_ext.ca:
                    cand_errors.append(
                        f"Issuing candidate '{cand.subject.rfc4514_string()}' has basicConstraints with ca=False"
                    )
                    continue
            except x509.ExtensionNotFound:
                cand_errors.append(
                    f"Issuing candidate '{cand.subject.rfc4514_string()}' is missing mandatory basicConstraints extension"
                )
                continue

            valid_issuer = cand
            break

        if valid_issuer is not None:
            resolved_path.append(valid_issuer)
            seen_certs.add(valid_issuer)
            remaining_candidates.remove(valid_issuer)
            current = valid_issuer
        else:
            if cand_errors:
                if any("ca=False" in e or "missing mandatory" in e for e in cand_errors):
                    return resolved_path, ("CA_CONSTRAINT_VIOLATION", "; ".join(cand_errors)), False
                else:
                    return resolved_path, ("INVALID_SIGNATURE_IN_CHAIN", "; ".join(cand_errors)), False
            return resolved_path, None, False


def classify_path_failure(terminating_cert, store_certs, store_type, failure_err):
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
        The transmitted chain includes a self-signed root CA whose signature verifies,
        but that root CA is absent from the active trust store. The wire capture is
        internally authentic; the issue is strictly local trust policy.
      • INCOMPLETE_CHAIN_MISSING_INTERMEDIATE:
        The transmitted path terminates at a non-self-signed certificate whose issuing
        CA was omitted by the server and is absent from the active store. The server
        misconfigured its TLS handshake by failing to transmit intermediate links.
      • PATH_VALIDATION_FAILED:
        The terminating root CA IS present in the active trust store, but PKIX path
        validation failed due to constraint violations (pathLenConstraint, basicConstraints),
        name constraints, or unverified hop signatures.
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
        return "INCOMPLETE_CHAIN_MISSING_INTERMEDIATE", (
            f"Incomplete chain: path terminates at certificate "
            f"'{terminating_cert.subject.rfc4514_string()}' issued by '{terminating_cert.issuer.rfc4514_string()}', "
            f"but issuing CA certificate was not transmitted in TLS handshake "
            f"and is not present in active '{store_type}' store."
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

        # REFERENCE IDENTITY RESOLUTION (RFC 6125 §6.1):
        # Reference identity MUST come from independently observed connection context (SNI).
        reference_identity = get_x509_subject(claimed_sni) if claimed_sni else None
        builder = PolicyBuilder().store(active_store).time(now)

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

                if reference_identity is not None:
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
                            trust_store_type=store_type, base_dir=trust_store_manager.base_dir
                        )
                        if pkix_ok:
                            trust_status = "TRUSTED_CHAIN_HOSTNAME_MISMATCH"
                            trust_details = (
                                f"Single leaf certificate directly anchored to root CA in "
                                f"{store_type} store, but does NOT match claimed SNI '{claimed_sni}'."
                            )
                            is_anchored = True
                        else:
                            pkix_err = pkix_err or str(e_sni)
                else:
                    hostname_match_status = "SKIPPED_NO_SNI"
                    pkix_ok, pkix_err = verify_pkix_path(
                        leaf_obj, [],
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
                        leaf_obj, store_certs, store_type, pkix_err
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
                # Step 2: Prospective path resolution (RFC 5280 §6.1 / RFC 8446 §4.4.2)
                candidate_pool = raw_cert_objs[1:]
                resolved_path, path_error, is_terminating_self_signed = resolve_prospective_path(
                    leaf_obj, candidate_pool
                )

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

                    if reference_identity is not None:
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
                                trust_store_type=store_type, base_dir=trust_store_manager.base_dir
                            )
                            if pkix_ok:
                                trust_status = "TRUSTED_CHAIN_HOSTNAME_MISMATCH"
                                trust_details = (
                                    f"Certificate chain cryptographically authentic and anchored to "
                                    f"{store_type} store, but does NOT match claimed SNI '{claimed_sni}'."
                                )
                                is_anchored = True
                            else:
                                pkix_err = pkix_err or str(e_sni)
                    else:
                        hostname_match_status = "SKIPPED_NO_SNI"
                        pkix_ok, pkix_err = verify_pkix_path(
                            leaf_obj, intermediates_for_pkix,
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
                            terminating_ca, store_certs, store_type, pkix_err
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
            "active_trust_store":            store_type,
            "active_trust_store_description": store_description,
            "anchored_in_active_store":      is_anchored,
            "claimed_sni":                   claimed_sni,
            "hostname_match":                hostname_match_status,
            "revocation_status":             "NOT_CHECKED (PASSIVE_OFFLINE_ANALYSIS)",
            "leaf_cert":                     leaf_dict,
            "full_chain":                    parsed_chain,
            "parse_errors":                  parse_errors
        }

    return sessions_certs



# Backward compatibility alias
_get_x509_subject = get_x509_subject
_verify_pkix_path = verify_pkix_path
extract_certificate = extract_certificates
