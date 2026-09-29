import csv
import json
import math
from datetime import datetime, timezone
from pathlib import Path


INPUT_FILES = sorted(
    str(p)
    for p in Path("datasets/ml/zgrab").glob("zgrab_*.json")
)

OUTPUT = Path("datasets/ml/zgrab/zgrab_features.csv")


def get(d, *keys, default=None):
    for key in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(key)
    return d


def parse_time(value):
    if not value:
        return None

    try:
        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except Exception:
        return None


def extract(row):
    smtp = get(row, "data", "smtp", default={}) or {}
    result = smtp.get("result") or {}

    tls = result.get("tls") or {}
    handshake = tls.get("handshake_log") or {}
    server_hello = handshake.get("server_hello") or {}

    certs = handshake.get("server_certificates") or {}
    cert = get(certs, "certificate", "parsed", default={}) or {}

    ski = cert.get("subject_key_info") or {}
    rsa_key = ski.get("rsa_public_key") or {}
    ecdsa_key = ski.get("ecdsa_public_key") or {}

    extensions = cert.get("extensions") or {}

    san = extensions.get("subject_alt_name") or {}
    basic = extensions.get("basic_constraints") or {}
    eku = extensions.get("extended_key_usage") or {}
    key_usage = extensions.get("key_usage") or {}

    validity = cert.get("validity") or {}

    aia = extensions.get("authority_info_access") or {}
    policies = extensions.get("certificate_policies") or []
    scts = extensions.get("signed_certificate_timestamps") or []
    crl = extensions.get("crl_distribution_points") or []

    chain = certs.get("chain") or []

    cipher = server_hello.get("cipher_suite") or {}
    key_share = server_hello.get("key_share") or {}

    version_obj = server_hello.get("version")
    tls_version = (
        version_obj.get("name")
        if isinstance(version_obj, dict)
        else version_obj
    )

    selected_version = (
        server_hello.get("supported_versions", {}).get("selected_version")
        if isinstance(server_hello.get("supported_versions"), dict)
        else None
    )

    extension_ids = server_hello.get("extension_identifiers") or []

    # -------------------------
    # Basic protocol state
    # -------------------------

    smtp_status = smtp.get("status")
    banner = result.get("banner")
    ehlo = result.get("ehlo")

    tls_observed = bool(tls)
    cert_observed = bool(cert)

    # -------------------------
    # Cipher-derived features
    # -------------------------

    cipher_name = cipher.get("name")

    cipher_upper = (cipher_name or "").upper()

    uses_aead = any(
        x in cipher_upper
        for x in ["GCM", "CHACHA20", "POLY1305"]
    )

    uses_cbc = "CBC" in cipher_upper

    uses_rsa_kex = (
        cipher_upper.startswith("TLS_RSA_")
        or "_RSA_WITH_" in cipher_upper and "ECDHE_RSA" not in cipher_upper
    )

    uses_ecdhe = "ECDHE" in cipher_upper

    uses_chacha = "CHACHA20" in cipher_upper

    uses_gcm = "GCM" in cipher_upper

    # -------------------------
    # TLS version features
    # -------------------------

    tls_version_upper = (tls_version or "").upper()

    is_tls10 = tls_version_upper in {"TLSV1.0", "TLS1.0"}
    is_tls11 = tls_version_upper in {"TLSV1.1", "TLS1.1"}
    is_tls12 = tls_version_upper in {"TLSV1.2", "TLS1.2"}
    is_tls13 = tls_version_upper in {"TLSV1.3", "TLS1.3"}

    is_legacy_tls = is_tls10 or is_tls11

    # -------------------------
    # Key exchange
    # -------------------------

    key_exchange = key_share.get("name")

    key_exchange_upper = (key_exchange or "").upper()

    uses_x25519 = key_exchange_upper == "X25519"
    uses_p256 = key_exchange_upper in {"SECP256R1", "P-256"}
    uses_p384 = key_exchange_upper in {"SECP384R1", "P-384"}

    uses_pfs = uses_ecdhe or bool(key_exchange)

    # -------------------------
    # TLS extension features
    # -------------------------

    extension_count = len(extension_ids)

    has_supported_versions = "supported_versions" in extension_ids
    has_key_share = "key_share" in extension_ids
    has_server_name = "server_name" in extension_ids
    has_alpn = "application_layer_protocol_negotiation" in extension_ids
    has_signature_algorithms = "signature_algorithms" in extension_ids
    has_supported_groups = "supported_groups" in extension_ids

    # -------------------------
    # Certificate features
    # -------------------------

    cert_key_algorithm = (
        ski.get("key_algorithm", {}).get("name")
        if isinstance(ski.get("key_algorithm"), dict)
        else ski.get("key_algorithm")
    )

    rsa_key_size = rsa_key.get("length")
    ecdsa_key_size = ecdsa_key.get("length")
    ecdsa_curve = ecdsa_key.get("curve")

    signature_algorithm = (
        cert.get("signature_algorithm", {}).get("name")
        if isinstance(cert.get("signature_algorithm"), dict)
        else cert.get("signature_algorithm")
    )

    signature_upper = (signature_algorithm or "").upper()

    cert_sha1 = "SHA1" in signature_upper
    cert_sha256 = "SHA256" in signature_upper
    cert_sha384 = "SHA384" in signature_upper
    cert_sha512 = "SHA512" in signature_upper

    cert_san_names = san.get("dns_names", []) or []
    cert_san_count = len(cert_san_names)

    cert_has_wildcard = any(
        isinstance(x, str) and x.startswith("*.")
        for x in cert_san_names
    )

    cert_max_san_length = max(
        [len(x) for x in cert_san_names if isinstance(x, str)],
        default=0
    )

    cert_unique_san_count = len(set(cert_san_names))

    cert_server_auth = eku.get("server_auth")
    cert_client_auth = eku.get("client_auth")

    key_usage_count = sum(
        1
        for key, value in key_usage.items()
        if key != "value" and value is True
    ) if isinstance(key_usage, dict) else 0

    cert_digital_signature = bool(
        key_usage.get("digital_signature")
    ) if isinstance(key_usage, dict) else False

    cert_key_encipherment = bool(
        key_usage.get("key_encipherment")
    ) if isinstance(key_usage, dict) else False

    cert_key_agreement = bool(
        key_usage.get("key_agreement")
    ) if isinstance(key_usage, dict) else False

    cert_is_ca = basic.get("is_ca")

    cert_self_signed = get(
        cert,
        "signature",
        "self_signed"
    )

    # -------------------------
    # Certificate validity
    # -------------------------

    scan_time = parse_time(
        smtp.get("timestamp") or row.get("timestamp")
    )

    validity_start = parse_time(validity.get("start"))
    validity_end = parse_time(validity.get("end"))

    cert_validity_days = None
    cert_days_remaining = None
    cert_expired = None
    cert_not_yet_valid = None

    if validity_start and validity_end:
        cert_validity_days = (
            validity_end - validity_start
        ).total_seconds() / 86400

        reference_time = scan_time or datetime.now(timezone.utc)

        cert_days_remaining = (
            validity_end - reference_time
        ).total_seconds() / 86400

        cert_expired = cert_days_remaining < 0
        cert_not_yet_valid = reference_time < validity_start

    # -------------------------
    # Certificate extension features
    # -------------------------

    ocsp_urls = aia.get("ocsp_urls", []) or []
    issuer_urls = aia.get("issuer_urls", []) or []

    cert_policy_count = len(policies)
    cert_sct_count = len(scts)
    cert_crl_url_count = len(crl)

    # -------------------------
    # Risk flags
    # -------------------------

    weak_rsa_key = (
        rsa_key_size is not None and rsa_key_size < 2048
    )

    weak_cipher = uses_cbc or uses_rsa_kex

    legacy_protocol_risk = is_legacy_tls

    certificate_signature_risk = cert_sha1

    certificate_identity_risk = (
        cert_self_signed is True
        or cert_server_auth is False
        or cert_expired is True
        or cert_not_yet_valid is True
    )

    # -------------------------
    # Return feature vector
    # -------------------------

    return {
        # -------------------------
        # Original/raw features
        # -------------------------
        "ip": row.get("ip"),
        "port": smtp.get("port"),
        "scan_timestamp": smtp.get("timestamp") or row.get("timestamp"),

        "smtp_status": smtp_status,
        "smtp_protocol": smtp.get("protocol"),
        "banner_present": int(bool(banner)),
        "ehlo_present": int(bool(ehlo)),
        "starttls_present": int("starttls" in result),

        "tls_observed": int(tls_observed),
        "tls_handshake_success": int(
            bool(tls.get("handshake_completed_successfully"))
        ),

        "tls_version": tls_version,
        "cipher_suite": cipher_name,
        "key_exchange": key_exchange,
        "ja3s": tls.get("ja3s"),

        "certificate_observed": int(cert_observed),
        "browser_trusted": get(
            certs,
            "validation",
            "browser_trusted"
        ),

        "cert_key_algorithm": cert_key_algorithm,
        "cert_rsa_key_size": rsa_key_size,
        "cert_signature_algorithm": signature_algorithm,
        "cert_validation_level": cert.get("validation_level"),
        "cert_self_signed": cert_self_signed,

        "cert_san_count": cert_san_count,
        "cert_is_ca": cert_is_ca,
        "cert_server_auth": cert_server_auth,
        "cert_key_usage_count": key_usage_count,
        "cert_extension_count": len(extensions),
        "cert_chain_length": len(chain),

        # -------------------------
        # TLS derived
        # -------------------------
        "tls_selected_version": selected_version,
        "tls_extension_count": extension_count,

        "tls_has_supported_versions": int(has_supported_versions),
        "tls_has_key_share": int(has_key_share),
        "tls_has_server_name": int(has_server_name),
        "tls_has_alpn": int(has_alpn),
        "tls_has_signature_algorithms": int(
            has_signature_algorithms
        ),
        "tls_has_supported_groups": int(has_supported_groups),

        "tls_has_session_ticket": int(
            bool(server_hello.get("ticket"))
        ),
        "tls_has_ocsp_stapling": int(
            bool(server_hello.get("ocsp_stapling"))
        ),
        "tls_secure_renegotiation": int(
            bool(server_hello.get("secure_renegotiation"))
        ),
        "tls_extended_master_secret": int(
            bool(server_hello.get("extended_master_secret"))
        ),
        "tls_heartbeat": int(
            bool(server_hello.get("heartbeat"))
        ),

        "tls_compression_method": (
            server_hello.get("compression_method")
        ),

        "tls_session_id_present": int(
            bool(server_hello.get("session_id"))
        ),

        # -------------------------
        # Cipher derived
        # -------------------------
        "cipher_uses_aead": int(uses_aead),
        "cipher_uses_cbc": int(uses_cbc),
        "cipher_uses_rsa_kex": int(uses_rsa_kex),
        "cipher_uses_ecdhe": int(uses_ecdhe),
        "cipher_uses_chacha20": int(uses_chacha),
        "cipher_uses_gcm": int(uses_gcm),

        # -------------------------
        # TLS version derived
        # -------------------------
        "is_tls10": int(is_tls10),
        "is_tls11": int(is_tls11),
        "is_tls12": int(is_tls12),
        "is_tls13": int(is_tls13),
        "is_legacy_tls": int(is_legacy_tls),

        # -------------------------
        # Key exchange derived
        # -------------------------
        "key_exchange_x25519": int(uses_x25519),
        "key_exchange_p256": int(uses_p256),
        "key_exchange_p384": int(uses_p384),
        "uses_forward_secrecy": int(uses_pfs),

        # -------------------------
        # Certificate crypto
        # -------------------------
        "cert_ecdsa_key_size": ecdsa_key_size,
        "cert_ecdsa_curve": ecdsa_curve,

        "cert_rsa_exponent": rsa_key.get("exponent"),

        "cert_sha1_signature": int(cert_sha1),
        "cert_sha256_signature": int(cert_sha256),
        "cert_sha384_signature": int(cert_sha384),
        "cert_sha512_signature": int(cert_sha512),

        "cert_weak_rsa_key": int(weak_rsa_key),

        # -------------------------
        # Certificate identity
        # -------------------------
        "cert_has_wildcard_san": int(cert_has_wildcard),
        "cert_max_san_length": cert_max_san_length,
        "cert_unique_san_count": cert_unique_san_count,

        "cert_client_auth": (
            int(bool(cert_client_auth))
            if cert_client_auth is not None
            else None
        ),

        "cert_digital_signature": int(cert_digital_signature),
        "cert_key_encipherment": int(cert_key_encipherment),
        "cert_key_agreement": int(cert_key_agreement),

        # -------------------------
        # Certificate validity
        # -------------------------
        "cert_validity_days": cert_validity_days,
        "cert_days_remaining": cert_days_remaining,
        "cert_expired": (
            int(cert_expired)
            if cert_expired is not None
            else None
        ),
        "cert_not_yet_valid": (
            int(cert_not_yet_valid)
            if cert_not_yet_valid is not None
            else None
        ),

        # -------------------------
        # Certificate infrastructure
        # -------------------------
        "cert_ocsp_url_count": len(ocsp_urls),
        "cert_issuer_url_count": len(issuer_urls),
        "cert_has_ocsp": int(bool(ocsp_urls)),
        "cert_policy_count": cert_policy_count,
        "cert_has_certificate_policy": int(
            cert_policy_count > 0
        ),
        "cert_sct_count": cert_sct_count,
        "cert_has_sct": int(cert_sct_count > 0),
        "cert_crl_url_count": cert_crl_url_count,
        "cert_has_crl_distribution": int(
            cert_crl_url_count > 0
        ),
        "cert_has_authority_key_id": int(
            bool(extensions.get("authority_key_id"))
        ),
        "cert_has_subject_key_id": int(
            bool(extensions.get("subject_key_id"))
        ),

        # -------------------------
        # Security-derived flags
        # -------------------------
        "risk_legacy_tls": int(legacy_protocol_risk),
        "risk_weak_cipher": int(weak_cipher),
        "risk_rsa_key_exchange": int(uses_rsa_kex),
        "risk_cbc_cipher": int(uses_cbc),
        "risk_sha1_certificate": int(certificate_signature_risk),
        "risk_weak_rsa_certificate": int(weak_rsa_key),
        "risk_certificate_identity": int(
            certificate_identity_risk
        ),

        "smtp_plaintext_only": int(
            bool(result)
            and not tls_observed
            and "starttls" not in result
        ),

        "smtp_starttls_to_tls_success": int(
            "starttls" in result and tls_observed
        ),
    }


def main():
    rows = []

    for filename in INPUT_FILES:
        path = Path(filename)

        if not path.exists():
            print(f"WARNING: missing {path}")
            continue

        with path.open() as f:
            for line in f:
                line = line.strip()

                if not line:
                    continue

                try:
                    row = json.loads(line)
                    rows.append(extract(row))
                except Exception as e:
                    print(f"ERROR parsing row in {path}: {e}")

    if not rows:
        raise SystemExit("No observations extracted.")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = list(rows[0].keys())

    with OUTPUT.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"Extracted observations : {len(rows)}")
    print(f"Features               : {len(fieldnames)}")
    print(f"Output                 : {OUTPUT}")


if __name__ == "__main__":
    main()
