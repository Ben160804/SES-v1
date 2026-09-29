import json
import csv
from pathlib import Path


INPUT_FILES = [
    "/home/rick/Downloads/smtp_587_50.json",
    "/home/rick/Downloads/smtp_587_new.json",
]

OUTPUT = Path("datasets/ml/zgrab/zgrab_features.csv")


def get(d, *keys, default=None):
    for key in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(key)
    return d


def extract(row):
    smtp = get(row, "data", "smtp", default={})
    result = smtp.get("result", {})

    tls = result.get("tls") or {}
    handshake = tls.get("handshake_log") or {}
    server_hello = handshake.get("server_hello") or {}

    certs = handshake.get("server_certificates") or {}
    cert = get(certs, "certificate", "parsed", default={}) or {}

    ski = cert.get("subject_key_info") or {}
    rsa_key = ski.get("rsa_public_key") or {}
    extensions = cert.get("extensions") or {}

    san = extensions.get("subject_alt_name") or {}
    basic = extensions.get("basic_constraints") or {}
    eku = extensions.get("extended_key_usage") or {}
    key_usage = extensions.get("key_usage") or {}

    chain = certs.get("chain") or []

    # TLS cipher
    cipher = server_hello.get("cipher_suite") or {}
    key_share = server_hello.get("key_share") or {}

    return {
        # Identity / collection metadata
        "ip": row.get("ip"),
        "port": smtp.get("port"),
        "scan_timestamp": smtp.get("timestamp") or row.get("timestamp"),

        # SMTP
        "smtp_status": smtp.get("status"),
        "smtp_protocol": smtp.get("protocol"),
        "banner_present": int(bool(result.get("banner"))),
        "ehlo_present": int(bool(result.get("ehlo"))),
        "starttls_present": int("starttls" in result),

        # TLS
        "tls_observed": int(bool(tls)),
        "tls_handshake_success": int(
            bool(tls.get("handshake_completed_successfully"))
        ),
        "tls_version": (
            server_hello.get("version", {}).get("name")
            if isinstance(server_hello.get("version"), dict)
            else server_hello.get("version")
        ),
        "cipher_suite": cipher.get("name"),
        "key_exchange": key_share.get("name"),
        "ja3s": tls.get("ja3s"),

        # Certificate presence / trust
        "certificate_observed": int(bool(cert)),
        "browser_trusted": get(
            certs, "validation", "browser_trusted"
        ),

        # Certificate crypto
        "cert_key_algorithm": ski.get("key_algorithm", {}).get("name")
            if isinstance(ski.get("key_algorithm"), dict)
            else ski.get("key_algorithm"),

        "cert_rsa_key_size": rsa_key.get("length"),

        "cert_signature_algorithm": (
            cert.get("signature_algorithm", {}).get("name")
            if isinstance(cert.get("signature_algorithm"), dict)
            else cert.get("signature_algorithm")
        ),

        # Certificate validation
        "cert_validation_level": cert.get("validation_level"),
        "cert_self_signed": get(cert, "signature", "self_signed"),

        # Certificate extensions
        "cert_san_count": len(san.get("dns_names", []) or []),
        "cert_is_ca": basic.get("is_ca"),
        "cert_server_auth": eku.get("server_auth"),

        "cert_key_usage_count": sum(
            1 for key, value in key_usage.items()
            if key != "value" and value is True
        ) if isinstance(key_usage, dict) else 0,

        "cert_extension_count": len(extensions),

        # Chain
        "cert_chain_length": len(chain),
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
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Extracted observations : {len(rows)}")
    print(f"Features               : {len(fieldnames)}")
    print(f"Output                 : {OUTPUT}")


if __name__ == "__main__":
    main()
