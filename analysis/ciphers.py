import csv
import os
import ssl
import sys

"""
IANA TLS Cipher Suite Database Loader

This module parses the official IANA TLS Parameters registry CSV into an in-memory
lookup dictionary. It handles several subtle cryptographic and syntactic edge cases:

PROBLEMS & EDGE CASES HANDLED:
---------------------------------------------------------------------------------------
1. Unassigned & Reserved Rows (Data Corruption Prevention):
   - Many rows in the registry are unassigned ranges or single reserved entries
     (e.g. '0x00,0x1C-1D' or 'Reserved to avoid conflicts with SSLv3').
   - These are explicitly skipped to prevent dummy cipher suites from polluting the DB.

2. SCSV Pseudo-Suites (Signaling Filtering):
   - Values like TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00,0xFF) and TLS_FALLBACK_SCSV (0x56,0x00)
     are signaling indicators for downgrade/renegotiation defense (RFC 5746, RFC 7507).
   - They are not encryption algorithms and are filtered out of session cipher lookups.

3. Anonymous DH / ECDH Suites (Critical Security Distinction):
   - Anonymous suites (e.g. TLS_DH_anon_WITH_AES_128_CBC_SHA) provide mathematical PFS
     but ZERO authentication, making them trivially vulnerable to MITM interception.
   - They are explicitly classified as kex="ANONYMOUS" and strength="BROKEN".

4. PSK & Kerberos Authentication (RFC 4279, RFC 5489, RFC 2712):
   - Pre-Shared Key (PSK) and Kerberos (KRB5) suites do not use traditional PKIX RSA authentication.
   - Plain PSK (RFC 4279 §2) and Kerberos (RFC 2712) lack Ephemeral Diffie-Hellman key exchange.
     Consequently, they provide NO Forward Secrecy (PFS = False). Compromise of the pre-shared key
     allows retroactive decryption of past captured traffic.
   - Per NIST SP 800-52r2 and our security model, any suite lacking PFS is classified as WEAK
     regardless of whether it employs modern AEAD (GCM/CCM) or legacy CBC.
   - Conversely, DHE_PSK (RFC 4279 §3) and ECDHE_PSK (RFC 5489) combine PSK authentication with
     ephemeral DH key exchange, maintaining forward secrecy (PFS = True) and achieving HIGH or MEDIUM.

5. TLS 1.3 Key Exchange Nuance (RFC 8446):
   - TLS 1.3 cipher suite names (e.g. TLS_AES_256_GCM_SHA384) do not encode the key exchange
     in the cipher name; the ephemeral group (e.g. x25519) is negotiated via the key_share extension.
   - These suites are labeled kex="TLS13_EPHEMERAL" with forward_secrecy=True guaranteed.

6. CCM_8 Truncated-Tag Distinction:
   - Suites with '_CCM_8' use a short 64-bit authentication tag, which represents an insecure
     trade-off (discouraged by IANA/RFCs). These are trapped and categorized as WEAK before
     the generic 'CCM' check can promote them to HIGH.

7. 4-Tier Cryptographic Strength Model (Mozilla & NIST SP 800-52r2):
   - HIGH: Modern AEAD ciphers with Forward Secrecy (GCM, Poly1305, full CCM) and PFS.
   - MEDIUM: Ciphers with Forward Secrecy (ECDHE/DHE) but using legacy CBC mode.
   - WEAK: Non-PFS key exchange (Static RSA, plain PSK, Kerberos — No Forward Secrecy), truncated tags (CCM_8), or IANA deprecated.
   - BROKEN: Anonymous ciphers (no auth), NULL, EXPORT, RC4, 3DES, DES, or MD5.

8. Robust Error Handling & Path Validation:
   - Validates CSV file presence with explicit warnings if missing.
   - Key formatting f"0x{int(b1, 16):02x}{int(b2, 16):02x}".lower() matches TShark output.
"""

def load_iana_cipher_database(csv_path=None):
    """
    Loads and normalizes the official IANA cipher suite registry CSV into a dictionary
    keyed by 4-character hex ID (e.g. '0xc030').
    """
    if csv_path is None:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        csv_path = os.path.join(base_dir, "..", "data", "tls_ciphers.csv")

    if not os.path.exists(csv_path):
        sys.stderr.write(f"[ERROR] IANA cipher suite database not found at {csv_path}!\n")
        return {}

    cipher_db = {}

    with open(csv_path, mode="r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                val = row.get("Value", "").strip().replace('"', '')
                desc = row.get("Description", "").strip()
                rec = row.get("Recommended", "").strip()

                # 1. Skip empty, unassigned, or reserved rows
                if not desc or "Reserved" in desc or "Unassigned" in desc:
                    continue

                # 2. Skip SCSV signaling values
                if desc.endswith("_SCSV"):
                    continue

                # 3. Format hex key: e.g. "0x00,0x2F" -> "0x002f", "0xC0,0x30" -> "0xc030"
                if "," not in val:
                    continue
                b1, b2 = val.split(",")
                hex_id = f"0x{int(b1, 16):02x}{int(b2, 16):02x}".lower()

                name_upper = desc.upper()

                # 4. Key Exchange & Authentication Identification
                if "ANON" in name_upper:
                    kex = "ANONYMOUS"
                elif name_upper.startswith("TLS_AES_") or name_upper.startswith("TLS_CHACHA20_"):
                    kex = "TLS13_EPHEMERAL"  # Group negotiated via key_share extension
                elif "ECDHE" in name_upper:
                    kex = "ECDHE_PSK" if "PSK" in name_upper else "ECDHE"
                elif "DHE" in name_upper:
                    kex = "DHE_PSK" if "PSK" in name_upper else "DHE"
                elif "PSK" in name_upper:
                    kex = "PSK"
                elif "KRB5" in name_upper:
                    kex = "KERBEROS"
                else:
                    kex = "RSA_STATIC"

                # Forward Secrecy (PFS) determination
                has_pfs = kex in ("ECDHE", "DHE", "ECDHE_PSK", "DHE_PSK", "TLS13_EPHEMERAL", "ANONYMOUS")

                # 5. 4-Tier Cryptographic Strength Model (Load-bearing evaluation order)
                # TIER 1: BROKEN
                # - Anonymous (unauthenticated MITM), NULL, EXPORT, RC4, 3DES, DES, MD5
                if (kex == "ANONYMOUS" or 
                    "NULL" in name_upper or 
                    "EXPORT" in name_upper or
                    any(bad in name_upper for bad in ("RC4", "3DES", "DES", "_MD5"))):
                    strength = "BROKEN"

                # TIER 2: WEAK (Checked BEFORE Tier 3 - deliberate and load-bearing!)
                # - Deprecated by IANA (rec == 'D')
                # - Non-PFS key exchange (Static RSA, plain PSK, Kerberos — No Forward Secrecy):
                #   NOTE: This intentionally traps suites like TLS_RSA_WITH_AES_256_GCM_SHA384
                #   and TLS_PSK_WITH_AES_128_GCM_SHA256. Even though GCM is modern AEAD, the lack
                #   of PFS disqualifies them from HIGH or MEDIUM. Static/non-PFS configurations
                #   are inherently WEAK per our security model and NIST SP 800-52r2.
                # - Short 64-bit truncated authentication tag (CCM_8)
                elif (rec == "D" or 
                      not has_pfs or 
                      "_CCM_8" in name_upper or 
                      "_CCM-8" in name_upper):
                    strength = "WEAK"

                # TIER 3: HIGH
                # - Modern full AEAD ciphers with Forward Secrecy (GCM, Poly1305, full CCM)
                # - Strictly requires has_pfs == True
                elif has_pfs and any(aead in name_upper for aead in ("GCM", "POLY1305", "CCM")):
                    strength = "HIGH"

                # TIER 4: MEDIUM
                # - Ciphers with Forward Secrecy (ECDHE, DHE, ECDHE_PSK, DHE_PSK) that use legacy CBC mode
                #   (e.g. TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_DHE_PSK_WITH_AES_128_CBC_SHA).
                # - Also captures Camellia/ARIA/SEED with ephemeral PFS.
                else:
                    strength = "MEDIUM"

                cipher_db[hex_id] = {
                    "name": desc,
                    "kex": kex,
                    "forward_secrecy": has_pfs,
                    "strength": strength,
                    "iana_recommended": rec == "Y"
                }

            except (ValueError, IndexError):
                continue

    return cipher_db


# Global cache
_GLOBAL_CIPHER_DB = None

def get_cipher_info(cipher_hex):
    """
    Returns the metadata dictionary for a given hex code (e.g. '0xc030').
    Falls back gracefully if the hex is not recognized.
    """
    global _GLOBAL_CIPHER_DB
    if _GLOBAL_CIPHER_DB is None:
        _GLOBAL_CIPHER_DB = load_iana_cipher_database()

    cipher_hex = cipher_hex.strip().lower()
    if cipher_hex in _GLOBAL_CIPHER_DB:
        return _GLOBAL_CIPHER_DB[cipher_hex]

    return {
        "name": f"Unknown ({cipher_hex})",
        "kex": "UNKNOWN",
        "forward_secrecy": False,
        "strength": "UNKNOWN",
        "iana_recommended": False
    }


# ---------------------------------------------------------------------------
# Dynamic Bidirectional IANA <-> OpenSSL Cipher Suite Translator
# ---------------------------------------------------------------------------

_IANA_NAME_TO_HEX = None
_HEX_TO_OPENSSL_NAME = None
_OPENSSL_NAME_TO_HEX = None


def _init_openssl_mapping():
    """
    Initializes the mapping between the full IANA cipher database and OpenSSL's
    internal cipher table by correlating their standard 16-bit cipher IDs.
    """
    global _IANA_NAME_TO_HEX, _HEX_TO_OPENSSL_NAME, _OPENSSL_NAME_TO_HEX
    if _IANA_NAME_TO_HEX is not None:
        return

    db = load_iana_cipher_database()
    _IANA_NAME_TO_HEX = {}
    for hex_id, entry in db.items():
        name = entry.get("name")
        if name:
            _IANA_NAME_TO_HEX[name.upper()] = hex_id.lower()

    _HEX_TO_OPENSSL_NAME = {}
    _OPENSSL_NAME_TO_HEX = {}
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.set_ciphers("ALL:COMPLEMENTOFALL:@SECLEVEL=0")
        for c in ctx.get_ciphers():
            hex_id = f"0x{c['id'] & 0xFFFF:04x}".lower()
            name = c["name"]
            _HEX_TO_OPENSSL_NAME[hex_id] = name
            _OPENSSL_NAME_TO_HEX[name.upper()] = hex_id
    except Exception:
        pass


# Canonical IANA -> OpenSSL translation for suites (including legacy/broken ciphers)
CANONICAL_IANA_TO_OPENSSL: dict[str, str] = {
    # 3DES / DES
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA": "DES-CBC3-SHA",
    "TLS_RSA_WITH_DES_CBC_SHA": "DES-CBC-SHA",
    "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA": "EDH-RSA-DES-CBC3-SHA",
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA": "ECDHE-RSA-DES-CBC3-SHA",
    # RC4
    "TLS_RSA_WITH_RC4_128_SHA": "RC4-SHA",
    "TLS_RSA_WITH_RC4_128_MD5": "RC4-MD5",
    "TLS_ECDHE_RSA_WITH_RC4_128_SHA": "ECDHE-RSA-RC4-SHA",
    "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA": "ECDHE-ECDSA-RC4-SHA",
    # Static RSA AES
    "TLS_RSA_WITH_AES_128_CBC_SHA": "AES128-SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA": "AES256-SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA256": "AES128-SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA256": "AES256-SHA256",
    "TLS_RSA_WITH_AES_128_GCM_SHA256": "AES128-GCM-SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384": "AES256-GCM-SHA384",
}
CANONICAL_OPENSSL_TO_IANA: dict[str, str] = {v.upper(): k for k, v in CANONICAL_IANA_TO_OPENSSL.items()}


def iana_to_openssl(iana_name: str) -> str | None:
    """
    Translates an official IANA cipher suite name (e.g. 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384'
    or 'TLS_RSA_WITH_3DES_EDE_CBC_SHA') to its OpenSSL cipher string ('DHE-RSA-AES256-GCM-SHA384',
    'DES-CBC3-SHA').

    If the name is already a recognized OpenSSL cipher name, it returns the name unchanged.
    Returns None if the cipher cannot be mapped to an OpenSSL name.
    """
    _init_openssl_mapping()
    clean = iana_name.strip()
    clean_upper = clean.upper()

    # 1. Match from dynamically discovered OpenSSL runtime ciphers
    hex_id = _IANA_NAME_TO_HEX.get(clean_upper)
    if hex_id and hex_id in _HEX_TO_OPENSSL_NAME:
        return _HEX_TO_OPENSSL_NAME[hex_id]

    # 2. Match canonical IANA -> OpenSSL translation table (including legacy/broken ciphers)
    if clean_upper in CANONICAL_IANA_TO_OPENSSL:
        return CANONICAL_IANA_TO_OPENSSL[clean_upper]

    # 3. Check if already an OpenSSL cipher name
    if clean_upper in _OPENSSL_NAME_TO_HEX:
        return clean

    return None


def openssl_to_iana(openssl_name: str) -> str | None:
    """
    Translates an OpenSSL cipher name (e.g. 'DHE-RSA-AES256-GCM-SHA384') to its official
    IANA cipher suite name ('TLS_DHE_RSA_WITH_AES_256_GCM_SHA384').
    """
    _init_openssl_mapping()
    clean = openssl_name.strip()
    clean_upper = clean.upper()

    hex_id = _OPENSSL_NAME_TO_HEX.get(clean_upper)
    if hex_id:
        info = get_cipher_info(hex_id)
        if info and not info["name"].startswith("Unknown"):
            return info["name"]

    if clean_upper in CANONICAL_OPENSSL_TO_IANA:
        return CANONICAL_OPENSSL_TO_IANA[clean_upper]

    return None
