"""
TLS Protocol Constants & Registry Mappings

Standard lookup tables and RFC definitions for TLS version numbers,
RFC 8446 / RFC 7919 NamedGroups (key share groups), and PSK exchange modes.
"""

# Standard TLS Handshake Version lookup table
TLS_VERSION_MAP = {
    "0x0301": "TLS 1.0",
    "0x0302": "TLS 1.1",
    "0x0303": "TLS 1.2",
    "0x0304": "TLS 1.3",
}

# TLS 1.3 NamedGroup → human-readable name (RFC 8446 §4.2.7, RFC 7919, RFC 8422)
# tshark emits tls.handshake.extensions_key_share_group as FT_UINT16 BASE_DEC,
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
    # Post-Quantum / Hybrid groups (draft-ietf-tls-hybrid-design, draft-cfrg-schwabe-kyber)
    "4587": "x25519_kyber512_draft00",
    "4588": "x25519_kyber768_draft00",
    "25497": "x25519_mlkem768",
    "25498": "secp256r1_mlkem768",
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

# ── HANDSHAKE MESSAGE TYPES (RFC 5246 §7.4, RFC 8446 §4) ──────────────────────
# Note: HelloRetryRequest (RFC 8446 §4.1.4) is NOT a distinct handshake type on the
# wire — it uses the ServerHello structure (Type 2) and is identified exclusively
# by the special constant SHA-256("HelloRetryRequest") in ServerHello.random.
HANDSHAKE_TYPE_MAP = {
    "0": "HelloRequest",
    "1": "ClientHello",
    "2": "ServerHello",
    "4": "NewSessionTicket",
    "5": "EndOfEarlyData",
    "8": "EncryptedExtensions",
    "11": "Certificate",
    "12": "ServerKeyExchange",
    "13": "CertificateRequest",
    "14": "ServerHelloDone",
    "15": "CertificateVerify",
    "16": "ClientKeyExchange",
    "20": "Finished",
    "24": "KeyUpdate",
}

# ── RECORD CONTENT TYPES (RFC 5246 §6.2.1, RFC 8446 §5.1) ─────────────────────
RECORD_CONTENT_TYPE_MAP = {
    "20": "ChangeCipherSpec",
    "21": "Alert",
    "22": "Handshake",
    "23": "ApplicationData",
    "24": "Heartbeat",
}

# ── TLS ALERT LEVELS & DESCRIPTIONS (RFC 5246 §7.2, RFC 8446 §6) ─────────────
TLS_ALERT_LEVEL_MAP = {
    "1": "WARNING",
    "2": "FATAL",
}

TLS_ALERT_DESC_MAP = {
    "0": "close_notify",
    "10": "unexpected_message",
    "20": "bad_record_mac",
    "21": "decryption_failed_RESERVED",
    "22": "record_overflow",
    "30": "decompression_failure",
    "40": "handshake_failure",
    "41": "no_certificate_RESERVED",
    "42": "bad_certificate",
    "43": "unsupported_certificate",
    "44": "certificate_revoked",
    "45": "certificate_expired",
    "46": "certificate_unknown",
    "47": "illegal_parameter",
    "48": "unknown_ca",
    "49": "access_denied",
    "50": "decode_error",
    "51": "decrypt_error",
    "60": "export_restriction_RESERVED",
    "70": "protocol_version",
    "71": "insufficient_security",
    "80": "internal_error",
    "86": "inappropriate_fallback",
    "90": "user_canceled",
    "100": "no_renegotiation",
    "109": "missing_extension",
    "110": "unsupported_extension",
    "111": "certificate_unobtainable",
    "112": "unrecognized_name",
    "113": "bad_certificate_status_response",
    "114": "bad_certificate_hash_value",
    "115": "unknown_psk_identity",
    "116": "certificate_required",
    "120": "no_application_protocol",
}

# ── SIGNATURE SCHEMES / SIGNATURE ALGORITHMS (RFC 8446 §4.2.3, RFC 5246 §7.4.1.4.1) ─
# Wire identifiers for handshake and certificate signature algorithms.
SIG_HASH_ALG_MAP = {
    # RSASSA-PKCS1-v1_5 (RFC 5246 / RFC 8446)
    "0x0401": "rsa_pkcs1_sha256",
    "0x0501": "rsa_pkcs1_sha384",
    "0x0601": "rsa_pkcs1_sha512",
    "0x0301": "rsa_pkcs1_sha224",
    "0x0201": "rsa_pkcs1_sha1",
    "0x0101": "rsa_pkcs1_md5",
    # ECDSA (RFC 5246 / RFC 8446)
    "0x0403": "ecdsa_secp256r1_sha256",
    "0x0503": "ecdsa_secp384r1_sha384",
    "0x0603": "ecdsa_secp521r1_sha512",
    "0x0303": "ecdsa_sha224",
    "0x0203": "ecdsa_sha1",
    "0x081a": "ecdsa_brainpoolP256r1tls13_sha256",
    "0x081b": "ecdsa_brainpoolP384r1tls13_sha384",
    "0x081c": "ecdsa_brainpoolP512r1tls13_sha512",
    # DSA (RFC 5246 §7.4.1.4.1 legacy)
    "0x0202": "dsa_sha1",
    "0x0302": "dsa_sha224",
    "0x0402": "dsa_sha256",
    "0x0502": "dsa_sha384",
    "0x0602": "dsa_sha512",
    # RSASSA-PSS RSAE (RFC 8446)
    "0x0804": "rsa_pss_rsae_sha256",
    "0x0805": "rsa_pss_rsae_sha384",
    "0x0806": "rsa_pss_rsae_sha512",
    # RSASSA-PSS PSS (RFC 8446)
    "0x0809": "rsa_pss_pss_sha256",
    "0x080a": "rsa_pss_pss_sha384",
    "0x080b": "rsa_pss_pss_sha512",
    # EdDSA (RFC 8446)
    "0x0807": "ed25519",
    "0x0808": "ed448",
    # Post-Quantum (provisional / draft)
    "0x0904": "mldsa44",
    "0x0905": "mldsa65",
    "0x0906": "mldsa87",
}

# ── RFC 8446 SPECIAL CONSTANTS ────────────────────────────────────────────────
# HelloRetryRequest magic constant: SHA-256("HelloRetryRequest") (RFC 8446 §4.1.4)
# When ServerHello.random exactly matches these 32 bytes, the message is a HelloRetryRequest.
RFC8446_HRR_RANDOM = "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"

# Downgrade sentinels (RFC 8446 §4.1.3):
# Placed in the last 8 bytes (16 hex chars) of ServerHello.random by a TLS 1.3-capable
# server negotiating TLS 1.2 or below.
RFC8446_DOWNGRADE_SENTINEL_TLS12 = "444f574e47524401"  # "DOWNGRD\x01"
RFC8446_DOWNGRADE_SENTINEL_TLS11 = "444f574e47524400"  # "DOWNGRD\x00"

