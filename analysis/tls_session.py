"""
SECUREMAILSCOPE TLS FORENSIC TELEMETRY ENGINE:
  • PASSIVE TLS METADATA EXTRACTION
  • HANDSHAKE METADATA RECONSTRUCTION (RFC 5246, RFC 8446)
  • FORENSIC NEGOTIATION ANALYSIS

===============================================================================
ARCHITECTURAL OVERVIEW & DESIGN PRINCIPLES
===============================================================================
This module implements passive, non-intrusive wire-level reconstruction of
Transport Layer Security (TLS) handshakes from raw packet captures (PCAP).
It operates strictly on wire metadata without requiring session decryption keys,
keylog files, or private keys.

RFC STANDARDS IMPLEMENTED:
  • RFC 5246: The Transport Layer Security (TLS) Protocol Version 1.2
  • RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
  • RFC 8422: Elliptic Curve Cryptography (ECC) Cipher Suites for TLS 1.2
  • RFC 7919: Negotiated Finite-Field Diffie-Hellman Ephemeral Parameters for TLS
  • RFC 6066: Transport Layer Security (TLS) Extensions: Extension Definitions (SNI)
  • RFC 7301: Transport Layer Security (TLS) Application-Layer Protocol Negotiation (ALPN)
  • RFC 7748: Elliptic Curves for Security (Curve25519, Curve448)

PASSIVE WIRE INSPECTION CONSTRAINTS & RFC 8446 RECORD ENCRYPTION (THE "WHY"):
  1. Handshake Encryption Boundary:
     In TLS 1.2 (RFC 5246), handshake messages (ServerHello, Certificate, ServerKeyExchange,
     CertificateRequest, ServerHelloDone, ClientKeyExchange) are transmitted in plaintext,
     and only Finished messages are encrypted under negotiated session keys.
     In TLS 1.3 (RFC 8446 §2), all handshake messages following the ServerHello
     (EncryptedExtensions, Certificate, CertificateVerify, Finished) are immediately encrypted
     under the server_handshake_traffic_secret.

  2. Outer Record Content Type 23 vs Inner Plaintext Content Type:
     In TLS 1.2 (RFC 5246 §6.2.1), record content type 23 strictly designates Application Data.
     In TLS 1.3 (RFC 8446 §5.1-§5.2), all encrypted records (TLSCiphertext) mandate an outer
     legacy_record_type of 23 (application_data) for compatibility with legacy middleboxes
     that would otherwise drop unknown record types. The true inner content type
     (Handshake=22, Alert=21, Application Data=23) is encrypted inside the payload
     (TLSInnerPlaintext.type).
     
     CONSEQUENCE FOR PASSIVE ANALYSIS:
       A passive PCAP analyzer observing outer record type 23 in TLS 1.3 CANNOT determine
       whether that record contains encrypted handshake messages (Finished, NewSessionTicket)
       or true post-handshake application data without decryption keys.
       Therefore:
         - TLS 1.2: record type 23 -> application_data_observed = True
         - TLS 1.3: outer record type 23 -> application_data_observed = "NOT_DETERMINABLE"

  3. Non-Goals (Scope Boundaries):
     This module deliberately does NOT implement HKDF key derivation, TLS 1.3 traffic secret
     recovery, or payload decryption. Forensic passive capture analysis must be defensible
     purely on observable wire evidence. Decryption is out of scope entirely — including
     for testbed dataset generation, since training data must match production's key-blind visibility.
"""

import os
import sys
import subprocess

_pkg_dir = os.path.dirname(os.path.abspath(__file__))
if _pkg_dir not in sys.path:
    sys.path.insert(0, _pkg_dir)

try:
    from .constants import (
        TLS_VERSION_MAP, TLS13_GROUP_MAP, TLS13_PSK_MODE_MAP,
        HANDSHAKE_TYPE_MAP, RECORD_CONTENT_TYPE_MAP, TLS_ALERT_LEVEL_MAP, TLS_ALERT_DESC_MAP,
        SIG_HASH_ALG_MAP, RFC8446_HRR_RANDOM, RFC8446_DOWNGRADE_SENTINEL_TLS12, RFC8446_DOWNGRADE_SENTINEL_TLS11
    )
    from .ciphers import get_cipher_info
except (ImportError, ValueError):
    from constants import (
        TLS_VERSION_MAP, TLS13_GROUP_MAP, TLS13_PSK_MODE_MAP,
        HANDSHAKE_TYPE_MAP, RECORD_CONTENT_TYPE_MAP, TLS_ALERT_LEVEL_MAP, TLS_ALERT_DESC_MAP,
        SIG_HASH_ALG_MAP, RFC8446_HRR_RANDOM, RFC8446_DOWNGRADE_SENTINEL_TLS12, RFC8446_DOWNGRADE_SENTINEL_TLS11
    )
    from ciphers import get_cipher_info


def parse_named_group(group_val):
    """
    Normalizes decimal and hexadecimal NamedGroup identifiers to canonical IANA names.

    RFC REFERENCES:
      • RFC 8422 §5.1.1: Supported Elliptic Curves Extension (NamedCurve)
      • RFC 7919 §3: Finite Field Diffie-Hellman Ephemeral Parameters (FFDHE)
      • RFC 8446 §4.2.7: Supported Groups (NamedGroup)
      • draft-ietf-tls-hybrid-design: Post-Quantum Hybrid Key Exchange (X25519Kyber768)

    WHY THIS NORMALIZATION IS NECESSARY:
      Wireshark/tshark fields format NamedGroup values inconsistently across dissecting layers:
        - `tls.handshake.extensions_supported_group` emits decimal strings (e.g., '29', '4588').
        - `tls.handshake.server_named_curve` emits 2-byte hexadecimal strings (e.g., '0x001d').
      This function harmonizes both hexadecimal and decimal representations into standard
      canonical strings (e.g., 'x25519', 'secp256r1', 'x25519_kyber768_draft00') using
      the authoritative TLS13_GROUP_MAP table in constants.py.
    """
    if not group_val:
        return None
    val = group_val.strip().lower()
    if val.startswith("0x"):
        try:
            dec_str = str(int(val, 16))
            return TLS13_GROUP_MAP.get(dec_str, f"unknown_group_{val}")
        except ValueError:
            return val
    elif val.isdigit():
        return TLS13_GROUP_MAP.get(val, f"unknown_group_{val}")
    return val


import struct

def parse_client_hello_signature_schemes(raw_hex):
    """
    Direct wire-level parser for ClientHello signature algorithm extensions.
    ========================================================================
    RFC REFERENCES:
      • RFC 5246 §7.4.1.4.1: Signature Algorithms extension (Type 13)
      • RFC 8446 §4.2.3: Signature Algorithms (Type 13) and Signature Algorithms Cert (Type 50)

    WHY DIRECT EXTENSION PARSING IS NECESSARY (THE "WHY"):
      Wireshark/tshark reuses the single field `tls.handshake.sig_hash_alg` across both
      extension 13 (signature_algorithms) and extension 50 (signature_algorithms_cert).
      It does not expose an extension-scoped field for extension 50. When both extensions
      are present in a ClientHello, `tls.handshake.sig_hash_alg` emits a blended list that
      conflates handshake signature schemes with certificate signature schemes.
      
      By parsing the raw ClientHello extension block directly from the wire bytes:
        - Extension 13 (signature_algorithms) -> list of schemes for handshake/CertificateVerify
        - Extension 50 (signature_algorithms_cert) -> list of schemes strictly for Certificate messages
      This guarantees RFC 8446 §4.2.3 compliant separation between the two lists.

    WIRE STRUCTURE (RFC 8446 §4.2.3):
      ExtensionType: uint16 (13 or 50)
      ExtensionLength: uint16
      SignatureSchemeList:
        uint16 list_length
        SignatureScheme supported_signature_algorithms<2..2^16-2> (each uint16)

    Returns:
      Tuple of (sig_algs_hex_list, sig_algs_cert_hex_list)
    """
    if not raw_hex or not raw_hex.strip():
        return [], []
    try:
        data = bytes.fromhex(raw_hex.strip())
    except ValueError:
        return [], []

    offset = 0
    while offset < len(data) - 5:
        # Scan for TLS record layer Handshake ContentType (0x16)
        if data[offset] == 0x16:
            rec_len = struct.unpack('!H', data[offset+3:offset+5])[0]
            hs_start = offset + 5
            # Verify Handshake Type is ClientHello (0x01)
            if hs_start < len(data) and data[hs_start] == 0x01:
                if hs_start + 4 > len(data):
                    break
                p = hs_start + 4
                # legacy_version (2 bytes) + random (32 bytes)
                p += 2 + 32
                if p >= len(data):
                    break
                # legacy_session_id (1 byte length + variable)
                sid_len = data[p]
                p += 1 + sid_len
                if p + 2 > len(data):
                    break
                # cipher_suites (2 bytes length + variable)
                cs_len = struct.unpack('!H', data[p:p+2])[0]
                p += 2 + cs_len
                if p + 1 > len(data):
                    break
                # legacy_compression_methods (1 byte length + variable)
                comp_len = data[p]
                p += 1 + comp_len
                if p + 2 > len(data):
                    break
                # extensions (2 bytes length + variable)
                exts_total_len = struct.unpack('!H', data[p:p+2])[0]
                p += 2
                exts_end = min(p + exts_total_len, len(data))

                sig_algs = []
                sig_algs_cert = []
                while p + 4 <= exts_end:
                    etype, elen = struct.unpack('!HH', data[p:p+4])
                    p += 4
                    edata = data[p:min(p+elen, exts_end)]
                    p += elen
                    if etype == 13:  # signature_algorithms (RFC 8446 §4.2.3)
                        if len(edata) >= 2:
                            list_len = struct.unpack('!H', edata[:2])[0]
                            for i in range(2, min(2 + list_len, len(edata) - 1), 2):
                                scheme = f"0x{struct.unpack('!H', edata[i:i+2])[0]:04x}"
                                sig_algs.append(scheme)
                    elif etype == 50:  # signature_algorithms_cert (RFC 8446 §4.2.3)
                        if len(edata) >= 2:
                            list_len = struct.unpack('!H', edata[:2])[0]
                            for i in range(2, min(2 + list_len, len(edata) - 1), 2):
                                scheme = f"0x{struct.unpack('!H', edata[i:i+2])[0]:04x}"
                                sig_algs_cert.append(scheme)
                return sig_algs, sig_algs_cert
            offset += 5 + rec_len
        else:
            offset += 1
    return [], []


def reconstruct_handshake(pcap_path):
    """
    RFC-COMPLIANT TLS HANDSHAKE RECONSTRUCTION ENGINE (RFC 5246, RFC 8446)
    =======================================================================

    PURPOSE:
      Reconstructs the full stateful TLS handshake across every TCP stream in a PCAP capture,
      correlating client capabilities, server negotiation, cryptographic parameters,
      packet flight sequencing, and downgrade sentinel forensics.

    RECONSTRUCTION GOALS & RFC COMPLIANCE:
      1. ClientHello Capabilities (RFC 5246 §7.4.1.2, RFC 8446 §4.1.2):
         - Extract all offered protocol versions, respecting RFC 8446 §4.2.1 supported_versions.
         - Enumerate offered cipher suites in client-advertised preference order.
         - Capture offered Diffie-Hellman groups (RFC 8446 §4.2.7) and preemptive key shares (RFC 8446 §4.2.8).
         - Extract signature algorithms (RFC 8446 §4.2.3) and advertised PSK key exchange modes (RFC 8446 §4.2.9).
         - Detect Server Name Indication (SNI, RFC 6066 §3) and ALPN (RFC 7301).

      2. ServerHello Negotiation & Key Exchange (RFC 5246 §7.4.1.3, RFC 8446 §4.1.3):
         - Bypass TLS 1.3 middlebox compatibility version ("0x0303" lie) via supported_versions.
         - Derive selected Key Exchange Mode (ECDHE vs PSK_ONLY vs PSK_DHE) exclusively from
           ServerHello wire fields (selected_identity and key_share).
         - Detect HelloRetryRequest (RFC 8446 §4.1.4) via SHA-256("HelloRetryRequest") random constant.
         - Audit RFC 8446 §4.1.3 downgrade protection sentinels (DOWNGRD\\x01 and DOWNGRD\\x00).

      3. TLS 1.2 Ephemeral Key Exchange Parameters (RFC 5246 §7.4.3, RFC 8422 §3):
         - Strictly isolate RFC 8422 ECDHE named curve from RFC 5246 DHE prime bit length (p_len * 8).
         - Capture wire signature hash algorithm used to authenticate the ephemeral key exchange.

      4. Handshake Message Flight & Reassembly (RFC 5246 §6.2.1, RFC 8446 §5.1):
         - Track chronological message types, frame numbers, record content types, and reassembly pointers.
         - Capture TLS alerts (RFC 5246 §7.2, RFC 8446 §6) per frame.

      5. Cryptographic Forensic Analysis & Lifecycle States:
         - Defensible 5-state lifecycle model: COMPLETED_OBSERVED, COMPLETED_INFERRED,
           HANDSHAKE_STATUS_UNRESOLVED, ABORTED, INCOMPLETE.
         - Strict handling of TLS 1.3 outer record 23: treated as NOT_DETERMINABLE without keys.
         - 0-RTT early data guard: prevents premature completion inference on early data records.
         - Non-accusatory downgrade classification: distinguishes benign legacy client negotiation
           with sentinel from true downgrade protection signals.

    EXECUTION PIPELINE:
      Pass 1: Flight sequencing, record content types, reassembly tracking, and alerts.
      Pass 2: ClientHello capability extraction (versions, ciphers, groups, shares, sig_algs, PSK modes).
      Pass 3: ServerHello negotiation extraction (versions, ciphers, HRR, downgrade sentinels, KEX modes).
      Pass 4: TLS 1.2 ServerKeyExchange cryptographic parameter extraction (ECDHE vs DHE).
      Pass 5: Multi-stream correlation, forensic downgrade analysis, and lifecycle state determination.

    Returns:
      Dict mapping stream_id (int) -> reconstructed handshake telemetry dictionary.
    """
    # ── PASS 1: Flight Sequencing, Record Content Types, Alerts & Reassembly ─────
    # WHY THIS FILTER:
    #   We filter on `tls.record.content_type in {20, 21, 22, 23}` to capture every valid
    #   TLS record layer header (RFC 5246 §6.2.1, RFC 8446 §5.1):
    #     20: ChangeCipherSpec (RFC 5246 §7.1, RFC 8446 Appendix D middlebox compatibility)
    #     21: Alert (RFC 5246 §7.2, RFC 8446 §6)
    #     22: Handshake (RFC 5246 §7.4, RFC 8446 §4)
    #     23: Application Data / TLSCiphertext (RFC 5246 §6.2.1, RFC 8446 §5.2)
    #   We do NOT use `tls.alert` because encrypted alerts or alerts wrapped in fragmented
    #   records are suppressed by tshark unless filtered at the record layer.
    #
    # WHY REASSEMBLY TRACKING:
    #   X.509 Certificate chains (RFC 5246 §7.4.6) frequently exceed the TCP MSS (~1460 bytes)
    #   and are fragmented across multiple TCP packets. Tracking `tls.handshake.reassembled_in`
    #   ensures multi-packet handshake flights are accurately correlated.
    cmd_flight = [
        "tshark", "-r", pcap_path,
        "-Y", "tls.record.content_type in {20, 21, 22, 23}",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "tcp.stream",
        "-e", "tls.handshake.type",
        "-e", "tls.record.content_type",
        "-e", "tls.alert_message.level",
        "-e", "tls.alert_message.desc",
        "-e", "tls.handshake.reassembled_in",
    ]
    res_flight = subprocess.run(cmd_flight, capture_output=True, text=True)
    flights = {}
    if res_flight.stdout.strip():
        for line in res_flight.stdout.strip().splitlines():
            parts = line.split('\t')
            while len(parts) < 7:
                parts.append("")
            f_num, s_id, hs_type_str, rec_ct_str, al_lvl_str, al_dsc_str, reasm_str = parts
            if not s_id.isdigit():
                continue
            sid = int(s_id)
            if sid not in flights:
                flights[sid] = {
                    "messages": [],
                    "finished_observed": False,
                    "outer_record_23_observed": False,
                    "first_record_23_frame": None,
                    "alerts": [],
                    "server_hello_frame": None,
                }
            frame = int(f_num) if f_num.isdigit() else None
            reasm = int(reasm_str) if reasm_str.isdigit() else None

            # Handshake messages (type 22)
            if hs_type_str.strip():
                for t in hs_type_str.split(','):
                    t = t.strip()
                    if t.isdigit():
                        t_id = int(t)
                        msg_name = HANDSHAKE_TYPE_MAP.get(t, f"UnknownHandshake_{t}")
                        flights[sid]["messages"].append({
                            "frame": frame,
                            "type_id": t_id,
                            "message": msg_name,
                            "reassembled_in": reasm
                        })
                        if t_id == 20: # Finished
                            flights[sid]["finished_observed"] = True
                        if t_id == 2 and flights[sid]["server_hello_frame"] is None:
                            flights[sid]["server_hello_frame"] = frame

            # Record Content Types (RFC 5246, RFC 8446 §5.1)
            if rec_ct_str.strip():
                for ct in rec_ct_str.split(','):
                    ct = ct.strip()
                    if ct == "23":
                        # Record type 23:
                        # In TLS 1.2: definite Application Data.
                        # In TLS 1.3: TLSCiphertext outer header for all encrypted records.
                        flights[sid]["outer_record_23_observed"] = True
                        if flights[sid]["first_record_23_frame"] is None:
                            flights[sid]["first_record_23_frame"] = frame

            # Alerts (record 21 or alert fields)
            if al_lvl_str.strip() or al_dsc_str.strip() or "21" in rec_ct_str.split(','):
                lvl_name = TLS_ALERT_LEVEL_MAP.get(al_lvl_str.strip(), "UNKNOWN")
                dsc_name = TLS_ALERT_DESC_MAP.get(al_dsc_str.strip(), f"AlertDesc_{al_dsc_str.strip()}" if al_dsc_str.strip() else "EncryptedAlert")
                flights[sid]["alerts"].append({
                    "frame": frame,
                    "level": lvl_name,
                    "description": dsc_name,
                    "raw_desc": al_dsc_str.strip() or None
                })

    # ── PASS 2: ClientHello Capability Extraction ────────────────────────────────
    # WHY WE EXTRACT CLIENT CAPABILITIES:
    #   Accurate cryptographic downgrade detection requires comparing what the client
    #   offered against what the server negotiated.
    #   RFC 5246 §7.4.1.2 & RFC 8446 §4.1.2 define the client advertisement:
    #     - supported_versions (RFC 8446 §4.2.1): Supersedes client_version. RFC 8446 mandates
    #       client_version be fixed to 0x0303 (TLS 1.2) for middlebox compatibility; the true
    #       list of supported versions resides exclusively in this extension.
    #     - cipher_suites: Client lists ciphers in strict descending order of preference.
    #     - supported_groups (RFC 8446 §4.2.7): Named curves and FFDHE groups the client supports.
    #     - key_share (RFC 8446 §4.2.8): Preemptive ephemeral public keys sent by the client.
    #     - signature_algorithms (RFC 8446 §4.2.3): Hash/signature algorithms client accepts.
    #     - psk_key_exchange_modes (RFC 8446 §4.2.9): Modes client allows (psk_ke vs psk_dhe_ke).
    #     - server_name (RFC 6066 §3): SNI hostname intended for certificate validation.
    #     - early_data (RFC 8446 §4.2.10): Extension 42 indicating 0-RTT intent.
    cmd_ch = [
        "tshark", "-r", pcap_path,
        "-Y", "tls.handshake.type == 1",
        "-T", "fields",
        "-e", "tcp.stream",
        "-e", "tls.handshake.version",
        "-e", "tls.handshake.extensions.supported_version",
        "-e", "tls.handshake.ciphersuite",
        "-e", "tls.handshake.extensions_supported_group",
        "-e", "tls.handshake.extensions_key_share_group",
        "-e", "tls.handshake.sig_hash_alg",
        "-e", "tls.extension.psk_ke_mode",
        "-e", "tls.handshake.extensions_server_name",
        "-e", "tls.handshake.extensions_alpn_str",
        "-e", "tls.handshake.extension.type",
        "-e", "tcp.payload",
    ]
    res_ch = subprocess.run(cmd_ch, capture_output=True, text=True)
    client_hellos = {}
    if res_ch.stdout.strip():
        for line in res_ch.stdout.strip().splitlines():
            parts = line.split('\t')
            while len(parts) < 12:
                parts.append("")
            s_id, hs_ver, supp_vers, ciphers_str, groups_str, ks_str, sig_algs_str, psk_mode_str, sni_str, alpn_str, ext_types_str, tcp_payload = parts
            if not s_id.isdigit():
                continue
            sid = int(s_id)

            # Offered versions:
            # RFC 8446 §4.2.1: If supported_versions extension is present, its list of versions
            # takes precedence over the legacy ClientHello.client_version field.
            offered_versions = []
            if supp_vers.strip():
                for v in supp_vers.split(','):
                    v_clean = v.strip().lower()
                    if v_clean:
                        offered_versions.append(TLS_VERSION_MAP.get(v_clean, f"Unknown ({v_clean})"))
            elif hs_ver.strip():
                v_clean = hs_ver.strip().lower()
                offered_versions.append(TLS_VERSION_MAP.get(v_clean, f"Unknown ({v_clean})"))

            # Offered cipher suites in client preference order:
            # RFC 5246 §7.4.1.2: Client presents cipher suites in order of preference (favorite choice first).
            offered_ciphers = []
            if ciphers_str.strip():
                for cs in ciphers_str.split(','):
                    cs_clean = cs.strip().lower()
                    if cs_clean:
                        ci = get_cipher_info(cs_clean)
                        offered_ciphers.append({
                            "hex": cs_clean,
                            "name": ci["name"],
                            "strength": ci["strength"],
                            "forward_secrecy": ci["forward_secrecy"]
                        })

            # Supported groups (NamedCurves and FFDHE groups, RFC 8446 §4.2.7):
            # Normalizes decimal/hex group codepoints into standardized curve/group names.
            supported_groups = []
            if groups_str.strip():
                for g in groups_str.split(','):
                    g_clean = g.strip()
                    if g_clean:
                        supported_groups.append(parse_named_group(g_clean))

            # Client preemptive key shares (RFC 8446 §4.2.8):
            # In TLS 1.3, client speculatively generates key shares for groups it predicts the server supports.
            client_key_shares = []
            if ks_str.strip():
                for ks in ks_str.split(','):
                    ks_clean = ks.strip()
                    if ks_clean:
                        client_key_shares.append(parse_named_group(ks_clean))

            # Signature algorithms separation (RFC 8446 §4.2.3, RFC 5246 §7.4.1.4.1):
            # Extension 13: signature_algorithms (handshake and certificate verification)
            # Extension 50: signature_algorithms_cert (explicitly scoped for certificate verification)
            #
            # WHY DIRECT WIRE PARSING IS EMPLOYED:
            #   tshark reuses `tls.handshake.sig_hash_alg` for both extension 13 and extension 50.
            #   We parse the ClientHello extensions directly from the wire payload (`tcp.payload`)
            #   to cleanly separate Extension 13 schemes from Extension 50 schemes.
            raw_ext13, raw_ext50 = parse_client_hello_signature_schemes(tcp_payload)
            
            sig_algs = []
            if raw_ext13:
                for sa in raw_ext13:
                    sig_algs.append(SIG_HASH_ALG_MAP.get(sa.lower(), f"sig_alg_{sa.lower()}"))
            elif sig_algs_str.strip():
                for sa in sig_algs_str.split(','):
                    sa_clean = sa.strip().lower()
                    if sa_clean:
                        sig_algs.append(SIG_HASH_ALG_MAP.get(sa_clean, f"sig_alg_{sa_clean}"))

            sig_algs_cert = []
            if raw_ext50:
                for sac in raw_ext50:
                    sig_algs_cert.append(SIG_HASH_ALG_MAP.get(sac.lower(), f"sig_alg_{sac.lower()}"))

            # PSK key exchange modes advertised by client (RFC 8446 §4.2.9):
            # Note: This reflects what the client is WILLING to do, not what was negotiated.
            #   psk_ke (0): client permits resumption without DH.
            #   psk_dhe_ke (1): client permits resumption with ephemeral DH.
            psk_modes = []
            if psk_mode_str.strip():
                for pm in psk_mode_str.split(','):
                    pm_clean = pm.strip()
                    if pm_clean in TLS13_PSK_MODE_MAP:
                        psk_modes.append(TLS13_PSK_MODE_MAP[pm_clean])

            # Extension type IDs:
            # Detects RFC 8446 §4.2.3 signature_algorithms_cert (50) and early_data (42).
            ext_type_ids = set()
            if ext_types_str.strip():
                for et in ext_types_str.split(','):
                    et = et.strip()
                    if et.isdigit():
                        ext_type_ids.add(int(et))

            sig_algs_cert_present = (50 in ext_type_ids or bool(sig_algs_cert))

            client_hellos[sid] = {
                "offered_versions": offered_versions,
                "offered_ciphers": offered_ciphers,
                "offered_ciphers_count": len(offered_ciphers),
                "supported_groups": supported_groups,
                "offered_key_shares": client_key_shares,
                "signature_algorithms": sig_algs,
                "signature_algorithms_cert": sig_algs_cert,
                "signature_algorithms_cert_present": sig_algs_cert_present,
                "psk_key_exchange_modes": psk_modes,
                "sni": sni_str.strip() or None,
                "alpn": [a.strip() for a in alpn_str.split(',') if a.strip()] if alpn_str.strip() else [],
                "early_data_offered": (42 in ext_type_ids),
            }

    # ── PASS 3: ServerHello Negotiation & Parameter Resolution ───────────────────
    # WHY WE INSPECT SERVERHELLO:
    #   The ServerHello (RFC 5246 §7.4.1.3, RFC 8446 §4.1.3) establishes the connection
    #   parameters selected by the server:
    #     1. Protocol Version:
    #        In TLS 1.3, ServerHello.legacy_version is intentionally set to 0x0303 (TLS 1.2)
    #        to bypass middleboxes that drop packets with unknown version numbers. The true
    #        version is carried exclusively in the supported_versions extension (0x0304).
    #     2. HelloRetryRequest Detection (RFC 8446 §4.1.4):
    #        HRR is NOT a distinct handshake message type on the wire — it uses message type 2
    #        (ServerHello). It is identified uniquely by the special 32-byte constant:
    #        SHA-256("HelloRetryRequest") = cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c.
    #     3. RFC 8446 §4.1.3 Downgrade Sentinel Forensics:
    #        When a TLS 1.3-capable server negotiates TLS 1.2 or below, it MUST set the last
    #        8 bytes of ServerHello.random to a sentinel value:
    #          - TLS 1.2 negotiated: 44 4f 57 4e 47 52 44 01 ("DOWNGRD\x01")
    #          - TLS 1.1 or lower negotiated: 44 4f 57 4e 47 52 44 00 ("DOWNGRD\x00")
    #     4. TLS 1.3 Key Exchange Mode Selection (RFC 8446 §4.2.8, §4.2.9, §C.4):
    #        The actual mode is derived strictly from ServerHello:
    #          - key_share present, PSK absent -> ECDHE (Forward Secrecy = True)
    #          - PSK selected (pre_shared_key selected_identity), key_share absent -> PSK_ONLY (Forward Secrecy = False)
    #          - PSK selected + key_share present -> PSK_DHE (Forward Secrecy = True)
    cmd_sh = [
        "tshark", "-r", pcap_path,
        "-Y", "tls.handshake.type == 2",
        "-T", "fields",
        "-e", "tcp.stream",
        "-e", "tls.handshake.version",
        "-e", "tls.handshake.extensions.supported_version",
        "-e", "tls.handshake.ciphersuite",
        "-e", "tls.handshake.extensions_key_share_group",
        "-e", "tls.handshake.extensions_key_share_selected_group",
        "-e", "tls.handshake.extensions.psk.identity.selected",
        "-e", "tls.handshake.random",
    ]
    res_sh = subprocess.run(cmd_sh, capture_output=True, text=True)
    server_hellos = {}
    if res_sh.stdout.strip():
        for line in res_sh.stdout.strip().splitlines():
            parts = line.split('\t')
            while len(parts) < 8:
                parts.append("")
            s_id, hs_ver, supp_ver, ciphersuite, ks_grp, ks_sel_grp, psk_sel, random_hex = parts
            if not s_id.isdigit():
                continue
            sid = int(s_id)
            effective_ks = ks_grp.strip() or ks_sel_grp.strip()
            psk_sel_clean = psk_sel.strip()

            # Handle TLS 1.3 middlebox lie: supported_versions takes precedence
            supp_ver_clean = supp_ver.split(',')[0].strip().lower() if supp_ver.strip() else ""
            true_ver_hex = supp_ver_clean if supp_ver_clean else hs_ver.strip().lower()
            is_tls13 = (true_ver_hex == "0x0304")

            cs_clean = ciphersuite.strip().lower()
            ci = get_cipher_info(cs_clean)

            # Derive TLS 1.3 Key Exchange mode from ServerHello selections:
            # - ECDHE: Server selected key_share group; no PSK was used.
            # - PSK_ONLY: Server accepted PSK (selected_identity) without ephemeral DH.
            # - PSK_DHE: Server accepted PSK and selected ephemeral key_share group.
            tls13_kex_group = parse_named_group(effective_ks) if (is_tls13 and effective_ks) else None
            tls13_psk_sel = bool(psk_sel_clean) if is_tls13 else None
            tls13_kex_mode = None
            if is_tls13:
                if effective_ks and not psk_sel_clean:
                    tls13_kex_mode = "ECDHE"
                elif psk_sel_clean and not effective_ks:
                    tls13_kex_mode = "PSK_ONLY"
                elif psk_sel_clean and effective_ks:
                    tls13_kex_mode = "PSK_DHE"

            # Perfect Forward Secrecy (PFS) correction for PSK_ONLY:
            # RFC 8446 §C.4: If PSK key establishment is used without DH (psk_ke / PSK_ONLY),
            # past sessions can be decrypted if the PSK is ever compromised.
            forward_secrecy = ci["forward_secrecy"]
            if tls13_kex_mode == "PSK_ONLY":
                forward_secrecy = False

            # HelloRetryRequest detection via SHA-256("HelloRetryRequest") in ServerHello.random
            clean_rnd = random_hex.strip().lower().replace(":", "")
            is_hrr = (clean_rnd == RFC8446_HRR_RANDOM.lower())
            
            # If HelloRetryRequest was sent, update message label in flight
            if is_hrr and sid in flights:
                for m in flights[sid]["messages"]:
                    if m["type_id"] == 2:
                        m["message"] = "HelloRetryRequest"

            # RFC 8446 §4.1.3 Downgrade Sentinel Forensics (last 8 bytes of ServerHello.random)
            downgrade_info = {
                "sentinel_detected": False,
                "sentinel_type": None,
                "sentinel_bytes": None,
                "server_supports_tls13": False
            }
            if len(clean_rnd) >= 16:
                last_8_bytes = clean_rnd[-16:]
                if last_8_bytes == RFC8446_DOWNGRADE_SENTINEL_TLS12:
                    downgrade_info = {
                        "sentinel_detected": True,
                        "sentinel_type": "DOWNGRD_TLS12 (RFC 8446 §4.1.3)",
                        "sentinel_bytes": last_8_bytes,
                        "server_supports_tls13": True
                    }
                elif last_8_bytes == RFC8446_DOWNGRADE_SENTINEL_TLS11:
                    downgrade_info = {
                        "sentinel_detected": True,
                        "sentinel_type": "DOWNGRD_TLS11_OR_BELOW (RFC 8446 §4.1.3)",
                        "sentinel_bytes": last_8_bytes,
                        "server_supports_tls13": True
                    }

            server_hellos[sid] = {
                "raw_version": true_ver_hex,
                "selected_tls_version": TLS_VERSION_MAP.get(true_ver_hex, f"Unknown ({true_ver_hex})"),
                "selected_cipher": {
                    "hex": cs_clean,
                    "name": ci["name"],
                    "strength": ci["strength"],
                    "forward_secrecy": forward_secrecy,
                    "kex_mechanism": ci["kex"]
                },
                "tls13_key_exchange_group": tls13_kex_group,
                "tls13_psk_selected": tls13_psk_sel,
                "tls13_key_exchange_mode": tls13_kex_mode,
                "is_hello_retry_request": is_hrr,
                "tls12_server_key_exchange": None,
                "downgrade_sentinel": downgrade_info
            }

    # ── PASS 4: TLS 1.2 ServerKeyExchange (RFC 5246, RFC 8422) ──────────────────
    # WHY ECDHE AND DHE MUST BE STRICTLY SEPARATED:
    #   In TLS 1.2 (RFC 5246 §7.4.3), when an ephemeral key exchange is negotiated
    #   (ECDHE or DHE), the server transmits ServerKeyExchange (Handshake Type 12):
    #     - RFC 8422 ECDHE: Uses NamedCurve (`tls.handshake.server_named_curve`).
    #       Finite-field DH prime length (`p_len`) is NOT applicable.
    #     - RFC 5246 DHE: Uses explicit Diffie-Hellman parameters (prime p, generator g).
    #       `tls.handshake.p_len` represents the length of the prime modulus p in bytes.
    #       NamedCurve is NOT applicable.
    #   Mixing curve and prime length in the same object is a severe cryptographic category error.
    #   We also capture `tls.handshake.sig_hash_alg` to verify the digital signature scheme
    #   authenticating the ephemeral key exchange.
    cmd_ske = [
        "tshark", "-r", pcap_path,
        "-Y", "tls.handshake.type == 12",
        "-T", "fields",
        "-e", "tcp.stream",
        "-e", "tls.handshake.server_named_curve",
        "-e", "tls.handshake.p_len",
        "-e", "tls.handshake.sig_hash_alg",
    ]
    res_ske = subprocess.run(cmd_ske, capture_output=True, text=True)
    if res_ske.stdout.strip():
        for line in res_ske.stdout.strip().splitlines():
            parts = line.split('\t')
            while len(parts) < 4:
                parts.append("")
            s_id, curve_str, plen_str, sig_alg_str = parts
            if not s_id.isdigit():
                continue
            sid = int(s_id)
            if sid in server_hellos:
                curve_clean = curve_str.strip().lower()
                plen_clean = plen_str.strip()
                sig_alg_clean = sig_alg_str.strip().lower()

                kex_type = None
                curve_name = None
                dh_prime_bits = None

                # RFC 8422 ECDHE: server_named_curve carries the curve; p_len is N/A
                if curve_clean:
                    kex_type = "ECDHE"
                    curve_name = parse_named_group(curve_clean)
                # RFC 5246 DHE: p_len carries finite-field DH prime byte length; curve is N/A
                elif plen_clean:
                    kex_type = "DHE"
                    try:
                        dh_prime_bits = int(plen_clean) * 8
                    except ValueError:
                        dh_prime_bits = None

                server_hellos[sid]["tls12_server_key_exchange"] = {
                    "kex_type": kex_type,
                    "named_curve": curve_name,
                    "named_curve_hex": curve_clean or None,
                    "dh_prime_length_bits": dh_prime_bits,
                    "wire_signature_algorithm": SIG_HASH_ALG_MAP.get(sig_alg_clean, f"sig_alg_{sig_alg_clean}") if sig_alg_clean else None
                }

    # ── PASS 5: Multi-Stream Correlation, Downgrade Forensics & Lifecycle Analysis ─
    # Correlates flights, ClientHello offers, and ServerHello selections per stream.
    all_stream_ids = sorted(set(list(flights.keys()) + list(client_hellos.keys()) + list(server_hellos.keys())))
    reconstructed = {}

    for sid in all_stream_ids:
        ch = client_hellos.get(sid, {})
        sh = server_hellos.get(sid, {})
        fl = flights.get(sid, {
            "messages": [],
            "finished_observed": False,
            "outer_record_23_observed": False,
            "first_record_23_frame": None,
            "alerts": [],
            "server_hello_frame": None,
        })

        # ── 1. Downgrade Sentinel & Version Forensics (RFC 8446 §4.1.3) ──────────
        # WHY NON-ACCUSATORY LABELS (THE "WHY"):
        #   A passive network trace provides evidence of wire protocol conditions, not
        #   proof of malicious attacker intent. RFC 8446 §4.1.3 specifies that any TLS 1.3
        #   server negotiating TLS 1.2 MUST embed DOWNGRD\x01 in ServerHello.random.
        #   When the client only offered TLS 1.2, the presence of the sentinel simply
        #   indicates that the server supports TLS 1.3, which is normal and benign.
        #   Only when the client offered TLS 1.3 but negotiated TLS 1.2 with the sentinel
        #   present do we flag a downgrade protection signal.
        client_offered_vers = ch.get("offered_versions", [])
        client_max_ver = client_offered_vers[0] if client_offered_vers else None
        negotiated_ver = sh.get("selected_tls_version", None)
        sentinel_info = sh.get("downgrade_sentinel", {})
        sentinel_detected = sentinel_info.get("sentinel_detected", False)

        downgrade_signal_detected = False
        downgrade_classification = "MATCH"
        downgrade_details = "Negotiated version matches or is consistent with connection context."

        if sentinel_detected:
            # Case A: Client offered TLS 1.3, but server negotiated TLS 1.2 with downgrade sentinel
            if "TLS 1.3" in client_offered_vers and negotiated_ver != "TLS 1.3":
                downgrade_signal_detected = True
                downgrade_classification = "RFC8446_DOWNGRADE_PROTECTION_SIGNAL"
                downgrade_details = (
                    "Client offered TLS 1.3, but server negotiated TLS 1.2 with RFC 8446 §4.1.3 "
                    "downgrade protection sentinel (DOWNGRD\\x01). Wire evidence of downgrade protection signal."
                )
            else:
                # Case B: Client maximum offered version was <= TLS 1.2; server simply advertised 1.3 capability
                downgrade_signal_detected = False
                downgrade_classification = "SERVER_SUPPORTS_TLS13_LEGACY_CLIENT"
                downgrade_details = (
                    "Server supports TLS 1.3 and embedded RFC 8446 §4.1.3 downgrade protection sentinel "
                    "(DOWNGRD\\x01), but client offered max TLS 1.2. Normal legacy negotiation; no downgrade signal."
                )
        elif client_max_ver and negotiated_ver and client_max_ver != negotiated_ver:
            downgrade_signal_detected = True
            downgrade_classification = "NEGOTIATED_BELOW_CLIENT_MAX"
            downgrade_details = f"Server selected {negotiated_ver}, which is below client maximum offered version {client_max_ver}."

        # ── 2. Application Data & Lifecycle Evaluation ───────────────────────────
        # RFC 5246 vs RFC 8446 Application Data Distinction (THE "WHY"):
        #   - TLS 1.2: Record content type 23 strictly designates Application Data.
        #   - TLS 1.3: RFC 8446 §5.1 mandates outer record type 23 (application_data)
        #     for all TLSCiphertext records (EncryptedExtensions, Certificate,
        #     CertificateVerify, Finished, NewSessionTicket, Application Data).
        #     In passive PCAP analysis without session keys, outer record type 23
        #     indicates encrypted records; the inner plaintext type cannot be determined.
        #     Therefore, application_data_observed = "NOT_DETERMINABLE" unless decrypted.
        outer_23_seen = fl.get("outer_record_23_observed", False)
        if negotiated_ver == "TLS 1.3":
            if outer_23_seen:
                app_data_observed = "NOT_DETERMINABLE"
            else:
                app_data_observed = False
        else:
            # TLS 1.2 and earlier: record type 23 is genuine application data
            app_data_observed = True if outer_23_seen else False

        # 0-RTT early data awareness (RFC 8446 §4.2.10):
        # If client offered early data, application data records sent BEFORE ServerHello
        # do not prove the handshake succeeded, as the server can reject 0-RTT data.
        early_data_observed = False
        if ch.get("early_data_offered") and fl["first_record_23_frame"] is not None and fl["server_hello_frame"] is not None:
            if fl["first_record_23_frame"] < fl["server_hello_frame"]:
                early_data_observed = True

        # Lifecycle State Determination (THE "WHY"):
        #   1. COMPLETED_OBSERVED: Observed explicit Finished handshake record (type 20).
        #   2. COMPLETED_INFERRED: Observed genuine post-handshake Application Data (TLS 1.2).
        #   3. HANDSHAKE_STATUS_UNRESOLVED: TLS 1.3 outer 23 seen without keys, or 0-RTT ambiguity.
        #   4. ABORTED: Terminated by TLS Alert (record 21) prior to completion.
        #   5. INCOMPLETE: Handshake ended prematurely without Finished, Application Data, or encrypted traffic.
        if fl["finished_observed"]:
            handshake_status = "COMPLETED_OBSERVED"
        elif app_data_observed is True:
            if early_data_observed:
                handshake_status = "HANDSHAKE_STATUS_UNRESOLVED"
            else:
                handshake_status = "COMPLETED_INFERRED"
        elif fl["alerts"]:
            handshake_status = "ABORTED"
        elif app_data_observed == "NOT_DETERMINABLE":
            # Outer record 23 was seen in TLS 1.3, but without keys we cannot verify if
            # handshake reached Finished or if Application Data was exchanged.
            handshake_status = "HANDSHAKE_STATUS_UNRESOLVED"
        else:
            handshake_status = "INCOMPLETE"

        reconstructed[sid] = {
            "stream": sid,
            "client_hello": ch,
            "server_negotiation": sh,
            "flight": {
                "messages": fl["messages"],
                "finished_observed": fl["finished_observed"],
                "application_data_observed": app_data_observed,
                "outer_record_23_observed": outer_23_seen,
                "early_data_observed": early_data_observed,
                "alerts": fl["alerts"],
            },
            "forensic_analysis": {
                "handshake_status": handshake_status,
                "client_max_version": client_max_ver,
                "negotiated_version": negotiated_ver,
                "version_downgrade": {
                    "downgrade_signal_detected": downgrade_signal_detected,
                    "classification": downgrade_classification,
                    "details": downgrade_details
                },
                "cipher_downgrade": {
                    "downgrade_signal_detected": (sh.get("selected_cipher", {}).get("strength") in ("WEAK", "BROKEN")),
                    "details": f"Negotiated cipher suite strength is {sh.get('selected_cipher', {}).get('strength', 'UNKNOWN')}."
                }
            }
        }

    return reconstructed


def extract_tls_info(pcap_path):
    """
    Backward-compatible TLS Session Parameter Extractor.
    ---------------------------------------------------
    PURPOSE & BACKWARD COMPATIBILITY GUARANTEE:
      Delegates to reconstruct_handshake(pcap_path) and projects the negotiated session
      parameters into the flat dictionary structure expected by existing callers, CLI runners,
      and STARTTLS state machine correlation.

    Returns:
      Dict mapping stream_id (int) -> flat TLS parameter dictionary:
        {
          "stream": int,
          "raw_version": str,
          "tls_version": str,
          "raw_cipher_suite": str,
          "cipher_name": str,
          "key_exchange": str,
          "forward_secrecy": bool,
          "cipher_strength": str,
          "tls13_key_exchange_group": str or None,
          "tls13_psk_selected": bool or None,
          "tls13_key_exchange_mode": str or None
        }
    """
    handshakes = reconstruct_handshake(pcap_path)
    sessions = {}

    for sid, h in handshakes.items():
        sh = h.get("server_negotiation", {})
        if not sh:
            continue
        cipher_info = sh.get("selected_cipher", {})
        sessions[sid] = {
            "stream":                   sid,
            "raw_version":              sh.get("raw_version"),
            "tls_version":              sh.get("selected_tls_version"),
            "raw_cipher_suite":         cipher_info.get("hex"),
            "cipher_name":              cipher_info.get("name"),
            "key_exchange":             cipher_info.get("kex_mechanism"),
            "forward_secrecy":          cipher_info.get("forward_secrecy"),
            "cipher_strength":          cipher_info.get("strength"),
            "tls13_key_exchange_group": sh.get("tls13_key_exchange_group"),
            "tls13_psk_selected":       sh.get("tls13_psk_selected"),
            "tls13_key_exchange_mode":  sh.get("tls13_key_exchange_mode"),
        }

    return sessions
