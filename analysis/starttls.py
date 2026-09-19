import os
import sys
_pkg_dir = os.path.dirname(os.path.abspath(__file__))
if _pkg_dir not in sys.path:
    sys.path.insert(0, _pkg_dir)
import subprocess

try:
    from .tls_session import extract_tls_info
except ImportError:
    from tls_session import extract_tls_info


def detect_protocol(pcap_path):
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
        "-r", pcap_path,
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


def detect_starttls(pcap_path, tls_sessions=None):
    """
    STREAM-LEVEL STARTTLS STATE MACHINE (RFC 3207, RFC 2595, RFC 3501):
    ===================================================================
    Tracks protocol encryption transitions per TCP stream using directional
    message attribution between client and server.

    RFC REFERENCES & DIRECTIONAL SEMANTICS (THE "WHY"):
      • SMTP (RFC 3207 §4):
          Server -> Client: 250-STARTTLS (capability advertisement)
          Client -> Server: STARTTLS (command)
          Server -> Client: 220 Ready to start TLS (acceptance response)
          [TLS Handshake Begins]
          Note: Server may return error codes (454, 501) rejecting the upgrade.
      • POP3 (RFC 2595 §4):
          Server -> Client: +OK ... STLS ... (capability advertisement in CAPA)
          Client -> Server: STLS (command)
          Server -> Client: +OK Begin TLS negotiation (acceptance response)
          [TLS Handshake Begins]
          CRITICAL DISAMBIGUATION: The token 'STLS' appears in BOTH server
          advertisements and the client command. Without directional packet
          attribution (srcport/dstport), a server's STLS capability line is
          ambiguous with the client's command. Directional classification resolves
          this completely.
      • IMAP (RFC 3501 §6.2.1):
          Server -> Client: * CAPABILITY ... STARTTLS ... (capability advertisement)
          Client -> Server: [tag] STARTTLS (tagged command)
          Server -> Client: [tag] OK Begin TLS negotiation (acceptance response)
          [TLS Handshake Begins]

    Returns: Dict mapping stream_id (int) -> STARTTLS state dictionary
    """
    # Well-known mail server listener ports across SMTP, IMAP, and POP3:
    MAIL_SERVER_PORTS = {25, 465, 587, 2525, 143, 993, 110, 995}

    # Extract tcp.stream, ports, and payload bytes
    command = [
        "tshark",
        "-r", pcap_path,
        "-Y", "tcp.payload",
        "-T", "fields",
        "-e", "tcp.stream",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "tcp.payload"
    ]

    result = subprocess.run(command, capture_output=True, text=True)
    if tls_sessions is None:
        tls_sessions = extract_tls_info(pcap_path)

    # streams_packets: {stream_id: [(src_port, dst_port, text), ...]}
    streams_packets = {}
    if result.stdout.strip():
        for line in result.stdout.strip().split('\n'):
            parts = line.split('\t')
            if len(parts) < 4:
                continue
            stream_str, src_str, dst_str, payload_hex = parts[0], parts[1], parts[2], parts[3]
            if not stream_str.isdigit():
                continue
            sid = int(stream_str)
            src_port = int(src_str) if src_str.isdigit() else 0
            dst_port = int(dst_str) if dst_str.isdigit() else 0

            if sid not in streams_packets:
                streams_packets[sid] = []

            if payload_hex.strip():
                try:
                    text = bytes.fromhex(payload_hex.strip()).decode('latin1', errors='ignore')
                    streams_packets[sid].append((src_port, dst_port, text))
                except Exception:
                    pass

    # Include any TLS streams without observed cleartext TCP payloads (e.g. direct Implicit TLS)
    all_stream_ids = sorted(set(list(streams_packets.keys()) + list(tls_sessions.keys())))
    results = {}

    for sid in all_stream_ids:
        packets = streams_packets.get(sid, [])

        # ── 1. IDENTIFY SERVER PORT FOR THIS STREAM ─────────────────────────
        # Primary heuristic: check well-known mail ports on endpoints
        server_port = None
        for sp, dp, _ in packets:
            if sp in MAIL_SERVER_PORTS:
                server_port = sp
                break
            elif dp in MAIL_SERVER_PORTS:
                server_port = dp
                break

        # Fallback heuristic for non-standard ports:
        # In SMTP, POP3, and IMAP, the server transmits the greeting banner first.
        # The endpoint transmitting the initial '220', '+OK', or '* OK' is the server.
        if server_port is None and packets:
            for sp, dp, text in packets:
                text_strip = text.strip()
                if (text_strip.startswith("220") or 
                    text_strip.startswith("+OK") or 
                    text_strip.startswith("* OK") or 
                    text_strip.startswith("* PREAUTH")):
                    server_port = sp
                    break

        # Ultimate fallback: assume destination of initial packet is server
        if server_port is None and packets:
            server_port = packets[0][1]

        starttls_offered = False
        starttls_requested = False
        starttls_accepted = False
        plaintext_auth_attempted = False

        # ── 2. PROCESS PACKETS IN CHRONOLOGICAL ORDER ───────────────────────
        for sp, dp, text in packets:
            is_from_server = (server_port is not None and sp == server_port)
            is_from_client = (server_port is not None and dp == server_port) or (not is_from_server)

            # Split packet into individual protocol command/response lines
            lines = text.replace('\r\n', '\n').split('\n')
            for raw_line in lines:
                cleaned_line = raw_line.strip()
                if not cleaned_line:
                    continue
                line_upper = cleaned_line.upper()

                # ── SERVER-TO-CLIENT ATTRIBUTION ─────────────────────────────
                if is_from_server:
                    # A. Server Capability Advertisement (RFC 3207, RFC 2595, RFC 3501):
                    # - SMTP (RFC 3207): 250-STARTTLS or 250 STARTTLS
                    # - POP3 (RFC 2595): STLS advertised in CAPA response
                    # - IMAP (RFC 3501): * CAPABILITY ... STARTTLS ...
                    if cleaned_line.startswith("250") and "STARTTLS" in line_upper:
                        starttls_offered = True
                    elif cleaned_line.startswith("+OK") and "STLS" in line_upper:
                        starttls_offered = True
                    elif line_upper == "STLS":
                        # POP3 multi-line CAPA capability listing from server
                        starttls_offered = True
                    elif "CAPABILITY" in line_upper and "STARTTLS" in line_upper:
                        starttls_offered = True
                    elif "STARTTLS" in line_upper and (cleaned_line.startswith("250") or cleaned_line.startswith("*")):
                        starttls_offered = True

                    # B. Server Response to STARTTLS Command (RFC 3207 §4.2, RFC 2595 §4):
                    # Evaluated ONLY if the client previously issued the upgrade command.
                    # - SMTP: 220 2.0.0 Ready to start TLS (rejections: 454, 501)
                    # - POP3: +OK Begin TLS negotiation (rejection: -ERR)
                    # - IMAP: [tag] OK Begin TLS negotiation (rejections: NO, BAD)
                    if starttls_requested and not starttls_accepted:
                        if cleaned_line.startswith("220"):
                            starttls_accepted = True
                        elif cleaned_line.startswith("+OK"):
                            starttls_accepted = True
                        elif " OK " in line_upper or line_upper.startswith("OK "):
                            starttls_accepted = True

                # ── CLIENT-TO-SERVER ATTRIBUTION ─────────────────────────────
                elif is_from_client:
                    # A. Client Upgrade Command:
                    # - SMTP (RFC 3207 §4): STARTTLS
                    # - POP3 (RFC 2595 §4): STLS
                    # - IMAP (RFC 3501 §6.2.1): [tag] STARTTLS
                    if line_upper in ("STARTTLS", "STLS"):
                        starttls_requested = True
                    elif line_upper.endswith(" STARTTLS") or " STARTTLS " in line_upper:
                        starttls_requested = True

                    # B. Plaintext Authentication in Unencrypted Traffic:
                    # - RFC 4954 (SMTP AUTH): AUTH PLAIN, AUTH LOGIN
                    # - RFC 1939 (POP3): USER, PASS
                    # - RFC 3501 (IMAP): LOGIN
                    if (line_upper.startswith("AUTH ") or 
                        line_upper.startswith("USER ") or 
                        line_upper.startswith("PASS ") or 
                        " LOGIN " in line_upper or
                        line_upper.startswith("LOGIN ")):
                        plaintext_auth_attempted = True

        tls_active = sid in tls_sessions

        # ── 3. FIVE-STATE PROTOCOL LIFECYCLE EVALUATION ─────────────────────
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
