import os
import sys
import re
import subprocess
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple

_pkg_dir = os.path.dirname(os.path.abspath(__file__))
if _pkg_dir not in sys.path:
    sys.path.insert(0, _pkg_dir)

try:
    from .tls_session import extract_tls_info
except ImportError:
    from tls_session import extract_tls_info


# Well-known mail server listener ports across SMTP, IMAP, and POP3 (standard and testbed):
# RFC 5321 (SMTP 25), RFC 8314 (Implicit TLS 465, 993, 995), RFC 6409 (Submission 587),
# RFC 3501 (IMAP 143), RFC 1939 (POP3 110), plus non-standard testbed ports (2525, 2526, 1143, 1110).
MAIL_SERVER_PORTS = {25, 465, 587, 2525, 2526, 143, 993, 1143, 110, 995, 1110}


@dataclass
class StreamFlow:
    """
    Normalized TCP stream representation with directional reconstructed byte streams.

    RFC Standards:
      • RFC 793: Transmission Control Protocol (stream-oriented continuous delivery).
      • RFC 5321 (SMTP), RFC 3501 (IMAP), RFC 1939 (POP3): Line-oriented command/response dialogue.
    """
    stream_id: int
    client: str          # "ip:port"
    server: str          # "ip:port"
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    client_data: bytes   # Reassembled continuous stream sent by client -> server
    server_data: bytes   # Reassembled continuous stream sent by server -> client
    chunks: list         # Chronological list of (sender: "client"|"server", data: bytes)

    # ponytail: dictionary compatibility accessors so callers can use either attr or key
    def __getitem__(self, key):
        return getattr(self, key)

    def get(self, key, default=None):
        return getattr(self, key, default)

    def to_dict(self):
        return asdict(self)


def _parse_endpoint(ep_str: str) -> Tuple[str, int]:
    """Parse IPv4 or IPv6 'ip:port' or '[ip]:port' string into (ip, port)."""
    ep = ep_str.strip()
    if ep.startswith("[") and "]:" in ep:
        ip = ep[1:ep.rfind("]:")]
        port = int(ep[ep.rfind("]:") + 2:])
    elif ":" in ep:
        ip, p_str = ep.rsplit(":", 1)
        port = int(p_str) if p_str.isdigit() else 0
    else:
        ip = ep
        port = 0
    return ip, port


def _identify_server_node(p0: int, p1: int, b0: bytes, b1: bytes) -> int:
    """
    Identifies which node (0 or 1) in TShark's follow,tcp,raw block is the server.

    RFC References & Decision Hierarchy (THE 'WHY'):
      1. Server Greeting Banner (RFC 5321 §3.1 for SMTP, RFC 1939 §3 for POP3, RFC 3501 §6.1.1 for IMAP):
         In all three email protocols, the server sends the greeting banner upon connection establishment:
         - SMTP: '220 <domain> [ESMTP...]'
         - POP3: '+OK [greeting...]'
         - IMAP: '* OK [greeting...]' or '* PREAUTH'
         If node data begins with any of these prefixes, that node is definitively the server.
      2. Client Handshake / Command Initial Message:
         If one node begins with TLS ClientHello (\\x16\\x03) or standard client command tokens
         (EHLO, HELO, CAPA, USER, LOGIN, AUTH), that node is the client, making the peer the server.
      3. Well-Known Email Server Ports (RFC 5321, RFC 8314, RFC 3501, RFC 1939):
         Port membership in MAIL_SERVER_PORTS breaks ties when banners are absent or encrypted.
      4. Ephemeral Port Heuristic:
         Servers bind privileged/service ports (< 1024) while clients bind ephemeral ports (>= 1024).
      5. Fallback:
         Assume Node 1 is the server (Wireshark convention when Node 0 initiates connection).
    """
    n0_strip = b0.lstrip()
    n1_strip = b1.lstrip()

    # 1. Server greeting banners
    if n0_strip.startswith((b"220", b"+OK", b"* OK", b"* PREAUTH")):
        return 0
    if n1_strip.startswith((b"220", b"+OK", b"* OK", b"* PREAUTH")):
        return 1

    # 2. Client initiation (ClientHello or client commands)
    client_starters = (b"\x16\x03", b"EHLO", b"ehlo", b"HELO", b"helo", b"CAPA", b"capa",
                       b"USER", b"user", b"LOGIN", b"login", b"AUTH", b"auth", b"STARTTLS", b"starttls")
    if n0_strip.startswith(client_starters):
        return 1
    if n1_strip.startswith(client_starters):
        return 0

    # 3. Known server ports
    if p0 in MAIL_SERVER_PORTS and p1 not in MAIL_SERVER_PORTS:
        return 0
    if p1 in MAIL_SERVER_PORTS and p0 not in MAIL_SERVER_PORTS:
        return 1

    # 4. Port number heuristic
    if p0 < 1024 and p1 >= 1024:
        return 0
    if p1 < 1024 and p0 >= 1024:
        return 1

    # 5. Default fallback
    return 1


def parse_follow_raw_output(raw_text: str) -> Dict[int, StreamFlow]:
    """
    Parses TShark 'follow,tcp,raw' output into normalized StreamFlow instances.

    TShark Format Specification:
      Each stream block is demarcated by '====...':
        Filter: tcp.stream eq <stream_id>
        Node 0: <ip0>:<port0>
        Node 1: <ip1>:<port1>
        <hex_data>          <- Node 0 transmission (no leading tab)
        \\t<hex_data>       <- Node 1 transmission (leading tab)

    TShark's TCP reassembly engine sequence-sorts packets and discards duplicate
    retransmissions, producing a canonical reassembled byte sequence per node.
    """
    blocks = re.split(r'=+\s*\n', raw_text)
    flows = {}
    for block in blocks:
        lines = block.strip().splitlines()
        if not lines:
            continue
        sid = None
        n0_str, n1_str = "", ""
        raw_chunks = []
        for l in lines:
            if l.startswith("Filter: tcp.stream eq "):
                val = l.split("Filter: tcp.stream eq ")[1].strip()
                if val.isdigit():
                    sid = int(val)
            elif l.startswith("Node 0:"):
                n0_str = l.split("Node 0:")[1].strip()
            elif l.startswith("Node 1:"):
                n1_str = l.split("Node 1:")[1].strip()
            elif l.startswith("Follow:"):
                continue
            else:
                is_node1 = l.startswith("\t")
                h = l.strip()
                if h:
                    try:
                        raw_chunks.append((1 if is_node1 else 0, bytes.fromhex(h)))
                    except ValueError:
                        pass
        if sid is None:
            continue
        ip0, p0 = _parse_endpoint(n0_str)
        ip1, p1 = _parse_endpoint(n1_str)
        b0 = b"".join(c for n, c in raw_chunks if n == 0)
        b1 = b"".join(c for n, c in raw_chunks if n == 1)
        srv_node = _identify_server_node(p0, p1, b0, b1)

        srv_ip, srv_p = (ip0, p0) if srv_node == 0 else (ip1, p1)
        cli_ip, cli_p = (ip1, p1) if srv_node == 0 else (ip0, p0)
        srv_data = b0 if srv_node == 0 else b1
        cli_data = b1 if srv_node == 0 else b0

        norm_chunks = [
            ("server" if n == srv_node else "client", data)
            for n, data in raw_chunks
        ]
        flows[sid] = StreamFlow(
            stream_id=sid,
            client=f"{cli_ip}:{cli_p}",
            server=f"{srv_ip}:{srv_p}",
            client_ip=cli_ip,
            client_port=cli_p,
            server_ip=srv_ip,
            server_port=srv_p,
            client_data=cli_data,
            server_data=srv_data,
            chunks=norm_chunks
        )
    return flows


def reassemble_tcp_streams(pcap_path: str) -> Dict[int, StreamFlow]:
    """
    Ingests and normalizes all TCP streams from a PCAP using TShark's follow,tcp,raw.

    RFC Standards:
      • RFC 793 §3.4: Reassembles TCP segments by sequence number into continuous byte streams.
      • Eliminates duplicate/retransmitted segments automatically without custom sequence tracking.

    Returns:
      Dict mapping stream_id (int) -> StreamFlow
    """
    cmd_sids = ["tshark", "-r", pcap_path, "-T", "fields", "-e", "tcp.stream"]
    res_sids = subprocess.run(cmd_sids, capture_output=True, text=True)
    stream_ids = sorted(set(int(s) for s in res_sids.stdout.split() if s.isdigit()))
    if not stream_ids:
        return {}

    # ponytail: query all streams in one tshark invocation using multiple -z options
    cmd_follow = ["tshark", "-r", pcap_path, "-q"]
    for sid in stream_ids:
        cmd_follow.extend(["-z", f"follow,tcp,raw,{sid}"])
    res_follow = subprocess.run(cmd_follow, capture_output=True, text=True)
    flows = parse_follow_raw_output(res_follow.stdout)

    # Ensure streams with 0 data payload (e.g. bare SYN/ACK/RST) still get a valid entry
    for sid in stream_ids:
        if sid not in flows:
            flows[sid] = StreamFlow(
                stream_id=sid, client="", server="", client_ip="", client_port=0,
                server_ip="", server_port=0, client_data=b"", server_data=b"", chunks=[]
            )
    return flows


def extract_stream_frames(pcap_path: str, stream_id: Optional[int] = None) -> List[dict]:
    """
    Lazy / optional forensic path to extract per-packet frame evidence for streams.

    Preserves frame numbers, relative timestamps, sequence numbers, and retransmission flags.
    Called lazily only when forensic frame-level proof is required.
    """
    cmd = [
        "tshark", "-r", pcap_path,
        "-T", "fields",
        "-e", "frame.number",
        "-e", "tcp.stream",
        "-e", "frame.time_epoch",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "tcp.seq",
        "-e", "tcp.len",
        "-e", "tcp.analysis.retransmission"
    ]
    if stream_id is not None:
        cmd.extend(["-Y", f"tcp.stream == {stream_id}"])
    res = subprocess.run(cmd, capture_output=True, text=True)
    frames = []
    for line in res.stdout.strip().splitlines():
        parts = line.split('\t')
        while len(parts) < 8:
            parts.append("")
        f_num, sid_str, epoch_str, sp_str, dp_str, seq_str, len_str, retx_str = parts
        if not sid_str.isdigit():
            continue
        frames.append({
            "frame": int(f_num) if f_num.isdigit() else None,
            "stream": int(sid_str),
            "timestamp": float(epoch_str) if epoch_str else None,
            "src_port": int(sp_str) if sp_str.isdigit() else None,
            "dst_port": int(dp_str) if dp_str.isdigit() else None,
            "seq": int(seq_str) if seq_str.isdigit() else None,
            "len": int(len_str) if len_str.isdigit() else None,
            "is_retransmission": (retx_str == "1")
        })
    return frames


def detect_protocol(pcap_path: str, streams: Optional[Dict[int, StreamFlow]] = None) -> Dict[int, str]:
    """
    Deep Packet Inspection (DPI) protocol classifier per TCP stream.
    Consumes continuous reassembled directional streams (RFC 5321, RFC 3501, RFC 1939).

    Inspects application-layer banners and commands:
    - SMTP (RFC 5321): '220', 'EHLO', 'HELO', 'ESMTP'
    - IMAP (RFC 3501): '* OK', '* PREAUTH', 'CAPABILITY', 'LOGIN', tag commands
    - POP3 (RFC 1939): '+OK', 'USER', 'PASS', 'STAT', 'CAPA'
    Falls back to standard well-known IANA email ports if payload is encrypted (Implicit TLS).

    Returns: Dict mapping stream_id (int) -> protocol name (str)
    """
    if streams is None:
        streams = reassemble_tcp_streams(pcap_path)

    results = {}
    for sid, flow in streams.items():
        detected = None
        s_text = flow.server_data.decode('latin1', errors='ignore')
        c_text = flow.client_data.decode('latin1', errors='ignore')

        # Split continuous streams into individual protocol lines
        s_lines = [l.strip() for l in s_text.replace('\r\n', '\n').split('\n') if l.strip()]
        c_lines = [l.strip() for l in c_text.replace('\r\n', '\n').split('\n') if l.strip()]
        s_banner = s_lines[0] if s_lines else ""
        s_banner_upper = s_banner.upper()
        c_first = c_lines[0].upper() if c_lines else ""

        # SMTP DPI (RFC 5321 §3.1 banner 220, §4.1 EHLO/HELO)
        if (s_banner.startswith("220") or "ESMTP" in s_banner_upper or "SMTP" in s_banner_upper or
            c_first.startswith("EHLO") or c_first.startswith("HELO")):
            detected = "SMTP"
        # IMAP DPI (RFC 3501 §6.1.1 banner * OK/* PREAUTH, §6.2.1 CAPABILITY)
        elif (s_banner_upper.startswith("* OK") or s_banner_upper.startswith("* PREAUTH") or
              "IMAP" in s_banner_upper or c_first.startswith("CAPABILITY") or "LOGIN" in c_first):
            detected = "IMAP"
        # POP3 DPI (RFC 1939 §3 banner +OK, §4 USER/PASS/CAPA)
        elif (s_banner_upper.startswith("+OK") or "POP" in s_banner_upper or
              c_first.startswith("USER") or c_first.startswith("CAPA")):
            detected = "POP3"

        if not detected:
            # Port-based fallback for encrypted / implicit TLS sessions
            ports = {flow.server_port, flow.client_port}
            if ports.intersection({25, 465, 587, 2525, 2526}):
                detected = "SMTP"
            elif ports.intersection({143, 993, 1143}):
                detected = "IMAP"
            elif ports.intersection({110, 995, 1110}):
                detected = "POP3"
            else:
                detected = "Unknown"

        results[sid] = detected

    return results


def detect_starttls(
    pcap_path: str,
    tls_sessions: Optional[dict] = None,
    streams: Optional[Dict[int, StreamFlow]] = None
) -> Dict[int, dict]:
    """
    STREAM-LEVEL STARTTLS STATE MACHINE (RFC 3207, RFC 2595, RFC 3501):
    ===================================================================
    Tracks protocol encryption transitions per TCP stream using directional
    continuous stream tokenization between client and server.

    RFC REFERENCES & DIRECTIONAL SEMANTICS (THE 'WHY'):
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
          advertisements and client commands. Directional stream attribution
          resolves this completely.
      • IMAP (RFC 3501 §6.2.1):
          Server -> Client: * CAPABILITY ... STARTTLS ... (capability advertisement)
          Client -> Server: [tag] STARTTLS (tagged command)
          Server -> Client: [tag] OK Begin TLS negotiation (acceptance response)
          [TLS Handshake Begins]

    Returns: Dict mapping stream_id (int) -> STARTTLS state dictionary
    """
    if tls_sessions is None:
        tls_sessions = extract_tls_info(pcap_path)
    if streams is None:
        streams = reassemble_tcp_streams(pcap_path)

    all_stream_ids = sorted(set(list(streams.keys()) + list(tls_sessions.keys())))
    results = {}

    for sid in all_stream_ids:
        flow = streams.get(sid)
        if not flow or not flow.chunks:
            tls_active = (sid in tls_sessions)
            results[sid] = {
                "stream": sid,
                "starttls_offered": False,
                "starttls_requested": False,
                "starttls_accepted": False,
                "starttls_rejected": False,
                "tls_active": tls_active,
                "plaintext_auth_attempted": False,
                "status": "IMPLICIT_TLS" if tls_active else "CLEARTEXT_NO_ENCRYPTION",
                "details": "Session used direct implicit TLS without plaintext upgrade (e.g. SMTPS/IMAPS/POP3S)." if tls_active else "Session conducted completely in plaintext with no TLS."
            }
            continue

        starttls_offered = False
        starttls_requested = False
        starttls_accepted = False
        starttls_rejected = False
        requested_without_advertisement = False
        pending_starttls_response = False
        imap_starttls_tag = None
        plaintext_auth_attempted = False

        # Directional line buffers: guarantees lines split across TCP segment boundaries
        # are reconstructed into complete protocol lines before rule evaluation.
        # ponytail: maintain two string buffers, extract on \n delimiter
        line_buffers = {"server": "", "client": ""}

        def extract_lines(sender: str, raw_bytes: bytes) -> List[str]:
            text = raw_bytes.decode('latin1', errors='ignore')
            buf = line_buffers[sender] + text
            extracted = []
            while True:
                idx = buf.find('\n')
                if idx == -1:
                    line_buffers[sender] = buf
                    break
                line = buf[:idx].rstrip('\r')
                buf = buf[idx + 1:]
                extracted.append(line)
            return extracted

        # Process reassembled directional chunks in chronological order
        for sender, chunk_bytes in flow.chunks:
            lines = extract_lines(sender, chunk_bytes)
            for raw_line in lines:
                cleaned_line = raw_line.strip()
                if not cleaned_line:
                    continue
                line_upper = cleaned_line.upper()

                # ── SERVER-TO-CLIENT ATTRIBUTION ─────────────────────────────
                if sender == "server":
                    # A. Server Capability Advertisement (RFC 3207 §4, RFC 2595 §4, RFC 3501 §6.2.1):
                    if cleaned_line.startswith("250") and "STARTTLS" in line_upper:
                        starttls_offered = True
                    elif cleaned_line.startswith("+OK") and "STLS" in line_upper:
                        starttls_offered = True
                    elif line_upper == "STLS":
                        starttls_offered = True
                    elif "CAPABILITY" in line_upper and "STARTTLS" in line_upper:
                        starttls_offered = True
                    elif "STARTTLS" in line_upper and (cleaned_line.startswith("250") or cleaned_line.startswith("*")):
                        starttls_offered = True

                    # B. Server Response to STARTTLS Command (RFC 3207 §4.2, RFC 2595 §4, RFC 3501 §6.2.1):
                    # Evaluated strictly on the response correlating to the STARTTLS command:
                    # - For IMAP: Correlates to the specific command tag (e.g. 'A001 OK' vs 'A001 NO').
                    # - For SMTP/POP3: Evaluates the next response following the client command.
                    if pending_starttls_response:
                        if imap_starttls_tag:
                            # IMAP tagged response correlation (RFC 3501 §2.2.1)
                            if line_upper.startswith(imap_starttls_tag + " "):
                                parts = line_upper.split(None, 2)
                                status_token = parts[1] if len(parts) > 1 else ""
                                if status_token == "OK":
                                    starttls_accepted = True
                                    pending_starttls_response = False
                                elif status_token in ("NO", "BAD"):
                                    starttls_rejected = True
                                    pending_starttls_response = False
                        else:
                            # SMTP (RFC 3207 §4.2) / POP3 (RFC 2595 §4)
                            if cleaned_line.startswith("220"):
                                starttls_accepted = True
                                pending_starttls_response = False
                            elif cleaned_line.startswith("+OK"):
                                starttls_accepted = True
                                pending_starttls_response = False
                            elif cleaned_line.startswith(("4", "5")):
                                # SMTP 4xx (454 temp fail) or 5xx (501 syntax / 500 / 502)
                                starttls_rejected = True
                                pending_starttls_response = False
                            elif cleaned_line.startswith("-ERR"):
                                # POP3 -ERR rejection
                                starttls_rejected = True
                                pending_starttls_response = False

                # ── CLIENT-TO-SERVER ATTRIBUTION ─────────────────────────────
                elif sender == "client":
                    # A. Client Upgrade Command:
                    # RFC 3207 (SMTP: STARTTLS), RFC 2595 (POP3: STLS), RFC 3501 (IMAP: [tag] STARTTLS)
                    is_upgrade_cmd = False
                    if line_upper in ("STARTTLS", "STLS"):
                        is_upgrade_cmd = True
                    elif line_upper.endswith(" STARTTLS") or " STARTTLS " in line_upper:
                        is_upgrade_cmd = True
                        parts = cleaned_line.split()
                        if len(parts) >= 2 and parts[1].upper() == "STARTTLS":
                            imap_starttls_tag = parts[0].upper()

                    if is_upgrade_cmd:
                        starttls_requested = True
                        pending_starttls_response = True
                        if not starttls_offered:
                            # RFC 3207 §4: Client must not send STARTTLS without server capability advertisement
                            requested_without_advertisement = True

                    # B. Plaintext Authentication in Unencrypted Traffic:
                    if (line_upper.startswith("AUTH ") or
                        line_upper.startswith("USER ") or
                        line_upper.startswith("PASS ") or
                        " LOGIN " in line_upper or
                        line_upper.startswith("LOGIN ")):
                        plaintext_auth_attempted = True

        # Flush any remaining un-terminated line in buffer at stream close
        for sender in ("server", "client"):
            rem = line_buffers[sender].strip()
            if rem:
                line_upper = rem.upper()
                if sender == "client":
                    if line_upper in ("STARTTLS", "STLS") or line_upper.endswith(" STARTTLS"):
                        starttls_requested = True
                        pending_starttls_response = True
                        if not starttls_offered:
                            requested_without_advertisement = True
                        parts = rem.split()
                        if len(parts) >= 2 and parts[1].upper() == "STARTTLS":
                            imap_starttls_tag = parts[0].upper()
                elif sender == "server" and pending_starttls_response:
                    if imap_starttls_tag and line_upper.startswith(imap_starttls_tag + " "):
                        parts = line_upper.split(None, 2)
                        status_token = parts[1] if len(parts) > 1 else ""
                        if status_token == "OK":
                            starttls_accepted = True
                        elif status_token in ("NO", "BAD"):
                            starttls_rejected = True
                    elif not imap_starttls_tag:
                        if rem.startswith(("220", "+OK")):
                            starttls_accepted = True
                        elif rem.startswith(("4", "5", "-ERR")):
                            starttls_rejected = True

        # TLS activation: check tls_sessions or binary TLS record layer in client_data
        tls_active = (sid in tls_sessions)
        if not tls_active:
            tls_active = b"\x16\x03" in flow.client_data

        # ── 3. SIX-STATE PROTOCOL LIFECYCLE EVALUATION ─────────────────────
        # Decision Hierarchy:
        # Did client request STARTTLS?
        #   ├── Yes: Was advertisement observed?
        #   │         ├── No:  STARTTLS_WITHOUT_ADVERTISEMENT (preserves rejection evidence in telemetry)
        #   │         └── Yes: What was server response?
        #   │                   ├── Accepted & TLS active: UPGRADED
        #   │                   ├── Rejected:              STARTTLS_REJECTED
        #   │                   └── Other / Incomplete:    DOWNGRADE_OR_STRIPPED / CLEARTEXT
        #   └── No:  Normal flow:
        #             ├── Advertised & not TLS active:     DOWNGRADE_OR_STRIPPED
        #             ├── TLS active (unprompted):          IMPLICIT_TLS
        #             └── Neither:                          CLEARTEXT_NO_ENCRYPTION
        if starttls_requested:
            if requested_without_advertisement and not tls_active:
                status = "STARTTLS_WITHOUT_ADVERTISEMENT"
                details = "Client requested STARTTLS without observing server capability advertisement."
            elif starttls_accepted and tls_active:
                status = "UPGRADED"
                details = "STARTTLS successfully negotiated and encrypted session established."
            elif starttls_rejected and not tls_active:
                status = "STARTTLS_REJECTED"
                details = "Client requested STARTTLS, but server explicitly rejected the command."
            elif starttls_offered and not tls_active:
                status = "DOWNGRADE_OR_STRIPPED"
                details = "Server advertised STARTTLS, but session remained in plaintext! Potential stripping attack or insecure client."
            else:
                status = "CLEARTEXT_NO_ENCRYPTION"
                details = "Session conducted completely in plaintext with no TLS."
        else:
            if starttls_offered and not tls_active:
                status = "DOWNGRADE_OR_STRIPPED"
                details = "Server advertised STARTTLS, but session remained in plaintext! Potential stripping attack or insecure client."
            elif tls_active:
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
            "starttls_rejected": starttls_rejected,
            "tls_active": tls_active,
            "plaintext_auth_attempted": plaintext_auth_attempted,
            "status": status,
            "details": details
        }

    return results

