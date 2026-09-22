"""
testbed/runner/client.py
========================
Deterministic SMTP Client Runner (Milestone 2).

Architecture:
-------------
Consumes a ScenarioSpec or StagedScenario manifest to drive deterministic SMTP
interactions matching the scenario's client-side contract.

Protocol Support:
  - Implicit TLS (RFC 8314 §7.3 submissions on port 465)
  - Cleartext SMTP (RFC 5321 on port 25)
  - STARTTLS Negotiation (RFC 3207 on port 25)
  - Plaintext & Post-TLS Authentication (RFC 4954)
  - Expected Failure & Rejection Modes (PCAP-113, PCAP-120)

RFC References:
  - RFC 5321: Simple Mail Transfer Protocol (SMTP)
  - RFC 3207: SMTP Service Extension for Secure SMTP over Transport Layer Security (STARTTLS)
  - RFC 8314: Cleartext Considered Obsolete (Implicit TLS port 465)
  - RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
  - RFC 5246: The Transport Layer Security (TLS) Protocol Version 1.2
  - RFC 4954: SMTP Service Extension for Authentication
  - RFC 6066: Transport Layer Security (TLS) Extensions: Extension Definitions (SNI)
"""

from dataclasses import dataclass, field
import json
from pathlib import Path
import socket
import ssl
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple

# Ensure project root is on sys.path
_here = Path(__file__).resolve().parent
_project_root = _here.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

# Project imports
from analysis.ciphers import iana_to_openssl
from testbed.runner.spec import ScenarioSpec
from testbed.runner.stager import StagedScenario, derive_client_tls_config


def parse_ehlo_capabilities(lines: List[str]) -> Set[str]:
    """
    Parse RFC 5321 §4.1.1.1 and RFC 3207 EHLO keywords from multi-line SMTP responses.
    Each 250 continuation line has the form '250[- ]<keyword>[ <params>]'.
    Returns a set of uppercase capability keywords (e.g. {'STARTTLS', 'PIPELINING', 'AUTH'}).
    """
    caps: Set[str] = set()
    for line in lines:
        clean = line.strip()
        if len(clean) >= 4 and clean[:3] == "250" and clean[3] in ("-", " "):
            remainder = clean[4:].strip()
            if remainder:
                keyword = remainder.split()[0].upper()
                caps.add(keyword)
    return caps


@dataclass
class ClientResult:
    """
    Structured outcome of an executed SMTP scenario interaction.

    Semantics:
      - success: The scripted scenario completed as intended, reaching its
        expected protocol state machine terminus (including expected rejections
        such as 454 for PCAP-113).
      - tls_negotiated: Whether a TLS handshake actually completed on the wire.
      - expected_condition: Categorical tag describing the terminal state:
          "NORMAL", "STARTTLS_REJECTED", "UNADVERTISED_STARTTLS_REJECTED",
          "MANDATORY_ABORT", "OPPORTUNISTIC_DOWNGRADE", etc.
    """
    scenario_id: str
    success: bool
    tls_negotiated: bool
    expected_condition: str = "NORMAL"
    tls_version: Optional[str] = None
    cipher: Optional[Tuple[str, str, int]] = None
    peer_certificate_der: Optional[bytes] = None
    transcript: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to a JSON-serializable dictionary."""
        return {
            "scenario_id": self.scenario_id,
            "success": self.success,
            "tls_negotiated": self.tls_negotiated,
            "expected_condition": self.expected_condition,
            "tls_version": self.tls_version,
            "cipher": list(self.cipher) if self.cipher else None,
            "transcript_count": len(self.transcript),
            "error": self.error,
        }


def build_client_ssl_context(client_tls_config: Dict[str, Any]) -> ssl.SSLContext:
    """
    Construct an explicit ssl.SSLContext conforming to scenario specifications.

    Implementation Principles:
      1. Permissive Verification: Disables hostname check and certificate
         verification (verify_mode = CERT_NONE) so that testbed scenarios
         with expired, untrusted, or mismatched certificates can complete the
         handshake on the wire for analyzer evaluation.
      2. TLS Version Constraints: Restricts minimum and maximum TLS versions
         based on client_tls_config['offered_version'].
      3. TLS ≤ 1.2 Cipher Constraints: Constrains cipher lists for TLS 1.0–1.2
         via context.set_ciphers(). For TLS 1.3, Python ssl does not support
         set_ciphersuites() in Python ≤ 3.14, so TLS 1.3 ciphers are negotiated
         by server configuration and recorded post-handshake.
      4. Security Level: Appends :@SECLEVEL=0 when weak or legacy ciphers/protocols
         are requested, ensuring OpenSSL 3.x compatibility.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # 1. Permissive Certificate Handling (RFC 5280 inspection testbed)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # 2. Protocol Version Restrictions
    offered_version = client_tls_config.get("offered_version")
    if offered_version == "TLS 1.0":
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1
    elif offered_version == "TLS 1.1":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_1
        ctx.maximum_version = ssl.TLSVersion.TLSv1_1
    elif offered_version == "TLS 1.2":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    elif offered_version == "TLS 1.3":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    else:
        # Default unconstrained client offering TLS 1.2 through 1.3
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED

    # 3. Cipher Selection (TLS ≤ 1.2 only)
    # Python ssl.set_ciphers() only controls TLS 1.2 and below.
    if offered_version != "TLS 1.3":
        offered_ciphers = client_tls_config.get("offered_ciphers") or []
        # Exclude TLS 1.3 cipher suites from set_ciphers
        tls12_ciphers = []
        for c in offered_ciphers:
            if c.startswith("TLS_AES_") or c.startswith("TLS_CHACHA20_"):
                continue
            ossl = iana_to_openssl(c)
            if not ossl:
                raise ssl.SSLError(
                    f"Requested cipher '{c}' could not be translated to a supported OpenSSL cipher suite"
                )
            tls12_ciphers.append(ossl)

        if tls12_ciphers:
            cipher_str = ":".join(tls12_ciphers)
            try:
                ctx.set_ciphers(f"{cipher_str}:@SECLEVEL=0")
            except ssl.SSLError:
                # Fallback without SECLEVEL=0 if OpenSSL version differs
                try:
                    ctx.set_ciphers(cipher_str)
                except ssl.SSLError as second_error:
                    raise ssl.SSLError(
                        f"Unable to apply requested TLS cipher restriction '{cipher_str}': {second_error}"
                    ) from second_error

    return ctx


class SMTPClient:
    """
    Deterministic, line-oriented SMTP client designed for testbed PCAP generation.
    """

    def __init__(self, local_hostname: str = "client.test.local"):
        self.local_hostname = local_hostname

    @staticmethod
    def build_ssl_context(client_tls_config: Dict[str, Any]) -> ssl.SSLContext:
        """
        Construct an explicit ssl.SSLContext conforming to scenario specifications.
        Delegates to the protocol-agnostic build_client_ssl_context.
        """
        return build_client_ssl_context(client_tls_config)

    def _read_line(self, sock: socket.socket | ssl.SSLSocket) -> str:
        """
        Read a single CR-LF terminated line from the socket.
        """
        buffer = bytearray()
        while True:
            chunk = sock.recv(1)
            if not chunk:
                if buffer:
                    break
                raise ConnectionResetError("Remote server closed connection unexpectedly")
            buffer.extend(chunk)
            if buffer.endswith(b"\r\n") or buffer.endswith(b"\n"):
                break
        return buffer.decode("latin-1")

    def _read_smtp_response(
        self,
        sock: socket.socket | ssl.SSLSocket,
        transcript: List[Dict[str, Any]],
    ) -> Tuple[int, List[str]]:
        """
        Read a complete SMTP response (single-line or multi-line per RFC 5321 §4.2).

        Multi-line responses have a hyphen after the 3-digit code:
            250-mail.test.local
            250-STARTTLS
            250 OK
        """
        lines: List[str] = []
        status_code = 0

        while True:
            raw_line = self._read_line(sock)
            transcript.append({
                "direction": "in",
                "text": raw_line.rstrip("\r\n"),
                "timestamp": time.time(),
            })
            lines.append(raw_line)

            # Parse SMTP status code (3 ASCII digits)
            clean = raw_line.strip()
            if len(clean) >= 3 and clean[:3].isdigit():
                status_code = int(clean[:3])
                # If 4th char is not '-', this is the final line of the response
                if len(clean) == 3 or clean[3] != "-":
                    break
            else:
                # Malformed or continuation
                break

        return status_code, lines

    def _send_command(
        self,
        sock: socket.socket | ssl.SSLSocket,
        cmd: str,
        transcript: List[Dict[str, Any]],
    ) -> None:
        """
        Send a CRLF-terminated SMTP command to the server and record in transcript.
        """
        wire = f"{cmd}\r\n".encode("latin-1")
        sock.sendall(wire)
        transcript.append({
            "direction": "out",
            "text": cmd,
            "timestamp": time.time(),
        })

    def execute(
        self,
        scenario: StagedScenario | ScenarioSpec | Dict[str, Any],
        host_override: Optional[str] = None,
        port_override: Optional[int] = None,
        source_ip: Optional[str] = None,
        timeout: float = 10.0,
    ) -> ClientResult:
        """
        Execute an SMTP scenario against the target server.

        Args:
          scenario: StagedScenario, ScenarioSpec, or manifest dict.
          host_override: Target server IP or hostname (overrides scenario default).
          port_override: Target port (overrides scenario default).
          source_ip: Local source IP to bind (optional, e.g. "172.28.0.20").
          timeout: Socket connection and read timeout in seconds.

        Returns:
          ClientResult containing scenario success, TLS negotiation details,
          and complete wire transcript.
        """
        # 1. Normalize parameters from input object
        if isinstance(scenario, StagedScenario):
            manifest = scenario.manifest
            scenario_id = scenario.scenario_id
            server_ip = manifest["network"]["server_ip"]
            port = manifest["network"]["port"]
            tls_presence = manifest["server_tls"]["tls_presence"]
            client_tls = manifest["client_tls"]
        elif isinstance(scenario, ScenarioSpec):
            scenario_id = scenario.scenario_id
            server_ip = scenario.network.server_ip
            port = scenario.network.port
            tls_presence = scenario.server.tls_presence
            # Single source of truth: derive identical client TLS configuration as stager
            client_tls = derive_client_tls_config(scenario)
        elif isinstance(scenario, dict):
            manifest = scenario
            scenario_id = manifest.get("scenario_id", "UNKNOWN")
            server_ip = manifest.get("network", {}).get("server_ip", "172.28.0.10")
            port = manifest.get("network", {}).get("port", 25)
            tls_presence = manifest.get("server_tls", {}).get("tls_presence", "none")
            client_tls = manifest.get("client_tls", {})
        else:
            raise TypeError(f"Unsupported scenario type: {type(scenario)}")

        target_host = host_override if host_override is not None else server_ip
        target_port = port_override if port_override is not None else port

        auth_outcome = client_tls.get("auth_outcome", "none")
        starttls_enforcement = client_tls.get("starttls_enforcement", "none")
        client_behavior = client_tls.get("client_behavior", "")
        sni = client_tls.get("sni")

        transcript: List[Dict[str, Any]] = []
        raw_sock: Optional[socket.socket] = None
        active_sock: Optional[socket.socket | ssl.SSLSocket] = None

        tls_negotiated = False
        tls_version: Optional[str] = None
        cipher: Optional[Tuple[str, str, int]] = None
        peer_cert: Optional[bytes] = None
        expected_condition = "NORMAL"

        try:
            # 2. Establish TCP Connection
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(timeout)

            if source_ip:
                # Optional source IP binding (e.g. container IP 172.28.0.20)
                raw_sock.bind((source_ip, 0))

            raw_sock.connect((target_host, target_port))
            active_sock = raw_sock

            # ------------------------------------------------------------------
            # Scenario Path A: Implicit TLS (RFC 8314 §7.3 submissions on port 465)
            # ------------------------------------------------------------------
            if tls_presence == "implicit-TLS":
                ctx = self.build_ssl_context(client_tls)
                try:
                    ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=sni)
                    active_sock = ssl_sock
                except ssl.SSLError as ssl_err:
                    if client_behavior == "server_sends_fatal_alert":
                        # Expected negative TLS handshake failure: fatal alert received
                        transcript.append({
                            "direction": "in",
                            "text": f"SSL Alert received: {ssl_err}",
                            "timestamp": time.time(),
                        })
                        return ClientResult(
                            scenario_id=scenario_id,
                            success=True,
                            tls_negotiated=False,
                            expected_condition="EXPECTED_TLS_FAILURE",
                            transcript=transcript,
                            error=None,
                        )
                    raise

                # Record negotiated TLS parameters
                tls_negotiated = True
                tls_version = ssl_sock.version()
                cipher = ssl_sock.cipher()
                peer_cert = ssl_sock.getpeercert(binary_form=True)

                # Read 220 banner
                code, _ = self._read_smtp_response(active_sock, transcript)
                if code != 220:
                    return ClientResult(
                        scenario_id=scenario_id,
                        success=False,
                        tls_negotiated=tls_negotiated,
                        expected_condition="UNEXPECTED_BANNER",
                        tls_version=tls_version,
                        cipher=cipher,
                        peer_certificate_der=peer_cert,
                        transcript=transcript,
                        error=f"Unexpected banner code {code}",
                    )

                # Post-TLS SMTP Session: EHLO
                self._send_command(active_sock, f"EHLO {self.local_hostname}", transcript)
                self._read_smtp_response(active_sock, transcript)

                # Authentication if specified
                if auth_outcome == "post-TLS-encrypted":
                    self._send_command(active_sock, "AUTH PLAIN AHVzZXIAcGFzc3dvcmQ=", transcript)
                    self._read_smtp_response(active_sock, transcript)

                    # Optional mail transaction to generate rich traffic
                    self._send_command(active_sock, "MAIL FROM:<test@test.local>", transcript)
                    self._read_smtp_response(active_sock, transcript)
                    self._send_command(active_sock, "RCPT TO:<user@test.local>", transcript)
                    self._read_smtp_response(active_sock, transcript)

                # Clean termination
                self._send_command(active_sock, "QUIT", transcript)
                self._read_smtp_response(active_sock, transcript)

                return ClientResult(
                    scenario_id=scenario_id,
                    success=True,
                    tls_negotiated=True,
                    expected_condition="NORMAL",
                    tls_version=tls_version,
                    cipher=cipher,
                    peer_certificate_der=peer_cert,
                    transcript=transcript,
                )

            # ------------------------------------------------------------------
            # Scenario Path B: Cleartext SMTP (RFC 5321 on port 25, no TLS)
            # ------------------------------------------------------------------
            elif tls_presence == "none":
                # Read 220 banner
                code, _ = self._read_smtp_response(active_sock, transcript)
                if code != 220:
                    return ClientResult(
                        scenario_id=scenario_id,
                        success=False,
                        tls_negotiated=False,
                        expected_condition="UNEXPECTED_BANNER",
                        transcript=transcript,
                        error=f"Unexpected banner code {code}",
                    )

                self._send_command(active_sock, f"EHLO {self.local_hostname}", transcript)
                self._read_smtp_response(active_sock, transcript)

                # Plaintext authentication test (e.g. PCAP-061)
                if auth_outcome == "plaintext-attempted":
                    self._send_command(active_sock, "AUTH PLAIN AHVzZXIAcGFzc3dvcmQ=", transcript)
                    self._read_smtp_response(active_sock, transcript)

                self._send_command(active_sock, "QUIT", transcript)
                self._read_smtp_response(active_sock, transcript)

                return ClientResult(
                    scenario_id=scenario_id,
                    success=True,
                    tls_negotiated=False,
                    expected_condition="NORMAL",
                    transcript=transcript,
                )

            # ------------------------------------------------------------------
            # Scenario Path C: STARTTLS Upgraded (RFC 3207 on port 25)
            # ------------------------------------------------------------------
            elif tls_presence == "STARTTLS-upgraded":
                # Read initial cleartext 220 banner
                code, _ = self._read_smtp_response(active_sock, transcript)
                if code != 220:
                    return ClientResult(
                        scenario_id=scenario_id,
                        success=False,
                        tls_negotiated=False,
                        expected_condition="UNEXPECTED_BANNER",
                        transcript=transcript,
                        error=f"Unexpected banner code {code}",
                    )

                self._send_command(active_sock, f"EHLO {self.local_hostname}", transcript)
                _, ehlo_lines = self._read_smtp_response(active_sock, transcript)

                # Explicit capability parsing per RFC 5321 §4.1.1.1 / RFC 3207
                caps = parse_ehlo_capabilities(ehlo_lines)
                has_starttls_ad = "STARTTLS" in caps

                # Subcase C.1: Deliberate STARTTLS without advertisement (PCAP-120)
                if client_behavior == "protocol_proxy_or_modified_server":
                    # Invariant 1: In PCAP-120, STARTTLS MUST NOT be advertised!
                    if has_starttls_ad:
                        self._send_command(active_sock, "QUIT", transcript)
                        self._read_smtp_response(active_sock, transcript)
                        return ClientResult(
                            scenario_id=scenario_id,
                            success=False,
                            tls_negotiated=False,
                            expected_condition="UNEXPECTED_STARTTLS_ADVERTISED",
                            transcript=transcript,
                            error="STARTTLS was unexpectedly advertised in PCAP-120 scenario",
                        )

                    self._send_command(active_sock, "STARTTLS", transcript)
                    rej_code, _ = self._read_smtp_response(active_sock, transcript)
                    self._send_command(active_sock, "QUIT", transcript)
                    self._read_smtp_response(active_sock, transcript)

                    # Invariant 2: Server MUST reject the unadvertised STARTTLS (non-220, e.g. 500, 502, 503, 454)
                    if rej_code != 220:
                        return ClientResult(
                            scenario_id=scenario_id,
                            success=True,  # Scripted unadvertised probe and rejection executed as intended!
                            tls_negotiated=False,
                            expected_condition="UNADVERTISED_STARTTLS_REJECTED",
                            transcript=transcript,
                        )
                    else:
                        return ClientResult(
                            scenario_id=scenario_id,
                            success=False,
                            tls_negotiated=False,
                            expected_condition="UNEXPECTED_STARTTLS_ACCEPTANCE",
                            transcript=transcript,
                            error=f"Server illegally accepted unadvertised STARTTLS with code {rej_code}",
                        )

                # Subcase C.2: Advertised STARTTLS
                if has_starttls_ad:
                    self._send_command(active_sock, "STARTTLS", transcript)
                    starttls_code, _ = self._read_smtp_response(active_sock, transcript)

                    if starttls_code == 220:
                        # Upgrade socket to TLS
                        ctx = self.build_ssl_context(client_tls)
                        tls_sock = ctx.wrap_socket(raw_sock, server_hostname=sni)
                        active_sock = tls_sock

                        # Record negotiated parameters
                        tls_negotiated = True
                        tls_version = tls_sock.version()
                        cipher = tls_sock.cipher()
                        peer_cert = tls_sock.getpeercert(binary_form=True)

                        # RFC 3207 §4.2: Client MUST discard cached extensions and re-EHLO
                        self._send_command(active_sock, f"EHLO {self.local_hostname}", transcript)
                        self._read_smtp_response(active_sock, transcript)

                        if auth_outcome == "post-TLS-encrypted":
                            self._send_command(active_sock, "AUTH PLAIN AHVzZXIAcGFzc3dvcmQ=", transcript)
                            self._read_smtp_response(active_sock, transcript)
                            self._send_command(active_sock, "MAIL FROM:<test@test.local>", transcript)
                            self._read_smtp_response(active_sock, transcript)
                            self._send_command(active_sock, "RCPT TO:<user@test.local>", transcript)
                            self._read_smtp_response(active_sock, transcript)

                        self._send_command(active_sock, "QUIT", transcript)
                        self._read_smtp_response(active_sock, transcript)

                        return ClientResult(
                            scenario_id=scenario_id,
                            success=True,
                            tls_negotiated=True,
                            expected_condition="NORMAL",
                            tls_version=tls_version,
                            cipher=cipher,
                            peer_certificate_der=peer_cert,
                            transcript=transcript,
                        )

                    elif starttls_code == 454 or client_behavior == "server_rejects_starttls":
                        # Expected rejection (e.g. PCAP-113)
                        self._send_command(active_sock, "QUIT", transcript)
                        self._read_smtp_response(active_sock, transcript)
                        return ClientResult(
                            scenario_id=scenario_id,
                            success=True,  # Scripted rejection completed as intended!
                            tls_negotiated=False,
                            expected_condition="STARTTLS_REJECTED",
                            transcript=transcript,
                        )
                    else:
                        # Unexpected error response to STARTTLS
                        self._send_command(active_sock, "QUIT", transcript)
                        self._read_smtp_response(active_sock, transcript)
                        return ClientResult(
                            scenario_id=scenario_id,
                            success=False,
                            tls_negotiated=False,
                            expected_condition="UNEXPECTED_STARTTLS_RESPONSE",
                            transcript=transcript,
                            error=f"Unexpected STARTTLS response code {starttls_code}",
                        )

                # Subcase C.3: Not advertised (e.g. stripped or absent)
                else:
                    if starttls_enforcement == "mandatory_abort":
                        # Mandatory policy: refuse plaintext fallback and abort
                        self._send_command(active_sock, "QUIT", transcript)
                        self._read_smtp_response(active_sock, transcript)
                        return ClientResult(
                            scenario_id=scenario_id,
                            success=True,
                            tls_negotiated=False,
                            expected_condition="MANDATORY_ABORT",
                            transcript=transcript,
                        )
                    elif starttls_enforcement == "opportunistic_downgrade":
                        # Opportunistic downgrade: continue in plaintext
                        self._send_command(active_sock, "QUIT", transcript)
                        self._read_smtp_response(active_sock, transcript)
                        return ClientResult(
                            scenario_id=scenario_id,
                            success=True,
                            tls_negotiated=False,
                            expected_condition="OPPORTUNISTIC_DOWNGRADE",
                            transcript=transcript,
                        )
                    else:
                        self._send_command(active_sock, "QUIT", transcript)
                        self._read_smtp_response(active_sock, transcript)
                        return ClientResult(
                            scenario_id=scenario_id,
                            success=True,
                            tls_negotiated=False,
                            expected_condition="NO_STARTTLS_ADVERTISED",
                            transcript=transcript,
                        )

            else:
                raise ValueError(f"Unknown tls_presence: {tls_presence!r}")

        except (ssl.SSLError, socket.error, TimeoutError, OSError) as exc:
            return ClientResult(
                scenario_id=scenario_id,
                success=False,
                tls_negotiated=tls_negotiated,
                expected_condition="SOCKET_OR_SSL_ERROR",
                tls_version=tls_version,
                cipher=cipher,
                peer_certificate_der=peer_cert,
                transcript=transcript,
                error=str(exc),
            )

        finally:
            if active_sock:
                try:
                    active_sock.close()
                except Exception:
                    pass
            elif raw_sock:
                try:
                    raw_sock.close()
                except Exception:
                    pass


class IMAPClient:
    """
    Deterministic, line-oriented IMAP client designed for testbed PCAP generation (RFC 3501).
    """

    def __init__(self, username: str = "user@test.local", password: str = "password"):
        self.username = username
        self.password = password
        self._tag_counter = 0

    def _next_tag(self) -> str:
        self._tag_counter += 1
        return f"A{self._tag_counter:03d}"

    def _read_line(self, sock: socket.socket | ssl.SSLSocket) -> str:
        buffer = bytearray()
        while True:
            chunk = sock.recv(1)
            if not chunk:
                break
            buffer.extend(chunk)
            if buffer.endswith(b"\r\n"):
                break
        return buffer.decode("latin-1")

    def _read_imap_response(
        self,
        sock: socket.socket | ssl.SSLSocket,
        tag: str,
        transcript: List[Dict[str, Any]],
    ) -> Tuple[str, List[str]]:
        """
        Read until tagged completion response for `tag` (e.g. 'A001 OK ...', 'A001 NO ...', 'A001 BAD ...').
        """
        lines: List[str] = []
        status = ""
        tag_prefix = f"{tag} "
        while True:
            raw_line = self._read_line(sock)
            if not raw_line:
                break
            transcript.append({
                "direction": "in",
                "text": raw_line.rstrip("\r\n"),
                "timestamp": time.time(),
            })
            lines.append(raw_line)
            clean = raw_line.strip()
            if clean.startswith(tag_prefix):
                parts = clean.split(None, 2)
                if len(parts) >= 2:
                    status = parts[1].upper()
                break
        return status, lines

    def _send_command(
        self,
        sock: socket.socket | ssl.SSLSocket,
        tag: str,
        cmd: str,
        transcript: List[Dict[str, Any]],
    ) -> None:
        wire = f"{tag} {cmd}\r\n".encode("latin-1")
        sock.sendall(wire)
        transcript.append({
            "direction": "out",
            "text": f"{tag} {cmd}",
            "timestamp": time.time(),
        })

    def execute(
        self,
        scenario: StagedScenario | ScenarioSpec | Dict[str, Any],
        host_override: Optional[str] = None,
        port_override: Optional[int] = None,
        source_ip: Optional[str] = None,
        timeout: float = 10.0,
    ) -> ClientResult:
        if isinstance(scenario, StagedScenario):
            scenario_id = scenario.scenario_id
            manifest = scenario.manifest
            client_tls = manifest.get("client_tls", {})
            net = manifest.get("network", {})
            srv = manifest.get("server_tls", {})
            target_host = host_override or net.get("server_ip", "172.28.0.11")
            target_port = port_override or net.get("port", 143)
            tls_presence = srv.get("tls_presence", "none")
            starttls_enforcement = client_tls.get("starttls_enforcement", "none")
            auth_outcome = client_tls.get("auth_outcome", "none")
        elif isinstance(scenario, ScenarioSpec):
            scenario_id = scenario.scenario_id
            client_tls = derive_client_tls_config(scenario)
            target_host = host_override or scenario.network.server_ip
            target_port = port_override or scenario.network.port
            tls_presence = scenario.server.tls_presence
            starttls_enforcement = scenario.client.starttls_enforcement
            auth_outcome = scenario.client.auth_outcome
        elif isinstance(scenario, dict):
            scenario_id = scenario.get("scenario_id", "UNKNOWN")
            client_tls = scenario.get("client_tls", {})
            net = scenario.get("network", {})
            srv = scenario.get("server_tls", {})
            target_host = host_override or net.get("server_ip", "172.28.0.11")
            target_port = port_override or net.get("port", 143)
            tls_presence = srv.get("tls_presence", "none")
            starttls_enforcement = client_tls.get("starttls_enforcement", "none")
            auth_outcome = client_tls.get("auth_outcome", "none")
        else:
            raise TypeError(f"Unsupported scenario type: {type(scenario)}")

        sni = client_tls.get("sni") or "mail.test.local"

        transcript: List[Dict[str, Any]] = []
        raw_sock: Optional[socket.socket] = None
        active_sock: Optional[socket.socket | ssl.SSLSocket] = None

        tls_negotiated = False
        tls_version: Optional[str] = None
        cipher: Optional[Tuple[str, str, int]] = None
        peer_cert: Optional[bytes] = None

        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(timeout)

            if source_ip:
                raw_sock.bind((source_ip, 0))

            raw_sock.connect((target_host, target_port))
            active_sock = raw_sock

            # ------------------------------------------------------------------
            # Scenario Path A: Implicit TLS (port 993 / 1143)
            # ------------------------------------------------------------------
            if tls_presence == "implicit-TLS":
                ctx = SMTPClient.build_ssl_context(client_tls)
                ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=sni)
                active_sock = ssl_sock

                tls_negotiated = True
                tls_version = ssl_sock.version()
                cipher = ssl_sock.cipher()
                peer_cert = ssl_sock.getpeercert(binary_form=True)

                # Read greeting banner (* OK ...)
                greeting_line = self._read_line(active_sock)
                transcript.append({
                    "direction": "in",
                    "text": greeting_line.rstrip("\r\n"),
                    "timestamp": time.time(),
                })
                if not greeting_line.strip().startswith("* OK"):
                    return ClientResult(
                        scenario_id=scenario_id,
                        success=False,
                        tls_negotiated=True,
                        expected_condition="UNEXPECTED_BANNER",
                        tls_version=tls_version,
                        cipher=cipher,
                        peer_certificate_der=peer_cert,
                        transcript=transcript,
                        error=f"Unexpected greeting: {greeting_line.strip()}",
                    )

                # Post-TLS authentication if specified
                if auth_outcome == "post-TLS-encrypted":
                    t_login = self._next_tag()
                    self._send_command(active_sock, t_login, f"LOGIN {self.username} {self.password}", transcript)
                    login_status, _ = self._read_imap_response(active_sock, t_login, transcript)
                    if login_status != "OK":
                        return ClientResult(
                            scenario_id=scenario_id,
                            success=False,
                            tls_negotiated=True,
                            expected_condition="AUTH_FAILED",
                            tls_version=tls_version,
                            cipher=cipher,
                            peer_certificate_der=peer_cert,
                            transcript=transcript,
                            error=f"LOGIN failed with status {login_status}",
                        )

                # Clean LOGOUT
                t_logout = self._next_tag()
                self._send_command(active_sock, t_logout, "LOGOUT", transcript)
                self._read_imap_response(active_sock, t_logout, transcript)

                return ClientResult(
                    scenario_id=scenario_id,
                    success=True,
                    tls_negotiated=True,
                    expected_condition="NORMAL",
                    tls_version=tls_version,
                    cipher=cipher,
                    peer_certificate_der=peer_cert,
                    transcript=transcript,
                )

            # ------------------------------------------------------------------
            # Scenario Path B: Cleartext IMAP (port 143)
            # ------------------------------------------------------------------
            elif tls_presence == "none":
                # Read greeting banner (* OK ...)
                greeting_line = self._read_line(active_sock)
                transcript.append({
                    "direction": "in",
                    "text": greeting_line.rstrip("\r\n"),
                    "timestamp": time.time(),
                })
                if not greeting_line.strip().startswith("* OK"):
                    return ClientResult(
                        scenario_id=scenario_id,
                        success=False,
                        tls_negotiated=False,
                        expected_condition="UNEXPECTED_BANNER",
                        transcript=transcript,
                        error=f"Unexpected greeting: {greeting_line.strip()}",
                    )

                # Query capabilities
                t_cap = self._next_tag()
                self._send_command(active_sock, t_cap, "CAPABILITY", transcript)
                self._read_imap_response(active_sock, t_cap, transcript)

                # Plaintext auth attempt if scenario specifies it (e.g. PCAP-062)
                if auth_outcome == "plaintext-attempted":
                    t_login = self._next_tag()
                    self._send_command(active_sock, t_login, f"LOGIN {self.username} {self.password}", transcript)
                    self._read_imap_response(active_sock, t_login, transcript)

                # Clean LOGOUT
                t_logout = self._next_tag()
                self._send_command(active_sock, t_logout, "LOGOUT", transcript)
                self._read_imap_response(active_sock, t_logout, transcript)

                return ClientResult(
                    scenario_id=scenario_id,
                    success=True,
                    tls_negotiated=False,
                    expected_condition="CLEARTEXT_COMPLETED",
                    transcript=transcript,
                )

            # ------------------------------------------------------------------
            # Scenario Path C: STARTTLS Negotiation (port 143)
            # ------------------------------------------------------------------
            elif tls_presence == "STARTTLS-upgraded":
                # Read greeting banner (* OK ...)
                greeting_line = self._read_line(active_sock)
                transcript.append({
                    "direction": "in",
                    "text": greeting_line.rstrip("\r\n"),
                    "timestamp": time.time(),
                })
                if not greeting_line.strip().startswith("* OK"):
                    return ClientResult(
                        scenario_id=scenario_id,
                        success=False,
                        tls_negotiated=False,
                        expected_condition="UNEXPECTED_BANNER",
                        transcript=transcript,
                        error=f"Unexpected greeting: {greeting_line.strip()}",
                    )

                # Query capabilities to verify STARTTLS advertisement
                t_cap = self._next_tag()
                self._send_command(active_sock, t_cap, "CAPABILITY", transcript)
                _, cap_lines = self._read_imap_response(active_sock, t_cap, transcript)

                starttls_offered = False
                for cl in [greeting_line] + cap_lines:
                    if "STARTTLS" in cl.upper():
                        starttls_offered = True
                        break

                if starttls_offered:
                    t_stls = self._next_tag()
                    # Trailing space ensures Wireshark's IMAP dissector (packet-imap.c) tokenizes command name
                    self._send_command(active_sock, t_stls, "STARTTLS ", transcript)
                    stls_status, _ = self._read_imap_response(active_sock, t_stls, transcript)
                    if stls_status == "OK":
                        ctx = SMTPClient.build_ssl_context(client_tls)
                        ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=sni)
                        active_sock = ssl_sock

                        tls_negotiated = True
                        tls_version = ssl_sock.version()
                        cipher = ssl_sock.cipher()
                        peer_cert = ssl_sock.getpeercert(binary_form=True)

                        # RFC 3501 §6.2.1: Client SHOULD send CAPABILITY post-TLS
                        t_postcap = self._next_tag()
                        self._send_command(active_sock, t_postcap, "CAPABILITY", transcript)
                        self._read_imap_response(active_sock, t_postcap, transcript)

                        # Post-TLS authentication if specified
                        if auth_outcome == "post-TLS-encrypted":
                            t_login = self._next_tag()
                            self._send_command(active_sock, t_login, f"LOGIN {self.username} {self.password}", transcript)
                            self._read_imap_response(active_sock, t_login, transcript)

                        # Clean LOGOUT
                        t_logout = self._next_tag()
                        self._send_command(active_sock, t_logout, "LOGOUT", transcript)
                        self._read_imap_response(active_sock, t_logout, transcript)

                        return ClientResult(
                            scenario_id=scenario_id,
                            success=True,
                            tls_negotiated=True,
                            expected_condition="NORMAL",
                            tls_version=tls_version,
                            cipher=cipher,
                            peer_certificate_der=peer_cert,
                            transcript=transcript,
                        )
                    else:
                        return ClientResult(
                            scenario_id=scenario_id,
                            success=False,
                            tls_negotiated=False,
                            expected_condition="STARTTLS_REJECTED",
                            transcript=transcript,
                            error=f"STARTTLS rejected with status {stls_status}",
                        )
                else:
                    if starttls_enforcement == "mandatory_abort":
                        t_logout = self._next_tag()
                        self._send_command(active_sock, t_logout, "LOGOUT", transcript)
                        self._read_imap_response(active_sock, t_logout, transcript)
                        return ClientResult(
                            scenario_id=scenario_id,
                            success=True,
                            tls_negotiated=False,
                            expected_condition="MANDATORY_ABORT",
                            transcript=transcript,
                        )
                    else:
                        t_logout = self._next_tag()
                        self._send_command(active_sock, t_logout, "LOGOUT", transcript)
                        self._read_imap_response(active_sock, t_logout, transcript)
                        return ClientResult(
                            scenario_id=scenario_id,
                            success=True,
                            tls_negotiated=False,
                            expected_condition="NO_STARTTLS_ADVERTISED",
                            transcript=transcript,
                        )
            else:
                raise ValueError(f"Unknown tls_presence: {tls_presence!r}")

        except (ssl.SSLError, socket.error, TimeoutError, OSError) as exc:
            return ClientResult(
                scenario_id=scenario_id,
                success=False,
                tls_negotiated=tls_negotiated,
                expected_condition="SOCKET_OR_SSL_ERROR",
                tls_version=tls_version,
                cipher=cipher,
                peer_certificate_der=peer_cert,
                transcript=transcript,
                error=str(exc),
            )
        finally:
            if active_sock:
                try:
                    active_sock.close()
                except Exception:
                    pass
            elif raw_sock:
                try:
                    raw_sock.close()
                except Exception:
                    pass


class POP3Client:
    """
    Deterministic, line-oriented POP3 client designed for testbed PCAP generation.
    Conforms to RFC 1939 (POP3) and RFC 2595 (Using TLS with IMAP, POP3 and ACAP).
    """

    def __init__(
        self,
        username: str = "user@test.local",
        password: str = "password",
    ):
        self.username = username
        self.password = password

    def _read_line(self, sock: socket.socket | ssl.SSLSocket) -> str:
        """
        Read a single CR-LF terminated line from the socket.
        """
        buffer = bytearray()
        while True:
            chunk = sock.recv(1)
            if not chunk:
                if buffer:
                    break
                raise ConnectionResetError("Remote server closed connection unexpectedly")
            buffer.extend(chunk)
            if buffer.endswith(b"\r\n") or buffer.endswith(b"\n"):
                break
        return buffer.decode("latin-1")

    def _read_pop3_response(
        self,
        sock: socket.socket | ssl.SSLSocket,
        transcript: List[Dict[str, Any]],
        multiline: bool = False,
    ) -> Tuple[str, List[str]]:
        """
        Read a complete POP3 response (single-line or multiline per RFC 1939 / RFC 2449).

        Single-line responses start with +OK or -ERR:
            +OK Dovecot ready.
            -ERR Unknown command.

        Multiline responses (e.g. for CAPA) start with +OK, contain intermediate
        lines, and terminate with a line containing only a dot:
            +OK Capability list follows
            CAPA
            STLS
            .
        Note: If a command expected to return multiline returns -ERR, it is single-line.
        """
        lines: List[str] = []
        status = "-ERR"

        # 1. Read first line
        first_line = self._read_line(sock)
        transcript.append({
            "direction": "in",
            "text": first_line.rstrip("\r\n"),
            "timestamp": time.time(),
        })
        lines.append(first_line)

        clean = first_line.strip()
        if clean.startswith("+OK"):
            status = "+OK"
        elif clean.startswith("-ERR"):
            status = "-ERR"

        # If multiline and first line was +OK, read until dot line
        if multiline and status == "+OK":
            while True:
                line = self._read_line(sock)
                transcript.append({
                    "direction": "in",
                    "text": line.rstrip("\r\n"),
                    "timestamp": time.time(),
                })
                lines.append(line)
                if line.strip() == ".":
                    break

        return status, lines

    def _send_command(
        self,
        sock: socket.socket | ssl.SSLSocket,
        cmd: str,
        transcript: List[Dict[str, Any]],
    ) -> None:
        """
        Send a CRLF-terminated POP3 command to the server and record in transcript.
        """
        wire = f"{cmd}\r\n".encode("latin-1")
        sock.sendall(wire)
        transcript.append({
            "direction": "out",
            "text": cmd,
            "timestamp": time.time(),
        })

    def execute(
        self,
        scenario: StagedScenario | ScenarioSpec | Dict[str, Any],
        host_override: Optional[str] = None,
        port_override: Optional[int] = None,
        source_ip: Optional[str] = None,
        timeout: float = 6.0,
    ) -> ClientResult:
        """
        Execute deterministic POP3 protocol interaction based on scenario spec.
        """
        if isinstance(scenario, StagedScenario):
            scenario_id = scenario.scenario_id
            manifest = scenario.manifest
            client_tls = manifest.get("client_tls", {})
            net = manifest.get("network", {})
            srv = manifest.get("server_tls", {})
            target_host = host_override or net.get("server_ip", "172.28.0.11")
            target_port = port_override or net.get("port", 110)
            tls_presence = srv.get("tls_presence", "none")
            starttls_enforcement = client_tls.get("starttls_enforcement", "none")
            auth_outcome = client_tls.get("auth_outcome", "none")
        elif isinstance(scenario, ScenarioSpec):
            scenario_id = scenario.scenario_id
            client_tls = derive_client_tls_config(scenario)
            target_host = host_override or scenario.network.server_ip
            target_port = port_override or scenario.network.port
            tls_presence = scenario.server.tls_presence
            starttls_enforcement = scenario.client.starttls_enforcement
            auth_outcome = scenario.client.auth_outcome
        elif isinstance(scenario, dict):
            scenario_id = scenario.get("scenario_id", "UNKNOWN")
            client_tls = scenario.get("client_tls", {})
            net = scenario.get("network", {})
            srv = scenario.get("server_tls", {})
            target_host = host_override or net.get("server_ip", "172.28.0.11")
            target_port = port_override or net.get("port", 110)
            tls_presence = srv.get("tls_presence", "none")
            starttls_enforcement = client_tls.get("starttls_enforcement", "none")
            auth_outcome = client_tls.get("auth_outcome", "none")
        else:
            raise TypeError(f"Unsupported scenario type: {type(scenario)}")

        sni = client_tls.get("sni") or "mail.test.local"

        transcript: List[Dict[str, Any]] = []
        raw_sock: Optional[socket.socket] = None
        active_sock: Optional[socket.socket | ssl.SSLSocket] = None

        tls_negotiated = False
        tls_version: Optional[str] = None
        cipher: Optional[Tuple[str, str, int]] = None
        peer_cert: Optional[bytes] = None

        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(timeout)

            if source_ip:
                raw_sock.bind((source_ip, 0))

            raw_sock.connect((target_host, target_port))
            active_sock = raw_sock

            # ------------------------------------------------------------------
            # Scenario Path A: Implicit TLS (port 995 / 1110)
            # ------------------------------------------------------------------
            if tls_presence == "implicit-TLS":
                ctx = build_client_ssl_context(client_tls)
                ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=sni)
                active_sock = ssl_sock

                tls_negotiated = True
                tls_version = ssl_sock.version()
                cipher = ssl_sock.cipher()
                peer_cert = ssl_sock.getpeercert(binary_form=True)

                # Read greeting banner (+OK ...)
                status, _ = self._read_pop3_response(active_sock, transcript, multiline=False)
                if status != "+OK":
                    return ClientResult(
                        scenario_id=scenario_id,
                        success=False,
                        tls_negotiated=True,
                        expected_condition="UNEXPECTED_BANNER",
                        tls_version=tls_version,
                        cipher=cipher,
                        peer_certificate_der=peer_cert,
                        transcript=transcript,
                        error="Implicit TLS greeting did not start with +OK",
                    )

                # Post-TLS authentication if specified
                if auth_outcome == "post-TLS-encrypted":
                    self._send_command(active_sock, f"USER {self.username}", transcript)
                    u_stat, _ = self._read_pop3_response(active_sock, transcript, multiline=False)
                    if u_stat != "+OK":
                        return ClientResult(
                            scenario_id=scenario_id,
                            success=False,
                            tls_negotiated=True,
                            expected_condition="AUTH_FAILED",
                            tls_version=tls_version,
                            cipher=cipher,
                            peer_certificate_der=peer_cert,
                            transcript=transcript,
                            error=f"USER command failed with status {u_stat}",
                        )
                    self._send_command(active_sock, f"PASS {self.password}", transcript)
                    p_stat, _ = self._read_pop3_response(active_sock, transcript, multiline=False)
                    if p_stat != "+OK":
                        return ClientResult(
                            scenario_id=scenario_id,
                            success=False,
                            tls_negotiated=True,
                            expected_condition="AUTH_FAILED",
                            tls_version=tls_version,
                            cipher=cipher,
                            peer_certificate_der=peer_cert,
                            transcript=transcript,
                            error=f"PASS command failed with status {p_stat}",
                        )

                # Clean QUIT
                self._send_command(active_sock, "QUIT", transcript)
                self._read_pop3_response(active_sock, transcript, multiline=False)

                return ClientResult(
                    scenario_id=scenario_id,
                    success=True,
                    tls_negotiated=True,
                    expected_condition="NORMAL",
                    tls_version=tls_version,
                    cipher=cipher,
                    peer_certificate_der=peer_cert,
                    transcript=transcript,
                )

            # ------------------------------------------------------------------
            # Scenario Path B: Cleartext POP3 (port 110)
            # ------------------------------------------------------------------
            elif tls_presence == "none":
                # Read greeting banner (+OK ...)
                status, _ = self._read_pop3_response(active_sock, transcript, multiline=False)
                if status != "+OK":
                    return ClientResult(
                        scenario_id=scenario_id,
                        success=False,
                        tls_negotiated=False,
                        expected_condition="UNEXPECTED_BANNER",
                        transcript=transcript,
                        error="Cleartext greeting did not start with +OK",
                    )

                # Query capabilities
                self._send_command(active_sock, "CAPA", transcript)
                self._read_pop3_response(active_sock, transcript, multiline=True)

                # Plaintext auth attempt if scenario specifies it (e.g. PCAP-063)
                if auth_outcome == "plaintext-attempted":
                    self._send_command(active_sock, f"USER {self.username}", transcript)
                    self._read_pop3_response(active_sock, transcript, multiline=False)
                    self._send_command(active_sock, f"PASS {self.password}", transcript)
                    self._read_pop3_response(active_sock, transcript, multiline=False)

                # Clean QUIT
                self._send_command(active_sock, "QUIT", transcript)
                self._read_pop3_response(active_sock, transcript, multiline=False)

                return ClientResult(
                    scenario_id=scenario_id,
                    success=True,
                    tls_negotiated=False,
                    expected_condition="CLEARTEXT_COMPLETED",
                    transcript=transcript,
                )

            # ------------------------------------------------------------------
            # Scenario Path C: STLS Upgrade (RFC 2595, port 110)
            # ------------------------------------------------------------------
            elif tls_presence == "STARTTLS-upgraded":
                # Read greeting banner (+OK ...)
                status, _ = self._read_pop3_response(active_sock, transcript, multiline=False)
                if status != "+OK":
                    return ClientResult(
                        scenario_id=scenario_id,
                        success=False,
                        tls_negotiated=False,
                        expected_condition="UNEXPECTED_BANNER",
                        transcript=transcript,
                        error="Cleartext greeting did not start with +OK",
                    )

                # Query capabilities to verify STLS advertisement
                self._send_command(active_sock, "CAPA", transcript)
                capa_status, capa_lines = self._read_pop3_response(active_sock, transcript, multiline=True)

                stls_offered = False
                if capa_status == "+OK":
                    for cl in capa_lines:
                        if "STLS" in cl.strip().upper():
                            stls_offered = True
                            break

                if stls_offered:
                    self._send_command(active_sock, "STLS", transcript)
                    stls_status, _ = self._read_pop3_response(active_sock, transcript, multiline=False)
                    if stls_status == "+OK":
                        ctx = build_client_ssl_context(client_tls)
                        ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=sni)
                        active_sock = ssl_sock

                        tls_negotiated = True
                        tls_version = ssl_sock.version()
                        cipher = ssl_sock.cipher()
                        peer_cert = ssl_sock.getpeercert(binary_form=True)

                        # Post-TLS CAPA (RFC 2595 §4)
                        self._send_command(active_sock, "CAPA", transcript)
                        self._read_pop3_response(active_sock, transcript, multiline=True)

                        # Post-TLS authentication if specified
                        if auth_outcome == "post-TLS-encrypted":
                            self._send_command(active_sock, f"USER {self.username}", transcript)
                            self._read_pop3_response(active_sock, transcript, multiline=False)
                            self._send_command(active_sock, f"PASS {self.password}", transcript)
                            self._read_pop3_response(active_sock, transcript, multiline=False)

                        # Clean QUIT
                        self._send_command(active_sock, "QUIT", transcript)
                        self._read_pop3_response(active_sock, transcript, multiline=False)

                        return ClientResult(
                            scenario_id=scenario_id,
                            success=True,
                            tls_negotiated=True,
                            expected_condition="NORMAL",
                            tls_version=tls_version,
                            cipher=cipher,
                            peer_certificate_der=peer_cert,
                            transcript=transcript,
                        )
                    else:
                        return ClientResult(
                            scenario_id=scenario_id,
                            success=False,
                            tls_negotiated=False,
                            expected_condition="STARTTLS_REJECTED",
                            transcript=transcript,
                            error=f"STLS rejected with status {stls_status}",
                        )
                else:
                    if starttls_enforcement == "mandatory_abort":
                        self._send_command(active_sock, "QUIT", transcript)
                        self._read_pop3_response(active_sock, transcript, multiline=False)
                        return ClientResult(
                            scenario_id=scenario_id,
                            success=True,
                            tls_negotiated=False,
                            expected_condition="MANDATORY_ABORT",
                            transcript=transcript,
                        )
                    elif starttls_enforcement == "opportunistic_downgrade":
                        self._send_command(active_sock, "QUIT", transcript)
                        self._read_pop3_response(active_sock, transcript, multiline=False)
                        return ClientResult(
                            scenario_id=scenario_id,
                            success=True,
                            tls_negotiated=False,
                            expected_condition="OPPORTUNISTIC_DOWNGRADE",
                            transcript=transcript,
                        )
                    else:
                        self._send_command(active_sock, "QUIT", transcript)
                        self._read_pop3_response(active_sock, transcript, multiline=False)
                        return ClientResult(
                            scenario_id=scenario_id,
                            success=True,
                            tls_negotiated=False,
                            expected_condition="NO_STARTTLS_ADVERTISED",
                            transcript=transcript,
                        )
            else:
                raise ValueError(f"Unknown tls_presence: {tls_presence!r}")

        except (ssl.SSLError, socket.error, TimeoutError, OSError) as exc:
            return ClientResult(
                scenario_id=scenario_id,
                success=False,
                tls_negotiated=tls_negotiated,
                expected_condition="SOCKET_OR_SSL_ERROR",
                tls_version=tls_version,
                cipher=cipher,
                peer_certificate_der=peer_cert,
                transcript=transcript,
                error=str(exc),
            )
        finally:
            if active_sock:
                try:
                    active_sock.close()
                except Exception:
                    pass
            elif raw_sock:
                try:
                    raw_sock.close()
                except Exception:
                    pass


