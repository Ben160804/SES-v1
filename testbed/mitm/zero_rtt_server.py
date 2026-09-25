#!/usr/bin/env python3
"""
Dedicated TLS 1.3 0-RTT Early Data Server Harness (PCAP-122).
Listens on port 465 (SMTPS implicit-TLS).
Configures max_early_data = 16384 so session tickets issue 0-RTT allowance.
Handles:
  1. Prerequisite ticket harvest connection.
  2. Resumed 0-RTT connection.
"""

import argparse
import ctypes
import socket
import ssl
import sys
import time


class _PySSLContext(ctypes.Structure):
    _fields_ = [
        ("ob_refcnt", ctypes.c_ssize_t),
        ("ob_type", ctypes.c_void_p),
        ("ctx", ctypes.c_void_p),
    ]


def run_server(cert_path: str, key_path: str, listen_host: str = "0.0.0.0", port: int = 465):
    libssl = ctypes.CDLL("libssl.so.3")
    libssl.SSL_CTX_set_max_early_data.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    libssl.SSL_CTX_set_max_early_data.restype = ctypes.c_int
    libssl.SSL_CTX_set_recv_max_early_data.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    libssl.SSL_CTX_set_recv_max_early_data.restype = ctypes.c_int

    server_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    try:
        server_ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except Exception:
        pass
    server_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    server_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    server_ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    pctx = _PySSLContext.from_address(id(server_ctx))
    libssl.SSL_CTX_set_max_early_data(pctx.ctx, 16384)
    libssl.SSL_CTX_set_recv_max_early_data(pctx.ctx, 16384)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((listen_host, port))
    sock.listen(5)
    print(f"[zero_rtt_server] Listening on {listen_host}:{port}...", flush=True)

    # Session 1: Prerequisite ticket harvest
    cs1, addr1 = sock.accept()
    print(f"[zero_rtt_server] Connection 1 (harvest) from {addr1}", flush=True)
    ss1 = server_ctx.wrap_socket(cs1, server_side=True)
    ss1.sendall(b"220 mail.test.local ESMTP Postfix\r\n")
    try:
        data = ss1.recv(1024)
        if b"QUIT" in data.upper():
            ss1.sendall(b"221 2.0.0 Bye\r\n")
        time.sleep(0.3)
    except Exception:
        pass
    finally:
        ss1.close()
    print("[zero_rtt_server] Connection 1 closed.", flush=True)

    # Session 2: 0-RTT Resumed connection
    cs2, addr2 = sock.accept()
    print(f"[zero_rtt_server] Connection 2 (0-RTT) from {addr2}", flush=True)
    ss2 = server_ctx.wrap_socket(cs2, server_side=True)
    print(f"[zero_rtt_server] Handshake 2 complete: version={ss2.version()}, cipher={ss2.cipher()}", flush=True)
    ss2.sendall(b"220 mail.test.local ESMTP Postfix\r\n")
    try:
        while True:
            line = ss2.recv(1024)
            if not line:
                break
            cmd = line.strip().upper()
            if cmd.startswith(b"EHLO") or cmd.startswith(b"HELO"):
                ss2.sendall(b"250-mail.test.local\r\n250-AUTH PLAIN LOGIN\r\n250 DSN\r\n")
            elif cmd.startswith(b"AUTH"):
                ss2.sendall(b"235 2.7.0 Authentication successful\r\n")
            elif cmd.startswith(b"MAIL FROM:"):
                ss2.sendall(b"250 2.1.0 Ok\r\n")
            elif cmd.startswith(b"RCPT TO:"):
                ss2.sendall(b"250 2.1.5 Ok\r\n")
            elif cmd.startswith(b"QUIT"):
                ss2.sendall(b"221 2.0.0 Bye\r\n")
                break
            else:
                ss2.sendall(b"250 Ok\r\n")
    except Exception as exc:
        print(f"[zero_rtt_server] Conn 2 error: {exc}", flush=True)
    finally:
        ss2.close()

    sock.close()
    print("[zero_rtt_server] Finished.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=465)
    args = parser.parse_args()

    run_server(args.cert, args.key, args.host, args.port)
