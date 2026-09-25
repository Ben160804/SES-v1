#!/usr/bin/env python3
"""
Dedicated TLS Downgrade Sentinel Server Harness (PCAP-109).
Listens on port 465 (SMTPS implicit-TLS).
Negotiates TLS 1.2 and embeds the RFC 8446 §4.1.3 downgrade protection sentinel (DOWNGRD\\x01)
in ServerHello.random.
"""

import argparse
import ctypes
import mmap
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


def patch_libssl_downgrade_sentinel():
    libssl_path = None
    base_addr = None
    with open("/proc/self/maps") as f:
        for line in f:
            if "libssl.so" in line and "/" in line:
                parts = line.split()
                if base_addr is None:
                    base_addr = int(parts[0].split("-")[0], 16)
                for part in parts:
                    if part.startswith("/") and "libssl.so" in part:
                        libssl_path = part
                        break
            if libssl_path and base_addr is not None:
                break

    if not libssl_path or base_addr is None:
        return

    with open(libssl_path, "rb") as f:
        data = f.read()

    # Search for patterns where downgrade sentinel check occurs:
    # Pattern 1 (Debian/Ubuntu x86_64 OpenSSL 3.x): cmp $1, %ebp; je ...; cmp $2, %ebp
    pattern1 = b"\x83\xfd\x01\x74\x6b\x83\xfd\x02"
    # Pattern 2 (Arch Linux x86_64 OpenSSL 3.x): cmp $1, %r12d; je ...; cmp $2, %r12d
    pattern2 = b"\x41\x83\xfc\x01\x74\x51\x41\x83\xfc\x02"

    offset = None
    if pattern1 in data:
        offset = data.find(pattern1) + 3
    elif pattern2 in data:
        offset = data.find(pattern2) + 4

    if offset is not None:
        libc = ctypes.CDLL(None)
        srv_target = base_addr + offset
        srv_page = srv_target & ~(mmap.PAGESIZE - 1)
        libc.mprotect(ctypes.c_void_p(srv_page), mmap.PAGESIZE * 2, 7)
        ctypes.memmove(srv_target, b"\xeb", 1)


def run_server(cert_path: str, key_path: str, listen_host: str = "0.0.0.0", port: int = 465, single_session: bool = True):
    patch_libssl_downgrade_sentinel()

    _CH_CB = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.c_void_p)
    libssl = ctypes.CDLL("libssl.so.3")
    libssl.SSL_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_long, ctypes.c_void_p]
    libssl.SSL_ctrl.restype = ctypes.c_long
    libssl.SSL_CTX_set_client_hello_cb.argtypes = [ctypes.c_void_p, _CH_CB, ctypes.c_void_p]

    @_CH_CB
    def _client_hello_cb(s, al, arg):
        # Force server to select TLS 1.2
        libssl.SSL_ctrl(s, 124, 0x0303, None)
        return 1

    server_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    server_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    server_ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    pctx = _PySSLContext.from_address(id(server_ctx))
    server_ctx._cb = _client_hello_cb
    libssl.SSL_CTX_set_client_hello_cb(pctx.ctx, _client_hello_cb, None)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((listen_host, port))
    sock.listen(5)
    print(f"[downgrade_server] Listening on {listen_host}:{port}...", flush=True)

    while True:
        try:
            cs, addr = sock.accept()
            print(f"[downgrade_server] Accepted connection from {addr}", flush=True)
            ss = server_ctx.wrap_socket(cs, server_side=True)
            print(f"[downgrade_server] Handshake complete: version={ss.version()}, cipher={ss.cipher()}", flush=True)

            ss.sendall(b"220 mail.securemailscope.local ESMTP Postfix\r\n")
            while True:
                line = ss.recv(1024)
                if not line:
                    break
                cmd = line.strip().upper()
                if cmd.startswith(b"EHLO") or cmd.startswith(b"HELO"):
                    ss.sendall(b"250-mail.securemailscope.local\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-AUTH PLAIN LOGIN\r\n250-ENHANCEDSTATUSCODES\r\n250 8BITMIME\r\n")
                elif cmd.startswith(b"AUTH"):
                    ss.sendall(b"235 2.7.0 Authentication successful\r\n")
                elif cmd.startswith(b"MAIL FROM:"):
                    ss.sendall(b"250 2.1.0 Ok\r\n")
                elif cmd.startswith(b"RCPT TO:"):
                    ss.sendall(b"250 2.1.5 Ok\r\n")
                elif cmd.startswith(b"QUIT"):
                    ss.sendall(b"221 2.0.0 Bye\r\n")
                    break
                else:
                    ss.sendall(b"250 Ok\r\n")

            ss.close()
            if single_session:
                break
        except Exception as exc:
            print(f"[downgrade_server] Error: {exc}", flush=True)
            if single_session:
                break

    sock.close()
    print("[downgrade_server] Finished.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=465)
    parser.add_argument("--single", action="store_true", default=False)
    args = parser.parse_args()

    run_server(args.cert, args.key, args.host, args.port, args.single)
