#!/usr/bin/env python3
"""
testbed/legacy/legacy_ed25519_server.py
=======================================
Dedicated RFC 8422 TLS 1.0 SMTP Server Responder for PCAP-083.

Protocol Details:
  - TLS 1.0 (0x0301)
  - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xC009)
  - Leaf Certificate: Genuinely self-signed Ed25519
  - ServerKeyExchange: secp256r1 (P-256) ephemeral ECDH parameters
    + RFC 8422 §5.4 Ed25519 pure signature (NO TLS 1.2 prefix on the wire)
  - Real cryptographic ECDHE agreement, master secret derivation, and Finished verification
  - Line-oriented SMTP protocol exchange (220, EHLO, 250, QUIT, 221)
"""

import argparse
import hashlib
import hmac
import os
import socket
import struct
import sys
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def p_hash(hash_mod, secret: bytes, seed: bytes, length: int) -> bytes:
    res = bytearray()
    a = seed
    while len(res) < length:
        a = hmac.new(secret, a, hash_mod).digest()
        res.extend(hmac.new(secret, a + seed, hash_mod).digest())
    return bytes(res[:length])


def tls10_prf(secret: bytes, label: bytes, seed: bytes, length: int) -> bytes:
    label_seed = label + seed
    half_len = (len(secret) + 1) // 2
    s1 = secret[:half_len]
    s2 = secret[-half_len:]
    p_md5 = p_hash(hashlib.md5, s1, label_seed, length)
    p_sha1 = p_hash(hashlib.sha1, s2, label_seed, length)
    return bytes(a ^ b for a, b in zip(p_md5, p_sha1))


class TLSRecordLayer:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.read_seq = 0
        self.write_seq = 0
        self.enc_write = False
        self.enc_read = False
        self.write_mac_key = b""
        self.read_mac_key = b""
        self.write_enc_key = b""
        self.read_enc_key = b""
        self.write_iv = b""
        self.read_iv = b""

    def send_record(self, content_type: int, payload: bytes):
        if not self.enc_write:
            header = struct.pack("!BHH", content_type, 0x0301, len(payload))
            self.sock.sendall(header + payload)
            return

        mac = hmac.new(
            self.write_mac_key,
            struct.pack("!Q", self.write_seq) + struct.pack("!BHH", content_type, 0x0301, len(payload)) + payload,
            hashlib.sha1
        ).digest()
        self.write_seq += 1

        plaintext = payload + mac
        block_size = 16
        pad_len = block_size - (len(plaintext) % block_size)
        if pad_len == 0:
            pad_len = block_size
        padding = bytes([pad_len - 1] * pad_len)
        data = plaintext + padding

        cipher = Cipher(algorithms.AES(self.write_enc_key), modes.CBC(self.write_iv))
        enc = cipher.encryptor()
        ct = enc.update(data) + enc.finalize()
        self.write_iv = ct[-16:]

        header = struct.pack("!BHH", content_type, 0x0301, len(ct))
        self.sock.sendall(header + ct)

    def recv_record(self) -> tuple[int, bytes]:
        header = self._recv_exact(5)
        ctype, ver, length = struct.unpack("!BHH", header)
        payload = self._recv_exact(length)

        if not self.enc_read:
            return ctype, payload

        cipher = Cipher(algorithms.AES(self.read_enc_key), modes.CBC(self.read_iv))
        dec = cipher.decryptor()
        pt_mac = dec.update(payload) + dec.finalize()
        self.read_iv = payload[-16:]

        pad_len = pt_mac[-1] + 1
        pt_mac = pt_mac[:-pad_len]
        mac = pt_mac[-20:]
        pt = pt_mac[:-20]

        expected = hmac.new(
            self.read_mac_key,
            struct.pack("!Q", self.read_seq) + struct.pack("!BHH", ctype, 0x0301, len(pt)) + pt,
            hashlib.sha1
        ).digest()
        self.read_seq += 1
        if mac != expected:
            raise ValueError("TLS Record MAC verification failed")
        return ctype, pt

    def _recv_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionResetError("Remote connection closed")
            buf.extend(chunk)
        return bytes(buf)


def handle_client(conn: socket.socket, cert: x509.Certificate, server_ed_key: ed25519.Ed25519PrivateKey):
    tls = TLSRecordLayer(conn)
    transcript = bytearray()

    # 1. Recv ClientHello
    ctype, chello = tls.recv_record()
    if ctype != 22 or chello[0] != 1:
        raise ValueError(f"Expected ClientHello, got ctype={ctype}")
    transcript.extend(chello)
    client_random = chello[6:38]

    # 2. Send ServerHello
    server_random = int(time.time()).to_bytes(4, "big") + os.urandom(28)
    shello_body = struct.pack("!H", 0x0301) + server_random + b"\x00" + struct.pack("!H", 0xC009) + b"\x00"
    shello_msg = bytes([2]) + len(shello_body).to_bytes(3, "big") + shello_body
    transcript.extend(shello_msg)
    tls.send_record(22, shello_msg)

    # 3. Send Certificate
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    cert_list_bytes = len(cert_der).to_bytes(3, "big") + cert_der
    cert_msg_body = len(cert_list_bytes).to_bytes(3, "big") + cert_list_bytes
    cert_msg = bytes([11]) + len(cert_msg_body).to_bytes(3, "big") + cert_msg_body
    transcript.extend(cert_msg)
    tls.send_record(22, cert_msg)

    # 4. Generate Ephemeral P-256 ECDH & Send ServerKeyExchange
    server_ec_priv = ec.generate_private_key(ec.SECP256R1())
    server_ec_pub = server_ec_priv.public_key()
    server_ec_pub_bytes = server_ec_pub.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
    )
    # ServerECDHParams: curve_type=3 (named_curve), namedcurve=0x0017 (secp256r1), point_len=65, point=65B
    params = struct.pack("!BHB", 3, 0x0017, len(server_ec_pub_bytes)) + server_ec_pub_bytes

    # RFC 8422 §5.4: pure Ed25519 signature over ClientHello.random + ServerHello.random + params
    sig_input = client_random + server_random + params
    ed_sig = server_ed_key.sign(sig_input)

    # In TLS 1.0: opaque signature<0..2^16-1> (NO TLS 1.2 SignatureAndHashAlgorithm prefix)
    ske_body = params + struct.pack("!H", len(ed_sig)) + ed_sig
    ske_msg = bytes([12]) + len(ske_body).to_bytes(3, "big") + ske_body
    transcript.extend(ske_msg)
    tls.send_record(22, ske_msg)

    # 5. Send ServerHelloDone
    shd_msg = bytes([14, 0, 0, 0])
    transcript.extend(shd_msg)
    tls.send_record(22, shd_msg)

    # 6. Recv ClientKeyExchange
    ctype, ckex = tls.recv_record()
    if ctype != 22 or ckex[0] != 16:
        raise ValueError(f"Expected ClientKeyExchange, got ctype={ctype}")
    transcript.extend(ckex)
    client_pub_bytes = ckex[5:5 + ckex[4]]
    client_ec_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_pub_bytes)

    # Compute ECDH shared secret (32-byte x-coordinate)
    server_shared = server_ec_priv.exchange(ec.ECDH(), client_ec_pub)

    # 7. Recv Client ChangeCipherSpec
    ctype, ccs = tls.recv_record()
    if ctype != 20 or ccs != b"\x01":
        raise ValueError("Expected ChangeCipherSpec")

    # Derive TLS 1.0 Master Secret & Keys
    master_secret = tls10_prf(server_shared, b"master secret", client_random + server_random, 48)
    key_block = tls10_prf(master_secret, b"key expansion", server_random + client_random, 104)

    tls.read_mac_key = key_block[0:20]
    tls.read_enc_key = key_block[40:56]
    tls.read_iv = key_block[72:88]
    tls.enc_read = True

    # 8. Recv Client Finished
    ctype, c_fin = tls.recv_record()
    if ctype != 22 or c_fin[0] != 20:
        raise ValueError("Expected Client Finished")
    expected_c_verify = tls10_prf(
        master_secret, b"client finished",
        hashlib.md5(transcript).digest() + hashlib.sha1(transcript).digest(),
        12
    )
    if c_fin[4:16] != expected_c_verify:
        raise ValueError("Client Finished verify_data mismatch")
    transcript.extend(c_fin)

    # 9. Send Server ChangeCipherSpec & Finished
    tls.sock.sendall(struct.pack("!BHH", 20, 0x0301, 1) + b"\x01")
    tls.write_mac_key = key_block[20:40]
    tls.write_enc_key = key_block[56:72]
    tls.write_iv = key_block[88:104]
    tls.enc_write = True

    s_verify = tls10_prf(
        master_secret, b"server finished",
        hashlib.md5(transcript).digest() + hashlib.sha1(transcript).digest(),
        12
    )
    s_fin_msg = bytes([20]) + (12).to_bytes(3, "big") + s_verify
    tls.send_record(22, s_fin_msg)

    # 10. Execute Encrypted SMTP Protocol Transaction
    # S: 220 banner
    tls.send_record(23, b"220 mail.test.local ESMTP Postfix\r\n")

    # C: EHLO
    ctype, ehlo = tls.recv_record()
    if ctype == 23 and b"EHLO" in ehlo:
        tls.send_record(23, b"250-mail.test.local\r\n250 PIPELINING\r\n250 8BITMIME\r\n250 OK\r\n")

    # C: QUIT (or subsequent commands)
    ctype, cmd = tls.recv_record()
    if ctype == 23 and b"QUIT" in cmd:
        tls.send_record(23, b"221 2.0.0 Bye\r\n")

    time.sleep(0.1)


def main():
    parser = argparse.ArgumentParser(description="PCAP-083 TLS 1.0 Ed25519 SMTP Server Responder")
    parser.add_argument("--cert", required=True, help="Path to leaf certificate PEM")
    parser.add_argument("--key", required=True, help="Path to leaf private key PEM")
    parser.add_argument("--bind", default="0.0.0.0", help="Bind IP address")
    parser.add_argument("--port", type=int, default=465, help="Port to listen on")
    parser.add_argument("--single", action="store_true", help="Exit after serving one client")
    args = parser.parse_args()

    cert_data = Path(args.cert).read_bytes()
    key_data = Path(args.key).read_bytes()

    cert = x509.load_pem_x509_certificate(cert_data)
    server_ed_key = serialization.load_pem_private_key(key_data, password=None)
    if not isinstance(server_ed_key, ed25519.Ed25519PrivateKey):
        raise ValueError("Server key must be Ed25519PrivateKey")

    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind((args.bind, args.port))
    lsock.listen(5)

    print(f"[legacy_ed25519_server] Listening on {args.bind}:{args.port}", flush=True)
    print("READY", flush=True)

    try:
        while True:
            conn, addr = lsock.accept()
            print(f"[legacy_ed25519_server] Accepted connection from {addr}", flush=True)
            try:
                handle_client(conn, cert, server_ed_key)
                print(f"[legacy_ed25519_server] Successfully completed handshake & SMTP transaction with {addr}", flush=True)
            except Exception as e:
                print(f"[legacy_ed25519_server] Error handling {addr}: {e}", file=sys.stderr, flush=True)
            finally:
                conn.close()
            if args.single:
                break
    finally:
        lsock.close()


if __name__ == "__main__":
    main()
