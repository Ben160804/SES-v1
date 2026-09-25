#!/usr/bin/env python3
"""
testbed/legacy/legacy_ed25519_client.py
=======================================
Dedicated RFC 8422 TLS 1.0 SMTP Client for PCAP-083.

Features:
  - Real RFC 5280 certificate chain & trust store validation:
    Verifies leaf self-signature, temporal validity, SNI match, and
    trust store anchoring (confirming TRUSTED_SELF_SIGNED) before proceeding.
  - Ephemeral secp256r1 (P-256) ECDH key agreement.
  - Verification of ServerKeyExchange RFC 8422 §5.4 Ed25519 signature.
  - Verification of Finished verify_data and encrypted SMTP interaction.
"""

import argparse
from datetime import datetime, timezone
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


def verify_peer_certificate(cert: x509.Certificate, trust_store_pem: str, expected_hostname: str):
    """
    Real RFC 5280 Certificate Chain & Trust Anchor Validation (Condition 1).
    Validates:
      1. Self-signature verification
      2. Subject == Issuer (self-signed shape)
      3. Temporal validity window
      4. Hostname matching (SAN DNS / CN)
      5. Trust store anchor lookup -> TRUSTED_SELF_SIGNED
    """
    pubkey = cert.public_key()
    if not isinstance(pubkey, ed25519.Ed25519PublicKey):
        raise ValueError(f"Expected Ed25519 peer public key, got {type(pubkey)}")

    # 1. Cryptographic self-signature check
    try:
        pubkey.verify(cert.signature, cert.tbs_certificate_bytes)
    except Exception as e:
        raise ValueError(f"Peer certificate self-signature verification failed: {e}") from e

    # 2. Issuer == Subject
    if cert.issuer != cert.subject:
        raise ValueError("Peer certificate is not self-signed (issuer != subject)")

    # 3. Temporal validity check
    now = datetime.now(timezone.utc)
    if now < cert.not_valid_before_utc:
        raise ValueError(f"Peer certificate not yet valid (valid from {cert.not_valid_before_utc})")
    if now > cert.not_valid_after_utc:
        raise ValueError(f"Peer certificate expired (valid until {cert.not_valid_after_utc})")

    # 4. Hostname verification
    san_ext = None
    try:
        san_ext = cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        pass

    matched_host = False
    if san_ext:
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)
        if expected_hostname in dns_names:
            matched_host = True

    if not matched_host:
        cns = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if cns and cns[0].value == expected_hostname:
            matched_host = True

    if not matched_host:
        raise ValueError(f"Hostname match failed: {expected_hostname} not found in peer certificate")

    # 5. Trust Store Anchor Verification
    trusted_certs = x509.load_pem_x509_certificates(trust_store_pem.encode())
    if not trusted_certs:
        raise ValueError("Trust store is empty; self-signed certificate is UNTRUSTED")

    peer_der = cert.public_bytes(serialization.Encoding.DER)
    is_trusted = any(tc.public_bytes(serialization.Encoding.DER) == peer_der for tc in trusted_certs)

    if not is_trusted:
        raise ValueError("Peer self-signed certificate not found in active trust store (UNTRUSTED_SELF_SIGNED)")

    print(f"[legacy_ed25519_client] Real trust validation passed: TRUSTED_SELF_SIGNED for {expected_hostname}", flush=True)


def run_client(host: str, port: int, trust_store_path: str, expected_hostname: str = "mail.test.local"):
    trust_pem = Path(trust_store_path).read_text()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10.0)
    sock.connect((host, port))
    tls = TLSRecordLayer(sock)
    transcript = bytearray()

    # 1. Send ClientHello offering 0xC009 with P-256 (secp256r1)
    client_random = int(time.time()).to_bytes(4, "big") + os.urandom(28)
    sni_bytes = expected_hostname.encode()
    sni_payload = struct.pack("!HBH", len(sni_bytes) + 3, 0, len(sni_bytes)) + sni_bytes
    ext_sni = struct.pack("!HH", 0, len(sni_payload)) + sni_payload
    groups_payload = struct.pack("!HH", 2, 0x0017)  # secp256r1
    ext_groups = struct.pack("!HH", 10, len(groups_payload)) + groups_payload
    ec_pf_payload = struct.pack("!BB", 1, 0)        # uncompressed
    ext_ec_pf = struct.pack("!HH", 11, len(ec_pf_payload)) + ec_pf_payload

    exts = ext_sni + ext_groups + ext_ec_pf
    chello_body = (
        struct.pack("!H", 0x0301) + client_random + b"\x00" +
        struct.pack("!HHH", 4, 0xC009, 0xC00A) +
        struct.pack("!BB", 1, 0) +
        struct.pack("!H", len(exts)) + exts
    )
    chello_msg = bytes([1]) + len(chello_body).to_bytes(3, "big") + chello_body
    transcript.extend(chello_msg)
    tls.send_record(22, chello_msg)

    # 2. Recv ServerHello
    ctype, shello = tls.recv_record()
    if ctype != 22 or shello[0] != 2:
        raise ValueError(f"Expected ServerHello, got ctype={ctype}")
    transcript.extend(shello)
    server_random = shello[6:38]
    selected_cipher = struct.unpack("!H", shello[39:41])[0]
    if selected_cipher != 0xC009:
        raise ValueError(f"Unexpected cipher selected: {hex(selected_cipher)}")

    # 3. Recv Certificate & Perform Real Trust Store Verification
    ctype, cert_msg = tls.recv_record()
    if ctype != 22 or cert_msg[0] != 11:
        raise ValueError(f"Expected Certificate, got ctype={ctype}")
    transcript.extend(cert_msg)

    first_cert_len = int.from_bytes(cert_msg[7:10], "big")
    recvd_cert_der = cert_msg[10:10 + first_cert_len]
    recvd_cert = x509.load_der_x509_certificate(recvd_cert_der)

    # Real RFC 5280 trust verification against staged trust store
    verify_peer_certificate(recvd_cert, trust_pem, expected_hostname)
    server_ed_pub = recvd_cert.public_key()

    # 4. Recv ServerKeyExchange & Verify RFC 8422 §5.4 Ed25519 Signature
    ctype, ske_msg = tls.recv_record()
    if ctype != 22 or ske_msg[0] != 12:
        raise ValueError(f"Expected ServerKeyExchange, got ctype={ctype}")
    transcript.extend(ske_msg)
    ske_body = ske_msg[4:]

    curve_type = ske_body[0]
    named_curve = struct.unpack("!H", ske_body[1:3])[0]
    point_len = ske_body[3]
    server_point = ske_body[4:4 + point_len]
    if curve_type != 3 or named_curve != 0x0017 or point_len != 65:
        raise ValueError(f"Invalid ServerECDHParams: curve_type={curve_type}, curve={hex(named_curve)}, len={point_len}")

    params = ske_body[:4 + point_len]
    sig_len = struct.unpack("!H", ske_body[4 + point_len:6 + point_len])[0]
    sig_bytes = ske_body[6 + point_len:6 + point_len + sig_len]
    if sig_len != 64:
        raise ValueError(f"Unexpected Ed25519 signature length: {sig_len}")

    # Cryptographically verify Ed25519 signature over ClientHello.random + ServerHello.random + params
    sig_input = client_random + server_random + params
    server_ed_pub.verify(sig_bytes, sig_input)

    # 5. Recv ServerHelloDone
    ctype, shd_msg = tls.recv_record()
    if ctype != 22 or shd_msg[0] != 14:
        raise ValueError(f"Expected ServerHelloDone, got ctype={ctype}")
    transcript.extend(shd_msg)

    # 6. Ephemeral Key Generation & ClientKeyExchange
    client_ec_priv = ec.generate_private_key(ec.SECP256R1())
    client_ec_pub = client_ec_priv.public_key()
    client_ec_pub_bytes = client_ec_pub.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
    )
    ckex_body = struct.pack("!B", len(client_ec_pub_bytes)) + client_ec_pub_bytes
    ckex_msg = bytes([16]) + len(ckex_body).to_bytes(3, "big") + ckex_body
    transcript.extend(ckex_msg)
    tls.send_record(22, ckex_msg)

    # Compute Premaster Secret
    server_ec_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), server_point)
    client_shared = client_ec_priv.exchange(ec.ECDH(), server_ec_pub)

    # 7. Send Client ChangeCipherSpec & Finished
    tls.sock.sendall(struct.pack("!BHH", 20, 0x0301, 1) + b"\x01")
    master_secret = tls10_prf(client_shared, b"master secret", client_random + server_random, 48)
    key_block = tls10_prf(master_secret, b"key expansion", server_random + client_random, 104)

    tls.write_mac_key = key_block[0:20]
    tls.write_enc_key = key_block[40:56]
    tls.write_iv = key_block[72:88]
    tls.enc_write = True

    c_verify = tls10_prf(
        master_secret, b"client finished",
        hashlib.md5(transcript).digest() + hashlib.sha1(transcript).digest(),
        12
    )
    c_fin_msg = bytes([20]) + (12).to_bytes(3, "big") + c_verify
    transcript.extend(c_fin_msg)
    tls.send_record(22, c_fin_msg)

    # 8. Recv Server ChangeCipherSpec & Finished
    ctype, ccs = tls.recv_record()
    if ctype != 20 or ccs != b"\x01":
        raise ValueError("Expected ChangeCipherSpec from server")

    tls.read_mac_key = key_block[20:40]
    tls.read_enc_key = key_block[56:72]
    tls.read_iv = key_block[88:104]
    tls.enc_read = True

    ctype, s_fin = tls.recv_record()
    if ctype != 22 or s_fin[0] != 20:
        raise ValueError("Expected Server Finished")
    expected_s_verify = tls10_prf(
        master_secret, b"server finished",
        hashlib.md5(transcript).digest() + hashlib.sha1(transcript).digest(),
        12
    )
    if s_fin[4:16] != expected_s_verify:
        raise ValueError("Server Finished verify_data mismatch")

    # 9. Perform SMTP Interaction
    ctype, banner = tls.recv_record()
    if ctype != 23 or b"220" not in banner:
        raise ValueError(f"Expected 220 banner, got {banner}")

    tls.send_record(23, f"EHLO {expected_hostname}\r\n".encode())
    ctype, ehlo_resp = tls.recv_record()
    if ctype != 23 or b"250" not in ehlo_resp:
        raise ValueError(f"Expected 250 response, got {ehlo_resp}")

    tls.send_record(23, b"QUIT\r\n")
    ctype, quit_resp = tls.recv_record()
    if ctype != 23 or b"221" not in quit_resp:
        raise ValueError(f"Expected 221 response, got {quit_resp}")

    time.sleep(0.1)
    sock.close()
    print("[legacy_ed25519_client] Handshake and SMTP exchange completed successfully!", flush=True)


def main():
    parser = argparse.ArgumentParser(description="PCAP-083 TLS 1.0 Ed25519 SMTP Client")
    parser.add_argument("--host", default="172.28.0.40", help="Server host IP")
    parser.add_argument("--port", type=int, default=465, help="Server port")
    parser.add_argument("--trust-store", required=True, help="Path to trust store PEM")
    parser.add_argument("--sni", default="mail.test.local", help="Expected SNI hostname")
    args = parser.parse_args()

    run_client(args.host, args.port, args.trust_store, args.sni)


if __name__ == "__main__":
    main()
