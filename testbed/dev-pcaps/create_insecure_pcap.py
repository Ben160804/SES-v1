#!/usr/bin/env python3
"""
Generates a realistic synthetic PCAP file containing an unencrypted SMTP session
with cleartext authentication (AUTH LOGIN) and STARTTLS stripping vulnerability.
"""

import struct
import time

def create_pcap(filename="smtp_cleartext_insecure.pcap"):
    # PCAP Global Header: magic, v2.4, thiszone, sigfigs, snaplen (65535), network (1 = Ethernet)
    pcap_header = struct.pack("!IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    packets = []
    
    # Base addresses & ports
    src_mac = b"\x00\x0c\x29\x6b\x8a\x11"
    dst_mac = b"\x00\x0c\x29\x3e\x5d\x22"
    eth_type = b"\x08\x00" # IPv4
    
    client_ip = struct.pack("!BBBB", 192, 168, 1, 100)
    server_ip = struct.pack("!BBBB", 192, 168, 1, 25)
    client_port = 49152
    server_port = 25

    def make_ip_packet(src, dst, proto, payload):
        total_len = 20 + len(payload)
        ident = 54321
        flags_offset = 0x4000 # Don't fragment
        ttl = 64
        # Pseudo checksum placeholder
        hdr_no_cs = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ident, flags_offset, ttl, proto, 0, src, dst)
        
        # Calculate IP checksum
        checksum = 0
        for i in range(0, len(hdr_no_cs), 2):
            w = (hdr_no_cs[i] << 8) + hdr_no_cs[i+1]
            checksum += w
        while checksum >> 16:
            checksum = (checksum & 0xffff) + (checksum >> 16)
        checksum = ~checksum & 0xffff
        
        ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ident, flags_offset, ttl, proto, checksum, src, dst)
        return ip_hdr + payload

    def make_tcp_packet(src_p, dst_p, seq, ack, flags, data=b""):
        offset_res = (5 << 4) # 5 dwords = 20 bytes
        window = 64240
        urgent = 0
        # TCP without checksum calculation (tshark accepts 0 or ignores with checksum validation off)
        tcp_hdr = struct.pack("!HHIIBBHHH", src_p, dst_p, seq, ack, offset_res, flags, window, 0, urgent)
        return tcp_hdr + data

    # Simulated SMTP Dialog
    # 1. Server 220 banner
    # 2. Client EHLO
    # 3. Server 250 response (advertises STARTTLS)
    # 4. Client ignores STARTTLS (stripping/downgrade) and attempts AUTH LOGIN in plaintext!
    # 5. Credentials transmitted in clear
    
    seq_c = 1000
    seq_s = 5000
    
    dialog = [
        # (dir, payload, flags)
        ("S->C", b"220 mail.insecure.corp ESMTP InsecureMailServer\r\n", 0x18), # PSH, ACK
        ("C->S", b"EHLO client.victim.org\r\n", 0x18),
        ("S->C", b"250-mail.insecure.corp\r\n250-PIPELINING\r\n250-STARTTLS\r\n250-AUTH LOGIN PLAIN\r\n250 8BITMIME\r\n", 0x18),
        ("C->S", b"AUTH LOGIN\r\n", 0x18), # Insecure: Authenticating over cleartext!
        ("S->C", b"334 VXNlcm5hbWU6\r\n", 0x18),
        ("C->S", b"YWRtaW5AaW5zZWN1cmUuY29ycA==\r\n", 0x18), # admin@insecure.corp
        ("S->C", b"334 UGFzc3dvcmQ6\r\n", 0x18),
        ("C->S", b"UGFzc3dvcmQxMjMhIQ==\r\n", 0x18), # Password123!! (Leaked)
        ("S->C", b"235 2.7.0 Authentication successful\r\n", 0x18),
        ("C->S", b"QUIT\r\n", 0x18),
        ("S->C", b"221 2.0.0 Bye\r\n", 0x18)
    ]

    base_time = 1725900000

    for idx, (direction, text, flags) in enumerate(dialog):
        ts_sec = base_time + idx
        ts_usec = idx * 100000

        if direction == "S->C":
            src_m, dst_m = dst_mac, src_mac
            src_i, dst_i = server_ip, client_ip
            sp, dp = server_port, client_port
            seq, ack = seq_s, seq_c
            seq_s += len(text)
        else:
            src_m, dst_m = src_mac, dst_mac
            src_i, dst_i = client_ip, server_ip
            sp, dp = client_port, server_port
            seq, ack = seq_c, seq_s
            seq_c += len(text)

        tcp = make_tcp_packet(sp, dp, seq, ack, flags, text)
        ip = make_ip_packet(src_i, dst_i, 6, tcp) # 6 = TCP
        eth = dst_m + src_m + eth_type + ip

        pkt_hdr = struct.pack("!IIII", ts_sec, ts_usec, len(eth), len(eth))
        packets.append(pkt_hdr + eth)

    with open(filename, "wb") as f:
        f.write(pcap_header)
        for p in packets:
            f.write(p)

    print(f"[+] Created synthetic insecure PCAP: {filename}")

if __name__ == "__main__":
    create_pcap()
