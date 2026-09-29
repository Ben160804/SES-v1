#!/usr/bin/env python3
"""
Verify MAWI 2006-12-19 email/STARTTLS PCAP trace.

Usage:
    python3 verify_mawi.py [path/to/pcap.dump]

Analyzes a MAWI backbone capture for email protocol sessions and STARTTLS/TLS
handshake data. Handles truncated gzip streams gracefully.
"""

import struct
import os
import sys
import collections

def analyze_pcap(pcap_path):
    """Parse pcap file and extract email/TLS statistics."""

    file_size = os.path.getsize(pcap_path)
    print(f"File: {pcap_path}")
    print(f"Size: {file_size} bytes ({file_size/1024/1024:.1f} MB)")

    with open(pcap_path, 'rb') as f:
        header = f.read(24)
        if len(header) < 24:
            print("ERROR: File too short for pcap header")
            return None

        magic = struct.unpack('<I', header[0:4])[0]
        if magic == 0xa1b2c3d4:
            endian = '<'
        elif magic == 0xd4c3b2a1:
            endian = '>'
        else:
            magic_be = struct.unpack('>I', header[0:4])[0]
            if magic_be == 0xa1b2c3d4:
                endian = '>'
            else:
                print(f"ERROR: Unknown magic 0x{magic:08x}")
                return None

        ver_major, ver_minor = struct.unpack(endian + 'HH', header[4:8])
        snaplen = struct.unpack(endian + 'I', header[16:20])[0]
        network = struct.unpack(endian + 'I', header[20:24])[0]

        print(f"Version: {ver_major}.{ver_minor} | Snaplen: {snaplen} | Network: {network}")

        email_ports = {25, 465, 587, 110, 995, 143, 993}
        smtp_ports = {25, 465, 587}
        imap_ports = {143, 993}
        pop3_ports = {110, 995}

        pkt_count = 0
        email_packets = 0
        tls_records = 0
        starttls_found = False
        smtp_greetings_found = False
        tls_versions = collections.Counter()

        email_sessions = set()
        tls_on_email_ports = 0
        tls_on_ports = collections.Counter()

        try:
            while True:
                data = f.read(16)
                if len(data) < 16:
                    break

                incl_len = struct.unpack(endian + 'I', data[8:12])[0]
                orig_len = struct.unpack(endian + 'I', data[12:16])[0]

                if incl_len > snaplen or incl_len == 0 or incl_len > 65535:
                    continue

                packet = f.read(incl_len)
                if len(packet) < incl_len:
                    break

                pkt_count += 1

                if len(packet) < 14:
                    continue
                eth_type = struct.unpack('!H', packet[12:14])[0]
                if eth_type != 0x0800:
                    continue

                ip_header = packet[14:]
                if len(ip_header) < 20:
                    continue
                protocol = ip_header[9]
                if protocol != 6:
                    continue

                src_ip = '.'.join(str(b) for b in ip_header[12:16])
                dst_ip = '.'.join(str(b) for b in ip_header[16:20])
                ip_hdr_len = (ip_header[0] & 0x0F) * 4

                tcp_header = ip_header[ip_hdr_len:]
                if len(tcp_header) < 13:
                    continue

                src_port = struct.unpack('!H', tcp_header[0:2])[0]
                dst_port = struct.unpack('!H', tcp_header[2:4])[0]
                tcp_hdr_len = (tcp_header[12] >> 4) * 4

                if len(tcp_header) < tcp_hdr_len:
                    continue
                tcp_payload = tcp_header[tcp_hdr_len:]

                is_email = src_port in email_ports or dst_port in email_ports

                if is_email:
                    email_packets += 1
                    session = (src_ip, src_port, dst_ip, dst_port)
                    email_sessions.add(session)

                    if b'STARTTLS' in tcp_payload or b'starttls' in tcp_payload:
                        starttls_found = True
                    if b'220 ' in tcp_payload:
                        smtp_greetings_found = True

                if len(tcp_payload) >= 3 and tcp_payload[0] == 0x16:
                    tls_records += 1
                    port = max(src_port, dst_port)
                    tls_on_ports[port] += 1

                    tls_version = tcp_payload[1:3]
                    if tls_version == b'\x03\x01':
                        tls_versions['TLS 1.0'] += 1
                    elif tls_version == b'\x03\x02':
                        tls_versions['TLS 1.1'] += 1
                    elif tls_version == b'\x03\x03':
                        tls_versions['TLS 1.2'] += 1
                    elif tls_version == b'\x03\x04':
                        tls_versions['TLS 1.3'] += 1

                    if is_email:
                        tls_on_email_ports += 1

        except (struct.error, Exception) as e:
            print(f"Stopped parsing at packet {pkt_count}: {e}")

        print(f"\n=== MAWI Trace Analysis ===")
        print(f"Total packets parsed: {pkt_count:,}")
        print(f"Email protocol packets: {email_packets:,}")
        print(f"Unique email sessions: {len(email_sessions):,}")

        smtp_sessions = sum(1 for s in email_sessions
                          if s[1] in smtp_ports or s[3] in smtp_ports)
        imap_sessions = sum(1 for s in email_sessions
                          if s[1] in imap_ports or s[3] in imap_ports)
        pop3_sessions = sum(1 for s in email_sessions
                          if s[1] in pop3_ports or s[3] in pop3_ports)

        print(f"  SMTP sessions (25/465/587): {smtp_sessions:,}")
        print(f"  IMAP sessions (143/993): {imap_sessions:,}")
        print(f"  POP3 sessions (110/995): {pop3_sessions:,}")
        print(f"TLS handshake records (all ports): {tls_records:,}")
        print(f"TLS records on email ports: {tls_on_email_ports}")

        if tls_versions:
            print(f"TLS versions detected:")
            for ver, count in tls_versions.most_common():
                print(f"  {ver}: {count}")

        if tls_on_ports:
            port_labels = {443: 'HTTPS', 22: 'SSH', 25: 'SMTP'}
            print(f"\nTop TLS ports:")
            for port, count in tls_on_ports.most_common(10):
                print(f"  Port {port}: {count:,} records")

        print(f"\nSTARTTLS commands found: {'YES' if starttls_found else 'NO'}")
        print(f"SMTP 220 greetings found: {'YES' if smtp_greetings_found else 'NO'}")

        if not starttls_found and not smtp_greetings_found:
            print(f"\nNOTE: Snaplen={snaplen} truncates packets to {snaplen} bytes.")
            print(f"  Ethernet(14) + IP(20) + TCP(~36) = ~70 bytes header")
            print(f"  Only ~26 bytes of TCP payload captured per packet.")

        return True

    f.close()

if __name__ == '__main__':
    pcap_path = sys.argv[1] if len(sys.argv) > 1 else \
        "/home/rick/SES-v1/dataset/newdataset/mawi_20061219_1400_recovered.dump"
    analyze_pcap(pcap_path)
