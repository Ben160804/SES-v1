"""Bounded, streaming sample audit for large gzip-compressed MAWI PCAPs."""

from __future__ import annotations

import argparse
import gzip
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import dpkt


MAIL_PORTS = {
    "SMTP": {25, 465, 587},
    "IMAP": {143, 993},
    "POP3": {110, 995},
}


def _endpoints(packet: bytes) -> tuple[str, int, str, int, bytes] | None:
    try:
        ethernet = dpkt.ethernet.Ethernet(packet)
        network = ethernet.data
        if isinstance(network, dpkt.ip.IP):
            src, dst = dpkt.utils.inet_to_str(network.src), dpkt.utils.inet_to_str(network.dst)
        elif isinstance(network, dpkt.ip6.IP6):
            src, dst = dpkt.utils.inet_to_str(network.src), dpkt.utils.inet_to_str(network.dst)
        else:
            return None
        if not isinstance(network.data, dpkt.tcp.TCP):
            return None
        tcp = network.data
        return src, tcp.sport, dst, tcp.dport, bytes(tcp.data)
    except (dpkt.dpkt.UnpackError, ValueError, TypeError):
        return None


def audit(path: Path, packet_limit: int) -> dict[str, Any]:
    packet_count = 0
    tcp_count = 0
    protocol_packets = Counter()
    tls_prefix_packets = Counter()
    flows: dict[str, set[tuple[tuple[str, int], tuple[str, int]]]] = defaultdict(set)
    mail_commands = Counter()
    first_ts = last_ts = None
    truncated_packet_count = 0

    with gzip.open(path, "rb") as source:
        reader = dpkt.pcap.Reader(source)
        snaplen = reader.snaplen
        linktype = reader.datalink()
        for timestamp, packet in reader:
            packet_count += 1
            first_ts = timestamp if first_ts is None else first_ts
            last_ts = timestamp
            endpoints = _endpoints(packet)
            if endpoints is None:
                if len(packet) >= snaplen:
                    truncated_packet_count += 1
                if packet_count >= packet_limit:
                    break
                continue
            tcp_count += 1
            src, sport, dst, dport, payload = endpoints
            matched = [name for name, ports in MAIL_PORTS.items() if sport in ports or dport in ports]
            for name in matched:
                protocol_packets[name] += 1
                a, b = sorted(((src, sport), (dst, dport)))
                flows[name].add((a, b))
                if payload.startswith((b"\x16\x03", b"\x14\x03", b"\x15\x03", b"\x17\x03")):
                    tls_prefix_packets[name] += 1
                upper = payload.upper()
                for command in (b"STARTTLS", b"EHLO ", b"HELO ", b"CAPABILITY", b"AUTH ", b"USER ", b"PASS "):
                    if command in upper:
                        mail_commands[command.decode().strip()] += 1
            if packet_count >= packet_limit:
                break
        uncompressed_bytes_read = source.tell()

    return {
        "source_file": path.name,
        "compressed_bytes": path.stat().st_size,
        "sample_packet_limit": packet_limit,
        "sample_packets_read": packet_count,
        "uncompressed_bytes_read": uncompressed_bytes_read,
        "pcap_linktype": linktype,
        "pcap_snaplen": snaplen,
        "sample_first_timestamp": first_ts,
        "sample_last_timestamp": last_ts,
        "tcp_packets": tcp_count,
        "email_port_packet_counts": dict(protocol_packets),
        "email_port_bidirectional_flow_candidates": {
            name: len(items) for name, items in sorted(flows.items())
        },
        "tls_record_prefix_packet_counts_on_email_ports": dict(tls_prefix_packets),
        "visible_email_command_occurrences": dict(mail_commands),
        "packets_at_or_above_snaplen_without_decoded_tcp": truncated_packet_count,
        "limitations": [
            "This is a first-N-packet sample, not a complete capture analysis or prevalence estimate.",
            "Port-based flow candidates are not confirmed SMTP/IMAP/POP3 sessions.",
            "TLS prefix counts are packet-level heuristics and do not reconstruct TLS handshakes.",
            "Low snap length can truncate application payloads and prevent protocol/handshake reconstruction.",
        ],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcaps", nargs="+", type=Path)
    parser.add_argument("--packet-limit", type=int, default=250_000)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.packet_limit < 1:
        parser.error("--packet-limit must be positive")
    result = {
        "audit_type": "bounded_mawi_packet_sample",
        "results": [audit(path, args.packet_limit) for path in args.pcaps],
    }
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
