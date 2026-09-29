"""Stream TLS handshake features from the separate HTTPS PCAP corpus in mix.zip."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import dpkt


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from analysis.ciphers import load_iana_cipher_database

SOURCE = ROOT / "datasets" / "ml" / "tls" / "mix.zip"
OUTPUT = ROOT / "datasets" / "ml" / "processed" / "https_tls_v1.csv"
METADATA = ROOT / "datasets" / "ml" / "metadata" / "https_tls_v1.json"
TLS_VERSIONS = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
GROUPS = {
    19: "secp192r1", 21: "secp224r1", 23: "secp256r1", 24: "secp384r1",
    25: "secp521r1", 29: "x25519", 30: "x448", 256: "ffdhe2048",
    257: "ffdhe3072", 258: "ffdhe4096", 259: "ffdhe6144", 260: "ffdhe8192",
}
EXTENSIONS = {"sni": 0, "supported_groups": 10, "signature_algorithms": 13, "supported_versions": 43, "key_share": 51}


def _archive_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _reassemble(segments: list[tuple[int, bytes]]) -> tuple[bytes, bool]:
    if not segments:
        return b"", False
    segments.sort(key=lambda item: item[0])
    output = bytearray()
    next_seq = segments[0][0]
    gaps = False
    for sequence, payload in segments:
        if sequence > next_seq:
            gaps = True
            next_seq = sequence
        overlap = max(0, next_seq - sequence)
        if overlap < len(payload):
            output.extend(payload[overlap:])
            next_seq = sequence + len(payload)
    return bytes(output), gaps


def _extensions(data: bytes) -> list[tuple[int, bytes]]:
    if len(data) < 2:
        return []
    end = min(len(data), 2 + int.from_bytes(data[:2], "big"))
    pos = 2
    result = []
    while pos + 4 <= end:
        ext_type = int.from_bytes(data[pos:pos + 2], "big")
        length = int.from_bytes(data[pos + 2:pos + 4], "big")
        pos += 4
        if pos + length > end:
            break
        result.append((ext_type, data[pos:pos + length]))
        pos += length
    return result


def _hello_features(client_stream: bytes, server_stream: bytes) -> dict[str, Any]:
    records = []
    handshakes = {"client": bytearray(), "server": bytearray()}
    record_bytes = 0
    for direction, stream in (("client", client_stream), ("server", server_stream)):
        pos = 0
        while pos + 5 <= len(stream):
            content_type = stream[pos]
            record_version = int.from_bytes(stream[pos + 1:pos + 3], "big")
            length = int.from_bytes(stream[pos + 3:pos + 5], "big")
            if length > 18432 or pos + 5 + length > len(stream):
                break
            body = stream[pos + 5:pos + 5 + length]
            records.append((content_type, record_version, length))
            record_bytes += 5 + length
            if content_type == 22:
                handshakes[direction].extend(body)
            pos += 5 + length

    parsed: dict[int, Any] = {}
    for direction, raw in handshakes.items():
        pos = 0
        while pos + 4 <= len(raw):
            msg_len = int.from_bytes(raw[pos + 1:pos + 4], "big")
            if pos + 4 + msg_len > len(raw):
                break
            message = bytes(raw[pos:pos + 4 + msg_len])
            try:
                hs = dpkt.ssl.TLSHandshake(message)
                if hs.type in (1, 2) and hs.type not in parsed:
                    parsed[hs.type] = hs.data
            except (dpkt.dpkt.UnpackError, dpkt.ssl.SSL3Exception, ValueError):
                pass
            pos += 4 + msg_len

    client = parsed.get(1)
    server = parsed.get(2)
    client_ext = list(getattr(client, "extensions", [])) if client else []
    server_ext = list(getattr(server, "extensions", [])) if server else []
    client_ext_map = dict(client_ext)
    server_ext_map = dict(server_ext)

    offered_versions = []
    versions_ext = client_ext_map.get(43, b"")
    if versions_ext:
        size = versions_ext[0]
        offered_versions = [
            TLS_VERSIONS.get(int.from_bytes(versions_ext[i:i + 2], "big"), "UNKNOWN")
            for i in range(1, min(1 + size, len(versions_ext)), 2)
            if i + 2 <= len(versions_ext)
        ]
    elif client:
        offered_versions = [TLS_VERSIONS.get(client.version, "UNKNOWN")]

    selected_version = None
    selected_ext = server_ext_map.get(43, b"")
    if len(selected_ext) >= 2:
        selected_version = int.from_bytes(selected_ext[:2], "big")
    elif server:
        selected_version = server.version

    groups_ext = client_ext_map.get(10, b"")
    groups = []
    if len(groups_ext) >= 2:
        size = int.from_bytes(groups_ext[:2], "big")
        groups = [
            GROUPS.get(int.from_bytes(groups_ext[i:i + 2], "big"), f"group_{int.from_bytes(groups_ext[i:i + 2], 'big')}")
            for i in range(2, min(2 + size, len(groups_ext)), 2)
            if i + 2 <= len(groups_ext)
        ]

    server_group = ""
    key_share = server_ext_map.get(51, b"")
    if len(key_share) >= 4:
        group_id = int.from_bytes(key_share[:2], "big")
        server_group = GROUPS.get(group_id, f"group_{group_id}")

    cipher_object = getattr(server, "ciphersuite", None) if server else None
    if cipher_object is None and server is not None:
        cipher_object = getattr(server, "cipher_suite", None)
    cipher_id = getattr(cipher_object, "code", None)
    cipher_db = getattr(_hello_features, "cipher_db", {})
    cipher_info = cipher_db.get(f"0x{cipher_id:04x}", {}) if cipher_id is not None else {}
    selected_cipher = cipher_info.get(
        "name", getattr(cipher_object, "name", f"0x{cipher_id:04x}" if cipher_id is not None else "")
    )
    selected = TLS_VERSIONS.get(selected_version, "UNKNOWN") if selected_version is not None else ""

    return {
        "client_hello_observed": bool(client),
        "server_hello_observed": bool(server),
        "handshake_observed": bool(client and server),
        "client_hello_legacy_version": TLS_VERSIONS.get(client.version, "UNKNOWN") if client else "",
        "client_offered_versions": "|".join(offered_versions),
        "client_offered_version_count": len(offered_versions),
        "client_offered_cipher_count": len(getattr(client, "ciphersuites", [])) if client else 0,
        "client_extension_count": len(client_ext),
        "client_sni_extension": int(0 in client_ext_map),
        "client_supported_groups_count": len(groups),
        "client_supported_groups": "|".join(groups),
        "client_key_share_extension": int(51 in client_ext_map),
        "client_signature_algorithms_extension": int(13 in client_ext_map),
        "selected_tls_version": selected,
        "selected_cipher_id": f"0x{cipher_id:04x}" if cipher_id is not None else "",
        "selected_cipher_suite": selected_cipher,
        "selected_cipher_strength": cipher_info.get("strength", "UNKNOWN"),
        "selected_key_exchange": cipher_info.get("kex", "UNKNOWN"),
        "selected_key_share_group": server_group,
        "server_extension_count": len(server_ext),
        "server_supported_versions_extension": int(43 in server_ext_map),
        "tls_record_count": len(records),
        "tls_record_bytes": record_bytes,
        "tls_record_type_22_count": sum(content_type == 22 for content_type, _, _ in records),
        "tls_record_type_23_count": sum(content_type == 23 for content_type, _, _ in records),
        "record_legacy_version_set": "|".join(sorted({TLS_VERSIONS.get(version, "UNKNOWN") for _, version, _ in records})),
        "tls_payload_bytes_client": len(client_stream),
        "tls_payload_bytes_server": len(server_stream),
    }


def _extract_one(archive: zipfile.ZipFile, entry: zipfile.ZipInfo, index: int) -> dict[str, Any]:
    record = {
        "record_id": hashlib.sha256(entry.filename.encode()).hexdigest()[:24],
        "server_group_id": hashlib.sha256(entry.filename.split("/")[1].encode()).hexdigest()[:24] if "/" in entry.filename else "",
        "data_source": "real_https_tls_pcap",
        "source_ref": entry.filename,
        "source_entry_index": index,
        "capture_bytes": entry.file_size,
        "parse_status": "ERROR",
    }
    try:
        with archive.open(entry) as source:
            reader = dpkt.pcap.Reader(source)
            flows: dict[tuple[bytes, bytes, int, int], dict[str, Any]] = {}
            packet_count = 0
            timestamps = []
            for timestamp, raw in reader:
                packet_count += 1
                try:
                    eth = dpkt.ethernet.Ethernet(raw)
                    ip = eth.data
                    tcp = ip.data
                    if not isinstance(tcp, dpkt.tcp.TCP) or not tcp.data:
                        continue
                    src, dst = bytes(ip.src), bytes(ip.dst)
                    key = (src, dst, tcp.sport, tcp.dport)
                    reverse = (dst, src, tcp.dport, tcp.sport)
                    flow_key = min(key, reverse)
                    flow = flows.setdefault(flow_key, {"client": [], "server": [], "packets": 0, "bytes": 0})
                    direction = "client" if tcp.dport == 443 else "server" if tcp.sport == 443 else "client"
                    flow[direction].append((tcp.seq, bytes(tcp.data)))
                    flow["packets"] += 1
                    flow["bytes"] += len(tcp.data)
                    timestamps.append(timestamp)
                except (AttributeError, dpkt.dpkt.UnpackError, ValueError):
                    continue
            if not flows:
                record.update({"parse_status": "NO_TCP_PAYLOAD", "packet_count": packet_count})
                return record
            flow = max(flows.values(), key=lambda item: item["bytes"])
            client_stream, client_gaps = _reassemble(flow["client"])
            server_stream, server_gaps = _reassemble(flow["server"])
            record.update(_hello_features(client_stream, server_stream))
            record.update({
                "parse_status": "PARSED",
                "packet_count": packet_count,
                "tcp_payload_packet_count": flow["packets"],
                "tcp_flow_count": len(flows),
                "tcp_sequence_gap_observed": bool(client_gaps or server_gaps),
                "capture_duration_seconds": round(max(timestamps) - min(timestamps), 6) if len(timestamps) > 1 else 0.0,
            })
    except Exception as exc:
        record["parse_status"] = f"ERROR:{type(exc).__name__}:{str(exc)[:120]}"
    return record


def extract(limit: int | None = None) -> None:
    if not SOURCE.exists():
        raise FileNotFoundError(SOURCE)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    METADATA.parent.mkdir(parents=True, exist_ok=True)
    counts: Counter[str] = Counter()
    fields: list[str] = []
    with zipfile.ZipFile(SOURCE) as archive:
        entries = [item for item in archive.infolist() if not item.is_dir() and item.filename.lower().endswith(".pcap")]
        if limit is not None:
            entries = entries[:limit]
        with OUTPUT.open("w", newline="", encoding="utf-8") as destination:
            writer = None
            for index, entry in enumerate(entries, start=1):
                row = _extract_one(archive, entry, index)
                if writer is None:
                    fields = list(row)
                    writer = csv.DictWriter(destination, fieldnames=fields)
                    writer.writeheader()
                writer.writerow(row)
                counts[row["parse_status"].split(":", 1)[0]] += 1
                counts["client_hello"] += int(bool(row.get("client_hello_observed")))
                counts["server_hello"] += int(bool(row.get("server_hello_observed")))
                counts["handshake"] += int(bool(row.get("handshake_observed")))
                if index % 2000 == 0:
                    print(f"Processed {index}/{len(entries)} captures", flush=True)

    metadata = {
        "dataset_id": "https_tls_v1",
        "description": "TLS handshake/record features from the separate HTTPS PCAP corpus; not email traffic.",
        "source_path": str(SOURCE.relative_to(ROOT)),
        "source_sha256": _archive_sha256(SOURCE),
        "capture_count_processed": sum(v for k, v in counts.items() if k in ("PARSED", "ERROR", "NO_TCP_PAYLOAD")),
        "counts": dict(counts),
        "extractor": "dpkt offline PCAP reader; TCP payloads are sequence-sorted and overlap-trimmed before TLS record parsing.",
        "model_feature_exclusions": ["record_id", "server_group_id", "data_source", "source_ref", "source_entry_index", "parse_status"],
        "limitations": [
            "HTTPS-only corpus; never merge into SMTP/IMAP/POP3 populations or claim email-specific generalization.",
            "TLS 1.3 encrypts the post-ServerHello certificate flight; this passive extractor cannot see certificate facts there without secrets.",
            "A ClientHello/ServerHello absence may reflect capture truncation or packet loss; retain explicit observation flags.",
            "Current TCP reassembly is single-flow-per-capture oriented; multi-flow captures select the highest-payload flow and record the flow count.",
            "No labeled anomalous TLS traffic exists in this corpus; novelty scores are not attack or vulnerability verdicts.",
        ],
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "schema_version": "1.0",
        "output_path": str(OUTPUT.relative_to(ROOT)),
    }
    METADATA.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(f"Processed captures: {metadata['capture_count_processed']}; status counts: {dict(counts)}")
    print(f"Features: {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=None, help="Process only the first N PCAP entries for a smoke test")
    args = parser.parse_args()
    _hello_features.cipher_db = load_iana_cipher_database(ROOT / "data" / "tls_ciphers.csv")
    extract(args.limit)
