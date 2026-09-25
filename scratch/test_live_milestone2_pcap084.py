#!/usr/bin/env python3
"""
scratch/test_live_milestone2_pcap084.py
======================================
Live Docker-bridge capture and verification for PCAP-084:
  - Generates exact not-yet-valid ECDSA cert into testbed/active/legacy/
  - Runs legacy_ecdh_server inside mailtest-legacy (172.28.0.40:465)
  - Captures on host bridge br-87a3125207be via tshark -> testbed/captures/PCAP-084.pcap
  - Runs legacy_ecdh_client with permissive validation (Condition 2) across the bridge
  - Analyzes PCAP via PCAPAnalyzer and validates zero mismatches with compare()
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import time

# Ensure project root is on sys.path
sys.path.insert(0, "/home/bigfoot/mailtest")
from analysis.parser import PCAPAnalyzer
from testbed.pki.generator.make_certs import PKIFactory
from testbed.runner.comparator import compare
from testbed.runner.observed import build_observed_artifact
from testbed.runner.runner import discover_docker_bridge
from testbed.runner.spec import load_matrix


def main():
    print("=" * 70)
    print("MILESTONE 2: LIVE PCAP-084 CAPTURE OVER DOCKER BRIDGE")
    print("=" * 70)

    bridge = discover_docker_bridge("testbed_mailtest_net")
    server_ip = "172.28.0.40"
    port = 465

    captures_dir = Path("/home/bigfoot/mailtest/testbed/captures")
    captures_dir.mkdir(parents=True, exist_ok=True)
    pcap_path = captures_dir / "PCAP-084.pcap"
    if pcap_path.exists():
        pcap_path.unlink()

    active_legacy_dir = Path("/home/bigfoot/mailtest/testbed/active/legacy")
    active_legacy_dir.mkdir(parents=True, exist_ok=True)

    # 1. Generate PKI Profile for PCAP-084
    matrix_specs = {s.scenario_id: s for s in load_matrix()}
    s84_spec = matrix_specs["PCAP-084"]

    factory = PKIFactory()
    prof = factory.generate_cert_profile(
        sig_algo=s84_spec.pki.sig_algo,
        validity=s84_spec.pki.validity,
        chain_shape=s84_spec.pki.chain_shape,
        san_type=s84_spec.pki.san_type,
    )

    cert_path = active_legacy_dir / "PCAP-084_cert.pem"
    key_path = active_legacy_dir / "PCAP-084_key.pem"
    trust_path = active_legacy_dir / "PCAP-084_trust.pem"

    cert_path.write_text(prof["cert_pem"])
    key_path.write_text(prof["key_pem"])
    trust_path.write_text(prof["trust_store_pem"])
    print(f"✓ Staged PKI files to {active_legacy_dir}")

    # 2. Kill any stale server processes in mailtest-legacy
    subprocess.run([
        "docker", "exec", "mailtest-legacy", "pkill", "-f", "legacy_ecdh_server"
    ], check=False)
    time.sleep(0.3)

    # 3. Start static ECDH server inside mailtest-legacy container
    srv_proc = subprocess.Popen(
        [
            "docker", "exec", "-i", "mailtest-legacy",
            "/legacy/legacy_ecdh_server",
            "--cert", "/etc/mailtest/active/legacy/PCAP-084_cert.pem",
            "--key", "/etc/mailtest/active/legacy/PCAP-084_key.pem",
            "--port", str(port),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    ready = False
    for _ in range(50):
        line = srv_proc.stdout.readline()
        if "READY" in line:
            ready = True
            break
        time.sleep(0.05)
    if not ready:
        err = srv_proc.stderr.read()
        raise RuntimeError(f"Server did not become ready: {err}")
    print(f"✓ Server ready and listening on {server_ip}:{port}")

    # 4. Start tshark capture on Docker bridge interface
    cap_proc = subprocess.Popen(
        [
            "tshark",
            "-i", bridge,
            "-f", f"tcp port {port}",
            "-w", str(pcap_path),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    for _ in range(50):
        line = cap_proc.stderr.readline()
        if "Capturing on " in line:
            break
        time.sleep(0.05)
    time.sleep(1.0)
    print(f"✓ tshark capturing on {bridge} for tcp port {port}")

    # 5. Execute client across Docker bridge with permissive verification (Condition 2)
    clnt_res = subprocess.run(
        [
            "/home/bigfoot/mailtest/testbed/legacy/legacy_ecdh_client",
            "--host", server_ip,
            "--port", str(port),
        ],
        capture_output=True,
        text=True,
    )
    print("Client STDOUT:\n", clnt_res.stdout)
    if clnt_res.returncode != 0:
        print("Client STDERR:\n", clnt_res.stderr)
        raise RuntimeError("Client execution failed!")

    srv_proc.wait(timeout=3.0)

    # 6. Flush and terminate capture
    time.sleep(0.5)
    cap_proc.terminate()
    try:
        cap_proc.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        cap_proc.kill()
        cap_proc.wait()

    assert pcap_path.exists() and pcap_path.stat().st_size > 0
    print(f"✓ Captured PCAP successfully: {pcap_path} ({pcap_path.stat().st_size} bytes)")

    # 7. Analyze with PCAPAnalyzer
    analyzer = PCAPAnalyzer(str(pcap_path), trust_store=str(trust_path))
    analysis = analyzer.analyze()

    sessions = analysis.get(0, {})
    assert bool(sessions), "No stream 0 found in PCAP!"
    tls_info = sessions.get("tls", {})
    print(f"TLS Version: {tls_info.get('tls_version')}")
    print(f"Cipher Suite: {tls_info.get('raw_cipher_suite')} ({tls_info.get('cipher_name')})")
    print(f"Cipher Strength: {tls_info.get('cipher_strength')}")
    print(f"Forward Secrecy: {tls_info.get('forward_secrecy')}")

    cert_info = sessions.get("certificate", {})
    leaf = cert_info.get("leaf_cert", {})
    print(f"Trust Status: {cert_info.get('trust_status')}")
    print(f"Not Yet Valid: {leaf.get('not_yet_valid')}")
    print(f"Public Key Algorithm: {leaf.get('public_key_algorithm')}")

    # Verify no ServerKeyExchange in flight
    flight_msgs = [m.get("message") for m in sessions.get("handshake", {}).get("flight", {}).get("messages", [])]
    print(f"Flight messages: {flight_msgs}")
    assert "ServerKeyExchange" not in flight_msgs, "RFC 4492 VIOLATION: ServerKeyExchange observed in static ECDH!"
    print("✓ Confirmed: ZERO ServerKeyExchange messages in flight (RFC 4492 §2.1 strictly obeyed)")

    # 8. Compare against PCAP-084 Expected Data
    expected_data = s84_spec.to_expected_dict(selected_cipher=tls_info.get("cipher_name"))
    observed_data = build_observed_artifact("PCAP-084", analysis)
    cmp_res = compare(expected_data, observed_data)

    print("\n--- COMPARISON RESULT ---")
    print("Status:", cmp_res["status"])
    print("Mismatches count:", len(cmp_res["mismatches"]))
    for m in cmp_res["mismatches"]:
        print("  Mismatch:", m)

    assert cmp_res["status"] == "PASS" and len(cmp_res["mismatches"]) == 0, f"Comparison failed: {cmp_res['mismatches']}"
    print("\n======================================================================")
    print("MILESTONE 2 COMPLETE: PCAP-084 PASSES WITH 0 MISMATCHES ON LIVE BRIDGE!")
    print("======================================================================")


if __name__ == "__main__":
    main()
