#!/usr/bin/env python3
"""
scratch/test_live_milestone1_pcap083.py
======================================
Live Docker-bridge capture and verification for PCAP-083:
  - Generates exact self-signed Ed25519 cert & trust store into testbed/active/legacy/
  - Runs legacy_ed25519_server.py inside mailtest-legacy (172.28.0.40:465)
  - Captures on host bridge br-87a3125207be via tshark -> testbed/captures/PCAP-083.pcap
  - Runs legacy_ed25519_client.py with real trust verification (Condition 1)
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
from testbed.runner.runner import discover_docker_bridge
from testbed.runner.spec import load_matrix


def main():
    print("=" * 70)
    print("MILESTONE 1: LIVE PCAP-083 CAPTURE OVER DOCKER BRIDGE")
    print("=" * 70)

    bridge = discover_docker_bridge("testbed_mailtest_net")
    server_ip = "172.28.0.40"
    port = 465

    captures_dir = Path("/home/bigfoot/mailtest/testbed/captures")
    captures_dir.mkdir(parents=True, exist_ok=True)
    pcap_path = captures_dir / "PCAP-083.pcap"
    if pcap_path.exists():
        pcap_path.unlink()

    active_legacy_dir = Path("/home/bigfoot/mailtest/testbed/active/legacy")
    active_legacy_dir.mkdir(parents=True, exist_ok=True)

    # 1. Generate PKI Profile for PCAP-083
    matrix_specs = {s.scenario_id: s for s in load_matrix()}
    s83_spec = matrix_specs["PCAP-083"]

    factory = PKIFactory()
    prof = factory.generate_cert_profile(
        sig_algo=s83_spec.pki.sig_algo,
        validity=s83_spec.pki.validity,
        chain_shape=s83_spec.pki.chain_shape,
        san_type=s83_spec.pki.san_type,
    )

    cert_path = active_legacy_dir / "PCAP-083_cert.pem"
    key_path = active_legacy_dir / "PCAP-083_key.pem"
    trust_path = active_legacy_dir / "PCAP-083_trust.pem"

    cert_path.write_text(prof["cert_pem"])
    key_path.write_text(prof["key_pem"])
    trust_path.write_text(prof["trust_store_pem"])
    print(f"✓ Staged PKI files to {active_legacy_dir}")

    # 2. Kill any stale server processes in mailtest-legacy
    subprocess.run([
        "docker", "exec", "mailtest-legacy", "pkill", "-f", "legacy_ed25519_server.py"
    ], check=False)
    time.sleep(0.3)

    # 3. Start server inside mailtest-legacy container
    # Staged files are mounted into container at /etc/mailtest/active/legacy/
    srv_proc = subprocess.Popen(
        [
            "docker", "exec", "-i", "mailtest-legacy",
            "python3", "/legacy/legacy_ed25519_server.py",
            "--cert", "/etc/mailtest/active/legacy/PCAP-083_cert.pem",
            "--key", "/etc/mailtest/active/legacy/PCAP-083_key.pem",
            "--port", str(port),
            "--single"
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    # Wait for server readiness
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
    print(f"✓ tshark capturing on {bridge} for tcp port {port}")

    # 5. Execute client across Docker bridge with Real Trust Verification (Condition 1)
    clnt_res = subprocess.run(
        [
            sys.executable,
            "/home/bigfoot/mailtest/testbed/legacy/legacy_ed25519_client.py",
            "--host", server_ip,
            "--port", str(port),
            "--trust-store", str(trust_path),
            "--sni", "mail.test.local"
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

    sessions = analysis.get("tls_sessions", [])
    print(f"\nCaptured TLS sessions: {len(sessions)}")
    assert len(sessions) > 0, "No TLS sessions found in PCAP!"
    s0 = sessions[0]
    print(f"TLS Version: {s0.get('tls_version')}")
    print(f"Cipher Suite: {s0.get('cipher_suite')} ({s0.get('cipher_suite_name')})")
    print(f"Cipher Strength: {s0.get('cipher_strength')}")
    print(f"KEX Named Curve: {s0.get('kex_named_curve')}")
    print(f"Finished Observed: {s0.get('finished_observed')}")

    certs = analysis.get("certificates", [])
    print(f"Captured Certificates: {len(certs)}")
    assert len(certs) > 0, "No certificates extracted from PCAP!"
    c0 = certs[0]
    leaf = c0.get("leaf_cert", {})
    print(f"Leaf Subject: {leaf.get('subject_dn')}")
    print(f"Leaf Signature Algorithm: {leaf.get('signature_algorithm_name')}")
    print(f"Leaf Public Key Algorithm: {leaf.get('public_key_algorithm')}")
    print(f"Trust Status: {c0.get('trust_status')}")

    # 8. Compare against PCAP-083 Expected Data
    expected_data = s83_spec.to_expected_dict(selected_cipher=s0.get("cipher_suite_name"))
    cmp_res = compare(expected_data, analysis)

    print("\n--- COMPARISON RESULT ---")
    print("Status:", cmp_res.status)
    print("Mismatches count:", len(cmp_res.mismatches))
    for m in cmp_res.mismatches:
        print("  Mismatch:", m)

    assert cmp_res.status == "PASS" and len(cmp_res.mismatches) == 0, f"Comparison failed: {cmp_res.mismatches}"
    print("\n======================================================================")
    print("MILESTONE 1 COMPLETE: PCAP-083 PASSES WITH 0 MISMATCHES ON LIVE BRIDGE!")
    print("======================================================================")


if __name__ == "__main__":
    main()
