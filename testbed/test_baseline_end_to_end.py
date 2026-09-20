"""
testbed/test_baseline_end_to_end.py
====================================
End-to-end integration test for the Postfix testbed:
  1. Verifies Postfix is listening on port 2525 (or 172.28.0.10:25).
  2. Spawns tshark / tcpdump to capture the live SMTP session.
  3. Executes an SMTP STARTTLS transaction using Python stdlib smtplib + ssl.
  4. Parses the resulting PCAP using extract_certificates() and TrustStoreManager.
  5. Asserts that trust_status is TRUSTED_CHAIN and hostname_match is MATCHED.
"""

import os
import pathlib
import smtplib
import ssl
import subprocess
import sys
import time

# Ensure project root is on sys.path
here = pathlib.Path(__file__).resolve().parent
project_root = here.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from analysis.cert_validator import extract_certificates
from analysis.trust_store import TrustStoreManager


def test_baseline_smtp():
    pcap_dir = here / "pcaps"
    pcap_dir.mkdir(parents=True, exist_ok=True)
    pcap_path = pcap_dir / "baseline_test.pcap"
    if pcap_path.exists():
        pcap_path.unlink()

    # Determine target host and port:
    # 127.0.0.1:2525 via Docker port mapping, or 172.28.0.10:25 directly
    target_host = "172.28.0.10"
    target_port = 25
    sni_hostname = "mail.test.local"

    print(f"[*] Starting packet capture on lo/docker0 to {pcap_path}...")
    # ponytail: tshark captures on any or lo interface for port 2525
    capture_proc = subprocess.Popen(
        [
            "tshark", "-i", "any",
            "-f", f"tcp port {target_port} or tcp port 25",
            "-w", str(pcap_path),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1.5)  # allow tshark sniffer to initialize

    try:
        print(f"[*] Connecting to SMTP server at {target_host}:{target_port}...")
        smtp = smtplib.SMTP(target_host, target_port, timeout=10)
        smtp.set_debuglevel(1)

        code, msg = smtp.ehlo("client.test.local")
        print(f"[+] EHLO response: {code} {msg.decode(errors='ignore')}")

        if not smtp.has_extn("STARTTLS"):
            raise RuntimeError("Server did not advertise STARTTLS extension!")

        print("[*] Negotiating STARTTLS with server...")
        # Create client SSL context using our testbed root CA
        root_ca_path = str(here / "pki" / "ca" / "root_ca.crt")
        ssl_ctx = ssl.create_default_context(cafile=root_ca_path)
        # Verify hostname matches SERVER_HOSTNAME (mail.test.local)
        ssl_ctx.check_hostname = True
        # For passive wire inspection of the Certificate handshake message (RFC 5246),
        # negotiate TLS 1.2 so certificates are not encrypted in TLSCiphertext (RFC 8446).
        ssl_ctx.maximum_version = ssl.TLSVersion.TLSv1_2

        # smtplib.SMTP.starttls uses self._host as server_hostname in wrap_socket
        smtp._host = sni_hostname
        smtp.starttls(context=ssl_ctx)
        print("[+] STARTTLS handshake succeeded!")

        # Post-TLS EHLO & minimal mail transaction
        smtp.ehlo("client.test.local")
        smtp.mail("sender@test.local")
        smtp.rcpt("recipient@test.local")
        smtp.data("Subject: Baseline PCAP Test\n\nPayload from SecureMailScope testbed.")
        smtp.quit()
        print("[+] SMTP session completed cleanly.")

    finally:
        # Stop capture
        time.sleep(1.0)
        capture_proc.terminate()
        capture_proc.wait()
        print(f"[+] Capture stopped. PCAP size: {pcap_path.stat().st_size if pcap_path.exists() else 0} bytes")

    # Forensic Analysis of the captured PCAP
    print("[*] Running extract_certificates with TrustStoreManager(trust_store='testbed')...")
    ts_manager = TrustStoreManager(trust_store="testbed", base_dir=str(project_root / "analysis"))
    print(f"[*] TrustStoreManager backing file: {ts_manager.get_ca_file_path()}")

    results = extract_certificates(str(pcap_path), trust_store_manager=ts_manager)
    print(f"[*] Extracted {len(results)} certificate stream(s) from PCAP:")

    for sid, data in results.items():
        print(f"    Stream {sid}:")
        print(f"      trust_status:  {data.get('trust_status')}")
        print(f"      trust_details: {data.get('trust_details')}")
        print(f"      hostname_match:{data.get('hostname_match')}")

        # Assertions
        assert data.get("trust_status") == "TRUSTED_CHAIN", f"Expected TRUSTED_CHAIN, got {data.get('trust_status')}"
        assert data.get("hostname_match") == "MATCHED", f"Expected MATCHED, got {data.get('hostname_match')}"

    print("\n[✓] BASELINE INTEGRATION TEST PASSED: Full closed-loop verification successful!")


if __name__ == "__main__":
    test_baseline_smtp()
