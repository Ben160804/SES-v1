"""
testbed/stage_baseline.py
=========================
Stage the baseline scenario (PCAP-001/PCAP-005):
  - Certificate: ECDSA, valid, complete-chain, matched_dns
  - Postfix config: baseline main.cf & master.cf (STARTTLS enabled)
  - Target: testbed/active/ (mounted into Postfix at /etc/mailtest/active/)
"""

import os
import pathlib
import shutil
import sys

# Ensure mailtest root is on path
here = pathlib.Path(__file__).resolve().parent
project_root = here.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from testbed.pki.generator.make_certs import PKIFactory


def stage_baseline():
    active_dir = here / "active"
    active_dir.mkdir(parents=True, exist_ok=True)

    # 1. Generate baseline PKI artifacts
    pki_dir = here / "pki"
    factory = PKIFactory(pki_dir=str(pki_dir))
    profile = factory.generate_cert_profile(
        sig_algo="ecdsa",
        validity="valid",
        chain_shape="complete",
        san_type="matched_dns",
    )

    chain_file = active_dir / "chain.pem"
    key_file   = active_dir / "key.pem"
    chain_file.write_text(profile["chain_pem"])
    key_file.write_text(profile["key_pem"])

    # 2. Copy baseline Postfix configs
    templates_dir = here / "postfix" / "templates"
    shutil.copy2(templates_dir / "main.cf.base", active_dir / "main.cf")

    print(f"[stage_baseline] Successfully staged baseline artifacts in {active_dir}:")
    print(f"  - {chain_file.name} ({len(profile['chain_pem'])} bytes)")
    print(f"  - {key_file.name} ({len(profile['key_pem'])} bytes)")
    print(f"  - main.cf")


if __name__ == "__main__":
    stage_baseline()
