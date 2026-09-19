"""
SecureMailScope Forensic Telemetry Engine — Orchestrator & CLI Runner
=====================================================================

ARCHITECTURAL OVERVIEW & PURPOSE:
  Serves as the unified coordination facade and entrypoint for offline forensic
  analysis of email traffic captures (SMTP, IMAP, POP3).
  
  Coordinates four specialized domain engines to construct a multi-layer
  telemetry model per TCP stream:
    1. TLS Handshake Reconstruction Engine (analysis/tls_session.py):
       Stateful reconstruction of RFC 5246 (TLS 1.2) and RFC 8446 (TLS 1.3)
       flights, ClientHello offered capabilities, ServerHello parameter negotiation,
       ephemeral key exchange separation (RFC 8422 ECDHE vs RFC 5246 DHE),
       RFC 8446 §4.1.3 downgrade protection sentinels, and defensible lifecycle states.
    2. X.509 Cryptographic & Trust Engine (analysis/cert_validator.py):
       Extracts full certificate telemetry (Subject, Issuer, Validity, SANs, Key Usage,
       EKU, Basic Constraints, SCTs, Serial) and performs RFC 5280 PKIX path validation,
       cryptographic signature checks (RSA/ECDSA/Ed25519), and RFC 6125 SAN matching.
    3. STARTTLS State Machine & Protocol DPI Engine (analysis/starttls.py):
       Chronological 5-step transition tracking for SMTP (RFC 3207), POP3 (RFC 2595),
       and IMAP (RFC 3501), auditing capability advertisement, client request, server
       acceptance, TLS activation, and plaintext credential exposure.
    4. Trust Store Manager (analysis/trust_store.py):
       Provides pluggable root trust environments (Testbed CA vs Mozilla production bundle)
       to perform comparative forensics on self-signed vs publicly anchored certificates.
"""

import os
import json
import sys
import warnings
from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

_pkg_dir = os.path.dirname(os.path.abspath(__file__))
if _pkg_dir not in sys.path:
    sys.path.insert(0, _pkg_dir)

try:
    from .constants import TLS_VERSION_MAP, TLS13_GROUP_MAP, TLS13_PSK_MODE_MAP
    from .trust_store import TrustStoreManager
    from .cert_validator import (
        verify_certificate_signature,
        check_hostname_match,
        get_x509_subject,
        verify_pkix_path,
        extract_certificates,
    )
    from .tls_session import extract_tls_info, reconstruct_handshake
    from .starttls import detect_protocol, detect_starttls
    from .ciphers import get_cipher_info
except (ImportError, ValueError):
    from constants import TLS_VERSION_MAP, TLS13_GROUP_MAP, TLS13_PSK_MODE_MAP
    from trust_store import TrustStoreManager
    from cert_validator import (
        verify_certificate_signature,
        check_hostname_match,
        get_x509_subject,
        verify_pkix_path,
        extract_certificates,
    )
    from tls_session import extract_tls_info, reconstruct_handshake
    from starttls import detect_protocol, detect_starttls
    from ciphers import get_cipher_info


class PCAPAnalyzer:
    """
    High-level PCAP Forensic Analyzer.
    =================================
    Coordinates specialized domain modules to inspect TLS, X.509, and email
    protocol negotiation across all TCP streams in a capture.

    DESIGN PRINCIPLES:
      • Single Responsibility: Specialized engines handle TLS, X.509, DPI, and Trust separately.
      • Non-Intrusive Wire Forensics: Operates strictly on passive packet captures without keys.
      • Pluggable Trust Anchors: Supports dynamic switching between lab testbed roots and
        production Mozilla CA bundles for differential trust analysis.
    """
    def __init__(self, pcap_path, trust_store="testbed"):
        """
        Initializes the analyzer with the target capture file and root trust configuration.

        Args:
            pcap_path: Absolute or relative filesystem path to the target .pcap/.pcapng file.
            trust_store: Root trust anchor type:
                         - "testbed": Root certificates from ./certs/ (for lab captures).
                         - "production": Mozilla CA bundle via `certifi` (for public endpoints).
                         - "system": Operating system trust store (/etc/ssl/certs).
        """
        self.pcap_path = pcap_path
        self.trust_store_type = trust_store
        self.trust_store_manager = TrustStoreManager(
            trust_store=trust_store,
            base_dir=os.path.dirname(os.path.abspath(__file__))
        )

    @property
    def trust_store_description(self):
        """Human-readable description of the active trust store."""
        return self.trust_store_manager.trust_store_description

    @property
    def _store_certs(self):
        """Parallel list of cryptography.x509.Certificate objects in active store."""
        return self.trust_store_manager._store_certs

    @property
    def _loaded_store(self):
        """Cached OpenSSL.crypto.X509Store object."""
        return self.trust_store_manager._loaded_store

    def _get_trust_store(self):
        """Lazy-loads the active trust store via TrustStoreManager."""
        return self.trust_store_manager.get_store()

    @staticmethod
    def _get_x509_subject(identifier_str):
        """Converts an SNI identifier to an x509 Subject for ServerVerifier."""
        return get_x509_subject(identifier_str)

    def _verify_pkix_path(self, leaf_cert, candidate_intermediates):
        """Raw RFC 5280 PKIX path validation without hostname binding."""
        return verify_pkix_path(
            leaf_cert,
            candidate_intermediates,
            trust_store_type=self.trust_store_type,
            base_dir=self.trust_store_manager.base_dir
        )

    def extract_tls_info(self):
        """
        Extracts negotiated TLS session parameters (versions, ciphers, key exchange).
        Maintains 100% backward-compatible flat structure for existing consumers.
        """
        return extract_tls_info(self.pcap_path)

    def reconstruct_handshake(self):
        """
        RFC-Compliant TLS Handshake Reconstruction Engine (RFC 5246, RFC 8446).
        Extracts client capabilities, server negotiation, cryptographic parameters,
        packet flight sequencing, and evaluates stateful downgrade forensics.
        """
        return reconstruct_handshake(self.pcap_path)

    def extract_certificate(self):
        """Extracts and cryptographically validates transmitted X.509 certificate chains."""
        return extract_certificates(self.pcap_path, trust_store_manager=self.trust_store_manager)

    def detect_protocol(self):
        """DPI email protocol classifier (SMTP, IMAP, POP3) inspecting payloads and ports."""
        return detect_protocol(self.pcap_path)

    def detect_starttls(self):
        """
        Tracks the chronological 5-step STARTTLS state machine per TCP stream:
        1. Advertisement -> 2. Client Command -> 3. Server Response -> 4. TLS Handshake -> 5. Cleartext Audit.
        """
        return detect_starttls(self.pcap_path, tls_sessions=self.extract_tls_info())

    def analyze(self):
        """
        Unified PCAP Forensic Analysis Pipeline.
        ========================================
        Correlates TLS handshake reconstruction, X.509 certificate telemetry,
        protocol DPI classification, and STARTTLS state machines across all
        observed TCP streams into a single unified session object.
        
        CORRELATION SCHEMA PER STREAM:
          - stream_id: TCP stream index (int).
          - protocol: Classified protocol ("SMTP", "IMAP", "POP3", "Unknown").
          - starttls: Detailed 5-step STARTTLS state machine results and transition status.
          - tls: Flat negotiated TLS parameters (backward compatible).
          - handshake: Full RFC 5246/8446 reconstructed flight, capabilities, and forensics.
          - certificate: X.509 leaf and intermediate telemetry, trust status, and SAN match.
        
        Returns:
          Dict mapping stream_id (int) -> unified session analysis object.
        """
        tls_info = self.extract_tls_info()
        handshake_info = self.reconstruct_handshake()
        cert_info = self.extract_certificate()
        protocol_info = self.detect_protocol()
        starttls_info = self.detect_starttls()

        all_stream_ids = sorted(set(
            list(tls_info.keys()) +
            list(handshake_info.keys()) +
            list(cert_info.keys()) +
            list(protocol_info.keys()) +
            list(starttls_info.keys())
        ))

        sessions = {}
        for sid in all_stream_ids:
            sessions[sid] = {
                "stream_id": sid,
                "protocol": protocol_info.get(sid, "Unknown"),
                "starttls": starttls_info.get(sid, {
                    "stream": sid,
                    "starttls_offered": False,
                    "starttls_requested": False,
                    "starttls_accepted": False,
                    "tls_active": sid in tls_info,
                    "plaintext_auth_attempted": False,
                    "status": "IMPLICIT_TLS" if sid in tls_info else "CLEARTEXT_NO_ENCRYPTION",
                    "details": "Implicit TLS session" if sid in tls_info else "Cleartext session"
                }),
                "tls": tls_info.get(sid, None),
                "handshake": handshake_info.get(sid, None),
                "certificate": cert_info.get(sid, None)
            }

        return sessions


if __name__ == "__main__":
    target_pcap = sys.argv[1] if len(sys.argv) > 1 else "../tls12_only.pcap"
    
    print("\n" + "=" * 80)
    print(f" SECUREMAILSCOPE FORENSIC TELEMETRY ENGINE")
    print(f" Target PCAP: {os.path.abspath(target_pcap)}")
    print("=" * 80)

    # 1. Primary Analysis: Testbed Trust Store (Default for lab/synthetic captures)
    analyzer = PCAPAnalyzer(target_pcap, trust_store="testbed")
    analyzer._get_trust_store()
    print(f"\n[ACTIVE TRUST STORE] {analyzer.trust_store_description}")

    print("\n" + "-" * 40 + " [1] UNIFIED SESSION RECONSTRUCTION " + "-" * 40)
    unified_sessions = analyzer.analyze()
    print(json.dumps(unified_sessions, indent=2))

    print("\n" + "-" * 40 + " [2] TLS SESSION PARAMETERS " + "-" * 40)
    tls_sessions = analyzer.extract_tls_info()
    print(json.dumps(tls_sessions, indent=2))

    print("\n" + "-" * 40 + " [3] X.509 CERTIFICATE TELEMETRY & TRUST VALIDATION " + "-" * 40)
    cert_sessions = analyzer.extract_certificate()
    print(json.dumps(cert_sessions, indent=2))

    print("\n" + "-" * 40 + " [4] PROTOCOL DETECTION " + "-" * 40)
    protocol = analyzer.detect_protocol()
    print(json.dumps(protocol, indent=2))

    print("\n" + "-" * 40 + " [5] STARTTLS STATE MACHINE " + "-" * 40)
    starttls_state = analyzer.detect_starttls()
    print(json.dumps(starttls_state, indent=2))

    print("\n" + "-" * 40 + " [6] RECONSTRUCTED TLS HANDSHAKE & FORENSICS " + "-" * 40)
    handshake_sessions = analyzer.reconstruct_handshake()
    print(json.dumps(handshake_sessions, indent=2))

    # 2. Forensic Trust Store Comparison: Testbed vs Production (Mozilla CA Bundle)
    print("\n" + "=" * 80)
    print(" FORENSIC TRUST STORE COMPARISON (Testbed CA vs Mozilla Production CA)")
    print("=" * 80)
    analyzer_prod = PCAPAnalyzer(target_pcap, trust_store="production")
    analyzer_prod._get_trust_store()
    cert_prod = analyzer_prod.extract_certificate()

    for sid in cert_sessions:
        tb_stream = cert_sessions[sid]
        prod_stream = cert_prod.get(sid, {})
        if "leaf_cert" not in tb_stream:
            print(f"\n[Stream {sid}] Certificate Parse Diagnostics:")
            print(f"  Status: {tb_stream.get('trust_status')}")
            print(f"  Errors: {tb_stream.get('parse_errors')}")
            continue
        print(f"\n[Stream {sid}] Subject: {tb_stream['leaf_cert']['subject_cn']}")
        print(f"  • Under 'testbed' store    : {tb_stream['trust_status']} | Anchored: {tb_stream['anchored_in_active_store']}")
        print(f"    Details: {tb_stream['trust_details']}")
        print(f"  • Under 'production' store : {prod_stream.get('trust_status')} | Anchored: {prod_stream.get('anchored_in_active_store')}")
        print(f"    Details: {prod_stream.get('trust_details')}")

    print("\n" + "=" * 80 + "\n")
