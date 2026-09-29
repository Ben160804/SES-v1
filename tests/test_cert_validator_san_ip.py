"""
analysis/test_cert_validator_san_ip.py
======================================
Comprehensive unit tests for check_hostname_match() per RFC 9525 / RFC 6125 and RFC 5280.
Validates:
  1. IPv4 exact match against iPAddress SAN (PCAP-116 scenario)
  2. IPv4 mismatch against iPAddress SAN
  3. RFC 9525 §4.4: IP reference identity MUST NOT match against dNSName SAN or Subject CN
  4. RFC 9525 §4.3: Wildcard matching MUST NOT be applied to IP addresses
  5. IPv6 normalization (compressed :: vs uncompressed leading zeros)
  6. Bracketed IPv6 reference identity ([2001:db8::1])
  7. Strict typed parsing: malformed candidate entries in san_ip do not trigger false string matches
  8. DNS reference identity against certificate containing only iPAddress SANs (returns MISMATCH)
  9. Backward compatibility for legacy 3-argument callers (san_ip omitted)
  10. Single-level wildcard match (*.example.com matches mail.example.com)
  11. Multi-level wildcard mismatch (*.example.com does not match a.mail.example.com)
  12. Cert without identifiers returns SKIPPED_NO_CERT_IDENTIFIER
  13. Empty or None claimed_sni returns SKIPPED_NO_SNI
"""

import unittest
from analysis.cert_validator import check_hostname_match


class TestIPAddressSANMatching(unittest.TestCase):
    """
    RFC 9525 §4.4 / RFC 5280 §4.2.1.6 IP-ID reference identity tests.
    """

    def test_pcap116_ipv4_matched(self):
        """PCAP-116: IP reference identity 172.28.0.10 matches iPAddress SAN 172.28.0.10."""
        status = check_hostname_match(
            claimed_sni="172.28.0.10",
            san_dns=[],
            leaf_cn="mail.test.local",
            san_ip=["172.28.0.10"]
        )
        self.assertEqual(status, "MATCHED")

    def test_ipv4_mismatch(self):
        """IP reference identity does not match any entry in san_ip."""
        status = check_hostname_match(
            claimed_sni="172.28.0.10",
            san_dns=[],
            leaf_cn="mail.test.local",
            san_ip=["10.0.0.1", "192.168.1.1"]
        )
        self.assertEqual(status, "MISMATCH")

    def test_rfc9525_no_cn_or_dns_fallback_for_ip(self):
        """
        RFC 9525 §4.4:
        If reference ID is an IP, client MUST NOT match against dNSName SAN or Subject CN.
        Even if leaf_cn or san_dns contains the exact string '172.28.0.10', if san_ip
        is empty, it must return MISMATCH.
        """
        status = check_hostname_match(
            claimed_sni="172.28.0.10",
            san_dns=["172.28.0.10"],
            leaf_cn="172.28.0.10",
            san_ip=[]
        )
        self.assertEqual(status, "MISMATCH")

    def test_rfc9525_wildcard_prohibited_for_ip(self):
        """
        RFC 9525 §4.3 / RFC 6125 §6.4.3: Wildcards cannot match an IP-ID.
        """
        status = check_hostname_match(
            claimed_sni="172.28.0.10",
            san_dns=["*.28.0.10"],
            leaf_cn="*.28.0.10",
            san_ip=["*.28.0.10"]
        )
        self.assertEqual(status, "MISMATCH")

    def test_ipv6_normalization(self):
        """
        RFC 9525 §4.4: Octet-for-octet comparison allows canonical representation equivalence.
        Compressed 2001:db8::1 matches uncompressed 2001:0db8:0000:0000:0000:0000:0000:0001.
        """
        status = check_hostname_match(
            claimed_sni="2001:db8::1",
            san_dns=[],
            leaf_cn=None,
            san_ip=["2001:0db8:0000:0000:0000:0000:0000:0001"]
        )
        self.assertEqual(status, "MATCHED")

    def test_ipv6_bracketed_notation(self):
        """Client reference identity using [2001:db8::1] bracket notation."""
        status = check_hostname_match(
            claimed_sni="[2001:db8::1]",
            san_dns=[],
            leaf_cn=None,
            san_ip=["2001:db8::1"]
        )
        self.assertEqual(status, "MATCHED")

    def test_strictly_typed_san_ip_ignores_malformed_candidates(self):
        """
        Malformed candidates in san_ip raise ValueError when parsed by ipaddress,
        and must be safely ignored without raising exceptions or falling back to raw string equality.
        """
        # Candidate list has a malformed string followed by the correct IP
        status = check_hostname_match(
            claimed_sni="172.28.0.10",
            san_dns=[],
            leaf_cn=None,
            san_ip=["not_an_ip_address", "172.28.0.10"]
        )
        self.assertEqual(status, "MATCHED")

        # Candidate list has only a malformed string matching target string literal
        status2 = check_hostname_match(
            claimed_sni="172.28.0.10",
            san_dns=[],
            leaf_cn=None,
            san_ip=["172.28.0.10.malformed"]
        )
        self.assertEqual(status2, "MISMATCH")

    def test_dns_reference_identity_with_ip_only_cert(self):
        """
        RFC 9525 §4.4: A DNS reference identity cannot match an iPAddress SAN.
        When cert has only san_ip, it must return MISMATCH.
        """
        status = check_hostname_match(
            claimed_sni="mail.example.com",
            san_dns=[],
            leaf_cn=None,
            san_ip=["172.28.0.10"]
        )
        self.assertEqual(status, "MISMATCH")

    def test_backward_compatibility_3_args(self):
        """Callers invoking check_hostname_match with only 3 positional arguments continue to work."""
        status = check_hostname_match(
            "mail.example.com",
            ["mail.example.com"],
            "mail.example.com"
        )
        self.assertEqual(status, "MATCHED")

    def test_dns_wildcard_matching(self):
        """Standard RFC 9525 §4.3 single-level wildcard matching."""
        status = check_hostname_match(
            claimed_sni="mail.example.com",
            san_dns=["*.example.com"],
            leaf_cn=None,
            san_ip=[]
        )
        self.assertEqual(status, "MATCHED")

    def test_dns_wildcard_multi_label_mismatch(self):
        """Wildcard *.example.com does not match a.mail.example.com (crosses label boundary)."""
        status = check_hostname_match(
            claimed_sni="a.mail.example.com",
            san_dns=["*.example.com"],
            leaf_cn=None,
            san_ip=[]
        )
        self.assertEqual(status, "MISMATCH")

    def test_skipped_no_cert_identifier(self):
        """Cert has no san_dns, no san_ip, and no valid leaf_cn."""
        status_ip = check_hostname_match(
            claimed_sni="172.28.0.10",
            san_dns=[],
            leaf_cn="Unknown",
            san_ip=[]
        )
        self.assertEqual(status_ip, "SKIPPED_NO_CERT_IDENTIFIER")

        status_dns = check_hostname_match(
            claimed_sni="mail.example.com",
            san_dns=[],
            leaf_cn=None,
            san_ip=[]
        )
        self.assertEqual(status_dns, "SKIPPED_NO_CERT_IDENTIFIER")

    def test_skipped_no_sni(self):
        """No reference identity provided returns SKIPPED_NO_SNI."""
        self.assertEqual(check_hostname_match("", ["mail.example.com"], "mail.example.com"), "SKIPPED_NO_SNI")
        self.assertEqual(check_hostname_match(None, ["mail.example.com"], "mail.example.com"), "SKIPPED_NO_SNI")


if __name__ == "__main__":
    unittest.main()
