"""
analysis/test_tls_session_hrr.py
================================
Unit tests for RFC 8446 §4.1.4 HelloRetryRequest flight relabeling
and session state preservation in analysis/tls_session.py.
"""

import unittest
from unittest.mock import patch, MagicMock
from analysis.tls_session import (
    reconstruct_handshake,
    extract_tls_info,
    RFC8446_HRR_RANDOM,
)


class TestHelloRetryRequest(unittest.TestCase):
    """
    Test suite for RFC 8446 §4.1.4 HelloRetryRequest handling.
    """

    @patch("analysis.tls_session.subprocess.run")
    def test_hrr_followed_by_server_hello(self, mock_run):
        """
        In a standard TLS 1.3 HRR exchange:
          Frame 10: ClientHello
          Frame 12: ServerHello (HRR random: cf21ad74...)
          Frame 14: ClientHello
          Frame 16: ServerHello (normal random: aabbccdd...)
        Verify:
          1. Frame 12 is relabeled as 'HelloRetryRequest'
          2. Frame 16 remains 'ServerHello'
          3. Final server_negotiation preserves hello_retry_request = True
          4. Negotiated parameters reflect the final ServerHello
        """
        # Pass 1: flight extraction (frame, stream, hs_type, rec_ct, al_lvl, al_dsc, reasm, opaque_ct)
        out_pass1 = (
            "10\t0\t1\t\t\t\t\t\n"       # Frame 10: ClientHello
            "12\t0\t2\t\t\t\t\t\n"       # Frame 12: HRR (type 2)
            "14\t0\t1\t\t\t\t\t\n"       # Frame 14: ClientHello (2nd)
            "16\t0\t2\t\t\t\t\t\n"       # Frame 16: ServerHello (type 2)
            "16\t0\t20\t\t\t\t\t\n"      # Frame 16: Finished
        )

        # Pass 2: ClientHello extraction
        out_pass2 = (
            "0\t0x0303\t0x0304\t0x1301,0x1302\t0x0017,0x001d\t0x0017\t\t\tmail.test.local\t\t\t"
        )

        # Pass 3: ServerHello extraction (with frame.number as field 0)
        # Line 1: Frame 12 (HRR) requests group 0x001d (x25519) via selected_group
        # Line 2: Frame 16 (ServerHello) confirms group 0x001d via key_share
        normal_random = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        out_pass3 = (
            f"12\t0\t0x0303\t0x0304\t0x1302\t\t0x001d\t\t{RFC8446_HRR_RANDOM}\n"
            f"16\t0\t0x0303\t0x0304\t0x1302\t0x001d\t\t\t{normal_random}\n"
        )

        # Pass 4: ServerKeyExchange (empty for TLS 1.3)
        out_pass4 = ""

        # Configure mock_run return values in order of execution
        mock_run.side_effect = [
            MagicMock(stdout=out_pass1),  # Pass 1: flight
            MagicMock(stdout=out_pass2),  # Pass 2: ClientHello
            MagicMock(stdout=out_pass3),  # Pass 3: ServerHello
            MagicMock(stdout=out_pass4),  # Pass 4: ServerKeyExchange
        ]

        result = reconstruct_handshake("dummy.pcap")
        self.assertIn(0, result)
        stream_data = result[0]

        # 1. Verify flight messages
        messages = stream_data["flight"]["messages"]
        self.assertEqual(len(messages), 5)
        # Message 0: ClientHello at frame 10
        self.assertEqual(messages[0]["frame"], 10)
        self.assertEqual(messages[0]["message"], "ClientHello")
        # Message 1: HRR at frame 12
        self.assertEqual(messages[1]["frame"], 12)
        self.assertEqual(messages[1]["message"], "HelloRetryRequest")
        # Message 2: Second ClientHello at frame 14
        self.assertEqual(messages[2]["frame"], 14)
        self.assertEqual(messages[2]["message"], "ClientHello")
        # Message 3: ServerHello at frame 16 (must NOT be overwritten with HelloRetryRequest!)
        self.assertEqual(messages[3]["frame"], 16)
        self.assertEqual(messages[3]["message"], "ServerHello")
        # Message 4: Finished at frame 16
        self.assertEqual(messages[4]["frame"], 16)
        self.assertEqual(messages[4]["message"], "Finished")

        # 2. Verify server negotiation preserves HRR fact and reflects final ServerHello
        sh = stream_data["server_negotiation"]
        self.assertTrue(sh["hello_retry_request"])
        self.assertTrue(sh["is_hello_retry_request"])
        self.assertEqual(sh["selected_tls_version"], "TLS 1.3")
        self.assertEqual(sh["selected_cipher"]["name"], "TLS_AES_256_GCM_SHA384")
        self.assertEqual(sh["tls13_key_exchange_group"], "x25519")
        self.assertEqual(sh["tls13_key_exchange_mode"], "ECDHE")
        self.assertEqual(sh["selected_cipher"]["kex_mechanism"], "ECDHE")
        self.assertTrue(sh["selected_cipher"]["forward_secrecy"])

    @patch("analysis.tls_session.reconstruct_handshake")
    def test_extract_tls_info_exposes_hello_retry_request(self, mock_recon):
        """Verify extract_tls_info projects hello_retry_request properly."""
        mock_recon.return_value = {
            0: {
                "server_negotiation": {
                    "raw_version": "0x0304",
                    "selected_tls_version": "TLS 1.3",
                    "selected_cipher": {
                        "hex": "0x1302",
                        "name": "TLS_AES_256_GCM_SHA384",
                        "strength": "HIGH",
                        "forward_secrecy": True,
                        "kex_mechanism": "ECDHE"
                    },
                    "tls13_key_exchange_group": "x25519",
                    "tls13_psk_selected": False,
                    "tls13_key_exchange_mode": "ECDHE",
                    "hello_retry_request": True,
                }
            }
        }
        sessions = extract_tls_info("dummy.pcap")
        self.assertIn(0, sessions)
        self.assertTrue(sessions[0]["hello_retry_request"])
        self.assertEqual(sessions[0]["tls_version"], "TLS 1.3")

    @patch("analysis.tls_session.subprocess.run")
    def test_handshake_without_hrr(self, mock_run):
        """Verify standard handshake without HRR reports hello_retry_request = False."""
        normal_random = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        out_pass1 = "10\t0\t1\t\t\t\t\t\n12\t0\t2\t\t\t\t\t\n"
        out_pass2 = "0\t0x0303\t0x0304\t0x1302\t0x001d\t0x001d\t\t\tmail.test.local\t\t\t"
        out_pass3 = f"12\t0\t0x0303\t0x0304\t0x1302\t0x001d\t\t\t{normal_random}\n"
        out_pass4 = ""

        mock_run.side_effect = [
            MagicMock(stdout=out_pass1),
            MagicMock(stdout=out_pass2),
            MagicMock(stdout=out_pass3),
            MagicMock(stdout=out_pass4),
        ]

        result = reconstruct_handshake("dummy.pcap")
        self.assertIn(0, result)
        stream_data = result[0]
        self.assertFalse(stream_data["server_negotiation"]["hello_retry_request"])
        self.assertEqual(stream_data["flight"]["messages"][1]["message"], "ServerHello")

    @patch("analysis.tls_session.subprocess.run")
    def test_hrr_defensive_fallback_first_type2(self, mock_run):
        """
        If frame numbers diverge (e.g. synthetic data or missing frame), verify
        that only the first chronological type-2 message is relabeled to HRR,
        and the subsequent type-2 message remains ServerHello.
        """
        out_pass1 = (
            "10\t0\t1\t\t\t\t\t\n"
            "999\t0\t2\t\t\t\t\t\n"       # First type-2 message (different frame)
            "14\t0\t1\t\t\t\t\t\n"
            "888\t0\t2\t\t\t\t\t\n"       # Second type-2 message (different frame)
        )
        out_pass2 = "0\t0x0303\t0x0304\t0x1302\t0x001d\t0x001d\t\t\tmail.test.local\t\t\t"
        normal_random = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        # Line 1 has frame 12 (not matching 999), Line 2 has frame 16 (not matching 888)
        out_pass3 = (
            f"12\t0\t0x0303\t0x0304\t0x1302\t\t0x001d\t\t{RFC8446_HRR_RANDOM}\n"
            f"16\t0\t0x0303\t0x0304\t0x1302\t0x001d\t\t\t{normal_random}\n"
        )
        out_pass4 = ""

        mock_run.side_effect = [
            MagicMock(stdout=out_pass1),
            MagicMock(stdout=out_pass2),
            MagicMock(stdout=out_pass3),
            MagicMock(stdout=out_pass4),
        ]

        result = reconstruct_handshake("dummy.pcap")
        messages = result[0]["flight"]["messages"]
        self.assertEqual(messages[1]["message"], "HelloRetryRequest")
        self.assertEqual(messages[3]["message"], "ServerHello")
        self.assertTrue(result[0]["server_negotiation"]["hello_retry_request"])


if __name__ == "__main__":
    unittest.main()
