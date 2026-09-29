"""
Regression & Unit Tests: TCP Stream Reassembly and Directional DPI
-------------------------------------------------------------------
Verifies:
  1. Parsing of TShark follow,tcp,raw output into normalized StreamFlow instances.
  2. Client/Server direction attribution when Node 0 is server or Node 1 is server.
  3. Reassembly and detection when protocol lines are split across TCP segments.
  4. STARTTLS state machine tracking when STARTTLS commands/responses are fragmented.
  5. Integration with live PCAPs (baseline_test.pcap, smtp_cleartext_insecure.pcap),
     including automatic deduplication of retransmitted TCP segments.

Usage:
    python3 analysis/test_stream_reassembly.py
"""

import os
import sys

_here = os.path.dirname(os.path.abspath(__file__))
_root = os.path.dirname(_here)
if _root not in sys.path:
    sys.path.insert(0, _root)

from analysis.starttls import (
    StreamFlow,
    parse_follow_raw_output,
    reassemble_tcp_streams,
    detect_protocol,
    detect_starttls,
    _identify_server_node,
    _parse_endpoint,
)


def test_endpoint_parser():
    """Verifies IPv4 and IPv6 endpoint string parsing."""
    ip, port = _parse_endpoint("192.168.1.1:25")
    assert ip == "192.168.1.1" and port == 25, f"IPv4 parse failed: {ip}:{port}"

    ip6, port6 = _parse_endpoint("[::1]:587")
    assert ip6 == "::1" and port6 == 587, f"IPv6 parse failed: {ip6}:{port6}"


def test_server_node_identification():
    """Verifies server vs client identification does not assume Node 0 is client."""
    # Case A: Node 1 has server banner (SMTP 220) -> Node 1 is server
    s1 = _identify_server_node(53304, 25, b"ehlo client\r\n", b"220 mail.test.local ESMTP\r\n")
    assert s1 == 1, f"Expected Node 1 as server, got {s1}"

    # Case B: Node 0 has server banner (SMTP 220) -> Node 0 is server
    s0 = _identify_server_node(25, 49152, b"220 mail.insecure.corp ESMTP\r\n", b"EHLO client\r\n")
    assert s0 == 0, f"Expected Node 0 as server, got {s0}"

    # Case C: IMAP banner on Node 0
    s_imap = _identify_server_node(143, 60000, b"* OK IMAP4rev1 ready\r\n", b"a001 CAPABILITY\r\n")
    assert s_imap == 0, f"Expected Node 0 as IMAP server, got {s_imap}"

    # Case D: POP3 banner on Node 1
    s_pop = _identify_server_node(55000, 110, b"USER alice\r\n", b"+OK POP3 server ready\r\n")
    assert s_pop == 1, f"Expected Node 1 as POP3 server, got {s_pop}"


def test_protocol_line_split_across_segments():
    """
    Verifies that when a server banner line is split across multiple TCP segments,
    the continuous reassembled byte stream restores the full line and detect_protocol
    correctly classifies it.
    """
    # Segment 1: "220 mai" -> hex: 323230206d6169
    # Segment 2: "l.example.com ESMTP\r\n" -> hex: 6c2e6578616d706c652e636f6d2045534d54500d0a
    sample = (
        "===================================================================\n"
        "Follow: tcp,raw\n"
        "Filter: tcp.stream eq 0\n"
        "Node 0: 10.0.0.1:45000\n"
        "Node 1: 10.0.0.2:25\n"
        "\t323230206d6169\n"
        "\t6c2e6578616d706c652e636f6d2045534d54500d0a\n"
        "65686c6f20636c69656e740d0a\n"
        "===================================================================\n"
    )
    flows = parse_follow_raw_output(sample)
    assert 0 in flows, "Stream 0 not found in flows"
    flow = flows[0]

    # Check continuous reassembly
    assert flow.server_data == b"220 mail.example.com ESMTP\r\n", (
        f"Server data was not reassembled continuously: {flow.server_data!r}"
    )
    assert flow.server_port == 25
    assert flow.client_port == 45000

    # Check protocol detection on reassembled stream
    proto = detect_protocol("", streams=flows)
    assert proto.get(0) == "SMTP", f"Expected SMTP from split banner, got {proto.get(0)}"


def test_starttls_command_split_across_segments():
    """
    Verifies that a STARTTLS command fragmented across TCP segments is reconstructed
    and evaluated by detect_starttls as a continuous command.
    """
    # Flow:
    # 1. Server sends 220 banner: "220 mail.test.local ESMTP\r\n"
    # 2. Client sends EHLO: "ehlo client\r\n"
    # 3. Server advertises 250-STARTTLS: "250-STARTTLS\r\n250 HELP\r\n"
    # 4. Client sends STARTTLS fragmented: "STAR" in seg 1, "TTLS\r\n" in seg 2
    # 5. Server accepts: "220 Ready to start TLS\r\n"
    # 6. Client starts TLS (ClientHello): \x16\x03\x01\x00\x05...
    sample = (
        "===================================================================\n"
        "Follow: tcp,raw\n"
        "Filter: tcp.stream eq 0\n"
        "Node 0: 10.0.0.1:50000\n"
        "Node 1: 10.0.0.2:25\n"
        "\t323230206d61696c2e746573742e6c6f63616c2045534d54500d0a\n"
        "65686c6f20636c69656e740d0a\n"
        "\t3235302d5354415254544c530d0a3235302048454c500d0a\n"
        "53544152\n"
        "54544c530d0a\n"
        "\t32323020322e302e3020526561647920746f20737461727420544c530d0a\n"
        "16030100050100000100\n"
        "===================================================================\n"
    )
    flows = parse_follow_raw_output(sample)
    flow = flows[0]

    # Verify client_data has continuous STARTTLS
    assert b"STARTTLS\r\n" in flow.client_data, (
        f"STARTTLS command was not concatenated in client_data: {flow.client_data!r}"
    )

    # State machine evaluation with simulated active TLS session
    res = detect_starttls("", tls_sessions={0: {"tls_version": "TLS 1.3"}}, streams=flows)
    st = res.get(0, {})

    assert st.get("starttls_offered") is True, "starttls_offered should be True"
    assert st.get("starttls_requested") is True, "starttls_requested should be True for split command"
    assert st.get("starttls_accepted") is True, "starttls_accepted should be True"
    assert st.get("status") == "UPGRADED", f"Expected UPGRADED status, got {st.get('status')}"


def test_integration_baseline_pcap():
    """
    Integration test using the real capture testbed/pcaps/baseline_test.pcap.
    Verifies:
      - Endpoints attributed properly (server is port 25, client is port 53304).
      - Reassembled streams deduplicate the retransmitted packets present in the raw capture.
      - Protocol is detected as SMTP.
      - STARTTLS state machine reaches UPGRADED.
    """
    pcap_path = os.path.join(_root, "testbed", "pcaps", "baseline_test.pcap")
    if not os.path.exists(pcap_path):
        print("  SKIP  test_integration_baseline_pcap (file not found)")
        return

    flows = reassemble_tcp_streams(pcap_path)
    assert 0 in flows, "Stream 0 not found in baseline_test.pcap"
    flow = flows[0]

    assert flow.server_port == 25, f"Expected server port 25, got {flow.server_port}"
    assert flow.client_port == 53304, f"Expected client port 53304, got {flow.client_port}"
    assert flow.server == "172.28.0.10:25"
    assert flow.client == "172.28.0.1:53304"

    # Retransmission deduplication check:
    # The capture has duplicate frames for greeting banner; reassembly must have exactly 1
    assert flow.server_data.count(b"220 mail.test.local ESMTP Postfix\r\n") == 1, (
        "Duplicate server greeting was not deduplicated by TShark TCP reassembly!"
    )
    assert flow.client_data.count(b"STARTTLS\r\n") == 1, (
        "Duplicate STARTTLS command was not deduplicated by TShark TCP reassembly!"
    )

    proto = detect_protocol(pcap_path, streams=flows)
    assert proto.get(0) == "SMTP", f"Expected SMTP, got {proto.get(0)}"

    st = detect_starttls(pcap_path, streams=flows)
    assert st.get(0, {}).get("status") == "UPGRADED", f"Expected UPGRADED, got {st.get(0)}"


def test_integration_cleartext_pcap():
    """
    Integration test using smtp_cleartext_insecure.pcap where Node 0 was the server.
    Verifies direction handling when Node 0 is server and credentials detection.
    """
    pcap_path = os.path.join(_root, "smtp_cleartext_insecure.pcap")
    if not os.path.exists(pcap_path):
        print("  SKIP  test_integration_cleartext_pcap (file not found)")
        return

    flows = reassemble_tcp_streams(pcap_path)
    assert 0 in flows
    flow = flows[0]

    # In this capture, Node 0 is 192.168.1.25:25 (server)
    assert flow.server == "192.168.1.25:25", f"Expected server 192.168.1.25:25, got {flow.server}"
    assert flow.client == "192.168.1.100:49152", f"Expected client 192.168.1.100:49152, got {flow.client}"

    proto = detect_protocol(pcap_path, streams=flows)
    assert proto.get(0) == "SMTP"

    st = detect_starttls(pcap_path, streams=flows)
    assert st.get(0, {}).get("status") == "DOWNGRADE_OR_STRIPPED"
    assert st.get(0, {}).get("plaintext_auth_attempted") is True


def test_starttls_rejected_smtp():
    """
    Verifies that when a client requests STARTTLS after server advertisement,
    and the server responds with a 4xx/5xx rejection (RFC 3207 §4.2),
    detect_starttls outputs STARTTLS_REJECTED and sets starttls_rejected=True.
    """
    # Flow:
    # S: 220 mail.test.local ESMTP\r\n
    # C: EHLO client\r\n
    # S: 250-STARTTLS\r\n250 HELP\r\n
    # C: STARTTLS\r\n
    # S: 454 4.7.0 TLS not available due to temporary reason\r\n
    sample = (
        "===================================================================\n"
        "Follow: tcp,raw\n"
        "Filter: tcp.stream eq 0\n"
        "Node 0: 10.0.0.1:50000\n"
        "Node 1: 10.0.0.2:25\n"
        "\t323230206d61696c2e746573742e6c6f63616c2045534d54500d0a\n"
        "45484c4f20636c69656e740d0a\n"
        "\t3235302d5354415254544c530d0a3235302048454c500d0a\n"
        "5354415254544c530d0a\n"
        "\t34353420342e372e3020544c53206e6f7420617661696c61626c650d0a\n"
        "===================================================================\n"
    )
    flows = parse_follow_raw_output(sample)
    res = detect_starttls("", tls_sessions={}, streams=flows)
    st = res[0]

    assert st["starttls_offered"] is True, "starttls_offered must be True"
    assert st["starttls_requested"] is True, "starttls_requested must be True"
    assert st["starttls_accepted"] is False, "starttls_accepted must be False"
    assert st["starttls_rejected"] is True, "starttls_rejected must be True"
    assert st["status"] == "STARTTLS_REJECTED", f"Expected STARTTLS_REJECTED, got {st['status']}"


def test_starttls_rejected_pop3():
    """
    Verifies POP3 STLS rejection (-ERR response per RFC 2595 §4) emits STARTTLS_REJECTED.
    """
    # Flow:
    # S: +OK POP3 server ready\r\n
    # C: CAPA\r\n
    # S: +OK Capability list follows\r\nSTLS\r\n.\r\n
    # C: STLS\r\n
    # S: -ERR Command not permitted when TLS is already active\r\n
    sample = (
        "===================================================================\n"
        "Follow: tcp,raw\n"
        "Filter: tcp.stream eq 0\n"
        "Node 0: 10.0.0.1:51000\n"
        "Node 1: 10.0.0.2:110\n"
        "\t2b4f4b20504f5033207365727665722072656164790d0a\n"
        "434150410d0a\n"
        "\t2b4f4b204361706162696c6974790d0a53544c530d0a2e0d0a\n"
        "53544c530d0a\n"
        "\t2d45525220544c532074656d706f726172696c7920756e617661696c61626c650d0a\n"
        "===================================================================\n"
    )
    flows = parse_follow_raw_output(sample)
    res = detect_starttls("", tls_sessions={}, streams=flows)
    st = res[0]

    assert st["starttls_offered"] is True
    assert st["starttls_requested"] is True
    assert st["starttls_rejected"] is True
    assert st["status"] == "STARTTLS_REJECTED"


def test_starttls_rejected_imap_tagged():
    """
    Verifies that IMAP STARTTLS rejection correlates to the specific command tag (RFC 3501 §6.2.1),
    ignoring subsequent unrelated negative responses.
    """
    # Flow:
    # S: * OK IMAP4rev1 Service Ready\r\n
    # C: a001 CAPABILITY\r\n
    # S: * CAPABILITY IMAP4rev1 STARTTLS\r\n a001 OK Completed\r\n
    # C: a002 STARTTLS\r\n
    # S: a002 NO TLS negotiation failed\r\n
    # C: a003 NOOP\r\n
    # S: a003 NO Command failed\r\n
    sample = (
        "===================================================================\n"
        "Follow: tcp,raw\n"
        "Filter: tcp.stream eq 0\n"
        "Node 0: 10.0.0.1:52000\n"
        "Node 1: 10.0.0.2:143\n"
        "\t2a204f4b20494d4150347265763120536572766963652052656164790d0a\n"
        "61303031204341504142494c4954590d0a\n"
        "\t2a204341504142494c49545920494d41503472657631205354415254544c530d0a61303031204f4b20436f6d706c657465640d0a\n"
        "61303032205354415254544c530d0a\n"
        "\t61303032204e4f20544c53206e65676f74696174696f6e206661696c65640d0a\n"
        "61303033204e4f4f500d0a\n"
        "\t61303033204e4f20436f6d6d616e64206661696c65640d0a\n"
        "===================================================================\n"
    )
    flows = parse_follow_raw_output(sample)
    res = detect_starttls("", tls_sessions={}, streams=flows)
    st = res[0]

    assert st["starttls_offered"] is True
    assert st["starttls_requested"] is True
    assert st["starttls_accepted"] is False
    assert st["starttls_rejected"] is True
    assert st["status"] == "STARTTLS_REJECTED"


def test_starttls_accepted_imap_with_later_no():
    """
    Verifies that when IMAP STARTTLS is accepted (a002 OK), a subsequent unrelated
    negative response (a003 NO) does NOT trigger rejection or corrupt UPGRADED state.
    """
    # Flow:
    # S: * OK IMAP4rev1 Service Ready\r\n
    # C: a001 CAPABILITY\r\n
    # S: * CAPABILITY IMAP4rev1 STARTTLS\r\n a001 OK Completed\r\n
    # C: a002 STARTTLS\r\n
    # S: a002 OK Begin TLS negotiation\r\n
    # C: [TLS ClientHello]
    # ... session established ...
    # C: a003 BADCMD\r\n
    # S: a003 NO Command not understood\r\n
    sample = (
        "===================================================================\n"
        "Follow: tcp,raw\n"
        "Filter: tcp.stream eq 0\n"
        "Node 0: 10.0.0.1:52000\n"
        "Node 1: 10.0.0.2:143\n"
        "\t2a204f4b20494d4150347265763120536572766963652052656164790d0a\n"
        "61303031204341504142494c4954590d0a\n"
        "\t2a204341504142494c49545920494d41503472657631205354415254544c530d0a61303031204f4b20436f6d706c657465640d0a\n"
        "61303032205354415254544c530d0a\n"
        "\t61303032204f4b20426567696e20544c53206e65676f74696174696f6e0d0a\n"
        "16030100050100000100\n"
        "6130303320424144434d440d0a\n"
        "\t61303033204e4f20436f6d6d616e64206e6f7420756e64657273746f6f640d0a\n"
        "===================================================================\n"
    )
    flows = parse_follow_raw_output(sample)
    res = detect_starttls("", tls_sessions={0: {"tls_version": "TLS 1.3"}}, streams=flows)
    st = res[0]

    assert st["starttls_offered"] is True
    assert st["starttls_requested"] is True
    assert st["starttls_accepted"] is True
    assert st["starttls_rejected"] is False, "Subsequent a003 NO must NOT trigger starttls_rejected"
    assert st["status"] == "UPGRADED", f"Expected UPGRADED, got {st['status']}"


def test_starttls_without_advertisement_smtp():
    """
    Verifies that when a client requests STARTTLS without observing capability
    advertisement, detect_starttls outputs STARTTLS_WITHOUT_ADVERTISEMENT while
    still preserving starttls_rejected=True if the server subsequently rejects it.
    """
    # Flow:
    # S: 220 mail.test.local ESMTP\r\n
    # C: EHLO client\r\n
    # S: 250-PIPELINING\r\n250 HELP\r\n  (NO STARTTLS offered!)
    # C: STARTTLS\r\n                   (Unprompted request)
    # S: 502 5.5.1 Command not implemented\r\n
    sample = (
        "===================================================================\n"
        "Follow: tcp,raw\n"
        "Filter: tcp.stream eq 0\n"
        "Node 0: 10.0.0.1:53000\n"
        "Node 1: 10.0.0.2:25\n"
        "\t323230206d61696c2e746573742e6c6f63616c2045534d54500d0a\n"
        "45484c4f20636c69656e740d0a\n"
        "\t3235302d504950454c494e494e470d0a3235302048454c500d0a\n"
        "5354415254544c530d0a\n"
        "\t35303220352e352e3120436f6d6d616e64206e6f7420696d706c656d656e7465640d0a\n"
        "===================================================================\n"
    )
    flows = parse_follow_raw_output(sample)
    res = detect_starttls("", tls_sessions={}, streams=flows)
    st = res[0]

    assert st["starttls_offered"] is False, "starttls_offered must be False"
    assert st["starttls_requested"] is True, "starttls_requested must be True"
    assert st["starttls_rejected"] is True, "starttls_rejected must be preserved as True"
    assert st["status"] == "STARTTLS_WITHOUT_ADVERTISEMENT", f"Expected STARTTLS_WITHOUT_ADVERTISEMENT, got {st['status']}"


def test_empty_stream_schema_consistency():
    """Verifies that an empty/no-flow stream returns starttls_rejected=False for schema consistency."""
    # Empty flow with no chunks
    flow = StreamFlow(
        stream_id=99, client="", server="", client_ip="", client_port=0,
        server_ip="", server_port=0, client_data=b"", server_data=b"", chunks=[]
    )
    res = detect_starttls("", tls_sessions={}, streams={99: flow})
    st = res[99]

    assert "starttls_rejected" in st, "starttls_rejected must be present in empty stream result"
    assert st["starttls_rejected"] is False


if __name__ == "__main__":
    tests = [
        test_endpoint_parser,
        test_server_node_identification,
        test_protocol_line_split_across_segments,
        test_starttls_command_split_across_segments,
        test_starttls_rejected_smtp,
        test_starttls_rejected_pop3,
        test_starttls_rejected_imap_tagged,
        test_starttls_accepted_imap_with_later_no,
        test_starttls_without_advertisement_smtp,
        test_empty_stream_schema_consistency,
        test_integration_baseline_pcap,
        test_integration_cleartext_pcap,
    ]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
        except AssertionError as e:
            print(f"  FAIL  {t.__name__}\n        {e}")
            failed += 1
        except Exception as e:
            print(f"  ERROR {t.__name__}\n        {type(e).__name__}: {e}")
            failed += 1
    print()
    if failed:
        print(f"{failed}/{len(tests)} test(s) failed.")
        sys.exit(1)
    print(f"All {len(tests)} tests passed.")

