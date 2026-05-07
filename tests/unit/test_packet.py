import pytest
from ospf_attack.core.packet import (
    build_hello_packet, build_lsu_packet, build_lsa_header,
    parse_ospf_packet, get_ospf_type_name, OSPF_TYPE_HELLO, OSPF_TYPE_LSU,
)


class TestBuildHelloPacket:
    def test_minimal_hello(self):
        pkt = build_hello_packet(
            router_id="1.1.1.1", area_id="0.0.0.0",
            src_ip="10.0.0.1", dst_ip="224.0.0.5",
        )
        assert pkt is not None
        assert pkt.haslayer("OSPF_Hdr")
        assert pkt["OSPF_Hdr"].type == OSPF_TYPE_HELLO
        assert pkt["OSPF_Hdr"].src == "1.1.1.1"
        assert pkt["OSPF_Hdr"].area == "0.0.0.0"

    def test_hello_with_priority(self):
        pkt = build_hello_packet(
            router_id="1.1.1.1", area_id="0.0.0.0",
            src_ip="10.0.0.1", dst_ip="224.0.0.5",
            router_priority=200,
        )
        assert pkt["OSPF_Hello"].prio == 200


class TestBuildLSUPacket:
    def test_minimal_lsu(self):
        pkt = build_lsu_packet(
            router_id="1.1.1.1", area_id="0.0.0.0",
            src_ip="10.0.0.1", dst_ip="224.0.0.5",
            lsa_count=0,
        )
        assert pkt is not None
        assert pkt["OSPF_Hdr"].type == OSPF_TYPE_LSU


class TestBuildLSAHeader:
    def test_router_lsa(self):
        lsa = build_lsa_header(
            lsa_type=1, link_state_id="1.1.1.1",
            advertising_router="1.1.1.1",
            sequence=0x80000001, age=0,
        )
        assert lsa is not None

    def test_external_lsa(self):
        lsa = build_lsa_header(
            lsa_type=5, link_state_id="10.0.0.0",
            advertising_router="1.1.1.1",
            sequence=0x80000001, age=0,
        )
        assert lsa is not None

    def test_max_age_lsa(self):
        lsa = build_lsa_header(
            lsa_type=1, link_state_id="1.1.1.1",
            advertising_router="1.1.1.1",
            sequence=0x80000001, age=3600,
        )
        assert lsa is not None

    def test_max_sequence(self):
        lsa = build_lsa_header(
            lsa_type=1, link_state_id="1.1.1.1",
            advertising_router="1.1.1.1",
            sequence=0x7FFFFFFF, age=0,
        )
        assert lsa is not None


class TestParseOSPFacket:
    def test_returns_none_for_non_ospf(self):
        from scapy.all import IP, UDP
        pkt = IP() / UDP(sport=12345, dport=53)
        result = parse_ospf_packet(bytes(pkt))
        assert result is None


class TestOSPFTypeName:
    def test_hello(self):
        assert get_ospf_type_name(1) == "Hello"

    def test_lsu(self):
        assert get_ospf_type_name(4) == "LSU"
