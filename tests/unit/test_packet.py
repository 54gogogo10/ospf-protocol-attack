import pytest
from ospf_attack.core.packet import (
    build_hello_packet, build_lsu_packet, build_lsa_header,
    parse_ospf_packet, get_ospf_type_name, OSPF_TYPE_HELLO, OSPF_TYPE_LSU,
    AUTH_NONE, AUTH_PLAIN, AUTH_MD5,
)
from ospf_attack.core.auth import _pad_key


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


class TestHelloAuth:
    """Hello packet with authentication."""

    def test_hello_auth_none_default(self):
        pkt = build_hello_packet(
            router_id="1.1.1.1", area_id="0.0.0.0",
            src_ip="10.0.0.1", dst_ip="224.0.0.5",
        )
        assert pkt["OSPF_Hdr"].authtype == AUTH_NONE
        # Serialized: auth field is 8 zero bytes
        raw = bytes(pkt)
        iphl = (raw[0] & 0x0F) * 4
        assert raw[iphl + 16:iphl + 24] == b"\x00" * 8

    def test_hello_auth_plain(self):
        pkt = build_hello_packet(
            router_id="1.1.1.1", area_id="0.0.0.0",
            src_ip="10.0.0.1", dst_ip="224.0.0.5",
            auth_type=AUTH_PLAIN, auth_key=b"secret",
        )
        assert pkt["OSPF_Hdr"].authtype == AUTH_PLAIN
        # Verify serialized: auth field contains padded password
        expected = _pad_key(b"secret")
        raw = bytes(pkt)
        iphl = (raw[0] & 0x0F) * 4
        assert raw[iphl + 16:iphl + 24] == expected

    def test_hello_auth_md5_sets_fields(self):
        pkt = build_hello_packet(
            router_id="1.1.1.1", area_id="0.0.0.0",
            src_ip="10.0.0.1", dst_ip="224.0.0.5",
            auth_type=AUTH_MD5, auth_key=b"mykey", crypto_seq=100,
        )
        assert pkt["OSPF_Hdr"].authtype == AUTH_MD5
        assert pkt["OSPF_Hdr"].authdatalen == 16
        assert pkt["OSPF_Hdr"].seq == 100
        # MD5 trailer should be appended (Raw layer after Hello)
        raw = bytes(pkt)
        assert len(raw) > 44  # basic Hello is ~44 bytes; MD5 adds 16


class TestLSUAuth:
    """LSU packet with authentication."""

    def test_lsu_auth_none_default(self):
        pkt = build_lsu_packet(
            router_id="1.1.1.1", area_id="0.0.0.0",
            src_ip="10.0.0.1", dst_ip="224.0.0.6", lsa_count=1,
        )
        assert pkt["OSPF_Hdr"].authtype == AUTH_NONE

    def test_lsu_auth_plain(self):
        pkt = build_lsu_packet(
            router_id="1.1.1.1", area_id="0.0.0.0",
            src_ip="10.0.0.1", dst_ip="224.0.0.6", lsa_count=1,
            auth_type=AUTH_PLAIN, auth_key=b"secret",
        )
        assert pkt["OSPF_Hdr"].authtype == AUTH_PLAIN

    def test_lsu_auth_md5_has_trailer(self):
        pkt = build_lsu_packet(
            router_id="1.1.1.1", area_id="0.0.0.0",
            src_ip="10.0.0.1", dst_ip="224.0.0.6", lsa_count=1,
            auth_type=AUTH_MD5, auth_key=b"mykey", crypto_seq=1,
        )
        assert pkt["OSPF_Hdr"].authtype == AUTH_MD5
        assert pkt["OSPF_Hdr"].authdatalen == 16
        # MD5 trailer present
        raw = bytes(pkt)
        # IP(20) + OSPF(24) + LSU(4) + MD5(16) = 64
        iphl = (raw[0] & 0x0F) * 4
        assert len(raw) >= iphl + 24 + 4 + 16


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
