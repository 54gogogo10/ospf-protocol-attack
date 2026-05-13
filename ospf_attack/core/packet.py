import struct
from scapy.all import IP, raw, Raw
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello, OSPF_LSUpd, OSPF_LSA_Hdr
from scapy.fields import RawVal

from .auth import AUTH_NONE, AUTH_PLAIN, AUTH_MD5, build_ospf_auth, _pad_key, _MD5_TRAILER_LEN

OSPF_TYPE_HELLO = 1
OSPF_TYPE_DD = 2
OSPF_TYPE_LSR = 3
OSPF_TYPE_LSU = 4
OSPF_TYPE_LSAck = 5

OSPF_TYPE_NAMES = {
    1: "Hello",
    2: "DB Description",
    3: "LS Request",
    4: "LSU",
    5: "LS Ack",
}

OSPF_MULTICAST_ALL = "224.0.0.5"
OSPF_MULTICAST_DR = "224.0.0.6"

# Re-export for backward compatibility
# (AUTH_NONE, AUTH_PLAIN, AUTH_MD5 now canonical in auth.py)


def _apply_auth_ospf_hdr(ospf_hdr: OSPF_Hdr, auth_type: int, auth_key: bytes,
                          crypto_seq: int = 1) -> OSPF_Hdr:
    """Configure OSPF_Hdr fields for authentication (mutates in place)."""
    ospf_hdr.authtype = auth_type
    if auth_type == AUTH_PLAIN:
        ospf_hdr.authdata = RawVal(_pad_key(auth_key))
    elif auth_type == AUTH_MD5:
        ospf_hdr.keyid = 1
        ospf_hdr.authdatalen = _MD5_TRAILER_LEN
        ospf_hdr.seq = crypto_seq
    return ospf_hdr


def _apply_md5_trailer(pkt, auth_key: bytes):
    """Compute and append MD5 HMAC trailer to a Scapy OSPF packet.

    Returns a new packet (IP/OSPF/body/Raw(trailer)).
    """
    from hashlib import md5
    import hmac

    # Serialize with auth field zeroed
    raw_pkt = bytes(pkt)
    ospf_hdr = pkt[1]  # pkt = IP / OSPF_Hdr / ...
    ip = pkt[0]

    # Zero auth field in serialized form, compute HMAC
    iphl = (raw_pkt[0] & 0x0F) * 4
    ospf_start = iphl
    data = (raw_pkt[:ospf_start + 16]
            + b"\x00\x00\x00\x00\x00\x00\x00\x00"
            + raw_pkt[ospf_start + 24:])
    digest = hmac.HMAC(auth_key, data, md5).digest()

    return pkt / Raw(digest)


def build_hello_packet(
    router_id: str,
    area_id: str,
    src_ip: str,
    dst_ip: str,
    router_priority: int = 1,
    hello_interval: int = 10,
    router_dead_interval: int = 40,
    designated_router: str = "0.0.0.0",
    backup_dr: str = "0.0.0.0",
    auth_type: int = AUTH_NONE,
    auth_key: bytes = b"",
    crypto_seq: int = 1,
    options: int = 0x02,
):
    ip = IP(src=src_ip, dst=dst_ip, proto=89, ttl=1)
    ospf_hdr = _apply_auth_ospf_hdr(
        OSPF_Hdr(version=2, type=OSPF_TYPE_HELLO, src=router_id, area=area_id),
        auth_type, auth_key, crypto_seq)
    hello = OSPF_Hello(
        mask="255.255.255.0",
        hellointerval=hello_interval,
        prio=router_priority,
        deadinterval=router_dead_interval,
        router=designated_router,
        backup=backup_dr,
        options=options,
    )
    pkt = ip / ospf_hdr / hello
    if auth_type == AUTH_MD5:
        pkt = _apply_md5_trailer(pkt, auth_key)
    return pkt


def build_lsu_packet(
    router_id: str,
    area_id: str,
    src_ip: str,
    dst_ip: str,
    lsa_count: int = 1,
    auth_type: int = AUTH_NONE,
    auth_key: bytes = b"",
    crypto_seq: int = 1,
):
    ip = IP(src=src_ip, dst=dst_ip, proto=89, ttl=1)
    ospf_hdr = _apply_auth_ospf_hdr(
        OSPF_Hdr(version=2, type=OSPF_TYPE_LSU, src=router_id, area=area_id),
        auth_type, auth_key, crypto_seq)
    lsu = OSPF_LSUpd(lsacount=lsa_count)
    pkt = ip / ospf_hdr / lsu
    if auth_type == AUTH_MD5:
        pkt = _apply_md5_trailer(pkt, auth_key)
    return pkt


def build_lsa_header(
    lsa_type: int,
    link_state_id: str,
    advertising_router: str,
    sequence: int = 0x80000001,
    age: int = 0,
    options: int = 0x22,
):
    return OSPF_LSA_Hdr(
        type=lsa_type,
        id=link_state_id,
        adrouter=advertising_router,
        seq=sequence,
        age=age,
        options=options,
    )


def build_router_lsa_body(
    advertising_router: str,
    flags: int = 0x02,  # 0x02 = ASBR
) -> bytes:
    """Build a Type-1 Router-LSA body with a single stub link."""
    link_id = advertising_router
    link_data = "255.255.255.255"
    link_type = 3  # Stub
    num_tos = 0
    metric = 1

    body = struct.pack("!BBH",
        flags & 0x07, 0, 1)  # flags, reserved, link count = 1
    # Link entry (12 bytes)
    body += bytes(int(x) for x in link_id.split("."))
    body += bytes(int(x) for x in link_data.split("."))
    body += struct.pack("!BBH", link_type, num_tos, metric)
    return body


def build_external_lsa_body(
    network_mask: str = "255.255.255.0",
    metric: int = 20,
    forwarding_address: str = "0.0.0.0",
    external_route_tag: int = 0,
) -> bytes:
    """Build a Type-5 External LSA body."""
    body = bytes(int(x) for x in network_mask.split("."))
    # bit E=1 (Type-5), metric in upper 24 bits
    body += struct.pack("!I", 0x80000000 | (metric & 0x00FFFFFF))
    body += bytes(int(x) for x in forwarding_address.split("."))
    body += struct.pack("!I", external_route_tag)
    return body


def build_full_lsa(
    lsa_type: int,
    link_state_id: str,
    advertising_router: str,
    sequence: int = 0x80000001,
    age: int = 0,
    options: int = 0x22,
    body_data: bytes = b"",
):
    """Build an LSA header with a Raw body payload."""
    hdr = OSPF_LSA_Hdr(
        type=lsa_type,
        id=link_state_id,
        adrouter=advertising_router,
        seq=sequence,
        age=age,
        options=options,
    )
    if body_data:
        return hdr / Raw(body_data)
    return hdr


def build_lsa_with_body(
    lsa_type: int,
    link_state_id: str,
    advertising_router: str,
    sequence: int = 0x80000001,
    age: int = 0,
    metric: int = 1,
    network_mask: str = "255.255.255.0",
) -> bytes:
    """Build a complete OSPF LSA (header + body) based on LSA type.

    Returns bytes ready to be appended to an LSU packet via /Raw().
    """
    if lsa_type == 1:  # Router-LSA
        body = build_router_lsa_body(advertising_router)
    elif lsa_type == 3:  # Summary-LSA (Type-3)
        # Summary body: network mask (4) + metric (4)
        body = (bytes(int(x) for x in network_mask.split("."))
                + struct.pack("!I", metric & 0x00FFFFFF))
    elif lsa_type == 5:  # External-LSA (Type-5)
        body = build_external_lsa_body(network_mask, metric)
    else:
        body = b""
    return build_full_lsa(lsa_type, link_state_id, advertising_router,
                          sequence, age, body_data=body)


def parse_ospf_packet(data: bytes):
    try:
        pkt = IP(data)
        if pkt.haslayer(OSPF_Hdr):
            return pkt
        return None
    except Exception:
        return None


def get_ospf_type_name(ptype: int) -> str:
    return OSPF_TYPE_NAMES.get(ptype, f"Unknown({ptype})")
