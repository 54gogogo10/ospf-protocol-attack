import struct
from scapy.all import IP, raw, Raw
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello, OSPF_LSUpd, OSPF_LSA_Hdr

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

AUTH_NONE = 0
AUTH_PLAIN = 1
AUTH_MD5 = 2


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
    options: int = 0x02,
):
    ip = IP(src=src_ip, dst=dst_ip, proto=89, ttl=1)
    ospf_hdr = OSPF_Hdr(
        version=2,
        type=OSPF_TYPE_HELLO,
        src=router_id,
        area=area_id,
        authtype=auth_type,
    )
    hello = OSPF_Hello(
        mask="255.255.255.0",
        hellointerval=hello_interval,
        prio=router_priority,
        deadinterval=router_dead_interval,
        router=designated_router,
        backup=backup_dr,
        options=options,
    )
    return ip / ospf_hdr / hello


def build_lsu_packet(
    router_id: str,
    area_id: str,
    src_ip: str,
    dst_ip: str,
    lsa_count: int = 1,
):
    ip = IP(src=src_ip, dst=dst_ip, proto=89, ttl=1)
    ospf_hdr = OSPF_Hdr(
        version=2,
        type=OSPF_TYPE_LSU,
        src=router_id,
        area=area_id,
    )
    lsu = OSPF_LSUpd(lsacount=lsa_count)
    return ip / ospf_hdr / lsu


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
        pkt = IP(raw(data))
        if pkt.haslayer(OSPF_Hdr):
            return pkt
        return None
    except Exception:
        return None


def get_ospf_type_name(ptype: int) -> str:
    return OSPF_TYPE_NAMES.get(ptype, f"Unknown({ptype})")
