from scapy.all import IP, raw
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
