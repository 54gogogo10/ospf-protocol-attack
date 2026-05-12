from dataclasses import dataclass, field
from enum import Enum


class AttackMode(Enum):
    PASSIVE = "passive"
    ACTIVE = "active"


class SniffMode(Enum):
    HUB = "hub"
    ARP_SPOOF = "arp_spoof"


class AttackCategory(Enum):
    ADJACENCY = "adjacency"
    LSA = "lsa"
    DOS = "dos"
    PROTOCOL = "protocol"


@dataclass
class AttackResult:
    success: bool
    packets_sent: int
    target_affected: bool
    details: str
    evidence: dict = field(default_factory=dict)


@dataclass
class AttackConfig:
    """所有攻击类型共享的基础配置"""
    iface: str
    target: str
    mode: AttackMode = AttackMode.PASSIVE
    sniff_mode: SniffMode = SniffMode.HUB
    router_id: str = "1.1.1.1"
    area_id: str = "0.0.0.0"

    sniff_duration: int = 30

    arp_target_a: str = ""
    arp_target_b: str = ""
    arp_interval: int = 2

    packet_rate: int = 10
    max_packets: int = 0

    verbose: bool = False


@dataclass
class HelloInjectionConfig(AttackConfig):
    """恶意 Hello 注入 / 邻接破坏 / DR 操纵 专用配置"""
    hello_interval: int = 10
    router_dead_interval: int = 40
    router_priority: int = 255
    auth_type: str = "none"
    auth_key: str = ""
    subnet_mask: str = "255.255.255.0"


@dataclass
class LSAConfig(AttackConfig):
    """LSA 攻击专用配置"""
    lsa_type: int = 5
    link_state_id: str = ""
    advertising_router: str = ""
    sequence_number: int = 0x80000001
    age: int = 0
    metric: int = 1
    network_mask: str = "255.255.255.0"
    forwarding_address: str = "0.0.0.0"
    external_routes: list = field(default_factory=list)


@dataclass
class DoSConfig(AttackConfig):
    """拒绝服务攻击专用配置"""
    duration: int = 60
    thread_count: int = 1
    lsa_change_interval: int = 2
    lsa_count: int = 1000


@dataclass
class MITMConfig(AttackConfig):
    """中间人攻击专用配置"""
    target_a: str = ""
    target_b: str = ""
    action: str = "modify"
    modify_rules: list = field(default_factory=list)


@dataclass
class ReplayConfig(AttackConfig):
    """重放攻击专用配置"""
    capture_file: str = ""
    replay_loop: bool = False
    replay_interval: int = 5
    modify_fields: dict = field(default_factory=dict)
