# OSPF 协议攻击模拟器 — 设计文档

**日期:** 2026-05-08
**状态:** 草案

## 1. 概述

基于 Python 的 OSPF 协议攻击模拟与测试工具，通过 PyInstaller 打包为单个 Windows `.exe` 文件，支持 Win7+ 零依赖部署。支持旁路模式（不建立邻居关系，被动嗅探+注入）和主动模式（建立邻居关系后攻击），可对虚拟和物理 OSPF 路由器发起测试。

### 使用场景
- 教育/实验环境：隔离虚拟网络（GNS3/EVE-NG/Docker）
- 受控渗透测试：对物理路由器进行安全评估
- 安全研究：新攻击技术开发

### 交互方式
- 核心 Python 库（可导入的 SDK）
- CLI 命令行工具（基于 Click）作为主要操作入口

---

## 2. 技术栈

| 层级 | 选型 | 理由 |
|------|------|------|
| 语言 | Python 3.10+ | 协议库成熟，开发效率高 |
| 协议引擎 | Scapy（`scapy.contrib.ospf`） | 原生 OSPF 报文构造/解析 |
| 高性能发包 | Raw Socket 降级方案 | 泛洪攻击时的低层注入 |
| 报文捕获 | pcap-ct（提供 `import pcap`）+ Npcap | Windows 平台混杂模式嗅探 |
| CLI | Click | 轻量级，子命令可组合 |
| 打包 | PyInstaller `--onefile` | 单文件 ~45MB `.exe`，无需安装 Python |
| Npcap 捆绑 | `--add-binary` 嵌入 + 启动时自动检测 | 零配置网络抓包 |
| 测试 | pytest + Docker FRRouting 拓扑 | 单元测试 + 集成验证 |
| 配置格式 | YAML | 人类可读的攻击场景文件 |

---

## 3. 架构

### 目录结构

```
OSPF_Protocol_Attack/
├── ospf_attack/
│   ├── __init__.py
│   ├── core/                         # 核心引擎
│   │   ├── __init__.py
│   │   ├── packet.py                 # OSPF 报文构造/解析（Scapy 封装）
│   │   ├── neighbor.py               # 邻居状态机（Down→Init→2-Way→Full）
│   │   ├── lsa_db.py                 # 链路状态数据库模拟
│   │   ├── router.py                 # 虚拟路由器身份（ID、区域、认证）
│   │   ├── sniffer.py                # 被动嗅探引擎
│   │   ├── arp_spoof.py              # ARP 欺骗引擎（交换环境用）
│   │   └── event.py                  # 事件总线，解耦通信
│   ├── attacks/                      # 攻击插件
│   │   ├── __init__.py
│   │   ├── base.py                   # AttackBase 抽象基类 + AttackResult
│   │   ├── adjacency/                # 邻接关系攻击
│   │   │   ├── hello_inject.py       # 恶意 Hello 注入
│   │   │   ├── adjacency_break.py    # 邻接关系破坏
│   │   │   └── dr_bdr_hijack.py      # DR/BDR 选举操纵
│   │   ├── lsa/                      # LSA 攻击
│   │   │   ├── route_inject.py       # 路由注入/毒化
│   │   │   ├── max_seq.py            # 最大序列号攻击
│   │   │   ├── max_age.py            # Max-Age 攻击
│   │   │   └── fight_back.py         # Fight-back 反击
│   │   ├── dos/                      # 拒绝服务攻击
│   │   │   ├── flood.py              # Hello/LSA 泛洪
│   │   │   ├── spf_recalc.py         # SPF 重计算攻击
│   │   │   └── db_overflow.py        # 数据库溢出
│   │   └── protocol/                 # 协议级操控攻击
│   │       ├── mitm.py               # 中间人攻击
│   │       └── replay.py             # 重放攻击
│   ├── network/                      # 网络抽象层
│   │   ├── sender.py                 # 发包器（Scapy + Raw Socket 降级）
│   │   └── adapter.py                # 接口抽象（pcap/Ethernet 按环境适配）
│   ├── config/                       # 配置体系
│   │   ├── config.py                 # 配置加载器（YAML + CLI 合并，三层优先级）
│   │   └── types.py                  # 各攻击类别的 dataclass 配置类型
│   ├── npcap/                        # Npcap 依赖管理
│   │   ├── detector.py               # 启动时检测 Npcap 是否存在
│   │   └── installer.py              # 内嵌安装程序提取 + 静默安装
│   ├── cli/                          # CLI 层
│   │   ├── __init__.py
│   │   ├── main.py                   # Click 入口
│   │   ├── commands.py               # 每个攻击类型的子命令注册
│   │   └── formatters.py             # 输出格式化（表格、JSON、摘要）
│   └── utils/                        # 工具函数
│       ├── validators.py             # IP/路由/参数校验
│       └── logging.py                # 结构化日志与审计追踪
├── tests/
│   ├── unit/                         # 单元测试（每个模块独立）
│   │   ├── test_packet.py
│   │   ├── test_neighbor.py
│   │   ├── test_hello_inject.py
│   │   └── ...
│   └── integration/                  # Docker 集成测试
│       ├── conftest.py               # FRR 容器 fixtures
│       └── test_topology_attacks.py
├── docker/                           # 集成测试拓扑
│   ├── topo1-single-area/
│   │   ├── docker-compose.yml
│   │   └── frr/
│   │       ├── r1/
│   │       └── r2/
│   └── topo2-multi-area/
├── assets/
│   └── npcap-installer.exe           # 内嵌 Npcap 安装程序
├── pyproject.toml
├── README.md
└── build.ps1                         # PyInstaller 构建脚本
```

### 核心设计原则

1. **插件式架构** — 每个攻击类型为独立模块，实现 `AttackBase` 接口
2. **双模式攻击** — PASSIVE（旁路，不建邻居）/ ACTIVE（主动，建邻居后攻击）
3. **双环境嗅探** — HUB（集线器，直接混杂嗅探）/ ARP_SPOOF（交换环境，先 ARP 欺骗再嗅探）
4. **事件总线** — 攻击逻辑与网络传输层解耦
5. **三层配置优先级** — 默认值 → YAML 配置文件 → CLI 参数，后者覆盖前者
6. **自包含部署** — 单 `.exe` 内嵌 Npcap，启动时自动检测 + 提示安装

---

## 4. AttackBase 接口

```python
from abc import ABC, abstractmethod
from enum import Enum
from dataclasses import dataclass, field

class AttackMode(Enum):
    PASSIVE = "passive"       # 旁路：不建邻居，嗅探 + 注入
    ACTIVE  = "active"        # 主动：先建邻居，借助邻居关系攻击

class SniffMode(Enum):
    HUB       = "hub"         # 集线器环境：直接混杂模式嗅探
    ARP_SPOOF = "arp_spoof"   # 交换环境：先 ARP 欺骗，再嗅探

class AttackCategory(Enum):
    ADJACENCY = "adjacency"   # 邻接关系
    LSA       = "lsa"         # 链路状态通告
    DOS       = "dos"         # 拒绝服务
    PROTOCOL  = "protocol"    # 协议级操控

@dataclass
class AttackResult:
    """攻击执行结果"""
    success: bool              # 攻击是否成功执行
    packets_sent: int          # 发送的报文数
    target_affected: bool      # 目标是否受影响（由 verify 判定）
    details: str               # 详细信息
    evidence: dict = field(default_factory=dict)  # 验证证据（如抓包摘要）

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
        """阶段一：初始化——嗅探拓扑或建立邻接关系"""

    @abstractmethod
    def launch(self) -> AttackResult:
        """阶段二：执行攻击"""

    @abstractmethod
    def verify(self) -> bool:
        """阶段三：通过观察状态变化确认攻击效果"""

    @abstractmethod
    def teardown(self) -> None:
        """阶段四：清理资源（关闭 socket、重置状态）"""

    def run(self) -> AttackResult:
        """模板方法，统一编排四个阶段"""
        try:
            self.setup()
            result = self.launch()
            result.target_affected = self.verify()
            return result
        finally:
            self.teardown()
```

---

## 5. 攻击模块清单

### 5.1 邻接关系攻击（ADJACENCY）

| # | 模块 | 默认模式 | 攻击手法 | 验证指标 |
|---|------|---------|---------|---------|
| 1 | `hello-inject` | 旁路 | 嗅探合法 Hello 报文，注入伪造 Hello 建立未授权邻接关系 | 目标邻居表出现攻击者的 Router ID 条目 |
| 2 | `adjacency-break` | 旁路 | 注入畸形 Hello（错误 Area ID、认证不匹配、1-Way 状态），破坏合法邻居关系 | 目标邻居状态从 Full 变为 Down |
| 3 | `dr-bdr-hijack` | 旁路 | 注入 Priority=255 的 Hello 报文，抢占 DR 角色 | 目标的 DR/BDR 角色变化，LSA 泛洪路径被重定向 |

### 5.2 LSA 攻击（LSA）

| # | 模块 | 默认模式 | 攻击手法 | 验证指标 |
|---|------|---------|---------|---------|
| 4 | `route-inject` | 旁路 | 嗅探合法 LSU，构造毒化 LSA（Type-5 外部路由或 Type-3 区域间路由），通过 LSU 注入 | 目标路由表出现毒化路由条目 |
| 5 | `max-seq` | 旁路 | 注入 Sequence=0x7FFFFFFF 的 LSU，合法 LSA 因序列号更低被忽略 | 目标 LSDB 中攻击者 LSA 成为权威版本 |
| 6 | `max-age` | 旁路 | 注入 Age=3600（MaxAge）的 LSU，迫使目标清除该 LSA | 目标 LSDB 对应条目被删除；路由表丢失对应路由 |
| 7 | `fight-back` | 旁路 | 持续嗅探合法 LSA，即时注入更高序列号的对抗 LSA | 合法 LSA 无法传播，攻击者版本持续存在 |

### 5.3 拒绝服务攻击（DOS）

| # | 模块 | 默认模式 | 攻击手法 | 验证指标 |
|---|------|---------|---------|---------|
| 8 | `flood` | 旁路 | 高频发送 Hello/LSU 报文，耗尽路由器 CPU 资源 | 目标 CPU 使用率持续 >80% |
| 9 | `spf-recalc` | 旁路 | 持续注入变化的 LSA，迫使路由器反复执行 SPF 算法 | SPF 执行间隔低于可配置阈值（默认 1 秒） |
| 10 | `db-overflow` | 旁路 | 注入大量外部 LSA（Type-5），填满链路状态数据库 | 目标 LSDB 条目数超过配置上限，路由器可能进入过载状态 |

### 5.4 协议级操控攻击（PROTOCOL）

| # | 模块 | 默认模式 | 攻击手法 | 验证指标 |
|---|------|---------|---------|---------|
| 11 | `mitm` | 旁路 | 可选集线器模式（直接混杂嗅探）或 ARP 欺骗模式（欺骗后嗅探），拦截 OSPF 报文 → 篡改 → 转发 | 目标路由表反映被篡改 LSA 的内容 |
| 12 | `replay` | 旁路 | 捕获合法 OSPF 报文 → 延后重放（可选修改字段）引发路由震荡 | 目标路由表震荡，LSDB 出现序列号回退 |

---

## 6. 配置体系

### 6.1 基础配置

```python
@dataclass
class AttackConfig:
    """所有攻击类型共享的基础配置"""
    iface: str                              # 网卡接口
    target: str                             # 目标 IP 或网段
    mode: AttackMode = AttackMode.PASSIVE   # 攻击模式
    sniff_mode: SniffMode = SniffMode.HUB   # 嗅探模式：hub / arp_spoof
    router_id: str = "1.1.1.1"             # 伪装的路由器 ID
    area_id: str = "0.0.0.0"               # OSPF 区域

    # 嗅探参数
    sniff_duration: int = 30                # 嗅探持续时间（秒）

    # ARP 欺骗参数（仅 sniff_mode=arp_spoof 时生效）
    arp_target_a: str = ""                  # ARP 欺骗目标 A IP
    arp_target_b: str = ""                  # ARP 欺骗目标 B IP
    arp_interval: int = 2                   # ARP 欺骗包发送间隔（秒）

    # 发包参数
    packet_rate: int = 10                   # 每秒发包数（pps）
    max_packets: int = 0                    # 最大发包数，0=不限

    # 输出参数
    verbose: bool = False
    pcap_output: str = ""                   # 输出 pcap 文件路径
```

### 6.2 各攻击类别专用配置

```python
@dataclass
class HelloInjectionConfig(AttackConfig):
    """恶意 Hello 注入 / 邻接破坏 / DR 操纵 专用配置"""
    hello_interval: int = 10                # Hello 发送间隔
    router_dead_interval: int = 40          # Dead 间隔
    router_priority: int = 255              # 路由器优先级
    auth_type: str = "none"                 # 认证类型：none / plain / md5
    auth_key: str = ""
    subnet_mask: str = "255.255.255.0"

@dataclass
class LSAConfig(AttackConfig):
    """LSA 攻击专用配置"""
    lsa_type: int = 5                       # LSA 类型：1=Router, 3=Summary, 5=External
    link_state_id: str = ""
    advertising_router: str = ""
    sequence_number: int = 0x80000001       # 序列号
    age: int = 0                            # LSA Age，Max-Age 攻击设为 3600
    metric: int = 1
    network_mask: str = "255.255.255.0"
    forwarding_address: str = "0.0.0.0"
    external_routes: list = field(default_factory=list)  # Type-5 注入的外部路由列表

@dataclass
class DoSConfig(AttackConfig):
    """拒绝服务攻击专用配置"""
    duration: int = 60                      # 攻击持续时间（秒）
    thread_count: int = 1                   # 并发发包线程数
    lsa_change_interval: int = 2            # SPF 重计算：LSA 变化间隔（秒）
    lsa_count: int = 1000                   # DB 溢出：注入 LSA 数量

@dataclass
class MITMConfig(AttackConfig):
    """中间人攻击专用配置"""
    target_a: str = ""                      # 路由器 A IP
    target_b: str = ""                      # 路由器 B IP
    action: str = "modify"                  # 操作类型：drop / modify / forward / inject
    modify_rules: list = field(default_factory=list)  # 修改规则列表

@dataclass
class ReplayConfig(AttackConfig):
    """重放攻击专用配置"""
    capture_file: str = ""                  # 捕获的 pcap 文件路径
    replay_loop: bool = False               # 是否循环重放
    replay_interval: int = 5                # 重放间隔（秒）
    modify_fields: dict = field(default_factory=dict)  # 重放时修改的字段
```

### 6.3 配置优先级

默认值 → YAML 配置文件 → CLI 参数（后者覆盖前者）

### 6.4 CLI 使用示例

```bash
# 旁路 Hello 注入（集线器模式）
ospf-attack hello-inject --iface eth0 --target 192.168.1.0/24 \
    --passive --sniff-mode hub --priority 255 --sniff-duration 30

# Max-Age 攻击清除 LSA（ARP 欺骗模式下嗅探）
ospf-attack max-age --iface eth0 --target 224.0.0.5 \
    --passive --sniff-mode arp_spoof \
    --arp-target-a 10.0.0.1 --arp-target-b 10.0.0.2 \
    --age 3600 --lsa-type 1

# DoS 泛洪（无需 ARP 欺骗，直接发包）
ospf-attack flood --iface eth0 --target 224.0.0.5 \
    --duration 60 --packet-rate 500 --thread-count 4

# MITM（ARP 欺骗模式）
ospf-attack mitm --iface eth1 --target 10.0.0.0/24 \
    --sniff-mode arp_spoof --target-a 10.0.0.1 --target-b 10.0.0.2 \
    --action modify

# 从 YAML 配置文件加载
ospf-attack mitm --config ./mitm_attack.yaml
```

### 6.5 YAML 配置文件示例

```yaml
# mitm_attack_hub.yaml（集线器环境）
attack: mitm
iface: eth1
target: 10.0.0.0/24
sniff_mode: hub
mode: passive
sniff_duration: 60
action: modify
modify_rules:
  - field: lsa.age
    set: 3600
  - field: lsa.metric
    add: 100
verbose: true
pcap_output: ./attack_capture.pcap

# mitm_attack_arp.yaml（交换环境，ARP 欺骗）
attack: mitm
iface: eth1
target: 10.0.0.0/24
sniff_mode: arp_spoof
arp_target_a: 10.0.0.1
arp_target_b: 10.0.0.2
arp_interval: 2
mode: passive
sniff_duration: 60
action: modify
modify_rules:
  - field: lsa.age
    set: 3600
verbose: true
```

---

## 7. Npcap 依赖管理

### 启动流程

```
程序启动
    │
    ├─ 检测 Npcap 是否已安装
    │   ├─ 读取注册表 HKLM\SOFTWARE\WOW6432Node\Npcap
    │   └─ 或尝试 pcap.findalldevs()
    │
    ├─ 已安装 → 嗅探功能正常启用
    │
    └─ 未安装 → 控制台提示
        "检测到系统中未安装 Npcap，缺少 Npcap 将无法使用嗅探功能。
         是否安装 Npcap？(Y/n)"
        ├─ Y → 从内嵌资源提取 npcap-installer.exe 到 %TEMP%
        │       静默安装：npcap-installer.exe /S
        │       安装后重新检测 → 嗅探功能启用
        └─ N → 嗅探功能降级，发包攻击全部可用
```

- 所有 12 类攻击模块的纯发包模式不依赖 Npcap
- 仅被动嗅探拓扑发现功能需要 Npcap

---

## 8. 数据流

### 8.1 集线器模式（sniff_mode=hub）

```
[OSPF 网络] ── 混杂嗅探 ──→ Sniffer (pcap-ct)
                                  │
                                  ▼
                            报文解析器 (Scapy)
                                  │
                                  ▼
                            拓扑模型
                            ├─ router_ids[]       路由器 ID 列表
                            ├─ area_ids[]         区域 ID 列表
                            ├─ dr_bdr_map{}       DR/BDR 映射
                            └─ lsa_summary[]      LSA 摘要
                                  │
                                  ▼
                       Attack.setup() ── 构建攻击计划
                                  │
                                  ▼
                       Attack.launch() ── 构造恶意报文
                                  │
                                  ▼
                       Sender ── 通过 Scapy/RawSocket 发送
                                  │
                                  ▼
                       Attack.verify() ── 重新嗅探，对比状态
```

### 8.2 ARP 欺骗模式（sniff_mode=arp_spoof）

```
ARP 欺骗引擎启动
    ├─ 向 arp_target_a 持续发送：我是 arp_target_b 的 MAC
    ├─ 向 arp_target_b 持续发送：我是 arp_target_a 的 MAC
    └─ 开启 IP 转发（允许攻击机转发双方流量）
            │
            ▼
路由器 A/B 互发流量 ──→ 经过攻击机网卡 ──→ Sniffer (pcap-ct)
            │                                       │
            ▼                                       ▼
    MITM 攻击处理                            报文解析器 (Scapy)
    ├─ action=modify: 篡改 OSPF 字段后转发         │
    ├─ action=drop:   丢弃报文                     ▼
    ├─ action=forward: 原样转发                 拓扑模型
    └─ action=inject: 额外注入伪造报文              │
                                                   ▼
                                         Attack.launch()
                                         Attack.verify()

          ┌──── 攻击机 teardown() 时 ────┐
          │ 停止 ARP 欺骗线程            │
          │ 发送正确 ARP 恢复缓存         │
          │ 关闭 IP 转发                 │
          └──────────────────────────────┘
```

---

## 9. 测试策略

### 单元测试（pytest）
- 每个攻击模块独立测试，使用 mock 模拟网络层
- 验证报文构造正确性（字段值、校验和）
- 验证状态机转换正确性
- 验证配置解析优先级（默认值 → YAML → CLI）

### 集成测试（Docker + FRRouting）
- 拓扑：3 路由器单区域 OSPF 网络
- 每种攻击对运行中的 FRR 容器执行
- 验证：邻居状态变化、LSDB 内容、路由表变更
- 多区域拓扑用于跨区域攻击验证

### Docker 集成测试拓扑

```
docker-compose.yml
├── r1 (FRR, 10.0.0.1, Area 0.0.0.0)
├── r2 (FRR, 10.0.0.2, Area 0.0.0.0)
│   └── r2 连接子网 192.168.1.0/24
├── r3 (FRR, 10.0.0.3, Area 0.0.0.1)
└── attacker (ospf-attack 容器)
    └── 桥接到同一 LAN 段
```

---

## 10. PyInstaller 构建

```powershell
# build.ps1
pyinstaller `
    --onefile `
    --name ospf-attack `
    --add-binary "assets/npcap-installer.exe;." `
    --hidden-import scapy.contrib.ospf `
    --hidden-import pcap `
    --hidden-import click `
    --hidden-import yaml `
    --hidden-import scapy.layers.l2 `
    --hidden-import scapy.layers.inet `
    ospf_attack/cli/main.py
```

编译产物：`dist/ospf-attack.exe`（~45MB，自包含，支持 Win7+ 32/64 位）

---

## 11. 明确避免的反模式

- 不强制建立邻居关系 — 所有攻击均支持旁路模式
- 不要求部署时安装任何外部依赖 — 单 `.exe` 自包含
- 攻击模块不共享可变状态 — 每种攻击独立可运行
- 除了可选的 pcap 输出和 Npcap 安装程序提取外，不进行磁盘写入
- ARP 欺骗结束后必须恢复目标 ARP 缓存，避免残留影响

---

## 12. ARP 欺骗引擎设计要点

### 启动流程

```
setup() 中调用 ARP 欺骗引擎：
    │
    ├─ 校验 arp_target_a / arp_target_b 均已配置
    ├─ 解析目标 IP 的 MAC 地址
    ├─ 获取本机 MAC（伪造用）
    ├─ 开启 IP 转发（Linux: /proc/sys/net/ipv4/ip_forward；Windows: 注册表）
    ├─ 启动后台线程：每 arp_interval 秒
    │   ├─ 发送 ARP 响应（arp_target_a: 我是 arp_target_b 的 MAC）
    │   └─ 发送 ARP 响应（arp_target_b: 我是 arp_target_a 的 MAC）
    └─ 记录日志：ARP 欺骗已建立
```

### 清理流程

```
teardown() 中调用 ARP 欺骗引擎清理：
    │
    ├─ 停止后台发送线程
    ├─ 发送正确 ARP 响应（恢复双方 ARP 缓存）
    ├─ 关闭 IP 转发
    └─ 记录日志：ARP 欺骗已清除
```

