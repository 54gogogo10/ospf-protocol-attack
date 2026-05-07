# OSPF Protocol Attack Simulator — Design Document

**Date:** 2026-05-08
**Status:** Draft

## 1. Overview

A Python-based OSPF protocol attack simulation and testing tool, packaged as a single Windows `.exe` via PyInstaller for Win7+ zero-dependency deployment. Supports passive (out-of-band, no neighbor adjacency) and active (in-band, neighbor-established) attack modes against both virtual and physical OSPF routers.

### Use Cases
- Educational/lab environments: isolated virtual networks (GNS3/EVE-NG/Docker)
- Controlled penetration testing against physical routers
- Security research and new attack technique development

### Interaction Model
- Core Python library (importable SDK)
- CLI tool (Click-based) as the primary entry point

---

## 2. Technology Stack

| Layer | Choice | Rationale |
|-------|--------|-----------|
| Language | Python 3.10+ | Protocol libraries mature, rapid development |
| Protocol engine | Scapy (`scapy.contrib.ospf`) | Native OSPF packet construction/parsing |
| High-perf sending | Raw socket fallback | Low-level injection for flood attacks |
| Packet capture | pcap-ct (provides `import pcap`) + Npcap | Promiscuous-mode sniffing on Windows |
| CLI | Click | Lightweight, composable subcommands |
| Packaging | PyInstaller `--onefile` | Single ~45MB `.exe`, no Python install needed |
| Npcap bundling | `--add-binary` embedded + auto-detect at startup | Zero-config network capture |
| Testing | pytest + Docker FRRouting topologies | Unit + integration verification |
| Config format | YAML | Human-readable attack scenario files |

---

## 3. Architecture

### Directory Structure

```
OSPF_Protocol_Attack/
├── ospf_attack/
│   ├── __init__.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── packet.py          # OSPF packet construction/parsing (Scapy wrapper)
│   │   ├── neighbor.py        # Neighbor state machine (Down→Init→2-Way→Full)
│   │   ├── lsa_db.py          # Link-state database simulation
│   │   ├── router.py          # Virtual router identity (ID, area, auth)
│   │   ├── sniffer.py         # Passive sniffing engine
│   │   └── event.py           # Event bus for decoupled communication
│   ├── attacks/
│   │   ├── __init__.py
│   │   ├── base.py            # AttackBase abstract class + AttackResult
│   │   ├── adjacency/
│   │   │   ├── hello_inject.py
│   │   │   ├── adjacency_break.py
│   │   │   └── dr_bdr_hijack.py
│   │   ├── lsa/
│   │   │   ├── route_inject.py
│   │   │   ├── max_seq.py
│   │   │   ├── max_age.py
│   │   │   └── fight_back.py
│   │   ├── dos/
│   │   │   ├── flood.py
│   │   │   ├── spf_recalc.py
│   │   │   └── db_overflow.py
│   │   └── protocol/
│   │       ├── mitm.py
│   │       └── replay.py
│   ├── network/
│   │   ├── sender.py          # Packet sender (Scapy + raw socket fallback)
│   │   └── adapter.py         # Interface abstraction (pcap/Ethernet per env)
│   ├── config/
│   │   ├── config.py          # Config loader (YAML + CLI merge, 3-tier priority)
│   │   └── types.py           # Dataclass config types per attack category
│   ├── npcap/
│   │   ├── detector.py        # Npcap presence detection at startup
│   │   └── installer.py       # Embedded installer extraction + silent install
│   ├── cli/
│   │   ├── __init__.py
│   │   ├── main.py            # Click entry point
│   │   ├── commands.py        # Subcommand registration per attack
│   │   └── formatters.py      # Output formatting (table, json, summary)
│   └── utils/
│       ├── validators.py      # IP/route/parameter validation
│       └── logging.py         # Structured logging with audit trail
├── tests/
│   ├── unit/                  # Per-module unit tests
│   │   ├── test_packet.py
│   │   ├── test_neighbor.py
│   │   ├── test_hello_inject.py
│   │   └── ...
│   └── integration/           # Docker-based topology tests
│       ├── conftest.py        # FRR container fixtures
│       └── test_topology_attacks.py
├── docker/
│   ├── topo1-single-area/
│   │   ├── docker-compose.yml
│   │   └── frr/
│   │       ├── r1/
│   │       └── r2/
│   └── topo2-multi-area/
├── assets/
│   └── npcap-installer.exe    # Embedded Npcap installer binary
├── pyproject.toml
├── README.md
└── build.ps1                   # PyInstaller build script
```

### Core Design Principles

1. **Plugin architecture** — Each attack is an independent module implementing `AttackBase`
2. **Dual attack modes** — PASSIVE (out-of-band, no neighbor) / ACTIVE (in-band, with adjacency)
3. **Event bus** — Decouples attack logic from network transport
4. **3-tier config** — Defaults → YAML file → CLI flags (later overrides earlier)
5. **Self-contained deployment** — Single `.exe` with embedded Npcap; auto-detect + prompt-install at startup

---

## 4. AttackBase Interface

```python
from abc import ABC, abstractmethod
from enum import Enum
from dataclasses import dataclass, field

class AttackMode(Enum):
    PASSIVE = "passive"
    ACTIVE  = "active"

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
        """Phase 1: initialize — sniff topology or establish adjacency."""

    @abstractmethod
    def launch(self) -> AttackResult:
        """Phase 2: execute the attack."""

    @abstractmethod
    def verify(self) -> bool:
        """Phase 3: confirm attack effect via observed state change."""

    @abstractmethod
    def teardown(self) -> None:
        """Phase 4: cleanup resources (close sockets, reset state)."""

    def run(self) -> AttackResult:
        """Template method orchestrating all four phases."""
        try:
            self.setup()
            result = self.launch()
            result.target_affected = self.verify()
            return result
        finally:
            self.teardown()
```

---

## 5. Attack Module Catalog

### 5.1 Adjacency Attacks (Category: ADJACENCY)

| # | Module | Default Mode | Technique | Verification |
|---|--------|-------------|-----------|-------------|
| 1 | `hello-inject` | passive | Sniff legitimate Hello packets, then inject forged Hello with matching parameters to establish unauthorized adjacency | Target neighbor table shows new entry with attacker's Router ID |
| 2 | `adjacency-break` | passive | Inject malformed Hello (wrong Area ID, auth mismatch, 1-Way state) to tear down existing adjacency | Target neighbor state transitions from Full to Down |
| 3 | `dr-bdr-hijack` | passive | Inject Hello with Priority=255 to win DR election | Target's DR/BDR role changes; LSA flooding path redirected |

### 5.2 LSA Attacks (Category: LSA)

| # | Module | Default Mode | Technique | Verification |
|---|--------|-------------|-----------|-------------|
| 4 | `route-inject` | passive | Sniff legitimate LSU, construct poisoned LSA (Type-5 for external routes, or Type-3 for inter-area), advertise via LSU | Target routing table contains poisoned route |
| 5 | `max-seq` | passive | Inject LSU with Sequence=0x7FFFFFFF; legitimate LSA ignored due to lower sequence | Target LSDB shows attacker's LSA as the canonical version |
| 6 | `max-age` | passive | Inject LSU with Age=3600 (MaxAge); target removes the LSA from LSDB | Target LSDB entry deleted; routing table loses the corresponding route |
| 7 | `fight-back` | passive | Continuously sniff for legitimate LSAs and immediately inject a higher-sequence counter-LSA | Legitimate LSA cannot propagate; attacker's version persists |

### 5.3 Denial of Service Attacks (Category: DOS)

| # | Module | Default Mode | Technique | Verification |
|---|--------|-------------|-----------|-------------|
| 8 | `flood` | passive | High-rate Hello/LSU injection to exhaust router CPU | Target CPU utilization sustained >80% |
| 9 | `spf-recalc` | passive | Continuously inject changing LSAs to force repeated SPF recomputation | SPF execution interval drops below configurable threshold (default 1s) |
| 10 | `db-overflow` | passive | Inject large number of external LSAs (Type-5) to fill the LSDB | Target LSDB entry count exceeds configured max; router may drop into overload state |

### 5.4 Protocol-Level Manipulation Attacks (Category: PROTOCOL)

| # | Module | Default Mode | Technique | Verification |
|---|--------|-------------|-----------|-------------|
| 11 | `mitm` | passive | Hub-environment: promiscuous sniff → modify OSPF fields in-transit → forward altered packet | Target routing table reflects modified LSA content |
| 12 | `replay` | passive | Capture OSPF packets → replay later (optionally with field modification) to cause routing instability | Target routing table oscillates; LSDB shows sequence number rollback |

---

## 6. Configuration System

### 6.1 Base Configuration

```python
@dataclass
class AttackConfig:
    """Shared configuration for all attack types."""
    iface: str                          # Network interface
    target: str                         # Target IP or subnet
    mode: AttackMode = AttackMode.PASSIVE
    router_id: str = "1.1.1.1"         # Spoofed Router ID
    area_id: str = "0.0.0.0"           # OSPF Area

    # Sniffing parameters
    sniff_duration: int = 30            # Sniff duration in seconds

    # Sending parameters
    packet_rate: int = 10               # Packets per second
    max_packets: int = 0                # 0 = unlimited

    # Output
    verbose: bool = False
    pcap_output: str = ""               # Output pcap file path
```

### 6.2 Per-Category Configurations

```python
@dataclass
class HelloInjectionConfig(AttackConfig):
    hello_interval: int = 10
    router_dead_interval: int = 40
    router_priority: int = 255
    auth_type: str = "none"             # none, plain, md5
    auth_key: str = ""
    subnet_mask: str = "255.255.255.0"

@dataclass
class LSAConfig(AttackConfig):
    lsa_type: int = 5                   # 1=Router, 3=Summary, 5=External
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
    duration: int = 60
    thread_count: int = 1
    lsa_change_interval: int = 2
    lsa_count: int = 1000

@dataclass
class MITMConfig(AttackConfig):
    target_a: str = ""
    target_b: str = ""
    action: str = "modify"              # drop, modify, forward, inject
    modify_rules: list = field(default_factory=list)

@dataclass
class ReplayConfig(AttackConfig):
    capture_file: str = ""
    replay_loop: bool = False
    replay_interval: int = 5
    modify_fields: dict = field(default_factory=dict)
```

### 6.3 Configuration Priority

Defaults → YAML file → CLI flags (later overrides earlier)

### 6.4 CLI Examples

```bash
# Passive Hello injection
ospf-attack hello-inject --iface eth0 --target 192.168.1.0/24 \
    --passive --priority 255 --sniff-duration 30

# Max-Age attack
ospf-attack max-age --iface eth0 --target 224.0.0.5 \
    --passive --age 3600 --lsa-type 1

# Flood DoS
ospf-attack flood --iface eth0 --target 224.0.0.5 \
    --duration 60 --packet-rate 500 --thread-count 4

# From YAML config
ospf-attack mitm --config ./mitm_attack.yaml
```

---

## 7. Npcap Dependency Management

### Startup Flow

```
Program starts
    |
    ├─ Check Npcap: read registry HKLM\SOFTWARE\WOW6432Node\Npcap
    │   or try pcap.findalldevs()
    │
    ├─ Present → sniffing enabled
    │
    └─ Absent → prompt:
        "Npcap not found. Sniffing unavailable without it.
         Install Npcap? (Y/n)"
        ├─ Y → extract embedded installer to %TEMP%
        │       run: npcap-installer.exe /S
        │       re-check → sniffing enabled
        └─ N → sniffing degraded, injection attacks fully functional
```

- Pure injection attacks (all 12 modules in passive mode) work without Npcap
- Only passive sniffing for topology discovery requires Npcap

---

## 8. Data Flow (Passive Mode)

```
[OSPF Network] ── promisc sniff ──→ Sniffer (pcap-ct)
                                        │
                                        ▼
                                   Packet Parser (Scapy)
                                        │
                                        ▼
                                   Topology Model
                                   ├─ router_ids[]
                                   ├─ area_ids[]
                                   ├─ dr_bdr_map{}
                                   └─ lsa_summary[]
                                        │
                                        ▼
                              Attack.setup() ── builds attack plan
                                        │
                                        ▼
                              Attack.launch() ── constructs malicious packets
                                        │
                                        ▼
                              Sender ── sends via Scapy/RawSocket
                                        │
                                        ▼
                              Attack.verify() ── re-sniffs, compares state
```

---

## 9. Testing Strategy

### Unit Tests (pytest)
- Each attack module tested in isolation with mocked network
- Verify packet construction correctness (field values, checksums)
- Verify state machine transitions
- Verify config resolution (defaults → YAML → CLI)

### Integration Tests (Docker + FRRouting)
- Topology: 3-router single-area OSPF network
- Each attack executed against running FRR container
- Verify: neighbor state change, LSDB content, routing table modification
- Multi-area topology for inter-area attack verification

### Docker Topology

```
docker-compose.yml
├── r1 (FRR, 10.0.0.1, Area 0.0.0.0)
├── r2 (FRR, 10.0.0.2, Area 0.0.0.0)
│   └── r2 connects to subnet 192.168.1.0/24
├── r3 (FRR, 10.0.0.3, Area 0.0.0.1)
└── attacker (ospf-attack container)
    └── bridge to same LAN segment
```

---

## 10. PyInstaller Build

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
    ospf_attack/cli/main.py
```

Output: `dist/ospf-attack.exe` (~45MB, self-contained for Win7+ 32/64-bit)

---

## 11. Anti-Patterns Explicitly Avoided

- No ARP spoofing — hub environment assumed for passive sniffing
- No neighbor adjacency required for any attack (all work in passive mode)
- No external Python/runtime dependencies at deployment time (single .exe)
- Attack modules never share mutable state (each attack is independently runnable)
- No write-to-disk required except for optional pcap output and Npcap installer extraction
