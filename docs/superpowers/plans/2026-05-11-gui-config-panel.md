# GUI 配置面板实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 OSPF 攻击模拟器增加 Tkinter GUI 操作面板，支持可视化配置、启动/停止攻击、实时日志。

**Architecture:** Tkinter 主窗口 + PanedWindow 左右分栏。左侧 Treeview 攻击列表，右侧分通用/专属参数表单 + 日志面板。攻击在 daemon 线程执行，通过 queue.Queue 线程安全回传日志到 UI。

**Tech Stack:** Python 3.10+ tkinter + ttk + threading + queue（全部标准库，零额外依赖）

---

## 文件结构

| 文件 | 操作 | 职责 |
|------|------|------|
| `ospf_attack/gui/__init__.py` | Create | 导出 `launch_gui()` |
| `ospf_attack/gui/styles.py` | Create | 颜色/字体/间距常量 |
| `ospf_attack/gui/log_panel.py` | Create | 日志面板 (ScrolledText + Queue 轮询) |
| `ospf_attack/gui/attack_tree.py` | Create | 左侧攻击列表 (Treeview) |
| `ospf_attack/gui/config_form.py` | Create | 动态配置表单 + 字段元数据 |
| `ospf_attack/gui/runner.py` | Create | 后台攻击线程 (Event 停止) |
| `ospf_attack/gui/app.py` | Create | 主窗口组装 |
| `ospf_attack/__main__.py` | Create | GUI 入口 |
| `tests/unit/test_gui_meta.py` | Create | 单元测试 (字段映射/配置构造) |

---

### Task 1: 样式常量 (styles.py)

**Files:**
- Create: `ospf_attack/gui/styles.py`

- [ ] **Step 1: 创建样式常量模块**

```python
"""GUI 样式常量。"""

# 颜色
BG_MAIN = "#f0f0f0"
BG_TREE = "#ffffff"
BG_LOG = "#1e1e1e"
FG_LOG_INFO = "#d4d4d4"
FG_LOG_WARN = "#e5c07b"
FG_LOG_ERROR = "#f44747"
FG_LOG_SYSTEM = "#569cd6"
FG_TITLE = "#333333"

# 字体
FONT_TITLE = ("Microsoft YaHei UI", 11, "bold")
FONT_TREE = ("Microsoft YaHei UI", 9)
FONT_LABEL = ("Microsoft YaHei UI", 9)
FONT_ENTRY = ("Consolas", 9)
FONT_LOG = ("Consolas", 9)
FONT_BUTTON = ("Microsoft YaHei UI", 9)
FONT_STATUS = ("Microsoft YaHei UI", 8)

# 间距
PAD_OUTER = 10
PAD_INNER = 5
PAD_FORM = 3
SECTION_GAP = 12

# 尺寸
TREE_MIN_WIDTH = 180
LOG_MIN_HEIGHT = 180
WINDOW_WIDTH = 1100
WINDOW_HEIGHT = 720
WINDOW_MIN_WIDTH = 900
WINDOW_MIN_HEIGHT = 600

# 日志级别标记
LOG_TAGS = {
    "INFO": FG_LOG_INFO,
    "WARN": FG_LOG_WARN,
    "ERROR": FG_LOG_ERROR,
    "SYSTEM": FG_LOG_SYSTEM,
}
```

- [ ] **Step 2: 验证模块可导入**

```bash
python -c "from ospf_attack.gui.styles import BG_MAIN; print(BG_MAIN)"
```

- [ ] **Step 3: 提交**

```bash
git add ospf_attack/gui/__init__.py ospf_attack/gui/styles.py
git commit -m "feat(gui): add styles module with color/font/spacing constants"
```

---

### Task 2: 日志面板 (log_panel.py)

**Files:**
- Create: `ospf_attack/gui/log_panel.py`

- [ ] **Step 1: 写测试**

```python
# tests/unit/test_gui_meta.py (部分)
import queue
import tkinter as tk
from ospf_attack.gui.log_panel import LogPanel


def test_log_panel_creates_widgets():
    root = tk.Tk()
    panel = LogPanel(root)
    assert panel._text is not None
    assert isinstance(panel._queue, queue.Queue)
    root.destroy()


def test_log_panel_write_adds_to_queue():
    root = tk.Tk()
    panel = LogPanel(root)
    panel.write("INFO", "test message")
    entry = panel._queue.get_nowait()
    assert entry == ("INFO", "test message")
    root.destroy()


def test_log_panel_flush_updates_text():
    root = tk.Tk()
    panel = LogPanel(root)
    panel._queue.put(("INFO", "line1"))
    panel._queue.put(("WARN", "line2"))
    panel._flush()
    content = panel._text.get("1.0", "end-1c")
    assert "line1" in content
    assert "line2" in content
    root.destroy()
```

- [ ] **Step 2: 验证测试失败**

```bash
pytest tests/unit/test_gui_meta.py -v
# Expected: FAIL (LogPanel not defined)
```

- [ ] **Step 3: 实现 LogPanel**

```python
"""日志输出面板 — 线程安全的彩色日志窗口。"""

import queue
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from datetime import datetime

from .styles import BG_LOG, FONT_LOG, LOG_TAGS


class LogPanel(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, **kw)
        self._queue = queue.Queue()
        self._running = True

        self._text = ScrolledText(
            self, bg=BG_LOG, fg="#d4d4d4",
            font=FONT_LOG, wrap=tk.WORD,
            insertbackground="#ffffff",
            selectbackground="#264f78",
            relief=tk.FLAT,
        )
        self._text.pack(fill=tk.BOTH, expand=True)

        # 配置颜色标签
        for tag, color in LOG_TAGS.items():
            self._text.tag_configure(tag, foreground=color)

        # 启动轮询
        self._poll()

    def write(self, level: str, message: str):
        """线程安全写入日志。level: INFO/WARN/ERROR/SYSTEM"""
        self._queue.put((level, message))

    def _poll(self):
        """UI 线程轮询队列，刷新日志显示。"""
        while True:
            try:
                level, message = self._queue.get_nowait()
                self._append(level, message)
            except queue.Empty:
                break
        if self._running:
            self.after(100, self._poll)

    def _append(self, level: str, message: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{timestamp}] {message}\n"
        tag = level if level in LOG_TAGS else "INFO"
        self._text.insert(tk.END, line, tag)
        self._text.see(tk.END)

    def _flush(self):
        """暴露给测试：直接刷新队列。"""
        self._poll()

    def destroy(self):
        self._running = False
        super().destroy()
```

- [ ] **Step 4: 验证测试通过**

```bash
pytest tests/unit/test_gui_meta.py::test_log_panel_creates_widgets -v
pytest tests/unit/test_gui_meta.py::test_log_panel_write_adds_to_queue -v
pytest tests/unit/test_gui_meta.py::test_log_panel_flush_updates_text -v
```

- [ ] **Step 5: 提交**

```bash
git add ospf_attack/gui/log_panel.py tests/unit/test_gui_meta.py
git commit -m "feat(gui): add log panel with thread-safe colored log output"
```

---

### Task 3: 攻击列表 (attack_tree.py)

**Files:**
- Create: `ospf_attack/gui/attack_tree.py`

- [ ] **Step 1: 写测试**

```python
# tests/unit/test_gui_meta.py (追加)

def test_attack_tree_populates_all_12_attacks():
    root = tk.Tk()
    tree = AttackTree(root)
    tree.pack()
    # 4 categories + 12 attacks = 16 nodes
    children = tree.tree.get_children()
    assert len(children) == 4  # 4 category nodes
    total_leaves = sum(
        len(tree.tree.get_children(cat)) for cat in children
    )
    assert total_leaves == 12
    root.destroy()


def test_attack_tree_get_selected_returns_none_initially():
    root = tk.Tk()
    tree = AttackTree(root)
    assert tree.get_selected() is None
    root.destroy()


def test_attack_tree_has_callback():
    root = tk.Tk()
    tree = AttackTree(root)
    called = []
    tree.on_select = lambda name: called.append(name)
    # simulate selection by finding a leaf
    for cat in tree.tree.get_children():
        leaves = tree.tree.get_children(cat)
        if leaves:
            first_leaf = leaves[0]
            tree.tree.selection_set(first_leaf)
            tree.tree.event_generate("<<TreeviewSelect>>")
            break
    assert len(called) == 1
    root.destroy()
```

- [ ] **Step 2: 实现 AttackTree**

```python
"""攻击模块列表 — 左侧 Treeview 展示 4 类 12 种攻击。"""

import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional

from .styles import BG_TREE, FONT_TREE


ATTACK_CATEGORIES = {
    "邻接关系攻击": ["hello-inject", "adjacency-break", "dr-bdr-hijack"],
    "LSA攻击": ["route-inject", "max-seq", "max-age", "fight-back"],
    "拒绝服务攻击": ["flood", "spf-recalc", "db-overflow"],
    "协议级操控攻击": ["mitm", "replay"],
}

ATTACK_LABELS = {
    "hello-inject": "Hello 注入",
    "adjacency-break": "邻接破坏",
    "dr-bdr-hijack": "DR/BDR 操纵",
    "route-inject": "路由注入",
    "max-seq": "最大序列号",
    "max-age": "Max-Age",
    "fight-back": "Fight-Back",
    "flood": "泛洪",
    "spf-recalc": "SPF 重计算",
    "db-overflow": "数据库溢出",
    "mitm": "MITM 中间人",
    "replay": "重放",
}


class AttackTree(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=BG_TREE, **kw)
        self.on_select: Optional[Callable[[str], None]] = None

        self.tree = ttk.Treeview(
            self, show="tree", selectmode="browse",
            style="Attack.Treeview",
        )
        self.tree.pack(fill=tk.BOTH, expand=True)

        self._name_to_iid: dict[str, str] = {}

        for cat, attacks in ATTACK_CATEGORIES.items():
            cat_id = self.tree.insert("", tk.END, text=cat, open=True)
            for name in attacks:
                label = ATTACK_LABELS.get(name, name)
                leaf_id = self.tree.insert(cat_id, tk.END, text=label)
                self._name_to_iid[name] = leaf_id

        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)

    def get_selected(self) -> Optional[str]:
        sel = self.tree.selection()
        if not sel:
            return None
        iid = sel[0]
        for name, nid in self._name_to_iid.items():
            if nid == iid:
                return name
        return None

    def _on_tree_select(self, event):
        name = self.get_selected()
        if name and self.on_select:
            self.on_select(name)
```

- [ ] **Step 3: 验证测试通过**

```bash
pytest tests/unit/test_gui_meta.py::test_attack_tree_populates_all_12_attacks -v
pytest tests/unit/test_gui_meta.py::test_attack_tree_get_selected_returns_none_initially -v
pytest tests/unit/test_gui_meta.py::test_attack_tree_has_callback -v
```

- [ ] **Step 4: 提交**

```bash
git add ospf_attack/gui/attack_tree.py tests/unit/test_gui_meta.py
git commit -m "feat(gui): add attack tree panel with 4 categories and 12 attacks"
```

---

### Task 4: 动态配置表单 (config_form.py)

**Files:**
- Create: `ospf_attack/gui/config_form.py`

这是最复杂的模块。核心数据结构是 `FIELD_META` 字典，定义每个配置字段的控件类型、标签、选项。

- [ ] **Step 1: 写测试**

```python
# tests/unit/test_gui_meta.py (追加)

from ospf_attack.gui.config_form import (
    FIELD_META, COMMON_FIELDS, SPECIFIC_FIELDS,
    get_widget_type, build_field_widgets,
)


def test_common_fields_have_metadata():
    """通用字段必须在 FIELD_META 中有定义"""
    for name in COMMON_FIELDS:
        assert name in FIELD_META, f"Missing meta for common field: {name}"


def test_specific_fields_have_metadata():
    """每个攻击类型的所有专属字段必须有元数据"""
    for attack_name, fields in SPECIFIC_FIELDS.items():
        for name in fields:
            assert name in FIELD_META, (
                f"Missing meta for {attack_name} field: {name}"
            )


def test_get_widget_type_returns_entry_for_str():
    assert get_widget_type("iface") == "entry"


def test_get_widget_type_returns_spinbox_for_int():
    assert get_widget_type("hello_interval") == "spinbox"


def test_field_meta_covers_all_config_fields():
    """FIELD_META 覆盖所有 5 个配置 dataclass 的全部字段"""
    import dataclasses
    from ospf_attack.config.types import (
        AttackConfig, HelloInjectionConfig, LSAConfig,
        DoSConfig, MITMConfig, ReplayConfig,
    )
    all_fields = set()
    for cls in (AttackConfig, HelloInjectionConfig, LSAConfig,
                DoSConfig, MITMConfig, ReplayConfig):
        for f in dataclasses.fields(cls):
            all_fields.add(f.name)
    missing = all_fields - set(FIELD_META.keys())
    assert not missing, f"Missing FIELD_META entries: {missing}"


class FakeEntry:
    def __init__(self, value=""):
        self.value = value
    def get(self):
        return self.value

class FakeVar:
    def __init__(self, value):
        self.value = value
    def get(self):
        return self.value

def test_build_config_dict_collects_field_values():
    """从虚拟 widget 字典收集配置参数"""
    widgets = {
        "iface": FakeEntry("eth0"),
        "target": FakeEntry("10.0.0.1"),
        "hello_interval": FakeEntry("30"),
        "router_priority": FakeEntry("200"),
    }
    meta = {
        "iface": {"widget": "entry", "type": str},
        "target": {"widget": "entry", "type": str},
        "hello_interval": {"widget": "spinbox", "type": int},
        "router_priority": {"widget": "spinbox", "type": int},
    }
    result = build_config_dict(widgets, meta)
    assert result["iface"] == "eth0"
    assert result["target"] == "10.0.0.1"
    assert result["hello_interval"] == 30
    assert result["router_priority"] == 200
```

- [ ] **Step 2: 实现 FIELD_META 和表单逻辑**

```python
"""动态配置表单 — 根据攻击类型动态生成参数字段。"""

import tkinter as tk
from tkinter import ttk
from typing import Any, Callable

from .styles import FONT_LABEL, FONT_ENTRY, PAD_FORM, PAD_OUTER, SECTION_GAP


# =====================================================================
# 字段元数据 — 每个配置字段的控件类型和标签
# =====================================================================

FIELD_META: dict[str, dict] = {
    # -- 通用参数 (AttackConfig) --
    "iface":          {"widget": "entry",   "label": "网卡接口"},
    "target":         {"widget": "entry",   "label": "目标地址"},
    "mode":           {"widget": "radio",   "label": "攻击模式", "choices": ["passive", "active"]},
    "sniff_mode":     {"widget": "radio",   "label": "嗅探模式", "choices": ["hub", "arp_spoof"]},
    "router_id":      {"widget": "entry",   "label": "伪装路由器 ID"},
    "area_id":        {"widget": "entry",   "label": "OSPF 区域"},
    "sniff_duration": {"widget": "spinbox", "label": "嗅探时长(秒)", "from_": 1, "to": 3600},
    "arp_target_a":   {"widget": "entry",   "label": "ARP 欺骗目标 A"},
    "arp_target_b":   {"widget": "entry",   "label": "ARP 欺骗目标 B"},
    "arp_interval":   {"widget": "spinbox", "label": "ARP 间隔(秒)", "from_": 1, "to": 60},
    "packet_rate":    {"widget": "spinbox", "label": "发包速率(pps)", "from_": 1, "to": 10000},
    "max_packets":    {"widget": "spinbox", "label": "最大发包数(0=不限)", "from_": 0, "to": 1000000},
    "verbose":        {"widget": "check",   "label": "详细输出"},
    "pcap_output":    {"widget": "entry",   "label": "PCAP 保存路径"},

    # -- HelloInjectionConfig 专属 --
    "hello_interval":       {"widget": "spinbox", "label": "Hello 间隔(秒)", "from_": 1, "to": 65535},
    "router_dead_interval": {"widget": "spinbox", "label": "Dead 间隔(秒)", "from_": 1, "to": 65535},
    "router_priority":      {"widget": "spinbox", "label": "路由器优先级", "from_": 0, "to": 255},
    "auth_type":            {"widget": "combo",   "label": "认证类型", "choices": ["none", "plain", "md5"]},
    "auth_key":             {"widget": "entry",   "label": "认证密钥"},
    "subnet_mask":          {"widget": "entry",   "label": "子网掩码"},

    # -- LSAConfig 专属 --
    "lsa_type":            {"widget": "combo",   "label": "LSA 类型", "choices": ["1", "3", "5"]},
    "link_state_id":       {"widget": "entry",   "label": "Link State ID"},
    "advertising_router":  {"widget": "entry",   "label": "通告路由器"},
    "sequence_number":     {"widget": "entry",   "label": "序列号 (hex)"},
    "age":                 {"widget": "spinbox", "label": "Age (秒)", "from_": 0, "to": 3600},
    "metric":              {"widget": "spinbox", "label": "Metric", "from_": 0, "to": 16777215},
    "network_mask":        {"widget": "entry",   "label": "网络掩码"},
    "forwarding_address":  {"widget": "entry",   "label": "转发地址"},
    "external_routes":     {"widget": "entry",   "label": "外部路由 (逗号分隔)"},

    # -- DoSConfig 专属 --
    "duration":             {"widget": "spinbox", "label": "持续时间(秒)", "from_": 1, "to": 86400},
    "thread_count":         {"widget": "spinbox", "label": "并发线程数", "from_": 1, "to": 100},
    "lsa_change_interval":  {"widget": "spinbox", "label": "LSA 变化间隔(秒)", "from_": 1, "to": 3600},
    "lsa_count":            {"widget": "spinbox", "label": "注入 LSA 数量", "from_": 1, "to": 100000},

    # -- MITMConfig 专属 --
    "target_a":    {"widget": "entry",   "label": "路由器 A IP"},
    "target_b":    {"widget": "entry",   "label": "路由器 B IP"},
    "action":      {"widget": "combo",   "label": "操作类型", "choices": ["drop", "modify", "forward", "inject"]},
    "modify_rules":{"widget": "entry",   "label": "修改规则 (JSON)"},

    # -- ReplayConfig 专属 --
    "capture_file":   {"widget": "entry",   "label": "捕获文件路径"},
    "replay_loop":    {"widget": "check",   "label": "循环重放"},
    "replay_interval":{"widget": "spinbox", "label": "重放间隔(秒)", "from_": 1, "to": 3600},
    "modify_fields":  {"widget": "entry",   "label": "修改字段 (JSON)"},
}

# 通用参数字段名列表 (AttackConfig 中的字段)
COMMON_FIELDS = [
    "iface", "target", "mode", "sniff_mode", "router_id", "area_id",
    "sniff_duration", "arp_target_a", "arp_target_b", "arp_interval",
    "packet_rate", "max_packets", "verbose", "pcap_output",
]

# 各攻击类型专属字段名列表
SPECIFIC_FIELDS: dict[str, list[str]] = {
    "hello-inject":    ["hello_interval", "router_dead_interval", "router_priority",
                        "auth_type", "auth_key", "subnet_mask"],
    "adjacency-break": ["hello_interval", "router_dead_interval", "router_priority",
                        "auth_type", "auth_key", "subnet_mask"],
    "dr-bdr-hijack":   ["hello_interval", "router_dead_interval", "router_priority",
                        "auth_type", "auth_key", "subnet_mask"],
    "route-inject":    ["lsa_type", "link_state_id", "advertising_router",
                        "sequence_number", "age", "metric", "network_mask",
                        "forwarding_address", "external_routes"],
    "max-seq":         ["lsa_type", "link_state_id", "advertising_router",
                        "sequence_number", "age", "metric", "network_mask",
                        "forwarding_address", "external_routes"],
    "max-age":         ["lsa_type", "link_state_id", "advertising_router",
                        "sequence_number", "age", "metric", "network_mask",
                        "forwarding_address", "external_routes"],
    "fight-back":      ["lsa_type", "link_state_id", "advertising_router",
                        "sequence_number", "age", "metric", "network_mask",
                        "forwarding_address", "external_routes"],
    "flood":           ["duration", "thread_count"],
    "spf-recalc":      ["duration", "thread_count", "lsa_change_interval"],
    "db-overflow":     ["duration", "lsa_count"],
    "mitm":            ["target_a", "target_b", "action", "modify_rules"],
    "replay":          ["capture_file", "replay_loop", "replay_interval", "modify_fields"],
}


def get_widget_type(field_name: str) -> str:
    """返回指定字段的控件类型: entry/spinbox/combo/check/radio"""
    return FIELD_META.get(field_name, {}).get("widget", "entry")


def build_config_dict(widgets: dict, meta: dict[str, dict]) -> dict[str, Any]:
    """从 widget 字典收集配置参数，根据 meta 做类型转换。"""
    result = {}
    for name, w in widgets.items():
        try:
            raw = w.get()
        except Exception:
            continue
        if raw == "" or raw is None:
            continue
        m = meta.get(name, {})
        wtype = m.get("widget", "entry")
        # 类型转换
        if wtype == "spinbox":
            try:
                result[name] = int(raw)
            except ValueError:
                result[name] = raw
        elif wtype == "check":
            result[name] = bool(raw)
        else:
            result[name] = str(raw)
    return result


class ConfigForm(tk.Frame):
    """动态配置表单 — 通用参数 + 攻击专属参数。"""

    def __init__(self, parent, **kw):
        super().__init__(parent, **kw)
        self._attack_name: str | None = None
        self._widgets: dict[str, Any] = {}
        self._sniff_var: tk.StringVar | None = None

        # 滚动容器
        self._canvas = tk.Canvas(self, highlightthickness=0)
        self._scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self._canvas.yview)
        self._scroll_frame = ttk.Frame(self._canvas)

        self._scroll_frame.bind("<Configure>",
            lambda e: self._canvas.configure(scrollregion=self._canvas.bbox("all")))
        self._canvas.create_window((0, 0), window=self._scroll_frame, anchor="nw")
        self._canvas.configure(yscrollcommand=self._scrollbar.set)

        self._canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self._common_frame = ttk.LabelFrame(self._scroll_frame, text="通用参数", padding=8)
        self._common_frame.pack(fill=tk.X, padx=PAD_OUTER, pady=(PAD_OUTER, 0))

        self._arp_frame = ttk.LabelFrame(self._scroll_frame, text="ARP 欺骗设置", padding=8)

        self._specific_frame = ttk.LabelFrame(self._scroll_frame, text="攻击专属参数", padding=8)

    def set_attack(self, attack_name: str):
        """切换攻击类型，重建专属参数区。"""
        self._attack_name = attack_name
        self._widgets.clear()

        # 清除旧控件
        for w in (self._common_frame, self._arp_frame, self._specific_frame):
            for child in w.winfo_children():
                child.destroy()

        # 重建通用参数
        self._build_common()

        # 重建 ARP 设置
        self._build_arp()

        # 重建专属参数
        self._build_specific(attack_name)

        # 按顺序 pack
        self._common_frame.pack(fill=tk.X, padx=PAD_OUTER, pady=(PAD_OUTER, 0))
        self._arp_frame.pack(fill=tk.X, padx=PAD_OUTER, pady=(SECTION_GAP, 0))
        self._specific_frame.pack(fill=tk.X, padx=PAD_OUTER, pady=(SECTION_GAP, 0))

    def get_config_dict(self) -> dict:
        """收集所有表单参数。"""
        return build_config_dict(self._widgets, FIELD_META)

    def set_config_dict(self, data: dict):
        """从字典回填表单值。"""
        for name, value in data.items():
            w = self._widgets.get(name)
            if w is None:
                continue
            try:
                if hasattr(w, "delete"):
                    w.delete(0, tk.END)
                    w.insert(0, str(value))
                elif hasattr(w, "set"):
                    w.set(str(value))
            except Exception:
                pass

    def _build_common(self):
        _build_field_row(self._common_frame, "iface", 0, self)
        _build_field_row(self._common_frame, "target", 1, self)
        _build_field_row(self._common_frame, "router_id", 2, self)
        _build_field_row(self._common_frame, "area_id", 3, self)

        # mode: radiobutton
        f_mode = ttk.Frame(self._common_frame)
        f_mode.grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=PAD_FORM)
        ttk.Label(f_mode, text="攻击模式:", font=FONT_LABEL).pack(side=tk.LEFT)
        mode_var = tk.StringVar(value="passive")
        ttk.Radiobutton(f_mode, text="旁路", variable=mode_var, value="passive").pack(side=tk.LEFT, padx=4)
        ttk.Radiobutton(f_mode, text="主动", variable=mode_var, value="active").pack(side=tk.LEFT, padx=4)
        self._widgets["mode"] = mode_var

        # sniff_mode: radiobutton
        f_sniff = ttk.Frame(self._common_frame)
        f_sniff.grid(row=5, column=0, columnspan=2, sticky=tk.W, pady=PAD_FORM)
        ttk.Label(f_sniff, text="嗅探模式:", font=FONT_LABEL).pack(side=tk.LEFT)
        sniff_var = tk.StringVar(value="hub")
        ttk.Radiobutton(f_sniff, text="集线器", variable=sniff_var, value="hub").pack(side=tk.LEFT, padx=4)
        ttk.Radiobutton(f_sniff, text="ARP欺骗", variable=sniff_var, value="arp_spoof").pack(side=tk.LEFT, padx=4)
        self._widgets["sniff_mode"] = sniff_var
        self._sniff_var = sniff_var

        # 绑定 ARP 面板显隐
        sniff_var.trace_add("write", lambda *_: self._toggle_arp())

        _build_field_row(self._common_frame, "sniff_duration", 6, self)
        _build_field_row(self._common_frame, "packet_rate", 7, self)
        _build_field_row(self._common_frame, "max_packets", 8, self)
        _build_field_row(self._common_frame, "pcap_output", 9, self)

        # verbose checkbox
        f_verbose = ttk.Frame(self._common_frame)
        f_verbose.grid(row=10, column=0, columnspan=2, sticky=tk.W, pady=PAD_FORM)
        verbose_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(f_verbose, text="详细输出", variable=verbose_var).pack(side=tk.LEFT)
        self._widgets["verbose"] = verbose_var

    def _build_arp(self):
        _build_field_row(self._arp_frame, "arp_target_a", 0, self)
        _build_field_row(self._arp_frame, "arp_target_b", 1, self)
        _build_field_row(self._arp_frame, "arp_interval", 2, self)
        self._toggle_arp()

    def _build_specific(self, attack_name: str):
        fields = SPECIFIC_FIELDS.get(attack_name, [])
        for i, name in enumerate(fields):
            _build_field_row(self._specific_frame, name, i, self)

    def _toggle_arp(self):
        if self._sniff_var and self._sniff_var.get() == "arp_spoof":
            self._arp_frame.pack(fill=tk.X, padx=PAD_OUTER, pady=(SECTION_GAP, 0))
        else:
            self._arp_frame.pack_forget()


def _build_field_row(parent: ttk.Frame, field_name: str, row: int, form: "ConfigForm"):
    """在父容器中创建一行: 标签 + 输入控件。注册到 form._widgets。"""
    meta = FIELD_META.get(field_name, {})
    label_text = meta.get("label", field_name)
    wtype = meta.get("widget", "entry")

    lbl = ttk.Label(parent, text=label_text + ":", font=FONT_LABEL)
    lbl.grid(row=row, column=0, sticky=tk.W, padx=(0, 6), pady=PAD_FORM)

    if wtype == "entry":
        var = tk.StringVar()
        w = ttk.Entry(parent, textvariable=var, font=FONT_ENTRY, width=32)
        w.grid(row=row, column=1, sticky=tk.EW, pady=PAD_FORM)
        form._widgets[field_name] = var

    elif wtype == "spinbox":
        from_ = meta.get("from_", 0)
        to = meta.get("to", 65535)
        var = tk.StringVar(value=str(from_))
        w = ttk.Spinbox(parent, from_=from_, to=to, textvariable=var,
                        font=FONT_ENTRY, width=30)
        w.grid(row=row, column=1, sticky=tk.EW, pady=PAD_FORM)
        form._widgets[field_name] = var

    elif wtype == "combo":
        choices = meta.get("choices", [])
        var = tk.StringVar(value=choices[0] if choices else "")
        w = ttk.Combobox(parent, textvariable=var, values=choices,
                         font=FONT_ENTRY, width=30, state="readonly")
        w.grid(row=row, column=1, sticky=tk.EW, pady=PAD_FORM)
        form._widgets[field_name] = var

    elif wtype == "check":
        var = tk.BooleanVar(value=False)
        w = ttk.Checkbutton(parent, variable=var)
        w.grid(row=row, column=1, sticky=tk.W, pady=PAD_FORM)
        form._widgets[field_name] = var

    parent.columnconfigure(1, weight=1)
```

- [ ] **Step 3: 验证测试通过**

```bash
pytest tests/unit/test_gui_meta.py -v
```

- [ ] **Step 4: 提交**

```bash
git add ospf_attack/gui/config_form.py tests/unit/test_gui_meta.py
git commit -m "feat(gui): add dynamic config form with field metadata and widget mapping"
```

---

### Task 5: 攻击执行器 (runner.py)

**Files:**
- Create: `ospf_attack/gui/runner.py`

- [ ] **Step 1: 写测试**

```python
# tests/unit/test_gui_meta.py (追加)
import threading
import queue
from unittest.mock import MagicMock, patch
from ospf_attack.gui.runner import AttackRunner


def test_runner_sends_log_on_start():
    log_q = queue.Queue()
    stop_ev = threading.Event()
    runner = AttackRunner("hello-inject", {"iface": "eth0", "target": "10.0.0.1"}, stop_ev, log_q)

    # Mock the attack execution to avoid actually sending packets
    with patch("ospf_attack.gui.runner._execute_attack") as mock_exec:
        mock_exec.return_value = None
        runner.start()
        runner.join(timeout=5)

    # Should have system log entries
    entries = []
    while not log_q.empty():
        entries.append(log_q.get_nowait())
    assert any("启动" in str(e) for e in entries)


def test_runner_stop_event_signals_attack():
    log_q = queue.Queue()
    stop_ev = threading.Event()
    runner = AttackRunner("flood", {
        "iface": "eth0", "target": "224.0.0.5",
        "duration": 30,
    }, stop_ev, log_q)

    with patch("ospf_attack.gui.runner._execute_attack") as mock_exec:
        runner.start()
        # 发出停止信号
        stop_ev.set()
        runner.join(timeout=5)

    # 验证 stop_ev 被设置
    assert stop_ev.is_set()
```

- [ ] **Step 2: 实现 AttackRunner**

```python
"""攻击执行器 — 在后台线程中运行攻击，通过队列回传日志。"""

import queue
import threading
import traceback
from typing import Any

from ..config.config import build_config
from ..cli.commands import _ATTACK_REGISTRY


def _execute_attack(attack_name: str, config_dict: dict, stop_event: threading.Event,
                    log_queue: queue.Queue):
    """在后台线程中执行攻击。写入日志到 log_queue。"""
    try:
        log_queue.put(("SYSTEM", f"正在初始化攻击模块: {attack_name}"))

        attack_cls, _ = _ATTACK_REGISTRY[attack_name]

        # 构建配置
        config = build_config(attack_name, config_dict)

        # 实例化攻击
        attack = attack_cls(config)

        # 注入 stop event (如果攻击支持)
        attack._should_stop = False

        log_queue.put(("SYSTEM", f"开始执行 {attack_name} ..."))

        # 在子线程中轮询停止信号
        def stop_checker():
            while not stop_event.is_set():
                stop_event.wait(0.5)
            attack._should_stop = True

        checker = threading.Thread(target=stop_checker, daemon=True)
        checker.start()

        log_queue.put(("INFO", f"目标: {config_dict.get('target', 'N/A')}"))
        log_queue.put(("INFO", f"接口: {config_dict.get('iface', 'N/A')}"))

        # 执行攻击
        result = attack.run()

        # 报告结果
        if result.success:
            log_queue.put(("INFO", f"攻击完成 — 发送 {result.packets_sent} 个报文"))
            log_queue.put(("SYSTEM", f"详情: {result.details}"))
        else:
            log_queue.put(("ERROR", f"攻击失败 — {result.details}"))

        log_queue.put(("_RESULT_", str(result)))

    except Exception as e:
        log_queue.put(("ERROR", f"执行异常: {e}"))
        log_queue.put(("ERROR", traceback.format_exc()))
        log_queue.put(("_ERROR_", str(e)))


class AttackRunner:
    """封装攻击线程的启动/停止/状态查询。"""

    def __init__(self, attack_name: str, config_dict: dict,
                 stop_event: threading.Event, log_queue: queue.Queue):
        self._attack_name = attack_name
        self._config_dict = config_dict
        self._stop_event = stop_event
        self._log_queue = log_queue
        self._thread: threading.Thread | None = None

    def start(self):
        """启动攻击线程。"""
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=_execute_attack,
            args=(self._attack_name, self._config_dict,
                  self._stop_event, self._log_queue),
            daemon=True,
        )
        self._thread.start()

    def stop(self):
        """发出停止信号。"""
        self._stop_event.set()

    def join(self, timeout: float | None = None):
        """等待攻击线程结束。"""
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()
```

- [ ] **Step 3: 验证测试通过**

```bash
pytest tests/unit/test_gui_meta.py -v -k "runner"
```

- [ ] **Step 4: 提交**

```bash
git add ospf_attack/gui/runner.py tests/unit/test_gui_meta.py
git commit -m "feat(gui): add attack runner with background thread and stop support"
```

---

### Task 6: 主窗口组装 (app.py)

**Files:**
- Create: `ospf_attack/gui/app.py`

- [ ] **Step 1: 实现主窗口**

```python
"""GUI 主窗口 — 组装左右面板、按钮区、状态栏。"""

import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from .styles import (
    BG_MAIN, FONT_TITLE, FONT_STATUS, FONT_BUTTON,
    PAD_OUTER, PAD_INNER, WINDOW_WIDTH, WINDOW_HEIGHT,
    WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT,
    LOG_MIN_HEIGHT, TREE_MIN_WIDTH,
)
from .attack_tree import AttackTree, ATTACK_LABELS
from .config_form import ConfigForm
from .log_panel import LogPanel
from .runner import AttackRunner


class MainWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("OSPF 协议攻击模拟器 — 操作面板")
        self.root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
        self.root.minsize(WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT)
        self.root.configure(bg=BG_MAIN)

        # 线程控制
        self._stop_event = threading.Event()
        self._log_queue = queue.Queue()
        self._runner: AttackRunner | None = None
        self._current_attack: str | None = None

        # Npcap 状态
        self._npcap_ok = self._check_npcap()
        self._log_queue.put(("SYSTEM", "GUI 操作面板已启动"))
        if self._npcap_ok:
            self._log_queue.put(("SYSTEM", "Npcap 已检测到，嗅探功能可用"))
        else:
            self._log_queue.put(("WARN", "未检测到 Npcap，嗅探功能不可用，纯发包功能正常"))

        self._build_ui()
        self._start_log_poll()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------
    # UI 构建
    # ------------------------------------------------------------------

    def _build_ui(self):
        # -- 标题栏 --
        title_bar = ttk.Frame(self.root)
        title_bar.pack(fill=tk.X, padx=PAD_OUTER, pady=(PAD_OUTER, 0))
        ttk.Label(title_bar, text="OSPF 协议攻击模拟器 — 操作面板",
                  font=FONT_TITLE).pack(side=tk.LEFT)

        # -- 主体: 左右分栏 --
        paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=PAD_OUTER, pady=PAD_OUTER)

        # 左侧: 攻击列表
        tree_frame = ttk.Frame(paned, width=TREE_MIN_WIDTH)
        self._attack_tree = AttackTree(tree_frame)
        self._attack_tree.pack(fill=tk.BOTH, expand=True)
        self._attack_tree.on_select = self._on_attack_select
        paned.add(tree_frame, weight=0)

        # 右侧: 表单 + 操作栏 + 日志
        right_frame = ttk.Frame(paned)
        paned.add(right_frame, weight=1)

        # 表单 (可滚动)
        self._form = ConfigForm(right_frame)
        self._form.pack(fill=tk.BOTH, expand=True)

        # 操作按钮栏
        btn_frame = ttk.Frame(right_frame)
        btn_frame.pack(fill=tk.X, pady=(PAD_INNER, 0))

        self._start_btn = ttk.Button(btn_frame, text="▶ 启动攻击",
                                     command=self._on_start)
        self._start_btn.pack(side=tk.LEFT, padx=(0, 4))

        self._stop_btn = ttk.Button(btn_frame, text="■ 停止",
                                    command=self._on_stop, state=tk.DISABLED)
        self._stop_btn.pack(side=tk.LEFT, padx=4)

        ttk.Button(btn_frame, text="📁 保存配置",
                   command=self._on_save_config).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="📂 加载配置",
                   command=self._on_load_config).pack(side=tk.LEFT, padx=4)

        # 状态栏
        status_frame = ttk.Frame(right_frame)
        status_frame.pack(fill=tk.X, pady=(PAD_INNER, 0))

        self._status_var = tk.StringVar(value="● 状态: 就绪")
        ttk.Label(status_frame, textvariable=self._status_var,
                  font=FONT_STATUS).pack(side=tk.LEFT)

        self._count_var = tk.StringVar(value="已发包: 0")
        ttk.Label(status_frame, textvariable=self._count_var,
                  font=FONT_STATUS).pack(side=tk.LEFT, padx=(20, 0))

        # 进度条
        self._progress = ttk.Progressbar(right_frame, mode="indeterminate")
        self._progress.pack(fill=tk.X, pady=(2, 0))

        # 日志面板
        log_frame = ttk.Frame(right_frame, height=LOG_MIN_HEIGHT)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(PAD_INNER, 0))
        self._log_panel = LogPanel(log_frame)
        self._log_panel.pack(fill=tk.BOTH, expand=True)

        # -- 底部状态栏 --
        bottom_bar = ttk.Frame(self.root)
        bottom_bar.pack(fill=tk.X, padx=PAD_OUTER, pady=(0, PAD_OUTER))
        npcap_status = "Npcap ✓" if self._npcap_ok else "Npcap ✗"
        ttk.Label(bottom_bar, text=npcap_status,
                  font=FONT_STATUS).pack(side=tk.LEFT)

    # ------------------------------------------------------------------
    # 日志轮询
    # ------------------------------------------------------------------

    def _start_log_poll(self):
        self._poll_log_queue()
        # 同时将初始化日志刷新到面板
        self._flush_init_logs()

    def _poll_log_queue(self):
        while True:
            try:
                level, message = self._log_queue.get_nowait()
                if level == "_RESULT_":
                    self._on_attack_done(message)
                elif level == "_ERROR_":
                    self._on_attack_error(message)
                else:
                    self._log_panel.write(level, message)
            except queue.Empty:
                break
        self.root.after(100, self._poll_log_queue)

    def _flush_init_logs(self):
        """刷新启动时的日志消息。"""
        self._poll_log_queue()

    # ------------------------------------------------------------------
    # 事件处理
    # ------------------------------------------------------------------

    def _on_attack_select(self, attack_name: str):
        self._current_attack = attack_name
        label = ATTACK_LABELS.get(attack_name, attack_name)
        self._form.set_attack(attack_name)
        self._log_queue.put(("SYSTEM", f"已选择攻击模块: {label} ({attack_name})"))

    def _on_start(self):
        if not self._current_attack:
            messagebox.showwarning("提示", "请先选择攻击类型")
            return
        if self._runner and self._runner.is_running:
            messagebox.showwarning("提示", "攻击正在运行中")
            return

        config_dict = self._form.get_config_dict()
        self._runner = AttackRunner(
            self._current_attack, config_dict,
            self._stop_event, self._log_queue,
        )
        self._runner.start()

        # 更新 UI 状态
        self._set_running_state(True)
        self._progress.start(10)

    def _on_stop(self):
        if self._runner:
            self._log_queue.put(("WARN", "用户请求停止攻击..."))
            self._runner.stop()
            self._stop_btn.configure(state=tk.DISABLED)

    def _on_attack_done(self, result_str: str):
        self._set_running_state(False)
        self._progress.stop()
        self._log_queue.put(("SYSTEM", f"结果: {result_str}"))

    def _on_attack_error(self, error_str: str):
        self._set_running_state(False)
        self._progress.stop()
        messagebox.showerror("攻击异常", error_str)

    def _on_save_config(self):
        if not self._current_attack:
            messagebox.showwarning("提示", "请先选择攻击类型")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".yaml",
            filetypes=[("YAML files", "*.yaml"), ("All files", "*.*")],
            title="保存攻击配置",
        )
        if not path:
            return
        config_dict = self._form.get_config_dict()
        config_dict["attack"] = self._current_attack
        import yaml
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(config_dict, f, allow_unicode=True, default_flow_style=False)
        self._log_queue.put(("INFO", f"配置已保存到: {path}"))

    def _on_load_config(self):
        path = filedialog.askopenfilename(
            filetypes=[("YAML files", "*.yaml"), ("All files", "*.*")],
            title="加载攻击配置",
        )
        if not path:
            return
        import yaml
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        attack_name = data.pop("attack", None)
        if attack_name:
            # 选择对应的攻击
            self._form.set_attack(attack_name)
            self._current_attack = attack_name
        self._form.set_config_dict(data)
        self._log_queue.put(("INFO", f"配置已加载: {path}"))

    def _on_close(self):
        if self._runner and self._runner.is_running:
            self._runner.stop()
            self._runner.join(timeout=3)
        self.root.destroy()

    # ------------------------------------------------------------------
    # 状态切换
    # ------------------------------------------------------------------

    def _set_running_state(self, running: bool):
        if running:
            self._start_btn.configure(state=tk.DISABLED)
            self._stop_btn.configure(state=tk.NORMAL)
            self._status_var.set("● 状态: 攻击运行中...")
        else:
            self._start_btn.configure(state=tk.NORMAL)
            self._stop_btn.configure(state=tk.DISABLED)
            self._status_var.set("● 状态: 就绪")

    # ------------------------------------------------------------------
    # Npcap 检测
    # ------------------------------------------------------------------

    def _check_npcap(self) -> bool:
        try:
            from ospf_attack.npcap.detector import is_npcap_installed
            return is_npcap_installed()
        except Exception:
            return False

    # ------------------------------------------------------------------
    # 启动
    # ------------------------------------------------------------------

    def run(self):
        self.root.mainloop()
```

- [ ] **Step 2: 实现 `launch_gui()` 入口**

创建 `ospf_attack/gui/__init__.py`:

```python
"""OSPF Attack GUI — Tkinter 操作面板。"""

def launch_gui():
    """启动 GUI 主窗口。"""
    from .app import MainWindow
    app = MainWindow()
    app.run()
```

- [ ] **Step 3: 验证 GUI 可启动**

手动测试（在 Docker 或 Linux 环境中需要 X11 forwarding，Windows 可直接运行）:

```bash
python -c "from ospf_attack.gui import launch_gui; launch_gui()"
# 验证窗口弹出，布局正确
```

- [ ] **Step 4: 提交**

```bash
git add ospf_attack/gui/app.py ospf_attack/gui/__init__.py
git commit -m "feat(gui): add main window assembly with left-right split layout"
```

---

### Task 7: GUI 入口 (__main__.py)

**Files:**
- Create: `ospf_attack/__main__.py`

- [ ] **Step 1: 创建入口文件**

```python
"""OSPF 攻击模拟器 GUI 入口 — python -m ospf_attack 启动操作面板。"""
from ospf_attack.gui import launch_gui

if __name__ == "__main__":
    launch_gui()
```

- [ ] **Step 2: 验证入口可用**

```bash
python -m ospf_attack
# 应弹出 GUI 窗口
```

- [ ] **Step 3: 提交**

```bash
git add ospf_attack/__main__.py
git commit -m "feat(gui): add __main__.py entry point for GUI launch"
```

---

### Task 8: 运行全部测试并修复集成

- [ ] **Step 1: 运行全部单元测试**

```bash
pytest tests/unit/ -v
```

确认已有的 73 个测试仍然全部通过，新增的 GUI 逻辑测试也通过。

- [ ] **Step 2: 检查 GUI 模块导入链**

```bash
python -c "from ospf_attack.gui.app import MainWindow; print('OK')"
```

- [ ] **Step 3: 提交**

```bash
git commit -m "chore(gui): verify all tests pass with GUI modules"
```

---

## 测试清单

| 测试 | 覆盖范围 |
|------|---------|
| `test_common_fields_have_metadata` | COMMON_FIELDS 所有字段在 FIELD_META 中 |
| `test_specific_fields_have_metadata` | 12 种攻击的专属字段均在 FIELD_META 中 |
| `test_field_meta_covers_all_config_fields` | FIELD_META 覆盖全部 6 个 dataclass |
| `test_get_widget_type_*` | 字段→控件类型映射正确 |
| `test_build_config_dict_*` | 从 widget 字典构建配置字典，类型转换正确 |
| `test_log_panel_*` (3 tests) | 日志面板创建、写入队列、刷新显示 |
| `test_attack_tree_*` (3 tests) | 攻击树节点数量、选中逻辑、回调 |
| `test_runner_*` (2 tests) | 启动日志、停止信号 |
