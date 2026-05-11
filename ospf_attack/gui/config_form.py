"""动态配置表单 — 根据攻击类型动态生成参数字段。"""

import json
import socket
import tkinter as tk
from tkinter import ttk
from typing import Any

from .styles import FONT_LABEL, FONT_ENTRY, PAD_FORM, PAD_OUTER, SECTION_GAP

# ---------------------------------------------------------------------------
# 路由条目编辑器 — 用于 LSA 攻击配置多条伪造路由
# ---------------------------------------------------------------------------

ROUTE_COLUMNS = ("network", "mask", "metric", "etype", "forward")


class RoutesHolder:
    """持有路由条目列表，兼容 StringVar 的 get/set 接口。"""

    def __init__(self, routes=None):
        self.routes: list[dict] = list(routes) if routes else []

    def get(self) -> list[dict]:
        return list(self.routes)

    def set(self, value):
        if isinstance(value, str):
            try:
                self.routes = json.loads(value)
            except (json.JSONDecodeError, TypeError):
                self.routes = []
        elif isinstance(value, list):
            self.routes = list(value)


class RoutesEditor(tk.Toplevel):
    """弹出窗口 — 用表格编辑多条伪造路由。"""

    LSA_TYPE_NAMES = {"1": "Type-1 Router", "3": "Type-3 Summary", "5": "Type-5 External"}

    def __init__(self, parent, holder: RoutesHolder, lsa_type: str = "5"):
        super().__init__(parent)
        type_name = self.LSA_TYPE_NAMES.get(lsa_type, f"Type-{lsa_type}")
        self.title(f"编辑伪造路由条目 — {type_name}")
        self.geometry("640x380")
        self.resizable(True, True)
        self.transient(parent)
        self.grab_set()

        self._holder = holder
        self._lsa_type = lsa_type
        self._routes: list[dict] = [r.copy() for r in holder.routes]

        self._build_ui()
        self._refresh_table()
        self.wait_window()

    def _build_ui(self):
        # 类型标签
        type_name = self.LSA_TYPE_NAMES.get(self._lsa_type, f"Type-{self._lsa_type}")
        ttk.Label(self, text=f"LSA 类型: {type_name}",
                  font=FONT_LABEL).pack(anchor=tk.W, padx=10, pady=(8, 0))

        # 表格
        headings = ("目标网段", "掩码", "Metric", "类型", "转发地址")
        widths = {"network": 130, "mask": 130, "metric": 60, "etype": 50, "forward": 130}
        self._tree = ttk.Treeview(self, columns=ROUTE_COLUMNS, show="headings",
                                  selectmode="browse", height=10)
        for col, heading in zip(ROUTE_COLUMNS, headings):
            self._tree.heading(col, text=heading)
            self._tree.column(col, width=widths.get(col, 100), anchor="center")
        self._tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 0))

        # 按钮栏
        bar = ttk.Frame(self)
        bar.pack(fill=tk.X, padx=10, pady=8)
        ttk.Button(bar, text="添加", command=self._on_add).pack(side=tk.LEFT, padx=2)
        ttk.Button(bar, text="编辑", command=self._on_edit).pack(side=tk.LEFT, padx=2)
        ttk.Button(bar, text="删除", command=self._on_delete).pack(side=tk.LEFT, padx=2)
        ttk.Button(bar, text="保存", command=self._on_save).pack(side=tk.RIGHT, padx=2)
        ttk.Button(bar, text="取消", command=self.destroy).pack(side=tk.RIGHT, padx=2)

    def _refresh_table(self):
        for row in self._tree.get_children():
            self._tree.delete(row)
        for r in self._routes:
            self._tree.insert("", tk.END, values=(
                r.get("network", ""),
                r.get("mask", "255.255.255.0"),
                r.get("metric", 20),
                r.get("etype", "E2"),
                r.get("forward", "0.0.0.0"),
            ))

    def _on_add(self):
        dlg = _RouteDialog(self, None)
        if dlg.result:
            self._routes.append(dlg.result)
            self._refresh_table()

    def _on_edit(self):
        sel = self._tree.selection()
        if not sel:
            return
        idx = self._tree.index(sel[0])
        dlg = _RouteDialog(self, self._routes[idx])
        if dlg.result:
            self._routes[idx] = dlg.result
            self._refresh_table()

    def _on_delete(self):
        sel = self._tree.selection()
        if sel:
            self._tree.delete(sel[0])
            idx = self._tree.index(sel[0])
            del self._routes[idx]

    def _on_save(self):
        self._holder.routes = list(self._routes)
        self.destroy()


class _RouteDialog(tk.Toplevel):
    """添加/编辑单条路由的对话框。"""

    def __init__(self, parent, existing: dict | None):
        super().__init__(parent)
        self.title("编辑路由" if existing else "添加路由")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.result: dict | None = None

        r = existing or {"network": "192.168.100.0", "mask": "255.255.255.0",
                         "metric": 20, "etype": "E2", "forward": "0.0.0.0"}

        self._vars: dict[str, tk.StringVar] = {}
        row = 0

        for label, key, val in [
            ("目标网段:", "network", str(r.get("network", ""))),
            ("掩码:", "mask", str(r.get("mask", "255.255.255.0"))),
            ("Metric:", "metric", str(r.get("metric", 20))),
        ]:
            ttk.Label(self, text=label, font=FONT_LABEL).grid(
                row=row, column=0, sticky=tk.W, padx=10, pady=4)
            var = tk.StringVar(value=val)
            ttk.Entry(self, textvariable=var, font=FONT_ENTRY, width=24).grid(
                row=row, column=1, sticky=tk.EW, padx=10, pady=4)
            self._vars[key] = var
            row += 1

        # E type combobox
        ttk.Label(self, text="Metric 类型:", font=FONT_LABEL).grid(
            row=row, column=0, sticky=tk.W, padx=10, pady=4)
        etype_var = tk.StringVar(value=r.get("etype", "E2"))
        ttk.Combobox(self, textvariable=etype_var, values=["E1", "E2"],
                     font=FONT_ENTRY, width=22, state="readonly").grid(
            row=row, column=1, sticky=tk.EW, padx=10, pady=4)
        self._vars["etype"] = etype_var
        row += 1

        # Forwarding address
        ttk.Label(self, text="转发地址:", font=FONT_LABEL).grid(
            row=row, column=0, sticky=tk.W, padx=10, pady=4)
        var = tk.StringVar(value=str(r.get("forward", "0.0.0.0")))
        ttk.Entry(self, textvariable=var, font=FONT_ENTRY, width=24).grid(
            row=row, column=1, sticky=tk.EW, padx=10, pady=4)
        self._vars["forward"] = var
        row += 1

        bar = ttk.Frame(self)
        bar.grid(row=row, column=0, columnspan=2, pady=10)
        ttk.Button(bar, text="确定", command=self._on_ok).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar, text="取消", command=self.destroy).pack(side=tk.LEFT, padx=4)

        self.wait_window()

    def _on_ok(self):
        try:
            self.result = {
                "network": self._vars["network"].get(),
                "mask": self._vars["mask"].get(),
                "metric": int(self._vars["metric"].get()),
                "etype": self._vars["etype"].get(),
                "forward": self._vars["forward"].get(),
            }
        except ValueError:
            self.result = None
        self.destroy()


def get_network_interfaces() -> list[str]:
    """获取本机网卡列表（可读名称）。Windows 用 Scapy/Npcap，Linux 用 socket。"""
    # Windows: Scapy IFACES 提供 Npcap 可读名称
    try:
        from scapy.all import IFACES
        names = sorted(set(
            d.description for d in IFACES.data.values()
            if d.description
        ))
        if names:
            return names
    except Exception:
        pass
    # Linux / fallback
    try:
        return [name for _, name in socket.if_nameindex()]
    except Exception:
        pass
    return []


# =====================================================================
# 字段元数据 — 每个配置字段的控件类型和标签
# =====================================================================

FIELD_META: dict[str, dict] = {
    # -- 通用参数 (AttackConfig) --
    "iface":          {"widget": "iface",   "label": "网卡接口"},
    "target":         {"widget": "entry",   "label": "目标地址", "default": "224.0.0.5"},
    "mode":           {"widget": "radio",   "label": "攻击模式", "choices": ["passive", "active"]},
    "sniff_mode":     {"widget": "radio",   "label": "嗅探模式", "choices": ["hub", "arp_spoof"]},
    "router_id":      {"widget": "entry",   "label": "伪装路由器 ID", "default": "1.1.1.1"},
    "area_id":        {"widget": "entry",   "label": "OSPF 区域", "default": "0.0.0.0"},
    "sniff_duration": {"widget": "spinbox", "label": "嗅探时长(秒)", "from_": 1, "to": 3600, "default": 30},
    "arp_target_a":   {"widget": "entry",   "label": "ARP 欺骗目标 A"},
    "arp_target_b":   {"widget": "entry",   "label": "ARP 欺骗目标 B"},
    "arp_interval":   {"widget": "spinbox", "label": "ARP 间隔(秒)", "from_": 1, "to": 60, "default": 2},
    "packet_rate":    {"widget": "spinbox", "label": "发包速率(pps)", "from_": 1, "to": 10000, "default": 10},
    "max_packets":    {"widget": "spinbox", "label": "最大发包数(0=不限)", "from_": 0, "to": 1000000, "default": 0},
    "verbose":        {"widget": "check",   "label": "详细输出"},
    "pcap_output":    {"widget": "entry",   "label": "PCAP 保存路径"},

    # -- HelloInjectionConfig 专属 --
    "hello_interval":       {"widget": "spinbox", "label": "Hello 间隔(秒)", "from_": 1, "to": 65535, "default": 10},
    "router_dead_interval": {"widget": "spinbox", "label": "Dead 间隔(秒)", "from_": 1, "to": 65535, "default": 40},
    "router_priority":      {"widget": "spinbox", "label": "路由器优先级", "from_": 0, "to": 255, "default": 255},
    "auth_type":            {"widget": "combo",   "label": "认证类型", "choices": ["none", "plain", "md5"], "default": "none"},
    "auth_key":             {"widget": "entry",   "label": "认证密钥"},
    "subnet_mask":          {"widget": "entry",   "label": "子网掩码", "default": "255.255.255.0"},

    # -- LSAConfig 专属 --
    "lsa_type":            {"widget": "combo",   "label": "LSA 类型", "choices": ["1", "3", "5"], "default": "5"},
    "link_state_id":       {"widget": "entry",   "label": "Link State ID"},
    "advertising_router":  {"widget": "entry",   "label": "通告路由器"},
    "sequence_number":     {"widget": "entry",   "label": "序列号 (hex)", "default": "0x80000001"},
    "age":                 {"widget": "spinbox", "label": "Age (秒)", "from_": 0, "to": 3600, "default": 0},
    "metric":              {"widget": "spinbox", "label": "Metric", "from_": 0, "to": 16777215, "default": 20},
    "network_mask":        {"widget": "entry",   "label": "网络掩码", "default": "255.255.255.0"},
    "forwarding_address":  {"widget": "entry",   "label": "转发地址", "default": "0.0.0.0"},
    "external_routes":     {"widget": "routes",  "label": "伪造路由条目"},

    # -- DoSConfig 专属 --
    "duration":             {"widget": "spinbox", "label": "持续时间(秒)", "from_": 1, "to": 86400, "default": 60},
    "thread_count":         {"widget": "spinbox", "label": "并发线程数", "from_": 1, "to": 100, "default": 1},
    "lsa_change_interval":  {"widget": "spinbox", "label": "LSA 变化间隔(秒)", "from_": 1, "to": 3600, "default": 2},
    "lsa_count":            {"widget": "spinbox", "label": "注入 LSA 数量", "from_": 1, "to": 100000, "default": 1000},

    # -- MITMConfig 专属 --
    "target_a":    {"widget": "entry",   "label": "路由器 A IP"},
    "target_b":    {"widget": "entry",   "label": "路由器 B IP"},
    "action":      {"widget": "combo",   "label": "操作类型", "choices": ["drop", "modify", "forward", "inject"], "default": "modify"},
    "modify_rules":{"widget": "entry",   "label": "修改规则 (JSON)"},

    # -- ReplayConfig 专属 --
    "capture_file":   {"widget": "entry",   "label": "捕获文件路径"},
    "replay_loop":    {"widget": "check",   "label": "循环重放"},
    "replay_interval":{"widget": "spinbox", "label": "重放间隔(秒)", "from_": 1, "to": 3600, "default": 5},
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
        if wtype == "routes":
            result[name] = w.get()
        elif wtype == "spinbox":
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

    def format_preview(self) -> str:
        """返回当前参数对应的 OSPF 报文预览字符串，供外部预览面板使用。"""
        return _format_ospf_preview(self)

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
        self._specific_frame.pack(fill=tk.X, padx=PAD_OUTER, pady=(SECTION_GAP, 0))
        # ARP 面板根据 sniff_mode 决定显隐
        self._toggle_arp()

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
                if isinstance(w, RoutesHolder):
                    w.set(value)
                    label_var = self._widgets.get(f"_{name}_label")
                    if label_var:
                        _update_routes_label(w, label_var)
                elif hasattr(w, "set"):
                    w.set(str(value))
                elif hasattr(w, "delete"):
                    w.delete(0, tk.END)
                    w.insert(0, str(value))
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

    def _build_specific(self, attack_name: str):
        fields = SPECIFIC_FIELDS.get(attack_name, [])
        for i, name in enumerate(fields):
            _build_field_row(self._specific_frame, name, i, self)

    def _toggle_arp(self):
        if self._sniff_var and self._sniff_var.get() == "arp_spoof":
            self._arp_frame.pack(fill=tk.X, padx=PAD_OUTER, pady=(SECTION_GAP, 0))
        else:
            self._arp_frame.pack_forget()


def _update_routes_label(holder: RoutesHolder, var: tk.StringVar):
    n = len(holder.routes)
    var.set(f"{n} 条路由" if n else "未配置")


def _open_routes_editor(parent: ttk.Frame, holder: RoutesHolder, count_var: tk.StringVar,
                        form: "ConfigForm"):
    lsa_type = "5"
    if form and form._widgets.get("lsa_type"):
        try:
            lsa_type = str(form._widgets["lsa_type"].get())
        except Exception:
            pass
    RoutesEditor(parent.winfo_toplevel(), holder, lsa_type)
    _update_routes_label(holder, count_var)


# ---------------------------------------------------------------------------
# 报文预览
# ---------------------------------------------------------------------------

def _format_ospf_preview(form: "ConfigForm") -> str:
    """根据当前表单值构造 OSPF 报文并按协议格式展示。"""
    w = form._widgets
    attack = form._attack_name or ""

    def _get(key, default=""):
        v = w.get(key)
        if v is None:
            return default
        try:
            return v.get()
        except Exception:
            return str(v) if v else default

    iface = _get("iface", "eth0")
    target = _get("target", "224.0.0.5")
    rid = _get("router_id", "1.1.1.1")
    aid = _get("area_id", "0.0.0.0")
    mode = _get("mode", "passive")
    sniff = _get("sniff_mode", "hub")

    # Try to get src IP
    src_ip = "(unknown)"
    try:
        from ospf_attack.network.adapter import get_local_ip
        src_ip = get_local_ip(iface)
    except Exception:
        pass

    lines = []
    lines.append("┌── IP Header ──────────────────────────┐")
    lines.append(f"│ Src : {src_ip:<30} │")
    lines.append(f"│ Dst : {target:<30} │")
    lines.append(f"│ Proto: OSPF (89)   TTL: 1             │")
    lines.append("├── OSPF Header ────────────────────────┤")
    lines.append(f"│ Version: 2   Type: (unknown)         │")
    lines.append(f"│ Router ID : {rid:<24} │")
    lines.append(f"│ Area ID   : {aid:<24} │")
    lines.append(f"│ Auth: Null                            │")

    # Attack-specific body
    if attack in ("hello-inject", "adjacency-break", "dr-bdr-hijack"):
        hi = _get("hello_interval", "10")
        di = _get("router_dead_interval", "40")
        pri = _get("router_priority", "255")
        mask = _get("subnet_mask", "255.255.255.0")
        lines.append("├── OSPF Hello ─────────────────────────┤")
        lines.append(f"│ Network Mask : {mask:<22} │")
        lines.append(f"│ Hello Interval: {hi}s   Dead: {di}s         │")
        lines.append(f"│ Priority: {pri:<3}   Options: 0x02          │")
        lines.append(f"│ DR: 0.0.0.0   BDR: 0.0.0.0          │")

    elif attack in ("route-inject", "max-seq", "max-age", "fight-back"):
        lsa_type = _get("lsa_type", "5")
        lsid = _get("link_state_id", rid)
        adv = _get("advertising_router", rid)
        seq = _get("sequence_number", "0x80000001")
        age = _get("age", "0")
        metric = _get("metric", "20")
        nmask = _get("network_mask", "255.255.255.0")
        fwd = _get("forwarding_address", "0.0.0.0")
        routes = _get("external_routes")
        n_routes = len(routes) if isinstance(routes, list) else 0

        lsa_names = {"1": "Router", "3": "Summary", "5": "External"}
        lsa_name = lsa_names.get(str(lsa_type), f"Type-{lsa_type}")

        lines.append("├── OSPF LSU ────────────────────────────┤")
        lines.append(f"│ LSA Count: {1 + n_routes:<26} │")
        lines.append("├── LSA Header ─────────────────────────┤")
        lines.append(f"│ Type: {lsa_name:<4}  LS ID: {lsid:<16} │")
        lines.append(f"│ Adv Router: {adv:<23} │")
        lines.append(f"│ Sequence: {seq:<10}  Age: {age:<5}s     │")
        lines.append("├── LSA Body ───────────────────────────┤")
        if str(lsa_type) == "5":
            lines.append(f"│ Network Mask: {nmask:<22} │")
            lines.append(f"│ Metric: {metric:<5}  Fwd Addr: {fwd:<12} │")
        elif str(lsa_type) == "3":
            lines.append(f"│ Network Mask: {nmask:<22} │")
            lines.append(f"│ Metric: {metric:<28} │")
        if n_routes:
            type_label = {"1": "Type-1 Router", "3": "Type-3 Summary",
                          "5": "Type-5 External"}.get(str(lsa_type), f"Type-{lsa_type}")
            lines.append(f"├── 伪造路由条目 ({type_label}) ────────────┤")
            for i, r in enumerate(routes):
                r_net = r.get("network", "-")
                r_mask = r.get("mask", "255.255.255.0")
                r_metric = r.get("metric", 20)
                r_etype = r.get("etype", "E2")
                r_fwd = r.get("forward", "0.0.0.0")
                lines.append(f"│ #{i + 1} {r_net}/{r_mask}  [{r_etype}]")
                lines.append(f"│    Metric: {r_metric}  Fwd: {r_fwd}")

    elif attack in ("flood", "spf-recalc", "db-overflow"):
        dur = _get("duration", "60")
        rate = _get("packet_rate", "10")
        lines.append("├── DoS 攻击参数 ────────────────────────┤")
        lines.append(f"│ Duration: {dur}s   Rate: {rate} pps        │")
        if attack == "spf-recalc":
            interval = _get("lsa_change_interval", "2")
            lines.append(f"│ LSA Change Interval: {interval}s              │")
        elif attack == "db-overflow":
            count = _get("lsa_count", "1000")
            lines.append(f"│ LSA Count: {count:<26} │")

    elif attack in ("mitm",):
        action = _get("action", "modify")
        ta = _get("target_a", "")
        tb = _get("target_b", "")
        lines.append("├── MITM 参数 ───────────────────────────┤")
        lines.append(f"│ Action: {action:<27} │")
        lines.append(f"│ Target A: {ta:<25} │")
        lines.append(f"│ Target B: {tb:<25} │")

    elif attack in ("replay",):
        cap = _get("capture_file", "")
        loop = _get("replay_loop", False)
        lines.append("├── Replay 参数 ─────────────────────────┤")
        lines.append(f"│ Capture: {str(cap)[:28]:<28} │")
        lines.append(f"│ Loop: {str(loop):<31} │")

    lines.append("└────────────────────────────────────────┘")
    return "\n".join(lines)


class PacketPreview(ttk.LabelFrame):
    """报文预览面板 — 显示构造的 OSPF 报文结构。"""

    def __init__(self, parent, preview_fn, **kw):
        super().__init__(parent, text="报文预览", padding=6, **kw)
        self._preview_fn = preview_fn

        bar = ttk.Frame(self)
        bar.pack(fill=tk.X, pady=(0, 4))
        ttk.Button(bar, text="刷新预览", command=self.refresh).pack(side=tk.RIGHT)

        self._text = tk.Text(self, font=("Consolas", 9), width=42, height=24,
                             bg="#1e1e1e", fg="#d4d4d4",
                             insertbackground="#ffffff",
                             relief=tk.FLAT, state=tk.DISABLED,
                             wrap=tk.NONE)
        self._text.pack(fill=tk.BOTH, expand=True)

        self.refresh()

    def refresh(self):
        try:
            preview = self._preview_fn()
        except Exception:
            preview = "(报文预览不可用)"
        self._text.configure(state=tk.NORMAL)
        self._text.delete("1.0", tk.END)
        self._text.insert("1.0", preview)
        self._text.configure(state=tk.DISABLED)


def _build_field_row(parent: ttk.Frame, field_name: str, row: int, form: "ConfigForm"):
    """在父容器中创建一行: 标签 + 输入控件。注册到 form._widgets。"""
    meta = FIELD_META.get(field_name, {})
    label_text = meta.get("label", field_name)
    wtype = meta.get("widget", "entry")

    lbl = ttk.Label(parent, text=label_text + ":", font=FONT_LABEL)
    lbl.grid(row=row, column=0, sticky=tk.W, padx=(0, 6), pady=PAD_FORM)

    if wtype == "iface":
        ifaces = get_network_interfaces()
        var = tk.StringVar(value=ifaces[0] if ifaces else "")
        w = ttk.Combobox(parent, textvariable=var, values=ifaces,
                         font=FONT_ENTRY, width=30)
        w.grid(row=row, column=1, sticky=tk.EW, pady=PAD_FORM)
        form._widgets[field_name] = var

    elif wtype == "entry":
        default = meta.get("default", "")
        var = tk.StringVar(value=str(default))
        w = ttk.Entry(parent, textvariable=var, font=FONT_ENTRY, width=32)
        w.grid(row=row, column=1, sticky=tk.EW, pady=PAD_FORM)
        form._widgets[field_name] = var

    elif wtype == "spinbox":
        from_ = meta.get("from_", 0)
        to = meta.get("to", 65535)
        default = meta.get("default", from_)
        var = tk.StringVar(value=str(default))
        w = ttk.Spinbox(parent, from_=from_, to=to, textvariable=var,
                        font=FONT_ENTRY, width=30)
        w.grid(row=row, column=1, sticky=tk.EW, pady=PAD_FORM)
        form._widgets[field_name] = var

    elif wtype == "combo":
        choices = meta.get("choices", [])
        default = meta.get("default", choices[0] if choices else "")
        var = tk.StringVar(value=str(default))
        w = ttk.Combobox(parent, textvariable=var, values=choices,
                         font=FONT_ENTRY, width=30, state="readonly")
        w.grid(row=row, column=1, sticky=tk.EW, pady=PAD_FORM)
        form._widgets[field_name] = var

    elif wtype == "routes":
        holder = RoutesHolder()
        count_var = tk.StringVar(value="未配置")
        f = ttk.Frame(parent)
        f.grid(row=row, column=1, sticky=tk.EW, pady=PAD_FORM)
        ttk.Button(f, text="编辑路由...",
                   command=lambda h=holder, cv=count_var, f=form: _open_routes_editor(parent, h, cv, f)
                   ).pack(side=tk.LEFT)
        ttk.Label(f, textvariable=count_var, font=FONT_LABEL,
                  foreground="gray").pack(side=tk.LEFT, padx=6)
        form._widgets[field_name] = holder
        form._widgets[f"_{field_name}_label"] = count_var

    elif wtype == "check":
        var = tk.BooleanVar(value=False)
        w = ttk.Checkbutton(parent, variable=var)
        w.grid(row=row, column=1, sticky=tk.W, pady=PAD_FORM)
        form._widgets[field_name] = var

    parent.columnconfigure(1, weight=1)
