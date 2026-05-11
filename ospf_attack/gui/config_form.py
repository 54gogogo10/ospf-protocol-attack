"""动态配置表单 — 根据攻击类型动态生成参数字段。"""

import tkinter as tk
from tkinter import ttk
from typing import Any

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
