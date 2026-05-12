"""报文嗅探捕获 / pcap 导入 / 报文浏览器。"""

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from .styles import FONT_LABEL, FONT_ENTRY


# ---------------------------------------------------------------------------
# OSPF 报文解析
# ---------------------------------------------------------------------------

def _ip_to_str(data: bytes, offset: int) -> str:
    return ".".join(str(b) for b in data[offset:offset + 4])


def _parse_ospf_hello(data: bytes) -> dict | None:
    """解析 OSPF Hello 报文，返回关键字段字典。"""
    iphl = (data[0] & 0x0F) * 4
    ospf = iphl
    if len(data) < ospf + 44:
        return None
    h = ospf + 24  # Hello body starts after OSPF header (24 bytes)
    if len(data) < h + 20:
        return None

    nbrs = [".".join(str(b) for b in data[n:n + 4])
            for n in range(h + 20, len(data), 4)]

    return {
        "pkt_type": "Hello",
        "router_id": _ip_to_str(data, ospf + 4),
        "area_id": _ip_to_str(data, ospf + 8),
        "src_ip": _ip_to_str(data, 12),
        "dst_ip": _ip_to_str(data, 16),
        "mask": _ip_to_str(data, h),
        "hello_interval": int.from_bytes(data[h + 4:h + 6], "big"),
        "options": data[h + 6],
        "priority": data[h + 7],
        "dead_interval": int.from_bytes(data[h + 8:h + 12], "big"),
        "dr": _ip_to_str(data, h + 12),
        "bdr": _ip_to_str(data, h + 16),
        "neighbors": nbrs,
    }


def _parse_ospf_lsu(data: bytes) -> dict | None:
    """解析 OSPF LSU 报文，提取第一个 LSA 的关键字段。"""
    iphl = (data[0] & 0x0F) * 4
    ospf = iphl
    if len(data) < ospf + 32:
        return None

    lsu = ospf + 24  # LSU body starts after OSPF header
    if len(data) < lsu + 4:
        return None

    lsa_count = int.from_bytes(data[lsu:lsu + 4], "big")
    lsa_start = lsu + 4
    if len(data) < lsa_start + 20:
        return None

    # LSA header (20 bytes): age(2) + options(1) + type(1) + lsid(4) + adv(4) + seq(4) + chk(2) + len(2)
    age = int.from_bytes(data[lsa_start:lsa_start + 2], "big")
    lsa_type = data[lsa_start + 2]
    lsid = _ip_to_str(data, lsa_start + 3)
    adv = _ip_to_str(data, lsa_start + 7)
    seq = int.from_bytes(data[lsa_start + 11:lsa_start + 15], "big")
    body_len = int.from_bytes(data[lsa_start + 18:lsa_start + 20], "big")

    result = {
        "pkt_type": f"LSU (Type-{lsa_type})",
        "router_id": _ip_to_str(data, ospf + 4),
        "area_id": _ip_to_str(data, ospf + 8),
        "src_ip": _ip_to_str(data, 12),
        "dst_ip": _ip_to_str(data, 16),
        "lsa_type": lsa_type,
        "lsa_count": lsa_count,
        "link_state_id": lsid,
        "advertising_router": adv,
        "sequence": seq,
        "age": age,
        "raw_body": data[lsa_start:lsa_start + body_len] if lsa_start + body_len <= len(data) else b"",
    }

    # Parse LSA body for additional fields
    body = result["raw_body"]
    if lsa_type == 5 and len(body) >= 16:
        result["network_mask"] = _ip_to_str(body, 0)
        result["metric"] = int.from_bytes(body[4:8], "big") & 0x00FFFFFF
        result["forwarding_address"] = _ip_to_str(body, 8)
    elif lsa_type == 3 and len(body) >= 8:
        result["network_mask"] = _ip_to_str(body, 0)
        result["metric"] = int.from_bytes(body[4:8], "big") & 0x00FFFFFF

    return result


def _parse_ospf_dbd(data: bytes) -> dict | None:
    """解析 OSPF DBD 报文。"""
    iphl = (data[0] & 0x0F) * 4
    ospf = iphl
    if len(data) < ospf + 32:
        return None
    dbd = ospf + 24
    return {
        "pkt_type": "DBD",
        "router_id": _ip_to_str(data, ospf + 4),
        "area_id": _ip_to_str(data, ospf + 8),
        "src_ip": _ip_to_str(data, 12),
        "dst_ip": _ip_to_str(data, 16),
        "mtu": int.from_bytes(data[dbd:dbd + 2], "big"),
        "flags": data[dbd + 2],
        "ddseq": int.from_bytes(data[dbd + 4:dbd + 8], "big"),
    }


def _parse_ospf_lsr(data: bytes) -> dict | None:
    """解析 OSPF LSR 报文。"""
    iphl = (data[0] & 0x0F) * 4
    ospf = iphl
    if len(data) < ospf + 28:
        return None
    lsr = ospf + 24
    return {
        "pkt_type": "LSR",
        "router_id": _ip_to_str(data, ospf + 4),
        "area_id": _ip_to_str(data, ospf + 8),
        "src_ip": _ip_to_str(data, 12),
        "dst_ip": _ip_to_str(data, 16),
    }


def parse_ospf_packet(raw: bytes) -> dict | None:
    """解析一个 OSPF 报文，返回结构化字段字典。"""
    if len(raw) < 34:
        return None
    iphl = (raw[0] & 0x0F) * 4
    if raw[0] >> 4 != 4 or len(raw) < iphl + 24:
        return None
    if raw[9] != 89:  # not OSPF
        return None
    ptype = raw[iphl + 1]
    parsers = {1: _parse_ospf_hello, 2: _parse_ospf_dbd, 3: _parse_ospf_lsr, 4: _parse_ospf_lsu}
    parser = parsers.get(ptype)
    if parser:
        return parser(raw)
    return None


# ---------------------------------------------------------------------------
# 实时嗅探
# ---------------------------------------------------------------------------

def sniff_ospf(iface: str, timeout: int = 10) -> list[dict]:
    """在指定接口嗅探 OSPF 报文，返回解析后的报文列表。"""
    results = []
    try:
        from scapy.all import sniff
        packets = sniff(
            filter="proto 89", iface=iface,
            timeout=timeout, store=True,
        )
        for pkt in packets:
            parsed = parse_ospf_packet(bytes(pkt))
            if parsed:
                parsed["_raw"] = bytes(pkt)
                results.append(parsed)
    except Exception:
        import traceback
        traceback.print_exc()
    return results


# ---------------------------------------------------------------------------
# pcap 文件导入
# ---------------------------------------------------------------------------

def read_pcap(path: str) -> list[dict]:
    """从 pcap 文件读取 OSPF 报文，返回解析后的列表。"""
    results = []
    try:
        from scapy.utils import rdpcap
        packets = rdpcap(path)
        for pkt in packets:
            parsed = parse_ospf_packet(bytes(pkt))
            if parsed:
                parsed["_raw"] = bytes(pkt)
                results.append(parsed)
    except Exception:
        import traceback
        traceback.print_exc()
    return results


# ---------------------------------------------------------------------------
# 报文浏览器弹窗
# ---------------------------------------------------------------------------

PACKET_COLUMNS = ("type", "src", "dst", "summary")


class PacketBrowser(tk.Toplevel):
    """报文浏览/选择弹窗 — 展示捕获或导入的 OSPF 报文，支持选择后自动填充参数。"""

    def __init__(self, parent, packets: list[dict], auto_fill_callback=None):
        super().__init__(parent)
        self.title(f"OSPF 报文浏览器 — {len(packets)} 个报文")
        self.geometry("860x480")
        self.resizable(True, True)
        self.transient(parent)

        self._packets = packets
        self._auto_fill = auto_fill_callback

        self._build_ui()
        self._populate()

    def _build_ui(self):
        # 表格
        cols = ("类型", "源 IP", "目的 IP", "摘要")
        self._tree = ttk.Treeview(self, columns=cols, show="headings",
                                  selectmode="browse", height=14)
        headings = {
            "type": "类型", "src": "源 IP", "dst": "目的 IP", "summary": "摘要"
        }
        widths = {"type": 120, "src": 140, "dst": 140, "summary": 400}
        for col, heading in headings.items():
            self._tree.heading(col, text=heading)
            self._tree.column(col, width=widths.get(col, 100), anchor="w" if col == "summary" else "center")
        self._tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 0))

        # 底部: 详情 + 按钮
        bottom = ttk.Frame(self)
        bottom.pack(fill=tk.X, padx=10, pady=8)

        # 详情文本
        self._detail = tk.Text(bottom, font=("Consolas", 9), height=8,
                               bg="#1e1e1e", fg="#d4d4d4", relief=tk.FLAT,
                               state=tk.DISABLED, wrap=tk.NONE)
        self._detail.pack(fill=tk.BOTH, expand=True, pady=(0, 6))

        # 按钮栏
        bar = ttk.Frame(bottom)
        bar.pack(fill=tk.X)
        ttk.Button(bar, text="应用到表单", command=self._on_apply).pack(side=tk.LEFT, padx=2)
        ttk.Button(bar, text="保存为 pcap", command=self._on_save).pack(side=tk.LEFT, padx=2)
        ttk.Button(bar, text="关闭", command=self.destroy).pack(side=tk.RIGHT, padx=2)

        self._tree.bind("<<TreeviewSelect>>", self._on_select)

    def _populate(self):
        for pkt in self._packets:
            ptype = pkt.get("pkt_type", "?")
            src = pkt.get("src_ip", "?")
            dst = pkt.get("dst_ip", "?")
            summary = self._format_summary(pkt)
            self._tree.insert("", tk.END, values=(ptype, src, dst, summary))

    def _format_summary(self, pkt: dict) -> str:
        rid = pkt.get("router_id", "?")
        aid = pkt.get("area_id", "?")
        parts = [f"RID={rid}", f"Area={aid}"]

        if "hello_interval" in pkt:
            parts.append(f"HelloInterval={pkt['hello_interval']}s")
            parts.append(f"Priority={pkt.get('priority', '?')}")
            parts.append(f"DR={pkt.get('dr', '?')} BDR={pkt.get('bdr', '?')}")
        if "lsa_type" in pkt:
            parts.append(f"LSA-Type={pkt['lsa_type']}")
            parts.append(f"LSID={pkt.get('link_state_id', '?')}")
            parts.append(f"Seq=0x{pkt.get('sequence', 0):08X}")
            parts.append(f"Age={pkt.get('age', '?')}s")
        return "  |  ".join(parts)

    def _format_detail(self, pkt: dict) -> str:
        lines = []
        lines.append(f"协议类型: {pkt.get('pkt_type', '?')}")
        lines.append(f"源 IP:      {pkt.get('src_ip', '?')}")
        lines.append(f"目的 IP:    {pkt.get('dst_ip', '?')}")
        lines.append(f"Router ID:  {pkt.get('router_id', '?')}")
        lines.append(f"Area ID:    {pkt.get('area_id', '?')}")

        if "hello_interval" in pkt:
            lines.append("--- Hello 字段 ---")
            lines.append(f"  掩码:        {pkt.get('mask', '?')}")
            lines.append(f"  Hello间隔:   {pkt.get('hello_interval', '?')}s")
            lines.append(f"  优先级:      {pkt.get('priority', '?')}")
            lines.append(f"  Dead间隔:    {pkt.get('dead_interval', '?')}s")
            lines.append(f"  DR:          {pkt.get('dr', '?')}")
            lines.append(f"  BDR:         {pkt.get('bdr', '?')}")
            lines.append(f"  邻居数:      {len(pkt.get('neighbors', []))}")

        if "lsa_type" in pkt:
            lines.append("--- LSA 字段 ---")
            lines.append(f"  LSA 类型:    Type-{pkt.get('lsa_type', '?')}")
            lines.append(f"  Link State:  {pkt.get('link_state_id', '?')}")
            lines.append(f"  Adv Router:  {pkt.get('advertising_router', '?')}")
            lines.append(f"  序列号:      0x{pkt.get('sequence', 0):08X}")
            lines.append(f"  Age:         {pkt.get('age', '?')}s")
            if "metric" in pkt:
                lines.append(f"  Metric:      {pkt.get('metric', '?')}")
            if "network_mask" in pkt:
                lines.append(f"  网络掩码:    {pkt.get('network_mask', '?')}")
            if "forwarding_address" in pkt:
                lines.append(f"  转发地址:    {pkt.get('forwarding_address', '?')}")

        return "\n".join(lines)

    def _on_select(self, _event):
        sel = self._tree.selection()
        if not sel:
            return
        idx = self._tree.index(sel[0])
        pkt = self._packets[idx]
        detail = self._format_detail(pkt)
        self._detail.configure(state=tk.NORMAL)
        self._detail.delete("1.0", tk.END)
        self._detail.insert("1.0", detail)
        self._detail.configure(state=tk.DISABLED)

    def _on_apply(self):
        sel = self._tree.selection()
        if not sel:
            messagebox.showinfo("提示", "请先选择一个报文")
            return
        idx = self._tree.index(sel[0])
        pkt = self._packets[idx]
        if self._auto_fill:
            self._auto_fill(pkt)
        self.destroy()

    def _on_save(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("pcap files", "*.pcap"), ("All files", "*.*")],
            title="保存捕获的报文为 pcap",
        )
        if not path:
            return
        try:
            from scapy.utils import wrpcap
            raw_pkts = [pkt["_raw"] for pkt in self._packets if "_raw" in pkt]
            if raw_pkts:
                wrpcap(path, raw_pkts)
        except Exception as e:
            messagebox.showerror("保存失败", str(e))
