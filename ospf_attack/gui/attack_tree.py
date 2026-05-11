"""攻击模块列表 — 左侧 Treeview 展示 4 类 12 种攻击。"""

import tkinter as tk
from tkinter import ttk
from typing import Callable

from .styles import BG_TREE


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
        self.on_select: Callable[[str], None] | None = None

        self.tree = ttk.Treeview(
            self, show="tree", selectmode="browse",
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

    def get_selected(self) -> str | None:
        sel = self.tree.selection()
        if not sel:
            return None
        iid = sel[0]
        for name, nid in self._name_to_iid.items():
            if nid == iid:
                return name
        return None

    def _on_tree_select(self, _event):
        name = self.get_selected()
        if name and self.on_select:
            self.on_select(name)
