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
from .config_form import ConfigForm, PacketPreview
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

        # 右侧: 表单 + 操作栏 + 日志 (左) | 报文预览 (右)
        right_frame = ttk.Frame(paned)
        paned.add(right_frame, weight=1)

        # 右侧内部左右分栏
        right_paned = ttk.PanedWindow(right_frame, orient=tk.HORIZONTAL)
        right_paned.pack(fill=tk.BOTH, expand=True)

        # 左列: 表单 + 按钮 + 状态 + 日志
        left_col = ttk.Frame(right_paned)
        right_paned.add(left_col, weight=1)

        self._form = ConfigForm(left_col)
        self._form.pack(fill=tk.BOTH, expand=True)

        # 操作按钮栏
        btn_frame = ttk.Frame(left_col)
        btn_frame.pack(fill=tk.X, pady=(PAD_INNER, 0))

        self._start_btn = ttk.Button(btn_frame, text="▶ 启动攻击",
                                     command=self._on_start)
        self._start_btn.pack(side=tk.LEFT, padx=(0, 4))

        self._stop_btn = ttk.Button(btn_frame, text="■ 停止",
                                    command=self._on_stop, state=tk.DISABLED)
        self._stop_btn.pack(side=tk.LEFT, padx=4)

        ttk.Button(btn_frame, text="保存配置",
                   command=self._on_save_config).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="加载配置",
                   command=self._on_load_config).pack(side=tk.LEFT, padx=4)

        # 状态栏
        status_frame = ttk.Frame(left_col)
        status_frame.pack(fill=tk.X, pady=(PAD_INNER, 0))

        self._status_var = tk.StringVar(value="● 状态: 就绪")
        ttk.Label(status_frame, textvariable=self._status_var,
                  font=FONT_STATUS).pack(side=tk.LEFT)

        self._count_var = tk.StringVar(value="已发包: 0")
        ttk.Label(status_frame, textvariable=self._count_var,
                  font=FONT_STATUS).pack(side=tk.LEFT, padx=(20, 0))

        # 进度条
        self._progress = ttk.Progressbar(left_col, mode="indeterminate")
        self._progress.pack(fill=tk.X, pady=(2, 0))

        # 日志面板
        log_frame = ttk.Frame(left_col, height=LOG_MIN_HEIGHT)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(PAD_INNER, 0))
        self._log_panel = LogPanel(log_frame)
        self._log_panel.pack(fill=tk.BOTH, expand=True)

        # 右列: 报文预览
        self._preview = PacketPreview(right_paned,
                                      lambda: self._form.format_preview())
        right_paned.add(self._preview, weight=0)

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

    # ------------------------------------------------------------------
    # 事件处理
    # ------------------------------------------------------------------

    def _on_attack_select(self, attack_name: str):
        self._current_attack = attack_name
        label = ATTACK_LABELS.get(attack_name, attack_name)
        self._form.set_attack(attack_name)
        self._preview.refresh()
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
