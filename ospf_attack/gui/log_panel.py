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
        self._after_id: str | None = None

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
            self._after_id = self.after(100, self._poll)

    _MAX_LINES = 10000

    def _append(self, level: str, message: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{timestamp}] {message}\n"
        tag = level if level in LOG_TAGS else "INFO"
        self._text.insert(tk.END, line, tag)
        # Trim oldest lines to prevent unbounded memory growth
        line_count = int(self._text.index("end-1c").split(".", 1)[0])
        if line_count > self._MAX_LINES:
            self._text.delete("1.0", f"{line_count - self._MAX_LINES}.0")
        self._text.see(tk.END)

    def _flush(self):
        """暴露给测试：直接刷新队列。"""
        self._poll()

    def destroy(self):
        self._running = False
        if self._after_id is not None:
            self.after_cancel(self._after_id)
        super().destroy()
