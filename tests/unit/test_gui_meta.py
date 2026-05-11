"""Tests for GUI metadata and logic — no Tk interaction needed for most."""

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
