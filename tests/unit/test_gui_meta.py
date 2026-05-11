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


from ospf_attack.gui.attack_tree import AttackTree


def test_attack_tree_populates_all_12_attacks():
    root = tk.Tk()
    tree = AttackTree(root)
    tree.pack()
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
    for cat in tree.tree.get_children():
        leaves = tree.tree.get_children(cat)
        if leaves:
            first_leaf = leaves[0]
            tree.tree.selection_set(first_leaf)
            tree.tree.event_generate("<<TreeviewSelect>>")
            break
    assert len(called) == 1
    root.destroy()
