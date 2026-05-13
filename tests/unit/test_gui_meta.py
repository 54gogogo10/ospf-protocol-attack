"""Tests for GUI metadata and logic — no Tk interaction needed for most."""

import queue
import tkinter as tk
import pytest

from ospf_attack.gui.log_panel import LogPanel


@pytest.fixture
def tk_root():
    """Create a Tk root, skipping if Tcl/Tk not available in this environment."""
    try:
        root = tk.Tk()
        yield root
        try:
            root.destroy()
        except Exception:
            pass
    except tk.TclError:
        pytest.skip("Tk not available in this environment")


def test_log_panel_creates_widgets(tk_root):
    panel = LogPanel(tk_root)
    assert panel._text is not None
    assert isinstance(panel._queue, queue.Queue)


def test_log_panel_write_adds_to_queue(tk_root):
    panel = LogPanel(tk_root)
    panel.write("INFO", "test message")
    entry = panel._queue.get_nowait()
    assert entry == ("INFO", "test message")


def test_log_panel_flush_updates_text(tk_root):
    panel = LogPanel(tk_root)
    panel._queue.put(("INFO", "line1"))
    panel._queue.put(("WARN", "line2"))
    panel._flush()
    content = panel._text.get("1.0", "end-1c")
    assert "line1" in content
    assert "line2" in content


from ospf_attack.gui.attack_tree import AttackTree


def test_attack_tree_populates_all_12_attacks(tk_root):
    tree = AttackTree(tk_root)
    tree.pack()
    children = tree.tree.get_children()
    assert len(children) == 4  # 4 category nodes
    total_leaves = sum(
        len(tree.tree.get_children(cat)) for cat in children
    )
    assert total_leaves == 12


def test_attack_tree_get_selected_returns_none_initially(tk_root):
    tree = AttackTree(tk_root)
    assert tree.get_selected() is None


def test_attack_tree_has_callback(tk_root):
    tree = AttackTree(tk_root)
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


from ospf_attack.gui.config_form import (
    FIELD_META, COMMON_FIELDS, SPECIFIC_FIELDS,
    get_widget_type, build_config_dict,
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
    assert get_widget_type("target") == "entry"


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


class FakeVar:
    def __init__(self, value):
        self._value = value
    def get(self):
        return self._value


def test_build_config_dict_collects_field_values():
    """从虚拟 widget 字典收集配置参数"""
    widgets = {
        "iface": FakeVar("eth0"),
        "target": FakeVar("10.0.0.1"),
        "hello_interval": FakeVar("30"),
        "router_priority": FakeVar("200"),
    }
    meta = {
        "iface": {"widget": "entry"},
        "target": {"widget": "entry"},
        "hello_interval": {"widget": "spinbox"},
        "router_priority": {"widget": "spinbox"},
    }
    result = build_config_dict(widgets, meta)
    assert result["iface"] == "eth0"
    assert result["target"] == "10.0.0.1"
    assert result["hello_interval"] == 30
    assert result["router_priority"] == 200


import threading
from unittest.mock import MagicMock, patch
from ospf_attack.gui.runner import AttackRunner, _execute_attack


class TestAttackRunner:
    """Tests for AttackRunner — constructor and lifecycle only."""

    def test_constructor_stores_params(self):
        log_q = queue.Queue()
        stop_ev = threading.Event()
        runner = AttackRunner(
            "hello-inject",
            {"iface": "eth0", "target": "10.0.0.1"},
            stop_ev, log_q,
        )
        assert runner._attack_name == "hello-inject"
        assert runner._config_dict == {"iface": "eth0", "target": "10.0.0.1"}
        assert not runner.is_running

    def test_start_and_stop_lifecycle(self):
        log_q = queue.Queue()
        stop_ev = threading.Event()
        runner = AttackRunner("hello-inject", {"iface": "eth0"}, stop_ev, log_q)
        # Patch _execute_attack with a blocking function to simulate running attack
        def _fake_exec(name, cfg, sev, lq):
            sev.wait(timeout=5)
        with patch("ospf_attack.gui.runner._execute_attack", side_effect=_fake_exec):
            runner.start()
            assert runner.is_running
            runner.stop()
            assert stop_ev.is_set()
            runner.join(timeout=5)
            assert not runner.is_running


class TestExecuteAttack:
    """Tests for _execute_attack — log output and error handling."""

    def test_execute_attack_logs_initialization(self):
        log_q = queue.Queue()
        stop_ev = threading.Event()

        # Mock all the heavy dependencies
        fake_attack_cls = MagicMock()
        fake_attack = MagicMock()
        fake_attack.run.return_value = MagicMock(
            success=True, packets_sent=42,
            details="test OK",
        )
        fake_attack_cls.return_value = fake_attack

        with patch("ospf_attack.gui.runner.ATTACK_REGISTRY",
                   {"hello-inject": (fake_attack_cls, None)}):
            with patch("ospf_attack.gui.runner.build_config") as mock_build:
                mock_build.return_value = MagicMock()
                _execute_attack("hello-inject",
                               {"iface": "eth0", "target": "10.0.0.1"},
                               stop_ev, log_q)

        # Drain log queue
        entries = []
        while True:
            try:
                entries.append(log_q.get_nowait())
            except queue.Empty:
                break

        levels = [e[0] for e in entries]
        assert "SYSTEM" in levels
        assert "INFO" in levels

    def test_execute_attack_handles_error(self):
        log_q = queue.Queue()
        stop_ev = threading.Event()

        with patch("ospf_attack.gui.runner.ATTACK_REGISTRY",
                   {"bad-attack": (MagicMock(side_effect=KeyError("test error")), None)}):
            _execute_attack("bad-attack", {}, stop_ev, log_q)

        entries = []
        while True:
            try:
                entries.append(log_q.get_nowait())
            except queue.Empty:
                break

        levels = [e[0] for e in entries]
        assert "_ERROR_" in levels
