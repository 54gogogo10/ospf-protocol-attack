"""OSPF 攻击模拟器 GUI 入口 — python -m ospf_attack 启动操作面板。"""
import warnings
warnings.filterwarnings("ignore", message=".*'iface' has no effect on L3 I/O.*")

from ospf_attack.gui import launch_gui

if __name__ == "__main__":
    launch_gui()
