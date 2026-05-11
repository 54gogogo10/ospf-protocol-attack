"""OSPF Attack GUI — Tkinter 操作面板。"""

def launch_gui():
    """启动 GUI 主窗口。"""
    from .app import MainWindow
    app = MainWindow()
    app.run()
