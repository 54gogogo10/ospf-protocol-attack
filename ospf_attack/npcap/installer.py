import os
import sys
import subprocess

_INSTALLER_NAME = "npcap-installer.exe"


def _get_installer_path() -> str:
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
        return os.path.join(base, _INSTALLER_NAME)
    return os.path.join(os.path.dirname(__file__), "..", "..", "assets", _INSTALLER_NAME)


def install_npcap() -> bool:
    installer = _get_installer_path()
    if not os.path.exists(installer):
        print(f"Npcap 安装程序未找到: {installer}")
        return False
    print("正在启动 Npcap 安装程序...")
    try:
        result = subprocess.run([installer], timeout=300)
        if result.returncode == 0:
            print("Npcap 安装成功！")
            return True
        else:
            print(f"Npcap 安装失败 (exit code: {result.returncode})")
            return False
    except subprocess.TimeoutExpired:
        print("Npcap 安装超时")
        return False
    except Exception as e:
        print(f"Npcap 安装出错: {e}")
        return False
