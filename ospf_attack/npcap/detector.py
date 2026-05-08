import sys
import os


def is_npcap_installed() -> bool:
    if sys.platform != "win32":
        try:
            import pcap
            return True
        except ImportError:
            return False
    try:
        import winreg
        for path in [r"SOFTWARE\WOW6432Node\Npcap", r"SOFTWARE\Npcap"]:
            try:
                winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
                return True
            except OSError:
                continue
    except ImportError:
        pass
    try:
        import pcap
        pcap.findalldevs()
        return True
    except Exception:
        pass
    return False


def check_npcap() -> bool:
    if is_npcap_installed():
        return True
    print("检测到系统中未安装 Npcap，嗅探功能不可用。")
    print("是否安装 Npcap？(Y/n)")
    try:
        answer = input().strip().lower()
        if answer in ("", "y", "yes"):
            from ospf_attack.npcap.installer import install_npcap
            return install_npcap()
    except (EOFError, KeyboardInterrupt):
        pass
    print("将以降级模式运行：发包攻击可用，嗅探功能不可用。")
    return False
