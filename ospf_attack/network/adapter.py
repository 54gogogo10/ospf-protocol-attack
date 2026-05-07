import uuid


def get_local_mac(iface: str) -> str:
    try:
        import netifaces
        addrs = netifaces.ifaddresses(iface)
        link = addrs.get(netifaces.AF_LINK)
        if link:
            return link[0]["addr"]
    except ImportError:
        pass
    node = uuid.getnode()
    return ":".join(f"{(node >> (i * 8)) & 0xFF:02x}" for i in reversed(range(6)))


def get_local_ip(iface: str) -> str:
    try:
        import netifaces
        addrs = netifaces.ifaddresses(iface)
        inet = addrs.get(netifaces.AF_INET)
        if inet:
            return inet[0]["addr"]
    except ImportError:
        pass
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()
