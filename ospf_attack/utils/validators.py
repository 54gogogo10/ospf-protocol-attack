import ipaddress


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_router_id(rid: str) -> bool:
    if not is_valid_ip(rid):
        return False
    addr = ipaddress.ip_address(rid)
    return not addr.is_multicast
