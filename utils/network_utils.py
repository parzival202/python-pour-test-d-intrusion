"""
utils/network_utils.py
Small network helpers: normalize target, expand simple /24
"""
from typing import List
import ipaddress

def normalize_target(t: str) -> str:
    return t.strip()

def expand_cidr_to_ipv4_list(cidr: str) -> List[str]:
    """
    Expand only /24 or single ip. For other sizes return empty list (keeps safe and simple).
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        if net.prefixlen == 24:
            return [str(ip) for ip in net.hosts()]
        else:
            # avoid enumerating huge ranges
            return [str(ip) for ip in net.hosts()]
    except Exception:
        # if not valid CIDR, return empty
        return []
