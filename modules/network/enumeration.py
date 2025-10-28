"""
modules/network/enumeration.py
Wrapper that will orchestrate host discovery and helper utilities.
For now this file exposes the function discover_and_list which calls
the scanner adapter (modules.network.scanner.discover_hosts) or fallback.
"""
from modules.network.scanner import discover_hosts

def discover_and_list(target_range, threads=20, timeout=1.0):
    """
    Returns list of alive hosts for the given range or IP.
    """
    return discover_hosts(target_range, timeout=timeout, threads=threads)
