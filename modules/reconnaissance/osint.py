"""
modules/reconnaissance/osint.py
Minimal OSINT helpers (safe, non-intrusive).
- basic_host_info(ip_or_host): DNS reverse + simple socket probe
- whois_lookup(domain): uses python-whois if present (optional)
- probe_subdomains(domain, words=[...]) : small brute-force probe using A record lookup
"""

import socket
import subprocess
from pathlib import Path
import json
import time

def basic_host_info(target):
    """
    Return dict with basic resolution info for target (ip or hostname).
    Non-intrusive: uses socket.gethostbyname and reverse lookup.
    """
    info = {"target": target}
    try:
        ip = socket.gethostbyname(target)
        info["ip"] = ip
        try:
            rev = socket.gethostbyaddr(ip)
            info["reverse"] = rev[0]
        except Exception:
            info["reverse"] = None
    except Exception:
        info["ip"] = None
        info["reverse"] = None
    # quick TCP probe for port 80 to check basic reachability
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.6)
        s.connect((info["ip"], 80))
        s.close()
        info["port80"] = True
    except Exception:
        info["port80"] = False
    return info

def whois_lookup(domain):
    """
    Optional whois lookup: tries to use 'whois' binary or python-whois if available.
    Returns dict or None if unavailable.
    """
    # try python-whois
    try:
        import whois as _pywhois
        return _pywhois.whois(domain)
    except Exception:
        pass
    # try system whois
    try:
        out = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=10)
        return {"raw": out.stdout}
    except Exception:
        return None

def probe_subdomains(domain, words=None, timeout=0.8):
    """
    Small, non-aggressive subdomain probe.
    words: list of strings to prefix to domain (['www','test','dev']).
    Returns list of discovered subdomains with resolved IP.
    """
    if words is None:
        # tiny default list -> safe and quick
        words = ["www", "mail", "dev", "test", "beta"]
    results = []
    for w in words:
        fqdn = f"{w}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            results.append({"subdomain": fqdn, "ip": ip})
        except Exception:
            # not found -> ignore
            pass
    return results

def save_json(path, data):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
