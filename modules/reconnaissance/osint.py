"""
modules/reconnaissance/osint.py
Comprehensive OSINT helpers (safe, non-intrusive).
- basic_host_info(ip_or_host): DNS reverse + simple socket probe
- dns_enumeration(domain): Full DNS enumeration (A, AAAA, MX, NS, TXT, CNAME)
- whois_lookup(domain): Integrated WHOIS lookup
- probe_subdomains(domain, words=[...]): Enhanced subdomain discovery
"""

import socket
import subprocess
from pathlib import Path
import json
import time
import dns.resolver
import dns.exception
from typing import List, Dict, Optional

def basic_host_info(target: str) -> Dict:
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

def dns_enumeration(domain: str) -> Dict:
    """
    Perform comprehensive DNS enumeration.
    Returns dict with A, AAAA, MX, NS, TXT, CNAME records.
    """
    results = {"domain": domain}

    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            records = []
            for rdata in answers:
                if rtype == 'MX':
                    records.append(f"{rdata.preference} {rdata.exchange}")
                elif rtype == 'TXT':
                    records.append(str(rdata))
                else:
                    records.append(str(rdata))
            results[rtype.lower()] = records
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            results[rtype.lower()] = []
        except Exception:
            results[rtype.lower()] = []

    return results

def whois_lookup(domain: str) -> Optional[Dict]:
    """
    Integrated WHOIS lookup: tries python-whois first, then system whois.
    Returns structured dict or None if unavailable.
    """
    # try python-whois first
    try:
        import whois as _pywhois
        w = _pywhois.whois(domain)
        if w:
            return {
                "domain": w.domain_name,
                "registrar": w.registrar,
                "creation_date": str(w.creation_date) if w.creation_date else None,
                "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                "name_servers": w.name_servers,
                "emails": w.emails,
                "raw": str(w)
            }
    except Exception:
        pass

    # fallback to system whois
    try:
        out = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=15)
        if out.returncode == 0:
            return {"raw": out.stdout, "source": "system_whois"}
    except Exception:
        pass

    return None

def probe_subdomains(domain: str, words: Optional[List[str]] = None, timeout: float = 0.8) -> List[Dict]:
    """
    Enhanced subdomain discovery with DNS resolution.
    words: list of prefixes to try (defaults to common ones).
    Returns list of discovered subdomains with IPs and record types.
    """
    if words is None:
        # expanded default list
        words = ["www", "mail", "ftp", "admin", "test", "dev", "beta", "staging", "api", "app",
                 "secure", "vpn", "remote", "portal", "webmail", "mx", "ns", "dns"]

    results = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout

    for prefix in words:
        fqdn = f"{prefix}.{domain}"
        try:
            # Try A record first
            answers = resolver.resolve(fqdn, 'A')
            for rdata in answers:
                results.append({
                    "subdomain": fqdn,
                    "ip": str(rdata),
                    "record_type": "A",
                    "prefix": prefix
                })
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            # Try CNAME
            try:
                answers = resolver.resolve(fqdn, 'CNAME')
                for rdata in answers:
                    results.append({
                        "subdomain": fqdn,
                        "target": str(rdata.target),
                        "record_type": "CNAME",
                        "prefix": prefix
                    })
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass  # not found
        except Exception:
            pass  # timeout or other error

    return results

def comprehensive_osint(target: str) -> Dict:
    """
    Run comprehensive OSINT gathering on target.
    Includes DNS enumeration, WHOIS, subdomain probing, and basic host info.
    """
    results = {"target": target, "timestamp": time.time()}

    # Basic host info
    results["host_info"] = basic_host_info(target)

    # DNS enumeration if target looks like a domain
    if '.' in target and not target.replace('.', '').isdigit():
        results["dns"] = dns_enumeration(target)
        results["whois"] = whois_lookup(target)
        results["subdomains"] = probe_subdomains(target)
    else:
        results["dns"] = None
        results["whois"] = None
        results["subdomains"] = []

    return results

def save_json(path: str, data: Dict) -> str:
    """Save data to JSON file with timestamp."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    return str(Path(path).resolve())
