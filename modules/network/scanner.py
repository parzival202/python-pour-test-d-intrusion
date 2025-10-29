"""
modules/network/scanner.py
Patched network scanner (MVP) — safe and robust.

Features:
- discover_hosts(range_or_ip, timeout, threads): discovery using TCP connect on port 80 (heuristic)
- scan_ports(ip, ports, timeout, threads): parallel TCP connect scan
- run_nmap(ip, args): wrapper to call nmap binary if installed (optional)
- scan_target(target, threads, timeout, nmap_args): orchestration that returns structured JSON-like dict

Notes:
- All sockets are closed in finally blocks to avoid ResourceWarning.
- This module does NOT import any 'tp_sources' package.
- Designed to be portable and safe for lab/VM testing.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import subprocess
import time
import logging
from typing import List, Dict, Optional

DEFAULT_THREADS = 20
DEFAULT_TIMEOUT = 2.0
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389]

logger = logging.getLogger(__name__)
if not logger.handlers:
    # basic config if not already configured by project
    logging.basicConfig(format="%(asctime)s %(levelname)s %(name)s: %(message)s", level=logging.INFO)


def _safe_close(sock: Optional[socket.socket]) -> None:
    try:
        if sock:
            sock.close()
    except Exception:
        # ignore close errors
        pass


def is_host_alive(ip: str, port: int = 80, timeout: float = 1.0) -> bool:
    """
    Heuristic host 'alive' check by attempting a TCP connect to ip:port (default port 80).
    Returns True if connect succeeds, False otherwise. Ensures socket is always closed.
    """
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        return True
    except Exception:
        return False
    finally:
        _safe_close(s)


def tcp_connect_check(ip: str, port: int, timeout: float = 1.0) -> bool:
    """
    Check if TCP port is open by attempting to connect. Returns True if connect succeeds.
    Ensures socket is always closed.
    """
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, int(port)))
        return True
    except Exception:
        return False
    finally:
        _safe_close(s)


def discover_hosts(range_or_ip: str, timeout: float = 0.8, threads: int = DEFAULT_THREADS, probe_port: int = 80) -> List[str]:
    """
    Discover alive hosts in a range or single IP.
    Supports CIDR notation, IP ranges, and single IPs.
    Enhanced with proper IP address parsing and safety limits.
    """
    try:
        # Parse target - could be IP, CIDR, or range
        if '/' in range_or_ip:
            # CIDR notation
            import ipaddress
            network = ipaddress.ip_network(range_or_ip, strict=False)
            candidates = [str(ip) for ip in network.hosts()]
        elif '-' in range_or_ip:
            # IP range (e.g., 192.168.1.1-192.168.1.10)
            start_ip, end_ip = range_or_ip.split('-')
            import ipaddress
            start = ipaddress.ip_address(start_ip.strip())
            end = ipaddress.ip_address(end_ip.strip())
            candidates = [str(ipaddress.ip_address(int(start) + i)) for i in range(int(end) - int(start) + 1)]
        else:
            # Single IP
            candidates = [range_or_ip]

        # Limit to reasonable size to prevent abuse
        if len(candidates) > 1024:
            logger.warning("Target range too large (%d hosts), limiting to 1024", len(candidates))
            candidates = candidates[:1024]

        alive: List[str] = []
        logger.debug("discover_hosts: scanning %d candidates with %d threads", len(candidates), threads)
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(is_host_alive, ip, probe_port, timeout): ip for ip in candidates}
            for fut in as_completed(futures):
                ip = futures[fut]
                try:
                    if fut.result():
                        alive.append(ip)
                except Exception:
                    # ignore individual errors
                    logger.debug("discover_hosts: error probing %s", ip)
                    pass
        return sorted(alive)

    except Exception as e:
        logger.error("Error in discover_hosts: %s", e)
        return []


def scan_ports(ip: str, ports: Optional[List[int]] = None, timeout: float = 1.0, threads: int = DEFAULT_THREADS) -> Dict[int, bool]:
    """
    Scan specified ports on an IP using TCP connect. Returns dict {port: is_open}.
    If ports is None, uses DEFAULT_PORTS.
    """
    if ports is None:
        ports = DEFAULT_PORTS
    results: Dict[int, bool] = {}
    logger.debug("scan_ports: scanning %s ports=%s", ip, ports)
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(tcp_connect_check, ip, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            p = futures[fut]
            try:
                results[p] = bool(fut.result())
            except Exception:
                results[p] = False
    return results


def run_nmap(ip: str, args: str = "-sV -O -Pn", timeout: int = 300) -> Optional[str]:
    """
    Run nmap on target IP with specified arguments.
    Enhanced with configurable timeout and better error handling.
    Returns raw nmap output or None if failed.
    """
    try:
        cmd = ["nmap"] + args.split() + [str(ip)]
        logger.info("Running nmap: %s", " ".join(cmd))
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if proc.returncode == 0:
            return proc.stdout
        else:
            logger.warning("nmap failed for %s: %s", ip, proc.stderr)
            return None
    except FileNotFoundError:
        logger.debug("run_nmap: nmap binary not found")
        return None
    except subprocess.TimeoutExpired:
        logger.warning("nmap timed out for %s", ip)
        return None
    except Exception as e:
        logger.debug("run_nmap: exception %s", e)
        return None


def scan_target(target: str, threads: int = DEFAULT_THREADS, timeout: float = DEFAULT_TIMEOUT, nmap_args: Optional[str] = None, probe_port: int = 80) -> Dict:
    """
    High-level orchestration:
      - discover hosts in 'target' (IP or /24)
      - for each host, run port scan
      - optionally call nmap for deeper info (if nmap_args provided and nmap exists)
    Returns a dict with keys: target, hosts_alive, hosts_info, nmap_raw, meta
    """
    start = time.time()
    logger.info("scan_target: starting scan target=%s threads=%s timeout=%s", target, threads, timeout)

    hosts = discover_hosts(target, timeout=timeout, threads=threads, probe_port=probe_port)
    hosts_info: Dict[str, Dict] = {}
    for h in hosts:
        ports_result = scan_ports(h, timeout=timeout, threads=threads)
        hosts_info[h] = {"ports": ports_result}

    nmap_raw: Dict[str, Optional[str]] = {}
    if nmap_args:
        # attempt nmap for each host
        for h in hosts:
            out = run_nmap(h, args=nmap_args)
            nmap_raw[h] = out

    total_time = time.time() - start
    result = {
        "target": target,
        "hosts_alive": hosts,
        "hosts_info": hosts_info,
        "nmap_raw": nmap_raw,
        "meta": {"duration_s": round(total_time, 2), "threads": threads, "timeout": timeout}
    }
    logger.info("scan_target: finished target=%s hosts_found=%d duration=%.2fs", target, len(hosts), total_time)
    return result


# CLI test utility
if __name__ == "__main__":
    import argparse
    import json

    p = argparse.ArgumentParser(prog="scanner", description="Simple network scanner CLI (MVP)")
    p.add_argument("--target", required=True, help="IP or CIDR (e.g. 192.168.1.0/24)")
    p.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    p.add_argument("--nmap", dest="nmap_args", default=None, help="pass args to nmap (optional)")
    p.add_argument("--probe-port", dest="probe_port", type=int, default=80, help="port used for host discovery heuristic (default 80)")
    args = p.parse_args()

    out = scan_target(args.target, threads=args.threads, timeout=args.timeout, nmap_args=args.nmap_args, probe_port=args.probe_port)
    print(json.dumps(out, indent=2))
