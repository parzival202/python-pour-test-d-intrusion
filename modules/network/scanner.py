"""
modules/network/scanner.py
Scanner réseau corrigé (MVP) — sûr et robuste.

Fonctionnalités :
- discover_hosts(range_or_ip, timeout, threads): découverte utilisant TCP connect sur le port 80 (heuristique)
- scan_ports(ip, ports, timeout, threads): scan TCP connect parallèle
- run_nmap(ip, args): wrapper pour appeler le binaire nmap si installé (optionnel)
- scan_target(target, threads, timeout, nmap_args): orchestration qui retourne un dictionnaire structuré JSON-like

Notes :
- Toutes les sockets sont fermées dans les blocs finally pour éviter ResourceWarning.
- Ce module n'importe PAS le package 'tp_sources'.
- Conçu pour être portable et sûr pour les tests en lab/VM.
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
    """Fermer en toute sécurité une socket."""
    try:
        if sock:
            sock.close()
    except Exception:
        # ignorer les erreurs de fermeture
        pass


def is_host_alive(ip: str, port: int = 80, timeout: float = 1.0) -> bool:
    """
    Vérification heuristique de l'hôte 'vivant' en tentant une connexion TCP à ip:port (port par défaut 80).
    Retourne True si la connexion réussit, False sinon. Assure que la socket est toujours fermée.
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
    Vérifier si le port TCP est ouvert en tentant de se connecter. Retourne True si la connexion réussit.
    Assure que la socket est toujours fermée.
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
    Découvrir les hôtes vivants dans une plage ou une IP unique.
    Prend en charge la notation CIDR, les plages IP et les IPs uniques.
    Amélioré avec l'analyse d'adresse IP appropriée et les limites de sécurité.
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
    Scanner les ports spécifiés sur une IP en utilisant TCP connect. Retourne un dictionnaire {port: is_open}.
    Si ports est None, utilise DEFAULT_PORTS.
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
    Exécuter nmap sur l'IP cible avec les arguments spécifiés.
    Amélioré avec un timeout configurable et une meilleure gestion d'erreur.
    Retourne la sortie brute nmap ou None si échoué.
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
    Orchestration de haut niveau :
      - découvrir les hôtes dans 'target' (IP ou /24)
      - pour chaque hôte, exécuter le scan de ports
      - optionnellement appeler nmap pour des infos plus profondes (si nmap_args fourni et nmap existe)
    Retourne un dictionnaire avec les clés : target, hosts_alive, hosts_info, nmap_raw, meta
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


# Utilitaire CLI de test
if __name__ == "__main__":
    import argparse
    import json

    p = argparse.ArgumentParser(prog="scanner", description="Scanner réseau simple CLI (MVP)")
    p.add_argument("--target", required=True, help="IP ou CIDR (ex. 192.168.1.0/24)")
    p.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    p.add_argument("--nmap", dest="nmap_args", default=None, help="passer les args à nmap (optionnel)")
    p.add_argument("--probe-port", dest="probe_port", type=int, default=80, help="port utilisé pour l'heuristique de découverte d'hôte (par défaut 80)")
    args = p.parse_args()

    out = scan_target(args.target, threads=args.threads, timeout=args.timeout, nmap_args=args.nmap_args, probe_port=args.probe_port)
    print(json.dumps(out, indent=2))
