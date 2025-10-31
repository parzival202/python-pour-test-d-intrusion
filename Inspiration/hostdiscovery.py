#!/usr/bin/env python3
"""
Module de découverte d’hôtes réseau
Inclut ARP scanning, ICMP sweeps et découverte TCP/UDP.
"""

import socket
import struct
import subprocess
import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# Import de Scapy si disponible
try:
    from scapy.all import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[-] Scapy non disponible - fonctionnalités limitées")

# Import structure externe
from network_structures import Host


class HostDiscovery:
    """Classe pour la découverte d’hôtes sur le réseau"""

    def __init__(self, max_threads=50, timeout=3):
        self.max_threads = max_threads
        self.timeout = timeout
        self.discovered_hosts = {}
        self.discovery_stats = {
            'total_ips_scanned': 0,
            'hosts_discovered': 0,
            'arp_responses': 0,
            'icmp_responses': 0,
            'tcp_responses': 0,
            'udp_responses': 0
        }
        self.lock = threading.Lock()

    def arp_discovery(self, network):
        """Découverte d’hôtes via ARP scanning"""
        if not SCAPY_AVAILABLE:
            print("[-] ARP discovery nécessite Scapy")
            return []

        print(f"[*] ARP discovery sur le réseau {network}")

        try:
            # Création de la requête ARP broadcast
            arp_request = ARP(pdst=str(network))
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request

            # Envoi et réception avec timeout
            answered_list = srp(arp_request_broadcast, timeout=self.timeout, verbose=False)[0]

            discovered_hosts = []

            for element in answered_list:
                ip = element[1].psrc
                mac = element[1].hwsrc

                # Tentative de résolution DNS inverse
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    hostname = ""

                host = Host(
                    ip=ip,
                    hostname=hostname,
                    os_guess="",
                    open_ports=[],
                    filtered_ports=[],
                    closed_ports=[],
                    response_time=0,
                    last_seen=time.time()
                )

                discovered_hosts.append(host)
                self.discovered_hosts[ip] = {
                    'mac': mac,
                    'hostname': hostname,
                    'discovery_method': 'ARP',
                    'first_seen': time.time()
                }

                print(f"[+] Host discovered via ARP : {ip} ({mac}) - {hostname}")

                with self.lock:
                    self.discovery_stats['hosts_discovered'] += 1
                    self.discovery_stats['arp_responses'] += 1

            return discovered_hosts

        except Exception as e:
            print(f"[-] Erreur ARP discovery : {e}")
            return []

    def icmp_sweep(self, network):
        """ICMP ping sweep sur un réseau"""
        print(f"[*] ICMP sweep sur le réseau {network}")

        network_obj = ipaddress.IPv4Network(network, strict=False)
        hosts = list(network_obj.hosts())
        discovered_hosts = []

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self.icmp_ping, str(ip)): ip for ip in hosts}

            for future in as_completed(futures):
                ip = futures[future]
                try:
                    result = future.result()
                    if result:
                        discovered_hosts.append(result)
                        print(f"[+] Host discovered via ICMP : {result.ip} - {result.hostname}")

                    with self.lock:
                        self.discovery_stats['total_ips_scanned'] += 1
                except Exception:
                    pass

        return discovered_hosts

    def icmp_ping(self, target_ip):
        """Ping ICMP vers une IP spécifique"""
        start_time = time.time()

        # Méthode 1 : utilisation de Scapy si disponible
        if SCAPY_AVAILABLE:
            try:
                icmp_packet = IP(dst=target_ip) / ICMP()
                response = sr1(icmp_packet, timeout=self.timeout, verbose=0)

                if response and response.haslayer(ICMP):
                    icmp_layer = response.getlayer(ICMP)
                    if icmp_layer.type == 0:  # Echo Reply
                        response_time = (time.time() - start_time) * 1000

                        try:
                            hostname = socket.gethostbyaddr(target_ip)[0]
                        except:
                            hostname = ""

                        host = Host(
                            ip=target_ip,
                            hostname=hostname,
                            os_guess="",
                            open_ports=[],
                            filtered_ports=[],
                            closed_ports=[],
                            response_time=response_time,
                            last_seen=time.time()
                        )

                        self.discovered_hosts[target_ip] = {
                            'hostname': hostname,
                            'discovery_method': 'ICMP',
                            'response_time': response_time,
                            'first_seen': time.time()
                        }

                        with self.lock:
                            self.discovery_stats['hosts_discovered'] += 1
                            self.discovery_stats['icmp_responses'] += 1

                        return host
            except Exception:
                pass

        # Méthode 2 : fallback avec ping système
        return self.system_ping(target_ip)

    def system_ping(self, target_ip):
        """Ping système (fallback si Scapy indisponible)"""
        try:
            import platform
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", str(self.timeout * 1000), target_ip]
            else:
                cmd = ["ping", "-c", "1", "-W", str(self.timeout), target_ip]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)

            if result.returncode == 0:
                output = result.stdout
                response_time = 0
                if "time=" in output:
                    import re
                    time_match = re.search(r'time[=<]([0-9.]+)', output)
                    if time_match:
                        response_time = float(time_match.group(1))

                try:
                    hostname = socket.gethostbyaddr(target_ip)[0]
                except:
                    hostname = ""

                host = Host(
                    ip=target_ip,
                    hostname=hostname,
                    os_guess="",
                    open_ports=[],
                    filtered_ports=[],
                    closed_ports=[],
                    response_time=response_time,
                    last_seen=time.time()
                )

                self.discovered_hosts[target_ip] = {
                    'hostname': hostname,
                    'discovery_method': 'System_Ping',
                    'response_time': response_time,
                    'first_seen': time.time()
                }

                with self.lock:
                    self.discovery_stats['hosts_discovered'] += 1
                    self.discovery_stats['icmp_responses'] += 1

                return host
        except Exception:
            pass

        return None
