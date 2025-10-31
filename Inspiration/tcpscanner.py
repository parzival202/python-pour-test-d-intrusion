#!/usr/bin/env python3
"""
Scanner TCP multithread avancé avec support de multiples techniques.
Intégration Scapy pour SYN scan et manipulation de paquets.
"""

import socket
import threading
import time
import random
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# Import conditionnel de Scapy
try:
    from scapy.all import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[-] Scapy non disponible - SYN scan désactivé")

# Structures externes (à définir ailleurs ou remplacer)
from network_structures import NetworkScanner, PortScanResult


class TCPScanner:
    """Scanner TCP avancé avec multiples techniques"""

    def __init__(self, max_threads=100, timeout=3):
        self.max_threads = max_threads
        self.timeout = timeout
        self.results = defaultdict(list)
        self.scan_stats = {
            'total_scanned': 0,
            'open_ports': 0,
            'closed_ports': 0,
            'filtered_ports': 0,
            'errors': 0
        }

        # Signatures de services pour la détection de bannière
        self.service_signatures = {
            21: {"name": "FTP", "banner_keywords": ["220", "FTP"]},
            22: {"name": "SSH", "banner_keywords": ["SSH-", "OpenSSH"]},
            23: {"name": "Telnet", "banner_keywords": ["login:", "Password:"]},
            25: {"name": "SMTP", "banner_keywords": ["220", "SMTP", "mail"]},
            53: {"name": "DNS", "banner_keywords": []},
            80: {"name": "HTTP", "banner_keywords": ["HTTP/", "Server:"]},
            110: {"name": "POP3", "banner_keywords": ["+OK", "POP3"]},
            143: {"name": "IMAP", "banner_keywords": ["* OK", "IMAP"]},
            443: {"name": "HTTPS", "banner_keywords": []},
            993: {"name": "IMAPS", "banner_keywords": []},
            995: {"name": "POP3S", "banner_keywords": []},
            3306: {"name": "MySQL", "banner_keywords": ["mysql", "MariaDB"]},
            3389: {"name": "RDP", "banner_keywords": []},
            5432: {"name": "PostgreSQL", "banner_keywords": ["postgres"]},
            6379: {"name": "Redis", "banner_keywords": ["REDIS"]}
        }

        # Configuration d’évasion
        self.evasion_config = {
            'source_port_randomization': False,
            'ip_fragmentation': False,
            'timing_randomization': False,
            'decoy_scanning': False,
            'custom_user_agent': True
        }

        self.lock = threading.Lock()

    def tcp_connect_scan(self, target, port):
        """Scan TCP Connect standard"""
        start_time = time.time()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            # Randomisation du port source si activée
            if self.evasion_config['source_port_randomization']:
                source_port = random.randint(1024, 65535)
                sock.bind(('', source_port))

            result = sock.connect_ex((target, port))
            response_time = (time.time() - start_time) * 1000

            if result == 0:
                banner = self.grab_banner(sock, port)
                service_info = self.identify_service(port, banner)

                scan_result = PortScanResult(
                    port=port,
                    protocol='tcp',
                    state='open',
                    service=service_info['name'],
                    version=service_info.get('version', ''),
                    banner=banner,
                    response_time=response_time,
                    scan_technique='tcp_connect'
                )

                with self.lock:
                    self.results[target].append(scan_result)
                    self.scan_stats['open_ports'] += 1

                return scan_result

            else:
                with self.lock:
                    self.scan_stats['closed_ports'] += 1
                return PortScanResult(
                    port=port,
                    protocol='tcp',
                    state='closed',
                    service='',
                    version='',
                    banner='',
                    response_time=response_time,
                    scan_technique='tcp_connect'
                )

        except socket.timeout:
            with self.lock:
                self.scan_stats['filtered_ports'] += 1
            return PortScanResult(
                port=port,
                protocol='tcp',
                state='filtered',
                service='',
                version='',
                banner='',
                response_time=self.timeout * 1000,
                scan_technique='tcp_connect'
            )

        except Exception as e:
            with self.lock:
                self.scan_stats['errors'] += 1
            return None

        finally:
            try:
                sock.close()
            except:
                pass

    def syn_scan(self, target, port):
        """Scan SYN utilisant Scapy (nécessite root)"""
        if not SCAPY_AVAILABLE:
            print("[-] Scapy requis pour SYN scan")
            return None

        start_time = time.time()

        try:
            src_port = random.randint(1024, 65535) if self.evasion_config['source_port_randomization'] else 54321
            syn_packet = IP(dst=target) / TCP(sport=src_port, dport=port, flags="S")

            response = sr1(syn_packet, timeout=self.timeout, verbose=0)
            response_time = (time.time() - start_time) * 1000

            if response:
                if response.haslayer(TCP):
                    tcp_layer = response.getlayer(TCP)

                    if tcp_layer.flags == 18:  # SYN-ACK
                        rst_packet = IP(dst=target) / TCP(sport=src_port, dport=port, flags="R", seq=tcp_layer.ack)
                        send(rst_packet, verbose=0)

                        banner = self.grab_banner_connect(target, port)
                        service_info = self.identify_service(port, banner)

                        result = PortScanResult(
                            port=port,
                            protocol='tcp',
                            state='open',
                            service=service_info['name'],
                            version=service_info.get('version', ''),
                            banner=banner,
                            response_time=response_time,
                            scan_technique='syn_scan'
                        )

                        with self.lock:
                            self.results[target].append(result)
                            self.scan_stats['open_ports'] += 1

                        return result

                    elif tcp_layer.flags == 4:  # RST
                        with self.lock:
                            self.scan_stats['closed_ports'] += 1
                        return PortScanResult(port=port, protocol='tcp', state='closed')

            with self.lock:
                self.scan_stats['filtered_ports'] += 1
            return PortScanResult(port=port, protocol='tcp', state='filtered')

        except Exception as e:
            with self.lock:
                self.scan_stats['errors'] += 1
            return None

    # --- (les autres fonctions grab_banner, identify_service, scan_common_ports, etc.)
