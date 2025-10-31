#!/usr/bin/env python3
"""
Scanner UDP avancé avec probes spécifiques et gestion ICMP
Détection de services UDP courants avec payloads dédiés
"""
import socket
import struct
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import random

try:
    from scapy.all import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from network_structures import PortScanResult


class UDPScanner:
    """Scanner UDP avancé avec probes spécifiques"""

    def __init__(self, max_threads=20, timeout=5):
        self.max_threads = max_threads
        self.timeout = timeout
        self.results = defaultdict(list)
        self.scan_stats = {
            'total_scanned': 0,
            'open_ports': 0,
            'open_filtered': 0,
            'closed_ports': 0,
            'errors': 0
        }

        # Probes UDP spécifiques par port
        self.udp_probes = {
            53: self.dns_probe,
            69: self.tftp_probe,
            123: self.ntp_probe,
            161: self.snmp_probe,
            162: self.snmp_trap_probe,
            500: self.ipsec_probe,
            514: self.syslog_probe,
            1900: self.upnp_probe,
            5353: self.mdns_probe
        }

        # Signatures de réponse pour identification
        self.service_signatures = {
            53: {"name": "DNS", "response_patterns": [b"\x81\x80", b"\x81\x83"]},
            69: {"name": "TFTP", "response_patterns": [b"\x00\x03", b"\x00\x05"]},
            123: {"name": "NTP", "response_patterns": [b"\x1c", b"\x24"]},
            161: {"name": "SNMP", "response_patterns": [b"\x30", b"public"]},
            500: {"name": "IPSec", "response_patterns": [b"\x00\x00\x00"]},
            514: {"name": "Syslog", "response_patterns": [b"<"]},
            1900: {"name": "UPnP", "response_patterns": [b"HTTP/", b"NOTIFY"]},
            5353: {"name": "mDNS", "response_patterns": [b"\x84\x00", b"\x81\x80"]}
        }

        self.lock = threading.Lock()

    def dns_probe(self):
        """Génère une probe DNS"""
        # Requête DNS pour "google.com" type A
        query = (
            b"\x12\x34"  # Transaction ID
            b"\x01\x00"  # Flags: standard query
            b"\x00\x01"  # Questions: 1
            b"\x00\x00"  # Answer RRs: 0
            b"\x00\x00"  # Authority RRs: 0
            b"\x00\x00"  # Additional RRs: 0
            b"\x06google\x03com\x00"  # Name
            b"\x00\x01"  # Type: A
            b"\x00\x01"  # Class: IN
        )
        return query

    def ntp_probe(self):
        """Génère une probe NTP"""
        return b"\x1b" + b"\x00" * 47  # NTP version 3, mode client

    def snmp_probe(self):
        """Génère une probe SNMP GetRequest"""
        snmp_packet = (
            b"\x30\x26"
            b"\x02\x01\x00"
            b"\x04\x06public"
            b"\xa0\x19"
            b"\x02\x04\x00\x00\x00\x01"
            b"\x02\x01\x00"
            b"\x02\x01\x00"
            b"\x30\x0b"
            b"\x30\x09"
            b"\x06\x05\x2b\x06\x01\x02\x01"
            b"\x05\x00"
        )
        return snmp_packet

    def tftp_probe(self):
        """Génère une probe TFTP Read Request"""
        tftp_packet = (
            b"\x00\x01"  # Opcode: RRQ
            b"test\x00"  # Filename
            b"octet\x00"  # Mode
        )
        return tftp_packet

    def snmp_trap_probe(self):
        """Génère une probe SNMP Trap"""
        return b"\x30\x82\x00\x27\x02\x01\x00\x04\x06public"

    def ipsec_probe(self):
        """Génère une probe IPSec ISAKMP"""
        return b"\x00" * 16

    def syslog_probe(self):
        """Génère une probe Syslog"""
        return b"<30>Test syslog message"

    def upnp_probe(self):
        """Génère une probe UPnP SSDP"""
        upnp_packet = (
            b"M-SEARCH * HTTP/1.1\r\n"
            b"HOST:239.255.255.250:1900\r\n"
            b"MAN:\"ssdp:discover\"\r\n"
            b"ST:upnp:rootdevice\r\n"
            b"MX:3\r\n\r\n"
        )
        return upnp_packet

    def mdns_probe(self):
        """Génère une probe mDNS"""
        return self.dns_probe()

    def udp_scan(self, target, port):
        """Scan UDP avec probe spécifique si disponible"""
        start_time = time.time()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)

            # Sélection de la probe appropriée
            probe_data = self.udp_probes.get(port, lambda: b"\x00" * 10)()

            # Envoi de la probe
            sock.sendto(probe_data, (target, port))

            try:
                response, addr = sock.recvfrom(1024)
                response_time = (time.time() - start_time) * 1000

                service_info = self.analyze_udp_response(port, response)

                result = PortScanResult(
                    port=port,
                    protocol='udp',
                    state='open',
                    service=service_info['name'],
                    version=service_info.get('version', ''),
                    banner=response[:100].decode('utf-8', errors='ignore') if response else '',
                    response_time=response_time,
                    scan_technique='udp_probe'
                )

                with self.lock:
                    self.results[target].append(result)
                    self.scan_stats['open_ports'] += 1

                return result

            except socket.timeout:
                response_time = (time.time() - start_time) * 1000
                is_closed = self.check_icmp_unreachable(target, port) if SCAPY_AVAILABLE else False
                state = 'closed' if is_closed else 'open|filtered'

                result = PortScanResult(
                    port=port,
                    protocol='udp',
                    state=state,
                    service=self.get_common_udp_service(port),
                    version='',
                    banner='',
                    response_time=response_time,
                    scan_technique='udp_probe'
                )

                with self.lock:
                    if is_closed:
                        self.scan_stats['closed_ports'] += 1
                    else:
                        self.scan_stats['open_filtered'] += 1

                return result

        except Exception as e:
            with self.lock:
                self.scan_stats['errors'] += 1
            return None

        finally:
            try:
                sock.close()
            except:
                pass

    def check_icmp_unreachable(self, target, port):
        """Vérifie si un paquet ICMP port unreachable est reçu"""
        if not SCAPY_AVAILABLE:
            return False

        try:
            udp_packet = IP(dst=target) / UDP(dport=port) / Raw(b"test")
            response = sr1(udp_packet, timeout=2, verbose=0)

            if response and response.haslayer(ICMP):
                icmp_layer = response.getlayer(ICMP)
                if icmp_layer.type == 3 and icmp_layer.code == 3:
                    return True
            return False
        except Exception:
            return False

    def analyze_udp_response(self, port, response):
        """Analyse la réponse UDP pour identifier le service"""
        service_info = {'name': 'unknown', 'version': ''}

        if port in self.service_signatures:
            sig = self.service_signatures[port]
            service_info['name'] = sig['name']
            for pattern in sig['response_patterns']:
                if pattern in response:
                    service_info['version'] = self.extract_udp_version(port, response)
                    break
        else:
            service_info['name'] = self.get_common_udp_service(port)

        return service_info

    def extract_udp_version(self, port, response):
        """Extrait la version depuis une réponse UDP"""
        try:
            response_str = response.decode('utf-8', errors='ignore')

            if port == 53 and 'BIND' in response_str:
                import re
                match = re.search(r'BIND\s+(\d+\.\d+(?:\.\d+)*)', response_str)
                return match.group(1) if match else ''

            elif port == 161 and b'public' in response:
                return 'v1/v2c'

            elif port == 123 and len(response) >= 48:
                li_vn_mode = response[0]
                version = (li_vn_mode >> 3) & 0x07
                return f'v{version}'

        except Exception:
            pass

        return ''

    def get_common_udp_service(self, port):
        """Retourne le service UDP courant pour un port"""
        common_udp_services = {
            53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP',
            123: 'NTP', 161: 'SNMP', 162: 'SNMP-trap', 500: 'IPSec',
            514: 'Syslog', 1900: 'UPnP', 5353: 'mDNS'
        }
        return common_udp_services.get(port, 'unknown')

    def scan_common_udp_ports(self, target):
        """Scanne les ports UDP les plus communs"""
        common_udp_ports = [53, 67, 68, 69, 123, 161, 162, 500, 514, 1900, 5353]

        print(f"[*] Scanning common UDP ports on {target}")

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self.udp_scan, target, port): port for port in common_udp_ports}

            results = []
            for future in as_completed(futures):
                port = futures[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        if result.state == 'open':
                            print(f"[+] {target}:{port}/udp ouvert - {result.service}")
                        elif result.state == 'open|filtered':
                            print(f"[?] {target}:{port}/udp ouvert|filtré - {result.service}")

                    with self.lock:
                        self.scan_stats['total_scanned'] += 1

                except Exception as e:
                    print(f"[-] Erreur scan UDP port {port}: {e}")

            return self.results[target]

    def scan_udp_range(self, target, port_range):
        """Scanne une plage de ports UDP"""
        print(f"[*] Scanning UDP ports {port_range[0]}-{port_range[1]} on {target}")

        ports = list(range(port_range[0], port_range[1] + 1))

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self.udp_scan, target, port): port for port in ports}

            results = []
            for future in as_completed(futures):
                port = futures[future]
                try:
                    result = future.result()
                    if result and result.state in ['open', 'open|filtered']:
                        results.append(result)
                        print(f"[+] {target}:{port}/udp {result.state} - {result.service}")

                    with self.lock:
                        self.scan_stats['total_scanned'] += 1

                except Exception as e:
                    print(f"[-] Erreur scan UDP port {port}: {e}")

            return self.results[target]

    def generate_udp_report(self, target):
        """Génère un rapport de scan UDP"""
        if target not in self.results:
            return None

        results_for_target = self.results[target]
        open_ports = [r for r in results_for_target if r.state == 'open']
        open_filtered = [r for r in results_for_target if r.state == 'open|filtered']

        report = {
            'target': target,
            'protocol': 'UDP',
            'scan_time': time.ctime(),
            'total_ports_scanned': self.scan_stats['total_scanned'],
            'open_ports_count': len(open_ports),
            'open_filtered_count': len(open_filtered),
            'open_ports': [
                {
                    'port': r.port,
                    'service': r.service,
                    'version': r.version,
                    'state': r.state
                } for r in open_ports
            ],
            'open_filtered_ports': [
                {
                    'port': r.port,
                    'service': r.service,
                    'state': r.state
                } for r in open_filtered
            ],
            'scan_statistics': self.scan_stats
        }

        return report
