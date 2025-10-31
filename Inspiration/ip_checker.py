#!/usr/bin/env python3
"""
V´erificateur et analyseur d’adresses IP
"""
import socket
import ipaddress
import subprocess
import platform
import requests
import json
from concurrent.futures import ThreadPoolExecutor
import time

class IPChecker:
    """Analyseur d’adresses IP avec v´erifications de s´ecurit´e"""

    def __init__(self):
        self.results = {}
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389]

    def check_ip(self, ip_address):
        """Analyse compl`ete d’une adresse IP"""
        print(f"\n[*] Analyse de {ip_address}")

        # Validation de l’IP
        if not self._validate_ip(ip_address):
            print(f"[-] Adresse IP invalide: {ip_address}")
            return None

        self.results[ip_address] = {
            'ip': ip_address,
            'basic_info': {},
            'connectivity': {},
            'port_scan': {},
            'geolocation': {},
            'dns_info': {}
        }

        # Analyse de base
        self._basic_ip_analysis(ip_address)

        # Test de connectivit´e
        self._test_connectivity(ip_address)

        # Scan de ports basique
        self._basic_port_scan(ip_address)

        # Informations DNS
        self._dns_lookup(ip_address)

        # G´eolocalisation (si IP publique)
        self._get_geolocation(ip_address)

        return self.results[ip_address]

    def _validate_ip(self, ip_address):
        """Valide une adresse IP"""
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False

    def _basic_ip_analysis(self, ip_address):
        """Analyse de base de l’IP"""
        try:
            ip_obj = ipaddress.ip_address(ip_address)

            info = {
                'version': ip_obj.version,
                'is_private': ip_obj.is_private,
                'is_global': ip_obj.is_global,
                'is_multicast': ip_obj.is_multicast,
                'is_reserved': ip_obj.is_reserved,
                'is_loopback': ip_obj.is_loopback
            }

            self.results[ip_address]['basic_info'] = info

            print(f"[+] IPv{info['version']}")
            print(f"[+] Priv´ee: {info['is_private']}")
            print(f"[+] Publique: {info['is_global']}")

        except Exception as e:
            print(f"[-] Erreur analyse IP: {e}")

    def _test_connectivity(self, ip_address):
        """Test de connectivit´e avec ping"""
        try:
            # D´etection de l’OS pour adapter la commande ping
            system = platform.system().lower()
            if system == "windows":
                cmd = ["ping", "-n", "3", ip_address]
            else:
                cmd = ["ping", "-c", "3", ip_address]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            connectivity = {
                'ping_success': result.returncode == 0,
                'ping_output': result.stdout,
                'response_time': self._extract_ping_time(result.stdout)
            }

            self.results[ip_address]['connectivity'] = connectivity

            if connectivity['ping_success']:
                print(f"[+] Ping r´eussi (temps: {connectivity['response_time']}ms)")
            else:
                print("[-] Ping ´echou´e")

        except subprocess.TimeoutExpired:
            print("[-] Timeout lors du ping")
        except Exception as e:
            print(f"[-] Erreur ping: {e}")

    def _extract_ping_time(self, ping_output):
        """Extrait le temps de r´eponse du ping"""
        import re

        # Pattern pour extraire le temps en ms
        patterns = [
            r'time[<=](\d+(?:\.\d+)?)ms', # Linux
            r'Average = (\d+)ms', # Windows
            r'temps[<=](\d+)ms' # Windows FR
        ]

        for pattern in patterns:
            match = re.search(pattern, ping_output)
            if match:
                return float(match.group(1))

        return None

    def _basic_port_scan(self, ip_address):
        """Scan de ports basique sur les ports communs"""
        print("[*] Scan de ports basique...")

        open_ports = []

        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip_address, port))
                sock.close()

                if result == 0:
                    service = self._get_service_name(port)
                    print(f"[+] Port {port}/tcp ouvert ({service})")
                    return {'port': port, 'status': 'open', 'service': service}

            except Exception:
                pass

            return None

        # Scan en parall`ele pour am´eliorer les performances
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(scan_port, port): port for port in self.common_ports}

            for future in futures:
                result = future.result()
                if result:
                    open_ports.append(result)

        self.results[ip_address]['port_scan'] = {
            'scanned_ports': self.common_ports,
            'open_ports': open_ports,
            'total_open': len(open_ports)
        }

        print(f"[+] {len(open_ports)} ports ouverts trouv´es")

    def _get_service_name(self, port):
        """Retourne le nom du service pour un port donn´e"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S', 3389: 'RDP'
        }
        return services.get(port, 'Unknown')

    def _dns_lookup(self, ip_address):
        """Recherche DNS inverse"""
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]

            dns_info = {
                'hostname': hostname,
                'reverse_lookup_success': True
            }

            print(f"[+] Hostname: {hostname}")

        except socket.herror:
            dns_info = {
                'hostname': None,
                'reverse_lookup_success': False
            }
            print("[-] Pas de r´esolution DNS inverse")
        except Exception as e:
            dns_info = {
                'error': str(e),
                'reverse_lookup_success': False
            }
            print(f"[-] Erreur DNS: {e}")

        self.results[ip_address]['dns_info'] = dns_info

    def _get_geolocation(self, ip_address):
        """Obtient la g´eolocalisation d’une IP publique"""
        ip_obj = ipaddress.ip_address(ip_address)

        if ip_obj.is_private:
            print("[*] IP priv´ee - pas de g´eolocalisation")
            return

        try:
            # Utilisation de l’API gratuite ipapi.co
            response = requests.get(f"http://ipapi.co/{ip_address}/json/", timeout=5)

            if response.status_code == 200:
                geo_data = response.json()

                geolocation = {
                    'country': geo_data.get('country_name'),
                    'region': geo_data.get('region'),
                    'city': geo_data.get('city'),
                    'latitude': geo_data.get('latitude'),
                    'longitude': geo_data.get('longitude'),
                    'isp': geo_data.get('org'),
                    'timezone': geo_data.get('timezone')
                }

                self.results[ip_address]['geolocation'] = geolocation

                print(f"[+] Localisation: {geo_data.get('city')}, {geo_data.get('country_name')}")
                print(f"[+] ISP: {geo_data.get('org')}")

            else:
                print("[-] Impossible d’obtenir la g´eolocalisation")

        except Exception as e:
            print(f"[-] Erreur g´eolocalisation: {e}")

    def generate_report(self):
        """G´en`ere un rapport d’analyse des IPs"""
        print("\n" + "="*60)
        print("RAPPORT D’ANALYSE DES ADRESSES IP")
        print("="*60)

        for ip, data in self.results.items():
            print(f"\nIP: {ip}")

            # Informations de base
            basic = data.get('basic_info', {})
            if basic:
                print(f" Type: IPv{basic.get('version', 'N/A')}")
                print(f" Priv´ee: {basic.get('is_private', 'N/A')}")

            # Connectivit´e
            connectivity = data.get('connectivity', {})
            if connectivity.get('ping_success'):
                time_ms = connectivity.get('response_time', 'N/A')
                print(f" Ping: OK ({time_ms}ms)")
            else:
                print(" Ping: ´Echec")

            # Ports ouverts
            port_scan = data.get('port_scan', {})
            open_count = port_scan.get('total_open', 0)
            print(f" Ports ouverts: {open_count}")

            if open_count > 0:
                for port_info in port_scan.get('open_ports', []):
                    print(f" - {port_info['port']}/tcp ({port_info['service']})")

            # DNS
            dns_info = data.get('dns_info', {})
            if dns_info.get('reverse_lookup_success'):
                print(f" Hostname: {dns_info.get('hostname')}")

            # G´eolocalisation
            geo = data.get('geolocation', {})
            if geo:
                location = f"{geo.get('city', '')}, {geo.get('country', '')}"
                print(f" Localisation: {location}")

# Tests
if __name__ == "__main__":
    checker = IPChecker()

    # IPs de test autoris´ees
    test_ips = [
        "8.8.8.8", # DNS Google
        "1.1.1.1", # DNS Cloudflare
        "127.0.0.1", # Localhost
        "192.168.1.1" # IP priv´ee courante
    ]

    for ip in test_ips:
        try:
            checker.check_ip(ip)
            time.sleep(1) # Pause entre les scans
        except KeyboardInterrupt:
            print("\nInterruption par l’utilisateur")
            break
        except Exception as e:
            print(f"Erreur pour {ip}: {e}")

    checker.generate_report()
