#!/usr/bin/env python3

"""
Techniques d'évasion avancées pour les scans réseau
OPSEC et contournement des systèmes de détection
"""

import random
import time
import threading
import requests
from datetime import datetime, timedelta
from collections import defaultdict, deque
import socket
import struct

class EvasionManager:
    """Gestionnaire de techniques d'évasion"""

    def __init__(self):
        self.enabled_techniques = []
        self.timing_profiles = {
            'paranoid': {'min_delay': 5, 'max_delay': 30, 'jitter': 0.8},
            'careful': {'min_delay': 2, 'max_delay': 10, 'jitter': 0.5},
            'normal': {'min_delay': 0.5, 'max_delay': 3, 'jitter': 0.3},
            'aggressive': {'min_delay': 0.1, 'max_delay': 1, 'jitter': 0.2}
        }
        self.current_profile = 'normal'
        self.request_history = deque(maxlen=1000)
        self.lock = threading.Lock()

    def enable_technique(self, technique_name):
        """Active une technique d'évasion"""
        if technique_name not in self.enabled_techniques:
            self.enabled_techniques.append(technique_name)
            print(f"[+] Technique d'évasion activée: {technique_name}")

    def set_timing_profile(self, profile):
        """Définit le profil temporel"""
        if profile in self.timing_profiles:
            self.current_profile = profile
            print(f"[*] Profil temporel: {profile}")

    def get_adaptive_delay(self):
        """Calcule un délai adaptatif basé sur l'historique"""
        profile = self.timing_profiles[self.current_profile]

        base_delay = random.uniform(profile['min_delay'], profile['max_delay'])

        # Ajustement basé sur l'historique récent
        with self.lock:
            recent_requests = [req for req in self.request_history
                             if req['timestamp'] > time.time() - 60]  # Dernière minute

            # Si beaucoup de requêtes récentes
            if len(recent_requests) > 10:
                base_delay *= 1.5  # Augmenter le délai

        # Application du jitter
        jitter = random.uniform(-profile['jitter'], profile['jitter'])
        final_delay = max(0, base_delay * (1 + jitter))

        return final_delay

    def log_request(self, target, request_type):
        """Enregistre une requête pour l'historique"""
        with self.lock:
            self.request_history.append({
                'timestamp': time.time(),
                'target': target,
                'type': request_type
            })


class UserAgentRotator:
    """Rotation des User-Agents pour éviter la détection"""

    def __init__(self):
        self.user_agents = [
            # Chrome
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',

            # Firefox
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',

            # Safari
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',

            # Edge
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59',

            # Mobile
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Android 11; Mobile; rv:89.0) Gecko/89.0 Firefox/89.0'
        ]

        self.current_index = 0

    def get_random_user_agent(self):
        """Retourne un User-Agent aléatoire"""
        return random.choice(self.user_agents)

    def get_next_user_agent(self):
        """Retourne le prochain User-Agent en rotation"""
        ua = self.user_agents[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.user_agents)
        return ua


class ProxyRotator:
    """Rotation de proxies pour anonymisation"""

    def __init__(self):
        self.proxies = []
        self.current_index = 0
        self.failed_proxies = set()
        self.lock = threading.Lock()

    def load_proxies_from_file(self, filename):
        """Charge une liste de proxies depuis un fichier"""
        try:
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Format: IP:PORT ou IP:PORT:USERNAME:PASSWORD
                        parts = line.split(':')
                        if len(parts) >= 2:
                            proxy_info = {
                                'host': parts[0],
                                'port': int(parts[1]),
                                'username': parts[2] if len(parts) > 2 else None,
                                'password': parts[3] if len(parts) > 3 else None
                            }
                            self.proxies.append(proxy_info)

            print(f"[+] {len(self.proxies)} proxies chargés")

        except Exception as e:
            print(f"[-] Erreur chargement proxies: {e}")

    def get_next_proxy(self):
        """Retourne le prochain proxy disponible"""
        with self.lock:
            if not self.proxies:
                return None

            attempts = 0
            while attempts < len(self.proxies):
                proxy = self.proxies[self.current_index]
                self.current_index = (self.current_index + 1) % len(self.proxies)

                proxy_key = f"{proxy['host']}:{proxy['port']}"
                if proxy_key not in self.failed_proxies:
                    return proxy

                attempts += 1

            return None  # Tous les proxies ont échoué

    def mark_proxy_failed(self, proxy):
        """Marque un proxy comme défaillant"""
        with self.lock:
            proxy_key = f"{proxy['host']}:{proxy['port']}"
            self.failed_proxies.add(proxy_key)

    def test_proxy(self, proxy, test_url="http://httpbin.org/ip"):
        """Teste si un proxy fonctionne"""
        try:
            proxy_dict = {
                'http': f"http://{proxy['host']}:{proxy['port']}",
                'https': f"http://{proxy['host']}:{proxy['port']}"
            }
            if proxy['username']:
                proxy_dict['http'] = f"http://{proxy['username']}:{proxy['password']}@{proxy['host']}:{proxy['port']}"
                proxy_dict['https'] = f"http://{proxy['username']}:{proxy['password']}@{proxy['host']}:{proxy['port']}"

            response = requests.get(test_url, proxies=proxy_dict, timeout=10)
            return response.status_code == 200

        except Exception:
            return False


class TrafficShaper:
    """Mise en forme du trafic pour éviter la détection"""

    def __init__(self):
        self.bandwidth_limit = None  # bytes per second
        self.request_timestamps = deque(maxlen=100)
        self.bytes_sent = deque(maxlen=100)
        self.lock = threading.Lock()

    def set_bandwidth_limit(self, bps):
        """Définit la limite de bande passante en bytes/sec"""
        self.bandwidth_limit = bps
        print(f"[*] Limite de bande passante: {bps} bytes/sec")

    def should_throttle(self, payload_size):
        """Détermine s'il faut ralentir basé sur la bande passante"""
        if not self.bandwidth_limit:
            return False

        with self.lock:
            now = time.time()

            # Nettoyer les anciennes entrées (plus de 1 seconde)
            cutoff = now - 1.0
            while self.request_timestamps and self.request_timestamps[0] < cutoff:
                self.request_timestamps.popleft()
                self.bytes_sent.popleft()

            # Calculer le trafic actuel
            current_bps = sum(self.bytes_sent) if self.bytes_sent else 0

            # Vérifier si on dépasse la limite
            if current_bps + payload_size > self.bandwidth_limit:
                return True

        return False

    def log_transmission(self, bytes_sent):
        """Enregistre une transmission"""
        with self.lock:
            self.request_timestamps.append(time.time())
            self.bytes_sent.append(bytes_sent)

    def calculate_delay(self, payload_size):
        """Calcule le délai nécessaire pour respecter la limite"""
        if not self.bandwidth_limit:
            return 0

        # Délai basé sur la taille du payload et la limite
        delay = payload_size / self.bandwidth_limit
        return max(0, delay)


class DecoyManager:
    """Gestionnaire d'adresses IP leurres"""

    def __init__(self):
        self.decoy_ips = []
        self.real_ip = None

    def generate_decoy_ips(self, target_network, count=5):
        """Génère des IPs leurres dans le même réseau"""
        import ipaddress

        try:
            network = ipaddress.IPv4Network(target_network, strict=False)
            available_ips = list(network.hosts())

            # Sélectionner des IPs aléatoirement
            if len(available_ips) >= count:
                self.decoy_ips = random.sample(available_ips, count)
            else:
                self.decoy_ips = available_ips

            # Convertir en strings
            self.decoy_ips = [str(ip) for ip in self.decoy_ips]

            print(f"[+] {len(self.decoy_ips)} IPs leurres générées")

        except Exception as e:
            print(f"[-] Erreur génération leurres: {e}")

    def get_decoy_list(self):
        """Retourne la liste des leurres avec l'IP réelle"""
        if not self.decoy_ips:
            return []

        # Insérer l'IP réelle à une position aléatoire
        all_ips = self.decoy_ips.copy()
        if self.real_ip:
            position = random.randint(0, len(all_ips))
            all_ips.insert(position, self.real_ip)

        return all_ips


class AdvancedEvasionScanner:
    """Scanner avec techniques d'évasion intégrées"""

    def __init__(self):
        self.evasion_manager = EvasionManager()
        self.ua_rotator = UserAgentRotator()
        self.proxy_rotator = ProxyRotator()
        self.traffic_shaper = TrafficShaper()
        self.decoy_manager = DecoyManager()

        # Configuration par défaut
        self.session = requests.Session()
        self.current_proxy = None

    def configure_evasion(self, config):
        """Configure les techniques d'évasion"""
        if config.get('timing_profile'):
            self.evasion_manager.set_timing_profile(config['timing_profile'])

        if config.get('bandwidth_limit'):
            self.traffic_shaper.set_bandwidth_limit(config['bandwidth_limit'])

        if config.get('proxy_file'):
            self.proxy_rotator.load_proxies_from_file(config['proxy_file'])

        if config.get('decoy_network'):
            self.decoy_manager.generate_decoy_ips(config['decoy_network'])

        # Activation des techniques
        for technique in config.get('techniques', []):
            self.evasion_manager.enable_technique(technique)

    def evade_and_scan(self, target, port, scan_type='tcp_connect'):
        """Effectue un scan avec évasion"""
        # Préparation des techniques d'évasion
        self._prepare_evasion_session()

        # Délai adaptatif
        delay = self.evasion_manager.get_adaptive_delay()
        if delay > 0:
            print(f"[*] Délai d'évasion: {delay:.2f}s")
            time.sleep(delay)

        # Vérification de la limitation de bande passante
        payload_size = 64  # Taille approximative d'un paquet TCP SYN
        if self.traffic_shaper.should_throttle(payload_size):
            throttle_delay = self.traffic_shaper.calculate_delay(payload_size)
            print(f"[*] Traffic shaping delay: {throttle_delay:.2f}s")
            time.sleep(throttle_delay)

        # Exécution du scan
        result = self._execute_scan(target, port, scan_type)

        # Enregistrement de la requête
        self.evasion_manager.log_request(target, scan_type)
        self.traffic_shaper.log_transmission(payload_size)

        return result

    def _prepare_evasion_session(self):
        """Prépare la session avec les techniques d'évasion"""
        # Rotation User-Agent
        if 'user_agent_rotation' in self.evasion_manager.enabled_techniques:
            ua = self.ua_rotator.get_random_user_agent()
            self.session.headers.update({'User-Agent': ua})

        # Rotation de proxy
        if 'proxy_rotation' in self.evasion_manager.enabled_techniques:
            if not self.current_proxy or random.random() < 0.3:  # 30% chance de changer
                new_proxy = self.proxy_rotator.get_next_proxy()
                if new_proxy:
                    self.current_proxy = new_proxy
                    self._configure_proxy(new_proxy)

        # Headers supplémentaires pour le camouflage
        if 'header_manipulation' in self.evasion_manager.enabled_techniques:
            self._add_stealth_headers()

    def _configure_proxy(self, proxy):
        """Configure le proxy pour la session"""
        try:
            proxy_url = f"http://{proxy['host']}:{proxy['port']}"
            if proxy['username']:
                proxy_url = f"http://{proxy['username']}:{proxy['password']}@{proxy['host']}:{proxy['port']}"

            self.session.proxies.update({
                'http': proxy_url,
                'https': proxy_url
            })
            print(f"[*] Proxy configuré: {proxy['host']}:{proxy['port']}")

        except Exception as e:
            print(f"[-] Erreur configuration proxy: {e}")
            self.proxy_rotator.mark_proxy_failed(proxy)

    def _add_stealth_headers(self):
        """Ajoute des en-têtes pour le camouflage"""
        # Headers typiques d'un navigateur
        stealth_headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0'
        }

        # Ajouter quelques headers aléatoirement
        selected_headers = random.sample(list(stealth_headers.items()), k=random.randint(3, 6))
        for header, value in selected_headers:
            self.session.headers[header] = value

    def _execute_scan(self, target, port, scan_type):
        """Exécute le scan proprement dit"""
        if scan_type == 'http_stealth':
            return self._http_stealth_scan(target, port)
        elif scan_type == 'tcp_stealth':
            return self._tcp_stealth_scan(target, port)
        else:
            return self._basic_tcp_scan(target, port)

    def _http_stealth_scan(self, target, port):
        """Scan HTTP furtif"""
        try:
            url = f"http://{target}:{port}"
            if port == 443:
                url = f"https://{target}:{port}"

            # Requête avec techniques d'évasion
            response = self.session.get(url, timeout=10, allow_redirects=False, verify=False)

            return {
                'target': target,
                'port': port,
                'status': 'open',
                'service': 'http',
                'response_code': response.status_code,
                'headers': dict(response.headers),
                'server': response.headers.get('Server', ''),
                'evasion_used': True
            }

        except Exception as e:
            return {
                'target': target,
                'port': port,
                'status': 'filtered_or_closed',
                'error': str(e),
                'evasion_used': True
            }

    def _tcp_stealth_scan(self, target, port):
        """Scan TCP furtif"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)

            # Techniques de manipulation de socket pour l'évasion
            if 'socket_manipulation' in self.evasion_manager.enabled_techniques:
                # Manipulation des options TCP
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            result = sock.connect_ex((target, port))
            sock.close()

            if result == 0:
                return {
                    'target': target,
                    'port': port,
                    'status': 'open',
                    'evasion_used': True
                }
            else:
                return {
                    'target': target,
                    'port': port,
                    'status': 'closed',
                    'evasion_used': True
                }

        except Exception as e:
            return {
                'target': target,
                'port': port,
                'status': 'error',
                'error': str(e),
                'evasion_used': True
            }

    def _basic_tcp_scan(self, target, port):
        """Scan TCP basique avec évasion minimale"""

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)

            result = sock.connect_ex((target, port))
            sock.close()

            return {
                'target': target,
                'port': port,
                'status': 'open' if result == 0 else 'closed',
                'evasion_used': True
            }

        except Exception as e:
            return {
                'target': target,
                'port': port,
                'status': 'error',
                'error': str(e),
                'evasion_used': True
            }


# Exemple d'utilisation
def main():
    import argparse

    parser = argparse.ArgumentParser(description="Scanner avec évasion avancée")
    parser.add_argument("target", help="Cible à scanner")
    parser.add_argument("-p", "--ports", default="80,443,22,25", help="Ports à scanner")
    parser.add_argument("--timing", choices=['paranoid', 'careful', 'normal', 'aggressive'],
                       default='normal', help="Profil temporel")
    parser.add_argument("--proxies", help="Fichier de proxies")
    parser.add_argument("--bandwidth", type=int, help="Limite de bande passante (bytes/sec)")
    parser.add_argument("--decoy-network", help="Réseau pour générer des IPs leurres")

    args = parser.parse_args()

    # Configuration du scanner
    scanner = AdvancedEvasionScanner()

    evasion_config = {
        'timing_profile': args.timing,
        'techniques': ['user_agent_rotation', 'header_manipulation', 'socket_manipulation']
    }

    if args.proxies:
        evasion_config['proxy_file'] = args.proxies
        evasion_config['techniques'].append('proxy_rotation')

    if args.bandwidth:
        evasion_config['bandwidth_limit'] = args.bandwidth

    if args.decoy_network:
        evasion_config['decoy_network'] = args.decoy_network

    scanner.configure_evasion(evasion_config)

    # Scanning avec évasion
    ports = [int(p.strip()) for p in args.ports.split(',')]
    print(f"[*] Scan furtif de {args.target} sur ports {args.ports}")

    for port in ports:
        result = scanner.evade_and_scan(args.target, port, 'http_stealth' if port in [80, 443, 8080] else 'tcp_stealth')

        if result['status'] == 'open':
            print(f"[+] {args.target}:{port} - OUVERT")
            if 'server' in result:
                print(f"    Serveur: {result['server']}")
        elif result['status'] == 'closed':
            print(f"[-] {args.target}:{port} - FERMÉ")
        else:
            print(f"[?] {args.target}:{port} - {result['status'].upper()}")

    print("[*] Scan terminé avec techniques d'évasion")


if __name__ == "__main__":
    main()
