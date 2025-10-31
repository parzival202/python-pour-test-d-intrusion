#!/usr/bin/env python3
"""
Verificateur d’URLs avec analyse de s´ecurit´e
"""

import requests
import re
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime


class URLChecker:
    """Analyseur d’URLs avec v´erifications de s´ecurit´e"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecurityChecker/1.0'
        })
        self.results = {}

    def check_url(self, url):
        """Analyse compl`ete d’une URL"""
        print(f"\n[*] Analyse de {url}")
        self.results[url] = {
            'url': url,
            'timestamp': datetime.now(),
            'basic_info': {},
            'security_headers': {},
            'ssl_info': {},
            'vulnerabilities': []
        }
        # Analyse de base
        self._basic_analysis(url)
        # Analyse des headers de s´ecurit´e
        self._check_security_headers(url)
        # Analyse SSL
        self._check_ssl(url)
        # V´erifications de s´ecurit´e basiques
        self._basic_security_checks(url)
        return self.results[url]

    def _basic_analysis(self, url):
        """Analyse de base de l’URL"""
        try:
            parsed = urlparse(url)
            response = self.session.get(url, timeout=10, allow_redirects=True)
            self.results[url]['basic_info'] = {
                'scheme': parsed.scheme,
                'domain': parsed.netloc,
                'path': parsed.path,
                'status_code': response.status_code,
                'content_length': len(response.content),
                'response_time': response.elapsed.total_seconds(),
                'final_url': response.url,
                'redirects': len(response.history)
            }
            print(f"[+] Status: {response.status_code}")
            print(f"[+] Taille: {len(response.content)} bytes")
            print(f"[+] Temps de reponse: {response.elapsed.total_seconds():.2f}s")
        except Exception as e:
            print(f"[-] Erreur analyse de base: {e}")
            self.results[url]['basic_info']['error'] = str(e)

    def _check_security_headers(self, url):
        """Vérifie les headers de sécurité"""
        try:
            response = self.session.head(url, timeout=10)
            headers = response.headers
            security_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
                'X-XSS-Protection': '1; mode=block',
                'Strict-Transport-Security': 'max-age=',
                'Content-Security-Policy': 'default-src',
                'Referrer-Policy': 'strict-origin'
            }
            results = {}
            missing_headers = []
            for header, expected in security_headers.items():
                if header in headers:
                    results[header] = headers[header]
                    print(f"[+] {header}: {headers[header]}")
                else:
                    missing_headers.append(header)
                    print(f"[-] Header manquant: {header}")
            self.results[url]['security_headers'] = {
                'present': results,
                'missing': missing_headers,
                'security_score': (len(results) / len(security_headers)) * 100
            }
        except Exception as e:
            print(f"[-] Erreur headers: {e}")

    def _check_ssl(self, url):
        """Analyse du certificat SSL"""
        if not url.startswith('https://'):
            print("[-] Pas de SSL (HTTP)")
            return
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc
            port = parsed.port or 443
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
            self.results[url]['ssl_info'] = {
                'subject': dict(x[0] for x in cert['subject']),
                'issuer': dict(x[0] for x in cert['issuer']),
                'version': cert['version'],
                'serial_number': cert['serialNumber'],
                'not_before': cert['notBefore'],
                'not_after': cert['notAfter'],
                'signature_algorithm': cert.get('signatureAlgorithm', 'Unknown')
            }
            print(f"[+] SSL Certificate pour: {cert['subject']}")
            print(f"[+] Émis par: {cert['issuer']}")
            print(f"[+] Valide jusqu’au: {cert['notAfter']}")
        except Exception as e:
            print(f"[-] Erreur SSL: {e}")
            self.results[url]['ssl_info']['error'] = str(e)

    def _basic_security_checks(self, url):
        """Vérifications de sécurité basiques"""
        try:
            response = self.session.get(url, timeout=10)
            content = response.text.lower()
            suspicious_patterns = [
                (r'password.*=.*["\"][^"\"]*["\"]', 'Possible mot de passe en clair'),
                (r'api[_-]?key.*=.*["\"][^"\"]*["\"]', 'Possible clé API exposée'),
                (r'mysql_connect\(', 'Fonction MySQL détectée'),
                (r'eval\s*\(', 'Fonction eval() détectée (risque XSS)'),
                (r'<script[^>]*>', 'Balises script détectées'),
            ]
            vulnerabilities = []
            for pattern, description in suspicious_patterns:
                if re.search(pattern, content):
                    vulnerabilities.append({
                        'type': 'Pattern suspect',
                        'description': description,
                        'pattern': pattern
                    })
                    print(f"[!] {description}")
            # Vérification des formulaires
            if '<form' in content:
                if 'method="get"' in content and 'password' in content:
                    vulnerabilities.append({
                        'type': 'Formulaire non sécurisé',
                        'description': 'Formulaire de mot de passe en GET'
                    })
                    print("[!] Formulaire de mot de passe en GET détecté")
            self.results[url]['vulnerabilities'] = vulnerabilities
        except Exception as e:
            print(f"[-] Erreur vérifications sécurité: {e}")

    def generate_report(self):
        """Génère un rapport d’analyse"""
        print("\n" + "="*60)
        print("RAPPORT D’ANALYSE DES URLs")
        print("="*60)
        for url, data in self.results.items():
            print(f"\nURL: {url}")
            if 'basic_info' in data and 'status_code' in data['basic_info']:
                basic = data['basic_info']
                print(f" Status: {basic.get('status_code', 'N/A')}")
                print(f" Taille: {basic.get('content_length', 0)} bytes")
                print(f" Redirections: {basic.get('redirects', 0)}")
            if 'security_headers' in data:
                score = data['security_headers'].get('security_score', 0)
                print(f" Score de sécurité: {score:.1f}%")
                missing = data['security_headers'].get('missing', [])
                if missing:
                    print(f" Headers manquants: {len(missing)}")
            vulns = data.get('vulnerabilities', [])
            if vulns:
                print(f" Vulnérabilités détectées: {len(vulns)}")
            else:
                print(" Aucune vulnérabilité détectée")

# Tests
if __name__ == "__main__":
    checker = URLChecker()

    # URLs de test autoris´ees
    test_urls = [
        "https://httpbin.org/",
        "http://example.com/",
        "https://www.google.com/"
    ]

    for url in test_urls:
        try:
            checker.check_url(url)
        except KeyboardInterrupt:
            print("\nInterruption par l’utilisateur")
            break
        except Exception as e:
            print(f"Erreur pour {url}: {e}")

    checker.generate_report()