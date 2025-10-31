#!/usr/bin/env python3
"""
Utilisation avancée de la bibliothèque requests pour la cybersécurité
"""
import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
import json
import time
from urllib.parse import urljoin

class AdvancedRequestsDemo:
    """Démonstration des fonctionnalités avancées de requests"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CyberSecTool/1.0 (Educational)'
        })

        # Configuration SSL pour les tests (NE PAS UTILISER EN PRODUCTION)
        self.session.verify = False
        requests.urllib3.disable_warnings()

    def test_http_methods(self, base_url):
        """Test des différentes méthodes HTTP"""
        print(f"\n[*] Test des méthodes HTTP sur {base_url}")

        methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']
        results = {}

        for method in methods:
            try:
                response = self.session.request(method, base_url, timeout=5)
                results[method] = {
                    'status_code': response.status_code,
                    'allowed': response.status_code != 405
                }
                print(f"[+] {method}: {response.status_code}")

            except Exception as e:
                results[method] = {'error': str(e)}
                print(f"[-] {method}: Erreur - {e}")

        return results

    def test_authentication(self, url):
        """Test des méthodes d’authentification"""
        print(f"\n[*] Test d’authentification sur {url}")

        # Test sans authentification
        try:
            response = self.session.get(url, timeout=5)
            print(f"[*] Sans auth: {response.status_code}")

            if response.status_code == 401:
                print("[+] Authentification requise détectée")

            # Test avec des credentials faibles (éducatif uniquement)
            weak_creds = [
                ('admin', 'admin'),
                ('admin', 'password'),
                ('user', 'user'),
                ('test', 'test')
            ]

            for username, password in weak_creds:
                auth_response = self.session.get(
                    url,
                    auth=HTTPBasicAuth(username, password),
                    timeout=5
                )

                if auth_response.status_code == 200:
                    print(f"[!] Credentials faibles trouvées: {username}:{password}")
                    break
                else:
                    print(f"[-] {username}:{password} - {auth_response.status_code}")

        except Exception as e:
            print(f"[-] Erreur authentification: {e}")

    def analyze_headers(self, url):
        """Analyse des headers HTTP"""
        print(f"\n[*] Analyse des headers pour {url}")

        try:
            response = self.session.get(url, timeout=5)

            interesting_headers = [
                'Server', 'X-Powered-By', 'X-AspNet-Version',
                'Set-Cookie', 'X-Frame-Options', 'Content-Security-Policy'
            ]

            print("[+] Headers intéressants:")
            for header in interesting_headers:
                if header in response.headers:
                    print(f" {header}: {response.headers[header]}")

            # Recherche d’informations sensibles
            sensitive_patterns = ['version', 'server', 'php', 'asp', 'jsp']

            for header, value in response.headers.items():
                for pattern in sensitive_patterns:
                    if pattern.lower() in value.lower():
                        print(f"[!] Info sensible dans {header}: {value}")

        except Exception as e:
            print(f"[-] Erreur analyse headers: {e}")

    def test_file_upload(self, upload_url):
        """Test de upload de fichier (éducatif)"""
        print(f"\n[*] Test d’upload sur {upload_url}")

        # Fichier de test inoffensif
        test_files = {
            'test.txt': ('test.txt', 'Contenu de test', 'text/plain'),
            'test.php': ('test.php', '<?php echo "Test"; ?>', 'application/x-php'),
            'test.jsp': ('test.jsp', '<% out.println("Test"); %>', 'application/x-jsp')
        }

        for filename, file_data in test_files.items():
            try:
                files = {'file': file_data}
                response = self.session.post(upload_url, files=files, timeout=10)

                print(f"[*] Upload {filename}: {response.status_code}")

                if response.status_code == 200:
                    print(f"[+] Upload réussi pour {filename}")
                    if 'uploaded' in response.text.lower():
                        print("[!] Possible vulnérabilité d’upload")

            except Exception as e:
                print(f"[-] Erreur upload {filename}: {e}")

    def directory_bruteforce(self, base_url, wordlist=None):
        """Brute force de répertoires simple"""
        if wordlist is None:
            wordlist = [
                'admin', 'administrator', 'backup', 'config', 'test',
                'uploads', 'images', 'css', 'js', 'api', 'old'
            ]

        print(f"\n[*] Brute force de répertoires sur {base_url}")
        found_dirs = []

        for directory in wordlist:
            test_url = urljoin(base_url, directory + '/')

            try:
                response = self.session.get(test_url, timeout=3)

                if response.status_code == 200:
                    found_dirs.append(directory)
                    print(f"[+] Répertoire trouvé: /{directory}/")
                elif response.status_code == 403:
                    print(f"[*] Répertoire existe mais accès interdit: /{directory}/")

            except Exception:
                pass

            time.sleep(0.1) # Rate limiting

        return found_dirs

# Démonstration
if __name__ == "__main__":
    demo = AdvancedRequestsDemo()

    # URL de test autorisée
    test_url = "https://httpbin.org/"

    print("DÉMONSTRATION REQUESTS AVANCÉ")
    print("="*40)

    # Test des méthodes HTTP
    demo.test_http_methods(test_url)

    # Analyse des headers
    demo.analyze_headers(test_url)

    # Test d’authentification (avec httpbin)
    auth_url = "https://httpbin.org/basic-auth/user/pass"
    demo.test_authentication(auth_url)

    print("\n[*] Démonstration terminée")
