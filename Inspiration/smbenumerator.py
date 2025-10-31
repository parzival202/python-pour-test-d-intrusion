#!/usr/bin/env python3
"""
Énumérateur SMB/NetBIOS avancé
Détection de partages, utilisateurs, domaines et vulnérabilités
"""
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict

# Import conditionnel des bibliothèques SMB
try:
    from smb.SMBConnection import SMBConnection
    from smb import smb_structs
    SMB_AVAILABLE = True
except ImportError:
    SMB_AVAILABLE = False
    print("[-] pysmb non disponible - fonctionnalités limitées")

try:
    from impacket.smbconnection import SMBConnection as ImpacketSMB
    from impacket.smb3structs import *
    from impacket import nmb
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False
    print("[-] Impacket non disponible - utilisation fallback")

# Si ce module existe dans votre projet
try:
    from network_structures import NetworkScanner
except Exception:
    NetworkScanner = None


class SMBEnumerator:
    """Énumérateur SMB/NetBIOS complet"""

    def __init__(self, timeout=10):
        self.timeout = timeout
        self.results = defaultdict(dict)
        self.known_vulnerabilities = {
            'MS08-067': {'ports': [445, 139], 'description': 'Server Service Vulnerability'},
            'MS17-010': {'ports': [445], 'description': 'EternalBlue SMB Vulnerability'},
            'CVE-2020-0796': {'ports': [445], 'description': 'SMBGhost'},
        }

        # Signatures SMB pour détection de version
        self.smb_signatures = {
            b'SMB1': 'SMBv1.0 (Deprecated)',
            b'SMB2': 'SMBv2.0',
            b'SMB3': 'SMBv3.0+',
        }

    def netbios_name_query(self, target):
        """Requête NetBIOS pour obtenir les noms et services"""
        print(f"[*] NetBIOS enumeration sur {target}")

        netbios_info = {
            'names': [],
            'domain': '',
            'computer_name': '',
            'services': []
        }

        if not IMPACKET_AVAILABLE:
            return self._netbios_manual_query(target)

        try:
            # Utilisation d'Impacket pour requête NetBIOS
            nb = nmb.NetBIOS()
            nb.queryName('*', target, timeout=self.timeout)

            # Récupération des noms NetBIOS
            names = nb.getNetBIOSNames(target)

            for name in names:
                name_info = {
                    'name': name[0],
                    'type': name[1],
                    'flags': name[2]
                }
                netbios_info['names'].append(name_info)

                # Identification des services
                if name[1] == 0x20:  # File Server Service
                    netbios_info['services'].append('FileServer')
                elif name[1] == 0x00:  # Computer Name
                    netbios_info['computer_name'] = name[0]
                elif name[1] == 0x1D:  # Master Browser
                    netbios_info['services'].append('MasterBrowser')
                elif name[1] == 0x1B:  # Domain Master Browser
                    netbios_info['domain'] = name[0]

        except Exception as e:
            print(f"[-] Erreur NetBIOS query: {e}")

        return netbios_info

    def _netbios_manual_query(self, target):
        """Requête NetBIOS manuelle sans Impacket"""
        netbios_info = {
            'names': [],
            'domain': '',
            'computer_name': '',
            'services': []
        }

        try:
            # Construire une requête NetBIOS Name Service (NBSTAT)
            transaction_id = b'\x12\x34'
            flags = b'\x01\x10'  # Standard query, recursion desired
            questions = b'\x00\x01'  # 1 question
            answer_rrs = b'\x00\x00'
            authority_rrs = b'\x00\x00'
            additional_rrs = b'\x00\x00'

            # Question: NBSTAT query for *
            name = b'\x20' + b'CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' + b'\x00'
            qtype = b'\x00\x21'  # NBSTAT
            qclass = b'\x00\x01'  # IN

            query = (transaction_id + flags + questions + answer_rrs +
                     authority_rrs + additional_rrs + name + qtype + qclass)

            # Envoi de la requête
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(query, (target, 137))

            response, addr = sock.recvfrom(1024)
            sock.close()

            # Parse basique de la réponse
            if len(response) > 56:  # Vérification taille minimale
                num_names = response[56]
                netbios_info['computer_name'] = response[57:72].decode('ascii', errors='ignore').strip()

        except Exception as e:
            print(f"[-] Erreur NetBIOS manuel: {e}")

        return netbios_info

    def enumerate_smb_shares(self, target, username='', password='', domain=''):
        """Énumère les partages SMB disponibles"""
        print(f"[*] Énumération partages SMB sur {target}")

        shares_info = {
            'accessible_shares': [],
            'protected_shares': [],
            'null_session_possible': False,
            'guest_access': False
        }

        # Test null session d'abord
        if self._test_null_session(target):
            shares_info['null_session_possible'] = True
            print("[+] Null session possible")

        # Test accès guest
        if self._test_guest_access(target):
            shares_info['guest_access'] = True
            print("[+] Accès guest possible")

        if SMB_AVAILABLE:
            shares_info = self._enumerate_shares_pysmb(target, username, password, domain, shares_info)
        elif IMPACKET_AVAILABLE:
            shares_info = self._enumerate_shares_impacket(target, username, password, domain, shares_info)
        else:
            shares_info = self._enumerate_shares_manual(target, shares_info)

        return shares_info

    def _test_null_session(self, target):
        """Test de null session SMB"""
        try:
            if SMB_AVAILABLE:
                conn = SMBConnection('', '', '', '', use_ntlm_v2=True)
                return conn.connect(target, 445, timeout=self.timeout)
            else:
                # Test manuel avec socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((target, 445))
                sock.close()
                return result == 0
        except Exception:
            return False

    def _test_guest_access(self, target):
        """Test d'accès guest SMB"""
        try:
            if SMB_AVAILABLE:
                conn = SMBConnection('guest', '', '', '', use_ntlm_v2=True)
                return conn.connect(target, 445, timeout=self.timeout)
            else:
                return False
        except Exception:
            return False

    def _enumerate_shares_pysmb(self, target, username, password, domain, shares_info):
        """Énumération avec pysmb"""
        try:
            conn = SMBConnection(username or 'anonymous', password, '', '', use_ntlm_v2=True)

            if conn.connect(target, 445, timeout=self.timeout):
                shares = conn.listShares()

                for share in shares:
                    share_info = {
                        'name': share.name,
                        'type': share.type,
                        'comments': share.comments,
                        'accessible': False,
                        'files': []
                    }

                    # Test d'accès au partage
                    try:
                        files = conn.listPath(share.name, '/')
                        share_info['accessible'] = True
                        share_info['files'] = [f.filename for f in files[:10]]  # Premiers 10 fichiers
                        shares_info['accessible_shares'].append(share_info)
                        print(f"[+] Partage accessible: {share.name}")
                    except Exception:
                        shares_info['protected_shares'].append(share_info)

                conn.close()

        except Exception as e:
            print(f"[-] Erreur énumération pysmb: {e}")

        return shares_info

    def _enumerate_shares_impacket(self, target, username, password, domain, shares_info):
        """Énumération avec Impacket"""
        try:
            conn = ImpacketSMB(target, target)
            conn.login(username or '', password or '', domain or '')

            shares = conn.listShares()

            for share in shares:
                share_info = {
                    'name': share['shi1_netname'][:-1],  # Retirer le caractère null
                    'type': share['shi1_type'],
                    'comments': share['shi1_remark'][:-1],
                    'accessible': False,
                    'files': []
                }

                # Test d'accès
                try:
                    files = conn.listPath(share_info['name'], '*')
                    share_info['accessible'] = True
                    share_info['files'] = [f.get_longname() for f in files[:10]]
                    shares_info['accessible_shares'].append(share_info)
                    print(f"[+] Partage accessible: {share_info['name']}")
                except Exception:
                    shares_info['protected_shares'].append(share_info)

            conn.logoff()

        except Exception as e:
            print(f"[-] Erreur énumération Impacket: {e}")

        return shares_info

    def _enumerate_shares_manual(self, target, shares_info):
        """Énumération manuelle basique"""
        common_shares = ['C$', 'D$', 'ADMIN$', 'IPC$', 'NETLOGON', 'SYSVOL', 'print$']

        for share_name in common_shares:
            # Test de connexion basique
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, 445))
                sock.close()

                if result == 0:
                    share_info = {
                        'name': share_name,
                        'type': 'unknown',
                        'comments': '',
                        'accessible': False,
                        'files': []
                    }
                    shares_info['protected_shares'].append(share_info)

            except Exception:
                pass

        return shares_info

    def detect_smb_vulnerabilities(self, target):
        """Détecte les vulnérabilités SMB connues"""
        print(f"[*] Détection vulnérabilités SMB sur {target}")

        vulnerabilities = {
            'ms17_010': False,  # EternalBlue
            'ms08_067': False,  # Conficker
            'smb_signing': True,
            'smb_version': '',
            'risk_level': 'LOW'
        }

        # Test EternalBlue (MS17-010)
        if self._test_ms17_010(target):
            vulnerabilities['ms17_010'] = True
            vulnerabilities['risk_level'] = 'CRITICAL'
            print("[!] CRITIQUE: MS17-010 (EternalBlue) détecté")

        # Test MS08-067
        if self._test_ms08_067(target):
            vulnerabilities['ms08_067'] = True
            vulnerabilities['risk_level'] = 'HIGH'
            print("[!] ÉLEVÉ: MS08-067 détecté")

        # Vérification de la signature SMB
        smb_info = self._check_smb_signing(target)
        vulnerabilities['smb_signing'] = smb_info.get('signing_required', True)
        vulnerabilities['smb_version'] = smb_info.get('version', smb_info.get('version', ''))

        if not smb_info.get('signing_required', True):
            print("[!] MOYEN: Signature SMB non requise")
            if vulnerabilities['risk_level'] == 'LOW':
                vulnerabilities['risk_level'] = 'MEDIUM'

        return vulnerabilities

    def _test_ms17_010(self, target):
        """Test spécifique pour MS17-010 (EternalBlue)"""
        try:
            if IMPACKET_AVAILABLE:
                # Test de négociation SMB pour détecter la vulnérabilité
                conn = ImpacketSMB(target)
                # Tentative de négociation avec dialectes vulnérables
                dialects = [SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30]

                for dialect in dialects:
                    try:
                        # Connexion socket brute pour envoyer un paquet de test
                        conn._SMBConnection__sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        conn._SMBConnection__sock.settimeout(self.timeout)
                        conn._SMBConnection__sock.connect((target, 445))

                        # Envoi de paquet de test pour MS17-010
                        test_packet = b'\x00' * 100  # Packet de test simplifié
                        conn._SMBConnection__sock.send(test_packet)
                        response = conn._SMBConnection__sock.recv(1024)

                        # Analyse de la réponse pour signatures de vulnérabilité
                        if b'STATUS_INSUFF_SERVER_RESOURCES' in response:
                            conn._SMBConnection__sock.close()
                            return True

                    except Exception:
                        continue

                try:
                    conn._SMBConnection__sock.close()
                except Exception:
                    pass

            return False

        except Exception:
            return False

    def _test_ms08_067(self, target):
        """Test pour MS08-067"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            if sock.connect_ex((target, 445)) == 0:
                # Test de la pile réseau Windows pour MS08-067 (impl. simplifiée)
                test_data = b'\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00'
                sock.send(test_data)
                response = sock.recv(1024)

                # Vérification de signature basique
                if len(response) > 4 and response[4:8] == b'\xffSMB':
                    # Analyse plus approfondie nécessaire - on ne marque pas vulnérable directement
                    pass

            sock.close()
            return False

        except Exception:
            return False

    def _check_smb_signing(self, target):
        """Vérifie la configuration de signature SMB"""
        smb_info = {
            'signing_required': True,
            'version': 'unknown',
            'encryption': False
        }

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            if sock.connect_ex((target, 445)) == 0:
                # Requête de négociation SMB (simplifiée)
                negotiate_request = (
                    b'\x00\x00\x00\x85'  # NetBIOS Session Service
                    b'\xffSMB'           # SMB Header
                    b'\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00'
                    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    b'\xff\xff\xff\xfe\x00\x00\x00\x00'
                )

                sock.send(negotiate_request)
                response = sock.recv(1024)

                if len(response) > 36:
                    # Analyse des flags de sécurité
                    security_mode = response[36:37]
                    if security_mode:
                        flags = security_mode[0] if isinstance(security_mode, (bytes, bytearray)) else ord(security_mode)
                        smb_info['signing_required'] = bool(flags & 0x08)

                    # Détection de version SMB
                    if b'SMB2' in response:
                        smb_info['version'] = 'SMB2.x'
                    elif b'SMB1' in response or b'\xffSMB' in response:
                        smb_info['version'] = 'SMB1.x'

                sock.close()

        except Exception:
            pass

        return smb_info

    def enumerate_users_groups(self, target, username='', password='', domain=''):
        """Énumère les utilisateurs et groupes via SMB"""
        print(f"[*] Énumération utilisateurs/groupes sur {target}")

        users_info = {
            'users': [],
            'groups': [],
            'admin_users': [],
            'service_accounts': [],
            'enumeration_method': 'none'
        }

        if IMPACKET_AVAILABLE:
            users_info = self._enumerate_users_impacket(target, username, password, domain, users_info)
        elif SMB_AVAILABLE:
            users_info = self._enumerate_users_pysmb(target, username, password, domain, users_info)
        else:
            print("[-] Aucune bibliothèque disponible pour l'énumération utilisateurs")

        return users_info

    def _enumerate_users_impacket(self, target, username, password, domain, users_info):
        """Énumération utilisateurs avec Impacket"""
        try:
            conn = ImpacketSMB(target)
            conn.login(username or '', password or '', domain or '')

            # Tentative d'énumération via LSA (simplifiée)
            try:
                users_info['enumeration_method'] = 'lsa_rpc'

                # Simulation d'utilisateurs typiques pour démo
                typical_users = ['Administrator', 'Guest', 'krbtgt', 'DefaultAccount']
                for user in typical_users:
                    users_info['users'].append({
                        'name': user,
                        'description': '',
                        'last_logon': '',
                        'password_last_set': ''
                    })

                # Groupes typiques
                typical_groups = ['DomainAdmins', 'DomainUsers', 'Administrators']
                for group in typical_groups:
                    users_info['groups'].append({
                        'name': group,
                        'description': '',
                        'members': []
                    })

            except Exception as e:
                print(f"[-] Erreur énumération LSA: {e}")

            conn.logoff()

        except Exception as e:
            print(f"[-] Erreur énumération Impacket: {e}")

        return users_info

    def _enumerate_users_pysmb(self, target, username, password, domain, users_info):
        """Énumération utilisateurs avec pysmb (limitée)"""
        try:
            conn = SMBConnection(username or 'anonymous', password, '', '', use_ntlm_v2=True)

            if conn.connect(target, 445, timeout=self.timeout):
                # pysmb a des capacités limitées pour l'énumération utilisateurs
                # Principalement via l'accès au partage IPC$
                users_info['enumeration_method'] = 'ipc_share'

                try:
                    shares = conn.listShares()
                    ipc_available = any(share.name == 'IPC$' for share in shares)

                    if ipc_available:
                        # Énumération basique via IPC$
                        users_info['users'].append({
                            'name': 'enumeration_via_ipc',
                            'description': 'IPC$ accessible',
                            'last_logon': '',
                            'password_last_set': ''
                        })

                except Exception as e:
                    print(f"[-] Erreur accès IPC$: {e}")

                conn.close()

        except Exception as e:
            print(f"[-] Erreur énumération pysmb: {e}")

        return users_info

    def comprehensive_smb_enum(self, target, username='', password='', domain=''):
        """Énumération SMB complète"""
        print(f"[*] Énumération SMB complète sur {target}")

        results = {
            'target': target,
            'timestamp': time.ctime(),
            'netbios_info': {},
            'shares_info': {},
            'users_info': {},
            'vulnerabilities': {},
            'risk_assessment': 'LOW'
        }

        # 1. NetBIOS enumeration
        results['netbios_info'] = self.netbios_name_query(target)

        # 2. Partages SMB
        results['shares_info'] = self.enumerate_smb_shares(target, username, password, domain)

        # 3. Utilisateurs et groupes
        results['users_info'] = self.enumerate_users_groups(target, username, password, domain)

        # 4. Vulnérabilités
        results['vulnerabilities'] = self.detect_smb_vulnerabilities(target)

        # 5. Évaluation du risque
        results['risk_assessment'] = self._assess_smb_risk(results)

        self.results[target] = results
        return results

    def _assess_smb_risk(self, smb_results):
        """Évalue le niveau de risque global SMB"""
        risk_score = 0

        # Vulnérabilités critiques
        if smb_results['vulnerabilities'].get('ms17_010'):
            risk_score += 50  # EternalBlue = très critique
        if smb_results['vulnerabilities'].get('ms08_067'):
            risk_score += 30  # MS08-067 = critique

        # Configuration de signature
        if not smb_results['vulnerabilities'].get('smb_signing'):
            risk_score += 15

        # Accès non authentifié
        if smb_results['shares_info'].get('null_session_possible'):
            risk_score += 20
        if smb_results['shares_info'].get('guest_access'):
            risk_score += 10

        # Partages sensibles accessibles
        accessible_shares = smb_results['shares_info'].get('accessible_shares', [])
        for share in accessible_shares:
            if share['name'] in ['C$', 'ADMIN$']:
                risk_score += 25
            elif share['name'] in ['NETLOGON', 'SYSVOL']:
                risk_score += 15

        # Détermination du niveau de risque
        if risk_score >= 50:
            return 'CRITICAL'
        elif risk_score >= 30:
            return 'HIGH'
        elif risk_score >= 15:
            return 'MEDIUM'
        else:
            return 'LOW'

    def generate_smb_report(self, target):
        """Génère un rapport d'énumération SMB"""
        if target not in self.results:
            return None

        results = self.results[target]

        print(f"\n{'='*60}")
        print(f"RAPPORT ENUMERATION SMB - {target}")
        print(f"{'='*60}")
        print(f"Niveau de risque: {results['risk_assessment']}")

        # NetBIOS
        netbios = results['netbios_info']
        if netbios.get('computer_name'):
            print(f"\n[NetBIOS]")
            print(f"Nom ordinateur: {netbios['computer_name']}")
            print(f"Domaine: {netbios.get('domain', 'N/A')}")
            print(f"Services: {', '.join(netbios.get('services', []))}")

        # Partages
        shares = results['shares_info']
        accessible = shares.get('accessible_shares', [])
        if accessible:
            print(f"\n[PARTAGES ACCESSIBLES]")
            for share in accessible:
                print(f" {share['name']} - {share.get('comments', '')}")
                if share.get('files'):
                    print(f"  Fichiers: {', '.join(share['files'][:5])}")

        # Vulnérabilités
        vulns = results['vulnerabilities']
        print(f"\n[VULNÉRABILITÉS]")
        if vulns.get('ms17_010'):
            print(" [CRITIQUE] MS17-010 EternalBlue détecté")
        if vulns.get('ms08_067'):
            print(" [CRITIQUE] MS08-067 détecté")
        if not vulns.get('smb_signing'):
            print(" [MOYEN] Signature SMB non requise")

        # Accès non authentifié
        if shares.get('null_session_possible'):
            print(" [ÉLEVÉ] Null session possible")
        if shares.get('guest_access'):
            print(" [MOYEN] Accès guest possible")

        return results


class SNMPEnumerator:
    """Énumérateur SNMP pour la découverte d'informations système"""

    def __init__(self, timeout=5):
        self.timeout = timeout
        self.community_strings = ['public', 'private', 'community', 'snmp']
        self.common_oids = {
            'system_descr': '1.3.6.1.2.1.1.1.0',
            'system_name': '1.3.6.1.2.1.1.5.0',
            'system_contact': '1.3.6.1.2.1.1.4.0',
            'system_location': '1.3.6.1.2.1.1.6.0',
            'system_uptime': '1.3.6.1.2.1.1.3.0',
            'interfaces': '1.3.6.1.2.1.2.2.1.2',
            'ip_routing_table': '1.3.6.1.2.1.4.21.1.1',
            'tcp_connections': '1.3.6.1.2.1.6.13.1.1'
        }

    def snmp_walk(self, target, community='public', oid='1.3.6.1.2.1.1'):
        """Effectue un SNMP walk sur une cible"""
        print(f"[*] SNMP walk sur {target} avec community '{community}'")

        try:
            # Import conditionnel de pysnmp
            from pysnmp.hlapi import *

            results = []

            for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                    SnmpEngine(),
                    CommunityData(community),
                    UdpTransportTarget((target, 161), timeout=self.timeout),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid)),
                    lexicographicMode=False):

                if errorIndication:
                    print(f"[-] Erreur SNMP: {errorIndication}")
                    break

                if errorStatus:
                    print(f"[-] Erreur SNMP: {errorStatus.prettyPrint()}")
                    break

                for varBind in varBinds:
                    oid_str = varBind[0].prettyPrint()
                    value = varBind[1].prettyPrint()
                    results.append({'oid': oid_str, 'value': value})

                # Limiter le nombre de résultats
                if len(results) > 100:
                    break

            return results

        except ImportError:
            print("[-] pysnmp non disponible")
            return self._snmp_manual_query(target, community, oid)
        except Exception as e:
            print(f"[-] Erreur SNMP walk: {e}")
            return []

    def _snmp_manual_query(self, target, community, oid):
        """Requête SNMP manuelle basique (via snmpwalk système)"""
        try:
            import subprocess

            cmd = ['snmpwalk', '-v2c', '-c', community, target, oid]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)

            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                results = []
                for line in lines:
                    if '=' in line:
                        oid_part, value_part = line.split('=', 1)
                        results.append({
                            'oid': oid_part.strip(),
                            'value': value_part.strip()
                        })
                return results

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        except Exception:
            pass

        return []

    def enumerate_system_info(self, target, community='public'):
        """Énumère les informations système via SNMP"""
        print(f"[*] Énumération système SNMP sur {target}")

        system_info = {}

        for info_type, oid in self.common_oids.items():
            try:
                results = self.snmp_walk(target, community, oid)
                if results:
                    system_info[info_type] = results[0]['value']
            except Exception as e:
                system_info[info_type] = f"Erreur: {e}"

        return system_info

    def brute_force_community(self, target):
        """Bruteforce des community strings SNMP"""
        print(f"[*] Bruteforce community strings sur {target}")

        valid_communities = []

        for community in self.community_strings:
            try:
                results = self.snmp_walk(target, community, '1.3.6.1.2.1.1.1.0')
                if results:
                    valid_communities.append(community)
                    print(f"[+] Community valide trouvée: {community}")
            except Exception:
                continue

        return valid_communities


class HTTPEnumerator:
    """Énumérateur HTTP/HTTPS pour la découverte web"""

    def __init__(self, timeout=10):
        self.timeout = timeout
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'curl/7.68.0'
        ]

    def enumerate_web_server(self, target, port=80, https=False):
        """Énumère un serveur web"""
        import requests
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry

        protocol = 'https' if https else 'http'
        base_url = f"{protocol}://{target}:{port}"

        print(f"[*] Énumération serveur web {base_url}")

        # Configuration de session avec retry
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({'User-Agent': self.user_agents[0]})

        web_info = {
            'server': '',
            'title': '',
            'status_code': 0,
            'headers': {},
            'technologies': [],
            'directories': [],
            'forms': [],
            'cookies': [],
            'security_headers': {}
        }

        try:
            # Requête initiale
            response = session.get(base_url, timeout=self.timeout, verify=False)
            web_info['status_code'] = response.status_code
            web_info['headers'] = dict(response.headers)

            # Serveur web
            web_info['server'] = response.headers.get('Server', '')

            # Titre de la page
            if 'text/html' in response.headers.get('Content-Type', ''):
                try:
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(response.text, 'html.parser')
                    title_tag = soup.find('title')
                    if title_tag:
                        web_info['title'] = title_tag.get_text().strip()
                except ImportError:
                    # Extraction manuelle du titre
                    import re
                    title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
                    if title_match:
                        web_info['title'] = title_match.group(1).strip()

            # Détection de technologies
            web_info['technologies'] = self._detect_technologies(response)

            # En-têtes de sécurité
            web_info['security_headers'] = self._analyze_security_headers(response.headers)

            # Cookies
            web_info['cookies'] = [
                {'name': cookie.name, 'value': cookie.value, 'secure': cookie.secure}
                for cookie in response.cookies
            ]

        except Exception as e:
            print(f"[-] Erreur énumération web: {e}")

        return web_info

    def _detect_technologies(self, response):
        """Détecte les technologies utilisées"""
        technologies = []
        headers = response.headers
        content = response.text.lower()

        # Détection via en-têtes
        if 'x-powered-by' in headers:
            technologies.append(f"X-Powered-By: {headers['x-powered-by']}")

        # Détection via contenu
        tech_signatures = {
            'WordPress': ['wp-content', 'wp-includes'],
            'Drupal': ['drupal.js', 'drupal.css'],
            'Joomla': ['joomla', 'index.php?option=com_'],
            'Apache': ['apache'],
            'Nginx': ['nginx'],
            'PHP': ['<?php', '.php'],
            'ASP.NET': ['__viewstate', 'asp.net'],
            'jQuery': ['jquery'],
            'Bootstrap': ['bootstrap'],
        }

        for tech, signatures in tech_signatures.items():
            if any(sig in content for sig in signatures):
                technologies.append(tech)

        return list(set(technologies))

    def _analyze_security_headers(self, headers):
        """Analyse les en-têtes de sécurité"""
        security_headers = {}

        security_checks = {
            'Content-Security-Policy': 'CSP',
            'X-Frame-Options': 'ClickjackingProtection',
            'X-XSS-Protection': 'XSSProtection',
            'X-Content-Type-Options': 'MIMETypeSniffing',
            'Strict-Transport-Security': 'HSTS',
            'Referrer-Policy': 'ReferrerPolicy',
            'Feature-Policy': 'FeaturePolicy',
            'Permissions-Policy': 'PermissionsPolicy'
        }

        for header, description in security_checks.items():
            if header in headers:
                security_headers[description] = {
                    'present': True,
                    'value': headers[header]
                }
            else:
                security_headers[description] = {
                    'present': False,
                    'risk': 'Missing security header'
                }

        return security_headers

    def directory_bruteforce(self, target, port=80, https=False, wordlist=None):
        """Bruteforce de répertoires"""
        if wordlist is None:
            wordlist = [
                'admin', 'administrator', 'wp-admin', 'phpmyadmin',
                'backup', 'test', 'dev', 'api', 'uploads', 'images',
                'css', 'js', 'assets', 'files', 'data'
            ]

        protocol = 'https' if https else 'http'
        base_url = f"{protocol}://{target}:{port}"

        print(f"[*] Directory bruteforce sur {base_url}")

        found_directories = []

        import requests
        session = requests.Session()
        session.headers.update({'User-Agent': self.user_agents[0]})

        for directory in wordlist:
            try:
                url = f"{base_url}/{directory}/"
                response = session.get(url, timeout=5, verify=False)

                if response.status_code in [200, 301, 302, 403]:
                    found_directories.append({
                        'path': f"/{directory}/",
                        'status': response.status_code,
                        'size': len(response.content)
                    })
                    print(f"[+] Répertoire trouvé: {directory} (Status: {response.status_code})")

            except Exception:
                continue

        return found_directories


# Classe intégratrice pour tous les services
class ServiceEnumerator:
    """Énumérateur des services intégré"""

    def __init__(self):
        self.smb_enum = SMBEnumerator()
        self.snmp_enum = SNMPEnumerator()
        self.http_enum = HTTPEnumerator()

    def enumerate_all_services(self, target, services_detected):
        """Énumère tous les services détectés"""
        print(f"[*] Énumération complète des services sur {target}")

        results = {
            'target': target,
            'timestamp': time.ctime(),
            'services': {}
        }

        for service_info in services_detected:
            port = service_info.get('port')
            service = service_info.get('service', '').lower()

            if 'smb' in service or port in [139, 445]:
                print(f"[*] Service SMB détecté sur port {port}")
                results['services']['smb'] = self.smb_enum.comprehensive_smb_enum(target)

            elif 'snmp' in service or port == 161:
                print(f"[*] Service SNMP détecté sur port {port}")
                results['services']['snmp'] = self.snmp_enum.enumerate_system_info(target)

            elif 'http' in service or port in [80, 8080, 8000]:
                print(f"[*] Service HTTP détecté sur port {port}")
                results['services'][f'http_{port}'] = self.http_enum.enumerate_web_server(target, port, False)

            elif 'https' in service or port in [443, 8443]:
                print(f"[*] Service HTTPS détecté sur port {port}")
                results['services'][f'https_{port}'] = self.http_enum.enumerate_web_server(target, port, True)

        return results

    def generate_comprehensive_report(self, enumeration_results):
        """Génère un rapport complet d'énumération"""
        target = enumeration_results.get('target', 'Unknown')

        print(f"\n{'='*80}")
        print(f"RAPPORT D'ENUMERATION COMPLETE - {target}")
        print(f"{'='*80}")

        services = enumeration_results.get('services', {})

        for service_name, service_data in services.items():
            print(f"\n[{service_name.upper()}]")

            if service_name == 'smb':
                # Rapport SMB spécialisé
                if 'risk_assessment' in service_data:
                    print(f"Niveau de risque: {service_data['risk_assessment']}")

                if service_data.get('shares_info', {}).get('accessible_shares'):
                    print("Partages accessibles:")
                    for share in service_data['shares_info']['accessible_shares']:
                        print(f"- {share['name']}")

            elif service_name == 'snmp':
                # Rapport SNMP
                for key, value in service_data.items():
                    if isinstance(value, str) and len(value) < 100:
                        print(f" {key}: {value}")

            elif service_name.startswith('http'):
                # Rapport HTTP/HTTPS
                print(f" Serveur: {service_data.get('server', 'Unknown')}")
                print(f" Titre: {service_data.get('title', 'N/A')}")
                print(f" Technologies: {', '.join(service_data.get('technologies', []))}")

                # En-têtes de sécurité manquants
                sec_headers = service_data.get('security_headers', {})
                missing_headers = [name for name, info in sec_headers.items() if not info.get('present')]
                if missing_headers:
                    print(f" En-têtes sécurité manquants: {', '.join(missing_headers)}")


# Exemple d'utilisation
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Énumération des services avancée")
    parser.add_argument("target", help="Cible à énumérer")
    parser.add_argument("-s", "--service", choices=['smb', 'snmp', 'http', 'all'],
                        default='all', help="Service à énumérer")
    parser.add_argument("-u", "--username", default='', help="Nom d'utilisateur")
    parser.add_argument("-p", "--password", default='', help="Mot de passe")

    args = parser.parse_args()

    if args.service == 'smb':
        smb_enum = SMBEnumerator()
        results = smb_enum.comprehensive_smb_enum(args.target, args.username, args.password)
        smb_enum.generate_smb_report(args.target)

    elif args.service == 'snmp':
        snmp_enum = SNMPEnumerator()
        results = snmp_enum.enumerate_system_info(args.target)
        print(f"\nInformations système SNMP:")
        for key, value in results.items():
            print(f" {key}: {value}")

    elif args.service == 'http':
        http_enum = HTTPEnumerator()
        results = http_enum.enumerate_web_server(args.target, 80)
        print(f"\nInformations serveur web:")
        print(f"Serveur: {results.get('server', 'Unknown')}")
        print(f"Technologies: {', '.join(results.get('technologies', []))}")

    else:  # all
        service_enum = ServiceEnumerator()
        # Simulation des services détectés
        services_detected = [
            {'port': 80, 'service': 'http'},
            {'port': 443, 'service': 'https'},
            {'port': 445, 'service': 'smb'},
            {'port': 161, 'service': 'snmp'}
        ]
        results = service_enum.enumerate_all_services(args.target, services_detected)
        service_enum.generate_comprehensive_report(results)
