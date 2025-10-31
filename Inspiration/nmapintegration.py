#!/usr/bin/env python3
"""
Interface avancée pour Nmap avec python-nmap
Détection d’OS, services, et utilisation des scripts NSE
"""

import nmap
import xml.etree.ElementTree as ET
import json
import subprocess
import time
import os
from collections import defaultdict
from datetime import datetime
from network_structures import NetworkScanResults, PortScanResult


class AdvancedNmapScanner:
    """Interface avancée pour Nmap avec fonctionnalités étendues"""
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.scan_results = NetworkScanResults()
        self.nmap_path = self._find_nmap_binary()
        self.timing_profiles = {
            'paranoid': '-T0',
            'sneaky': '-T1',
            'polite': '-T2',
            'normal': '-T3',
            'aggressive': '-T4',
            'insane': '-T5'
        }
        self.last_scan_xml = None

    def _find_nmap_binary(self):
        """Trouve le chemin vers l'exécutable Nmap"""
        try:
            result = subprocess.run(['which', 'nmap'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass

        # Chemins par défaut
        common_paths = ['/usr/bin/nmap', '/usr/local/bin/nmap', r'C:\Program Files\Nmap\nmap.exe']
        for path in common_paths:
            if os.path.exists(path):
                return path
        return 'nmap'  # Espérer qu'il soit dans PATH

    def comprehensive_scan(self, targets, timing='normal', enable_os_detection=True,
                           enable_service_detection=True, enable_scripts=True):
        """Scan complet avec toutes les fonctionnalités"""
        print(f"[*] Lancement du scan complet sur {targets}")

        # Construction des arguments Nmap
        nmap_args = []

        # Profil de timing
        if timing in self.timing_profiles:
            nmap_args.append(self.timing_profiles[timing])

        # Détection d'OS
        if enable_os_detection:
            nmap_args.append('-O')

        # Détection des services et versions
        if enable_service_detection:
            nmap_args.append('-sV')

        # Scripts par défaut
        if enable_scripts:
            nmap_args.append('-sC')

        # Options supplémentaires
        nmap_args.extend(['-v', '--reason'])

        arguments = ' '.join(nmap_args)

        try:
            print(f"[*] Exécution : nmap {arguments} {targets}")
            scan_result = self.nm.scan(targets, arguments=arguments)

            # Traitement des résultats
            return self._process_comprehensive_results(scan_result)

        except Exception as e:
            print(f"[-] Erreur scan complet : {e}")
            return None

    def _process_comprehensive_results(self, scan_result):
        """Traite les résultats d'un scan complet"""
        processed_results = {
            'scan_info': scan_result.get('nmap', {}),
            'hosts': {}
        }

        for host in self.nm.all_hosts():
            host_info = {
                'ip': host,
                'hostname': self.nm[host].hostname(),
                'state': self.nm[host].state(),
                'protocols': {},
                'os_detection': {},
                'script_results': {}
            }

            # Détection d'OS (osmatch)
            if 'osmatch' in self.nm[host]:
                os_matches = []
                for osmatch in self.nm[host]['osmatch']:
                    os_matches.append({
                        'name': osmatch.get('name', ''),
                        'accuracy': osmatch.get('accuracy', ''),
                        'line': osmatch.get('line', '')
                    })
                host_info['os_detection']['matches'] = os_matches

            # Détection d'OS (osclass)
            if 'osclass' in self.nm[host]:
                os_classes = []
                for osclass in self.nm[host]['osclass']:
                    os_classes.append({
                        'type': osclass.get('type', ''),
                        'vendor': osclass.get('vendor', ''),
                        'osfamily': osclass.get('osfamily', ''),
                        'osgen': osclass.get('osgen', ''),
                        'accuracy': osclass.get('accuracy', '')
                    })
                host_info['os_detection']['classes'] = os_classes

            # Ports et services
            for protocol in self.nm[host].all_protocols():
                ports_info = []
                ports = self.nm[host][protocol].keys()

                for port in sorted(ports):
                    port_info = self.nm[host][protocol][port]

                    # Création d'un PortScanResult
                    scan_result_obj = PortScanResult(
                        port=port,
                        protocol=protocol,
                        state=port_info.get('state', ''),
                        service=port_info.get('name', ''),
                        version=f"{port_info.get('product','')}{port_info.get('version','')}".strip(),
                        banner=port_info.get('extrainfo', ''),
                        response_time=0,
                        scan_technique='nmap_comprehensive'
                    )

                    # Ajout aux résultats
                    self.scan_results.add_port_scan(host, [scan_result_obj])

                    ports_info.append({
                        'port': port,
                        'state': port_info.get('state', ''),
                        'service': port_info.get('name', ''),
                        'product': port_info.get('product', ''),
                        'version': port_info.get('version', ''),
                        'extrainfo': port_info.get('extrainfo', ''),
                        'reason': port_info.get('reason', ''),
                        'cpe': port_info.get('cpe', '')
                    })

                host_info['protocols'][protocol] = ports_info

            # Scripts NSE au niveau host
            if 'hostscript' in self.nm[host]:
                for script in self.nm[host]['hostscript']:
                    host_info['script_results'][script.get('id', '')] = {
                        'output': script.get('output', ''),
                        'elements': script.get('elements', {})
                    }

            # Scripts au niveau port
            for protocol in self.nm[host].all_protocols():
                ports = self.nm[host][protocol].keys()
                for port in ports:
                    if 'script' in self.nm[host][protocol][port]:
                        port_scripts = self.nm[host][protocol][port]['script']
                        key = f"{port}_{protocol}"
                        if key not in host_info['script_results']:
                            host_info['script_results'][key] = {}
                        # port_scripts est un dict {script_id: output}
                        host_info['script_results'][key].update(port_scripts)

            processed_results['hosts'][host] = host_info

        return processed_results

    def vulnerability_scan(self, targets, script_categories=None):
        """Scan de vulnérabilités avec scripts NSE"""
        if script_categories is None:
            script_categories = ['vuln', 'safe']

        script_args = '--script=' + ','.join(script_categories)

        print(f"[*] Scan de vulnérabilités avec scripts : {script_categories}")

        try:
            scan_result = self.nm.scan(targets, arguments=f'-sV {script_args}')
            return self._process_vulnerability_results(scan_result)
        except Exception as e:
            print(f"[-] Erreur scan vulnérabilités : {e}")
            return None

    def _process_vulnerability_results(self, scan_result):
        """Traite les résultats des scans de vulnérabilités"""
        vulnerabilities = defaultdict(list)

        for host in self.nm.all_hosts():
            # Scripts au niveau host
            if 'hostscript' in self.nm[host]:
                for script in self.nm[host]['hostscript']:
                    script_id = script.get('id', '')
                    if 'vuln' in script_id:
                        vuln_info = {
                            'script': script_id,
                            'output': script.get('output', ''),
                            'severity': self._extract_severity(script.get('output', '')),
                            'type': 'host_vulnerability'
                        }
                        vulnerabilities[host].append(vuln_info)

            # Scripts au niveau port
            for protocol in self.nm[host].all_protocols():
                ports = self.nm[host][protocol].keys()
                for port in ports:
                    if 'script' in self.nm[host][protocol][port]:
                        port_scripts = self.nm[host][protocol][port]['script']
                        for script_name, script_output in port_scripts.items():
                            if 'vuln' in script_name:
                                vuln_info = {
                                    'port': port,
                                    'protocol': protocol,
                                    'script': script_name,
                                    'output': script_output,
                                    'severity': self._extract_severity(script_output),
                                    'type': 'port_vulnerability'
                                }
                                vulnerabilities[host].append(vuln_info)

                                # Ajout à la structure de résultats
                                service = self.nm[host][protocol][port].get('name', '')
                                self.scan_results.map_vulnerabilities(host, port, service, [vuln_info])

        return dict(vulnerabilities)

    def _extract_severity(self, script_output):
        """Extrait la sévérité depuis la sortie d'un script"""
        output_lower = (script_output or '').lower()
        if any(keyword in output_lower for keyword in ['critical', 'high']):
            return 'HIGH'
        elif any(keyword in output_lower for keyword in ['medium', 'moderate']):
            return 'MEDIUM'
        elif any(keyword in output_lower for keyword in ['low', 'info']):
            return 'LOW'
        else:
            return 'UNKNOWN'

    def stealth_scan(self, targets, ports='1-1000'):
        """Scan furtif avec techniques d'évasion"""
        print(f"[*] Scan furtif sur {targets}")

        # Techniques d'évasion
        stealth_args = [
            '-sS',          # SYN scan
            '-T1',          # Timing lent
            '-f',           # Fragmentation
            '--randomize-hosts',
            '--data-length', '25'
        ]

        arguments = ' '.join(stealth_args) + f' -p{ports}'

        try:
            scan_result = self.nm.scan(targets, arguments=arguments)
            return self._process_stealth_results(scan_result)
        except Exception as e:
            print(f"[-] Erreur scan furtif : {e}")
            return None

    def _process_stealth_results(self, scan_result):
        """Traite les résultats des scans furtifs"""
        stealth_results = {}

        for host in self.nm.all_hosts():
            host_results = {
                'ip': host,
                'state': self.nm[host].state(),
                'open_ports': [],
                'filtered_ports': [],
                'scan_technique': 'stealth'
            }

            for protocol in self.nm[host].all_protocols():
                ports = self.nm[host][protocol].keys()
                for port in sorted(ports):
                    port_state = self.nm[host][protocol][port].get('state', '')
                    port_service = self.nm[host][protocol][port].get('name', '')
                    if port_state == 'open':
                        host_results['open_ports'].append({
                            'port': port,
                            'service': port_service
                        })
                    elif port_state == 'filtered':
                        host_results['filtered_ports'].append(port)

            stealth_results[host] = host_results

        return stealth_results

    def custom_nse_scan(self, targets, scripts, script_args=None):
        """Exécute des scripts NSE personnalisés"""
        print(f"[*] Exécution scripts NSE : {scripts}")

        nmap_args = ['-sV', f'--script={scripts}']
        if script_args:
            nmap_args.append(f'--script-args={script_args}')

        arguments = ' '.join(nmap_args)

        try:
            scan_result = self.nm.scan(targets, arguments=arguments)
            return self._process_nse_results(scan_result, scripts)
        except Exception as e:
            print(f"[-] Erreur scripts NSE : {e}")
            return None

    def _process_nse_results(self, scan_result, executed_scripts):
        """Traite les résultats des scripts NSE"""
        nse_results = defaultdict(dict)

        for host in self.nm.all_hosts():
            # Scripts au niveau host
            if 'hostscript' in self.nm[host]:
                nse_results[host]['host_scripts'] = nse_results[host].get('host_scripts', {})
                for script in self.nm[host]['hostscript']:
                    nse_results[host]['host_scripts'][script.get('id', '')] = {
                        'output': script.get('output', ''),
                        'elements': script.get('elements', {})
                    }

            # Scripts au niveau port
            nse_results[host]['port_scripts'] = {}
            for protocol in self.nm[host].all_protocols():
                ports = self.nm[host][protocol].keys()
                for port in ports:
                    if 'script' in self.nm[host][protocol][port]:
                        port_key = f"{port}/{protocol}"
                        nse_results[host]['port_scripts'][port_key] = self.nm[host][protocol][port].get('script', {})

        return dict(nse_results)

    def udp_service_scan(self, targets, top_ports=100):
        """Scan UDP avec détection des services sur les top ports"""
        print(f"[*] Scan UDP services sur top {top_ports} ports")

        arguments = f'-sU --top-ports {top_ports} -sV'

        try:
            scan_result = self.nm.scan(targets, arguments=arguments)
            return self._process_udp_results(scan_result)
        except Exception as e:
            print(f"[-] Erreur scan UDP : {e}")
            return None

    def _process_udp_results(self, scan_result):
        """Traite les résultats des scans UDP"""
        udp_results = {}

        for host in self.nm.all_hosts():
            if 'udp' in self.nm[host].all_protocols():
                host_udp = {
                    'ip': host,
                    'udp_ports': []
                }

                ports = self.nm[host]['udp'].keys()
                for port in sorted(ports):
                    port_info = self.nm[host]['udp'][port]
                    udp_port = {
                        'port': port,
                        'state': port_info.get('state', ''),
                        'service': port_info.get('name', ''),
                        'version': f"{port_info.get('product','')}{port_info.get('version','')}".strip(),
                        'reason': port_info.get('reason', '')
                    }

                    host_udp['udp_ports'].append(udp_port)

                    # Ajout à la structure de résultats
                    scan_result_obj = PortScanResult(
                        port=port,
                        protocol='udp',
                        state=port_info.get('state', ''),
                        service=port_info.get('name', ''),
                        version=udp_port['version'],
                        banner='',
                        response_time=0,
                        scan_technique='nmap_udp'
                    )

                    self.scan_results.add_port_scan(host, [scan_result_obj])

                udp_results[host] = host_udp

        return udp_results

    def export_results(self, filename, format='json'):
        """Exporte les résultats dans différents formats"""
        try:
            if format.lower() == 'json':
                results = self.scan_results.generate_comprehensive_report('dict')
                with open(f"{filename}.json", 'w') as f:
                    json.dump(results, f, indent=2, default=str)
                print(f"[+] Résultats exportés vers {filename}.json")

            elif format.lower() == 'xml' and self.last_scan_xml:
                with open(f"{filename}.xml", 'w') as f:
                    f.write(self.last_scan_xml)
                print(f"[+] Résultats XML exportés vers {filename}.xml")

        except Exception as e:
            print(f"[-] Erreur export : {e}")

    def generate_comprehensive_report(self, target, results):
        """Génère un rapport complet"""
        print(f"\n{'=' * 80}")
        print(f"RAPPORT NMAP COMPLET - {target}")
        print(f"{'=' * 80}")
        print(f"Date de scan : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        if not results or 'hosts' not in results:
            print("Aucun résultat disponible")
            return

        for host_ip, host_data in results['hosts'].items():
            print(f"\n[HOST] {host_ip}")
            if host_data.get('hostname'):
                print(f"Hostname : {host_data['hostname']}")
            print(f"État : {host_data.get('state', '')}")

            # Détection d'OS
            if host_data.get('os_detection', {}).get('matches'):
                print("\n[OS DETECTION]")
                for match in host_data['os_detection']['matches'][:3]:
                    print(f" {match.get('name','')} (Accuracy: {match.get('accuracy','')}%)")

            # Ports et services
            for protocol, ports in host_data.get('protocols', {}).items():
                if ports:
                    print(f"\n[{protocol.upper()} PORTS]")
                    for port in ports:
                        if port.get('state') == 'open':
                            service_info = f"{port.get('service','')}"
                            if port.get('product'):
                                service_info += f"({port.get('product','')}"
                                if port.get('version'):
                                    service_info += f"{port.get('version','')}"
                                service_info += ")"
                            print(f" {port.get('port')}/{protocol} - {service_info}")

            # Vulnérabilités détectées via scripts
            if host_data.get('script_results'):
                vuln_scripts = {k: v for k, v in host_data['script_results'].items() if 'vuln' in k}
                if vuln_scripts:
                    print("\n[VULNÉRABILITÉS DÉTECTÉES]")
                    for script_name, script_data in vuln_scripts.items():
                        print(f" Script: {script_name}")
                        output_lines = script_data.get('output', '').split('\n')[:3]
                        for line in output_lines:
                            if line.strip():
                                print(f"  {line.strip()}")


class NmapResultsAnalyzer:
    """Analyseur des résultats Nmap pour extraction d'informations"""
    def __init__(self):
        self.vulnerability_keywords = [
            'vulnerable', 'exploit', 'backdoor', 'weak', 'insecure',
            'disclosure', 'injection', 'overflow', 'traversal'
        ]

    def extract_critical_findings(self, nmap_results):
        """Extrait les découvertes critiques des résultats"""
        findings = {
            'critical_services': [],
            'vulnerable_services': [],
            'suspicious_ports': [],
            'weak_configurations': []
        }

        if not nmap_results or 'hosts' not in nmap_results:
            return findings

        for host_ip, host_data in nmap_results['hosts'].items():
            # Services critiques
            for protocol, ports in host_data.get('protocols', {}).items():
                for port in ports:
                    if port.get('state') == 'open':
                        # Services à risque
                        if port.get('port') in [23, 135, 445, 1433, 3306, 3389, 5432]:
                            findings['critical_services'].append({
                                'host': host_ip,
                                'port': port.get('port'),
                                'service': port.get('service'),
                                'reason': 'Service à risque élevé'
                            })
                        # Ports non-standards
                        if port.get('port') and port.get('port') > 49152:
                            findings['suspicious_ports'].append({
                                'host': host_ip,
                                'port': port.get('port'),
                                'service': port.get('service')
                            })

            # Analyse des scripts pour vulnérabilités
            for script_name, script_data in host_data.get('script_results', {}).items():
                script_output = (script_data.get('output', '') or '').lower()
                if any(keyword in script_output for keyword in self.vulnerability_keywords):
                    findings['vulnerable_services'].append({
                        'host': host_ip,
                        'script': script_name,
                        'finding': (script_data.get('output', '') or '')[:200] + '...'
                    })

        return findings

    def generate_executive_summary(self, nmap_results):
        """Génère un résumé exécutif des résultats"""
        summary = {
            'total_hosts': 0,
            'total_open_ports': 0,
            'critical_findings': 0,
            'top_services': {},
            'security_score': 0
        }

        if not nmap_results or 'hosts' not in nmap_results:
            return summary

        summary['total_hosts'] = len(nmap_results['hosts'])
        service_count = defaultdict(int)

        for host_ip, host_data in nmap_results['hosts'].items():
            for protocol, ports in host_data.get('protocols', {}).items():
                for port in ports:
                    if port.get('state') == 'open':
                        summary['total_open_ports'] += 1
                        service_count[port.get('service', '')] += 1

        # Top 5 services
        summary['top_services'] = dict(
            sorted(service_count.items(), key=lambda x: x[1], reverse=True)[:5]
        )

        # Score de sécurité basique (100 - pénalités)
        security_score = 100
        findings = self.extract_critical_findings(nmap_results)

        security_score -= len(findings['critical_services']) * 10
        security_score -= len(findings['vulnerable_services']) * 15
        security_score -= len(findings['suspicious_ports']) * 5

        summary['security_score'] = max(0, security_score)
        summary['critical_findings'] = len(findings['critical_services']) + len(findings['vulnerable_services'])

        return summary


# Exemple d'utilisation
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Scanner Nmap avancé")
    parser.add_argument("targets", help="Cibles à scanner")
    parser.add_argument("-t", "--type", choices=['comprehensive', 'vuln', 'stealth', 'udp'],
                        default='comprehensive', help="Type de scan")
    parser.add_argument("--timing", choices=['paranoid', 'sneaky', 'polite', 'normal', 'aggressive', 'insane'],
                        default='normal', help="Profil de timing")
    parser.add_argument("-o", "--output", help="Fichier de sortie (sans extension)")

    args = parser.parse_args()

    scanner = AdvancedNmapScanner()
    results = None

    if args.type == 'comprehensive':
        results = scanner.comprehensive_scan(args.targets, timing=args.timing)
        if results:
            scanner.generate_comprehensive_report(args.targets, results)

    elif args.type == 'vuln':
        results = scanner.vulnerability_scan(args.targets)
        if results:
            print("\n[VULNÉRABILITÉS TROUVÉES]")
            for host, vulns in results.items():
                print(f"\nHost: {host}")
                for vuln in vulns:
                    print(f" {vuln.get('script','')} - {vuln.get('severity','')}")

    elif args.type == 'stealth':
        results = scanner.stealth_scan(args.targets)
        if results:
            for host, data in results.items():
                print(f"\n[STEALTH] {host}: {len(data.get('open_ports', []))} ports ouverts")

    elif args.type == 'udp':
        results = scanner.udp_service_scan(args.targets)
        if results:
            for host, data in results.items():
                print(f"\n[UDP] {host}: {len(data.get('udp_ports', []))} ports UDP")

    # Export si demandé
    if args.output:
        scanner.export_results(args.output)

    # Analyse critique
    if 'results' in locals() and results:
        analyzer = NmapResultsAnalyzer()
        findings = analyzer.extract_critical_findings(results)
        summary = analyzer.generate_executive_summary(results)

        print(f"\n[RÉSUMÉ EXÉCUTIF]")
        print(f"Score de sécurité: {summary['security_score']}/100")
        print(f"Découvertes critiques: {summary['critical_findings']}")
