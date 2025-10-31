#!/usr/bin/env python3

"""
Framework de scanning réseau intégré
Combine découverte, scanning ports, et énumération services
"""

import json
import xml.etree.ElementTree as ET
import time
import threading
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# Imports des modules développés précédemment
from network_structures import NetworkScanner, NetworkScanResults, ScannerFactory
from host_discovery import HostDiscovery, NetworkAnalyzer
from tcp_scanner import AdvancedTCPScanner
from udp_scanner import UDPScanner
from nmap_integration import AdvancedNmapScanner, NmapResultsAnalyzer
from smb_enumerator import ServiceEnumerator

class IntegratedNetworkScanner:
    """Framework de scanning réseau intégré"""

    def __init__(self, config=None):
        self.config = config or self._default_config()

        # Initialisation des composants
        self.host_discovery = HostDiscovery(
            max_threads=self.config['threads']['discovery'],
            timeout=self.config['timeouts']['discovery']
        )

        self.tcp_scanner = AdvancedTCPScanner(
            max_threads=self.config['threads']['tcp_scan'],
            timeout=self.config['timeouts']['port_scan']
        )

        self.udp_scanner = UDPScanner(
            max_threads=self.config['threads']['udp_scan'],
            timeout=self.config['timeouts']['udp_scan']
        )

        self.nmap_scanner = AdvancedNmapScanner()
        self.service_enumerator = ServiceEnumerator()
        self.network_analyzer = NetworkAnalyzer()

        # Résultats consolidés
        self.consolidated_results = NetworkScanResults()
        self.scan_timeline = []
        self.active_plugins = []

    def _default_config(self):
        """Configuration par défaut"""
        return {
            'discovery': {
                'methods': ['arp', 'icmp', 'tcp'],
                'tcp_ports': [22, 80, 443]
            },
            'port_scanning': {
                'tcp_technique': 'connect',
                'enable_udp': True,
                'port_ranges': {
                    'quick': '1-1000',
                    'comprehensive': '1-65535',
                    'common': 'top-1000'
                }
            },
            'service_enumeration': {
                'enable_nmap_scripts': True,
                'enable_custom_enum': True,
                'services': ['smb', 'http', 'snmp', 'ssh']
            },
            'evasion': {
                'enable': False,
                'techniques': ['timing', 'fragmentation'],
                'timing_profile': 'normal'
            },
            'threads': {
                'discovery': 50,
                'tcp_scan': 100,
                'udp_scan': 20,
                'enumeration': 10
            },
            'timeouts': {
                'discovery': 3,
                'port_scan': 3,
                'udp_scan': 5,
                'enumeration': 10
            },
            'output': {
                'formats': ['json', 'xml', 'html'],
                'directory': './scan_results',
                'timestamp': True
            }
        }

    def load_osint_data(self, osint_file):
        """Charge les données OSINT du TP2 pour prioriser les cibles"""
        try:
            with open(osint_file, 'r') as f:
                osint_data = json.load(f)

            # Extraction des cibles prioritaires
            priority_targets = []

            if 'modules_results' in osint_data:
                results = osint_data['modules_results']
                # IPs depuis DNS
                if 'DNS_Recon' in results:
                    dns_data = results['DNS_Recon']
                    if 'dns_records' in dns_data and 'A' in dns_data['dns_records']:
                        priority_targets.extend(dns_data['dns_records']['A'])

                # Données Shodan si disponibles
                if 'shodan' in osint_data:
                    for host in osint_data['shodan'].get('hosts', []):
                        if 'ip' in host:
                            priority_targets.append(host['ip'])

            print(f"[+] {len(priority_targets)} cibles prioritaires extraites depuis OSINT")
            return priority_targets

        except Exception as e:
            print(f"[-] Erreur chargement OSINT: {e}")
            return []

    def comprehensive_network_scan(self, targets, scan_type='comprehensive', osint_file=None):
        """Scan complet automatisé d'un réseau"""
        print(f"[*] Démarrage scan complet - Type: {scan_type}")
        self._log_timeline("Scan started", {"targets": targets, "type": scan_type})

        # 1. Chargement des données OSINT si disponibles
        priority_targets = []
        if osint_file:
            priority_targets = self.load_osint_data(osint_file)

        # 2. Phase de découverte
        print(f"\n{'='*60}")
        print("PHASE 1: DÉCOUVERTE D'HOTES")
        print(f"{'='*60}")
        discovered_hosts = self._discovery_phase(targets)

        # 3. Priorisation des cibles
        scan_targets = self._prioritize_targets(discovered_hosts, priority_targets)

        # 4. Phase de scanning des ports
        print(f"\n{'='*60}")
        print("PHASE 2: SCANNING DES PORTS")
        print(f"{'='*60}")
        port_results = self._port_scanning_phase(scan_targets, scan_type)

        # 5. Phase d'énumération des services
        print(f"\n{'='*60}")
        print("PHASE 3: ÉNUMÉRATION DES SERVICES")
        print(f"{'='*60}")
        enumeration_results = self._service_enumeration_phase(port_results)

        # 6. Consolidation et analyse
        print(f"\n{'='*60}")
        print("PHASE 4: ANALYSE ET CONSOLIDATION")
        print(f"{'='*60}")
        final_results = self._consolidate_results(discovered_hosts, port_results, enumeration_results)

        # 7. Génération des rapports
        self._generate_reports(final_results)
        self._log_timeline("Scan completed", {"total_hosts": len(final_results)})

        return final_results

    def _discovery_phase(self, targets):
        """Phase de découverte d'hôtes"""
        if isinstance(targets, str):
            # Réseau CIDR ou IP unique
            if '/' in targets:
                discovered_hosts = self.host_discovery.comprehensive_discovery(targets)
            else:
                # IP unique - créer un objet Host
                from network_structures import Host
                host = Host(
                    ip=targets,
                    hostname='',
                    os_guess='',
                    open_ports=[],
                    filtered_ports=[],
                    closed_ports=[],
                    response_time=0,
                    last_seen=time.time()
                )
                discovered_hosts = [host]
        else:
            # Liste d'IPs
            discovered_hosts = []
            for ip in targets:
                # Ping de base pour vérifier l'accessibilité
                if self.host_discovery.icmp_ping(ip):
                    from network_structures import Host
                    host = Host(
                        ip=ip,
                        hostname='',
                        os_guess='',
                        open_ports=[],
                        filtered_ports=[],
                        closed_ports=[],
                        response_time=0,
                        last_seen=time.time()
                    )
                    discovered_hosts.append(host)

        print(f"[+] {len(discovered_hosts)} hôtes découverts")
        self._log_timeline("Discovery completed", {"hosts_found": len(discovered_hosts)})
        return discovered_hosts

    def _prioritize_targets(self, discovered_hosts, priority_ips):
        """Priorise les cibles basées sur les données OSINT"""
        if not priority_ips:
            return discovered_hosts

        # Séparer les cibles prioritaires des autres
        priority_hosts = []
        standard_hosts = []

        for host in discovered_hosts:
            if host.ip in priority_ips:
                priority_hosts.append(host)
                print(f"[+] Cible prioritaire: {host.ip}")
            else:
                standard_hosts.append(host)

        # Retourner d'abord les prioritaires
        return priority_hosts + standard_hosts

    def _port_scanning_phase(self, targets, scan_type):
        """Phase de scanning des ports"""
        port_results = {}

        for host in targets:
            print(f"\n[*] Scanning ports sur {host.ip}")

            # Sélection des ports selon le type de scan
            if scan_type == 'quick':
                # Scan rapide des ports les plus communs
                tcp_results = self.tcp_scanner.scan_common_ports(host.ip, 'tcp_connect')
            elif scan_type == 'comprehensive':
                # Scan complet avec Nmap
                nmap_results = self.nmap_scanner.comprehensive_scan(host.ip, timing='normal')
                tcp_results = self._extract_tcp_results_from_nmap(nmap_results, host.ip)
            elif scan_type == 'stealth':
                # Scan furtif
                tcp_results = self.tcp_scanner.stealth_scan(host.ip, list(range(1, 1001)))
            else:  # default/custom
                tcp_results = self.tcp_scanner.scan_port_range(host.ip, (1, 1000), 'tcp_connect')

            port_results[host.ip] = tcp_results

            # Scan UDP également
            if self.config['port_scanning']['enable_udp']:
                udp_results = self.udp_scanner.scan_common_udp_ports(host.ip)
                port_results[f"{host.ip}_udp"] = udp_results

            # Pause entre hôtes si évasion activée
            if self.config['evasion']['enable']:
                time.sleep(1)

        self._log_timeline("Port scanning completed", {"hosts_scanned": len(targets)})
        return port_results

    def _extract_tcp_results_from_nmap(self, nmap_results, host_ip):
        """Extrait les résultats TCP depuis les résultats Nmap"""
        tcp_results = []

        if not nmap_results or 'hosts' not in nmap_results:
            return tcp_results

        if host_ip in nmap_results['hosts']:
            host_data = nmap_results['hosts'][host_ip]
            for protocol, ports in host_data.get('protocols', {}).items():
                if protocol == 'tcp':
                    for port_info in ports:
                        if port_info['state'] == 'open':
                            from network_structures import PortScanResult
                            result = PortScanResult(
                                port=port_info['port'],
                                protocol='tcp',
                                state='open',
                                service=port_info['service'],
                                version=f"{port_info.get('product', '')} {port_info.get('version', '')}".strip(),
                                banner=port_info.get('extrainfo', ''),
                                response_time=0,
                                scan_technique='nmap_comprehensive'
                            )
                            tcp_results.append(result)

        return tcp_results

    def _service_enumeration_phase(self, port_results):
        """Phase d'énumération des services"""
        enumeration_results = {}

        for host_ip, port_data in port_results.items():
            if '_udp' in host_ip:
                continue  # Skip UDP results for service enumeration

            print(f"\n[*] Énumération services sur {host_ip}")

            # Identifier les services à énumérer
            services_detected = []

            # Traiter les résultats selon le type
            if isinstance(port_data, list):
                # Résultats de notre scanner
                for port_result in port_data:
                    if hasattr(port_result, 'state') and port_result.state == 'open':
                        services_detected.append({
                            'port': port_result.port,
                            'service': port_result.service,
                            'version': port_result.version
                        })

            # Énumération des services identifiés
            if services_detected:
                host_enum_results = self.service_enumerator.enumerate_all_services(
                    host_ip, services_detected
                )
                enumeration_results[host_ip] = host_enum_results

        self._log_timeline("Service enumeration completed", {"hosts_enumerated": len(enumeration_results)})
        return enumeration_results

    def _consolidate_results(self, discovered_hosts, port_results, enumeration_results):
        """Consolide tous les résultats"""
        consolidated = {}

        for host in discovered_hosts:
            host_ip = host.ip

            # Structure de base
            host_results = {
                'ip': host_ip,
                'hostname': host.hostname,
                'discovery_info': {
                    'method': 'comprehensive',
                    'response_time': host.response_time,
                    'last_seen': host.last_seen
                },
                'open_ports': [],
                'services': {},
                'vulnerabilities': [],
                'risk_level': 'LOW',
                'recommendations': []
            }

            # Ajout des résultats de ports
            if host_ip in port_results:
                tcp_results = port_results[host_ip]
                if isinstance(tcp_results, list):
                    for port_result in tcp_results:
                        if hasattr(port_result, 'state') and port_result.state == 'open':
                            host_results['open_ports'].append({
                                'port': port_result.port,
                                'protocol': port_result.protocol,
                                'service': port_result.service,
                                'version': port_result.version,
                                'banner': port_result.banner
                            })

            # Ajout des résultats d'énumération
            if host_ip in enumeration_results:
                enum_data = enumeration_results[host_ip]
                if 'services' in enum_data:
                    host_results['services'] = enum_data['services']

                # Extraction des vulnérabilités
                host_results['vulnerabilities'] = self._extract_vulnerabilities(enum_data)

            host_results['risk_level'] = self._assess_host_risk(host_results)
            host_results['recommendations'] = self._generate_recommendations(host_results)

            consolidated[host_ip] = host_results

        return consolidated

    def _extract_vulnerabilities(self, enumeration_data):
        """Extrait les vulnérabilités depuis les données d'énumération"""
        vulnerabilities = []

        services = enumeration_data.get('services', {})

        # Vulnérabilités SMB
        if 'smb' in services:
            smb_data = services['smb']
            if smb_data.get('vulnerabilities', {}).get('ms17_010'):
                vulnerabilities.append({
                    'type': 'SMB',
                    'id': 'MS17-010',
                    'description': 'EternalBlue SMB Vulnerability',
                    'severity': 'CRITICAL',
                    'cvss_score': 9.3
                })

            if smb_data.get('vulnerabilities', {}).get('ms08_067'):
                vulnerabilities.append({
                    'type': 'SMB',
                    'id': 'MS08-067',
                    'description': 'Server Service Vulnerability',
                    'severity': 'CRITICAL',
                    'cvss_score': 9.3
                })

            if not smb_data.get('vulnerabilities', {}).get('smb_signing'):
                vulnerabilities.append({
                    'type': 'SMB',
                    'id': 'SMB-SIGNING',
                    'description': 'SMB Signing Not Required',
                    'severity': 'MEDIUM',
                    'cvss_score': 5.0
                })

        # Vulnérabilités HTTP
        for service_name in services:
            if service_name.startswith('http'):
                http_data = services[service_name]
                missing_headers = []
                sec_headers = http_data.get('security_headers', {})

                for header_name, header_info in sec_headers.items():
                    if not header_info.get('present'):
                        missing_headers.append(header_name)

                if missing_headers:
                    vulnerabilities.append({
                        'type': 'HTTP',
                        'id': 'MISSING-SEC-HEADERS',
                        'description': f'Missing security headers: {", ".join(missing_headers)}',
                        'severity': 'LOW',
                        'cvss_score': 2.0
                    })

        return vulnerabilities

    def _assess_host_risk(self, host_results):
        """Évalue le niveau de risque d'un hôte"""
        risk_score = 0

        # Score basé sur les vulnérabilités
        for vuln in host_results.get('vulnerabilities', []):
            if vuln['severity'] == 'CRITICAL':
                risk_score += 40
            elif vuln['severity'] == 'HIGH':
                risk_score += 25
            elif vuln['severity'] == 'MEDIUM':
                risk_score += 10
            elif vuln['severity'] == 'LOW':
                risk_score += 3

        # Score basé sur les services exposés
        sensitive_services = {
            'smb': 15,
            'rdp': 20,
            'ssh': 5,
            'telnet': 25,
            'ftp': 10,
            'snmp': 8
        }

        for port_info in host_results.get('open_ports', []):
            service = port_info.get('service', '').lower()
            for sensitive_service, score in sensitive_services.items():
                if sensitive_service in service:
                    risk_score += score
                    break

        # Détermination du niveau
        if risk_score >= 50:
            return 'CRITICAL'
        elif risk_score >= 30:
            return 'HIGH'
        elif risk_score >= 15:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _generate_recommendations(self, host_results):
        """Génère des recommandations de sécurité"""
        recommendations = []

        # Recommandations basées sur les vulnérabilités
        for vuln in host_results.get('vulnerabilities', []):
            if vuln['id'] == 'MS17-010':
                recommendations.append("URGENT: Appliquer le patch MS17-010 pour corriger EternalBlue")
            elif vuln['id'] == 'MS08-067':
                recommendations.append("URGENT: Appliquer le patch MS08-067")
            elif vuln['id'] == 'SMB-SIGNING':
                recommendations.append("Activer la signature SMB obligatoire")
            elif vuln['id'] == 'MISSING-SEC-HEADERS':
                recommendations.append("Configurer les en-têtes de sécurité HTTP manquants")

        # Recommandations générales
        open_ports = host_results.get('open_ports', [])
        if len(open_ports) > 10:
            recommendations.append("Réduire la surface d'attaque en fermant les ports inutiles")

        # Services à risque
        risky_services = ['telnet', 'ftp', 'snmp']
        for port_info in open_ports:
            service = port_info.get('service', '').lower()
            if any(risky in service for risky in risky_services):
                recommendations.append(f"Considérer la désactivation du service {service} sur le port {port_info['port']}")

        return recommendations

    def _generate_reports(self, consolidated_results):
        """Génère les rapports dans différents formats"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Rapport JSON
        if 'json' in self.config['output']['formats']:
            json_file = f"{self.config['output']['directory']}/scan_report_{timestamp}.json"
            self._generate_json_report(consolidated_results, json_file)

        # Rapport HTML
        if 'html' in self.config['output']['formats']:
            html_file = f"{self.config['output']['directory']}/scan_report_{timestamp}.html"
            self._generate_html_report(consolidated_results, html_file)

        # Rapport XML
        if 'xml' in self.config['output']['formats']:
            xml_file = f"{self.config['output']['directory']}/scan_report_{timestamp}.xml"
            self._generate_xml_report(consolidated_results, xml_file)

        # Rapport console
        self._generate_console_report(consolidated_results)

    def _generate_json_report(self, results, filename):
        """Génère un rapport JSON"""
        try:
            report_data = {
                'scan_info': {
                    'timestamp': datetime.now().isoformat(),
                    'scanner': 'IntegratedNetworkScanner',
                    'version': '1.0',
                    'total_hosts': len(results)
                },
                'timeline': self.scan_timeline,
                'results': results,
                'statistics': self._generate_statistics(results)
            }

            with open(filename, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)

            print(f"[+] Rapport JSON généré: {filename}")

        except Exception as e:
            print(f"[-] Erreur génération JSON: {e}")

    def _generate_html_report(self, results, filename):
        """Génère un rapport HTML"""
        try:
            html_content = f"""
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport de Scan Réseau</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .host {{ border: 1px solid #ddd; margin: 20px 0; padding: 15px; border-radius: 5px; }}
        .critical {{ border-left: 5px solid #e74c3c; }}
        .high {{ border-left: 5px solid #f39c12; }}
        .medium {{ border-left: 5px solid #f1c40f; }}
        .low {{ border-left: 5px solid #27ae60; }}
        .ports {{ margin: 10px 0; }}
        .port {{ display: inline-block; margin: 2px; padding: 3px 8px; background: #ecf0f1; border-radius: 3px; }}
        .vuln {{ background: #ffebee; padding: 10px; margin: 5px 0; border-radius: 3px; }}
        .recommendations {{ background: #e8f5e8; padding: 10px; margin: 10px 0; border-radius: 3px; }}
        ul {{ list-style-type: none; padding-left: 0; }}
        li {{ margin: 5px 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Rapport de Scan Réseau Intégré</h1>
        <p>Généré le: {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}</p>
        <p>Nombre d'hôtes scannés: {len(results)}</p>
    </div>
"""

            for host_ip, host_data in results.items():
                risk_class = host_data.get('risk_level', 'low').lower()

                html_content += f"""
    <div class="host {risk_class}">
        <h2>{host_ip}</h2>
        <p><strong>Niveau de risque:</strong> {host_data.get('risk_level', 'UNKNOWN')}</p>

        <div class="ports">
            <h3>Ports ouverts ({len(host_data.get('open_ports', []))})</h3>
"""

                for port in host_data.get('open_ports', []):
                    html_content += f'<span class="port">{port["port"]}/{port["protocol"]} - {port["service"]}</span>'

                html_content += "</div>"

                # Vulnérabilités
                vulns = host_data.get('vulnerabilities', [])
                if vulns:
                    html_content += "<h3>Vulnérabilités</h3>"
                    for vuln in vulns:
                        html_content += f"""
        <div class="vuln">
            <strong>{vuln['id']}</strong> - {vuln['severity']}<br>
            {vuln['description']}
        </div>
"""

                # Recommandations
                recommendations = host_data.get('recommendations', [])
                if recommendations:
                    html_content += '<div class="recommendations"><h3>Recommandations</h3><ul>'
                    for rec in recommendations:
                        html_content += f"<li> {rec}</li>"
                    html_content += "</ul></div>"

                html_content += "</div>"

            html_content += """
</body>
</html>"""

            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)

            print(f"[+] Rapport HTML généré: {filename}")

        except Exception as e:
            print(f"[-] Erreur génération HTML: {e}")

    def _generate_console_report(self, results):
        """Génère un rapport console résumé"""
        print(f"\n{'='*80}")
        print("RAPPORT DE SCAN RÉSEAU COMPLET")
        print(f"{'='*80}")

        # Statistiques globales
        stats = self._generate_statistics(results)
        print(f"Hôtes scannés: {stats['total_hosts']}")
        print(f"Ports ouverts trouvés: {stats['total_open_ports']}")
        print(f"Services identifiés: {stats['services_identified']}")
        print(f"Vulnérabilités critiques: {stats['critical_vulnerabilities']}")

        # Top des services
        print(f"\nTop services:")
        for service, count in stats['top_services'].items():
            print(f"  {service}: {count}")

        # Hôtes à risque élevé
        high_risk_hosts = [ip for ip, data in results.items()
                          if data.get('risk_level') in ['CRITICAL', 'HIGH']]

        if high_risk_hosts:
            print(f"\nHOTES À RISQUE ÉLEVÉ:")
            for host_ip in high_risk_hosts:
                host_data = results[host_ip]
                print(f"  {host_ip} - {host_data.get('risk_level')}")
                vulns = [v for v in host_data.get('vulnerabilities', [])
                        if v['severity'] in ['CRITICAL', 'HIGH']]
                for vuln in vulns[:3]:  # Top 3
                    print(f"    {vuln['id']}: {vuln['description']}")

    def _generate_statistics(self, results):
        """Génère des statistiques de scan"""
        stats = {
            'total_hosts': len(results),
            'total_open_ports': 0,
            'services_identified': 0,
            'critical_vulnerabilities': 0,
            'high_vulnerabilities': 0,
            'medium_vulnerabilities': 0,
            'low_vulnerabilities': 0,
            'top_services': defaultdict(int),
            'risk_distribution': defaultdict(int)
        }

        for host_ip, host_data in results.items():
            # Ports
            open_ports = host_data.get('open_ports', [])
            stats['total_open_ports'] += len(open_ports)

            # Services
            stats['services_identified'] += len(host_data.get('services', {}))

            # Distribution des services
            for port in open_ports:
                service = port.get('service', 'unknown')
                stats['top_services'][service] += 1

            # Vulnérabilités par sévérité
            for vuln in host_data.get('vulnerabilities', []):
                severity = vuln['severity'].lower()
                stats[f'{severity}_vulnerabilities'] += 1

            # Distribution des niveaux de risque
            risk_level = host_data.get('risk_level', 'UNKNOWN')
            stats['risk_distribution'][risk_level] += 1

        # Convertir defaultdict en dict normal et trier
        stats['top_services'] = dict(sorted(stats['top_services'].items(),
                                          key=lambda x: x[1], reverse=True)[:10])
        stats['risk_distribution'] = dict(stats['risk_distribution'])

        return stats

    def _log_timeline(self, event, data=None):
        """Enregistre les événements dans la timeline"""
        timeline_entry = {
            'timestamp': datetime.now().isoformat(),
            'event': event,
            'data': data or {}
        }
        self.scan_timeline.append(timeline_entry)


# Plugin system pour extensibilité
class ScanPlugin:
    """Classe de base pour les plugins de scan"""

    def __init__(self, name):
        self.name = name

    def pre_scan(self, targets, config):
        """Exécuté avant le scan"""
        pass

    def post_scan(self, results):
        """Exécuté après le scan"""
        pass

    def process_host(self, host_ip, host_data):
        """Traite les données d'un hôte spécifique"""
        return host_data


class VulnerabilityAssessmentPlugin(ScanPlugin):
    """Plugin d'évaluation de vulnérabilités"""

    def __init__(self):
        super().__init__("VulnerabilityAssessment")
        self.cve_database = self._load_cve_database()

    def _load_cve_database(self):
        """Charge une base de CVE simplifiée"""
        return {
            'apache': {
                '2.4.41': ['CVE-2019-10092', 'CVE-2019-10097'],
                '2.4.38': ['CVE-2019-0211', 'CVE-2019-0215']
            },
            'openssh': {
                '7.4': ['CVE-2018-15473'],
                '6.6': ['CVE-2016-0777', 'CVE-2016-0778']
            },
            'mysql': {
                '5.7.25': ['CVE-2019-2740'],
                '5.6.43': ['CVE-2019-2627']
            }
        }

    def process_host(self, host_ip, host_data):
        """Enrichit les données avec des CVE spécifiques"""
        for port_info in host_data.get('open_ports', []):
            service = port_info.get('service', '').lower()
            version = port_info.get('version', '')

            # Recherche de CVE
            cves = self._find_cves(service, version)
            if cves:
                for cve in cves:
                    vuln = {
                        'type': service.upper(),
                        'id': cve,
                        'description': f'Known vulnerability in {service} {version}',
                        'severity': 'MEDIUM',  # Devrait être déterminé par la base CVE
                        'cvss_score': 5.0,
                        'port': port_info.get('port')
                    }
                    if 'vulnerabilities' not in host_data:
                        host_data['vulnerabilities'] = []
                    host_data['vulnerabilities'].append(vuln)

        return host_data

    def _find_cves(self, service, version):
        """Trouve les CVE pour un service/version"""
        cves = []
        for service_name, versions in self.cve_database.items():
            if service_name in service:
                for ver, ver_cves in versions.items():
                    if ver in version:
                        cves.extend(ver_cves)
                        break
        return cves


# Exemple d'utilisation et CLI
def main():
    import argparse
    import os

    parser = argparse.ArgumentParser(description="Framework de scanning réseau intégré")
    parser.add_argument("targets", help="Cibles à scanner (IP, réseau CIDR, ou fichier)")
    parser.add_argument("-t", "--type", choices=['quick', 'comprehensive', 'stealth'],
                       default='comprehensive', help="Type de scan")
    parser.add_argument("--osint", help="Fichier OSINT du TP2 pour priorisation")
    parser.add_argument("-o", "--output", default='./scan_results', help="Répertoire de sortie")
    parser.add_argument("--config", help="Fichier de configuration JSON")
    parser.add_argument("--plugins", nargs='+', help="Plugins à activer")

    args = parser.parse_args()

    # Création du répertoire de sortie
    os.makedirs(args.output, exist_ok=True)

    # Chargement de configuration
    config = None
    if args.config and os.path.exists(args.config):
        with open(args.config, 'r') as f:
            config = json.load(f)

    # Initialisation du scanner
    scanner = IntegratedNetworkScanner(config)
    scanner.config['output']['directory'] = args.output

    # Activation des plugins
    if args.plugins:
        if 'vuln' in args.plugins:
            vuln_plugin = VulnerabilityAssessmentPlugin()
            scanner.active_plugins.append(vuln_plugin)

    # Traitement des cibles
    if os.path.isfile(args.targets):
        # Fichier contenant des cibles
        with open(args.targets, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        targets = args.targets

    # Lancement du scan
    results = scanner.comprehensive_network_scan(
        targets=targets,
        scan_type=args.type,
        osint_file=args.osint
    )

    print(f"\n[+] Scan terminé - {len(results)} hôtes analysés")
    print(f"[+] Rapports disponibles dans: {args.output}")


if __name__ == "__main__":
    main()
