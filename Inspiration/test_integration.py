#!/usr/bin/env python3
"""
Tests d'intégration pour le framework de scanning réseau
Validation complète de tous les composants développés
"""
import unittest
import tempfile
import json
import os
import time
import threading
from unittest.mock import patch, MagicMock

# Imports des modules à tester
from integrated_scanner import IntegratedNetworkScanner, VulnerabilityAssessmentPlugin
from evasion_techniques import AdvancedEvasionScanner, EvasionManager
from tcp_scanner import AdvancedTCPScanner
from udp_scanner import UDPScanner
from smb_enumerator import SMBEnumerator

class TestIntegratedFramework(unittest.TestCase):
    """Tests d'intégration du framework complet"""

    def setUp(self):
        """Configuration des tests"""
        self.test_targets = ["127.0.0.1", "scanme.nmap.org"]
        self.temp_dir = tempfile.mkdtemp()

        # Configuration de test
        self.test_config = {
            'discovery': {'methods': ['icmp']},
            'port_scanning': {'tcp_technique': 'connect', 'enable_udp': False},
            'threads': {'discovery': 5, 'tcp_scan': 10, 'udp_scan': 5},
            'timeouts': {'discovery': 2, 'port_scan': 2, 'udp_scan': 3},
            'output': {'directory': self.temp_dir, 'formats': ['json']}
        }

        # Données OSINT fictives pour test
        self.mock_osint_data = {
            'modules_results': {
                'DNS_Recon': {
                    'dns_records': {
                        'A': ['192.168.1.10', '192.168.1.20']
                    }
                }
            }
        }

        # Création du fichier OSINT temporaire
        self.osint_file = os.path.join(self.temp_dir, 'test_osint.json')
        with open(self.osint_file, 'w') as f:
            json.dump(self.mock_osint_data, f)

    def tearDown(self):
        """Nettoyage après tests"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_framework_initialization(self):
        """Test de l'initialisation du framework"""
        scanner = IntegratedNetworkScanner(self.test_config)

        # Vérification de la configuration
        self.assertEqual(scanner.config['threads']['discovery'], 5)
        self.assertEqual(scanner.config['output']['directory'], self.temp_dir)

        # Vérification de l'initialisation des composants
        self.assertIsNotNone(scanner.host_discovery)
        self.assertIsNotNone(scanner.tcp_scanner)
        self.assertIsNotNone(scanner.udp_scanner)

    def test_osint_integration(self):
        """Test de l'intégration des données OSINT"""
        scanner = IntegratedNetworkScanner(self.test_config)

        # Chargement des données OSINT
        priority_targets = scanner.load_osint_data(self.osint_file)

        # Vérification du chargement
        self.assertEqual(len(priority_targets), 2)
        self.assertIn('192.168.1.10', priority_targets)
        self.assertIn('192.168.1.20', priority_targets)

    def test_discovery_phase(self):
        """Test de la phase de découverte"""
        scanner = IntegratedNetworkScanner(self.test_config)

        # Test avec IP unique
        discovered_hosts = scanner._discovery_phase("127.0.0.1")
        self.assertEqual(len(discovered_hosts), 1)
        self.assertEqual(discovered_hosts[0].ip, "127.0.0.1")

        # Test avec liste d'IPs
        ip_list = ["127.0.0.1", "192.168.1.1"]
        discovered_hosts = scanner._discovery_phase(ip_list)
        self.assertGreaterEqual(len(discovered_hosts), 1) # Au moins localhost

    def test_port_scanning_phase(self):
        """Test de la phase de scanning des ports"""
        scanner = IntegratedNetworkScanner(self.test_config)

        # Création d'un hôte de test
        from network_structures import Host
        test_host = Host(
            ip="127.0.0.1",
            hostname="localhost",
            os_guess="",
            open_ports=[],
            filtered_ports=[],
            closed_ports=[],
            response_time=0,
            last_seen=time.time()
        )

        # Test du scanning
        port_results = scanner._port_scanning_phase([test_host], 'quick')

        # Vérification des résultats
        self.assertIn("127.0.0.1", port_results)
        self.assertIsInstance(port_results["127.0.0.1"], list)

    def test_vulnerability_extraction(self):
        """Test de l'extraction de vulnérabilités"""
        scanner = IntegratedNetworkScanner(self.test_config)

        # Données d'énumération fictives avec vulnérabilités SMB
        mock_enumeration_data = {
            'services': {
                'smb': {
                    'vulnerabilities': {
                        'ms17_010': True,
                        'smb_signing': False
                    }
                }
            }
        }

        # Test d'extraction
        vulnerabilities = scanner._extract_vulnerabilities(mock_enumeration_data)

        # Vérifications
        self.assertGreater(len(vulnerabilities), 0)
        vuln_ids = [v['id'] for v in vulnerabilities]
        self.assertIn('MS17-010', vuln_ids)
        self.assertIn('SMB-SIGNING', vuln_ids)

    def test_risk_assessment(self):
        """Test de l'évaluation des risques"""
        scanner = IntegratedNetworkScanner(self.test_config)

        # Hôte avec vulnérabilité critique
        high_risk_host = {
            'vulnerabilities': [
                {'severity': 'CRITICAL', 'id': 'MS17-010'},
                {'severity': 'MEDIUM', 'id': 'SMB-SIGNING'}
            ],
            'open_ports': [
                {'service': 'smb', 'port': 445}
            ]
        }
        risk_level = scanner._assess_host_risk(high_risk_host)
        self.assertIn(risk_level, ['CRITICAL', 'HIGH'])

        # Hôte à faible risque
        low_risk_host = {
            'vulnerabilities': [],
            'open_ports': [
                {'service': 'http', 'port': 80}
            ]
        }
        risk_level = scanner._assess_host_risk(low_risk_host)
        self.assertEqual(risk_level, 'LOW')

    def test_report_generation(self):
        """Test de la génération de rapports"""
        scanner = IntegratedNetworkScanner(self.test_config)

        # Résultats fictifs
        mock_results = {
            '127.0.0.1': {
                'ip': '127.0.0.1',
                'risk_level': 'LOW',
                'open_ports': [{'port': 80, 'protocol': 'tcp', 'service': 'http'}],
                'vulnerabilities': [],
                'recommendations': []
            }
        }

        # Test génération JSON
        scanner._generate_json_report(mock_results, os.path.join(self.temp_dir, 'test_report.json'))

        # Vérification du fichier généré
        report_file = os.path.join(self.temp_dir, 'test_report.json')
        self.assertTrue(os.path.exists(report_file))

        with open(report_file, 'r') as f:
            report_data = json.load(f)
        self.assertIn('scan_info', report_data)
        self.assertIn('results', report_data)
        self.assertEqual(len(report_data['results']), 1)

    def test_plugin_system(self):
        """Test du système de plugins"""
        scanner = IntegratedNetworkScanner(self.test_config)

        # Ajout d'un plugin
        vuln_plugin = VulnerabilityAssessmentPlugin()
        scanner.active_plugins.append(vuln_plugin)

        # Données d'hôte avec service Apache
        host_data = {
            'open_ports': [
                {'port': 80, 'service': 'apache', 'version': '2.4.41'}
            ]
        }

        # Application du plugin
        enriched_data = vuln_plugin.process_host('192.168.1.10', host_data)

        # Vérification de l'enrichissement
        if 'vulnerabilities' in enriched_data:
            vuln_ids = [v['id'] for v in enriched_data['vulnerabilities']]
            self.assertTrue(any('CVE-' in vid for vid in vuln_ids))


class TestEvasionTechniques(unittest.TestCase):
    """Tests des techniques d'évasion"""

    def setUp(self):
        """Configuration des tests d'évasion"""
        self.evasion_scanner = AdvancedEvasionScanner()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Nettoyage"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_evasion_manager(self):
        """Test du gestionnaire d'évasion"""
        manager = EvasionManager()

        # Test d'activation de techniques
        manager.enable_technique('user_agent_rotation')
        self.assertIn('user_agent_rotation', manager.enabled_techniques)

        # Test du profil temporel
        manager.set_timing_profile('paranoid')
        self.assertEqual(manager.current_profile, 'paranoid')

        # Test du délai adaptatif
        delay = manager.get_adaptive_delay()
        self.assertIsInstance(delay, float)
        self.assertGreaterEqual(delay, 0)

    def test_user_agent_rotation(self):
        """Test de la rotation des User-Agents"""
        from evasion_techniques import UserAgentRotator

        rotator = UserAgentRotator()

        # Test UA aléatoire
        ua1 = rotator.get_random_user_agent()
        ua2 = rotator.get_random_user_agent()
        self.assertIsInstance(ua1, str)
        self.assertGreater(len(ua1), 10)

        # Test rotation séquentielle
        ua3 = rotator.get_next_user_agent()
        ua4 = rotator.get_next_user_agent()
        self.assertNotEqual(ua3, ua4) # Devrait être différent en rotation

    def test_traffic_shaper(self):
        """Test du Traffic Shaper"""
        from evasion_techniques import TrafficShaper

        shaper = TrafficShaper()

        # Configuration de la limite
        shaper.set_bandwidth_limit(1000) # 1000 bytes/sec
        self.assertEqual(shaper.bandwidth_limit, 1000)

        # Test de throttling
        should_throttle = shaper.should_throttle(500)
        self.assertIsInstance(should_throttle, bool)

        # Test de calcul de délai
        delay = shaper.calculate_delay(100)
        self.assertIsInstance(delay, float)
        self.assertGreaterEqual(delay, 0)

    def test_proxy_rotation(self):
        """Test de la rotation de proxies"""
        from evasion_techniques import ProxyRotator

        rotator = ProxyRotator()

        # Création d'un fichier de proxies de test
        proxy_file = os.path.join(self.temp_dir, 'test_proxies.txt')
        with open(proxy_file, 'w') as f:
            f.write("192.168.1.10:8080\n")
            f.write("192.168.1.11:3128:user:pass\n")
            f.write("# Commentaire\n")
            f.write("192.168.1.12:1080\n")

        # Chargement des proxies
        rotator.load_proxies_from_file(proxy_file)
        self.assertEqual(len(rotator.proxies), 3)

        # Test de récupération de proxy
        proxy = rotator.get_next_proxy()
        self.assertIsNotNone(proxy)
        self.assertIn('host', proxy)
        self.assertIn('port', proxy)

    def test_evasion_configuration(self):
        """Test de la configuration d'évasion"""
        scanner = AdvancedEvasionScanner()
        config = {
            'timing_profile': 'careful',
            'bandwidth_limit': 2048,
            'techniques': ['user_agent_rotation', 'header_manipulation']
        }
        scanner.configure_evasion(config)

        # Vérifications
        self.assertEqual(scanner.evasion_manager.current_profile, 'careful')
        self.assertEqual(scanner.traffic_shaper.bandwidth_limit, 2048)
        self.assertIn('user_agent_rotation', scanner.evasion_manager.enabled_techniques)


class TestPerformanceAndStability(unittest.TestCase):
    """Tests de performance et de stabilité"""

    def test_concurrent_scanning(self):
        """Test de scanning concurrent"""
        scanner = AdvancedTCPScanner(max_threads=10, timeout=1)

        # Test de scan concurrent sur localhost
        start_time = time.time()
        results = scanner.scan_common_ports("127.0.0.1", 'tcp_connect')
        end_time = time.time()

        # Vérifications
        self.assertIsInstance(results, list)
        scan_duration = end_time - start_time
        self.assertLess(scan_duration, 30) # Devrait prendre moins de 30 secondes

    def test_memory_usage(self):
        """Test basique d'utilisation mémoire"""
        import psutil
        import os

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss

        # Création de multiples scanners
        scanners = []
        for i in range(10):
            scanner = IntegratedNetworkScanner()
            scanners.append(scanner)

        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory

        # Vérification que l'augmentation mémoire reste raisonnable
        self.assertLess(memory_increase, 100 * 1024 * 1024) # Moins de 100MB

    def test_error_handling(self):
        """Test de la gestion d'erreurs"""
        scanner = IntegratedNetworkScanner()

        # Test avec cible invalide
        try:
            results = scanner._discovery_phase("999.999.999.999")
            # Devrait gérer gracieusement l'erreur
            self.assertIsInstance(results, list)
        except Exception as e:
            self.fail(f"La gestion d'erreur a échoué: {e}")

        # Test avec fichier OSINT inexistant
        priority_targets = scanner.load_osint_data("fichier_inexistant.json")
        self.assertEqual(priority_targets, [])


class TestModularComponents(unittest.TestCase):
    """Tests des composants modulaires individuels"""

    def test_tcp_scanner_basic(self):
        """Test basique du scanner TCP"""
        scanner = AdvancedTCPScanner(timeout=1)

        # Test sur localhost port 80 (probablement fermé)
        result = scanner.tcp_connect_scan("127.0.0.1", 80)

        self.assertIsNotNone(result)
        self.assertEqual(result.port, 80)
        self.assertIn(result.state, ['open', 'closed', 'filtered'])

    def test_udp_scanner_basic(self):
        """Test basique du scanner UDP"""
        scanner = UDPScanner(timeout=2)

        # Test sur localhost port 53 (DNS)
        result = scanner.udp_scan("127.0.0.1", 53)

        self.assertIsNotNone(result)
        self.assertEqual(result.port, 53)
        self.assertIn(result.state, ['open', 'open|filtered', 'closed'])

    def test_smb_enumerator_basic(self):
        """Test basique de l'énumérateur SMB"""
        enumerator = SMBEnumerator(timeout=2)

        # Test NetBIOS query sur localhost (devrait échouer proprement)
        netbios_info = enumerator.netbios_name_query("127.0.0.1")

        self.assertIsInstance(netbios_info, dict)
        self.assertIn('names', netbios_info)
        self.assertIn('domain', netbios_info)


def run_integration_tests():
    """Exécute tous les tests d'intégration"""

    # Création de la suite de tests
    test_suite = unittest.TestSuite()

    # Ajout des classes de test
    test_classes = [
        TestIntegratedFramework,
        TestEvasionTechniques,
        TestPerformanceAndStability,
        TestModularComponents
    ]

    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)

    # Exécution des tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)

    return result


if __name__ == "__main__":
    print("="*60)
    print("TESTS D'INTÉGRATION - FRAMEWORK DE SCANNING RÉSEAU")
    print("="*60)
    
    # Exécution des tests
    test_result = run_integration_tests()

    # Rapport final
    print("\n" + "="*60)
    print("RAPPORT FINAL DES TESTS")
    print("="*60)
    
    total_tests = test_result.testsRun
    failures = len(test_result.failures)
    errors = len(test_result.errors)
    success = total_tests - failures - errors

    print(f"Tests exécutés: {total_tests}")
    print(f"Succès: {success}")
    print(f"Échecs: {failures}")
    print(f"Erreurs: {errors}")

    if failures > 0:
        print(f"\nÉCHECS ({failures}):")
        for test, traceback in test_result.failures:
            print(f" - {test}: {traceback.split('AssertionError: ')[-1].split('\n')[0]}")

    if errors > 0:
        print(f"\nERREURS ({errors}):")
        for test, traceback in test_result.errors:
            print(f" - {test}: {traceback.split('\n')[-2]}")

    # Calcul du taux de réussite
    success_rate = (success / total_tests) * 100 if total_tests > 0 else 0
    print(f"\nTaux de réussite: {success_rate:.1f}%")

    if success_rate >= 90:
        print(" Framework validé - Excellent travail!")
    elif success_rate >= 75:
        print(" Framework partiellement validé - Corrections mineures nécessaires")
    else:
        print(" Framework nécessite des corrections importantes")
