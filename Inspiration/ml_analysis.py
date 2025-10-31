#!/usr/bin/env python3
"""
Module d'analyse par apprentissage automatique
Classification et prédiction pour les résultats de scan réseau
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
import joblib
import json

class NetworkMLAnalyzer:
    """Analyseur ML pour données de scan réseau"""

    def __init__(self):
        self.risk_classifier = None
        self.service_predictor = None
        self.anomaly_detector = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()

    def prepare_host_features(self, host_data):
        """Prépare les features d'un hôte pour l'analyse ML"""
        features = {
            'total_open_ports': len(host_data.get('open_ports', [])),
            'has_smb': any('smb' in p.get('service', '').lower() for p in host_data.get('open_ports', [])),
            'has_http': any('http' in p.get('service', '').lower() for p in host_data.get('open_ports', [])),
            'has_ssh': any('ssh' in p.get('service', '').lower() for p in host_data.get('open_ports', [])),
            'has_rdp': any('rdp' in p.get('service', '').lower() for p in host_data.get('open_ports', [])),
            'critical_vulns': sum(1 for v in host_data.get('vulnerabilities', []) if v.get('severity') == 'CRITICAL'),
            'high_vulns': sum(1 for v in host_data.get('vulnerabilities', []) if v.get('severity') == 'HIGH'),
            'medium_vulns': sum(1 for v in host_data.get('vulnerabilities', []) if v.get('severity') == 'MEDIUM'),
            'response_time': host_data.get('discovery_info', {}).get('response_time', 0),
            'port_range_spread': self._calculate_port_spread(host_data.get('open_ports', []))
        }
        return features

    def _calculate_port_spread(self, open_ports):
        """Calcule la dispersion des ports ouverts"""
        if not open_ports:
            return 0
        ports = [p.get('port', 0) for p in open_ports]
        return max(ports) - min(ports) if len(ports) > 1 else 0

    def train_risk_classifier(self, training_data):
        """Entraîne le classificateur de risque"""
        features_list = []
        risk_labels = []

        for host_ip, host_data in training_data.items():
            features = self.prepare_host_features(host_data)
            features_list.append(list(features.values()))
            risk_labels.append(host_data.get('risk_level', 'LOW'))

        X = np.array(features_list)
        y = self.label_encoder.fit_transform(risk_labels)

        # Division train/test
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        # Normalisation
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        # Entraînement
        self.risk_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.risk_classifier.fit(X_train_scaled, y_train)

        # Évaluation
        y_pred = self.risk_classifier.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        print(f"Précision du classificateur de risque: {accuracy:.2f}")
        return accuracy

    def predict_risk_level(self, host_data):
        """Prédit le niveau de risque d'un hôte"""
        if not self.risk_classifier:
            return "UNKNOWN"
        features = self.prepare_host_features(host_data)
        X = np.array([list(features.values())])
        X_scaled = self.scaler.transform(X)
        risk_numeric = self.risk_classifier.predict(X_scaled)[0]
        risk_proba = self.risk_classifier.predict_proba(X_scaled)[0]
        risk_level = self.label_encoder.inverse_transform([risk_numeric])[0]
        confidence = max(risk_proba)
        return {
            'predicted_risk': risk_level,
            'confidence': confidence,
            'probabilities': dict(zip(self.label_encoder.classes_, risk_proba))
        }

    def detect_anomalies(self, scan_results):
        """Détecte les anomalies dans les configurations réseau"""
        features_list = []
        host_ips = []

        for host_ip, host_data in scan_results.items():
            features = self.prepare_host_features(host_data)
            features_list.append(list(features.values()))
            host_ips.append(host_ip)

        if len(features_list) < 2:
            return {}

        X = np.array(features_list)

        # Détection d'anomalies avec Isolation Forest
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        anomaly_scores = self.anomaly_detector.fit_predict(X)

        anomalies = {}
        for i, (host_ip, score) in enumerate(zip(host_ips, anomaly_scores)):
            if score == -1:  # Anomalie détectée
                anomalies[host_ip] = {
                    'anomaly_score': self.anomaly_detector.score_samples([X[i]])[0],
                    'features': dict(zip(
                        ['total_open_ports', 'has_smb', 'has_http', 'has_ssh', 'has_rdp',
                         'critical_vulns', 'high_vulns', 'medium_vulns', 'response_time', 'port_range_spread'],
                        X[i]
                    )),
                    'reason': self._analyze_anomaly_reason(X[i])
                }
        return anomalies

    def _analyze_anomaly_reason(self, features):
        """Analyse la raison d'une anomalie"""
        reasons = []
        if features[0] > 50:  # total_open_ports
            reasons.append("Nombre inhabituellement élevé de ports ouverts")
        if features[5] > 3:  # critical_vulns
            reasons.append("Nombre élevé de vulnérabilités critiques")
        if features[8] > 1000:  # response_time
            reasons.append("Temps de réponse inhabituellement élevé")
        if features[9] > 60000:  # port_range_spread
            reasons.append("Ports ouverts sur une plage très étendue")
        return reasons if reasons else ["Configuration atypique détectée"]

    def generate_intelligent_recommendations(self, host_data, osint_data=None):
        """Génère des recommandations intelligentes basées sur ML"""
        recommendations = []

        # Prédiction de risque
        risk_prediction = self.predict_risk_level(host_data)
        if risk_prediction['predicted_risk'] in ['HIGH', 'CRITICAL']:
            recommendations.append({
                'type': 'URGENT',
                'message': f"Risque {risk_prediction['predicted_risk']} prédit avec {risk_prediction['confidence']:.1%} de confiance",
                'priority': 1
            })

        # Analyse des patterns de ports
        open_ports = host_data.get('open_ports', [])
        port_pattern = self._analyze_port_pattern(open_ports)
        if port_pattern['suspicious']:
            recommendations.append({
                'type': 'SECURITY',
                'message': f"Pattern de ports suspect détecté: {port_pattern['description']}",
                'priority': 2
            })

        # Corrélation OSINT
        if osint_data:
            osint_recommendations = self._correlate_with_osint(host_data, osint_data)
            recommendations.extend(osint_recommendations)

        # Service-specific recommendations
        service_recommendations = self._analyze_services(open_ports)
        recommendations.extend(service_recommendations)

        return sorted(recommendations, key=lambda x: x['priority'])

    def _analyze_port_pattern(self, open_ports):
        """Analyse les patterns de ports ouverts"""
        if not open_ports:
            return {'suspicious': False, 'description': 'Aucun port ouvert'}
        ports = [p.get('port', 0) for p in open_ports]

        # Pattern malware courant
        malware_ports = [1234, 4444, 5555, 6666, 9999]
        if any(port in malware_ports for port in ports):
            return {
                'suspicious': True,
                'description': 'Ports associés à des malwares détectés'
            }

        # Pattern de backdoor
        if len(ports) > 20 and any(port > 30000 for port in ports):
            return {
                'suspicious': True,
                'description': 'Nombreux ports hauts ouverts (possible backdoor)'
            }

        # Pattern normal
        return {'suspicious': False, 'description': 'Pattern de ports standard'}

    def _correlate_with_osint(self, host_data, osint_data):
        """Corrèle les résultats de scan avec les données OSINT"""
        recommendations = []

        # Si l'hôte était dans les données OSINT mais pas dans les résultats attendus
        if 'expected_services' in osint_data:
            expected = set(osint_data['expected_services'])
            found = set(p.get('service', '') for p in host_data.get('open_ports', []))
            missing = expected - found
            unexpected = found - expected

            if missing:
                recommendations.append({
                    'type': 'INVESTIGATION',
                    'message': f"Services attendus manquants: {', '.join(missing)}",
                    'priority': 3
                })

            if unexpected:
                recommendations.append({
                    'type': 'ALERT',
                    'message': f"Services inattendus détectés: {', '.join(unexpected)}",
                    'priority': 2
                })

        return recommendations

    def _analyze_services(self, open_ports):
        """Analyse les services pour des recommandations spécifiques"""
        recommendations = []
        for port_info in open_ports:
            service = port_info.get('service', '').lower()
            port = port_info.get('port')

            # Recommandations par service
            if 'telnet' in service:
                recommendations.append({
                    'type': 'CRITICAL',
                    'message': f'Telnet (port {port}) utilise des communications non chiffrées',
                    'priority': 1
                })
            elif 'ftp' in service and port == 21:
                recommendations.append({
                    'type': 'MEDIUM',
                    'message': f'FTP (port {port}) peut transmettre des mots de passe en clair',
                    'priority': 3
                })
            elif 'http' in service and port == 80:
                recommendations.append({
                    'type': 'LOW',
                    'message': f'HTTP (port {port}) non chiffré détecté, considérer HTTPS',
                    'priority': 4
                })
        return recommendations

    def save_models(self, filepath):
        """Sauvegarde les modèles entraînés"""
        models = {
            'risk_classifier': self.risk_classifier,
            'scaler': self.scaler,
            'label_encoder': self.label_encoder,
            'anomaly_detector': self.anomaly_detector
        }
        joblib.dump(models, filepath)
        print(f"[+] Modèles sauvegardés dans {filepath}")

    def load_models(self, filepath):
        """Charge les modèles pré-entraînés"""
        try:
            models = joblib.load(filepath)
            self.risk_classifier = models['risk_classifier']
            self.scaler = models['scaler']
            self.label_encoder = models['label_encoder']
            self.anomaly_detector = models['anomaly_detector']
            print(f"[+] Modèles chargés depuis {filepath}")
            return True
        except Exception as e:
            print(f"[-] Erreur chargement modèles: {e}")
            return False

# Exemple d'utilisation du module ML
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Analyse ML des résultats de scan")
    parser.add_argument("scan_results", help="Fichier JSON des résultats de scan")
    parser.add_argument("--train", action="store_true", help="Entraîner les modèles")
    parser.add_argument("--save-models", help="Fichier pour sauvegarder les modèles")
    parser.add_argument("--load-models", help="Fichier pour charger les modèles")
    parser.add_argument("--osint", help="Données OSINT pour corrélation")

    args = parser.parse_args()

    # Chargement des résultats
    with open(args.scan_results, 'r') as f:
        scan_data = json.load(f)

    if 'results' in scan_data:
        results = scan_data['results']
    else:
        results = scan_data

    # Initialisation de l'analyseur
    analyzer = NetworkMLAnalyzer()

    # Chargement de modèles existants
    if args.load_models and analyzer.load_models(args.load_models):
        print("[+] Modèles pré-entraînés chargés")

    # Entraînement si demandé
    if args.train:
        print("[*] Entraînement des modèles...")
        accuracy = analyzer.train_risk_classifier(results)
        print(f"[+] Entraînement terminé - Précision: {accuracy:.2f}")

    # Analyse des anomalies
    print("\n[*] Détection d'anomalies...")
    anomalies = analyzer.detect_anomalies(results)

    if anomalies:
        print(f"[!] {len(anomalies)} anomalies détectées:")
        for host_ip, anomaly_info in anomalies.items():
            print(f" {host_ip}: {', '.join(anomaly_info['reason'])}")
    else:
        print("[+] Aucune anomalie détectée")

    # Prédictions et recommandations
    print("\n[*] Analyse ML par hôte:")
    osint_data = None
    if args.osint:
        with open(args.osint, 'r') as f:
            osint_data = json.load(f)

    for host_ip, host_data in results.items():
        print(f"\n--- {host_ip} ---")

        # Prédiction de risque
        if analyzer.risk_classifier:
            risk_pred = analyzer.predict_risk_level(host_data)
            print(f"Risque prédit: {risk_pred['predicted_risk']} (confiance: {risk_pred['confidence']:.1%})")

        # Recommandations intelligentes
        recommendations = analyzer.generate_intelligent_recommendations(host_data, osint_data)
        if recommendations:
            print("Recommandations ML:")
            for rec in recommendations[:3]:  # Top 3
                print(f" [{rec['type']}] {rec['message']}")

    # Sauvegarde des modèles
    if args.save_models:
        analyzer.save_models(args.save_models)
