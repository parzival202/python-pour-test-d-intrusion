# Guide Utilisateur

## Introduction

Ce guide utilisateur vous explique comment utiliser le Framework de Test d'Intrusion pour effectuer des tests de sécurité sur des cibles autorisées. Le framework est conçu pour être modulaire et extensible, permettant d'exécuter différents types de scans et d'analyses.

## Prérequis

Avant de commencer, assurez-vous d'avoir :
- Python 3.10 ou supérieur installé
- Les dépendances installées via `pip install -r requirements.txt`
- Des droits d'accès sur les systèmes cibles (tests uniquement sur des environnements autorisés)

## Commandes de Base

### Reconnaissance (OSINT)

La reconnaissance permet de collecter des informations sur une cible sans interaction directe.

```bash
# Reconnaissance OSINT basique sur un domaine
python main.py recon --target example.com --osint

# Reconnaissance passive (sans OSINT actif)
python main.py recon --target example.com

# Reconnaissance avec mode forcé (attention : peut être détecté)
python main.py recon --target example.com --force
```

### Scan Réseau

Le scan réseau découvre les hôtes actifs et analyse les ports ouverts.

```bash
# Scan d'un réseau complet (CIDR)
python main.py network --target 192.168.1.0/24

# Scan d'une plage d'adresses IP
python main.py network --target 192.168.1.1-192.168.1.10

# Scan d'un hôte unique
python main.py network --target 192.168.1.1

# Scan rapide avec ports spécifiques
python main.py network --target 192.168.1.0/24 --fast --ports 22,80,443

# Scan complet avec tous les ports
python main.py network --target 192.168.1.1 --full
```

### Scan Web

L'analyse web détecte les vulnérabilités courantes sur les applications web.

```bash
# Scan complet d'un site web (crawling + analyse)
python main.py web --target https://example.com --crawl --scan

# Crawling uniquement
python main.py web --target https://example.com --crawl

# Analyse de vulnérabilités uniquement
python main.py web --target https://example.com --scan

# Scan avec profondeur de crawling personnalisée
python main.py web --target https://example.com --crawl --depth 3
```

### Exploitation

L'exploitation tente d'exécuter des exploits sur les vulnérabilités découvertes.

```bash
# Exploitation avec module par défaut
python main.py exploit --target 192.168.1.1

# Exploitation avec module spécifique
python main.py exploit --target 192.168.1.1 --module web_exploit
```

### Génération de Rapports

Les rapports peuvent être générés en différents formats après une session de test.

```bash
# Générer un rapport HTML
python main.py report --session-id 20231029T143353Z --format html

# Générer plusieurs formats
python main.py report --session-id 20231029T143353Z --format html,json,pdf

# Spécifier le répertoire de sortie
python main.py report --session-id 20231029T143353Z --format html --outdir ./mes_rapports
```

### Configuration

Le framework peut être configuré via des fichiers ou des options CLI.

```bash
# Afficher la configuration actuelle
python main.py config --show

# Modifier la configuration
python main.py config --set scan.threads=50 --set logging.level=DEBUG

# Utiliser un fichier de configuration personnalisé
python main.py --config mon_config.json network --target 192.168.1.0/24
```

## Pipeline Complet

Pour exécuter un test d'intrusion complet :

```bash
# Pipeline automatique (recon + réseau + web + rapport)
python main.py all --target https://example.com

# Pipeline rapide (moins approfondi)
python main.py all --target https://example.com --quick
```

## Exemples Pratiques

### Test d'un Serveur Web Local

```bash
# 1. Reconnaissance
python main.py recon --target localhost

# 2. Scan réseau
python main.py network --target 127.0.0.1

# 3. Scan web
python main.py web --target http://localhost --crawl --scan

# 4. Rapport
python main.py report --session-id <SESSION_ID> --format html
```

### Test d'un Réseau Local

```bash
# Scan complet du réseau local
python main.py network --target 192.168.1.0/24 --full

# Analyse des vulnérabilités web sur les hôtes découverts
python main.py web --target http://192.168.1.100 --scan
```

### Audit de Sécurité Régulier

```bash
# Configuration pour un audit régulier
python main.py config --set scan.timeout=10 --set web.crawl_depth=2

# Exécution de l'audit
python main.py all --target https://mon-application.com

# Génération du rapport
python main.py report --session-id <SESSION_ID> --format html,pdf
```

## Gestion des Sessions

Chaque exécution crée une session unique identifiée par un timestamp UTC.

```bash
# Lister les sessions (via base de données)
# Note: Fonctionnalité à implémenter dans une future version

# Nettoyer les anciennes sessions
# Note: Fonctionnalité disponible via l'API Python
```

## Dépannage

### Problèmes Courants

1. **Erreur de connexion réseau**
   - Vérifiez que la cible est accessible
   - Utilisez `--force` uniquement si nécessaire

2. **Timeout lors des scans**
   - Augmentez le timeout : `--set scan.timeout=15`
   - Réduisez le nombre de threads : `--set scan.threads=10`

3. **Échec de génération de rapport**
   - Vérifiez que la session existe
   - Assurez-vous que les permissions d'écriture sont correctes

### Logs et Debug

```bash
# Activer les logs détaillés
python main.py --set logging.level=DEBUG network --target 192.168.1.0/24

# Consulter les logs
tail -f pentest.log
```

## Bonnes Pratiques

1. **Toujours obtenir une autorisation** avant de tester
2. **Utiliser des environnements de test** dédiés
3. **Sauvegarder les rapports** dans des endroits sécurisés
4. **Ne pas exécuter sur des systèmes de production** sans supervision
5. **Respecter les lois et réglementations** locales

## Support

Pour obtenir de l'aide :
- Consultez la documentation API (API REFERENCE.md)
- Vérifiez les logs pour les erreurs détaillées
- Ouvrez une issue sur le dépôt GitHub du projet

---

*Ce guide est destiné à un usage éducatif uniquement. Toute utilisation malveillante est strictement interdite.*
