# Guide Utilisateur Complet du Framework de Test d'Intrusion

## Introduction : C'est quoi ce framework ?

Bienvenue dans ce guide complet ! Ce Framework de Test d'Intrusion est un outil pédagogique conçu pour apprendre les bases de la cybersécurité de manière pratique et sécurisée. Imaginez-le comme un "simulateur de détective informatique" qui vous aide à découvrir comment les hackers testent la sécurité des systèmes, mais uniquement sur des environnements que vous contrôlez.

### À quoi ça sert ?
- **Apprendre la cybersécurité** : Comprendre comment fonctionnent les attaques sans faire de mal
- **Tester vos propres systèmes** : Vérifier la sécurité de vos applications web ou réseaux locaux
- **S'entraîner** : Pratiquer les techniques de pentest dans un cadre éducatif
- **Générer des rapports** : Créer des documents professionnels sur les vulnérabilités trouvées

### Qui peut l'utiliser ?
- Étudiants en cybersécurité
- Développeurs qui veulent sécuriser leurs applications
- Administrateurs système
- Toute personne curieuse de comprendre comment les pirates informatiques travaillent

⚠️ **Important** : Ce framework ne doit être utilisé que sur des systèmes que vous possédez ou pour lesquels vous avez une autorisation écrite. Toute utilisation malveillante est illégale.

---

## Prérequis et Installation

### Ce dont vous avez besoin
- **Python 3.10 ou plus récent** (vérifiez avec `python --version`)
- **Git** pour télécharger le projet
- **Connexion Internet** pour installer les dépendances
- **Un environnement virtuel** (recommandé pour éviter les conflits)

### Installation étape par étape

1. **Téléchargez le projet**
   ```bash
   git clone https://github.com/USERNAME/penetration_testing_framework.git
   cd penetration_testing_framework
   ```
   Remplacez `USERNAME` par le nom d'utilisateur GitHub si nécessaire.

2. **Créez un environnement virtuel** (optionnel mais recommandé)
   ```bash
   python -m venv venv
   # Sur Windows :
   venv\Scripts\activate
   # Sur Linux/Mac :
   source venv/bin/activate
   ```

3. **Installez les dépendances**
   ```bash
   pip install -r requirements.txt
   ```

4. **Vérifiez l'installation**
   ```bash
   python main.py --help
   ```
   Si vous voyez le menu d'aide, l'installation est réussie !

### Configuration de base
Le framework fonctionne avec des fichiers de configuration. Un exemple est fourni dans `config.example.json`. Copiez-le pour créer votre configuration :
```bash
cp config.example.json config.json
```

---

## Mode d'emploi : Les commandes expliquées simplement

Le framework utilise des commandes simples dans le terminal. Chaque commande correspond à une étape du test d'intrusion.

### Commande : Reconnaissance (`recon`)
**Objectif** : Collecter des informations sur une cible sans l'attaquer.

**Quand l'utiliser ?** : Au début de tout test, pour connaître votre cible.

**Exemples concrets** :
```bash
# Informations de base sur un site web
python main.py recon --target example.com

# Recherche active d'informations (OSINT)
python main.py recon --target example.com --osint

# Mode forcé (attention : peut être détecté)
python main.py recon --target example.com --osint --force
```

**Ce que ça fait** :
- Résout l'adresse IP du domaine
- Cherche des sous-domaines (www, mail, dev, etc.)
- Vérifie les enregistrements DNS
- Recherche des informations WHOIS

### Commande : Scan Réseau (`network`)
**Objectif** : Découvrir les ordinateurs connectés et leurs ports ouverts.

**Quand l'utiliser ?** : Pour cartographier un réseau local ou distant.

**Exemples concrets** :
```bash
# Scanner tout un réseau local
python main.py network --target 192.168.1.0/24

# Scanner un seul ordinateur
python main.py network --target 192.168.1.100

# Scan rapide des ports courants
python main.py network --target 192.168.1.0/24 --fast

# Scan complet de tous les ports
python main.py network --target 192.168.1.100 --full

# Scanner des ports spécifiques
python main.py network --target 192.168.1.100 --ports 22,80,443,3389
```

**Ce que ça fait** :
- Détecte les ordinateurs actifs sur le réseau
- Teste si les ports sont ouverts (comme des portes dans un bâtiment)
- Identifie les services qui tournent (web, SSH, etc.)

### Commande : Scan Web (`web`)
**Objectif** : Analyser les sites web pour trouver des failles de sécurité.

**Quand l'utiliser ?** : Sur les applications web que vous voulez tester.

**Exemples concrets** :
```bash
# Analyser complètement un site (navigation + tests de sécurité)
python main.py web --target https://example.com --crawl --scan

# Juste explorer le site (navigation automatique)
python main.py web --target https://example.com --crawl

# Juste tester les failles de sécurité
python main.py web --target https://example.com --scan

# Exploration profonde (plus de pages)
python main.py web --target https://example.com --crawl --depth 5
```

**Ce que ça fait** :
- Navigue automatiquement sur toutes les pages du site
- Cherche des formulaires web
- Teste des vulnérabilités comme :
  - XSS (injection de code JavaScript)
  - SQL Injection (accès à la base de données)
  - LFI (lecture de fichiers du serveur)

### Commande : Exploitation (`exploit`)
**Objectif** : Tenter d'exploiter les failles trouvées (simulation).

**Quand l'utiliser ?** : Après avoir trouvé des vulnérabilités, pour voir si elles sont exploitables.

**Exemples concrets** :
```bash
# Exploitation automatique
python main.py exploit --target 192.168.1.100

# Utiliser un module spécifique
python main.py exploit --target https://vulnerable-site.com --module web_exploit
```

**Ce que ça fait** :
- Essaie d'exécuter du code sur la cible
- Teste les vulnérabilités trouvées
- **Attention** : Cette commande peut être destructive !

### Commande : Rapport (`report`)
**Objectif** : Créer des rapports professionnels sur vos tests.

**Quand l'utiliser ?** : À la fin de chaque test pour documenter vos découvertes.

**Exemples concrets** :
```bash
# Rapport HTML simple
python main.py report --session-id 20231029T143353Z --format html

# Plusieurs formats
python main.py report --session-id 20231029T143353Z --format html,json,pdf

# Sauvegarder dans un dossier spécifique
python main.py report --session-id 20231029T143353Z --format html --outdir ./mes_rapports
```

**Ce que ça fait** :
- Compile tous les résultats de la session
- Génère des rapports lisibles
- Crée des graphiques et statistiques

### Commande : Configuration (`config`)
**Objectif** : Personnaliser le comportement du framework.

**Quand l'utiliser ?** : Pour adapter l'outil à vos besoins.

**Exemples concrets** :
```bash
# Voir la configuration actuelle
python main.py config --show

# Changer le nombre de threads (plus rapide mais plus de ressources)
python main.py config --set scan.threads=50

# Activer les logs détaillés
python main.py config --set logging.level=DEBUG
```

### Commande : Pipeline Complet (`all`)
**Objectif** : Faire un test d'intrusion complet automatiquement.

**Quand l'utiliser ?** : Pour un audit complet rapide.

**Exemples concrets** :
```bash
# Test complet sur un site web
python main.py all --target https://example.com

# Test rapide (moins approfondi)
python main.py all --target https://example.com --quick
```

**Ce que ça fait** :
- Exécute reconnaissance → scan réseau → scan web → exploitation → rapport
- Idéal pour les débutants

---

## Système de Configuration

### Comment ça marche ?
Le framework utilise une hiérarchie de configuration :
1. **Valeurs par défaut** (dans le code)
2. **Variables d'environnement** (commencent par `PEN_`)
3. **Fichier config.json** (dans le dossier du projet)
4. **Arguments de ligne de commande** (priorité maximale)

### Variables importantes
```json
{
  "scan": {
    "timeout": 2,           // Temps d'attente max par test
    "threads": 20,          // Nombre de tests simultanés
    "rate_limit": 100       // Limite de requêtes par minute
  },
  "logging": {
    "level": "INFO",        // Niveau de détail des logs
    "file": "pentest.log",  // Fichier de logs
    "json_lines": false     // Format des logs
  },
  "web": {
    "crawl_depth": 2,       // Profondeur de navigation
    "scan_timeout": 5       // Timeout pour les tests web
  }
}
```

### Variables d'environnement
```bash
export PEN_SCAN__THREADS=50
export PEN_LOGGING__LEVEL=DEBUG
export PEN_WEB__CRAWL_DEPTH=3
```

---

## Guide de Génération des Rapports

### Types de rapports
- **HTML** : Rapport interactif avec graphiques (recommandé)
- **JSON** : Données brutes pour traitement automatique
- **PDF** : Rapport imprimable professionnel

### Structure d'un rapport
Chaque rapport contient :
- **Résumé exécutif** : Vue d'ensemble des découvertes
- **Détails techniques** : Chaque vulnérabilité expliquée
- **Recommandations** : Comment corriger les problèmes
- **Statistiques** : Graphiques et métriques

### Exemple de workflow complet
```bash
# 1. Test complet
python main.py all --target https://mon-site.com

# 2. Trouver l'ID de session (dans les logs ou base de données)
# L'ID ressemble à : 20231029T143353Z

# 3. Générer le rapport
python main.py report --session-id 20231029T143353Z --format html,pdf

# 4. Ouvrir le rapport
open reports/20231029T143353Z/report.html
```

---

## Procédures de Sécurité et Limitations

### Règles d'or
1. **Toujours demander la permission** avant de tester
2. **Utiliser uniquement sur vos systèmes** ou avec autorisation écrite
3. **Ne pas tester en production** (risque de casser le service)
4. **Respecter les lois** de votre pays
5. **Sauvegarder vos données** avant les tests

### Limitations importantes
- **Pas un outil professionnel** : Destiné à l'apprentissage
- **Détection possible** : Certains tests peuvent être loggés
- **Faux positifs** : Peut signaler des failles qui n'en sont pas
- **Pas de garantie** : Ne détecte pas toutes les vulnérabilités

### Bonnes pratiques
- Testez d'abord sur des machines virtuelles
- Utilisez des environnements de développement
- Documentez toujours vos tests
- Nettoyez après vos tests (supprimez les fichiers temporaires)

---

## Exemples Pratiques et Cas d'Usage

### Scénario 1 : Tester son site web personnel
```bash
# Étape 1 : Reconnaissance
python main.py recon --target mon-site.com --osint

# Étape 2 : Scan réseau (si vous avez un serveur dédié)
python main.py network --target 123.45.67.89

# Étape 3 : Scan web complet
python main.py web --target https://mon-site.com --crawl --scan --depth 3

# Étape 4 : Rapport
python main.py report --session-id <ID_SESSION> --format html
```

### Scénario 2 : Audit d'un réseau local
```bash
# Configuration pour réseau local
python main.py config --set scan.timeout=1 --set scan.threads=10

# Scan du réseau complet
python main.py network --target 192.168.1.0/24 --full

# Test des vulnérabilités web sur les machines trouvées
python main.py web --target http://192.168.1.100 --scan
```

### Scénario 3 : Test rapide avant déploiement
```bash
# Pipeline automatique rapide
python main.py all --target https://staging.mon-app.com --quick

# Vérifier les résultats
python main.py report --session-id <ID_SESSION> --format html
```

### Scénario 4 : Apprentissage des vulnérabilités
```bash
# Tester une application vulnérable intentionnellement (DVWA, etc.)
python main.py web --target http://localhost:8080 --scan

# Voir les détails des vulnérabilités trouvées
python main.py report --session-id <ID_SESSION> --format json
```

---

## Dépannage et FAQ

### Problèmes courants

#### "Erreur de connexion réseau"
**Symptôme** : Le scan échoue avec "Connection timeout"
**Solutions** :
- Vérifiez que la cible est accessible : `ping example.com`
- Augmentez le timeout : `python main.py config --set scan.timeout=10`
- Utilisez `--force` seulement si nécessaire

#### "Timeout lors des scans"
**Symptôme** : Les scans prennent trop de temps
**Solutions** :
- Réduisez le nombre de threads : `--set scan.threads=5`
- Utilisez le mode fast : `--fast`
- Scannez moins de ports : `--ports 22,80,443`

#### "Échec de génération de rapport"
**Symptôme** : Erreur "Session not found"
**Solutions** :
- Vérifiez l'ID de session (format : AAAAMMJJTHHMMSSZ)
- Assurez-vous que la session existe dans `results/pentest.db`
- Vérifiez les permissions d'écriture dans le dossier `reports/`

#### "Module not found"
**Symptôme** : Erreur d'importation de module
**Solutions** :
- Réinstallez les dépendances : `pip install -r requirements.txt`
- Vérifiez que vous êtes dans le bon dossier
- Utilisez un environnement virtuel propre

### FAQ

**Q : Puis-je utiliser ce framework sur des sites web publics ?**
R : Non, uniquement sur vos propres systèmes ou avec autorisation explicite.

**Q : Les tests sont-ils destructeurs ?**
R : Certains peuvent l'être. Utilisez toujours `--safe-mode` ou évitez `--force`.

**Q : Comment puis-je contribuer ?**
R : Ouvrez des issues sur GitHub ou proposez des améliorations pédagogiques.

**Q : Le framework détecte-t-il toutes les vulnérabilités ?**
R : Non, c'est un outil d'apprentissage. Pour des audits professionnels, utilisez des outils spécialisés.

**Q : Puis-je automatiser les tests ?**
R : Oui, via l'API Python ou des scripts shell.

### Logs et débogage
```bash
# Activer les logs détaillés
python main.py config --set logging.level=DEBUG

# Consulter les logs
tail -f pentest.log

# Logs au format JSON pour analyse
python main.py config --set logging.json_lines=true
```

### Tests unitaires
```bash
# Vérifier que tout fonctionne
pytest -v

# Tests spécifiques
pytest tests/test_web_scanner.py -v
```

---

## Ressources Supplémentaires

- **Documentation API** : `API REFERENCE.md`
- **Guide d'installation** : `INSTALLATION.md`
- **README** : Présentation générale du projet
- **Tests unitaires** : Dans le dossier `tests/`

---

*Ce guide est conçu pour être évolutif. N'hésitez pas à suggérer des améliorations pour rendre l'apprentissage plus efficace !*

*Usage strictement éducatif - Toute utilisation malveillante est interdite par la loi.*
