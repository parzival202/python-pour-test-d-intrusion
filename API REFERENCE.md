# Référence de l'API

## Vue d'ensemble

Le Framework de Test d'Intrusion fournit une API CLI complète et une API Python programmable. Cette référence documente toutes les commandes disponibles, leurs paramètres et les fonctions principales.

## API CLI

### Structure Générale

Toutes les commandes suivent le format :
```bash
python main.py <commande> [options] [arguments]
```

### Commandes Disponibles

#### 1. Reconnaissance (`recon`)

Collecte des informations sur une cible via OSINT et reconnaissance passive.

**Syntaxe :**
```bash
python main.py recon --target <cible> [options]
```

**Paramètres :**
- `--target <cible>` : Cible à analyser (domaine ou IP) - requis
- `--osint` : Activer la collecte OSINT active
- `--force` : Forcer les actions potentiellement détectables

**Exemples :**
```bash
python main.py recon --target example.com --osint
python main.py recon --target 192.168.1.1 --force
```

**Sortie :** Informations sur l'hôte, DNS, WHOIS, sous-domaines découverts.

#### 2. Scan Réseau (`network`)

Découvre les hôtes actifs et analyse les ports ouverts.

**Syntaxe :**
```bash
python main.py network --target <cible> [options]
```

**Paramètres :**
- `--target <cible>` : Cible réseau (IP, CIDR, ou plage) - requis
- `--ports <ports>` : Ports spécifiques à scanner (format: 22,80,443)
- `--full` : Scan complet de tous les ports
- `--fast` : Scan rapide optimisé
- `--force` : Ignorer les sécurités intégrées

**Exemples :**
```bash
python main.py network --target 192.168.1.0/24
python main.py network --target 10.0.0.1 --ports 22,80,443 --fast
```

**Sortie :** Liste des hôtes actifs, ports ouverts, métadonnées du scan.

#### 3. Scan Web (`web`)

Analyse les vulnérabilités web et effectue du crawling.

**Syntaxe :**
```bash
python main.py web --target <cible> [options]
```

**Paramètres :**
- `--target <cible>` : URL cible - requis
- `--crawl` : Activer le crawling automatique
- `--scan` : Activer l'analyse de vulnérabilités
- `--depth <n>` : Profondeur maximale de crawling (défaut: 2)
- `--force` : Ignorer les restrictions de sécurité

**Exemples :**
```bash
python main.py web --target https://example.com --crawl --scan
python main.py web --target http://test.com --depth 3
```

**Sortie :** Résultats du crawling, formulaires découverts, vulnérabilités détectées.

#### 4. Exploitation (`exploit`)

Tente d'exploiter les vulnérabilités découvertes.

**Syntaxe :**
```bash
python main.py exploit --target <cible> [options]
```

**Paramètres :**
- `--target <cible>` : Cible à exploiter - requis
- `--module <module>` : Module d'exploitation spécifique
- `--force` : Ignorer les vérifications de sécurité

**Exemples :**
```bash
python main.py exploit --target 192.168.1.100
python main.py exploit --target https://vulnerable.com --module web_exploit
```

**Sortie :** Résultats des tentatives d'exploitation.

#### 5. Rapport (`report`)

Génère des rapports à partir des résultats de session.

**Syntaxe :**
```bash
python main.py report --session-id <id> [options]
```

**Paramètres :**
- `--session-id <id>` : ID de session - requis
- `--format <formats>` : Formats de sortie (html,json,pdf) - défaut: html
- `--outdir <répertoire>` : Répertoire de sortie - défaut: reports

**Exemples :**
```bash
python main.py report --session-id 20231029T143353Z --format html
python main.py report --session-id 20231029T143353Z --format html,json,pdf --outdir ./rapports
```

**Sortie :** Fichiers de rapport générés dans le répertoire spécifié.

#### 6. Configuration (`config`)

Gère la configuration du framework.

**Syntaxe :**
```bash
python main.py config [options]
```

**Paramètres :**
- `--show` : Afficher la configuration actuelle
- `--set <clé=valeur>` : Définir des valeurs de configuration

**Exemples :**
```bash
python main.py config --show
python main.py config --set scan.threads=50 --set logging.level=DEBUG
```

**Sortie :** Configuration actuelle ou confirmation de modification.

#### 7. Pipeline Complet (`all`)

Exécute un test d'intrusion complet automatique.

**Syntaxe :**
```bash
python main.py all --target <cible> [options]
```

**Paramètres :**
- `--target <cible>` : Cible principale - requis
- `--quick` : Mode rapide (moins approfondi)
- `--force` : Ignorer les sécurités intégrées

**Exemples :**
```bash
python main.py all --target https://example.com
python main.py all --target 192.168.1.0/24 --quick
```

**Sortie :** Résultats complets de tous les modules exécutés.

## API Python

### Fonctions Principales

#### Module `main.py`

##### `run(argv=None)`

Point d'entrée principal pour l'exécution programmatique.

**Paramètres :**
- `argv` : Liste d'arguments CLI (optionnel, utilise `sys.argv` par défaut)

**Retour :** Résultats de l'exécution

**Exemple :**
```python
from main import run

# Exécution programmatique
results = run(['network', '--target', '192.168.1.0/24'])
print(results)
```

#### Module `core.config`

##### Classe `Config`

Gestionnaire de configuration hiérarchique.

**Méthodes :**
- `__init__(config_path=None, cli_overrides=None)` : Initialise la configuration
- `get()` : Retourne la configuration complète
- `save_example(path="config.example.json")` : Sauvegarde un exemple de configuration

##### `load_from_cli(argv=None)`

Charge la configuration depuis les arguments CLI.

**Paramètres :**
- `argv` : Arguments CLI (optionnel)

**Retour :** Dictionnaire de configuration

#### Module `core.database`

##### Fonctions de Session

- `create_session(session_id, target, config=None)` : Crée une nouvelle session
- `close_session(session_id, status='finished')` : Ferme une session
- `get_session(session_id)` : Récupère les détails d'une session

##### Fonctions de Scan

- `add_scan(session_id, scan_type, target, results)` : Ajoute des résultats de scan
- `get_scans_by_session(session_id)` : Récupère tous les scans d'une session

##### Fonctions de Vulnérabilités

- `add_vulnerability(session_id, vuln_dict, scan_id=None)` : Ajoute une vulnérabilité
- `get_vulnerabilities_by_session(session_id)` : Récupère les vulnérabilités d'une session

##### Fonctions d'Exploitation

- `add_exploitation(session_id, vuln_id, exploit_dict)` : Ajoute une tentative d'exploitation
- `get_exploitations_by_session(session_id)` : Récupère les exploitations d'une session

##### Fonctions Utilitaires

- `get_session_results(session_id)` : Récupère tous les résultats d'une session
- `cleanup_old_sessions(days=30)` : Nettoie les anciennes sessions

#### Module `modules.reconnaissance.osint`

##### `basic_host_info(target)`

Informations de base sur un hôte.

**Paramètres :**
- `target` : Nom d'hôte ou IP

**Retour :** Dictionnaire avec IP, résolution inverse, accessibilité port 80

##### `dns_enumeration(domain)`

Énumération DNS complète.

**Paramètres :**
- `domain` : Domaine à analyser

**Retour :** Dictionnaire avec enregistrements A, AAAA, MX, NS, TXT, CNAME

##### `whois_lookup(domain)`

Recherche WHOIS.

**Paramètres :**
- `domain` : Domaine à analyser

**Retour :** Informations WHOIS structurées

##### `probe_subdomains(domain, words=None)`

Découverte de sous-domaines.

**Paramètres :**
- `domain` : Domaine parent
- `words` : Liste de préfixes à tester (optionnel)

**Retour :** Liste de sous-domaines découverts avec IPs

##### `comprehensive_osint(target)`

OSINT complet sur une cible.

**Paramètres :**
- `target` : Cible à analyser

**Retour :** Dictionnaire complet avec toutes les informations OSINT

#### Module `modules.network.scanner`

##### `discover_hosts(range_or_ip, timeout=0.8, threads=20, probe_port=80)`

Découvre les hôtes actifs.

**Paramètres :**
- `range_or_ip` : Plage réseau ou IP unique
- `timeout` : Timeout par hôte
- `threads` : Nombre de threads
- `probe_port` : Port utilisé pour la détection

**Retour :** Liste d'IPs actives

##### `scan_ports(ip, ports=None, timeout=1.0, threads=20)`

Scan des ports sur un hôte.

**Paramètres :**
- `ip` : Adresse IP cible
- `ports` : Liste de ports (défaut: ports courants)
- `timeout` : Timeout par port
- `threads` : Nombre de threads

**Retour :** Dictionnaire {port: ouvert}

##### `run_nmap(ip, args="-sV -O -Pn", timeout=300)`

Exécute Nmap sur un hôte.

**Paramètres :**
- `ip` : Adresse IP cible
- `args` : Arguments Nmap
- `timeout` : Timeout d'exécution

**Retour :** Sortie brute de Nmap ou None

##### `scan_target(target, threads=20, timeout=2.0, nmap_args=None)`

Orchestration complète du scan réseau.

**Paramètres :**
- `target` : Cible réseau
- `threads` : Nombre de threads
- `timeout` : Timeout général
- `nmap_args` : Arguments Nmap optionnels

**Retour :** Dictionnaire avec hôtes découverts, ports, métadonnées

#### Module `modules.web.scanner`

##### `detect_reflected_xss(url, session=None, timeout=5)`

Détection XSS réfléchie.

**Paramètres :**
- `url` : URL à tester
- `session` : Session requests (optionnel)
- `timeout` : Timeout par requête

**Retour :** Résultats de détection XSS

##### `detect_basic_sqli(url, session=None, timeout=5)`

Détection SQL injection basique.

**Paramètres :**
- `url` : URL à tester
- `session` : Session requests (optionnel)
- `timeout` : Timeout par requête

**Retour :** Résultats de détection SQLi

##### `detect_lfi(url, session=None, timeout=5)`

Détection LFI (Local File Inclusion).

**Paramètres :**
- `url` : URL à tester
- `session` : Session requests (optionnel)
- `timeout` : Timeout par requête

**Retour :** Résultats de détection LFI

##### `scan_page(url, session=None, timeout=5)`

Scan complet d'une page web.

**Paramètres :**
- `url` : URL à analyser
- `session` : Session requests (optionnel)
- `timeout` : Timeout par requête

**Retour :** Résultats complets du scan (XSS, SQLi, LFI)

#### Module `reporting.report_generator`

##### `generate(session_id, formats=["html"], out_dir="reports")`

Génère des rapports pour une session.

**Paramètres :**
- `session_id` : ID de session
- `formats` : Liste de formats ("html", "json", "pdf")
- `out_dir` : Répertoire de sortie

**Retour :** Dictionnaire avec chemins des fichiers générés

##### `generate_pdf(session_id, out_dir='reports')`

Génère un rapport PDF.

**Paramètres :**
- `session_id` : ID de session
- `out_dir` : Répertoire de sortie

**Retour :** Chemin du fichier PDF généré

##### `generate_executive_summary(session_id, results)`

Génère un résumé exécutif.

**Paramètres :**
- `session_id` : ID de session
- `results` : Résultats de session

**Retour :** Dictionnaire avec résumé et recommandations

## Codes d'Erreur

- `0` : Succès
- `1` : Erreur générale
- `2` : Arguments invalides
- `3` : Cible inaccessible
- `4` : Permissions insuffisantes
- `5` : Configuration invalide

## Variables d'Environnement

Le framework supporte les variables d'environnement préfixées par `PEN_` :

- `PEN_SCAN__THREADS` : Nombre de threads pour les scans
- `PEN_LOGGING__LEVEL` : Niveau de logging
- `PEN_WEB__CRAWL_DEPTH` : Profondeur de crawling

## Configuration

### Fichier de Configuration

Exemple `config.json` :
```json
{
  "scan": {
    "timeout": 2,
    "threads": 20,
    "rate_limit": 100
  },
  "logging": {
    "level": "INFO",
    "file": "pentest.log",
    "json_lines": false
  },
  "reporting": {
    "html_template": "report_template.html",
    "pdf_enabled": false
  },
  "recon": {
    "dns_timeout": 5,
    "subdomain_wordlist": ["www", "mail", "dev", "test", "beta"]
  },
  "web": {
    "crawl_depth": 2,
    "scan_timeout": 5
  },
  "exploit": {
    "safe_mode": true,
    "reverse_shell_port": 4444
  }
}
```

### Hiérarchie de Configuration

1. Valeurs par défaut hardcodées
2. Variables d'environnement
3. Fichier de configuration
4. Arguments CLI (priorité maximale)

## Extensions et Modules Personnalisés

Le framework est extensible via des modules personnalisés dans le répertoire `modules/`.

### Structure d'un Module

```python
# modules/custom_scanner.py
def run(target, **kwargs):
    # Logique du module personnalisé
    return {"results": "custom scan results"}
```

### Intégration

Les modules sont automatiquement découverts et peuvent être utilisés via :
```bash
python main.py exploit --module custom_scanner --target example.com
```

---

*Cette référence API est complète pour la version actuelle. Consultez le code source pour les détails d'implémentation les plus récents.*
