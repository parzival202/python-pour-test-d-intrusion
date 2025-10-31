# Guide Utilisateur Complet du Framework de Test d'Intrusion (FR)

## Introduction

Ce document explique comment utiliser le framework pas à pas, avec des exemples concrets et les bonnes pratiques. Le projet est conçu pour un usage pédagogique et d'audit sur des environnements autorisés uniquement.

Important : n'utilisez ce framework que sur des systèmes que vous possédez ou pour lesquels vous avez une autorisation écrite.

---

## Résumé des nouveautés (mises à jour récentes)

- Interface interactive : lancez `python main.py` sans arguments pour entrer dans une invite (`ptf>`) où vous pouvez taper des commandes.
- Option globale `--no-persist` : empêche la persistance des résultats en base pour une exécution ponctuelle.
- Options d'export : `--format` (json, html, pdf) et `--output` / `--outdir` pour écrire les résultats sur disque.

---

## Prérequis et installation (raccourci)

- Python 3.10+ (vérifier `python --version`)
- Créez un venv et installez les dépendances :

```pwsh
python -m venv venv
venv\Scripts\activate    # Windows
pip install -r requirements.txt
```

---

## Lancement du framework

1) Usage non interactif (commande immédiate) :

```pwsh
python main.py <commande> [options]
```

2) Usage interactif (recommandé pour l'exploration) :

```pwsh
python main.py
# puis à l'invite : ptf> all --target http://192.168.11.128 --format json
```

L'invite interactive affiche une liste d'exemples et accepte des lignes de commandes (elle parse la ligne et l'exécute comme si vous aviez lancé `python main.py ...`).

---

## Sous-commandes et options principales

Syntaxe générale : `python main.py <commande> [--target <cible>] [--format json,html,pdf] [--output <path>] [--no-persist]`

- `--no-persist` : ne pas écrire les résultats dans la base locale (fichier JSON `results/pentest_db.json`).
- `--format` : formats d'export (ex : `--format json,pdf`).
- `--output` ou `--outdir` : chemin pour écrire les fichiers de sortie.

Liste des commandes :

- recon : collecte d'informations (ex : DNS, sous-domaines, whois)
- network : scan réseau (hôtes et ports)
- web : crawl et scans web (XSS, SQLi, LFI...)
- exploit : modules d'exploitation (simulation)
- report : génération de rapports à partir d'un `session_id`
- config : lecture / écriture de la configuration
- all : pipeline complet (recon → network → web → exploit → report)

---

## Commandes détaillées avec exemples pratiques

Remarque : remplacez `http://192.168.11.128` par votre cible autorisée.

1) Full pipeline (équivalent de "--all")

```pwsh
python main.py all --target http://192.168.11.128
```

Exemple avec export JSON et sans persistance :

```pwsh
python main.py all --target http://192.168.11.128 --format json --output results/ --no-persist
```

Que fait `all` : lance la reconnaissance, le scan réseau, le scan web, un module d'exploitation simulé, puis génère un rapport agrégé. La sortie contient toujours un `session_id`.

2) Scan web ciblé (crawl + scan de vulnérabilités)

```pwsh
python main.py web --target http://192.168.11.128 --crawl --scan --depth 3 --format json --output results/web_scan.json
```

Options utiles : `--crawl` pour l'exploration, `--scan` pour les tests de vulnérabilités, `--depth` pour la profondeur de crawl.

3) Scan réseau

```pwsh
python main.py network --target 192.168.11.0/24 --fast
python main.py network --target 192.168.11.128 --ports 22,80,443
```

4) Générer un rapport à partir d'une session existante

```pwsh
python main.py report --session-id 20251030T144234Z --format html,pdf --outdir reports
```

Le rapport est construit à partir des données persistées en base (table `sessions` → `scans` → `vulnerabilities`...). Si vous avez exécuté avec `--no-persist`, la génération de PDF/HTML via `report` n'aura pas de données disponibles pour cette session.

5) Utiliser l'interface interactive

```pwsh
python main.py
# puis à l'invite
ptf> web --target http://192.168.11.128 --crawl --scan
ptf> report --session-id 20251030T144234Z --format html
```

L'invite accepte `help`, `commands`, `exit` et exécute la ligne fournie.

---

## Où sont enregistrés les résultats ?

- Base de données locale (JSON) : `results/pentest_db.json` — contient les listes `sessions`, `scans`, `vulnerabilities`, `exploitations` et des compteurs d'ID.
- Rapports et exports : dossier `reports/` et/ou le chemin indiqué via `--output` / `--outdir`.
- Dossiers de run : lors d'une exécution une variable `RUN_DIR` est créée (ex : `runs/run_<timestamp>`) et contient logs et fichiers temporaires.

Comment retrouver une session :

1. Regarder la sortie console : la commande `all` ou `web` renvoie un `session_id` (format UTC : `YYYYMMDDTHHMMSSZ`).
2. Vérifier la table `sessions` dans `results/pentest.db` (ou utiliser les outils de reporting).

Exemple pour lister rapidement (dans PowerShell) :

```pwsh
# Afficher la liste des fichiers de report
ls reports\

# Inspecter rapidement la DB (format JSON)

Vous pouvez afficher directement le fichier JSON ou utiliser le script d'audit fourni qui lit le fichier et affiche un résumé :

```pwsh
python .\tools\audit_db_check.py
```
```

---

## Formats et export des résultats

- JSON : structure complète des résultats — utile pour analyses automatisées.
- HTML : rendu lisible et interactif (graphes, tables).
- PDF : export imprimable (généré par le module de reporting si disponible).

Utilisation : préciser `--format json,html` et `--output` (ou `--outdir`) pour écrire les fichiers.

Si `--output` est un répertoire, un nom par défaut est utilisé (`<commande>_<session_id>.json`).

---

## Conseils opératoires et sécurité

- Toujours obtenir une autorisation écrite avant de lancer un test.
- Préférez des environnements de test (VM, containers) pour l'apprentissage.
- Evitez `--force` et l'exécution d'exploits sur des systèmes de production.

---

## Dépannage rapide

- "Connection timeout" : vérifier que la cible est joignable, augmenter `scan.timeout` dans la config.
- "Session not found" lors du `report` : vérifiez que la session a été persistée (ne pas avoir utilisé `--no-persist`).
- Erreurs d'import de module : assurez-vous d'être dans le dossier du projet et que le venv est activé.

### Aide supplémentaire

- Pour obtenir l'aide complète d'une commande :

```pwsh
python main.py <commande> --help
```

---

## Exemples concrets résumés

- Pipeline complet (persist et export JSON) :

```pwsh
python main.py all --target http://192.168.11.128 --format json --output results/
```

- Scan web seul (crawl + scan, écriture dans fichier JSON, pas de persistance) :

```pwsh
python main.py web --target http://192.168.11.128 --crawl --scan --depth 3 --format json --output results/web_scan.json --no-persist
```

- Générer un rapport PDF pour la session `20251030T144234Z` :

```pwsh
python main.py report --session-id 20251030T144234Z --format pdf --outdir reports
```

---

## Ressources et où contribuer

- Fichiers importants : `main.py`, `core/database.py`, `reporting/report_generator.py`, `config.example.json`.
- Tests : dossier `tests/` (exécuter `pytest -v`).
- Propositions d'amélioration : ouvrez une issue ou un PR sur le dépôt GitHub.

---

*Ce guide est fourni en français et vise à refléter les dernières améliorations du framework (interface interactive, options de sortie, persistance contrôlable).* 
