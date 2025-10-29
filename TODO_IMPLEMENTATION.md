# TODO d'implémentation — Framework de test de pénétration

Ce fichier décompose le plan approuvé en étapes logiques pour compléter le framework basé sur les exigences de TODO.md.

## ✅ 1. Améliorations du cœur (Priorité : Haute)
- [x] Améliorer core/logger.py : Ajouter la journalisation d'audit JSONL, rotation des fichiers (10 Mo), fonctions spécifiques (SCAN_START, VULNERABILITY, EXPLOITATION)
- [x] Améliorer core/config.py : Prendre en charge les fichiers YAML, variables d'environnement, remplacements CLI, créer config.example.json
- [x] Implémenter core/database.py : Schéma SQLite (sessions, scans, vulnérabilités, exploitations), opérations CRUD

## ✅ 2. Achèvements des modules (Priorité : Haute)
- [x] Améliorer modules/reconnaissance/osint.py : Ajouter l'énumération DNS, améliorer la découverte de sous-domaines, intégrer WHOIS
- [ ] Améliorer modules/reconnaissance/passive.py : Ajouter les infos de certificat TLS, améliorer l'agrégation
- [ ] Améliorer modules/network/scanner.py : Ajouter l'empreinte OS, détection de service, intégrer nmap
- [ ] Améliorer modules/web/scanner.py : Ajouter la détection RFI, test de paramètres complet, améliorer les vérifications de vulnérabilités
- [ ] Implémenter modules/web/exploiter.py : Validation PoC réelle, support de shell inverse
- [ ] Implémenter modules/system/exploiter.py : Débordement de tampon, shellcode, vrais shells inverses (sûrs)

## ✅ 3. CLI et interface (Priorité : Moyenne)
- [ ] Compléter main.py : Toutes les commandes CLI (scan --full, recon, network, web, exploit, report, config), menu d'aide
- [ ] Créer gui.py : GUI avec tkinter/PyQt pour la visualisation

## ✅ 4. Améliorations des rapports (Priorité : Moyenne)
- [ ] Améliorer reporting/report_generator.py : Génération PDF, résumé exécutif, notation des risques, captures d'écran
- [ ] Créer reporting/templates/ : Modèles HTML/PDF

## ✅ 5. Tests et validation (Priorité : Moyenne)
- [ ] Ajouter tests/test_*.py : Tests unitaires, fonctionnels, d'intégration complets (>80% de couverture)

## ✅ 6. Documentation et légal (Priorité : Faible)
- [ ] Créer docs/INSTALLATION.md, USER_GUIDE.md, API_REFERENCE.md, CONTRIBUTING.md, CHANGELOG.md, LICENSE
- [ ] Améliorer README.md : Avertissements, exemples
- [ ] Ajouter des avertissements légaux dans CLI et docs

## ✅ 7. Dépendances et configuration (Priorité : Haute)
- [ ] Mettre à jour requirements.txt : Ajouter PyYAML, python-nmap, reportlab, PyQt5
- [ ] S'assurer que tous les __init__.py ont des imports appropriés

## ✅ 8. Fonctionnalités bonus (Priorité : Faible)
- [ ] Configuration Docker, CI/CD GitHub Actions, détection WAF, modules de bruteforce

---

# Suivi de la progression
- Démarré : [Date/Heure]
- Étapes terminées : 4/XX (Améliorations du cœur et modules de reconnaissance terminés)
- Prochaine étape : Améliorer modules/reconnaissance/passive.py
