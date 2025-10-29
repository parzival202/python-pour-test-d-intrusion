TÂCHES PRIORITAIRES — Persistance & Reporting (OBJECTIF : terminer totalement)

[PRIORITÉ CRITIQUE] 1. Core - Base de données SQLite (core/database.py)
- [ ] Implémenter connexion SQLite persistante dans ./results/pentest.db (création dossier si nécessaire).
- [ ] Créer tables : sessions, scans, vulnerabilities, exploitations.
- [ ] Utiliser `check_same_thread=False` et `row_factory=sqlite3.Row`.
- [ ] Fonctions publiques :
    - create_session(session_id, target, config)
    - close_session(session_id, status='finished')
    - add_scan(session_id, scan_type, target, results) -> scan_id
    - add_vulnerability(session_id, vuln_dict, scan_id=None) -> vuln_id
    - add_exploitation(session_id, vuln_id, exploit_dict) -> exploit_id
    - get_session_results(session_id) -> dict complet
- [ ] Transactions atomiques pour les insertions cruciales.
- [ ] Serialisation JSON UTF-8 pour les champs complexes (ensure_ascii=False).

[PRIORITÉ CRITIQUE] 2. Intégration automatique DB dans les modules
- [ ] main.py : à l’entrée d’un run, créer session via db.create_session(session_id, target, cfg).
- [ ] main.py : à la fin du run, appeler db.close_session(session_id, status).
- [ ] modules/network/scanner.py : après un scan (nmap ou simulé), appeler db.add_scan(...) avec le résultat et stocker scan_id.
- [ ] modules/network/scanner.py : parser résultats nmap (hôtes, ports, services, os) et les inclure dans 'results'.
- [ ] modules/web/scanner.py : pour chaque vuln détectée (XSS, SQLi, LFI...), appeler db.add_vulnerability(session_id, vuln, scan_id).
- [ ] modules/exploitation/safe_stub.py : simuler exploitation puis appeler db.add_exploitation(session_id, vuln_id, exploit_result).
- [ ] Gérer exceptions DB dans chaque module (log + fallback).

[PRIORITAIRE] 3. Reporting complet (reporting/report_generator.py)
- [ ] Implémenter compute_risk_score(vulns) :
    - Pondérations : CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1
    - Retourner score brut, pourcentage et niveau (CRITICAL/HIGH/MEDIUM/LOW) et counts.
- [ ] Implementer generate_executive_summary(session_id, results) :
    - 1 page : métadonnées, niveau de risque, top 5 vulnérabilités, actions immédiates recommandées.
- [TRÈS IMPORTANT] 4. Génération PDF propre
- [ ] Utiliser reportlab si disponible ; sinon message d'erreur clair.
- [ ] PDF layout :
    - Page 1 : Titre, métadonnées, executive summary (niveau risque + top 5 + actions).
    - Page 2 : Tableau des vulnérabilités (type, sévérité, cible, paramètre, payload, preuve courte).
    - Annexes : lien/chemin vers report.json.
- [ ] Intégrer generate_pdf() dans pipeline main.py report --format pdf.
- [ ] Sauvegarder PDF dans ./reports/<session_id>/report.pdf.

[IMPORTANTS] 5. Tests unitaires & validation
- [ ] tests/test_database.py :
    - créer session test, ajouter vulnérabilité(s), vérifier get_session_results() retourne les données.
- [ ] tests/test_report_pdf.py :
    - générer PDF à partir d'une session test et vérifier l'existence et taille du fichier.
- [ ] tests/test_logger.py : vérifier création audit.jsonl et écriture d'entrées.
- [ ] Exécuter pytest et corriger les erreurs.

[DOCUMENTATION] 6. README / INSTALLATION / USER_GUIDE
- [ ] README : Quickstart, exemples CLI (scan, recon, network, web, report).
- [ ] INSTALLATION.md : dépendances (PyYAML, python-nmap, reportlab), commandes pip install.
- [ ] USER_GUIDE.md : workflow exemple, comment reproduire une session complète.
- [ ] Ajoute avertissement légal & éthique dans README (usage uniquement sur VMs isolées).

[SÉCURITÉ] 7. Précautions & stubs d'exploitation
- [ ] S'assurer que les modules d'exploitation réels ne sont pas fournis : uniquement des simulateurs.
- [ ] Si collecte de PoC, stocker uniquement des preuves non-exécutables (response snippets, payload encodés).
- [ ] Documenter procédure pour reproduction sécurisée sur VM de test.

[OPTIONNEL MAIS RECOMMANDÉ] 8. Améliorations & robustesse
- [ ] Ajouter logging détaillé dans chaque insertion DB (PentestLogger.log_action).
- [ ] Gérer verrous / concurrence légère si modules multi-threads (SQLite a limitations).
- [ ] Ajouter script de validation rapide scripts/validate_run.sh :
    - exécuter un recon simulé, un network simulé, écrire DB, générer PDF, exécuter tests.
- [ ] Ajouter entry dans requirements.txt : PyYAML, python-nmap (optionnel), reportlab.

[CHECKLIST DE VALIDATION (avant soutenance)]
- [ ] Présence de ./results/pentest.db avec au moins 1 session complète.
- [ ] Présence de ./reports/<session_id>/report.pdf (Executive summary visible).
- [ ] Les tests pytest passent localement.
- [ ] README + INSTALLATION incluent les étapes pour reproduire.
- [ ] Avertissement légal visible dans README & CLI.

[COMMANDES UTILES]
- Lancer un scan simulé (créera session) :
    python main.py recon --target example.com
- Lancer un scan réseau (simulé ou nmap si installé) :
    python main.py network --target 192.168.1.0/24 --ports 22
- Générer rapport PDF :
    python main.py report --session-id <SESSION_ID> --format pdf
- Exécuter tests :
    pip install -r requirements.txt
    pytest -q

[NOTE TECHNIQUE]
- Utiliser json.dumps(..., ensure_ascii=False) pour garder l'UTF-8 lisible (français) dans la DB.
- Pour reportlab : pip install reportlab
- Pour nmap integration : pip install python-nmap (adapter parsing avec nm[host][proto][port]).

