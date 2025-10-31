#!/usr/bin/env python3
"""
Script de vérification de l'enregistrement des scans/vulns/exploitations dans la BD SQLite.
Crée une session de test, ajoute un scan, une vulnérabilité et une exploitation,
puis affiche les comptes et les dernières entrées.
"""
import time
import json
import sys
import os

# Ensure project root is on sys.path so 'core' and 'modules' packages can be imported
proj_root = os.path.dirname(os.path.dirname(__file__))
if proj_root not in sys.path:
    sys.path.insert(0, proj_root)

from core import database

print("[INFO] Starting DB audit check...")

try:
    database.ensure_schema()
    ts = int(time.time())
    session_id = f"audit_test_{ts}"
    print(f"[INFO] Creating session: {session_id}")
    db_id = database.create_session(session_id, "127.0.0.1", {"note": "audit test"})
    print(f"[INFO] Session DB id: {db_id}")

    # Add a scan
    scan_results = {"target": "127.0.0.1", "hosts_alive": ["127.0.0.1"], "meta": {"duration_s": 0.1}}
    scan_id = database.add_scan(session_id, "unit_test_scan", "127.0.0.1", scan_results)
    print(f"[INFO] Added scan id: {scan_id}")

    # Add a vulnerability
    vuln = {"type": "test_vuln", "severity": "low", "target": "127.0.0.1", "description": "Test vuln", "details": {}}
    vuln_id = database.add_vulnerability(session_id, vuln, scan_id)
    print(f"[INFO] Added vulnerability id: {vuln_id}")

    # Add an exploitation
    exploit = {"type": "test_exploit", "success": True, "command": "echo test", "output": "ok"}
    exploit_id = database.add_exploitation(session_id, vuln_id, exploit)
    print(f"[INFO] Added exploitation id: {exploit_id}")

    # Close session
    database.close_session(session_id, status='completed')
    print(f"[INFO] Closed session {session_id}")

    # Now query counts and last rows using the JSON DB API
    counts = database.get_counts()
    print('\n[DB SUMMARY]')
    print('Sessions:', counts.get('sessions'))
    print('Scans:', counts.get('scans'))
    print('Vulnerabilities:', counts.get('vulnerabilities'))
    print('Exploitations:', counts.get('exploitations'))

    db = database._load_db()

    def print_items(title, items, fields=None):
        print(f"\n[{title}]")
        for it in items:
            if fields:
                print(tuple(it.get(f) for f in fields))
            else:
                print(it)

    recent_sessions = database.list_sessions(limit=5)
    print_items('RECENT SESSIONS', recent_sessions, fields=['session_id', 'target', 'status', 'start_time', 'end_time'])

    recent_scans = sorted(db.get('scans', []), key=lambda x: x.get('created_at') or '', reverse=True)[:5]
    print_items('RECENT SCANS', recent_scans, fields=['id', 'session_id', 'scan_type', 'target', 'created_at'])

    recent_vulns = sorted(db.get('vulnerabilities', []), key=lambda x: x.get('created_at') or '', reverse=True)[:5]
    print_items('RECENT VULNERABILITIES', recent_vulns, fields=['id', 'session_id', 'vuln_type', 'severity', 'target', 'created_at'])

    recent_exps = sorted(db.get('exploitations', []), key=lambda x: x.get('created_at') or '', reverse=True)[:5]
    print_items('RECENT EXPLOITATIONS', recent_exps, fields=['id', 'session_id', 'vuln_id', 'exploit_type', 'success', 'command', 'created_at'])

    print('\n[INFO] DB audit check completed successfully.')

except Exception as e:
    print('[ERROR] Exception during DB audit test:', e)
    raise
