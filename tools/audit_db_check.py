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
from core.database import get_connection

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

    # Now query counts and last rows
    conn = get_connection()
    c = conn.cursor()
    def fetch_count(q):
        c.execute(q)
        return c.fetchone()[0]

    print('\n[DB SUMMARY]')
    print('Sessions:', fetch_count("SELECT COUNT(*) FROM sessions"))
    print('Scans:', fetch_count("SELECT COUNT(*) FROM scans"))
    print('Vulnerabilities:', fetch_count("SELECT COUNT(*) FROM vulnerabilities"))
    print('Exploitations:', fetch_count("SELECT COUNT(*) FROM exploitations"))

    def print_rows(cursor):
        rows = cursor.fetchall()
        for r in rows:
            # sqlite3.Row -> convert to tuple for friendly print
            try:
                print(tuple(r))
            except Exception:
                print(r)

    print('\n[RECENT SESSIONS]')
    c.execute("SELECT session_id, target, status, start_time, end_time FROM sessions ORDER BY start_time DESC LIMIT 5")
    print_rows(c)

    print('\n[RECENT SCANS]')
    c.execute("SELECT id, session_id, scan_type, target, created_at FROM scans ORDER BY created_at DESC LIMIT 5")
    print_rows(c)

    print('\n[RECENT VULNERABILITIES]')
    c.execute("SELECT id, session_id, vuln_type, severity, target, created_at FROM vulnerabilities ORDER BY created_at DESC LIMIT 5")
    print_rows(c)

    print('\n[RECENT EXPLOITATIONS]')
    # exploitations table schema: id, session_id, vuln_id, exploit_type, success, command, output, details_json, created_at
    c.execute("SELECT id, session_id, vuln_id, exploit_type, success, command, created_at FROM exploitations ORDER BY created_at DESC LIMIT 5")
    print_rows(c)

    conn.close()
    print('\n[INFO] DB audit check completed successfully.')

except Exception as e:
    print('[ERROR] Exception during DB audit test:', e)
    raise
