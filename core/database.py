"""
core/database.py
Small persistence helper (stub). Use this later if you want to store sessions/results in sqlite.
"""
import sqlite3
from pathlib import Path

DB_PATH = Path("pentest_results.db")

def ensure_schema():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS scans (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   session_id TEXT,
                   target TEXT,
                   type TEXT,
                   result_json TEXT,
                   created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                 )""")
    conn.commit()
    conn.close()

def save_scan(session_id, target, scan_type, result_json):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO scans (session_id, target, type, result_json) VALUES (?, ?, ?, ?)",
              (session_id, target, scan_type, result_json))
    conn.commit()
    conn.close()
