"""
core/database.py
SQLite database helper for storing pentest sessions, scans, vulnerabilities, and exploitations.
Provides CRUD operations for all entities.
"""
import sqlite3
import json
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime

# Database path as per TODO requirements
DB_DIR = Path("./results")
DB_PATH = DB_DIR / "pentest.db"

def get_connection():
    """Get database connection with proper configuration."""
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def ensure_schema():
    """Create all necessary tables if they don't exist."""
    conn = get_connection()
    c = conn.cursor()

    # Sessions table
    c.execute("""CREATE TABLE IF NOT EXISTS sessions (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   session_id TEXT UNIQUE,
                   target TEXT,
                   config_json TEXT,
                   start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                   end_time DATETIME,
                   status TEXT DEFAULT 'running'
                 )""")

    # Scans table
    c.execute("""CREATE TABLE IF NOT EXISTS scans (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   session_id TEXT,
                   scan_type TEXT,
                   target TEXT,
                   results_json TEXT,
                   created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                   FOREIGN KEY (session_id) REFERENCES sessions (session_id)
                 )""")

    # Vulnerabilities table
    c.execute("""CREATE TABLE IF NOT EXISTS vulnerabilities (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   session_id TEXT,
                   scan_id INTEGER,
                   vuln_type TEXT,
                   severity TEXT,
                   target TEXT,
                   description TEXT,
                   details_json TEXT,
                   created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                   FOREIGN KEY (session_id) REFERENCES sessions (session_id),
                   FOREIGN KEY (scan_id) REFERENCES scans (id)
                 )""")

    # Exploitations table
    c.execute("""CREATE TABLE IF NOT EXISTS exploitations (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   session_id TEXT,
                   vuln_id INTEGER,
                   exploit_type TEXT,
                   success BOOLEAN,
                   command TEXT,
                   output TEXT,
                   details_json TEXT,
                   created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                   FOREIGN KEY (session_id) REFERENCES sessions (session_id),
                   FOREIGN KEY (vuln_id) REFERENCES vulnerabilities (id)
                 )""")

    conn.commit()
    conn.close()

# Session CRUD
def create_session(session_id: str, target: str, config: Optional[Dict] = None) -> int:
    """Create a new session. Returns session DB ID."""
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO sessions (session_id, target, config_json) VALUES (?, ?, ?)",
                  (session_id, target, json.dumps(config or {}, ensure_ascii=False)))
        session_db_id = c.lastrowid
        conn.commit()
        return session_db_id
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def close_session(session_id: str, status: str = 'finished'):
    """Close session with status."""
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute("UPDATE sessions SET status = ?, end_time = ? WHERE session_id = ?",
                  (status, datetime.utcnow(), session_id))
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def get_session(session_id: str) -> Optional[Dict]:
    """Get session details."""
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
        row = c.fetchone()
        if row:
            return {
                "id": row[0],
                "session_id": row[1],
                "target": row[2],
                "config": json.loads(row[3]) if row[3] else {},
                "start_time": row[4],
                "end_time": row[5],
                "status": row[6]
            }
        return None
    finally:
        conn.close()

# Scan CRUD
def add_scan(session_id: str, scan_type: str, target: str, results: Dict) -> int:
    """Add scan results and return scan_id."""
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO scans (session_id, scan_type, target, results_json) VALUES (?, ?, ?, ?)",
                  (session_id, scan_type, target, json.dumps(results, ensure_ascii=False)))
        scan_id = c.lastrowid
        conn.commit()
        return scan_id
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def get_scans_by_session(session_id: str) -> List[Dict]:
    """Get all scans for a session."""
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute("SELECT * FROM scans WHERE session_id = ? ORDER BY created_at", (session_id,))
        rows = c.fetchall()
        return [{
            "id": row[0],
            "session_id": row[1],
            "scan_type": row[2],
            "target": row[3],
            "results": json.loads(row[4]) if row[4] else {},
            "created_at": row[5]
        } for row in rows]
    finally:
        conn.close()

# Vulnerability CRUD
def add_vulnerability(session_id: str, vuln_dict: Dict, scan_id: Optional[int] = None) -> int:
    """Add vulnerability finding and return vuln_id."""
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute("""INSERT INTO vulnerabilities (session_id, scan_id, vuln_type, severity, target, description, details_json)
                     VALUES (?, ?, ?, ?, ?, ?, ?)""",
                  (session_id, scan_id, vuln_dict.get('type', 'unknown'),
                   vuln_dict.get('severity', 'medium'), vuln_dict.get('target', ''),
                   vuln_dict.get('description', ''), json.dumps(vuln_dict, ensure_ascii=False)))
        vuln_id = c.lastrowid
        conn.commit()
        return vuln_id
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def get_vulnerabilities_by_session(session_id: str) -> List[Dict]:
    """Get all vulnerabilities for a session."""
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute("SELECT * FROM vulnerabilities WHERE session_id = ? ORDER BY created_at", (session_id,))
        rows = c.fetchall()
        return [{
            "id": row[0],
            "session_id": row[1],
            "scan_id": row[2],
            "vuln_type": row[3],
            "severity": row[4],
            "target": row[5],
            "description": row[6],
            "details": json.loads(row[7]) if row[7] else {},
            "created_at": row[8]
        } for row in rows]
    finally:
        conn.close()

# Exploitation CRUD
def add_exploitation(session_id: str, vuln_id: int, exploit_dict: Dict) -> int:
    """Add exploitation attempt and return exploit_id."""
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute("""INSERT INTO exploitations (session_id, vuln_id, exploit_type, success, command, output, details_json)
                     VALUES (?, ?, ?, ?, ?, ?, ?)""",
                  (session_id, vuln_id, exploit_dict.get('type', 'unknown'),
                   exploit_dict.get('success', False), exploit_dict.get('command', ''),
                   exploit_dict.get('output', ''), json.dumps(exploit_dict, ensure_ascii=False)))
        exploit_id = c.lastrowid
        conn.commit()
        return exploit_id
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def get_exploitations_by_session(session_id: str) -> List[Dict]:
    """Get all exploitations for a session."""
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute("SELECT * FROM exploitations WHERE session_id = ? ORDER BY created_at", (session_id,))
        rows = c.fetchall()
        return [{
            "id": row[0],
            "session_id": row[1],
            "vuln_id": row[2],
            "exploit_type": row[3],
            "success": bool(row[4]),
            "command": row[5],
            "output": row[6],
            "details": json.loads(row[7]) if row[7] else {},
            "created_at": row[8]
        } for row in rows]
    finally:
        conn.close()

# Utility functions
def get_session_summary(session_id: str) -> Dict:
    """Get comprehensive session summary."""
    session = get_session(session_id)
    if not session:
        return {}

    return {
        "session": session,
        "scans": get_scans_by_session(session_id),
        "vulnerabilities": get_vulnerabilities_by_session(session_id),
        "exploitations": get_exploitations_by_session(session_id)
    }

def cleanup_old_sessions(days: int = 30):
    """Remove sessions older than specified days."""
    from datetime import timedelta
    cutoff = datetime.utcnow() - timedelta(days=days)
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute("DELETE FROM sessions WHERE start_time < ?", (cutoff,))
        deleted = c.rowcount
        conn.commit()
        return deleted
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def get_session_results(session_id: str) -> Dict:
    """Get complete session results as dict."""
    return get_session_summary(session_id)
