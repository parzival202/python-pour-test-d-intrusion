"""
core/database.py
Assistant SQLite pour la base de données stockant les sessions de pentest, scans, vulnérabilités et exploitations.
Fournit des opérations CRUD pour toutes les entités.
"""
import sqlite3
import json
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime

# Chemin de la base de données selon les exigences TODO
DB_DIR = Path("./results")
DB_PATH = DB_DIR / "pentest.db"

def get_connection():
    """Obtenir une connexion à la base de données avec la configuration appropriée."""
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def ensure_schema():
    """Créer toutes les tables nécessaires si elles n'existent pas."""
    conn = get_connection()
    c = conn.cursor()

    # Table des sessions
    c.execute("""CREATE TABLE IF NOT EXISTS sessions (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   session_id TEXT UNIQUE,
                   target TEXT,
                   config_json TEXT,
                   start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                   end_time DATETIME,
                   status TEXT DEFAULT 'running'
                 )""")

    # Table des scans
    c.execute("""CREATE TABLE IF NOT EXISTS scans (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   session_id TEXT,
                   scan_type TEXT,
                   target TEXT,
                   results_json TEXT,
                   created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                   FOREIGN KEY (session_id) REFERENCES sessions (session_id)
                 )""")

    # Table des vulnérabilités
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

    # Table des exploitations
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

# CRUD des sessions
def create_session(session_id: str, target: str, config: Optional[Dict] = None) -> int:
    """Créer une nouvelle session. Retourne l'ID de session DB."""
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
    """Fermer la session avec le statut."""
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
    """Obtenir les détails de la session."""
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

# CRUD des scans
def add_scan(session_id: str, scan_type: str, target: str, results: Dict) -> int:
    """Ajouter les résultats du scan et retourner scan_id."""
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
    """Obtenir tous les scans pour une session."""
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

# CRUD des vulnérabilités
def add_vulnerability(session_id: str, vuln_dict: Dict, scan_id: Optional[int] = None) -> int:
    """Ajouter une découverte de vulnérabilité et retourner vuln_id."""
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
    """Obtenir toutes les vulnérabilités pour une session."""
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

# CRUD des exploitations
def add_exploitation(session_id: str, vuln_id: int, exploit_dict: Dict) -> int:
    """Ajouter une tentative d'exploitation et retourner exploit_id."""
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
    """Obtenir toutes les exploitations pour une session."""
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

# Fonctions utilitaires
def get_session_summary(session_id: str) -> Dict:
    """Obtenir un résumé complet de la session."""
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
    """Supprimer les sessions plus anciennes que le nombre de jours spécifié."""
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
    """Obtenir les résultats complets de la session sous forme de dictionnaire."""
    return get_session_summary(session_id)


def persist_result(session_id: str, result: Dict) -> Dict:
    """Persist un dictionnaire de résultats de module dans la base.

    Comportement heuristique :
    - si le dict contient une clé 'scan_type' ou 'scan' => crée un enregistrement dans `scans`
    - si le dict contient 'vulnerabilities' (liste) => insère chaque vuln via add_vulnerability
    - si le dict contient 'exploitations' ou 'exploits' (liste) => insère via add_exploitation
    - si le dict ressemble à une vulnérabilité unique (presence de 'type' et 'severity') => l'insère
    Retourne un résumé des ids insérés.
    """
    ensure_schema()
    summary = {"scans": [], "vulnerabilities": [], "exploitations": []}
    try:
        # Track the most recently created scan id(s). If multiple scans are created, keep the last one as a sensible default
        last_scan_id = None

        # Single scan object (top-level)
        if isinstance(result, dict) and (result.get('scan_type') or result.get('scan')):
            scan_type = result.get('scan_type') or (result.get('scan') and result.get('scan').get('type')) or 'unknown'
            target = result.get('target') or result.get('scan', {}).get('target', '')
            results_blob = result.get('results') or result.get('scan') or result
            scan_id = add_scan(session_id, scan_type, target, results_blob)
            last_scan_id = scan_id
            summary['scans'].append(scan_id)

        # Top-level list of scans
        if isinstance(result, dict) and isinstance(result.get('scans'), list):
            for s in result.get('scans'):
                stype = s.get('scan_type') or s.get('type', 'unknown')
                target = s.get('target', '')
                sid = add_scan(session_id, stype, target, s.get('results') or s)
                last_scan_id = sid
                summary['scans'].append(sid)

        # Vulnerabilities list
        if isinstance(result, dict) and isinstance(result.get('vulnerabilities'), list):
            for v in result.get('vulnerabilities'):
                vid = add_vulnerability(session_id, v, last_scan_id)
                summary['vulnerabilities'].append(vid)

        # Single vulnerability dict (only insert if not part of vulnerabilities list)
        if isinstance(result, dict) and result.get('type') and result.get('severity') and not isinstance(result.get('vulnerabilities'), list):
            vid = add_vulnerability(session_id, result, last_scan_id)
            summary['vulnerabilities'].append(vid)

        # Exploitations list
        if isinstance(result, dict) and isinstance(result.get('exploitations'), list):
            for e in result.get('exploitations'):
                vuln_ref = e.get('vuln_id') or (e.get('vuln') and e.get('vuln').get('id'))
                exid = add_exploitation(session_id, vuln_ref, e)
                summary['exploitations'].append(exid)

        # Single exploitation dict
        if isinstance(result, dict) and (result.get('success') is not None) and result.get('type') and not isinstance(result.get('exploitations'), list):
            vuln_ref = result.get('vuln_id') or (result.get('vuln') and result.get('vuln').get('id'))
            exid = add_exploitation(session_id, vuln_ref, result)
            summary['exploitations'].append(exid)

    except Exception:
        # Ne pas rater la persistance globale si une insertion échoue; remonter l'exception
        raise
    return summary
