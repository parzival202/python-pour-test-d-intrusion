"""
core/database.py
Implementation légère de la persistance en utilisant uniquement la stdlib (JSON file)
Remplace sqlite par un fichier JSON pour éviter les problèmes d'environnement.

Le fichier est `results/pentest_db.json` et contient les listes : sessions, scans,
vulnerabilities, exploitations et des compteurs d'IDs.

L'API reste la même (fonctions CRUD) pour limiter les changements côté appelant.
"""
import json
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime, timezone, timedelta

# Fichier de base de données (JSON)
DB_DIR = Path("./results")
DB_FILE = DB_DIR / "pentest_db.json"


def _ensure_db_file():
    DB_DIR.mkdir(parents=True, exist_ok=True)
    if not DB_FILE.exists():
        initial = {
            "next_ids": {"session": 1, "scan": 1, "vuln": 1, "exploit": 1},
            "sessions": [],
            "scans": [],
            "vulnerabilities": [],
            "exploitations": []
        }
        DB_FILE.write_text(json.dumps(initial, indent=2, default=str), encoding='utf-8')


def _load_db() -> Dict:
    _ensure_db_file()
    try:
        return json.loads(DB_FILE.read_text(encoding='utf-8'))
    except Exception:
        # Recreate if corrupted
        _ensure_db_file()
        return json.loads(DB_FILE.read_text(encoding='utf-8'))


def _save_db(data: Dict):
    tmp = DB_FILE.with_suffix('.tmp')
    tmp.write_text(json.dumps(data, indent=2, default=str), encoding='utf-8')
    tmp.replace(DB_FILE)


def ensure_schema():
    """S'assure que le fichier DB existe et possède les clefs de base."""
    _ensure_db_file()

# CRUD des sessions
def create_session(session_id: str, target: str, config: Optional[Dict] = None) -> int:
    """Créer une nouvelle session. Retourne l'ID de session DB."""
    db = _load_db()
    sid = db['next_ids']['session']
    db['next_ids']['session'] += 1
    now = datetime.now(timezone.utc).isoformat()
    db['sessions'].append({
        'id': sid,
        'session_id': session_id,
        'target': target,
        'config': config or {},
        'start_time': now,
        'end_time': None,
        'status': 'running'
    })
    _save_db(db)
    return sid

def close_session(session_id: str, status: str = 'finished'):
    """Fermer la session avec le statut."""
    db = _load_db()
    now = datetime.now(timezone.utc).isoformat()
    changed = False
    for s in db.get('sessions', []):
        if s.get('session_id') == session_id:
            s['status'] = status
            s['end_time'] = now
            changed = True
            break
    if changed:
        _save_db(db)

def get_session(session_id: str) -> Optional[Dict]:
    """Obtenir les détails de la session."""
    db = _load_db()
    for s in db.get('sessions', []):
        if s.get('session_id') == session_id:
            return s
    return None

# CRUD des scans
def add_scan(session_id: str, scan_type: str, target: str, results: Dict) -> int:
    """Ajouter les résultats du scan et retourner scan_id."""
    db = _load_db()
    sid = db['next_ids']['scan']
    db['next_ids']['scan'] += 1
    now = datetime.now(timezone.utc).isoformat()
    db['scans'].append({
        'id': sid,
        'session_id': session_id,
        'scan_type': scan_type,
        'target': target,
        'results': results,
        'created_at': now
    })
    _save_db(db)
    return sid

def get_scans_by_session(session_id: str) -> List[Dict]:
    """Obtenir tous les scans pour une session."""
    db = _load_db()
    scans = [s for s in db.get('scans', []) if s.get('session_id') == session_id]
    scans.sort(key=lambda x: x.get('created_at'))
    return scans

# CRUD des vulnérabilités
def add_vulnerability(session_id: str, vuln_dict: Dict, scan_id: Optional[int] = None) -> int:
    """Ajouter une découverte de vulnérabilité et retourner vuln_id."""
    db = _load_db()
    vid = db['next_ids']['vuln']
    db['next_ids']['vuln'] += 1
    now = datetime.now(timezone.utc).isoformat()
    db['vulnerabilities'].append({
        'id': vid,
        'session_id': session_id,
        'scan_id': scan_id,
        'vuln_type': vuln_dict.get('type', 'unknown'),
        'severity': vuln_dict.get('severity', 'medium'),
        'target': vuln_dict.get('target', ''),
        'description': vuln_dict.get('description', ''),
        'details': vuln_dict,
        'created_at': now
    })
    _save_db(db)
    return vid

def get_vulnerabilities_by_session(session_id: str) -> List[Dict]:
    """Obtenir toutes les vulnérabilités pour une session."""
    db = _load_db()
    vulns = [v for v in db.get('vulnerabilities', []) if v.get('session_id') == session_id]
    vulns.sort(key=lambda x: x.get('created_at'))
    return vulns

# CRUD des exploitations
def add_exploitation(session_id: str, vuln_id: int, exploit_dict: Dict) -> int:
    """Ajouter une tentative d'exploitation et retourner exploit_id."""
    db = _load_db()
    eid = db['next_ids']['exploit']
    db['next_ids']['exploit'] += 1
    now = datetime.now(timezone.utc).isoformat()
    db['exploitations'].append({
        'id': eid,
        'session_id': session_id,
        'vuln_id': vuln_id,
        'exploit_type': exploit_dict.get('type', 'unknown'),
        'success': bool(exploit_dict.get('success', False)),
        'command': exploit_dict.get('command', ''),
        'output': exploit_dict.get('output', ''),
        'details': exploit_dict,
        'created_at': now
    })
    _save_db(db)
    return eid

def get_exploitations_by_session(session_id: str) -> List[Dict]:
    """Obtenir toutes les exploitations pour une session."""
    db = _load_db()
    exs = [e for e in db.get('exploitations', []) if e.get('session_id') == session_id]
    exs.sort(key=lambda x: x.get('created_at'))
    return exs

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
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    cutoff_iso = cutoff.isoformat()
    db = _load_db()
    original_count = len(db.get('sessions', []))
    # Keep sessions with start_time >= cutoff
    kept = []
    removed_session_ids = set()
    for s in db.get('sessions', []):
        st = s.get('start_time')
        if not st or st >= cutoff_iso:
            kept.append(s)
        else:
            removed_session_ids.add(s.get('session_id'))

    db['sessions'] = kept
    # Also remove scans/vulns/exploits related to removed sessions
    db['scans'] = [sc for sc in db.get('scans', []) if sc.get('session_id') not in removed_session_ids]
    db['vulnerabilities'] = [v for v in db.get('vulnerabilities', []) if v.get('session_id') not in removed_session_ids]
    db['exploitations'] = [e for e in db.get('exploitations', []) if e.get('session_id') not in removed_session_ids]

    _save_db(db)
    deleted = original_count - len(db.get('sessions', []))
    return deleted

def get_session_results(session_id: str) -> Dict:
    """Obtenir les résultats complets de la session sous forme de dictionnaire."""
    return get_session_summary(session_id)


def list_sessions(limit: Optional[int] = None) -> List[Dict]:
    """Retourne la liste des sessions triées par start_time desc.

    limit: si fourni, limite le nombre de sessions retournées.
    """
    db = _load_db()
    sess = list(db.get('sessions', []))
    sess.sort(key=lambda x: x.get('start_time') or '', reverse=True)
    if limit:
        return sess[:limit]
    return sess


def get_counts() -> Dict[str, int]:
    """Retourne un dict avec les comptes de chaque table."""
    db = _load_db()
    return {
        'sessions': len(db.get('sessions', [])),
        'scans': len(db.get('scans', [])),
        'vulnerabilities': len(db.get('vulnerabilities', [])),
        'exploitations': len(db.get('exploitations', []))
    }


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
