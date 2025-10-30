"""
utils/file_utils.py
Helpers to save/load JSON with basic safety.
"""
import json
from pathlib import Path
from datetime import datetime
import os

def save_json(path: str, data, pretty: bool = True):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    txt = json.dumps(data, indent=2, ensure_ascii=False) if pretty else json.dumps(data, ensure_ascii=False)
    p.write_text(txt, encoding='utf-8')
    return str(p.resolve())

def load_json(path: str):
    p = Path(path)
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding='utf-8'))

def make_run_dir(base: str = "results") -> str:
    """Créer un répertoire d'exécution horodaté sous `base` et retourner son chemin.

    Ex: results/run_20251030T091000Z
    """
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    p = Path(base) / f"run_{ts}"
    p.mkdir(parents=True, exist_ok=True)
    return str(p.resolve())
