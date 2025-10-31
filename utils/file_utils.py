from datetime import datetime, timezone
import os
import json
from pathlib import Path


def save_json(path: str, data, pretty: bool = True):
    """Écrit `data` en JSON dans `path`. Crée le répertoire parent si besoin.

    Si `path` est un répertoire existant, utilise `results.json` comme nom par défaut.
    Retourne le chemin absolu du fichier écrit.
    """
    p = Path(path)
    if p.exists() and p.is_dir():
        p = p / "results.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    txt = json.dumps(data, indent=2, ensure_ascii=False, default=str) if pretty else json.dumps(data, ensure_ascii=False, default=str)
    p.write_text(txt, encoding='utf-8')
    return str(p.resolve())


def load_json(path: str):
    p = Path(path)
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding='utf-8'))


def make_run_dir(base_dir: str = "results", prefix: str = "run"):
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = Path(base_dir) / f"{prefix}_{ts}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return str(run_dir.resolve())
