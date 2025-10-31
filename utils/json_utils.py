"""Helpers pour normaliser des objets Python en structures JSON-serializables.

Fonctions:
- normalize_for_json(obj): conversion récursive en dict/list/primitive
"""
from datetime import datetime, date
from pathlib import Path
from typing import Any


def _is_dataclass_instance(obj: Any) -> bool:
    try:
        from dataclasses import is_dataclass
        return is_dataclass(obj) and not isinstance(obj, type)
    except Exception:
        return False


def normalize_for_json(obj: Any) -> Any:
    """Convertit récursivement `obj` en une structure JSON-serializable.

    Gère: dict, list, tuple, set, datetime/date (isoformat), Path, dataclasses,
    objets avec to_dict()/__dict__.
    """
    # Primitives
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj

    # datetime/date
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()

    # Path -> str
    if isinstance(obj, Path):
        return str(obj)

    # Dicts
    if isinstance(obj, dict):
        return {str(k): normalize_for_json(v) for k, v in obj.items()}

    # Iterables
    if isinstance(obj, (list, tuple, set)):
        return [normalize_for_json(v) for v in obj]

    # dataclass instance
    if _is_dataclass_instance(obj):
        return normalize_for_json(obj.__dict__)

    # objects with to_dict
    if hasattr(obj, 'to_dict') and callable(getattr(obj, 'to_dict')):
        try:
            return normalize_for_json(obj.to_dict())
        except Exception:
            pass

    # objects with __dict__
    if hasattr(obj, '__dict__'):
        try:
            data = {k: v for k, v in vars(obj).items() if not k.startswith('_')}
            return normalize_for_json(data)
        except Exception:
            pass

    # fallback to str
    try:
        return str(obj)
    except Exception:
        return None
