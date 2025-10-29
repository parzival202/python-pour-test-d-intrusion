"""
core/logger.py
Logger centralisé avec journalisation d'audit, rotation de fichiers et fonctions spécifiques au pentest.
Prend en charge la journalisation console + fichier, les journaux d'audit JSONL et la rotation à 10 Mo.
"""
import logging
import sys
import json
import time
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

def _json_line(name, level, msg, extra=None):
    """Générer une entrée de journal d'audit JSONL."""
    entry = {
        "ts": int(time.time()),
        "logger": name,
        "level": level,
        "msg": msg
    }
    if extra:
        entry.update(extra)
    return json.dumps(entry)

def get_logger(name, cfg=None):
    """Obtenir ou créer un logger configuré."""
    logger = logging.getLogger(name)
    if getattr(logger, "_configured", False):
        return logger

    # Définir le niveau à partir de la config ou par défaut INFO
    level_str = cfg.get("logging", {}).get("level", "INFO") if cfg else "INFO"
    level = getattr(logging, level_str.upper(), logging.INFO)
    logger.setLevel(level)

    # Gestionnaire console
    ch = logging.StreamHandler(sys.stdout)
    if cfg and cfg.get("logging", {}).get("json_lines"):
        class JSONFormatter(logging.Formatter):
            def format(self, record):
                return _json_line(record.name, record.levelname, record.getMessage())
        ch.setFormatter(JSONFormatter())
    else:
        fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        ch.setFormatter(fmt)
    logger.addHandler(ch)

    # Gestionnaire de fichier avec rotation (10 Mo max)
    log_file = cfg.get("logging", {}).get("file", "pentest.log") if cfg else "pentest.log"
    fh = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(fh)

    logger._configured = True
    return logger

# Fonctions de journalisation spécifiques au pentest
def log_scan_start(logger, target, scan_type):
    """Journaliser l'événement de début de scan."""
    logger.info(f"SCAN_START: Démarrage du scan {scan_type} sur {target}")
    # Journal d'audit
    audit_file = "audit.jsonl"
    with open(audit_file, "a", encoding="utf-8") as f:
        f.write(_json_line("audit", "INFO", f"Scan démarré : {scan_type} sur {target}",
                          {"event": "SCAN_START", "target": target, "type": scan_type}) + "\n")

def log_vulnerability(logger, target, vuln_type, severity="medium", details=None):
    """Journaliser la découverte de vulnérabilité."""
    msg = f"VULNERABILITY: {vuln_type} trouvé sur {target} (sévérité : {severity})"
    if details:
        msg += f" - {details}"
    logger.warning(msg)
    # Journal d'audit
    audit_file = "audit.jsonl"
    with open(audit_file, "a", encoding="utf-8") as f:
        f.write(_json_line("audit", "WARNING", msg,
                          {"event": "VULNERABILITY", "target": target, "type": vuln_type,
                           "severity": severity, "details": details or {}}) + "\n")

def log_exploitation(logger, target, exploit_type, success=False, details=None):
    """Journaliser la tentative/résultat d'exploitation."""
    status = "SUCCESS" if success else "ATTEMPT"
    msg = f"EXPLOITATION: {status} - {exploit_type} sur {target}"
    if details:
        msg += f" - {details}"
    logger.info(msg)
    # Journal d'audit
    audit_file = "audit.jsonl"
    with open(audit_file, "a", encoding="utf-8") as f:
        f.write(_json_line("audit", "INFO", msg,
                          {"event": "EXPLOITATION", "target": target, "type": exploit_type,
                           "success": success, "details": details or {}}) + "\n")
