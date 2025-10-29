"""
core/logger.py
Centralized logger with audit logging, file rotation, and specific pentest functions.
Supports console + file logging, JSONL audit logs, and rotation at 10MB.
"""
import logging
import sys
import json
import time
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

def _json_line(name, level, msg, extra=None):
    """Generate JSONL audit log entry."""
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
    """Get or create a configured logger."""
    logger = logging.getLogger(name)
    if getattr(logger, "_configured", False):
        return logger

    # Set level from config or default to INFO
    level_str = cfg.get("logging", {}).get("level", "INFO") if cfg else "INFO"
    level = getattr(logging, level_str.upper(), logging.INFO)
    logger.setLevel(level)

    # Console handler
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

    # File handler with rotation (10MB max)
    log_file = cfg.get("logging", {}).get("file", "pentest.log") if cfg else "pentest.log"
    fh = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(fh)

    logger._configured = True
    return logger

# Specific pentest logging functions
def log_scan_start(logger, target, scan_type):
    """Log scan start event."""
    logger.info(f"SCAN_START: Starting {scan_type} scan on {target}")
    # Audit log
    audit_file = "audit.jsonl"
    with open(audit_file, "a", encoding="utf-8") as f:
        f.write(_json_line("audit", "INFO", f"Scan started: {scan_type} on {target}",
                          {"event": "SCAN_START", "target": target, "type": scan_type}) + "\n")

def log_vulnerability(logger, target, vuln_type, severity="medium", details=None):
    """Log vulnerability finding."""
    msg = f"VULNERABILITY: {vuln_type} found on {target} (severity: {severity})"
    if details:
        msg += f" - {details}"
    logger.warning(msg)
    # Audit log
    audit_file = "audit.jsonl"
    with open(audit_file, "a", encoding="utf-8") as f:
        f.write(_json_line("audit", "WARNING", msg,
                          {"event": "VULNERABILITY", "target": target, "type": vuln_type,
                           "severity": severity, "details": details or {}}) + "\n")

def log_exploitation(logger, target, exploit_type, success=False, details=None):
    """Log exploitation attempt/result."""
    status = "SUCCESS" if success else "ATTEMPT"
    msg = f"EXPLOITATION: {status} - {exploit_type} on {target}"
    if details:
        msg += f" - {details}"
    logger.info(msg)
    # Audit log
    audit_file = "audit.jsonl"
    with open(audit_file, "a", encoding="utf-8") as f:
        f.write(_json_line("audit", "INFO", msg,
                          {"event": "EXPLOITATION", "target": target, "type": exploit_type,
                           "success": success, "details": details or {}}) + "\n")
