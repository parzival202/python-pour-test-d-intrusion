"""
core/logger.py
Simple logger helper. Returns a logger which prints either formatted lines
or JSON lines depending on config['logging']['json_lines'].
"""
import logging
import sys
import json
import time

def _json_line(name, level, msg):
    return json.dumps({
        "ts": int(time.time()),
        "logger": name,
        "level": level,
        "msg": msg
    })

def get_logger(name, cfg=None):
    logger = logging.getLogger(name)
    if getattr(logger, "_configured", False):
        return logger
    logger.setLevel(logging.INFO)
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
    logger._configured = True
    return logger
