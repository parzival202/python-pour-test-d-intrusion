import logging
import os
from logging.handlers import RotatingFileHandler

def get_logger(name="ptf"):
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(ch)

    run_dir = os.environ.get("RUN_DIR", None)
    if run_dir:
        try:
            log_path = os.path.join(run_dir, "run.log")
            fh = RotatingFileHandler(log_path, maxBytes=5_000_000, backupCount=3)
            fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
            logger.addHandler(fh)
        except Exception:
            logger.debug("Could not add file handler.")
    return logger
