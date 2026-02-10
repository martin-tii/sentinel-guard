import logging
import sys

def setup_logging():
    """Configures logging for Project Sentinel."""
    logger = logging.getLogger("Sentinel")
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    # Console Handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # File Handler
    fh = logging.FileHandler("audit.log")
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    return logger

logger = setup_logging()

def audit(action, details, status="ALLOWED"):
    """Logs an action to the audit log."""
    logger.info(f"[{status}] {action}: {details}")
