"""SIEM Africa - Agent : Logger commun."""
import logging
import logging.handlers
import os
from pathlib import Path

import config


def setup_logger(name="siem-agent"):
    """Cree un logger qui ecrit dans /var/log/siem-africa/agent.log + stdout."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    level = getattr(logging, config.LOG_LEVEL.upper(), logging.INFO)
    logger.setLevel(level)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console (stdout - capture par systemd vers journalctl)
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # Fichier
    log_dir = Path(config.LOG_DIR)
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        pass

    log_file = log_dir / "agent.log"
    try:
        fh = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=5_000_000, backupCount=5
        )
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except PermissionError:
        # Si on n'a pas le droit d'ecrire dans le log, tant pis on garde la console
        pass

    return logger
