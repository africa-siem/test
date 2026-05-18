"""
SIEM Africa - Agent (Module 3)
Configuration du logging avec rotation automatique

Tous les modules de l'agent utilisent logging.getLogger(__name__).
Les logs sont écrits dans /var/log/siem-africa/agent.log avec rotation 10MB x 5.
"""
import logging
import logging.handlers
import sys
from pathlib import Path

from config import LOG_DIR, LOG_FILE, LOG_LEVEL


def setup_logging():
    """
    Configure le logger root pour toute l'application.
    À appeler une seule fois au démarrage dans main.py.
    """
    # Créer le dossier de logs si absent (avec gestion d'erreur)
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        # Si pas les droits, on passera juste par stdout
        pass

    # Format des messages
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Handler fichier avec rotation (10 MB par fichier, 5 fichiers conservés)
    handlers = []
    if LOG_FILE.parent.exists() and (LOG_FILE.parent.is_dir()):
        try:
            file_handler = logging.handlers.RotatingFileHandler(
                str(LOG_FILE),
                maxBytes=10 * 1024 * 1024,  # 10 MB
                backupCount=5,
                encoding="utf-8",
            )
            file_handler.setFormatter(formatter)
            handlers.append(file_handler)
        except (PermissionError, OSError):
            pass

    # Handler console (toujours actif, utile pour systemd journal)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    handlers.append(console_handler)

    # Configuration du root logger
    level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)

    # Nettoyer les handlers existants (au cas où on relance setup)
    for h in list(root.handlers):
        root.removeHandler(h)

    for h in handlers:
        root.addHandler(h)

    return root


def get_logger(name):
    """Helper pour récupérer un logger nommé."""
    return logging.getLogger(name)
