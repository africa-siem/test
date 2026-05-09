"""SIEM Africa - Agent : Dedup d'emails par signature.

Si la meme signature_hash a deja envoye un email dans les X dernieres minutes,
on saute l'envoi pour eviter d'inonder la boite.

Stockage en RAM uniquement (perdu au restart, c'est acceptable).
"""
import threading
import time

import db
from logger import setup_logger


log = setup_logger("notif.dedup")


_LOCK = threading.Lock()
_RECENT = {}  # signature_hash -> last_email_timestamp


def _get_window_seconds():
    val = db.get_setting("email_dedup_window_minutes")
    try:
        return int(val) * 60 if val else 5 * 60
    except (TypeError, ValueError):
        return 5 * 60


def is_duplicate(sig_hash):
    """Retourne True si on a deja envoye un email pour cette signature recemment."""
    if not sig_hash:
        return False

    window = _get_window_seconds()
    if window <= 0:
        return False  # Dedup desactive

    now = time.time()
    with _LOCK:
        # Cleanup vieux entries (> 1h)
        expired = [k for k, t in _RECENT.items() if now - t > 3600]
        for k in expired:
            del _RECENT[k]

        last = _RECENT.get(sig_hash)
        if last is not None and (now - last) < window:
            log.debug(f"Dedup hit pour {sig_hash[:12]}... ({int(now - last)}s)")
            return True
        return False


def mark_sent(sig_hash):
    """Marque qu'on vient d'envoyer un email pour cette signature."""
    if not sig_hash:
        return
    with _LOCK:
        _RECENT[sig_hash] = time.time()


def stats():
    with _LOCK:
        return {"tracked_signatures": len(_RECENT)}
