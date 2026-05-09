"""SIEM Africa - Agent : Rate limiter pour les emails.

Compte les emails envoyes dans la derniere heure (table email_logs).
Si on atteint le seuil, on bloque l'envoi mais on logue.
"""
import db
from logger import setup_logger


log = setup_logger("notif.rate_limiter")


def count_sent_last_hour():
    """Retourne le nombre d'emails 'sent' dans la derniere heure."""
    try:
        conn = db._get_conn()
        row = conn.execute(
            """
            SELECT COUNT(*) AS c FROM email_logs
             WHERE status='sent' AND created_at >= datetime('now', '-1 hour')
            """
        ).fetchone()
        return row["c"] if row else 0
    except Exception as exc:  # noqa: BLE001
        log.warning(f"Comptage emails impossible : {exc}")
        return 0


def is_exceeded(limit=None):
    """Renvoie True si on a deja envoye >= limit emails dans la derniere heure.

    Si `limit` est None, on lit settings.email_rate_limit_per_hour (defaut 30).
    """
    if limit is None:
        limit = _get_limit()

    if limit <= 0:
        return False  # 0 = pas de limite

    sent = count_sent_last_hour()
    if sent >= limit:
        log.warning(f"Rate limit atteint : {sent}/{limit} emails dans la derniere heure")
        _log_skip(sent, limit)
        return True
    return False


def _get_limit():
    val = db.get_setting("email_rate_limit_per_hour")
    try:
        return int(val) if val is not None else 30
    except (TypeError, ValueError):
        return 30


def _log_skip(sent, limit):
    """Logue un skip dans email_logs avec status='rate_limited'."""
    try:
        conn = db._get_conn()
        conn.execute(
            """
            INSERT INTO email_logs (recipient, subject, status, error_message, created_at)
            VALUES (?, ?, 'rate_limited', ?, CURRENT_TIMESTAMP)
            """,
            ("(skipped)", "(rate limited)",
             f"Skipped : {sent}/{limit} emails dans la derniere heure"),
        )
    except Exception:  # noqa: BLE001
        pass
