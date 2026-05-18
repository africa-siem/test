"""SIEM Africa - Agent : Orchestrateur de notifications.

Point d'entree unique pour notifier une alerte. Combine :
  - rate_limiter  (max 30 emails/h via SQL email_logs)
  - deduplicator  (memoire RAM, 5 min par signature_hash)
  - digest_worker (LOW/MEDIUM en email recap horaire)
  - email_sender  (envoi reel pour CRITICAL/HIGH ou si digest desactive)
"""
import db
from logger import setup_logger
from notif import deduplicator, digest_worker, email_sender, rate_limiter


log = setup_logger("notif.notifier")


# Severites considerees comme "critiques" -> email immediat
IMMEDIATE_SEVERITIES = {"CRITICAL", "HIGH"}


def notify(alert, signature_hash=None):
    """Notifie une alerte selon les regles de protection.

    `alert` : dict avec title, severity, src_ip, dst_ip, description,
              ai_description, ai_remediation, alert_id (optionnel).
    `signature_hash` : pour le dedup. Si absent, le dedup est saute.

    Retourne dict {action: 'sent'|'digested'|'deduplicated'|'rate_limited'|'disabled'}.
    """
    severity = (alert.get("severity") or "MEDIUM").upper()

    if not email_sender.is_configured():
        log.debug("Email non configure - skip notification")
        return {"action": "disabled"}

    if not db.get_setting_bool("email_enabled", True):
        log.debug("Emails desactives dans settings")
        return {"action": "disabled"}

    # Filtre par severite minimale
    min_sev = (db.get_setting("email_min_severity") or "INFO").upper()
    severity_order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    if severity_order.get(severity, 2) < severity_order.get(min_sev, 0):
        log.debug(f"Alerte {severity} sous le seuil {min_sev} - skip")
        return {"action": "below_threshold"}

    # Cas 1 : severite immediate (CRITICAL/HIGH)
    if severity in IMMEDIATE_SEVERITIES:
        return _send_immediate(alert, signature_hash)

    # Cas 2 : LOW/MEDIUM/INFO -> digest si active
    if digest_worker.is_enabled():
        digest_worker.add_alert(alert)
        log.info(f"Alerte {severity} ajoutee au digest (id={alert.get('alert_id')})")
        return {"action": "digested"}

    # Digest desactive -> on essaie l'envoi immediat (avec dedup + rate limit)
    return _send_immediate(alert, signature_hash)


def _send_immediate(alert, signature_hash):
    """Envoie immediat avec verification dedup + rate limit."""
    # Dedup
    if signature_hash and deduplicator.is_duplicate(signature_hash):
        log.info(f"Email dedup pour signature {signature_hash[:12]}... - skip")
        return {"action": "deduplicated"}

    # Rate limit
    if rate_limiter.is_exceeded():
        return {"action": "rate_limited"}

    # Envoi reel
    ok = email_sender.send_alert_email(alert)
    if ok:
        if signature_hash:
            deduplicator.mark_sent(signature_hash)
        return {"action": "sent"}
    return {"action": "failed"}
