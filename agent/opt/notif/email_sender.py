"""SIEM Africa - Agent : Envoi d'emails via Python smtplib.

Utilise la config dans /etc/siem-africa/smtp.env (chargee par config.py).
"""
import smtplib
import ssl
from email.message import EmailMessage

import config
import db
from logger import setup_logger


log = setup_logger("notif.email")


def is_configured():
    return bool(config.EMAIL_ENABLED and config.SMTP_USER and config.SMTP_PASS)


def send(subject, body_text, body_html=None, to=None):
    """Envoie un email. Retourne True/False.

    Si SMTP n'est pas configure, retourne False sans rien faire (et log).
    """
    if not is_configured():
        log.warning(f"Email non envoye (SMTP non configure) : {subject}")
        return False

    recipient = to or config.SMTP_TO or config.SMTP_USER
    sender = config.SMTP_FROM or config.SMTP_USER

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.set_content(body_text)
    if body_html:
        msg.add_alternative(body_html, subtype="html")

    try:
        if config.SMTP_PORT == 465:
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT, context=ctx, timeout=30) as smtp:
                smtp.login(config.SMTP_USER, config.SMTP_PASS)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=30) as smtp:
                if config.SMTP_USE_TLS:
                    smtp.starttls(context=ssl.create_default_context())
                smtp.login(config.SMTP_USER, config.SMTP_PASS)
                smtp.send_message(msg)
        log.info(f"Email envoye a {recipient} : {subject}")
        _log_email_db(recipient, subject, status="sent")
        return True
    except smtplib.SMTPAuthenticationError as exc:
        log.error(f"SMTP AUTH refuse : {exc}")
        _log_email_db(recipient, subject, status="auth_error", error=str(exc))
        return False
    except smtplib.SMTPException as exc:
        log.error(f"SMTP erreur : {exc}")
        _log_email_db(recipient, subject, status="smtp_error", error=str(exc))
        return False
    except OSError as exc:
        log.error(f"Reseau erreur : {exc}")
        _log_email_db(recipient, subject, status="network_error", error=str(exc))
        return False


def _log_email_db(recipient, subject, status, error=None):
    """Loggue l'envoi dans la table email_logs (best effort)."""
    try:
        conn = db._get_conn()
        conn.execute(
            """
            INSERT INTO email_logs (recipient, subject, status, error_message, created_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (recipient, subject[:200], status, error[:500] if error else None),
        )
    except Exception:  # noqa: BLE001
        # email_logs peut ne pas exister selon le schema
        pass


def send_alert_email(alert):
    """Envoie un email de notification pour une alerte.

    `alert` est un dict avec : title, severity, description, src_ip, dst_ip,
    ai_description, ai_remediation (list ou None).
    """
    severity = alert.get("severity", "?")
    title = alert.get("title", "Alerte SIEM")
    src_ip = alert.get("src_ip") or "-"
    dst_ip = alert.get("dst_ip") or "-"
    description = alert.get("ai_description") or alert.get("description") or "(pas de description)"
    remediation = alert.get("ai_remediation") or []
    if isinstance(remediation, str):
        remediation = [remediation]

    subject = f"[SIEM Africa] [{severity}] {title}"

    body_text = f"""SIEM AFRICA - Notification d'alerte

Severite : {severity}
Titre    : {title}
IP src   : {src_ip}
IP dst   : {dst_ip}

Description :
{description}

Recommandations :
""" + "\n".join(f"  - {r}" for r in remediation if r) + """

---
Cet email est genere automatiquement par l'agent SIEM Africa.
"""

    return send(subject, body_text)


def send_test_email():
    """Envoie un email de test (utilise par les tests + boot)."""
    subject = "[SIEM Africa] Email de test - Module 3"
    body = (
        "Cet email confirme que la configuration SMTP fonctionne.\n\n"
        f"Hote SMTP : {config.SMTP_HOST}:{config.SMTP_PORT}\n"
        f"Compte    : {config.SMTP_USER}\n"
        f"Destinataire : {config.SMTP_TO}\n\n"
        "Si tu recois cet email, le Module 3 peut envoyer des notifications.\n"
    )
    return send(subject, body)
