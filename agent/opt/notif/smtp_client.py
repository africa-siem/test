"""
SIEM Africa - Agent (Module 3) - notif/smtp_client.py
Client SMTP via smtplib (Python natif, sans dépendance externe).
"""
import smtplib
import ssl
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)


class SMTPClient:
    """Client SMTP minimal utilisant Python smtplib."""

    def __init__(self, host, port, username, password, use_tls=True,
                 from_email=None, from_name="SIEM Africa"):
        self.host = host
        self.port = int(port) if port else 587
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.from_email = from_email or username
        self.from_name = from_name

    def send(self, to_emails, subject, body_text):
        """
        Envoie un email à un ou plusieurs destinataires.
        to_emails : liste ou string séparé par virgules.
        Retourne (success: bool, error: str ou None).
        """
        if isinstance(to_emails, str):
            to_emails = [e.strip() for e in to_emails.split(",") if e.strip()]

        if not to_emails:
            return False, "Aucun destinataire"

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = f"{self.from_name} <{self.from_email}>"
            msg["To"] = ", ".join(to_emails)
            msg.attach(MIMEText(body_text, "plain", "utf-8"))

            context = ssl.create_default_context()
            if self.use_tls:
                with smtplib.SMTP(self.host, self.port, timeout=30) as server:
                    server.starttls(context=context)
                    server.login(self.username, self.password)
                    server.send_message(msg)
            else:
                with smtplib.SMTP_SSL(self.host, self.port, context=context, timeout=30) as server:
                    server.login(self.username, self.password)
                    server.send_message(msg)

            return True, None

        except smtplib.SMTPAuthenticationError as e:
            return False, f"Auth SMTP refusée : {e}"
        except smtplib.SMTPException as e:
            return False, f"Erreur SMTP : {e}"
        except Exception as e:
            return False, f"Erreur envoi : {e}"
