"""
SIEM Africa - Agent (Module 3) - Package notif
Notifications email (SMTP via smtplib natif Python).
4 types d'emails : alerte, bienvenue, récap quotidien, pic d'attaque.
"""
from notif.smtp_client import SMTPClient
from notif.email_sender import EmailSender
from notif.worker import EmailWorker

__all__ = ["SMTPClient", "EmailSender", "EmailWorker"]
