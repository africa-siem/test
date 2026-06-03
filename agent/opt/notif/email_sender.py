"""
SIEM Africa - Agent (Module 3) - notif/email_sender.py
EmailSender : auto-découverte SMTP (BDD + /etc/siem-africa/smtp.env) + anti-spam + 4 types d'emails.
"""
import os
import json
import logging
from datetime import datetime

from db import get_db
from notif.smtp_client import SMTPClient

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def severity_at_least(sev, min_sev):
    return SEVERITY_ORDER.get(sev, 0) >= SEVERITY_ORDER.get(min_sev, 0)


class EmailSender:
    """Envoi d'emails avec auto-config SMTP + anti-spam."""

    def __init__(self):
        self.db = get_db()
        self.client = None
        self.from_email = None
        self._reload_client()

    def _discover_smtp_settings(self):
        """Cherche les settings SMTP partout :
        1. BDD : table settings (categories smtp/mail/email + scan par nom)
        2. Fichiers .env : /etc/siem-africa/smtp.env, agent.env
        Les valeurs .env complètent les BDD vides."""
        all_settings = {}

        for cat_name in ("smtp", "mail", "email"):
            try:
                cat = self.db.get_settings_by_category(cat_name)
                if cat:
                    all_settings.update(cat)
            except Exception:
                pass

        try:
            with self.db.cursor() as cur:
                cur.execute("""
                    SELECT key, value, value_type FROM settings
                    WHERE LOWER(key) LIKE '%smtp%'
                       OR LOWER(key) LIKE '%mail%'
                       OR LOWER(key) LIKE '%email%'
                       OR LOWER(key) LIKE '%recipient%'
                """)
                for row in cur.fetchall():
                    key, value, vtype = row["key"], row["value"], row["value_type"]
                    if key in all_settings and all_settings[key]:
                        continue
                    if value is None:
                        all_settings[key] = None
                        continue
                    vt = (vtype or "").lower()
                    if vt in ("bool", "boolean"):
                        all_settings[key] = value.lower() in ("true", "1", "yes", "on")
                    elif vt in ("int", "integer", "number"):
                        try:
                            all_settings[key] = int(value)
                        except (ValueError, TypeError):
                            all_settings[key] = 0
                    else:
                        all_settings[key] = value
        except Exception as e:
            logger.debug(f"Scan BDD SMTP échoué : {e}")

        env_files = [
            "/etc/siem-africa/smtp.env",
            "/etc/siem-africa/mail.env",
            "/etc/siem-africa/agent.env",
        ]
        mappings = {
            "smtp_user": "smtp_username",
            "smtp_from": "smtp_from_email",
            "alert_email": "smtp_alert_recipients",
            "smtp_tls": "smtp_use_tls",
        }
        for env_path in env_files:
            if not os.path.exists(env_path):
                continue
            try:
                with open(env_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#") or "=" not in line:
                            continue
                        k, _, v = line.partition("=")
                        k = k.strip().lower()
                        v = v.strip().strip('"').strip("'")
                        if not v:
                            continue
                        if not any(p in k for p in ("smtp", "mail", "email", "alert", "recipient")):
                            continue
                        final_k = mappings.get(k, k)
                        if final_k not in all_settings or not all_settings[final_k]:
                            all_settings[final_k] = v
            except PermissionError:
                logger.warning(f"Permission denied sur {env_path}")
            except Exception as e:
                logger.debug(f"Lecture {env_path} échouée : {e}")

        return all_settings

    @staticmethod
    def _first_value(settings, keys, default=None):
        for k in keys:
            for variant in (k, k.lower(), k.upper(), k.replace("_", "."), k.replace(".", "_")):
                if variant in settings and settings[variant] not in (None, ""):
                    return settings[variant]
        return default

    def _reload_client(self):
        smtp_settings = self._discover_smtp_settings()

        enabled = self._first_value(smtp_settings, ["smtp_enabled", "mail_enabled"])
        if enabled is None:
            has_creds = (
                self._first_value(smtp_settings, ["smtp_host", "mail_host"])
                and self._first_value(smtp_settings, ["smtp_password", "mail_password"])
            )
            enabled = True if has_creds else False
        else:
            if isinstance(enabled, str):
                enabled = enabled.lower() in ("true", "1", "yes", "on")

        if not enabled:
            logger.info("SMTP désactivé")
            self.client = None
            return False

        host = self._first_value(smtp_settings, ["smtp_host", "mail_host", "smtp_server"], default="")
        try:
            port = int(self._first_value(smtp_settings, ["smtp_port", "mail_port"], default=587))
        except (ValueError, TypeError):
            port = 587
        username = self._first_value(smtp_settings, [
            "smtp_username", "smtp_user", "mail_username", "mail_user"
        ], default="")
        password = self._first_value(smtp_settings, [
            "smtp_password", "smtp_pass", "mail_password"
        ], default="")
        use_tls = self._first_value(smtp_settings, ["smtp_use_tls", "smtp_tls", "mail_tls"], default=True)
        if isinstance(use_tls, str):
            use_tls = use_tls.lower() in ("true", "1", "yes", "on")
        from_email = self._first_value(smtp_settings, [
            "smtp_from_email", "smtp_from", "mail_from"
        ], default=username)
        from_name = self._first_value(smtp_settings, [
            "smtp_from_name", "mail_from_name"
        ], default="SIEM Africa")

        if not host or not username or not password:
            missing = [n for n, v in [("host", host), ("username", username),
                                      ("password", password)] if not v]
            logger.warning(f"Config SMTP incomplète, manquant : {missing}")
            logger.warning(f"Clés détectées : {sorted(smtp_settings.keys())}")
            self.client = None
            return False

        logger.info(f"SMTP configuré : {host}:{port} (user={username}, tls={use_tls})")
        self.from_email = from_email
        self.client = SMTPClient(
            host=host, port=port, username=username, password=password,
            use_tls=use_tls, from_email=from_email, from_name=from_name,
        )
        return True

    def is_enabled(self):
        return self.client is not None

    def _get_recipients(self):
        smtp_settings = self._discover_smtp_settings()
        rec_str = self._first_value(smtp_settings, [
            "smtp_alert_recipients", "alert_recipients", "mail_recipients",
            "smtp_to", "mail_to", "admin_email", "notification_email",
            "alert_email"
        ], default="")
        if rec_str:
            recipients = [e.strip() for e in str(rec_str).split(",") if e.strip() and "@" in e]
            if recipients:
                return recipients

        try:
            with self.db.cursor() as cur:
                cur.execute("""
                    SELECT email FROM users
                    WHERE is_active = 1 AND email IS NOT NULL AND email != ''
                    ORDER BY id ASC LIMIT 1
                """)
                row = cur.fetchone()
                if row:
                    return [row[0]]
        except Exception:
            pass

        if self.from_email and "@" in self.from_email:
            return [self.from_email]

        return []

    def _can_send(self, subject):
        smtp_settings = self.db.get_settings_by_category("smtp")
        try:
            rate_limit = int(smtp_settings.get("smtp_rate_limit_per_hour", 30))
        except (ValueError, TypeError):
            rate_limit = 30
        sent_count = self.db.count_recent_emails(window_minutes=60)
        if sent_count >= rate_limit:
            logger.warning(f"Rate limit atteint ({sent_count}/{rate_limit}/h)")
            return False
        return True

    def send_alert(self, alert_id):
        if not self.is_enabled():
            return False
        alert = self.db.get_alert_by_id(alert_id)
        if not alert:
            return False

        smtp_settings = self.db.get_settings_by_category("smtp")
        min_sev = smtp_settings.get("smtp_min_severity", "HIGH")
        if not severity_at_least(alert["severity"], min_sev):
            logger.debug(f"Alerte #{alert_id} sous min_severity ({alert['severity']} < {min_sev})")
            return False

        if not self._can_send(alert["title"]):
            for rec in self._get_recipients():
                self.db.insert_email_log(rec, alert["title"][:200], "rate_limited", alert_id=alert_id)
            return False

        subject = f"[{alert['severity']}] {alert['title'][:80]}"
        body = self._build_alert_body(alert)
        recipients = self._get_recipients()
        if not recipients:
            logger.warning("Aucun destinataire pour l'email d'alerte")
            return False

        sent_to = []
        for rec in recipients:
            if self.db.email_already_sent(rec, subject, window_minutes=5):
                self.db.insert_email_log(rec, subject, "deduplicated", alert_id=alert_id)
                continue
            success, err = self.client.send([rec], subject, body)
            status = "sent" if success else "failed"
            self.db.insert_email_log(rec, subject, status, alert_id=alert_id, error_message=err)
            if success:
                sent_to.append(rec)
                logger.info(f"Email envoyé à {rec} (alert #{alert_id})")
            else:
                logger.warning(f"Email à {rec} échoué : {err}")

        return len(sent_to) > 0

    def _build_alert_body(self, alert):
        lines = [
            f"ALERTE {alert['severity']} - SIEM Africa",
            "=" * 60,
            "",
            f"ID alerte    : #{alert['id']}",
            f"Date         : {alert.get('created_at', 'N/A')}",
            f"Titre        : {alert['title']}",
            f"Sévérité     : {alert['severity']}",
            f"Confiance    : {alert.get('confidence', 'N/A')}/100",
            "",
            "DETAILS",
            "-" * 60,
        ]
        if alert.get("src_ip"):
            lines.append(f"IP source    : {alert['src_ip']}")
        if alert.get("dst_ip"):
            lines.append(f"IP cible     : {alert['dst_ip']}")
        if alert.get("src_port"):
            lines.append(f"Port source  : {alert['src_port']}")
        if alert.get("dst_port"):
            lines.append(f"Port cible   : {alert['dst_port']}")
        if alert.get("protocol"):
            lines.append(f"Protocole    : {alert['protocol']}")
        if alert.get("event_count", 1) > 1:
            lines.append(f"Occurrences  : {alert['event_count']}")

        # ----------------------------------------------------------------
        # DESCRIPTION : cascade de fallback
        # 1. ai_description (enrichissement IA Ollama, si dispo)
        # 2. sig_description_fr (BDD - seeds enrichis FR)
        # 3. sig_description    (BDD - description anglaise / brute)
        # 4. alert.description  (description courte stockée sur l'alerte)
        # ----------------------------------------------------------------
        description = (alert.get("ai_description")
                       or alert.get("sig_description_fr")
                       or alert.get("sig_description")
                       or alert.get("description"))
        if description:
            lines.extend(["", "DESCRIPTION", "-" * 60, str(description)[:800]])

        # ----------------------------------------------------------------
        # RECOMMANDATIONS : cascade de fallback
        # 1. ai_remediation     (enrichissement IA Ollama)
        # 2. sig_remediation_fr (BDD - seeds enrichis FR)
        # 3. sig_remediation    (BDD - remediation brute)
        # ----------------------------------------------------------------
        recommendations = (alert.get("ai_remediation")
                           or alert.get("sig_remediation_fr")
                           or alert.get("sig_remediation"))
        if recommendations:
            lines.extend(["", "RECOMMANDATIONS", "-" * 60, str(recommendations)[:800]])

        # ----------------------------------------------------------------
        # RÉFÉRENCES : CVE et URL documentation (si la signature en a)
        # ----------------------------------------------------------------
        if alert.get("sig_cve_ids"):
            try:
                cves = json.loads(alert["sig_cve_ids"])
                if cves:
                    lines.append("")
                    lines.append(f"CVE          : {', '.join(cves)}")
            except (ValueError, TypeError):
                pass
        if alert.get("sig_references_url"):
            lines.append(f"Documentation: {alert['sig_references_url']}")

        lines.extend([
            "", "=" * 60,
            "SIEM Africa - Détection automatique",
            "Voir le dashboard pour plus de détails",
        ])
        return "\n".join(lines)

    def send_welcome(self, healthcheck_results=None):
        if not self.is_enabled():
            return False
        recipients = self._get_recipients()
        if not recipients:
            return False

        subject = "[SIEM Africa] Agent démarré"
        lines = [
            "AGENT SIEM AFRICA - DEMARRAGE",
            "=" * 60, "",
            f"Date démarrage : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "HEALTHCHECK",
            "-" * 60,
        ]
        if healthcheck_results:
            for k, v in healthcheck_results.items():
                status = "OK" if v else "FAIL"
                lines.append(f"  {k:15s} : {status}")
        lines.extend(["", "L'agent est opérationnel et traite les alertes Wazuh en temps réel."])
        body = "\n".join(lines)

        for rec in recipients:
            success, err = self.client.send([rec], subject, body)
            status = "sent" if success else "failed"
            self.db.insert_email_log(rec, subject, status, error_message=err)
            if success:
                logger.info(f"Email bienvenue envoyé à {rec}")
        return True

    def send_daily_recap(self):
        if not self.is_enabled():
            return False
        recipients = self._get_recipients()
        if not recipients:
            return False

        metrics = self.db.compute_daily_kpis()
        subject = f"[SIEM Africa] Récap quotidien - {datetime.now().strftime('%Y-%m-%d')}"
        lines = ["RECAP SIEM AFRICA - 24 dernières heures", "=" * 60, ""]
        for name, val_unit in sorted(metrics.items()):
            if isinstance(val_unit, tuple):
                val, unit = val_unit
            else:
                val, unit = val_unit, "count"
            lines.append(f"  {name:30s} : {val} {unit}")
        body = "\n".join(lines)

        for rec in recipients:
            success, err = self.client.send([rec], subject, body)
            status = "sent" if success else "failed"
            self.db.insert_email_log(rec, subject, status, error_message=err)
        return True

    def send_attack_peak(self, alert_count):
        if not self.is_enabled():
            return False
        recipients = self._get_recipients()
        if not recipients:
            return False

        subject = f"[SIEM Africa] PIC D'ATTAQUE - {alert_count} alertes/min"
        body = f"""ALERTE - PIC D'ATTAQUE DETECTE
{'='*60}

Une activité anormale a été détectée :
  Nombre d'alertes : {alert_count} en 1 minute

Date : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Connectez-vous au dashboard pour voir les détails."""

        for rec in recipients:
            success, err = self.client.send([rec], subject, body)
            status = "sent" if success else "failed"
            self.db.insert_email_log(rec, subject, status, error_message=err)
        return True
