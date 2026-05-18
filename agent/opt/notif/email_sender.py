"""
SIEM Africa - Agent (Module 3) - notif/email_sender.py
EmailSender : logique anti-spam + 4 types d'emails (alerte, bienvenue, récap, pic).
"""
import logging
from datetime import datetime

from db import get_db
from config import severity_at_least
from notif.smtp_client import SMTPClient

logger = logging.getLogger(__name__)


# ============================================================================
class EmailSender:
    """Gère l'envoi des emails avec anti-spam et templating."""

    def __init__(self):
        self.db = get_db()
        self.client = None
        self._reload_client()

    def _reload_client(self):
        """Charge la config SMTP depuis settings de façon TOLÉRANTE.

        L'agent ne sait pas exactement comment le M2 a nommé ses clés
        (smtp_password, smtp.password, mail_password, etc.). On scanne donc
        TOUTES les settings de la BDD et on cherche par mots-clés.
        """
        smtp_settings = self._discover_smtp_settings()

        # Status enabled : on cherche les variantes possibles
        enabled = self._first_value(smtp_settings, ["smtp_enabled", "smtp.enabled", "mail_enabled"])
        # Si pas de clé enabled trouvée mais qu'il y a host+user+password → on suppose enabled
        if enabled is None:
            has_creds = (
                self._first_value(smtp_settings, ["smtp_host", "smtp.host", "mail_host", "smtp_server"])
                and self._first_value(smtp_settings, ["smtp_password", "smtp.password", "mail_password", "password"])
            )
            enabled = True if has_creds else False
        else:
            # Convertir string en bool si besoin
            if isinstance(enabled, str):
                enabled = enabled.lower() in ("true", "1", "yes", "on")

        if not enabled:
            logger.info("SMTP désactivé dans settings")
            self.client = None
            return False

        host = self._first_value(smtp_settings, [
            "smtp_host", "smtp.host", "mail_host", "smtp_server", "mail_server"
        ], default="")
        port = self._first_value(smtp_settings, [
            "smtp_port", "smtp.port", "mail_port"
        ], default=587)
        try:
            port = int(port)
        except (ValueError, TypeError):
            port = 587
        username = self._first_value(smtp_settings, [
            "smtp_username", "smtp.username", "smtp_user", "mail_username", "mail_user", "smtp_login"
        ], default="")
        password = self._first_value(smtp_settings, [
            "smtp_password", "smtp.password", "smtp_pass", "mail_password", "mail_pass"
        ], default="")
        use_tls = self._first_value(smtp_settings, [
            "smtp_use_tls", "smtp.use_tls", "smtp_tls", "mail_tls", "smtp_starttls"
        ], default=True)
        if isinstance(use_tls, str):
            use_tls = use_tls.lower() in ("true", "1", "yes", "on")
        from_email = self._first_value(smtp_settings, [
            "smtp_from_email", "smtp_from", "smtp.from_email", "mail_from", "mail_from_email"
        ], default=username)
        from_name = self._first_value(smtp_settings, [
            "smtp_from_name", "smtp.from_name", "mail_from_name", "from_name"
        ], default="SIEM Africa")

        if not host or not username or not password:
            missing = [n for n, v in [("host", host), ("username", username), ("password", password)] if not v]
            logger.warning(f"Config SMTP incomplète, manquant : {missing}. "
                           f"Clés SMTP disponibles en BDD : {sorted(smtp_settings.keys())}")
            self.client = None
            return False

        logger.info(f"SMTP configuré : {host}:{port} (user={username}, tls={use_tls})")
        self.client = SMTPClient(
            host=host, port=port, username=username, password=password,
            use_tls=use_tls, from_email=from_email, from_name=from_name,
        )
        return True

    def _discover_smtp_settings(self):
        """Découvre toutes les clés SMTP en BDD, sans dépendre de la colonne 'category'.
        Cherche dans toutes les settings dont la clé contient smtp/mail."""
        all_settings = {}
        try:
            # D'abord par catégorie (cas standard)
            try:
                cat = self.db.get_settings_by_category("smtp")
                all_settings.update(cat or {})
            except Exception:
                pass
            try:
                cat = self.db.get_settings_by_category("mail")
                all_settings.update(cat or {})
            except Exception:
                pass
            try:
                cat = self.db.get_settings_by_category("email")
                all_settings.update(cat or {})
            except Exception:
                pass

            # Ensuite : scan complet par nom de clé
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
                    if key in all_settings:
                        continue
                    if value is None:
                        all_settings[key] = None
                        continue
                    if vtype in ("bool", "boolean"):
                        all_settings[key] = value.lower() in ("true", "1", "yes", "on")
                    elif vtype in ("int", "integer", "number"):
                        try:
                            all_settings[key] = int(value)
                        except (ValueError, TypeError):
                            all_settings[key] = 0
                    else:
                        all_settings[key] = value
        except Exception as e:
            logger.error(f"Erreur découverte settings SMTP : {e}")
        return all_settings

    @staticmethod
    def _first_value(settings, keys, default=None):
        """Retourne la première valeur trouvée parmi les keys (avec variantes de casse)."""
        for k in keys:
            for variant in (k, k.lower(), k.upper(), k.replace("_", "."), k.replace(".", "_")):
                if variant in settings and settings[variant] not in (None, ""):
                    return settings[variant]
        return default

    def is_enabled(self):
        return self.client is not None

    def _get_recipients(self):
        """Retourne la liste des destinataires en cherchant tolérant en BDD.

        Cherche plusieurs noms de clés possibles. Si rien trouvé, fallback :
        utilise l'email de l'admin (du compte user le plus récent).
        """
        smtp_settings = self._discover_smtp_settings()

        recipients_str = self._first_value(smtp_settings, [
            "smtp_alert_recipients", "smtp.alert_recipients", "alert_recipients",
            "mail_recipients", "smtp_recipients", "smtp_to",
            "smtp_alert_recipient", "mail_to", "notification_email", "admin_email"
        ], default="")

        if recipients_str:
            recipients = [e.strip() for e in str(recipients_str).split(",") if e.strip() and "@" in e]
            if recipients:
                return recipients

        # Fallback : email de l'admin (utilisateur le plus ancien actif)
        try:
            with self.db.cursor() as cur:
                cur.execute("""
                    SELECT email FROM users
                    WHERE is_active = 1 AND email IS NOT NULL AND email != ''
                    ORDER BY id ASC LIMIT 1
                """)
                row = cur.fetchone()
                if row:
                    logger.info(f"Aucun destinataire SMTP configuré, fallback sur admin : {row[0]}")
                    return [row[0]]
        except Exception as e:
            logger.debug(f"Fallback users.email échoué : {e}")

        # Dernier fallback : utiliser l'email expéditeur SMTP
        from_email = self._first_value(smtp_settings, [
            "smtp_from_email", "smtp_username", "smtp_user", "mail_from"
        ], default=None)
        if from_email and "@" in from_email:
            logger.info(f"Aucun destinataire trouvé, fallback sur expéditeur : {from_email}")
            return [from_email]

        return []

    def _can_send(self, subject):
        """Vérifie anti-spam (rate limit + dedup)."""
        # Rate limit
        rate_limit = self.db.get_setting("smtp_rate_limit_per_hour", 30) or 30
        recent_count = self.db.count_recent_emails(window_minutes=60)
        if recent_count >= rate_limit:
            logger.warning(f"Rate limit SMTP atteint ({recent_count}/{rate_limit})")
            return False

        return True

    def _send_to_all(self, subject, body, alert_id=None, dedup=True):
        """Envoie à tous les destinataires avec trace."""
        if not self.is_enabled():
            return False

        recipients = self._get_recipients()
        if not recipients:
            logger.warning("Aucun destinataire configuré")
            return False

        if not self._can_send(subject):
            for r in recipients:
                self.db.insert_email_log(r, subject, "rate_limited", alert_id=alert_id)
            return False

        sent_count = 0
        for recipient in recipients:
            # Dédup par destinataire
            if dedup and self.db.email_already_sent(recipient, subject, window_minutes=5):
                logger.debug(f"Email déjà envoyé récemment à {recipient}, skip")
                self.db.insert_email_log(recipient, subject, "deduplicated", alert_id=alert_id)
                continue

            success, error = self.client.send([recipient], subject, body)
            if success:
                self.db.insert_email_log(recipient, subject, "sent", alert_id=alert_id)
                sent_count += 1
            else:
                self.db.insert_email_log(recipient, subject, "failed",
                                         alert_id=alert_id, error_message=error)
                logger.error(f"Échec envoi à {recipient} : {error}")

        return sent_count > 0

    # ========================================================================
    # TYPE 1 : EMAIL D'ALERTE
    # ========================================================================
    def send_alert(self, alert_id):
        """Envoie un email pour une alerte spécifique."""
        alert = self.db.get_alert_by_id(alert_id)
        if not alert:
            return False

        # Vérifier la sévérité minimum
        min_sev = self.db.get_setting("smtp_min_severity", "HIGH")
        if not severity_at_least(alert["severity"], min_sev):
            logger.debug(f"Alerte #{alert_id} sévérité {alert['severity']} < {min_sev}, pas d'email")
            return False

        # Récupérer le contexte signature
        sig = self.db.get_signature_with_context(alert["signature_id"])

        subject = f"[SIEM Africa] {alert['severity']} - {alert['title'][:80]}"
        body = self._build_alert_body(alert, sig)

        return self._send_to_all(subject, body, alert_id=alert_id)

    def _build_alert_body(self, alert, sig=None):
        """Construit le corps texte d'un email d'alerte."""
        sev_icon = {"CRITICAL": "[CRITICAL]", "HIGH": "[HIGH]",
                    "MEDIUM": "[MEDIUM]", "LOW": "[LOW]", "INFO": "[INFO]"}.get(alert["severity"], "[?]")

        lines = []
        lines.append("=" * 60)
        lines.append("SIEM AFRICA - NOTIFICATION D'ALERTE")
        lines.append("=" * 60)
        lines.append("")
        lines.append(f"{sev_icon} ALERTE {alert['severity']}")
        lines.append(f"Detectee le : {alert['created_at']}")
        lines.append("")
        lines.append("-" * 60)
        lines.append("  RESUME")
        lines.append("-" * 60)
        lines.append(f"Type        : {alert['title']}")
        if alert.get("description"):
            lines.append(f"Description : {alert['description'][:300]}")
        if alert.get("ai_description"):
            lines.append("")
            lines.append("Analyse IA :")
            lines.append(f"  {alert['ai_description'][:500]}")
        lines.append("")

        # Attaquant
        if alert.get("src_ip"):
            lines.append("-" * 60)
            lines.append("  ATTAQUANT")
            lines.append("-" * 60)
            lines.append(f"IP source : {alert['src_ip']}")
            if alert.get("src_port"):
                lines.append(f"Port      : {alert['src_port']}")
            rep = self.db.get_ip_reputation(alert["src_ip"])
            if rep:
                lines.append(f"Reputation: {rep['reputation_score']}/100 (vue {rep['times_seen']} fois)")
            lines.append("")

        # Cible
        if alert.get("dst_ip"):
            lines.append("-" * 60)
            lines.append("  CIBLE")
            lines.append("-" * 60)
            lines.append(f"IP cible    : {alert['dst_ip']}")
            if alert.get("dst_port"):
                lines.append(f"Port attaque: {alert['dst_port']}")
            if alert.get("protocol"):
                lines.append(f"Protocole   : {alert['protocol']}")
            lines.append("")

        # Stats
        if alert.get("event_count", 1) > 1:
            lines.append("-" * 60)
            lines.append("  STATISTIQUES")
            lines.append("-" * 60)
            lines.append(f"Tentatives : {alert['event_count']}")
            lines.append(f"Premiere   : {alert.get('first_seen', '?')}")
            lines.append(f"Derniere   : {alert.get('last_seen', '?')}")
            lines.append("")

        # MITRE
        if sig and sig.get("mitre_technique_id"):
            lines.append("-" * 60)
            lines.append("  MITRE ATT&CK")
            lines.append("-" * 60)
            lines.append(f"Tactique  : {sig.get('mitre_tactic_id', '?')} - {sig.get('mitre_tactic_name', '')}")
            lines.append(f"Technique : {sig['mitre_technique_id']} - {sig.get('mitre_technique_name', '')}")
            lines.append("")

        # Recommandations IA
        if alert.get("ai_remediation"):
            try:
                import json
                remediations = json.loads(alert["ai_remediation"]) if isinstance(alert["ai_remediation"], str) else alert["ai_remediation"]
                if remediations and isinstance(remediations, list):
                    lines.append("-" * 60)
                    lines.append("  RECOMMANDATIONS")
                    lines.append("-" * 60)
                    for i, r in enumerate(remediations[:5], 1):
                        lines.append(f"{i}. {r}")
                    lines.append("")
            except Exception:
                pass

        lines.append("=" * 60)
        lines.append("Notification automatique - SIEM Africa")
        lines.append("=" * 60)

        return "\n".join(lines)

    # ========================================================================
    # TYPE 2 : EMAIL DE BIENVENUE (démarrage agent)
    # ========================================================================
    def send_welcome(self, healthcheck_results=None):
        """Email envoyé au démarrage de l'agent."""
        if not self.is_enabled():
            return False

        recipients = self._get_recipients()
        if not recipients:
            return False

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        hc = healthcheck_results or {}

        subject = "[SIEM Africa] Agent demarre"
        lines = [
            "=" * 60,
            "SIEM AFRICA - AGENT DEMARRE",
            "=" * 60,
            "",
            f"L'agent SIEM Africa est actif depuis {now}.",
            "",
            "Healthcheck demarrage :",
            f"  - BDD          : {'OK' if hc.get('db') else 'KO'}",
            f"  - Wazuh log    : {'OK' if hc.get('wazuh_log') else 'KO'}",
            f"  - SMTP         : {'OK' if hc.get('smtp') else 'KO (configurez les credentials)'}",
            f"  - Ollama IA    : {'OK' if hc.get('ollama') else 'KO (mode degrade)'}",
            "",
            "Vous recevrez les alertes selon votre configuration",
            "(Settings > SMTP > Severite minimale).",
            "",
            "Configuration actuelle :",
            f"  - Severite minimum : {self.db.get_setting('smtp_min_severity', 'HIGH')}",
            f"  - Rate limit       : {self.db.get_setting('smtp_rate_limit_per_hour', 30)} emails/heure",
            f"  - Destinataires    : {len(recipients)}",
            "",
            "=" * 60,
            "Notification automatique - SIEM Africa",
            "=" * 60,
        ]

        body = "\n".join(lines)
        return self._send_to_all(subject, body, dedup=False)

    # ========================================================================
    # TYPE 3 : RECAP QUOTIDIEN
    # ========================================================================
    def send_daily_recap(self):
        """Email récap quotidien matin (à appeler par cron à 7h)."""
        if not self.is_enabled():
            return False

        # Récupérer stats des dernières 24h
        try:
            with self.db.cursor() as cur:
                # Total
                cur.execute("""
                    SELECT COUNT(*) FROM alerts
                    WHERE created_at >= datetime('now', '-1 day')
                """)
                total = cur.fetchone()[0]

                # Par sévérité
                stats_sev = {}
                for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    cur.execute("""
                        SELECT COUNT(*) FROM alerts
                        WHERE created_at >= datetime('now', '-1 day')
                        AND severity = ?
                    """, (sev,))
                    stats_sev[sev] = cur.fetchone()[0]

                # Top IPs
                cur.execute("""
                    SELECT src_ip, COUNT(*) as nb FROM alerts
                    WHERE created_at >= datetime('now', '-1 day')
                    AND src_ip IS NOT NULL
                    GROUP BY src_ip ORDER BY nb DESC LIMIT 5
                """)
                top_ips = cur.fetchall()

                # IPs bloquées
                cur.execute("""
                    SELECT COUNT(*) FROM blocked_ips
                    WHERE blocked_at >= datetime('now', '-1 day')
                """)
                blocked_today = cur.fetchone()[0]

                cur.execute("SELECT COUNT(*) FROM blocked_ips WHERE is_active = 1")
                blocked_active = cur.fetchone()[0]

        except Exception as e:
            logger.error(f"Erreur stats récap : {e}")
            return False

        subject = f"[SIEM Africa] Recap quotidien - {datetime.now().strftime('%d/%m/%Y')}"

        lines = [
            "=" * 60,
            "SIEM AFRICA - RECAP QUOTIDIEN",
            "=" * 60,
            "",
            f"Date : {datetime.now().strftime('%d/%m/%Y')}",
            "",
            f"Total alertes 24h : {total}",
            f"  Critical : {stats_sev['CRITICAL']}",
            f"  High     : {stats_sev['HIGH']}",
            f"  Medium   : {stats_sev['MEDIUM']}",
            f"  Low      : {stats_sev['LOW']}",
            "",
        ]

        if top_ips:
            lines.append("Top IPs attaquantes :")
            for ip, nb in top_ips:
                lines.append(f"  {ip} : {nb} alertes")
            lines.append("")

        lines.extend([
            f"IPs bloquees (24h) : {blocked_today}",
            f"IPs actuellement bloquees : {blocked_active}",
            "",
            "=" * 60,
            "SIEM Africa",
            "=" * 60,
        ])

        return self._send_to_all(subject, "\n".join(lines), dedup=False)

    # ========================================================================
    # TYPE 4 : PIC D'ATTAQUE
    # ========================================================================
    def send_attack_peak(self, alert_count):
        """Email quand un pic d'attaques est détecté."""
        if not self.is_enabled():
            return False

        subject = f"[SIEM Africa] PIC D'ATTAQUE - {alert_count} alertes/min"

        # Récupérer les IPs impliquées
        try:
            with self.db.cursor() as cur:
                cur.execute("""
                    SELECT src_ip, COUNT(*) as nb FROM alerts
                    WHERE created_at >= datetime('now', '-1 minute')
                    AND src_ip IS NOT NULL
                    GROUP BY src_ip ORDER BY nb DESC LIMIT 10
                """)
                top_ips = cur.fetchall()
        except Exception:
            top_ips = []

        lines = [
            "=" * 60,
            "SIEM AFRICA - PIC D'ATTAQUE DETECTE",
            "=" * 60,
            "",
            f"ATTENTION : {alert_count} alertes detectees en 1 minute.",
            "Ce niveau est anormal et peut indiquer une attaque coordonnee.",
            "",
            "Heure : " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "",
        ]

        if top_ips:
            lines.append("IPs sources impliquees :")
            for ip, nb in top_ips:
                lines.append(f"  {ip} : {nb} alertes")
            lines.append("")

        lines.extend([
            "Recommandations :",
            "  1. Verifier immediatement le dashboard",
            "  2. Identifier le pattern d'attaque",
            "  3. Bloquer manuellement les IPs si necessaire",
            "  4. Verifier l'integrite des serveurs critiques",
            "",
            "=" * 60,
            "Notification automatique - SIEM Africa",
            "=" * 60,
        ])

        return self._send_to_all(subject, "\n".join(lines), dedup=False)


# ============================================================================
# WORKER EMAIL (thread)
# ============================================================================
