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
        """Recharge la config SMTP depuis les settings."""
        smtp_settings = self.db.get_settings_by_category("smtp")
        if not smtp_settings.get("smtp_enabled"):
            self.client = None
            return False

        host = smtp_settings.get("smtp_host", "")
        port = smtp_settings.get("smtp_port", 587)
        username = smtp_settings.get("smtp_username", "")
        password = smtp_settings.get("smtp_password", "")
        use_tls = smtp_settings.get("smtp_use_tls", True)
        from_email = smtp_settings.get("smtp_from_email", username)
        from_name = smtp_settings.get("smtp_from_name", "SIEM Africa")

        if not all([host, username, password]):
            logger.warning("Config SMTP incomplète")
            self.client = None
            return False

        self.client = SMTPClient(
            host=host, port=port, username=username, password=password,
            use_tls=use_tls, from_email=from_email, from_name=from_name,
        )
        return True

    def is_enabled(self):
        return self.client is not None

    def _get_recipients(self):
        """Retourne la liste des destinataires depuis settings."""
        recipients = self.db.get_setting("smtp_alert_recipients", "")
        return [e.strip() for e in recipients.split(",") if e.strip()]

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
