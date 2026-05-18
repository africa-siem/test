"""
SIEM Africa - Agent (Module 3) - processor/alert_processor.py
AlertProcessor : cœur de l'agent.

Pour chaque event reçu du watcher :
1. Lookup signature en BDD
2. Vérification des filtres (faux positifs)
3. Déduplication (event_count++ si même alerte récente)
4. Mise à jour réputation IP
5. Insertion alerte enrichie
6. Corrélation (5+ alertes même IP → incident)
7. Push vers les queues : IA / Email / Active Response
"""
import logging
import threading
from datetime import datetime, timedelta

from db import get_db
from processor.utils import is_private_ip

logger = logging.getLogger(__name__)


# ============================================================================
# PROCESSOR
# ============================================================================
class AlertProcessor(threading.Thread):
    """
    Thread qui traite les events reçus du WazuhWatcher.
    """

    def __init__(self, event_queue, shutdown_event,
                 email_queue=None, ai_queue=None, block_queue=None):
        super().__init__(name="AlertProcessor", daemon=True)
        self.queue = event_queue
        self.shutdown = shutdown_event
        self.email_queue = email_queue
        self.ai_queue = ai_queue
        self.block_queue = block_queue
        self.db = get_db()

        # Compteur pour détection pic d'attaque
        self.alert_counter = []  # liste des timestamps
        self.last_peak_alert = None

    def run(self):
        logger.info("Démarrage AlertProcessor")

        while not self.shutdown.is_set():
            try:
                # Attendre un event (timeout pour vérifier shutdown)
                try:
                    event = self.queue.get(timeout=2)
                except Exception:
                    continue

                if event is None:
                    continue

                self._process_event(event)
                self._check_attack_peak()

            except Exception as e:
                logger.exception(f"Erreur boucle processor : {e}")

        logger.info("AlertProcessor arrêté")

    def _process_event(self, event):
        """Traite un event individuel."""
        source = event["source"]
        rule_id = event["rule_id"]
        src_ip = event.get("src_ip")
        severity = event.get("severity", "MEDIUM")

        # ---------------------------------------------------------------
        # 1. Lookup signature
        # ---------------------------------------------------------------
        sig = self.db.lookup_signature(source, rule_id)

        if not sig:
            # Signature inconnue : on en crée une "unknown"
            logger.info(f"Signature inconnue {source}/{rule_id}, création auto")
            new_sig_id = self.db.create_unknown_signature(
                source=source,
                rule_id=rule_id,
                name=event.get("description", f"Unknown {source}/{rule_id}")[:200],
                description=event.get("description"),
            )
            if not new_sig_id:
                logger.error(f"Impossible de créer signature pour {source}/{rule_id}, event perdu")
                return
            sig = self.db.lookup_signature(source, rule_id)
            if not sig:
                logger.error(f"Signature toujours introuvable après création")
                return

        signature_id = sig["id"]

        # Si signature désactivée, on ignore
        if not sig.get("is_active", 1):
            logger.debug(f"Signature {signature_id} désactivée, event ignoré")
            return

        # Override severity depuis la signature si plus précise
        if sig.get("severity"):
            severity = sig["severity"]

        # ---------------------------------------------------------------
        # 2. Vérification des filtres (faux positifs)
        # ---------------------------------------------------------------
        filters = self.db.get_active_filters(signature_id, src_ip)
        skip_alert = False
        notify_only = False

        for f in filters:
            action = f["action"]
            self.db.increment_filter_hit(f["id"])

            if action == "IGNORE":
                logger.debug(f"Filtre IGNORE déclenché ({f['name']}), event ignoré")
                skip_alert = True
                break
            elif action == "DOWNGRADE" and f.get("downgrade_to"):
                severity = f["downgrade_to"]
                logger.debug(f"Filtre DOWNGRADE → {severity}")
            elif action == "NOTIFY_ONLY":
                notify_only = True

        if skip_alert:
            self.db.insert_audit("alert_filtered_ignore",
                                 resource_type="signature",
                                 resource_id=signature_id,
                                 details={"src_ip": src_ip})
            return

        # ---------------------------------------------------------------
        # 3. Déduplication
        # ---------------------------------------------------------------
        existing = self.db.find_recent_similar_alert(signature_id, src_ip, window_minutes=5)
        if existing:
            self.db.increment_alert_count(existing["id"])
            logger.debug(f"Alerte dédupliquée (existing #{existing['id']}, "
                         f"count {existing['event_count']+1})")
            # Mise à jour réputation IP quand même
            if src_ip and not is_private_ip(src_ip):
                self.db.update_ip_reputation(src_ip, -1, source_seen=source)

            # Vérifier la corrélation même sur déduplication (event_count peut atteindre 5+)
            self._check_correlation(src_ip)

            # Tracker pour détection pic
            self.alert_counter.append(datetime.utcnow())
            return

        # ---------------------------------------------------------------
        # 4. Enrichissement (contexte)
        # ---------------------------------------------------------------
        title = sig.get("name", event.get("description", "Alerte"))[:500]
        description = sig.get("description_fr") or event.get("description", "")

        enriched = {
            "source": source,
            "rule_id": rule_id,
            "wazuh_level": event.get("level"),
            "full_log": event.get("full_log", "")[:1000],
            "groups": event.get("groups", []),
            "mitre_technique_id": None,
            "mitre_tactic_id": None,
        }

        # Récupérer le contexte MITRE si disponible
        sig_full = self.db.get_signature_with_context(signature_id)
        if sig_full:
            enriched["mitre_technique_id"] = sig_full.get("mitre_technique_id")
            enriched["mitre_tactic_id"] = sig_full.get("mitre_tactic_id")
            enriched["category_code"] = sig_full.get("category_code")
            enriched["category_name"] = sig_full.get("category_name")

        # ---------------------------------------------------------------
        # 5. Mise à jour réputation IP
        # ---------------------------------------------------------------
        if src_ip and not is_private_ip(src_ip):
            # Score baisse selon sévérité
            delta = {"CRITICAL": -20, "HIGH": -10, "MEDIUM": -5, "LOW": -2, "INFO": 0}.get(severity, -5)
            self.db.update_ip_reputation(src_ip, delta, source_seen=source)

            # Récupérer la réputation pour enrichissement
            rep = self.db.get_ip_reputation(src_ip)
            if rep:
                enriched["ip_reputation_score"] = rep["reputation_score"]
                enriched["ip_times_seen"] = rep["times_seen"]

        # ---------------------------------------------------------------
        # 6. Insertion alerte
        # ---------------------------------------------------------------
        # ai_status : pending si signature noisy ou unknown (sera enrichie par Bloc 5)
        ai_enabled = self.db.get_setting("ai_enabled", False)
        ai_min_severity = self.db.get_setting("ai_min_severity", "HIGH")

        needs_ai = False
        if ai_enabled:
            from config import severity_at_least
            if severity_at_least(severity, ai_min_severity):
                # Pour les signatures noisy ou inconnues, on demande à l'IA
                if sig.get("is_noisy") or not sig.get("description_fr"):
                    needs_ai = True

        ai_status = "pending" if needs_ai else "not_required"

        alert_id = self.db.insert_alert({
            "signature_id": signature_id,
            "severity": severity,
            "confidence": sig.get("confidence", 70),
            "title": title,
            "description": description,
            "src_ip": src_ip,
            "dst_ip": event.get("dst_ip"),
            "src_port": event.get("src_port"),
            "dst_port": event.get("dst_port"),
            "protocol": event.get("protocol"),
            "enriched_data": enriched,
            "ai_status": ai_status,
        })

        if not alert_id:
            logger.error("Échec insertion alerte")
            return

        self.db.insert_audit("alert_create",
                             resource_type="alert", resource_id=alert_id,
                             details={"signature_id": signature_id, "severity": severity,
                                     "src_ip": src_ip})

        # Tracker pour détection pic
        self.alert_counter.append(datetime.utcnow())

        # ---------------------------------------------------------------
        # 7. Corrélation
        # ---------------------------------------------------------------
        self._check_correlation(src_ip)

        # ---------------------------------------------------------------
        # 8. Push vers les queues des autres modules
        # ---------------------------------------------------------------
        # IA
        if needs_ai and self.ai_queue:
            try:
                self.ai_queue.put({"alert_id": alert_id, "signature_id": signature_id,
                                   "event": event}, timeout=2)
            except Exception:
                logger.warning("Queue IA pleine")

        # Email (skip si NOTIFY_ONLY pas déclenché)
        if not notify_only and self.email_queue:
            try:
                self.email_queue.put({"alert_id": alert_id, "type": "alert"}, timeout=2)
            except Exception:
                logger.warning("Queue email pleine")

        # Active Response (CRITICAL seulement)
        if severity == "CRITICAL" and self.block_queue and src_ip and not is_private_ip(src_ip):
            try:
                self.block_queue.put({"alert_id": alert_id, "ip": src_ip,
                                      "reason": title}, timeout=2)
            except Exception:
                logger.warning("Queue block pleine")

    def _check_correlation(self, src_ip):
        """Vérifie si une corrélation doit créer un incident (5+ occurrences même IP en 5 min)."""
        if not src_ip or is_private_ip(src_ip):
            return

        recent_count = self.db.count_recent_alerts_by_ip(src_ip, window_minutes=5)
        if recent_count < 5:
            return

        alert_ids = self.db.get_recent_alerts_by_ip(src_ip, window_minutes=5)
        if not alert_ids:
            # Toutes déjà liées à un incident
            return

        incident_id = self.db.create_incident(
            title=f"Attaque coordonnée depuis {src_ip}",
            severity="HIGH",
            description=f"{recent_count} occurrences en 5 minutes depuis cette IP",
            alert_ids=alert_ids,
        )
        if incident_id:
            self.db.insert_audit("incident_create",
                                 resource_type="incident", resource_id=incident_id,
                                 details={"src_ip": src_ip, "alert_count": recent_count})

    def _check_attack_peak(self):
        """Détecte un pic d'attaques (plus de 20 alertes en 1 minute)."""
        from datetime import timedelta
        now = datetime.utcnow()
        one_min_ago = now - timedelta(minutes=1)

        # Nettoyer les vieux timestamps
        self.alert_counter = [t for t in self.alert_counter if t >= one_min_ago]

        if len(self.alert_counter) >= 20:
            # Vérifier qu'on n'a pas envoyé d'alerte de pic récemment
            if self.last_peak_alert and (now - self.last_peak_alert) < timedelta(minutes=15):
                return

            self.last_peak_alert = now
            count = len(self.alert_counter)
            logger.warning(f"PIC D'ATTAQUE DÉTECTÉ : {count} alertes en 1 minute")

            if self.email_queue:
                try:
                    self.email_queue.put({"type": "attack_peak", "count": count}, timeout=2)
                except Exception:
                    pass

            self.db.insert_audit("attack_peak_detected",
                                 details={"alert_count_1min": count})
