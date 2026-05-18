"""SIEM Africa - Agent : Thread AIWorker.

Depile la queue ai_queue produite par alert_processor pour les alertes inconnues.
Pour chaque tache :
  1. Appelle ai.enrichment.enrich() (cherche cache puis Ollama)
  2. Met a jour l'alerte en BDD (ai_status, ai_description, etc.)
  3. Envoie un email avec la description IA
"""
import json
import threading
from queue import Empty

import db
from logger import setup_logger
from ai import enrichment as ai_enrichment
from notif import email_sender, notifier


log = setup_logger("ai.worker")


class AIWorker(threading.Thread):
    """Thread daemon qui traite les enrichissements IA un par un."""

    def __init__(self, queue, stop_event):
        super().__init__(name="AIWorker", daemon=True)
        self.queue = queue
        self.stop_event = stop_event
        self.processed = 0
        self.failed = 0

    def run(self):
        log.info("AIWorker demarre")
        while not self.stop_event.is_set():
            try:
                task = self.queue.get(timeout=1)
            except Empty:
                continue

            alert_id = task.get("alert_id")
            try:
                self._process_task(task)
                self.processed += 1
            except Exception as exc:  # noqa: BLE001
                log.error(f"Crash AIWorker sur #{alert_id} : {exc}")
                self.failed += 1
                # En cas de crash, on degrade l'alerte
                try:
                    db.update_alert_ai(
                        alert_id=alert_id,
                        ai_status="failed",
                        ai_description="Erreur interne durant analyse IA.",
                        ai_severity="MEDIUM",
                    )
                except Exception:  # noqa: BLE001
                    pass
            finally:
                try:
                    self.queue.task_done()
                except ValueError:
                    pass

        log.info(f"AIWorker arrete (traites={self.processed}, echecs={self.failed})")

    def _process_task(self, task):
        alert_id = task["alert_id"]
        source = task["source"]
        rule_id = task["rule_id"]

        log.info(f"AIWorker -> alerte #{alert_id} ({source}/{rule_id})")

        result = ai_enrichment.enrich(
            source=source,
            rule_id=rule_id,
            raw_message=task.get("raw_message"),
            raw_level=task.get("raw_level"),
            src_ip=task.get("src_ip"),
            dst_ip=task.get("dst_ip"),
        )

        # Mapping origin -> ai_status
        origin = result["origin"]
        if origin == "ai_cache":
            ai_status = "cached"
        elif origin == "ai_fresh":
            ai_status = "fresh"
        elif origin == "database":
            # Cas rare : la signature a ete ajoutee entre temps
            ai_status = "not_required"
        elif origin == "degraded":
            ai_status = "failed"
        else:
            ai_status = "failed"

        remediation = result.get("remediation") or []
        if isinstance(remediation, list):
            remediation_json = json.dumps(remediation, ensure_ascii=False)
        else:
            remediation_json = str(remediation)

        db.update_alert_ai(
            alert_id=alert_id,
            ai_status=ai_status,
            ai_description=result["description"],
            ai_remediation=remediation_json,
            ai_severity=result["severity"],
            ai_model_used=result.get("model_used"),
            ai_cache_id=result.get("cache_id"),
        )

        # Notification APRES enrichissement (rate limit + dedup + digest)
        if email_sender.is_configured():
            try:
                sig_hash = db.signature_hash(source, rule_id, task.get("raw_message"))
                notifier.notify({
                    "title": task.get("title", f"{source}/{rule_id}"),
                    "severity": result["severity"],
                    "description": result["description"],
                    "src_ip": task.get("src_ip"),
                    "dst_ip": task.get("dst_ip"),
                    "ai_description": result["description"],
                    "ai_remediation": remediation,
                    "alert_id": alert_id,
                }, signature_hash=sig_hash)
            except Exception as exc:  # noqa: BLE001
                log.error(f"Echec notify apres IA : {exc}")

    def stats(self):
        return {
            "processed": self.processed,
            "failed": self.failed,
            "queue_size": self.queue.qsize(),
        }
