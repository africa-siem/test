"""
SIEM Africa - Agent (Module 3) - notif/worker.py
EmailWorker : thread qui consomme la queue email et appelle EmailSender.
"""
import logging
import threading

from notif.email_sender import EmailSender

logger = logging.getLogger(__name__)


# ============================================================================
class EmailWorker(threading.Thread):
    """Thread qui consomme la queue email."""

    def __init__(self, email_queue, shutdown_event):
        super().__init__(name="EmailWorker", daemon=True)
        self.queue = email_queue
        self.shutdown = shutdown_event
        self.sender = EmailSender()

    def run(self):
        logger.info("Démarrage EmailWorker")

        while not self.shutdown.is_set():
            try:
                try:
                    task = self.queue.get(timeout=2)
                except Exception:
                    continue

                if task is None:
                    continue

                # Recharger le client si désactivé
                if not self.sender.is_enabled():
                    self.sender._reload_client()

                if not self.sender.is_enabled():
                    logger.debug("SMTP désactivé, email ignoré")
                    continue

                task_type = task.get("type", "alert")
                if task_type == "alert":
                    self.sender.send_alert(task["alert_id"])
                elif task_type == "attack_peak":
                    self.sender.send_attack_peak(task.get("count", 0))
                elif task_type == "welcome":
                    self.sender.send_welcome(task.get("healthcheck"))
                elif task_type == "daily_recap":
                    self.sender.send_daily_recap()

            except Exception as e:
                logger.exception(f"Erreur EmailWorker : {e}")

        logger.info("EmailWorker arrêté")
