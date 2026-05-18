"""
SIEM Africa - Agent (Module 3) - workers/daily_recap.py
DailyRecapWorker : pousse une tâche email récap quotidien chaque jour à 7h.
"""
import logging
import threading

from workers.utils import seconds_until

logger = logging.getLogger(__name__)


# ============================================================================
class DailyRecapWorker(threading.Thread):
    """Thread qui push un task email 'daily_recap' chaque jour à 7h."""

    def __init__(self, email_queue, shutdown_event):
        super().__init__(name="DailyRecapWorker", daemon=True)
        self.queue = email_queue
        self.shutdown = shutdown_event

    def run(self):
        logger.info("Démarrage DailyRecapWorker")

        while not self.shutdown.is_set():
            wait_s = seconds_until(7, 0)  # 07h00
            logger.debug(f"Prochain récap quotidien dans {wait_s}s")

            if self.shutdown.wait(timeout=wait_s):
                break

            try:
                if self.queue:
                    self.queue.put({"type": "daily_recap"}, timeout=5)
                    logger.info("Tâche daily_recap pushée vers EmailWorker")
            except Exception as e:
                logger.exception(f"Erreur push daily_recap : {e}")

        logger.info("DailyRecapWorker arrêté")
