"""
SIEM Africa - Agent (Module 3) - response/workers.py
BlockWorker     : thread qui consomme la queue de blocage depuis le Processor.
UnblockerWorker : cron horaire qui débloque les IPs expirées.
"""
import logging
import threading

from db import get_db
from response.ip_blocker import IPBlocker

logger = logging.getLogger(__name__)


# ============================================================================
class BlockWorker(threading.Thread):
    """Thread qui consomme la queue de blocage depuis le Processor."""

    def __init__(self, block_queue, shutdown_event):
        super().__init__(name="BlockWorker", daemon=True)
        self.queue = block_queue
        self.shutdown = shutdown_event
        self.blocker = IPBlocker()
        self.db = get_db()

    def run(self):
        logger.info("Démarrage BlockWorker")

        while not self.shutdown.is_set():
            try:
                try:
                    task = self.queue.get(timeout=2)
                except Exception:
                    continue

                if task is None:
                    continue

                # Vérifier que le blocage auto est activé
                if not self.db.get_setting("response_auto_block_enabled", True):
                    logger.debug("Blocage auto désactivé en config, skip")
                    continue

                ip = task.get("ip")
                if not ip:
                    continue

                # Durée par défaut depuis settings
                duration = self.db.get_setting("response_block_duration_minutes", 1440) or 1440

                self.blocker.block_ip(
                    ip_address=ip,
                    reason=task.get("reason", "Auto-block CRITICAL"),
                    alert_id=task.get("alert_id"),
                    duration_minutes=duration,
                )

            except Exception as e:
                logger.exception(f"Erreur BlockWorker : {e}")

        logger.info("BlockWorker arrêté")


# ============================================================================
# UNBLOCKER (cron toutes les heures)
# ============================================================================
class UnblockerWorker(threading.Thread):
    """Thread qui débloque les IPs expirées (vérification horaire)."""

    def __init__(self, shutdown_event):
        super().__init__(name="UnblockerWorker", daemon=True)
        self.shutdown = shutdown_event
        self.blocker = IPBlocker()
        self.db = get_db()

    def run(self):
        logger.info("Démarrage UnblockerWorker")

        # Premier passage au démarrage
        self._check_expired()

        while not self.shutdown.is_set():
            # Attendre 1 heure (3600s) ou shutdown
            if self.shutdown.wait(timeout=3600):
                break
            try:
                self._check_expired()
            except Exception as e:
                logger.exception(f"Erreur UnblockerWorker : {e}")

        logger.info("UnblockerWorker arrêté")

    def _check_expired(self):
        """Vérifie et débloque les IPs expirées."""
        expired = self.db.get_expired_blocks()
        if not expired:
            return

        logger.info(f"Déblocage de {len(expired)} IPs expirées")
        for block in expired:
            try:
                self.blocker.unblock_ip(block["ip_address"], block["id"])
            except Exception as e:
                logger.error(f"Erreur déblocage {block['ip_address']} : {e}")
