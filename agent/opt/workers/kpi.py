"""
SIEM Africa - Agent (Module 3) - workers/kpi.py
KPISnapshotter : snapshot quotidien des KPI à minuit.
"""
import logging
import threading

from db import get_db
from workers.utils import seconds_until

logger = logging.getLogger(__name__)


# ============================================================================
class KPISnapshotter(threading.Thread):
    """Thread qui calcule et insère les KPI quotidiens à minuit."""

    def __init__(self, shutdown_event):
        super().__init__(name="KPISnapshotter", daemon=True)
        self.shutdown = shutdown_event
        self.db = get_db()

    def run(self):
        logger.info("Démarrage KPISnapshotter")

        while not self.shutdown.is_set():
            wait_s = seconds_until(0, 5)  # 00h05
            logger.debug(f"Prochain snapshot KPI dans {wait_s}s")

            if self.shutdown.wait(timeout=wait_s):
                break

            try:
                self._snapshot()
            except Exception as e:
                logger.exception(f"Erreur snapshot KPI : {e}")

        logger.info("KPISnapshotter arrêté")

    def _snapshot(self):
        logger.info("Calcul du snapshot KPI quotidien")
        metrics = self.db.compute_daily_kpis()
        if not metrics:
            logger.warning("Aucun KPI calculé")
            return

        success = self.db.insert_kpi_snapshot(metrics)
        if success:
            self.db.insert_audit("kpi_snapshot",
                                 details={"metrics_count": len(metrics)})
            logger.info(f"Snapshot KPI inséré : {len(metrics)} métriques")


# ============================================================================
# DB BACKUP (2h du matin)
