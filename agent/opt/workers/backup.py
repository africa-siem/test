"""
SIEM Africa - Agent (Module 3) - workers/backup.py
DBBackup : sauvegarde la BDD chaque jour à 2h (rotation 30 jours).
"""
import logging
import threading
import shutil
from datetime import datetime, timedelta
from pathlib import Path

from db import get_db
from config import DB_PATH, BACKUP_DIR
from workers.utils import seconds_until

logger = logging.getLogger(__name__)


# ============================================================================
class DBBackup(threading.Thread):
    """Thread qui sauvegarde la BDD chaque jour à 2h (rotation 30 jours)."""

    def __init__(self, shutdown_event, retention_days=30):
        super().__init__(name="DBBackup", daemon=True)
        self.shutdown = shutdown_event
        self.db = get_db()
        self.retention_days = retention_days

    def run(self):
        logger.info("Démarrage DBBackup")

        # Créer le dossier de backup si absent
        try:
            BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.warning(f"Impossible de créer {BACKUP_DIR} : {e}")

        while not self.shutdown.is_set():
            wait_s = seconds_until(2, 0)  # 02h00
            logger.debug(f"Prochain backup BDD dans {wait_s}s")

            if self.shutdown.wait(timeout=wait_s):
                break

            try:
                self._backup()
                self._rotate()
            except Exception as e:
                logger.exception(f"Erreur backup BDD : {e}")

        logger.info("DBBackup arrêté")

    def _backup(self):
        """Copie la BDD vers BACKUP_DIR avec timestamp."""
        if not DB_PATH.exists():
            logger.error(f"BDD source introuvable : {DB_PATH}")
            return

        today = datetime.now().strftime("%Y%m%d")
        dest = BACKUP_DIR / f"siem-{today}.db"

        try:
            # Pour une copie SQLite cohérente en mode WAL,
            # on utilise sqlite3 .backup au lieu d'un simple cp
            import sqlite3
            src = sqlite3.connect(str(DB_PATH))
            dst = sqlite3.connect(str(dest))
            with dst:
                src.backup(dst)
            src.close()
            dst.close()

            size_mb = dest.stat().st_size / (1024 * 1024)
            logger.info(f"Backup BDD : {dest} ({size_mb:.1f} MB)")

            self.db.insert_audit("db_backup",
                                 details={"file": str(dest), "size_mb": round(size_mb, 2)})

        except Exception as e:
            logger.error(f"Erreur backup : {e}")
            # Fallback : copie simple
            try:
                shutil.copy2(DB_PATH, dest)
                logger.info(f"Backup fallback (copy) : {dest}")
            except Exception as e2:
                logger.error(f"Backup fallback échoué : {e2}")

    def _rotate(self):
        """Supprime les backups de plus de retention_days jours."""
        if not BACKUP_DIR.exists():
            return

        cutoff = datetime.now() - timedelta(days=self.retention_days)
        removed = 0

        for f in BACKUP_DIR.glob("siem-*.db"):
            try:
                # Extraire la date du nom de fichier siem-YYYYMMDD.db
                date_str = f.stem.split("-")[1]
                file_date = datetime.strptime(date_str, "%Y%m%d")
                if file_date < cutoff:
                    f.unlink()
                    removed += 1
            except Exception:
                continue

        if removed:
            logger.info(f"Rotation backups : {removed} fichiers supprimés (> {self.retention_days}j)")


# ============================================================================
# DAILY RECAP (7h du matin)
