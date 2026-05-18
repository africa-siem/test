"""
SIEM Africa - Agent (Module 3) - watchers/wazuh.py
WazuhWatcher : surveille alerts.json en temps réel via inotify (avec fallback polling).
"""
import time
import logging
import threading

from config import WAZUH_LOG, WAZUH_POLL_INTERVAL
from watchers.parser import parse_wazuh_event

logger = logging.getLogger(__name__)


class WazuhWatcher(threading.Thread):
    """
    Thread qui surveille alerts.json et met les events dans une queue.

    Gère :
    - Reconnexion auto si rotation du fichier (inode change)
    - Fallback polling si inotify échoue
    - Parser défensif (lignes JSON mal formées)
    """

    def __init__(self, event_queue, shutdown_event):
        super().__init__(name="WazuhWatcher", daemon=True)
        self.queue = event_queue
        self.shutdown = shutdown_event
        self.position = 0
        self.inode = None

    def run(self):
        logger.info(f"Démarrage watcher Wazuh sur {WAZUH_LOG}")

        # Position de départ : à la fin du fichier (pas relecture des anciens)
        try:
            if WAZUH_LOG.exists():
                self.position = WAZUH_LOG.stat().st_size
                self.inode = WAZUH_LOG.stat().st_ino
                logger.info(f"Position initiale : {self.position} bytes")
        except Exception as e:
            logger.warning(f"Impossible de stat {WAZUH_LOG} : {e}")

        # Essayer inotify, fallback sur polling
        try:
            self._run_inotify()
        except ImportError:
            logger.warning("inotify-simple non disponible, fallback polling")
            self._run_polling()
        except Exception as e:
            logger.error(f"Erreur inotify ({e}), fallback polling")
            self._run_polling()

    def _run_inotify(self):
        """Boucle de surveillance via inotify (efficace)."""
        from inotify_simple import INotify, flags

        inotify = INotify()
        watch_flags = flags.MODIFY | flags.CREATE | flags.MOVED_TO

        parent_dir = str(WAZUH_LOG.parent)
        wd = inotify.add_watch(parent_dir, watch_flags)

        while not self.shutdown.is_set():
            try:
                # Lire d'abord les events en attente
                self._read_new_lines()

                # Attendre les notifications (timeout 1s pour vérifier shutdown)
                events = inotify.read(timeout=1000)
                for event in events:
                    if event.name == WAZUH_LOG.name:
                        time.sleep(0.1)  # laisser Wazuh finir d'écrire
                        self._read_new_lines()
            except Exception as e:
                logger.error(f"Erreur boucle inotify : {e}")
                time.sleep(2)

        logger.info("Watcher Wazuh arrêté (inotify)")

    def _run_polling(self):
        """Boucle de surveillance par polling (fallback)."""
        while not self.shutdown.is_set():
            try:
                self._read_new_lines()
            except Exception as e:
                logger.error(f"Erreur polling : {e}")

            self.shutdown.wait(timeout=WAZUH_POLL_INTERVAL)

        logger.info("Watcher Wazuh arrêté (polling)")

    def _read_new_lines(self):
        """Lit les nouvelles lignes du fichier depuis la dernière position."""
        if not WAZUH_LOG.exists():
            return

        try:
            stat = WAZUH_LOG.stat()
            current_inode = stat.st_ino
            current_size = stat.st_size

            # Détection rotation : inode différent ou taille plus petite
            if self.inode is not None and current_inode != self.inode:
                logger.info("Rotation détectée (inode changé)")
                self.position = 0
                self.inode = current_inode

            if current_size < self.position:
                logger.info("Fichier tronqué, reset position")
                self.position = 0

            self.inode = current_inode

            if current_size <= self.position:
                return

            with open(WAZUH_LOG, "r", errors="replace") as f:
                f.seek(self.position)
                for line in f:
                    if self.shutdown.is_set():
                        break
                    line = line.strip()
                    if not line:
                        continue

                    event = parse_wazuh_event(line)
                    if event:
                        try:
                            self.queue.put(event, timeout=5)
                            logger.debug(
                                f"Event reçu : {event['source']}/{event['rule_id']} "
                                f"[{event['severity']}] {event['description'][:60]}"
                            )
                        except Exception as e:
                            logger.warning(f"Queue pleine ou bloquée : {e}")

                self.position = f.tell()

        except PermissionError:
            logger.error(f"Permission denied sur {WAZUH_LOG} (ajouter siem-agent au groupe wazuh)")
            time.sleep(10)
        except Exception as e:
            logger.error(f"Erreur lecture {WAZUH_LOG} : {e}")
