#!/usr/bin/env python3
"""
SIEM Africa - Agent (Module 3)
Point d'entrée principal - assemble tous les blocs

Threads démarrés :
  Bloc 3 : WazuhWatcher          (lecture alerts.json)
  Bloc 4 : AlertProcessor        (cœur d'enrichissement)
  Bloc 5 : AIEnricher            (Ollama)
  Bloc 6 : EmailWorker           (envois SMTP)
  Bloc 7 : BlockWorker           (iptables block on demand)
  Bloc 7 : UnblockerWorker       (cron horaire des unblocks)
  Bloc 8 : KPISnapshotter        (cron quotidien minuit)
  Bloc 8 : DBBackup              (cron quotidien 2h)
  Bloc 8 : DailyRecapWorker      (cron quotidien 7h)
"""
import sys
import signal
import threading
import queue
import time

# Setup logging en premier
from logger_setup import setup_logging
setup_logging()

import logging
logger = logging.getLogger("main")


# ============================================================================
# GESTION ARRET PROPRE
# ============================================================================
shutdown_event = threading.Event()


def signal_handler(signum, frame):
    logger.info(f"Signal {signum} reçu, arrêt en cours...")
    shutdown_event.set()


def setup_signals():
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)


# ============================================================================
# MAIN
# ============================================================================
def main():
    logger.info("=" * 60)
    logger.info("SIEM AFRICA AGENT - Démarrage")
    logger.info("=" * 60)

    # 1. Signaux
    setup_signals()

    # 2. Healthcheck
    from healthcheck import run_healthcheck
    healthy, hc_results = run_healthcheck()
    if not healthy:
        logger.error("Healthcheck critique échoué, arrêt")
        sys.exit(1)

    # 3. Initialiser la DB (singleton)
    from db import get_db
    db = get_db()
    db.insert_audit("agent_start", details={"healthcheck": hc_results})

    # 4. Créer les queues de communication entre threads
    event_queue = queue.Queue(maxsize=1000)     # Watcher -> Processor
    ai_queue = queue.Queue(maxsize=500)         # Processor -> AIEnricher
    email_queue = queue.Queue(maxsize=500)      # Processor -> EmailWorker (et workers cron)
    block_queue = queue.Queue(maxsize=200)      # Processor -> BlockWorker

    threads = []

    # 5. BLOC 3 : Watcher Wazuh
    try:
        from watchers import WazuhWatcher
        watcher = WazuhWatcher(event_queue, shutdown_event)
        watcher.start()
        threads.append(watcher)
        logger.info("Thread WazuhWatcher démarré")
    except Exception as e:
        logger.error(f"Échec démarrage WazuhWatcher : {e}")

    # 6. BLOC 4 : Processor
    try:
        from processor import AlertProcessor
        processor = AlertProcessor(
            event_queue=event_queue,
            shutdown_event=shutdown_event,
            email_queue=email_queue,
            ai_queue=ai_queue,
            block_queue=block_queue,
        )
        processor.start()
        threads.append(processor)
        logger.info("Thread AlertProcessor démarré")
    except Exception as e:
        logger.error(f"Échec démarrage AlertProcessor : {e}")

    # 7. BLOC 5 : AI Enricher
    try:
        from ai import AIEnricher
        ai_worker = AIEnricher(ai_queue, shutdown_event)
        ai_worker.start()
        threads.append(ai_worker)
        logger.info("Thread AIEnricher démarré")
    except Exception as e:
        logger.warning(f"AIEnricher non démarré : {e}")

    # 8. BLOC 6 : Email Worker
    try:
        from notif import EmailWorker
        email_worker = EmailWorker(email_queue, shutdown_event)
        email_worker.start()
        threads.append(email_worker)
        logger.info("Thread EmailWorker démarré")

        # Email de bienvenue
        try:
            email_queue.put({"type": "welcome", "healthcheck": hc_results}, timeout=2)
        except Exception:
            pass
    except Exception as e:
        logger.warning(f"EmailWorker non démarré : {e}")

    # 9. BLOC 7 : Active Response
    try:
        from response import BlockWorker, UnblockerWorker
        block_worker = BlockWorker(block_queue, shutdown_event)
        block_worker.start()
        threads.append(block_worker)
        logger.info("Thread BlockWorker démarré")

        unblocker = UnblockerWorker(shutdown_event)
        unblocker.start()
        threads.append(unblocker)
        logger.info("Thread UnblockerWorker démarré")
    except Exception as e:
        logger.warning(f"Active Response non démarré : {e}")

    # 10. BLOC 8 : Workers cron
    try:
        from workers import KPISnapshotter, DBBackup, DailyRecapWorker
        kpi_worker = KPISnapshotter(shutdown_event)
        kpi_worker.start()
        threads.append(kpi_worker)
        logger.info("Thread KPISnapshotter démarré")

        backup_worker = DBBackup(shutdown_event)
        backup_worker.start()
        threads.append(backup_worker)
        logger.info("Thread DBBackup démarré")

        recap_worker = DailyRecapWorker(email_queue, shutdown_event)
        recap_worker.start()
        threads.append(recap_worker)
        logger.info("Thread DailyRecapWorker démarré")
    except Exception as e:
        logger.warning(f"Workers cron non démarrés : {e}")

    logger.info(f"Agent OPÉRATIONNEL avec {len(threads)} threads")
    logger.info("=" * 60)

    # 11. Loop principale
    while not shutdown_event.is_set():
        try:
            shutdown_event.wait(timeout=60)
            if not shutdown_event.is_set():
                alive = sum(1 for t in threads if t.is_alive())
                logger.debug(f"Heartbeat - threads vivants : {alive}/{len(threads)}")
        except Exception as e:
            logger.error(f"Erreur boucle principale : {e}")
            time.sleep(5)

    # 12. Arrêt propre
    logger.info("Signal d'arrêt reçu, attente des threads...")
    for t in threads:
        t.join(timeout=10)

    db.insert_audit("agent_stop", details={"clean_shutdown": True})
    db.close()

    logger.info("Agent arrêté proprement")
    logger.info("=" * 60)
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Arrêt clavier")
        sys.exit(0)
    except Exception as e:
        logger.exception(f"Erreur fatale : {e}")
        sys.exit(1)
