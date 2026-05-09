"""SIEM Africa - Agent : main.py (lance par systemd).

Demarre :
  - healthcheck au boot
  - thread AIWorker (depile ai_queue)
  - thread WazuhWatcher
  - thread SnortWatcher
  - email de bienvenue
"""
import signal
import sys
import threading
import time
from pathlib import Path

# S'assurer que le dossier de l'agent est dans le path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import config
import db
import health_check
from logger import setup_logger
from processor.alert_processor import process_alert, AI_QUEUE
from watchers import wazuh_watcher, snort_watcher
from notif import email_sender
from ai.worker import AIWorker
from notif.digest_worker import DigestWorker


log = setup_logger("main")
STOP = threading.Event()


def _signal_handler(sig, frame):
    log.info(f"Signal {sig} recu - arret")
    STOP.set()


signal.signal(signal.SIGTERM, _signal_handler)
signal.signal(signal.SIGINT, _signal_handler)


def main():
    log.info("=" * 60)
    log.info("SIEM AFRICA AGENT - Demarrage")
    log.info("=" * 60)

    # Healthcheck
    health = health_check.run_all()

    if config.EMAIL_ALL_ALERTS and health["smtp"]:
        log.info("Mode email actif avec anti-spam (rate 30/h, dedup 5min, digest LOW/MEDIUM)")

    # Email de bienvenue
    if health["smtp"]:
        try:
            ok = email_sender.send(
                subject="[SIEM Africa] Agent demarre",
                body_text=(
                    "L'agent SIEM Africa vient de demarrer.\n\n"
                    f"Healthcheck :\n"
                    f"  DB     : {health['db']}\n"
                    f"  Ollama : {health['ollama']}\n"
                    f"  SMTP   : {health['smtp']}\n"
                ),
            )
            if ok:
                log.info("Email de bienvenue envoye")
        except Exception as exc:  # noqa: BLE001
            log.error(f"Email bienvenue : {exc}")

    # Audit boot
    try:
        db.audit_log(action="agent_started", resource_type="agent",
                     details=health, level="INFO" if all(health.values()) else "WARN")
    except Exception:  # noqa: BLE001
        pass

    threads = []

    # AIWorker (un seul thread, traite la queue)
    ai_worker = AIWorker(AI_QUEUE, STOP)
    ai_worker.start()
    threads.append(ai_worker)
    log.info("AIWorker demarre")

    # DigestWorker (envoie digest LOW/MEDIUM toutes les heures)
    digest_w = DigestWorker(STOP)
    digest_w.start()
    threads.append(digest_w)
    log.info("DigestWorker demarre")

    # Watchers
    if config.WAZUH_WATCHER_ENABLED:
        t = threading.Thread(
            target=wazuh_watcher.watch,
            args=(process_alert, STOP),
            name="wazuh-watcher",
            daemon=True,
        )
        t.start()
        threads.append(t)
        log.info("WazuhWatcher demarre")

    if config.SNORT_WATCHER_ENABLED:
        t = threading.Thread(
            target=snort_watcher.watch,
            args=(process_alert, STOP),
            name="snort-watcher",
            daemon=True,
        )
        t.start()
        threads.append(t)
        log.info("SnortWatcher demarre")

    log.info(f"Agent operationnel - {len(threads)} threads actifs")

    # Boucle principale
    try:
        while not STOP.is_set():
            time.sleep(2)
    except KeyboardInterrupt:
        STOP.set()

    log.info("Arret en cours...")
    for t in threads:
        t.join(timeout=10)

    log.info("Agent arrete proprement")


if __name__ == "__main__":
    main()
