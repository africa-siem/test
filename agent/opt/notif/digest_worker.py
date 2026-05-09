"""SIEM Africa - Agent : Digest worker.

Pour les alertes LOW/MEDIUM, on n'envoie pas un email a chaque fois mais on les
accumule dans un fichier JSON, et un thread daemon envoie 1 email recap a intervalles
reguliers (par defaut 60 minutes).

Le fichier est persiste sur disque pour resister aux redemarrages de l'agent.
"""
import json
import threading
import time
from datetime import datetime
from pathlib import Path

import db
from logger import setup_logger
from notif import email_sender


log = setup_logger("notif.digest")

DIGEST_FILE = Path("/var/lib/siem-africa/state/digest.json")
_LOCK = threading.Lock()


def _get_interval_seconds():
    val = db.get_setting("email_digest_interval_minutes")
    try:
        return int(val) * 60 if val else 3600
    except (TypeError, ValueError):
        return 3600


def is_enabled():
    return db.get_setting_bool("email_digest_enabled", True)


def add_alert(alert):
    """Ajoute une alerte LOW/MEDIUM au digest pending.

    `alert` est un dict avec : title, severity, src_ip, dst_ip, description, alert_id.
    """
    if not is_enabled():
        return False

    entry = {
        "alert_id": alert.get("alert_id"),
        "ts": datetime.utcnow().isoformat(timespec="seconds"),
        "title": alert.get("title", "?")[:200],
        "severity": alert.get("severity", "?"),
        "src_ip": alert.get("src_ip"),
        "dst_ip": alert.get("dst_ip"),
        "description": (alert.get("description") or "")[:300],
    }

    with _LOCK:
        items = _read_pending()
        items.append(entry)
        _write_pending(items)

    log.debug(f"Digest: alerte ajoutee, total pending = {len(items)}")
    return True


def _read_pending():
    if not DIGEST_FILE.is_file():
        return []
    try:
        with open(DIGEST_FILE, "r", encoding="utf-8") as f:
            return json.load(f) or []
    except (json.JSONDecodeError, OSError) as exc:
        log.warning(f"digest.json corrompu, reset : {exc}")
        return []


def _write_pending(items):
    try:
        DIGEST_FILE.parent.mkdir(parents=True, exist_ok=True)
        # Ecriture atomique
        tmp = DIGEST_FILE.with_suffix(".json.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(items, f, ensure_ascii=False, indent=2)
        tmp.replace(DIGEST_FILE)
    except OSError as exc:
        log.error(f"Ecriture digest.json echouee : {exc}")


def flush_now():
    """Envoie immediatement le digest (vide la queue)."""
    with _LOCK:
        items = _read_pending()
        if not items:
            log.debug("Digest vide, rien a envoyer")
            return False

        # Envoi
        ok = _send_digest(items)
        if ok:
            _write_pending([])
            log.info(f"Digest envoye : {len(items)} alertes")
        else:
            log.warning("Echec envoi digest, on garde les alertes pour la prochaine fois")
        return ok


def _send_digest(items):
    if not email_sender.is_configured():
        return False

    n = len(items)
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for it in items:
        sev = (it.get("severity") or "").upper()
        counts[sev] = counts.get(sev, 0) + 1

    subject = f"[SIEM Africa] Digest - {n} alertes (LOW/MEDIUM)"

    # Body texte
    lines = ["Resume des alertes LOW/MEDIUM accumulees :", ""]
    lines.append(f"  Total : {n} alertes")
    for sev, c in counts.items():
        if c > 0:
            lines.append(f"  {sev:<10} : {c}")
    lines.append("")
    lines.append("Detail :")
    lines.append("-" * 60)

    for it in items[-50:]:  # On limite a 50 dernieres pour pas exploser le mail
        ts = it.get("ts", "")
        sev = it.get("severity", "?")
        title = it.get("title", "?")
        src = it.get("src_ip") or "-"
        dst = it.get("dst_ip") or "-"
        desc = (it.get("description") or "")[:120]
        lines.append(f"[{ts}] [{sev}] {title}")
        lines.append(f"  src={src}  dst={dst}")
        if desc:
            lines.append(f"  {desc}")
        lines.append("")

    if n > 50:
        lines.append(f"... et {n - 50} autres alertes (voir le dashboard)")

    lines.append("")
    lines.append("Pour ne plus recevoir ce digest : email_digest_enabled=false dans settings.")
    lines.append("Pour reduire le bruit : augmenter email_min_severity dans settings.")

    body = "\n".join(lines)
    return email_sender.send(subject, body)


class DigestWorker(threading.Thread):
    """Thread daemon : envoie le digest a intervalle regulier."""

    def __init__(self, stop_event):
        super().__init__(name="DigestWorker", daemon=True)
        self.stop_event = stop_event

    def run(self):
        log.info("DigestWorker demarre")
        while not self.stop_event.is_set():
            interval = _get_interval_seconds()
            # On dort par tranches de 5s pour pouvoir s'arreter rapidement
            slept = 0
            while slept < interval and not self.stop_event.is_set():
                time.sleep(min(5, interval - slept))
                slept += 5

            if self.stop_event.is_set():
                break

            if is_enabled():
                try:
                    flush_now()
                except Exception as exc:  # noqa: BLE001
                    log.error(f"Erreur flush digest : {exc}")

        log.info("DigestWorker arrete - flush final")
        try:
            flush_now()
        except Exception:  # noqa: BLE001
            pass
