"""SIEM Africa - Agent : Traite chaque alerte d'un watcher.

Flux :
  1. Recoit alerte d'un watcher (callback)
  2. Filtre faux-positifs configures
  3. Cherche signature en BDD :
     - Trouvee -> insert immediat + email immediat (synchrone, rapide)
     - Pas trouvee -> insert avec ai_status='pending' + enqueue dans ai_queue
  4. AIWorker (thread separe) depile, fait l'enrichissement IA, update l'alerte,
     puis envoie l'email avec la description IA enrichie.
"""
import json
import threading
from queue import Queue

import db
from logger import setup_logger
from notif import email_sender, notifier
from ai import enrichment as ai_enrichment


log = setup_logger("processor")

# Queue partagee avec l'AIWorker (initialisee dans main.py)
AI_QUEUE = Queue(maxsize=500)


def _is_filtered(source, rule_id):
    """Verifie si une regle alert_filters demande d'ignorer cette alerte."""
    try:
        conn = db._get_conn()
        row = conn.execute(
            """
            SELECT af.action
              FROM alert_filters af
              LEFT JOIN signatures s ON s.id = af.signature_id
             WHERE af.is_active = 1
               AND s.source = ? AND s.rule_id = ?
            """,
            (source, str(rule_id)),
        ).fetchone()
        if row and (row["action"] or "").upper() == "IGNORE":
            return True
    except Exception:  # noqa: BLE001
        pass
    return False


def _safe_int(v):
    try:
        return int(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def _get_or_create_unknown_signature(source, rule_id):
    """Cree une signature 'unknown' pour respecter la FK alerts.signature_id."""
    conn = db._get_conn()
    row = conn.execute(
        "SELECT id FROM signatures WHERE source=? AND rule_id=?",
        (source, str(rule_id)),
    ).fetchone()
    if row:
        return row["id"]

    cat = conn.execute(
        "SELECT id FROM signature_categories WHERE name IN ('unknown','other') LIMIT 1"
    ).fetchone() or conn.execute(
        "SELECT id FROM signature_categories LIMIT 1"
    ).fetchone()
    if not cat:
        return None

    title = f"Unknown {source} rule {rule_id}"
    try:
        cur = conn.execute(
            """
            INSERT INTO signatures
            (source, rule_id, category_id, title, description, severity, confidence,
             is_enabled, is_unknown)
            VALUES (?, ?, ?, ?, ?, 'MEDIUM', 50, 1, 1)
            """,
            (source, str(rule_id), cat["id"], title,
             f"Signature {source} {rule_id} non repertoriee (auto-creee par l'agent)"),
        )
        return cur.lastrowid
    except Exception as exc:  # noqa: BLE001
        log.error(f"Echec creation signature unknown : {exc}")
        return None


def _send_email_safe(alert_dict, signature_hash=None):
    """Envoie via notifier (rate limit + dedup + digest) dans un thread."""
    try:
        notifier.notify(alert_dict, signature_hash=signature_hash)
    except Exception as exc:  # noqa: BLE001
        log.error(f"Echec notify : {exc}")


def process_alert(raw_alert):
    """Point d'entree pour chaque alerte d'un watcher."""
    source = raw_alert["source"]
    rule_id = str(raw_alert["rule_id"])
    title = (raw_alert.get("title") or f"{source} {rule_id}")[:200]

    # 1. Filtres faux-positifs
    if _is_filtered(source, rule_id):
        log.debug(f"Alerte ignoree par filtre : {source}/{rule_id}")
        return

    # 2. Cherche signature en BDD (immediat)
    sig = db.find_signature(source, rule_id)

    if sig:
        # === Cas 1 : signature connue, tout est synchrone ===
        signature_id = sig["id"]
        severity = sig["severity"]
        description = sig["description"] or sig["title"]
        remediation = _split_remediation(sig.get("remediation"))

        try:
            alert_id, alert_uuid = db.insert_alert(
                signature_id=signature_id,
                severity=severity,
                title=title,
                description=description,
                src_ip=raw_alert.get("src_ip"),
                dst_ip=raw_alert.get("dst_ip"),
                src_port=_safe_int(raw_alert.get("src_port")),
                dst_port=_safe_int(raw_alert.get("dst_port")),
                protocol=raw_alert.get("protocol"),
                ai_status="not_required",
                enriched_data={"raw": raw_alert.get("raw_event")},
            )
            log.info(f"Alerte #{alert_id} - {source}/{rule_id} - {severity} - signature BDD")
        except Exception as exc:  # noqa: BLE001
            log.error(f"Echec insert alerte : {exc}")
            return

        # Notification (rate limit + dedup + digest selon severite)
        if email_sender.is_configured():
            sig_hash = db.signature_hash(source, rule_id, raw_alert.get("raw_message"))
            threading.Thread(
                target=_send_email_safe,
                args=({
                    "title": title,
                    "severity": severity,
                    "description": description,
                    "src_ip": raw_alert.get("src_ip"),
                    "dst_ip": raw_alert.get("dst_ip"),
                    "ai_description": description,
                    "ai_remediation": remediation,
                    "alert_id": alert_id,
                }, sig_hash),
                daemon=True,
            ).start()

        # IP block immediat
        _maybe_block_ip(severity, raw_alert.get("src_ip"))
        return

    # === Cas 2 : signature inconnue ===
    # On cree une signature 'unknown' et on insert l'alerte avec ai_status='pending'
    # puis on enqueue pour traitement IA async
    signature_id = _get_or_create_unknown_signature(source, rule_id)
    if signature_id is None:
        log.error(f"Pas de signature unknown disponible pour {source}/{rule_id} - alerte perdue")
        return

    try:
        alert_id, alert_uuid = db.insert_alert(
            signature_id=signature_id,
            severity="MEDIUM",  # Severite provisoire en attendant l'IA
            title=title,
            description="Analyse IA en cours...",
            src_ip=raw_alert.get("src_ip"),
            dst_ip=raw_alert.get("dst_ip"),
            src_port=_safe_int(raw_alert.get("src_port")),
            dst_port=_safe_int(raw_alert.get("dst_port")),
            protocol=raw_alert.get("protocol"),
            ai_status="pending",
            enriched_data={"raw": raw_alert.get("raw_event")},
        )
        log.info(f"Alerte #{alert_id} - {source}/{rule_id} - PENDING IA")
    except Exception as exc:  # noqa: BLE001
        log.error(f"Echec insert alerte pending : {exc}")
        return

    # Enqueue pour AIWorker
    try:
        AI_QUEUE.put_nowait({
            "alert_id": alert_id,
            "source": source,
            "rule_id": rule_id,
            "title": title,
            "raw_message": raw_alert.get("raw_message"),
            "raw_level": raw_alert.get("raw_level"),
            "src_ip": raw_alert.get("src_ip"),
            "dst_ip": raw_alert.get("dst_ip"),
        })
    except Exception as exc:  # noqa: BLE001
        log.error(f"Queue IA pleine ou erreur : {exc}")
        # Fallback : on update directement en mode degrade
        db.update_alert_ai(
            alert_id=alert_id,
            ai_status="failed",
            ai_description="Queue IA saturee, analyse non realisee.",
            ai_severity="MEDIUM",
        )


def _split_remediation(text):
    if not text:
        return None
    text = text.strip()
    if text.startswith("["):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
    lines = [l.strip(" -*\t") for l in text.splitlines() if l.strip()]
    return lines or [text]


def _maybe_block_ip(severity, src_ip):
    if not db.get_setting_bool("ip_block_enabled", False):
        return
    if severity != "CRITICAL" or not src_ip:
        return
    try:
        from ip_blocker import block_ip
        block_ip(src_ip)
    except Exception as exc:  # noqa: BLE001
        log.error(f"Echec block IP {src_ip} : {exc}")
