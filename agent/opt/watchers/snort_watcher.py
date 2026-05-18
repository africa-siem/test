"""SIEM Africa - Agent : Watcher Snort 2.9 (format texte)."""
import os
import re
import time
from pathlib import Path

import config
from logger import setup_logger


log = setup_logger("watchers.snort")

ALERT_RE = re.compile(
    r"\[\*\*\]\s+\[(?P<gen>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+(?P<msg>.+?)\s+\[\*\*\]"
)
IP_RE = re.compile(
    r"(?P<src>\d+\.\d+\.\d+\.\d+)(?::(?P<srcport>\d+))?\s*->\s*(?P<dst>\d+\.\d+\.\d+\.\d+)(?::(?P<dstport>\d+))?"
)
CLASS_RE = re.compile(r"\[Classification:\s*([^\]]+)\]")
PRIO_RE = re.compile(r"\[Priority:\s*(\d+)\]")


def _open_for_tail(path):
    f = open(path, "r", encoding="utf-8", errors="replace")
    f.seek(0, os.SEEK_END)
    return f


def _parse_alert(text):
    m = ALERT_RE.search(text)
    if not m:
        return None
    sid = m.group("sid")
    msg = m.group("msg").strip()

    src_ip = dst_ip = src_port = dst_port = None
    ip_match = IP_RE.search(text)
    if ip_match:
        src_ip = ip_match.group("src")
        dst_ip = ip_match.group("dst")
        src_port = ip_match.group("srcport")
        dst_port = ip_match.group("dstport")

    classification = None
    cm = CLASS_RE.search(text)
    if cm:
        classification = cm.group(1).strip()

    priority = None
    pm = PRIO_RE.search(text)
    if pm:
        try:
            priority = int(pm.group(1))
        except ValueError:
            pass

    return {
        "source": "snort",
        "rule_id": sid,
        "raw_level": priority,
        "raw_message": msg,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": None,
        "title": msg,
        "classification": classification,
        "raw_event": {"text": text[:500]},
    }


def _flush_block(buf, callback):
    if not buf:
        return
    text = "\n".join(buf)
    alert = _parse_alert(text)
    if alert:
        try:
            callback(alert)
        except Exception as exc:  # noqa: BLE001
            log.error(f"Callback Snort : {exc}")


def watch(callback, stop_event):
    if not config.SNORT_WATCHER_ENABLED:
        log.info("Snort watcher desactive")
        return

    path = Path(config.SNORT_ALERT_FILE)

    waited = 0
    while not path.is_file() and not stop_event.is_set():
        if waited == 0:
            log.warning(f"En attente de {path}...")
        time.sleep(5)
        waited += 5
        if waited > 300:
            log.warning(f"{path} introuvable - watcher Snort abandonne")
            return

    if stop_event.is_set():
        return

    log.info(f"Demarrage watcher Snort sur {path}")

    f = _open_for_tail(str(path))
    buf = []
    try:
        while not stop_event.is_set():
            line = f.readline()
            if not line:
                _flush_block(buf, callback)
                buf = []
                stop_event.wait(2)
                continue
            line = line.rstrip("\n")
            if line.strip() == "":
                _flush_block(buf, callback)
                buf = []
            else:
                buf.append(line)
    finally:
        _flush_block(buf, callback)
        f.close()
