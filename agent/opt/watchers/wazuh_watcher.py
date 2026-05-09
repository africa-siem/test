"""SIEM Africa - Agent : Watcher Wazuh alerts.json.

Strategie : inotify si disponible, fallback polling 5s sinon.
"""
import json
import os
import time
from pathlib import Path

import config
from logger import setup_logger


log = setup_logger("watchers.wazuh")


def _try_inotify():
    try:
        import inotify_simple
        return inotify_simple
    except ImportError:
        return None


def _open_for_tail(path):
    f = open(path, "r", encoding="utf-8", errors="replace")
    f.seek(0, os.SEEK_END)
    return f


def _read_new_lines(f):
    lines = []
    while True:
        line = f.readline()
        if not line:
            break
        line = line.strip()
        if line:
            lines.append(line)
    return lines


def _parse_alert(line):
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None

    rule = data.get("rule") or {}
    agent = data.get("agent") or {}
    src = data.get("data", {})

    rule_id = str(rule.get("id") or "")
    if not rule_id:
        return None

    return {
        "source": "wazuh",
        "rule_id": rule_id,
        "raw_level": rule.get("level"),
        "raw_message": data.get("full_log") or rule.get("description") or "",
        "src_ip": src.get("srcip") or src.get("src_ip"),
        "dst_ip": src.get("dstip") or src.get("dst_ip"),
        "src_port": src.get("srcport"),
        "dst_port": src.get("dstport"),
        "protocol": src.get("protocol"),
        "agent_name": agent.get("name"),
        "title": rule.get("description") or f"Wazuh rule {rule_id}",
        "raw_event": data,
    }


def watch(callback, stop_event):
    if not config.WAZUH_WATCHER_ENABLED:
        log.info("Wazuh watcher desactive")
        return

    path = Path(config.WAZUH_ALERTS_FILE)

    waited = 0
    while not path.is_file() and not stop_event.is_set():
        if waited == 0:
            log.warning(f"En attente de {path}...")
        time.sleep(5)
        waited += 5
        if waited > 300:
            log.error(f"{path} introuvable apres 5 min")
            return

    if stop_event.is_set():
        return

    log.info(f"Demarrage watcher Wazuh sur {path}")
    inotify_mod = _try_inotify()
    if inotify_mod:
        _watch_inotify(path, callback, stop_event, inotify_mod)
    else:
        log.warning("inotify_simple indisponible - polling 5s")
        _watch_polling(path, callback, stop_event)


def _watch_polling(path, callback, stop_event):
    f = _open_for_tail(str(path))
    try:
        while not stop_event.is_set():
            for line in _read_new_lines(f):
                alert = _parse_alert(line)
                if alert:
                    try:
                        callback(alert)
                    except Exception as exc:  # noqa: BLE001
                        log.error(f"Callback : {exc}")
            stop_event.wait(5)
    finally:
        f.close()


def _watch_inotify(path, callback, stop_event, inotify_mod):
    flags = inotify_mod.flags
    inotify = inotify_mod.INotify()
    watch_flags = flags.MODIFY | flags.MOVE_SELF | flags.DELETE_SELF
    wd = inotify.add_watch(str(path), watch_flags)

    f = _open_for_tail(str(path))
    try:
        while not stop_event.is_set():
            for event in inotify.read(timeout=2000):
                if event.mask & flags.MODIFY:
                    for line in _read_new_lines(f):
                        alert = _parse_alert(line)
                        if alert:
                            try:
                                callback(alert)
                            except Exception as exc:  # noqa: BLE001
                                log.error(f"Callback : {exc}")
                if event.mask & (flags.MOVE_SELF | flags.DELETE_SELF):
                    log.warning("Fichier deplace/supprime - retry 5s")
                    f.close()
                    time.sleep(5)
                    f = _open_for_tail(str(path))
                    try:
                        inotify.rm_watch(wd)
                    except Exception:  # noqa: BLE001
                        pass
                    wd = inotify.add_watch(str(path), watch_flags)
    finally:
        f.close()
        try:
            inotify.rm_watch(wd)
        except Exception:  # noqa: BLE001
            pass
