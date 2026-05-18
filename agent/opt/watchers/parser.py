"""
SIEM Africa - Agent (Module 3) - watchers/parser.py
Parser des events JSON de Wazuh alerts.json.

Identifie automatiquement la source (Wazuh natif vs Snort relayé) via decoder.name.
"""
import json


def parse_wazuh_event(line):
    """
    Parse une ligne JSON de alerts.json.
    Retourne un dict normalisé ou None si invalide.

    Structure normalisée :
    {
        "source": "wazuh" | "snort",
        "rule_id": int (ou str pour Snort SID),
        "level": int (niveau Wazuh 0-15),
        "severity": str (INFO/LOW/MEDIUM/HIGH/CRITICAL),
        "description": str,
        "src_ip": str ou None,
        "dst_ip": str ou None,
        "src_port": int ou None,
        "dst_port": int ou None,
        "protocol": str ou None,
        "timestamp": str ISO,
        "raw": dict (event complet)
    }
    """
    if not line or not line.strip():
        return None

    try:
        event = json.loads(line.strip())
    except json.JSONDecodeError:
        # Stratégie défensive : essayer de réparer
        try:
            cleaned = line.strip().encode("utf-8", errors="ignore").decode("utf-8")
            event = json.loads(cleaned)
        except Exception:
            return None

    if not isinstance(event, dict):
        return None

    # Identifier la source via decoder.name
    decoder_name = ((event.get("decoder") or {}).get("name") or "").lower()
    if decoder_name == "snort":
        source = "snort"
        # Pour Snort, le SID est dans data.snort_id
        rule_id = (event.get("data") or {}).get("snort_id") or \
                  (event.get("rule") or {}).get("id")
    else:
        source = "wazuh"
        rule_id = (event.get("rule") or {}).get("id")

    if not rule_id:
        return None

    # Conversion rule_id (int si possible)
    try:
        rule_id = int(rule_id)
    except (ValueError, TypeError):
        pass

    rule = event.get("rule") or {}
    data = event.get("data") or {}

    # Récupérer IPs
    src_ip = data.get("srcip") or data.get("src_ip") or data.get("source_ip")
    dst_ip = data.get("dstip") or data.get("dst_ip") or data.get("destination_ip")

    # Ports
    src_port = None
    dst_port = None
    try:
        if data.get("srcport"):
            src_port = int(data["srcport"])
        if data.get("dstport"):
            dst_port = int(data["dstport"])
    except (ValueError, TypeError):
        pass

    protocol = data.get("protocol") or data.get("proto")

    # Severity à partir du niveau Wazuh
    level = rule.get("level", 0)
    severity = level_to_severity(level)

    return {
        "source": source,
        "rule_id": rule_id,
        "level": level,
        "severity": severity,
        "description": rule.get("description", ""),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "timestamp": event.get("timestamp"),
        "full_log": event.get("full_log", ""),
        "groups": rule.get("groups", []),
        "raw": event,
    }


def level_to_severity(level):
    """Convertit le niveau Wazuh (0-15) en sévérité SIEM Africa."""
    if level >= 12:
        return "CRITICAL"
    elif level >= 9:
        return "HIGH"
    elif level >= 6:
        return "MEDIUM"
    elif level >= 3:
        return "LOW"
    else:
        return "INFO"


# Alias rétro-compatibilité (l'ancien code utilisait _level_to_severity)
_level_to_severity = level_to_severity
