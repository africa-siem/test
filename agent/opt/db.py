"""SIEM Africa - Agent : Wrapper SQLite (siem.db)."""
import hashlib
import json
import sqlite3
import threading
import uuid
from datetime import datetime
from pathlib import Path

import config


_LOCAL = threading.local()


def _get_conn():
    """Cree (ou recupere) une connection SQLite par thread."""
    conn = getattr(_LOCAL, "conn", None)
    if conn is None:
        conn = sqlite3.connect(
            config.DB_PATH,
            timeout=30.0,
            isolation_level=None,  # autocommit
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        _LOCAL.conn = conn
    return conn


def health_check():
    """Verifie que la BDD est accessible et que les tables critiques existent."""
    try:
        conn = _get_conn()
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('alerts','signatures','ai_signature_cache','settings');"
        )
        names = {row["name"] for row in cur.fetchall()}
        required = {"alerts", "signatures", "ai_signature_cache", "settings"}
        missing = required - names
        if missing:
            return False, f"Tables manquantes : {missing}"
        return True, "BDD OK"
    except sqlite3.Error as exc:
        return False, str(exc)


# ============================================================================
# Settings
# ============================================================================

def get_setting(key, default=None):
    """Lit la valeur d'une cle dans settings."""
    conn = _get_conn()
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    if row is None:
        return default
    return row["value"]


def get_setting_bool(key, default=False):
    val = (get_setting(key) or "").strip().lower()
    if val in ("true", "1", "yes", "on"):
        return True
    if val in ("false", "0", "no", "off"):
        return False
    return default


# ============================================================================
# Signatures
# ============================================================================

def find_signature(source, rule_id):
    """Cherche une signature par source (wazuh/snort) et rule_id.

    Retourne dict ou None.
    """
    conn = _get_conn()
    row = conn.execute(
        """
        SELECT s.id, s.source, s.rule_id, s.title, s.description, s.severity,
               s.confidence, s.remediation, s.mitre_tactic_id, s.mitre_technique_id,
               s.is_enabled
        FROM signatures s
        WHERE s.source = ? AND s.rule_id = ?
        LIMIT 1
        """,
        (source, str(rule_id)),
    ).fetchone()
    return dict(row) if row else None


# ============================================================================
# AI Signature Cache
# ============================================================================

def signature_hash(source, rule_id, raw_message):
    """Calcule un hash unique pour une signature inconnue."""
    raw = f"{source}|{rule_id}|{raw_message or ''}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def find_ai_cache(sig_hash):
    """Cherche une analyse IA en cache."""
    conn = _get_conn()
    row = conn.execute(
        "SELECT * FROM ai_signature_cache WHERE signature_hash=?",
        (sig_hash,),
    ).fetchone()
    return dict(row) if row else None


def save_ai_cache(
    sig_hash, source, rule_id, raw_message,
    description, remediation_json, severity,
    model_used, response_time_ms,
    mitre_tactic=None, mitre_technique=None,
):
    """Insere une nouvelle analyse IA dans le cache."""
    conn = _get_conn()
    cur = conn.execute(
        """
        INSERT OR REPLACE INTO ai_signature_cache
        (signature_hash, source, rule_id, raw_message,
         ai_description, ai_remediation, ai_severity,
         ai_mitre_tactic, ai_mitre_technique,
         model_used, response_time_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            sig_hash, source, str(rule_id), raw_message,
            description, remediation_json, severity,
            mitre_tactic, mitre_technique,
            model_used, response_time_ms,
        ),
    )
    return cur.lastrowid


# ============================================================================
# Alerts
# ============================================================================

def insert_alert(
    signature_id, severity, title, description,
    src_ip=None, dst_ip=None, src_port=None, dst_port=None,
    protocol=None, asset_id=None, event_count=1,
    confidence=70,
    ai_status="not_required", ai_description=None,
    ai_remediation=None, ai_severity=None,
    ai_model_used=None, ai_cache_id=None,
    enriched_data=None,
):
    """Insere une alerte. Retourne (id, alert_uuid)."""
    conn = _get_conn()
    alert_uuid = str(uuid.uuid4())
    now = datetime.utcnow().isoformat(timespec="seconds")
    cur = conn.execute(
        """
        INSERT INTO alerts
        (alert_uuid, signature_id, severity, confidence, title, description,
         src_ip, dst_ip, src_port, dst_port, protocol,
         asset_id, event_count, first_seen, last_seen,
         ai_status, ai_description, ai_remediation, ai_severity,
         ai_model_used, ai_cache_id, ai_processed_at,
         enriched_data, status)
        VALUES (?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?,
                ?, 'NEW')
        """,
        (
            alert_uuid, signature_id, severity, confidence, title, description,
            src_ip, dst_ip, src_port, dst_port, protocol,
            asset_id, event_count, now, now,
            ai_status, ai_description, ai_remediation, ai_severity,
            ai_model_used, ai_cache_id,
            now if ai_status in ("cached", "fresh") else None,
            json.dumps(enriched_data) if enriched_data else None,
        ),
    )
    return cur.lastrowid, alert_uuid


def update_alert_ai(alert_id, ai_status, ai_description=None,
                    ai_remediation=None, ai_severity=None,
                    ai_model_used=None, ai_cache_id=None):
    """Met a jour les champs ai_* d'une alerte (apres analyse async)."""
    conn = _get_conn()
    now = datetime.utcnow().isoformat(timespec="seconds")
    conn.execute(
        """
        UPDATE alerts
           SET ai_status=?, ai_description=?, ai_remediation=?, ai_severity=?,
               ai_model_used=?, ai_cache_id=?, ai_processed_at=?
         WHERE id=?
        """,
        (ai_status, ai_description, ai_remediation, ai_severity,
         ai_model_used, ai_cache_id, now, alert_id),
    )


# ============================================================================
# Audit
# ============================================================================

def audit_log(action, resource_type, resource_id=None, details=None, level="INFO"):
    """Insere une entree d'audit."""
    conn = _get_conn()
    try:
        conn.execute(
            """
            INSERT INTO audit_log (action, resource_type, resource_id, details, level, created_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (action, resource_type, str(resource_id) if resource_id else None,
             json.dumps(details) if isinstance(details, (dict, list)) else details,
             level),
        )
    except sqlite3.OperationalError:
        # La table audit_log peut ne pas exister selon la version du schema
        pass


# ============================================================================
# Dedup / counts
# ============================================================================

def count_alerts_today():
    conn = _get_conn()
    row = conn.execute(
        "SELECT COUNT(*) AS c FROM alerts WHERE date(created_at)=date('now')"
    ).fetchone()
    return row["c"] if row else 0
