"""
SIEM Africa - Agent (Module 3) - db/manager.py
DatabaseManager : encapsule toutes les opérations BDD.

ALIGNÉ AU SCHÉMA M2 RÉEL :
- audit_log : action_category (NOT NULL), target_table/target_id, performed_at
- ai_signature_cache (PAS ai_explanations) : signature_hash, used_count, ai_description
- email_logs : email_uuid (NOT NULL), related_alert_id
- alert_filters : filter_uuid (NOT NULL)
- blocked_ips : reason NOT NULL
- ip_reputation : total_alerts, classification, last_seen_at
"""
import sqlite3
import uuid
import json
import hashlib
import logging
import threading
from datetime import datetime, timedelta
from contextlib import contextmanager

from config import DB_PATH
from db.helpers import now_sqlite, sqlite_future

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Gestionnaire de la base SQLite. Thread-safe."""

    def __init__(self):
        self._local = threading.local()
        self._setup_done = False
        self._setup_lock = threading.Lock()

    def _setup(self):
        with self._setup_lock:
            if self._setup_done:
                return
            try:
                conn = self._get_conn()
                conn.execute("PRAGMA foreign_keys = ON")
                conn.execute("PRAGMA journal_mode = WAL")
                conn.execute("PRAGMA synchronous = NORMAL")
                conn.commit()
                self._setup_done = True
            except Exception as e:
                logger.error(f"Setup BDD échoué : {e}")

    def _get_conn(self):
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                str(DB_PATH), timeout=10, isolation_level=None,
            )
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA foreign_keys = ON")
        return self._local.conn

    @contextmanager
    def cursor(self):
        self._setup()
        conn = self._get_conn()
        cur = conn.cursor()
        try:
            yield cur
        finally:
            cur.close()

    def close(self):
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

    # ========================================================================
    # SIGNATURES
    # ========================================================================
    def lookup_signature(self, source, rule_id):
        """Cherche par source + rule_id (stocké dans metadata JSON)."""
        try:
            with self.cursor() as cur:
                cur.execute("""
                    SELECT id, uuid, name, description, description_fr, source,
                           category_id, technique_id, severity, confidence,
                           is_active, is_noisy, is_critical_chain,
                           remediation_fr, cve_ids, metadata
                    FROM signatures
                    WHERE source = ?
                    AND (
                        json_extract(metadata, '$.rule_id') = ?
                        OR json_extract(metadata, '$.rule_id') = ?
                    )
                    LIMIT 1
                """, (source, str(rule_id), int(rule_id) if str(rule_id).isdigit() else rule_id))
                row = cur.fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"lookup_signature({source}, {rule_id}) : {e}")
            return None

    def get_signature_with_context(self, signature_id):
        try:
            with self.cursor() as cur:
                cur.execute("""
                    SELECT
                        s.id, s.uuid, s.name, s.description_fr, s.severity, s.confidence,
                        s.is_noisy, s.cve_ids, s.remediation_fr, s.metadata,
                        c.code as category_code, c.name_fr as category_name,
                        t.technique_id as mitre_technique_id,
                        t.name as mitre_technique_name,
                        mt.tactic_id as mitre_tactic_id,
                        mt.name as mitre_tactic_name
                    FROM signatures s
                    LEFT JOIN signature_categories c ON s.category_id = c.id
                    LEFT JOIN mitre_techniques t ON s.technique_id = t.id
                    LEFT JOIN mitre_tactics mt ON t.tactic_id = mt.id
                    WHERE s.id = ?
                    LIMIT 1
                """, (signature_id,))
                row = cur.fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"get_signature_with_context({signature_id}) : {e}")
            return None

    def create_unknown_signature(self, source, rule_id, name, description=None):
        """Crée une signature 'CUSTOM' avec rule_id dans metadata JSON."""
        try:
            with self.cursor() as cur:
                cur.execute("SELECT id FROM signature_categories WHERE code = 'CUSTOM' LIMIT 1")
                row = cur.fetchone()
                category_id = row[0] if row else 10

                metadata_json = json.dumps({"rule_id": str(rule_id), "auto_created": True})

                cur.execute("""
                    INSERT INTO signatures (
                        uuid, name, description_fr, source, category_id,
                        severity, confidence, is_active, is_noisy, metadata
                    ) VALUES (?, ?, ?, ?, ?, 'MEDIUM', 50, 1, 0, ?)
                """, (
                    str(uuid.uuid4()),
                    (name[:200] if name else f"Unknown {source}/{rule_id}"),
                    description, source, category_id, metadata_json,
                ))
                return cur.lastrowid
        except sqlite3.IntegrityError:
            return self.lookup_signature(source, rule_id)
        except Exception as e:
            logger.error(f"create_unknown_signature : {e}")
            return None

    def update_signature_description(self, signature_id, description_fr=None, remediation_fr=None):
        """Met à jour description_fr et remediation_fr d'une signature.

        Utilisé par l'AIEnricher : lorsqu'Ollama enrichit une signature qui
        n'avait pas de description française (typiquement une signature
        auto-créée par create_unknown_signature), on remplit la BDD pour
        que les futures requêtes voient directement le contenu en français.

        Args:
            signature_id : ID de la signature à mettre à jour
            description_fr : Texte français descriptif (str)
            remediation_fr : Recommandations - peut être str ou list (sera converti en texte)

        Returns:
            True si une ligne a été mise à jour, False sinon.
        """
        try:
            # On ne met à jour que les champs vides (pour ne pas écraser
            # les descriptions manuelles déjà présentes dans le M2)
            updates = []
            params = []

            if description_fr:
                updates.append("description_fr = COALESCE(NULLIF(TRIM(description_fr), ''), ?)")
                params.append(description_fr[:2000])

            if remediation_fr:
                # Convertir liste → texte numéroté si besoin
                if isinstance(remediation_fr, list):
                    rem_text = "\n".join(f"{i+1}. {r}" for i, r in enumerate(remediation_fr))
                else:
                    rem_text = str(remediation_fr)
                updates.append("remediation_fr = COALESCE(NULLIF(TRIM(remediation_fr), ''), ?)")
                params.append(rem_text[:2000])

            if not updates:
                return False

            params.append(signature_id)
            sql = f"UPDATE signatures SET {', '.join(updates)} WHERE id = ?"

            with self.cursor() as cur:
                cur.execute(sql, params)
                return cur.rowcount > 0
        except Exception as e:
            logger.error(f"update_signature_description({signature_id}) : {e}")
            return False

    # ========================================================================
    # ALERTS
    # ========================================================================
    def insert_alert(self, data):
        try:
            now = now_sqlite()
            alert_uuid = data.get("alert_uuid") or str(uuid.uuid4())

            with self.cursor() as cur:
                cur.execute("""
                    INSERT INTO alerts (
                        alert_uuid, signature_id, severity, confidence,
                        title, description, src_ip, dst_ip, src_port, dst_port,
                        protocol, asset_id, event_count, first_seen, last_seen,
                        status, enriched_data, ai_status, created_at, updated_at
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?,
                        'NEW', ?, ?, ?, ?
                    )
                """, (
                    alert_uuid, data["signature_id"], data["severity"],
                    data.get("confidence", 70), data["title"][:500],
                    data.get("description"), data.get("src_ip"), data.get("dst_ip"),
                    data.get("src_port"), data.get("dst_port"),
                    data.get("protocol"), data.get("asset_id"),
                    data.get("first_seen", now), data.get("last_seen", now),
                    json.dumps(data.get("enriched_data")) if data.get("enriched_data") else None,
                    data.get("ai_status", "not_required"),
                    now, now,
                ))
                alert_id = cur.lastrowid
                logger.info(f"Alerte insérée #{alert_id} [{data['severity']}] {data['title'][:60]}")
                return alert_id
        except Exception as e:
            logger.error(f"insert_alert : {e}")
            return None

    def find_recent_similar_alert(self, signature_id, src_ip, window_minutes=5):
        try:
            with self.cursor() as cur:
                cur.execute("""
                    SELECT id, event_count, first_seen FROM alerts
                    WHERE signature_id = ?
                    AND COALESCE(src_ip, '') = COALESCE(?, '')
                    AND status IN ('NEW', 'ACKNOWLEDGED')
                    AND created_at >= datetime('now', ?)
                    ORDER BY id DESC LIMIT 1
                """, (signature_id, src_ip, f"-{window_minutes} minutes"))
                row = cur.fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"find_recent_similar_alert : {e}")
            return None

    def increment_alert_count(self, alert_id):
        try:
            with self.cursor() as cur:
                now = now_sqlite()
                cur.execute("""
                    UPDATE alerts
                    SET event_count = event_count + 1, last_seen = ?, updated_at = ?
                    WHERE id = ?
                """, (now, now, alert_id))
                return True
        except Exception as e:
            logger.error(f"increment_alert_count({alert_id}) : {e}")
            return False

    def update_alert_ai(self, alert_id, ai_data):
        try:
            now = now_sqlite()
            with self.cursor() as cur:
                cur.execute("""
                    UPDATE alerts
                    SET ai_status = ?, ai_description = ?, ai_remediation = ?,
                        ai_model_used = ?, ai_cache_id = ?, ai_processed_at = ?,
                        updated_at = ?
                    WHERE id = ?
                """, (
                    ai_data.get("ai_status", "fresh"),
                    ai_data.get("ai_description"),
                    json.dumps(ai_data.get("ai_remediation")) if ai_data.get("ai_remediation") else None,
                    ai_data.get("ai_model_used"),
                    ai_data.get("ai_cache_id"),
                    now, now, alert_id,
                ))
                return True
        except Exception as e:
            logger.error(f"update_alert_ai : {e}")
            return False

    def get_alert_by_id(self, alert_id):
        """Récupère une alerte avec les champs enrichis de sa signature.

        Inclut les colonnes sig_* (sig_description_fr, sig_remediation_fr, etc.)
        qui servent de fallback quand l'enrichissement IA n'a pas eu lieu
        (ex: Ollama indisponible) ou pour les signatures auto-créées dont
        seule la BDD M2 connaît la vraie description.
        """
        try:
            with self.cursor() as cur:
                cur.execute("""
                    SELECT a.*,
                           s.name           AS sig_name,
                           s.description    AS sig_description,
                           s.description_fr AS sig_description_fr,
                           s.remediation    AS sig_remediation,
                           s.remediation_fr AS sig_remediation_fr,
                           s.references_url AS sig_references_url,
                           s.cve_ids        AS sig_cve_ids,
                           s.source         AS sig_source
                    FROM alerts a
                    LEFT JOIN signatures s ON a.signature_id = s.id
                    WHERE a.id = ?
                """, (alert_id,))
                row = cur.fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"get_alert_by_id : {e}")
            return None

    # ========================================================================
    # ALERT FILTERS
    # ========================================================================
    def get_active_filters(self, signature_id, src_ip=None):
        try:
            with self.cursor() as cur:
                cur.execute("""
                    SELECT id, name, signature_id, src_ip, action, downgrade_to
                    FROM alert_filters
                    WHERE is_active = 1
                    AND (signature_id IS NULL OR signature_id = ?)
                    AND (src_ip IS NULL OR src_ip = ? OR ? LIKE src_ip || '%')
                    AND (expires_at IS NULL OR expires_at > datetime('now'))
                """, (signature_id, src_ip, src_ip or ""))
                return [dict(r) for r in cur.fetchall()]
        except Exception as e:
            logger.error(f"get_active_filters : {e}")
            return []

    def increment_filter_hit(self, filter_id):
        try:
            with self.cursor() as cur:
                cur.execute("""
                    UPDATE alert_filters
                    SET hit_count = hit_count + 1, last_hit_at = ?
                    WHERE id = ?
                """, (now_sqlite(), filter_id))
                return True
        except Exception as e:
            logger.error(f"increment_filter_hit : {e}")
            return False

    # ========================================================================
    # INCIDENTS
    # ========================================================================
    def count_recent_alerts_by_ip(self, src_ip, window_minutes=5):
        try:
            with self.cursor() as cur:
                cur.execute("""
                    SELECT COALESCE(SUM(event_count), 0) FROM alerts
                    WHERE src_ip = ?
                    AND (created_at >= datetime('now', ?) OR last_seen >= datetime('now', ?))
                """, (src_ip, f"-{window_minutes} minutes", f"-{window_minutes} minutes"))
                return cur.fetchone()[0]
        except Exception as e:
            logger.error(f"count_recent_alerts_by_ip : {e}")
            return 0

    def create_incident(self, title, severity, description=None, alert_ids=None):
        try:
            now = now_sqlite()
            with self.cursor() as cur:
                cur.execute("""
                    INSERT INTO incidents (
                        incident_uuid, title, description, severity,
                        status, alert_count, started_at, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 'OPEN', ?, ?, ?, ?)
                """, (
                    str(uuid.uuid4()), title[:500], description, severity,
                    len(alert_ids) if alert_ids else 0,
                    now, now, now,
                ))
                incident_id = cur.lastrowid

                if alert_ids:
                    for aid in alert_ids:
                        cur.execute("UPDATE alerts SET incident_id = ? WHERE id = ?",
                                    (incident_id, aid))

                logger.info(f"Incident créé #{incident_id} - {len(alert_ids or [])} alertes")
                return incident_id
        except Exception as e:
            logger.error(f"create_incident : {e}")
            return None

    def get_recent_alerts_by_ip(self, src_ip, window_minutes=5):
        try:
            with self.cursor() as cur:
                cur.execute("""
                    SELECT id FROM alerts
                    WHERE src_ip = ?
                    AND created_at >= datetime('now', ?)
                    AND incident_id IS NULL
                """, (src_ip, f"-{window_minutes} minutes"))
                return [r[0] for r in cur.fetchall()]
        except Exception as e:
            logger.error(f"get_recent_alerts_by_ip : {e}")
            return []

    # ========================================================================
    # BLOCKED IPS (reason NOT NULL en M2)
    # ========================================================================
    def is_ip_blocked(self, ip_address):
        try:
            with self.cursor() as cur:
                cur.execute("""
                    SELECT id FROM blocked_ips
                    WHERE ip_address = ? AND is_active = 1
                    AND (expires_at IS NULL OR expires_at > datetime('now'))
                    LIMIT 1
                """, (ip_address,))
                return cur.fetchone() is not None
        except Exception as e:
            logger.error(f"is_ip_blocked : {e}")
            return False

    def insert_blocked_ip(self, ip_address, reason, duration_minutes=1440, alert_id=None):
        """reason NOT NULL en M2 - on garantit non vide."""
        try:
            now = now_sqlite()
            expires_at = None
            if duration_minutes > 0:
                expires_at = sqlite_future(duration_minutes)

            safe_reason = (reason or "Auto-block")[:500]

            with self.cursor() as cur:
                cur.execute("""
                    INSERT INTO blocked_ips (
                        block_uuid, ip_address, reason, block_type,
                        blocked_at, expires_at, alert_id, is_active
                    ) VALUES (?, ?, ?, 'AUTO', ?, ?, ?, 1)
                """, (
                    str(uuid.uuid4()), ip_address, safe_reason,
                    now, expires_at, alert_id,
                ))
                logger.info(f"IP bloquée : {ip_address} ({duration_minutes}min)")
                return cur.lastrowid
        except Exception as e:
            logger.error(f"insert_blocked_ip : {e}")
            return None

    def get_expired_blocks(self):
        try:
            with self.cursor() as cur:
                cur.execute("""
                    SELECT id, ip_address FROM blocked_ips
                    WHERE is_active = 1
                    AND expires_at IS NOT NULL
                    AND expires_at < datetime('now')
                """)
                return [dict(r) for r in cur.fetchall()]
        except Exception as e:
            logger.error(f"get_expired_blocks : {e}")
            return []

    def mark_block_inactive(self, block_id):
        try:
            with self.cursor() as cur:
                cur.execute("""
                    UPDATE blocked_ips SET is_active = 0, unblock_at = ?
                    WHERE id = ?
                """, (now_sqlite(), block_id))
                return True
        except Exception as e:
            logger.error(f"mark_block_inactive : {e}")
            return False

    # ========================================================================
    # IP REPUTATION (schéma M2 : total_alerts, classification, last_seen_at)
    # ========================================================================
    def update_ip_reputation(self, ip_address, delta_score, source_seen="agent"):
        try:
            now = now_sqlite()
            with self.cursor() as cur:
                cur.execute("""
                    UPDATE ip_reputation
                    SET reputation_score = MAX(0, MIN(100, reputation_score + ?)),
                        last_seen_at = ?,
                        total_alerts = total_alerts + 1
                    WHERE ip_address = ?
                """, (delta_score, now, ip_address))

                if cur.rowcount == 0:
                    base_score = max(0, min(100, 50 + delta_score))
                    classif = "MALICIOUS" if base_score < 30 else ("SUSPICIOUS" if base_score < 50 else "UNKNOWN")
                    cur.execute("""
                        INSERT INTO ip_reputation (
                            ip_address, reputation_score, classification,
                            total_alerts, first_seen_at, last_seen_at
                        ) VALUES (?, ?, ?, 1, ?, ?)
                    """, (ip_address, base_score, classif, now, now))
                return True
        except Exception as e:
            logger.error(f"update_ip_reputation : {e}")
            return False

    def get_ip_reputation(self, ip_address):
        try:
            with self.cursor() as cur:
                cur.execute("""
                    SELECT reputation_score, classification, total_alerts,
                           first_seen_at, last_seen_at, country_name
                    FROM ip_reputation WHERE ip_address = ?
                """, (ip_address,))
                row = cur.fetchone()
                if row:
                    d = dict(row)
                    d["times_seen"] = d.get("total_alerts", 0)
                    return d
                return None
        except Exception:
            return None

    # ========================================================================
    # AI CACHE (ai_signature_cache - schéma M2)
    # ========================================================================
    @staticmethod
    def _signature_hash(source, rule_id, raw_message=None):
        s = f"{source}:{rule_id}:{(raw_message or '')[:200]}"
        return hashlib.sha256(s.encode("utf-8")).hexdigest()

    def get_ai_cache(self, signature_id, ai_model, ttl_hours=168, source=None, rule_id=None):
        """Cherche par signature_hash (source+rule_id) si fournis, sinon par model_used."""
        try:
            with self.cursor() as cur:
                if source and rule_id is not None:
                    sig_hash = self._signature_hash(source, rule_id)
                    cur.execute("""
                        SELECT id, ai_description, ai_remediation, ai_severity,
                               model_used as ai_model, used_count
                        FROM ai_signature_cache
                        WHERE signature_hash = ? AND model_used = ?
                        AND created_at >= datetime('now', ?)
                        ORDER BY used_count DESC, id DESC LIMIT 1
                    """, (sig_hash, ai_model, f"-{ttl_hours} hours"))
                else:
                    cur.execute("""
                        SELECT id, ai_description, ai_remediation, ai_severity,
                               model_used as ai_model, used_count
                        FROM ai_signature_cache
                        WHERE model_used = ?
                        AND created_at >= datetime('now', ?)
                        ORDER BY used_count DESC, id DESC LIMIT 1
                    """, (ai_model, f"-{ttl_hours} hours"))

                row = cur.fetchone()
                if row:
                    d = dict(row)
                    d["explanation_fr"] = d.get("ai_description")  # alias compat
                    return d
                return None
        except Exception as e:
            logger.error(f"get_ai_cache : {e}")
            return None

    def insert_ai_explanation(self, alert_id, signature_id, ai_model, explanation_fr,
                              prompt_used=None, generation_time_ms=None,
                              source=None, rule_id=None, remediation=None):
        """Insère dans ai_signature_cache (NOT ai_explanations)."""
        try:
            with self.cursor() as cur:
                sig_hash = self._signature_hash(source or "unknown", rule_id or signature_id)
                remediation_json = json.dumps(remediation) if remediation else "[]"

                cur.execute("""
                    INSERT INTO ai_signature_cache (
                        signature_hash, source, rule_id, raw_message,
                        ai_description, ai_remediation, ai_severity,
                        model_used, response_time_ms, used_count, last_used_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 'MEDIUM', ?, ?, 1, ?)
                """, (
                    sig_hash, source or "unknown",
                    str(rule_id) if rule_id is not None else str(signature_id),
                    (prompt_used or "")[:500],
                    explanation_fr, remediation_json,
                    ai_model, generation_time_ms,
                    now_sqlite(),
                ))
                return cur.lastrowid
        except Exception as e:
            logger.error(f"insert_ai_explanation : {e}")
            return None

    def increment_ai_cache_hit(self, ai_cache_id):
        try:
            with self.cursor() as cur:
                cur.execute("""
                    UPDATE ai_signature_cache
                    SET used_count = used_count + 1, last_used_at = ?
                    WHERE id = ?
                """, (now_sqlite(), ai_cache_id))
                return True
        except Exception:
            return False

    # ========================================================================
    # EMAIL LOGS (schéma M2 : email_uuid NOT NULL, related_alert_id)
    # ========================================================================
    def insert_email_log(self, recipient, subject, status, alert_id=None,
                         error_message=None):
        try:
            now = now_sqlite()
            with self.cursor() as cur:
                cur.execute("""
                    INSERT INTO email_logs (
                        email_uuid, recipient, subject, status, related_alert_id,
                        error_message, queued_at, sent_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    str(uuid.uuid4()),
                    recipient[:200], subject[:500], status, alert_id,
                    error_message, now,
                    now if status in ("sent", "SENT") else None,
                ))
                return cur.lastrowid
        except Exception as e:
            logger.error(f"insert_email_log : {e}")
            return None

    def count_recent_emails(self, window_minutes=60):
        try:
            with self.cursor() as cur:
                cur.execute("""
                    SELECT COUNT(*) FROM email_logs
                    WHERE queued_at >= datetime('now', ?)
                    AND status IN ('sent', 'SENT')
                """, (f"-{window_minutes} minutes",))
                return cur.fetchone()[0]
        except Exception:
            return 0

    def email_already_sent(self, recipient, subject_pattern, window_minutes=5):
        try:
            with self.cursor() as cur:
                cur.execute("""
                    SELECT COUNT(*) FROM email_logs
                    WHERE recipient = ? AND subject = ?
                    AND status IN ('sent', 'SENT')
                    AND queued_at >= datetime('now', ?)
                """, (recipient, subject_pattern, f"-{window_minutes} minutes"))
                return cur.fetchone()[0] > 0
        except Exception:
            return False

    # ========================================================================
    # SETTINGS
    # ========================================================================
    def get_setting(self, key, default=None):
        try:
            with self.cursor() as cur:
                cur.execute("SELECT value, value_type FROM settings WHERE key = ?", (key,))
                row = cur.fetchone()
                if not row:
                    return default
                value, value_type = row["value"], row["value_type"]
                if value is None:
                    return default
                if value_type in ("bool", "boolean"):
                    return value.lower() in ("true", "1", "yes", "on")
                elif value_type in ("int", "integer", "number"):
                    try:
                        return int(value)
                    except (ValueError, TypeError):
                        return default
                else:
                    return value
        except Exception as e:
            logger.error(f"get_setting({key}) : {e}")
            return default

    def get_settings_by_category(self, category):
        try:
            with self.cursor() as cur:
                cur.execute("""
                    SELECT key, value, value_type FROM settings WHERE category = ?
                """, (category,))
                result = {}
                for row in cur.fetchall():
                    key, value, vtype = row["key"], row["value"], row["value_type"]
                    if value is None:
                        result[key] = None
                        continue
                    if vtype in ("bool", "boolean"):
                        result[key] = value.lower() in ("true", "1", "yes", "on")
                    elif vtype in ("int", "integer", "number"):
                        try:
                            result[key] = int(value)
                        except (ValueError, TypeError):
                            result[key] = 0
                    else:
                        result[key] = value
                return result
        except Exception as e:
            logger.error(f"get_settings_by_category({category}) : {e}")
            return {}

    # ========================================================================
    # AUDIT LOG (schéma M2 : action_category NOT NULL, target_table/target_id, performed_at)
    # ========================================================================
    def insert_audit(self, action, resource_type=None, resource_id=None,
                     details=None, user_id=None, ip_address=None,
                     action_category=None, status="SUCCESS"):
        """Insère dans audit_log. resource_type/resource_id sont mappés sur target_table/target_id."""
        try:
            if not action_category:
                if action.startswith("alert_") or action.startswith("incident_"):
                    action_category = "ALERT"
                elif action.startswith("ip_") or action.startswith("block_"):
                    action_category = "IP_BLOCK"
                elif action.startswith("email_") or action.startswith("notif_"):
                    action_category = "NOTIFICATION"
                elif action.startswith("agent_") or action.startswith("healthcheck") or action.startswith("kpi_") or action.startswith("db_"):
                    action_category = "SYSTEM"
                elif action.startswith("settings_") or action.startswith("config_"):
                    action_category = "CONFIG"
                else:
                    action_category = "OTHER"

            details_json = json.dumps(details) if isinstance(details, dict) else details

            target_id_int = None
            target_uuid_str = None
            if resource_id is not None:
                try:
                    target_id_int = int(resource_id)
                except (ValueError, TypeError):
                    target_uuid_str = str(resource_id)

            with self.cursor() as cur:
                cur.execute("""
                    INSERT INTO audit_log (
                        action, action_category, target_table, target_id, target_uuid,
                        details, user_id, ip_address, status, performed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    action, action_category, resource_type,
                    target_id_int, target_uuid_str,
                    details_json, user_id, ip_address, status,
                    now_sqlite(),
                ))
                return cur.lastrowid
        except Exception as e:
            logger.debug(f"insert_audit (non bloquant) : {e}")
            return None

    # ========================================================================
    # KPI HISTORY
    # ========================================================================
    def insert_kpi_snapshot(self, metrics):
        try:
            today = datetime.utcnow().date().isoformat()
            with self.cursor() as cur:
                for name, val_unit in metrics.items():
                    if isinstance(val_unit, tuple):
                        value, unit = val_unit
                    else:
                        value, unit = val_unit, "count"
                    cur.execute("""
                        INSERT INTO kpi_history (
                            snapshot_date, metric_name, metric_value, metric_unit
                        ) VALUES (?, ?, ?, ?)
                    """, (today, name, value, unit))
                return True
        except Exception as e:
            logger.error(f"insert_kpi_snapshot : {e}")
            return False

    def compute_daily_kpis(self):
        try:
            with self.cursor() as cur:
                metrics = {}

                cur.execute("SELECT COUNT(*) FROM alerts WHERE date(created_at) = date('now')")
                metrics["alerts_total"] = (cur.fetchone()[0], "count")

                for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                    cur.execute("""
                        SELECT COUNT(*) FROM alerts
                        WHERE date(created_at) = date('now') AND severity = ?
                    """, (sev,))
                    metrics[f"alerts_{sev.lower()}"] = (cur.fetchone()[0], "count")

                cur.execute("SELECT COUNT(*) FROM alerts WHERE date(created_at) = date('now') AND status = 'RESOLVED'")
                metrics["alerts_resolved"] = (cur.fetchone()[0], "count")

                cur.execute("SELECT COUNT(*) FROM alerts WHERE date(created_at) = date('now') AND status = 'FALSE_POSITIVE'")
                metrics["alerts_false_positive"] = (cur.fetchone()[0], "count")

                cur.execute("SELECT COUNT(*) FROM blocked_ips WHERE date(blocked_at) = date('now')")
                metrics["ips_blocked_total"] = (cur.fetchone()[0], "count")

                cur.execute("SELECT COUNT(*) FROM blocked_ips WHERE is_active = 1")
                metrics["ips_blocked_active"] = (cur.fetchone()[0], "count")

                cur.execute("SELECT COUNT(*) FROM ai_signature_cache WHERE date(created_at) = date('now')")
                metrics["ai_explanations"] = (cur.fetchone()[0], "count")

                cur.execute("SELECT COALESCE(SUM(used_count), 0) FROM ai_signature_cache")
                metrics["ai_cache_hits"] = (cur.fetchone()[0], "count")

                cur.execute("SELECT COUNT(*) FROM users WHERE is_active = 1")
                metrics["active_users"] = (cur.fetchone()[0], "count")

                return metrics
        except Exception as e:
            logger.error(f"compute_daily_kpis : {e}")
            return {}
