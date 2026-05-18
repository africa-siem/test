"""
SIEM Africa - Agent (Module 3) - db/manager.py
DatabaseManager : encapsule toutes les opérations BDD.

Cette classe est la SEULE qui parle à la BDD SQLite.
Tous les autres modules doivent passer par DatabaseManager.

Conformité schéma M2 :
- signatures.uuid : géré par trigger sig_auto_uuid (auto-généré)
- signatures.name : fourni à l'insert (NOT NULL)
- alerts.uuid : à fournir manuellement (NOT NULL UNIQUE)
- audit_log : trace de toutes les actions
"""
import sqlite3
import uuid
import json
import logging
import threading
import time
from datetime import datetime, timedelta
from contextlib import contextmanager

from config import DB_PATH
from db.helpers import now_sqlite, sqlite_future

logger = logging.getLogger(__name__)


# ============================================================================
# CONNEXION SQLITE THREAD-SAFE
# ============================================================================
class DatabaseManager:
    """
    Gestionnaire de la base SQLite.
    Thread-safe : chaque thread a sa propre connexion via threading.local.
    """

    def __init__(self):
        self._local = threading.local()
        self._setup_done = False
        self._setup_lock = threading.Lock()

    def _setup(self):
        """Configuration une seule fois (PRAGMA, foreign keys)."""
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
        """Récupère la connexion du thread courant (en crée une si besoin)."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                str(DB_PATH),
                timeout=10,
                isolation_level=None,  # autocommit
            )
            self._local.conn.row_factory = sqlite3.Row
            # PRAGMA par connexion
            self._local.conn.execute("PRAGMA foreign_keys = ON")
        return self._local.conn

    @contextmanager
    def cursor(self):
        """Context manager pour récupérer un curseur."""
        self._setup()
        conn = self._get_conn()
        cur = conn.cursor()
        try:
            yield cur
        finally:
            cur.close()

    def close(self):
        """Ferme la connexion du thread courant."""
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

    # ========================================================================
    # SIGNATURES (lecture)
    # ========================================================================
    def lookup_signature(self, source, rule_id):
        """
        Cherche une signature par source + id (rule_id Wazuh ou SID Snort).
        Retourne un dict ou None.
        """
        try:
            with self.cursor() as cur:
                cur.execute("""
                    SELECT s.id, s.uuid, s.name, s.description_fr, s.description_en,
                           s.source, s.severity, s.confidence, s.is_active, s.is_noisy,
                           s.is_critical_chain, s.category_id, s.technique_id,
                           s.remediation_fr, s.cve_ids
                    FROM signatures s
                    WHERE s.source = ? AND s.id = ?
                    LIMIT 1
                """, (source, rule_id))
                row = cur.fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"lookup_signature({source}, {rule_id}) : {e}")
            return None

    def get_signature_with_context(self, signature_id):
        """
        Récupère une signature avec sa catégorie et sa technique MITRE.
        Retourne un dict enrichi ou None.
        """
        try:
            with self.cursor() as cur:
                cur.execute("""
                    SELECT
                        s.id, s.uuid, s.name, s.description_fr, s.severity, s.confidence,
                        s.is_noisy, s.cve_ids, s.remediation_fr,
                        c.code as category_code, c.name_fr as category_name,
                        c.color_hex as category_color, c.icon as category_icon,
                        t.technique_id as mitre_technique_id,
                        t.name as mitre_technique_name,
                        t.description_fr as mitre_technique_desc,
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
        """
        Crée une signature 'inconnue' pour les events qui matchent rien.
        Utilise la catégorie 'CUSTOM' par défaut.
        Retourne l'id de la nouvelle signature.
        """
        try:
            with self.cursor() as cur:
                # Trouver category_id pour CUSTOM
                cur.execute("SELECT id FROM signature_categories WHERE code = 'CUSTOM' LIMIT 1")
                row = cur.fetchone()
                category_id = row[0] if row else 10  # fallback

                # uuid sera auto-généré par trigger
                cur.execute("""
                    INSERT INTO signatures (
                        id, uuid, name, description_fr, source, category_id,
                        severity, confidence, is_active, is_noisy
                    ) VALUES (?, ?, ?, ?, ?, ?, 'MEDIUM', 50, 1, 0)
                """, (
                    int(rule_id) if str(rule_id).isdigit() else None,
                    str(uuid.uuid4()),
                    name[:200] if name else f"Unknown {source}/{rule_id}",
                    description,
                    source,
                    category_id,
                ))
                return cur.lastrowid
        except sqlite3.IntegrityError:
            # Signature existe déjà, on la récupère
            return self.lookup_signature(source, rule_id)
        except Exception as e:
            logger.error(f"create_unknown_signature : {e}")
            return None

    # ========================================================================
    # ALERTS
    # ========================================================================
    def insert_alert(self, data):
        """
        Insère une nouvelle alerte.
        data doit contenir : signature_id, severity, title (NOT NULL)
        Champs optionnels : src_ip, dst_ip, src_port, dst_port, protocol,
                           asset_id, description, enriched_data
        Retourne l'id de la nouvelle alerte.
        """
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
                    alert_uuid,
                    data["signature_id"],
                    data["severity"],
                    data.get("confidence", 70),
                    data["title"][:500],
                    data.get("description"),
                    data.get("src_ip"),
                    data.get("dst_ip"),
                    data.get("src_port"),
                    data.get("dst_port"),
                    data.get("protocol"),
                    data.get("asset_id"),
                    data.get("first_seen", now),
                    data.get("last_seen", now),
                    json.dumps(data.get("enriched_data")) if data.get("enriched_data") else None,
                    data.get("ai_status", "not_required"),
                    now,
                    now,
                ))
                alert_id = cur.lastrowid
                logger.info(f"Alerte insérée #{alert_id} [{data['severity']}] {data['title'][:60]}")
                return alert_id
        except Exception as e:
            logger.error(f"insert_alert : {e}")
            return None

    def find_recent_similar_alert(self, signature_id, src_ip, window_minutes=5):
        """
        Cherche une alerte récente identique (même signature + même IP).
        Pour la déduplication (event_count++).
        """
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
        """Incrémente event_count + met à jour last_seen."""
        try:
            with self.cursor() as cur:
                cur.execute("""
                    UPDATE alerts
                    SET event_count = event_count + 1,
                        last_seen = ?,
                        updated_at = ?
                    WHERE id = ?
                """, (now_sqlite(),
                      now_sqlite(),
                      alert_id))
                return True
        except Exception as e:
            logger.error(f"increment_alert_count({alert_id}) : {e}")
            return False

    def update_alert_ai(self, alert_id, ai_data):
        """
        Met à jour les champs IA d'une alerte.
        ai_data : {ai_status, ai_description, ai_remediation, ai_model_used, ai_cache_id}
        """
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
                    now,
                    now,
                    alert_id,
                ))
                return True
        except Exception as e:
            logger.error(f"update_alert_ai : {e}")
            return False

    def get_alert_by_id(self, alert_id):
        """Récupère une alerte par son id."""
        try:
            with self.cursor() as cur:
                cur.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
                row = cur.fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"get_alert_by_id : {e}")
            return None

    # ========================================================================
    # ALERT FILTERS (Faux positifs)
    # ========================================================================
    def get_active_filters(self, signature_id, src_ip=None):
        """
        Récupère les filtres actifs qui pourraient matcher.
        Retourne une liste de filtres.
        """
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
        """Incrémente hit_count + last_hit_at d'un filtre."""
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
    # INCIDENTS (corrélation)
    # ========================================================================
    def count_recent_alerts_by_ip(self, src_ip, window_minutes=5):
        """Compte le TOTAL d'occurrences récentes depuis une IP source.
        Utilise SUM(event_count) pour tenir compte de la déduplication.
        Si la même alerte est dédupliquée 5 fois (event_count=5), elle compte pour 5."""
        try:
            with self.cursor() as cur:
                cur.execute("""
                    SELECT COALESCE(SUM(event_count), 0) FROM alerts
                    WHERE src_ip = ?
                    AND (
                        created_at >= datetime('now', ?)
                        OR last_seen >= datetime('now', ?)
                    )
                """, (src_ip, f"-{window_minutes} minutes", f"-{window_minutes} minutes"))
                return cur.fetchone()[0]
        except Exception as e:
            logger.error(f"count_recent_alerts_by_ip : {e}")
            return 0

    def create_incident(self, title, severity, description=None, alert_ids=None):
        """Crée un incident regroupant plusieurs alertes."""
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

                # Lier les alertes à l'incident
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
        """Récupère les alertes récentes d'une IP (pour corrélation)."""
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
    # BLOCKED IPS
    # ========================================================================
    def is_ip_blocked(self, ip_address):
        """Vérifie si une IP est déjà bloquée et active."""
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
        """
        Bloque une IP.
        duration_minutes : durée en minutes (0 = permanent).
        """
        try:
            now = now_sqlite()
            expires_at = None
            if duration_minutes > 0:
                expires_at = sqlite_future(duration_minutes)

            with self.cursor() as cur:
                cur.execute("""
                    INSERT INTO blocked_ips (
                        block_uuid, ip_address, reason, block_type,
                        blocked_at, expires_at, alert_id, is_active
                    ) VALUES (?, ?, ?, 'AUTO', ?, ?, ?, 1)
                """, (
                    str(uuid.uuid4()), ip_address, reason[:500],
                    now,
                    expires_at, alert_id,
                ))
                logger.info(f"IP bloquée : {ip_address} ({duration_minutes}min)")
                return cur.lastrowid
        except Exception as e:
            logger.error(f"insert_blocked_ip : {e}")
            return None

    def get_expired_blocks(self):
        """Récupère les IPs bloquées dont l'expiration est passée."""
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
        """Marque un blocage comme inactif (après déblocage iptables)."""
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
    # IP REPUTATION
    # ========================================================================
    def update_ip_reputation(self, ip_address, delta_score, source_seen="agent"):
        """
        Met à jour la réputation d'une IP. delta_score peut être négatif (alerte)
        ou positif (comportement normal).
        Score clampé entre 0 et 100.
        """
        try:
            now = now_sqlite()
            with self.cursor() as cur:
                # Tentative d'UPDATE
                cur.execute("""
                    UPDATE ip_reputation
                    SET reputation_score = MAX(0, MIN(100, reputation_score + ?)),
                        last_seen = ?,
                        times_seen = times_seen + 1
                    WHERE ip_address = ?
                """, (delta_score, now, ip_address))

                if cur.rowcount == 0:
                    # INSERT si pas trouvée
                    base_score = max(0, min(100, 50 + delta_score))
                    cur.execute("""
                        INSERT INTO ip_reputation (
                            ip_address, reputation_score, sources_seen,
                            times_seen, first_seen, last_seen
                        ) VALUES (?, ?, ?, 1, ?, ?)
                    """, (ip_address, base_score, source_seen, now, now))

                return True
        except sqlite3.OperationalError:
            # Table ip_reputation peut ne pas avoir tous les champs
            return False
        except Exception as e:
            logger.error(f"update_ip_reputation : {e}")
            return False

    def get_ip_reputation(self, ip_address):
        """Récupère le score de réputation d'une IP."""
        try:
            with self.cursor() as cur:
                cur.execute("""
                    SELECT reputation_score, times_seen, first_seen, last_seen
                    FROM ip_reputation WHERE ip_address = ?
                """, (ip_address,))
                row = cur.fetchone()
                return dict(row) if row else None
        except Exception as e:
            return None

    # ========================================================================
    # AI EXPLANATIONS (cache IA)
    # ========================================================================
    def get_ai_cache(self, signature_id, ai_model, ttl_hours=168):
        """
        Cherche une explication IA en cache pour cette signature.
        ttl_hours : durée de vie du cache (7 jours par défaut).
        """
        try:
            with self.cursor() as cur:
                cur.execute("""
                    SELECT id, explanation_fr, ai_model
                    FROM ai_explanations
                    WHERE signature_id = ? AND ai_model = ?
                    AND created_at >= datetime('now', ?)
                    ORDER BY cache_hits DESC, id DESC LIMIT 1
                """, (signature_id, ai_model, f"-{ttl_hours} hours"))
                row = cur.fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"get_ai_cache : {e}")
            return None

    def insert_ai_explanation(self, alert_id, signature_id, ai_model, explanation_fr,
                              prompt_used=None, generation_time_ms=None):
        """Insère une explication IA dans le cache."""
        try:
            now = now_sqlite()
            with self.cursor() as cur:
                cur.execute("""
                    INSERT INTO ai_explanations (
                        explanation_uuid, alert_id, signature_id,
                        explanation_fr, ai_provider, ai_model,
                        prompt_used, generation_time_ms, is_cached,
                        cache_hits, last_used_at, created_at
                    ) VALUES (?, ?, ?, ?, 'ollama', ?, ?, ?, 1, 0, ?, ?)
                """, (
                    str(uuid.uuid4()), alert_id, signature_id, explanation_fr,
                    ai_model, prompt_used, generation_time_ms, now, now,
                ))
                return cur.lastrowid
        except Exception as e:
            logger.error(f"insert_ai_explanation : {e}")
            return None

    def increment_ai_cache_hit(self, ai_cache_id):
        """Incrémente cache_hits + last_used_at."""
        try:
            with self.cursor() as cur:
                cur.execute("""
                    UPDATE ai_explanations
                    SET cache_hits = cache_hits + 1, last_used_at = ?
                    WHERE id = ?
                """, (now_sqlite(), ai_cache_id))
                return True
        except Exception:
            return False

    # ========================================================================
    # EMAIL LOGS
    # ========================================================================
    def insert_email_log(self, recipient, subject, status, alert_id=None,
                         error_message=None):
        """Trace un envoi d'email."""
        try:
            now = now_sqlite()
            with self.cursor() as cur:
                cur.execute("""
                    INSERT INTO email_logs (
                        recipient, subject, status, alert_id, error_message, sent_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, (recipient[:200], subject[:500], status, alert_id, error_message, now))
                return cur.lastrowid
        except Exception as e:
            logger.error(f"insert_email_log : {e}")
            return None

    def count_recent_emails(self, window_minutes=60):
        """Compte les emails envoyés dans la fenêtre (pour rate limit)."""
        try:
            with self.cursor() as cur:
                cur.execute("""
                    SELECT COUNT(*) FROM email_logs
                    WHERE sent_at >= datetime('now', ?)
                    AND status = 'sent'
                """, (f"-{window_minutes} minutes",))
                return cur.fetchone()[0]
        except Exception as e:
            return 0

    def email_already_sent(self, recipient, subject_pattern, window_minutes=5):
        """Vérifie si un email similaire a déjà été envoyé récemment (dedup)."""
        try:
            with self.cursor() as cur:
                cur.execute("""
                    SELECT COUNT(*) FROM email_logs
                    WHERE recipient = ? AND subject = ?
                    AND status = 'sent'
                    AND sent_at >= datetime('now', ?)
                """, (recipient, subject_pattern, f"-{window_minutes} minutes"))
                return cur.fetchone()[0] > 0
        except Exception:
            return False

    # ========================================================================
    # SETTINGS
    # ========================================================================
    def get_setting(self, key, default=None):
        """Récupère une valeur depuis la table settings."""
        try:
            with self.cursor() as cur:
                cur.execute("SELECT value, value_type FROM settings WHERE key = ?", (key,))
                row = cur.fetchone()
                if not row:
                    return default
                value, value_type = row["value"], row["value_type"]
                # Conversion selon le type
                if value_type == "bool":
                    return value.lower() in ("true", "1", "yes", "on")
                elif value_type == "int":
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
        """Récupère toutes les settings d'une catégorie."""
        try:
            with self.cursor() as cur:
                cur.execute("""
                    SELECT key, value, value_type FROM settings WHERE category = ?
                """, (category,))
                result = {}
                for row in cur.fetchall():
                    key, value, vtype = row["key"], row["value"], row["value_type"]
                    if vtype == "bool":
                        result[key] = value.lower() in ("true", "1", "yes", "on")
                    elif vtype == "int":
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
    # AUDIT LOG
    # ========================================================================
    def insert_audit(self, action, resource_type=None, resource_id=None,
                     details=None, user_id=None, ip_address=None):
        """Insère une entrée d'audit."""
        try:
            now = now_sqlite()
            with self.cursor() as cur:
                # Détecter colonnes disponibles dans audit_log
                cur.execute("PRAGMA table_info(audit_log)")
                cols = {r[1] for r in cur.fetchall()}

                # Construire INSERT selon colonnes disponibles
                fields = ["action", "created_at"]
                values = [action, now]
                placeholders = ["?", "?"]

                if "details" in cols:
                    fields.append("details")
                    values.append(json.dumps(details) if isinstance(details, dict) else details)
                    placeholders.append("?")
                if "resource_type" in cols and resource_type:
                    fields.append("resource_type")
                    values.append(resource_type)
                    placeholders.append("?")
                if "resource_id" in cols and resource_id is not None:
                    fields.append("resource_id")
                    values.append(str(resource_id))
                    placeholders.append("?")
                if "user_id" in cols and user_id:
                    fields.append("user_id")
                    values.append(user_id)
                    placeholders.append("?")
                if "ip_address" in cols and ip_address:
                    fields.append("ip_address")
                    values.append(ip_address)
                    placeholders.append("?")

                sql = f"INSERT INTO audit_log ({', '.join(fields)}) VALUES ({', '.join(placeholders)})"
                cur.execute(sql, values)
                return cur.lastrowid
        except Exception as e:
            logger.debug(f"insert_audit (non bloquant) : {e}")
            return None

    # ========================================================================
    # KPI HISTORY (Bloc 8)
    # ========================================================================
    def insert_kpi_snapshot(self, metrics):
        """Insère un snapshot de KPI. metrics est un dict {metric_name: (value, unit)}."""
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
        """Calcule les 18 KPI du jour."""
        try:
            with self.cursor() as cur:
                metrics = {}

                # Alertes
                cur.execute("SELECT COUNT(*) FROM alerts WHERE date(created_at) = date('now')")
                metrics["alerts_total"] = (cur.fetchone()[0], "count")

                for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                    cur.execute("""
                        SELECT COUNT(*) FROM alerts
                        WHERE date(created_at) = date('now') AND severity = ?
                    """, (sev,))
                    metrics[f"alerts_{sev.lower()}"] = (cur.fetchone()[0], "count")

                # Workflow
                cur.execute("""
                    SELECT COUNT(*) FROM alerts
                    WHERE date(created_at) = date('now') AND status = 'RESOLVED'
                """)
                metrics["alerts_resolved"] = (cur.fetchone()[0], "count")

                cur.execute("""
                    SELECT COUNT(*) FROM alerts
                    WHERE date(created_at) = date('now') AND status = 'FALSE_POSITIVE'
                """)
                metrics["alerts_false_positive"] = (cur.fetchone()[0], "count")

                # IPs bloquées
                cur.execute("SELECT COUNT(*) FROM blocked_ips WHERE date(blocked_at) = date('now')")
                metrics["ips_blocked_total"] = (cur.fetchone()[0], "count")

                cur.execute("SELECT COUNT(*) FROM blocked_ips WHERE is_active = 1")
                metrics["ips_blocked_active"] = (cur.fetchone()[0], "count")

                # IA
                cur.execute("""
                    SELECT COUNT(*) FROM ai_explanations
                    WHERE date(created_at) = date('now')
                """)
                metrics["ai_explanations"] = (cur.fetchone()[0], "count")

                cur.execute("""
                    SELECT COALESCE(SUM(cache_hits), 0) FROM ai_explanations
                """)
                metrics["ai_cache_hits"] = (cur.fetchone()[0], "count")

                # Utilisateurs actifs
                cur.execute("""
                    SELECT COUNT(*) FROM users WHERE is_active = 1
                """)
                metrics["active_users"] = (cur.fetchone()[0], "count")

                return metrics
        except Exception as e:
            logger.error(f"compute_daily_kpis : {e}")
            return {}


