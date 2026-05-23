"""
Requêtes pour les alertes et incidents — SIEM Africa Dashboard.

Lecture seule, en SQL direct via le curseur Django (placeholders %s).
"""
import json
from django.db import connection


def _rows(sql, params=None):
    with connection.cursor() as cur:
        cur.execute(sql, params or [])
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]


def _one(sql, params=None):
    rows = _rows(sql, params)
    return rows[0] if rows else None


# --- Alertes ----------------------------------------------------------------
def list_alerts(severity=None, status=None, source=None, search=None,
                period_hours=None, page=1, per_page=25):
    """Liste paginée des alertes avec filtres. Retourne (rows, total)."""
    where = []
    params = []

    if severity:
        where.append("a.severity = %s")
        params.append(severity)
    if status:
        where.append("a.status = %s")
        params.append(status)
    if source:
        where.append("s.source = %s")
        params.append(source)
    if period_hours:
        where.append("a.created_at >= datetime('now', %s)")
        params.append(f"-{int(period_hours)} hours")
    if search:
        where.append("(a.title LIKE %s OR a.src_ip LIKE %s OR s.name LIKE %s)")
        like = f"%{search}%"
        params += [like, like, like]

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    # Total
    total = _rows(
        f"""SELECT COUNT(*) AS n FROM alerts a
            JOIN signatures s ON a.signature_id = s.id {where_sql}""",
        params,
    )[0]["n"]

    # Page
    offset = (page - 1) * per_page
    rows = _rows(
        f"""
        SELECT a.id, a.title, a.severity, a.src_ip, a.status, a.event_count,
               a.created_at, a.tags, a.incident_id,
               s.name AS sig_name, s.source AS source,
               r.country_code AS country_code
        FROM alerts a
        JOIN signatures s ON a.signature_id = s.id
        LEFT JOIN ip_reputation r ON a.src_ip = r.ip_address
        {where_sql}
        ORDER BY a.created_at DESC
        LIMIT %s OFFSET %s
        """,
        params + [per_page, offset],
    )
    # Parser les tags JSON
    for row in rows:
        try:
            row["tags_list"] = json.loads(row["tags"]) if row["tags"] else []
        except (ValueError, TypeError):
            row["tags_list"] = []
    return rows, total


def get_alert(alert_id):
    """Détail complet d'une alerte (jointures signature + MITRE + IP)."""
    alert = _one(
        """
        SELECT a.*, s.name AS sig_name, s.description_fr AS sig_desc_fr,
               s.remediation_fr AS sig_remediation_fr, s.source AS source,
               s.cve_ids AS cve_ids, s.references_url AS refs,
               s.technique_id AS technique_id,
               r.country_code AS country_code, r.country_name AS country_name,
               r.classification AS ip_classification
        FROM alerts a
        JOIN signatures s ON a.signature_id = s.id
        LEFT JOIN ip_reputation r ON a.src_ip = r.ip_address
        WHERE a.id = %s
        """,
        [alert_id],
    )
    if not alert:
        return None

    # Technique MITRE liée
    if alert.get("technique_id"):
        mitre = _one(
            """SELECT technique_id, name, COALESCE(description_fr, description) AS desc_fr
               FROM mitre_techniques WHERE id = %s""",
            [alert["technique_id"]],
        )
        alert["mitre"] = mitre

    # Tags
    try:
        alert["tags_list"] = json.loads(alert["tags"]) if alert["tags"] else []
    except (ValueError, TypeError):
        alert["tags_list"] = []

    # Recommandations : on découpe la remédiation en lignes
    rem = alert.get("sig_remediation_fr") or ""
    alert["recommendations"] = [l.strip() for l in rem.split("\n") if l.strip()]

    return alert


def related_alerts(src_ip, exclude_id, limit=5):
    """Autres alertes de la même IP source."""
    if not src_ip:
        return []
    return _rows(
        """
        SELECT a.id, a.title, a.severity, a.created_at
        FROM alerts a
        WHERE a.src_ip = %s AND a.id != %s
        ORDER BY a.created_at DESC LIMIT %s
        """,
        [src_ip, exclude_id, limit],
    )


def update_alert_status(alert_id, new_status, user=None, notes=None):
    """Met à jour le statut d'une alerte + trace dans l'audit."""
    with connection.cursor() as cur:
        if new_status in ("RESOLVED", "FALSE_POSITIVE"):
            cur.execute(
                """UPDATE alerts SET status=%s, resolved_at=datetime('now'),
                   resolution_notes=%s, updated_at=datetime('now') WHERE id=%s""",
                [new_status, notes or "", alert_id],
            )
        else:
            cur.execute(
                "UPDATE alerts SET status=%s, updated_at=datetime('now') WHERE id=%s",
                [new_status, alert_id],
            )
    _audit(user, f"alert_{new_status.lower()}", "alerts", alert_id)


# --- Incidents --------------------------------------------------------------
def list_incidents(status=None, severity=None, page=1, per_page=25):
    where, params = [], []
    if status:
        where.append("status = %s"); params.append(status)
    if severity:
        where.append("severity = %s"); params.append(severity)
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    total = _rows(f"SELECT COUNT(*) AS n FROM incidents {where_sql}", params)[0]["n"]
    offset = (page - 1) * per_page
    rows = _rows(
        f"""SELECT id, title, severity, status, alert_count, started_at, created_at
            FROM incidents {where_sql}
            ORDER BY created_at DESC LIMIT %s OFFSET %s""",
        params + [per_page, offset],
    )
    return rows, total


def get_incident(incident_id):
    incident = _one("SELECT * FROM incidents WHERE id = %s", [incident_id])
    if not incident:
        return None
    # Alertes corrélées à cet incident
    incident["alerts"] = _rows(
        """SELECT id, title, severity, src_ip, created_at
           FROM alerts WHERE incident_id = %s ORDER BY created_at DESC""",
        [incident_id],
    )
    return incident


# --- Audit ------------------------------------------------------------------
def _audit(user, action, table, target_id):
    try:
        with connection.cursor() as cur:
            cur.execute(
                """INSERT INTO audit_log (user_id, user_email, action, action_category,
                   target_table, target_id, status, performed_at)
                   VALUES (%s, %s, %s, %s, %s, %s, 'SUCCESS', datetime('now'))""",
                [
                    user.id if user else None,
                    user.email if user else None,
                    action,
                    action.split("_")[0],
                    table,
                    target_id,
                ],
            )
    except Exception:
        pass  # l'audit ne doit jamais bloquer l'action principale


# ============================================================================
# LOT 4 : IPs bloquées, Signatures, Utilisateurs
# ============================================================================

# --- IPs bloquées -----------------------------------------------------------
def list_blocked_ips(active_only=False, search=None, page=1, per_page=25):
    where, params = [], []
    if active_only:
        where.append("b.is_active = 1")
    if search:
        where.append("b.ip_address LIKE %s")
        params.append(f"%{search}%")
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    total = _rows(f"SELECT COUNT(*) AS n FROM blocked_ips b {where_sql}", params)[0]["n"]
    offset = (page - 1) * per_page
    rows = _rows(
        f"""
        SELECT b.id, b.ip_address, b.reason, b.blocked_at, b.expires_at,
               b.is_active, b.hit_count, b.block_type,
               r.country_code AS country_code, r.country_name AS country_name
        FROM blocked_ips b
        LEFT JOIN ip_reputation r ON b.ip_address = r.ip_address
        {where_sql}
        ORDER BY b.blocked_at DESC
        LIMIT %s OFFSET %s
        """,
        params + [per_page, offset],
    )
    return rows, total


def unblock_ip(block_id, user=None, reason="Déblocage manuel depuis le dashboard"):
    """Désactive un blocage IP (is_active=0) + trace l'action.
    Note : la suppression de la règle iptables est gérée par l'agent (M3) qui
    surveille la table ; le dashboard se contente de marquer le déblocage."""
    with connection.cursor() as cur:
        cur.execute(
            """UPDATE blocked_ips
               SET is_active = 0, unblock_at = datetime('now'),
                   unblocked_by = %s, unblock_reason = %s
               WHERE id = %s""",
            [user.id if user else None, reason, block_id],
        )
    _audit(user, "ip_unblock", "blocked_ips", block_id)


def block_ip_manual(ip, reason, user=None, hours=24):
    """Ajoute un blocage manuel. L'agent M3 appliquera la règle iptables."""
    import uuid as _uuid
    with connection.cursor() as cur:
        cur.execute(
            """INSERT INTO blocked_ips (block_uuid, ip_address, reason, block_type,
               blocked_at, expires_at, blocked_by, is_active)
               VALUES (%s, %s, %s, 'MANUAL', datetime('now'),
                       datetime('now', %s), %s, 1)""",
            [str(_uuid.uuid4()), ip, reason, f"+{int(hours)} hours",
             user.id if user else None],
        )
    _audit(user, "ip_block", "blocked_ips", None)


# --- Signatures -------------------------------------------------------------
def list_signatures(source=None, severity=None, category_id=None, search=None,
                    page=1, per_page=25):
    where, params = [], []
    if source:
        where.append("s.source = %s"); params.append(source)
    if severity:
        where.append("s.severity = %s"); params.append(severity)
    if category_id:
        where.append("s.category_id = %s"); params.append(category_id)
    if search:
        where.append("(s.name LIKE %s OR s.description_fr LIKE %s)")
        like = f"%{search}%"; params += [like, like]
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    total = _rows(f"SELECT COUNT(*) AS n FROM signatures s {where_sql}", params)[0]["n"]
    offset = (page - 1) * per_page
    rows = _rows(
        f"""
        SELECT s.id, s.name, s.severity, s.source, s.is_active, s.is_noisy,
               COALESCE(c.name_fr, c.name) AS category,
               (SELECT COUNT(*) FROM alerts a WHERE a.signature_id = s.id) AS hit_count
        FROM signatures s
        LEFT JOIN signature_categories c ON s.category_id = c.id
        {where_sql}
        ORDER BY hit_count DESC, s.name ASC
        LIMIT %s OFFSET %s
        """,
        params + [per_page, offset],
    )
    return rows, total


def get_signature(sig_id):
    sig = _one(
        """SELECT s.*, COALESCE(c.name_fr, c.name) AS category
           FROM signatures s
           LEFT JOIN signature_categories c ON s.category_id = c.id
           WHERE s.id = %s""",
        [sig_id],
    )
    if sig:
        sig["hit_count"] = _rows(
            "SELECT COUNT(*) AS n FROM alerts WHERE signature_id = %s", [sig_id]
        )[0]["n"]
    return sig


def signature_categories():
    return _rows("SELECT id, COALESCE(name_fr, name) AS name FROM signature_categories ORDER BY display_order")


# --- Utilisateurs -----------------------------------------------------------
def list_users():
    return _rows(
        """
        SELECT u.id, u.email, u.first_name, u.last_name, u.is_active, u.is_locked,
               u.last_login_at, u.language, r.code AS role_code, r.name AS role_name
        FROM users u
        JOIN roles r ON u.role_id = r.id
        ORDER BY u.created_at ASC
        """
    )


def get_user(user_id):
    return _one(
        """SELECT u.*, r.code AS role_code FROM users u
           JOIN roles r ON u.role_id = r.id WHERE u.id = %s""",
        [user_id],
    )


def all_roles():
    return _rows("SELECT id, code, name FROM roles ORDER BY id")
