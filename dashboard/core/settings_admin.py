"""
Gestion des paramètres et du journal d'audit — SIEM Africa Dashboard.

Lecture/écriture de la table settings (regroupée par catégorie pour les onglets)
et consultation de la table audit_log.
"""
from django.db import connection


def _rows(sql, params=None):
    with connection.cursor() as cur:
        cur.execute(sql, params or [])
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]


# --- Paramètres -------------------------------------------------------------
def get_settings_by_category():
    """Retourne les paramètres groupés par catégorie, pour les onglets."""
    rows = _rows(
        """SELECT key, value, value_type, enum_values, category,
                  COALESCE(description_fr, description) AS desc, is_sensitive, is_editable
           FROM settings WHERE deleted_at IS NULL ORDER BY category, key"""
    )
    grouped = {}
    for r in rows:
        grouped.setdefault(r["category"], []).append(r)
    return grouped


def update_settings(post_data, user=None):
    """Met à jour les paramètres modifiés. post_data : dict {key: value}.
    Ignore les valeurs secrètes laissées vides (pour ne pas écraser un mot de
    passe par du vide)."""
    updated = 0
    with connection.cursor() as cur:
        # Récupérer les types pour savoir lesquels sont secrets
        cur.execute("SELECT key, value_type, is_editable FROM settings WHERE deleted_at IS NULL")
        meta = {k: (vt, ed) for k, vt, ed in cur.fetchall()}

        for key, value in post_data.items():
            if not key.startswith("set__"):
                continue
            real_key = key[5:]
            if real_key not in meta:
                continue
            value_type, editable = meta[real_key]
            if not editable:
                continue
            # Ne pas écraser un secret laissé vide
            if value_type == "secret" and not value.strip():
                continue
            cur.execute(
                "UPDATE settings SET value=%s, updated_by=%s, updated_at=datetime('now') WHERE key=%s",
                [value, user.id if user else None, real_key],
            )
            updated += 1
    return updated


# --- Journal d'audit --------------------------------------------------------
def list_audit(action_category=None, user_email=None, page=1, per_page=50):
    where, params = [], []
    if action_category:
        where.append("action_category = %s"); params.append(action_category)
    if user_email:
        where.append("user_email LIKE %s"); params.append(f"%{user_email}%")
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    total = _rows(f"SELECT COUNT(*) AS n FROM audit_log {where_sql}", params)[0]["n"]
    offset = (page - 1) * per_page
    rows = _rows(
        f"""SELECT performed_at, user_email, action, action_category,
                   target_table, target_id, status
            FROM audit_log {where_sql}
            ORDER BY performed_at DESC LIMIT %s OFFSET %s""",
        params + [per_page, offset],
    )
    return rows, total


def audit_categories():
    return [r["action_category"] for r in _rows(
        "SELECT DISTINCT action_category FROM audit_log WHERE action_category IS NOT NULL ORDER BY action_category"
    )]
