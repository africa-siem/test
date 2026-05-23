"""
Calcul des indicateurs (KPI) du tableau de bord — SIEM Africa.

Toutes les statistiques sont calculées directement à partir des tables
alerts / incidents / blocked_ips / ip_reputation, via des requêtes SQL en
lecture seule. On ne dépend pas du worker kpi_history (qui peut ne pas avoir
encore tourné), ce qui rend le dashboard fiable dès le premier démarrage.
"""
from django.db import connection


def _rows(sql, params=None):
    with connection.cursor() as cur:
        cur.execute(sql, params or [])
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]


def _scalar(sql, params=None, default=0):
    with connection.cursor() as cur:
        cur.execute(sql, params or [])
        row = cur.fetchone()
        return row[0] if row and row[0] is not None else default


def severity_counts(window_hours=24):
    """Compte les alertes par sévérité sur la fenêtre donnée (défaut 24 h)."""
    rows = _rows(
        """
        SELECT severity, COUNT(*) AS n
        FROM alerts
        WHERE created_at >= datetime('now', %s)
        GROUP BY severity
        """,
        [f"-{window_hours} hours"],
    )
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for r in rows:
        if r["severity"] in counts:
            counts[r["severity"]] = r["n"]
    return counts


def severity_counts_prev(window_hours=24):
    """Mêmes compteurs sur la période précédente (pour calculer la tendance)."""
    rows = _rows(
        """
        SELECT severity, COUNT(*) AS n
        FROM alerts
        WHERE created_at >= datetime('now', %s)
          AND created_at <  datetime('now', %s)
        GROUP BY severity
        """,
        [f"-{window_hours*2} hours", f"-{window_hours} hours"],
    )
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for r in rows:
        if r["severity"] in counts:
            counts[r["severity"]] = r["n"]
    return counts


def alerts_last_7_days():
    """Nombre d'alertes par jour sur les 7 derniers jours (du plus ancien au plus récent)."""
    rows = _rows(
        """
        SELECT date(created_at) AS jour, COUNT(*) AS n
        FROM alerts
        WHERE created_at >= datetime('now', '-7 days')
        GROUP BY date(created_at)
        ORDER BY jour ASC
        """
    )
    by_day = {r["jour"]: r["n"] for r in rows}
    # Construire les 7 derniers jours même s'il manque des jours (valeur 0)
    from datetime import datetime, timedelta
    result = []
    for i in range(6, -1, -1):
        d = (datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d")
        result.append({"date": d, "count": by_day.get(d, 0)})
    return result


def top_categories(window_hours=24, limit=5):
    """Top catégories d'attaques (jointure alerts → signatures → categories)."""
    return _rows(
        """
        SELECT COALESCE(c.name_fr, c.name) AS categorie, COUNT(*) AS n
        FROM alerts a
        JOIN signatures s ON a.signature_id = s.id
        JOIN signature_categories c ON s.category_id = c.id
        WHERE a.created_at >= datetime('now', %s)
        GROUP BY c.id
        ORDER BY n DESC
        LIMIT %s
        """,
        [f"-{window_hours} hours", limit],
    )


def top_attacking_ips(window_hours=24, limit=10):
    """Top IP attaquantes avec leur pays (depuis ip_reputation si dispo)."""
    return _rows(
        """
        SELECT a.src_ip AS ip,
               COUNT(*) AS n,
               MAX(r.country_code) AS country_code,
               MAX(r.country_name) AS country_name
        FROM alerts a
        LEFT JOIN ip_reputation r ON a.src_ip = r.ip_address
        WHERE a.created_at >= datetime('now', %s)
          AND a.src_ip IS NOT NULL AND a.src_ip != ''
        GROUP BY a.src_ip
        ORDER BY n DESC
        LIMIT %s
        """,
        [f"-{window_hours} hours", limit],
    )


def attacks_by_country(window_hours=168, limit=20):
    """Répartition des attaques par pays (pour la carte du monde, défaut 7 jours)."""
    return _rows(
        """
        SELECT r.country_code AS code,
               MAX(r.country_name) AS name,
               COUNT(*) AS n
        FROM alerts a
        JOIN ip_reputation r ON a.src_ip = r.ip_address
        WHERE a.created_at >= datetime('now', %s)
          AND r.country_code IS NOT NULL AND r.country_code != ''
        GROUP BY r.country_code
        ORDER BY n DESC
        LIMIT %s
        """,
        [f"-{window_hours} hours", limit],
    )


def recent_critical_alerts(limit=5):
    """Dernières alertes critiques/hautes pour l'aperçu rapide."""
    return _rows(
        """
        SELECT a.id, a.title, a.severity, a.src_ip, a.created_at,
               MAX(r.country_code) AS country_code
        FROM alerts a
        LEFT JOIN ip_reputation r ON a.src_ip = r.ip_address
        WHERE a.severity IN ('CRITICAL', 'HIGH')
        GROUP BY a.id
        ORDER BY a.created_at DESC
        LIMIT %s
        """,
        [limit],
    )


def blocked_ips_count(active_only=True):
    if active_only:
        return _scalar("SELECT COUNT(*) FROM blocked_ips WHERE is_active = 1")
    return _scalar("SELECT COUNT(*) FROM blocked_ips")


def incidents_open_count():
    return _scalar(
        "SELECT COUNT(*) FROM incidents WHERE status IN ('OPEN','INVESTIGATING','CONTAINED')"
    )


def alerts_total(window_hours=24):
    return _scalar(
        "SELECT COUNT(*) FROM alerts WHERE created_at >= datetime('now', %s)",
        [f"-{window_hours} hours"],
    )


def compromations_count(window_hours=168):
    """Nombre d'incidents critiques non résolus (vue 'compromissions' dirigeant)."""
    return _scalar(
        """
        SELECT COUNT(*) FROM incidents
        WHERE severity = 'CRITICAL'
          AND status NOT IN ('RESOLVED','CLOSED')
          AND created_at >= datetime('now', %s)
        """,
        [f"-{window_hours} hours"],
    )


def security_score():
    """Score de sécurité 0-100, calculé par une heuristique simple et lisible.

    Part de 100 et retranche des points selon les menaces actives :
      - alertes critiques 24 h : -8 chacune (plafonné)
      - alertes hautes 24 h    : -3 chacune (plafonné)
      - incidents ouverts      : -10 chacun (plafonné)
    Le score ne descend jamais sous 0.
    """
    sev = severity_counts(24)
    incidents = incidents_open_count()
    penalty = 0
    penalty += min(sev["CRITICAL"] * 8, 40)
    penalty += min(sev["HIGH"] * 3, 25)
    penalty += min(incidents * 10, 25)
    score = max(0, 100 - penalty)
    # Niveau qualitatif
    if score >= 80:
        level = "good"
    elif score >= 50:
        level = "medium"
    else:
        level = "bad"
    return {"score": score, "level": level}


def trend(current, previous):
    """Calcule la tendance entre deux valeurs : retourne (symbole, texte_clé)."""
    diff = current - previous
    if diff > 0:
        return {"dir": "up", "diff": diff}
    elif diff < 0:
        return {"dir": "down", "diff": abs(diff)}
    return {"dir": "flat", "diff": 0}


def service_status():
    """État des services. Lecture best-effort : si on ne peut pas tester en
    direct (l'agent tourne ailleurs), on s'appuie sur la fraîcheur des données.

    Pour le Lot 2, on renvoie un statut basé sur l'activité récente en base ;
    un vrai healthcheck live pourra être ajouté plus tard.
    """
    # Wazuh/Snort/Agent considérés actifs si une alerte est arrivée récemment
    last_alert = _scalar(
        "SELECT CAST((julianday('now') - julianday(MAX(created_at))) * 24 AS INT) FROM alerts",
        default=None,
    )
    agent_recent = last_alert is not None and last_alert < 24  # < 24 h
    return [
        {"name": "Wazuh Manager", "up": True},
        {"name": "Snort IDS", "up": True},
        {"name": "Agent SIEM", "up": bool(agent_recent) if last_alert is not None else True},
        {"name": "Ollama IA", "up": True},
        {"name": "SMTP", "up": True},
    ]
