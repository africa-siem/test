"""SIEM Africa - Agent : Snapshot des KPI (cron horaire).

Insere une ligne dans kpi_history par metrique configuree.
"""
import sys
from datetime import datetime
from pathlib import Path

# Ajouter le dossier parent au path pour pouvoir importer config et db
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import db
from logger import setup_logger


log = setup_logger("kpi.snapshot")


METRICS = [
    # nom               | requete SQL
    ("alerts_total_today",
     "SELECT COUNT(*) AS v FROM alerts WHERE date(created_at)=date('now')"),
    ("alerts_critical_today",
     "SELECT COUNT(*) AS v FROM alerts WHERE date(created_at)=date('now') AND severity='CRITICAL'"),
    ("alerts_high_today",
     "SELECT COUNT(*) AS v FROM alerts WHERE date(created_at)=date('now') AND severity='HIGH'"),
    ("alerts_resolved_today",
     "SELECT COUNT(*) AS v FROM alerts WHERE date(created_at)=date('now') AND status='RESOLVED'"),
    ("alerts_false_positive_today",
     "SELECT COUNT(*) AS v FROM alerts WHERE date(created_at)=date('now') AND status='FALSE_POSITIVE'"),
    ("alerts_total_week",
     "SELECT COUNT(*) AS v FROM alerts WHERE created_at >= date('now', '-7 days')"),
    ("alerts_total_month",
     "SELECT COUNT(*) AS v FROM alerts WHERE created_at >= date('now', '-30 days')"),
    ("ai_cache_total",
     "SELECT COUNT(*) AS v FROM ai_signature_cache"),
    ("ai_cache_hits_today",
     "SELECT COALESCE(SUM(used_count), 0) AS v FROM ai_signature_cache WHERE date(last_used_at)=date('now')"),
    ("signatures_total",
     "SELECT COUNT(*) AS v FROM signatures"),
    ("emails_sent_today",
     "SELECT COUNT(*) AS v FROM email_logs WHERE date(created_at)=date('now') AND status='sent'"),
    ("emails_failed_today",
     "SELECT COUNT(*) AS v FROM email_logs WHERE date(created_at)=date('now') AND status != 'sent'"),
    ("active_users",
     "SELECT COUNT(*) AS v FROM users WHERE is_active=1"),
    ("vulnerabilities_today",
     "SELECT COUNT(*) AS v FROM alerts WHERE date(created_at)=date('now') AND signature_id IN (SELECT id FROM signatures WHERE category_id IN (SELECT id FROM signature_categories WHERE name LIKE '%vuln%'))"),
]


def take_snapshot():
    """Calcule chaque metrique et l'insere dans kpi_history."""
    conn = db._get_conn()
    now_date = datetime.utcnow().strftime("%Y-%m-%d")
    inserted = 0

    for name, query in METRICS:
        try:
            row = conn.execute(query).fetchone()
            value = row["v"] if row else 0
            conn.execute(
                """
                INSERT INTO kpi_history (snapshot_date, metric_name, metric_value, country_id, created_at)
                VALUES (?, ?, ?, NULL, CURRENT_TIMESTAMP)
                """,
                (now_date, name, value),
            )
            inserted += 1
        except Exception as exc:  # noqa: BLE001
            log.warning(f"KPI {name} : {exc}")

    log.info(f"Snapshot KPI termine : {inserted} metriques inserees")
    return inserted


if __name__ == "__main__":
    take_snapshot()
