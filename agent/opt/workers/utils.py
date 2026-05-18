"""
SIEM Africa - Agent (Module 3) - workers/utils.py
Helpers pour les workers cron.
"""
from datetime import datetime, timedelta


# ============================================================================
def seconds_until(hour, minute=0):
    """Calcule le nombre de secondes jusqu'à la prochaine HH:MM."""
    now = datetime.now()
    target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    delta = (target - now).total_seconds()
    return max(int(delta), 1)


# ============================================================================
# KPI SNAPSHOTTER (minuit)
