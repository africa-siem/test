"""
SIEM Africa - Agent (Module 3) - db/helpers.py
Helpers pour gérer les timestamps au format SQLite.
"""
from datetime import datetime, timedelta


def now_sqlite():
    """Retourne timestamp UTC au format SQLite 'YYYY-MM-DD HH:MM:SS'.
    Cohérent avec le format retourné par datetime('now') de SQLite."""
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def sqlite_future(minutes):
    """Retourne timestamp UTC futur au format SQLite."""
    return (datetime.utcnow() + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
