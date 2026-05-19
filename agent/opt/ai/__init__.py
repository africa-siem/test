"""
SIEM Africa - Agent (Module 3) - Package db
Couche d'accès BDD - encapsule tous les appels SQLite.

Usage :
    from db import get_db
    db = get_db()
    db.insert_alert({...})
"""
from db.manager import DatabaseManager
from db.helpers import now_sqlite, sqlite_future


# Instance globale (singleton)
_db = None


def get_db():
    """Retourne le singleton DatabaseManager."""
    global _db
    if _db is None:
        _db = DatabaseManager()
    return _db


__all__ = ["DatabaseManager", "get_db", "now_sqlite", "sqlite_future"]
