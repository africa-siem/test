from django.apps import AppConfig


class CoreConfig(AppConfig):
    default_auto_field = "django.db.models.AutoField"
    name = "core"

    def ready(self):
        # Active les pragmas SQLite (WAL + FK) a chaque connection
        from django.db.backends.signals import connection_created

        def set_sqlite_pragmas(sender, connection, **kwargs):
            if connection.vendor == "sqlite":
                cursor = connection.cursor()
                cursor.execute("PRAGMA foreign_keys = ON;")
                cursor.execute("PRAGMA journal_mode = WAL;")

        connection_created.connect(set_sqlite_pragmas)
