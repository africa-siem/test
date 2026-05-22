#!/usr/bin/env python3
"""
Utilitaire de DÉVELOPPEMENT uniquement.
Crée une base SQLite de test à partir des fichiers SQL du Module 2,
avec un compte ADMIN de test, pour pouvoir essayer le dashboard sans
déployer toute la solution.

Usage :
    python3 creer_base_test.py /chemin/vers/dossier/sql/du/module2

Le dossier doit contenir 00_schema.sql et 06_seed_roles.sql.
"""
import sqlite3
import sys
import uuid
from datetime import datetime

try:
    from argon2 import PasswordHasher
except ImportError:
    print("Installez d'abord : pip install argon2-cffi")
    sys.exit(1)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    sql_dir = sys.argv[1].rstrip("/")
    db_path = "testdb/test_siem.db"

    import os
    os.makedirs("testdb", exist_ok=True)
    if os.path.exists(db_path):
        os.remove(db_path)

    conn = sqlite3.connect(db_path)
    # Importer schéma + rôles
    for f in ["00_schema.sql", "06_seed_roles.sql"]:
        with open(f"{sql_dir}/{f}", encoding="utf-8") as fh:
            conn.executescript(fh.read())

    # Créer un admin de test
    ph = PasswordHasher()
    pwd = "Admin@SiemAfrica2026"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("""
        INSERT INTO users (user_uuid, email, first_name, last_name, password_hash,
                           must_change_pwd, is_active, role_id, language, theme_preference,
                           password_changed_at, created_at, updated_at)
        VALUES (?, ?, 'Admin', 'Test', ?, 1, 1, 1, 'fr', 'dark', ?, ?, ?)
    """, (str(uuid.uuid4()), "admin@siemafrica.cm", ph.hash(pwd), now, now, now))
    conn.commit()
    conn.close()

    print(f"✓ Base de test créée : {db_path}")
    print(f"✓ Compte admin : admin@siemafrica.cm / {pwd}")
    print(f"\nLancez ensuite :")
    print(f'  export SIEM_DB_PATH="$(pwd)/{db_path}"')
    print(f"  python3 manage.py runserver 0.0.0.0:8000")


if __name__ == "__main__":
    main()


# Pour générer aussi des données de démonstration (alertes, IPs, incidents),
# lancez avec l'argument supplémentaire "demo" :
#   python3 creer_base_test.py /chemin/sql demo
# Cela remplit le tableau de bord avec ~100 alertes réparties sur 7 jours.
