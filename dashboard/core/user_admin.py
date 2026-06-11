"""
Gestion administrative des utilisateurs — SIEM Africa Dashboard.

Seul un ADMIN peut créer/modifier/désactiver des comptes. Les nouveaux comptes
sont créés avec un mot de passe temporaire et must_change_pwd=1 (changement
forcé à la première connexion).
"""
import secrets
import string
import uuid
from datetime import datetime

from django.db import connection

from .auth import hash_password


def generate_temp_password(length=14):
    """Génère un mot de passe temporaire conforme à la politique
    (majuscule, minuscule, chiffre, caractère spécial)."""
    alphabet = string.ascii_letters + string.digits
    specials = "!@#$%&*?"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length - 2))
        pwd += secrets.choice(specials) + secrets.choice(string.digits)
        if (any(c.isupper() for c in pwd) and any(c.islower() for c in pwd)
                and any(c.isdigit() for c in pwd)):
            return pwd


def create_user(email, first_name, last_name, role_id, language="fr",
                phone=None, temp_password=None):
    """Crée un utilisateur. Retourne (user_id, temp_password) ou lève ValueError."""
    email = (email or "").strip().lower()
    if not email:
        raise ValueError("L'email est obligatoire.")

    # Vérifier l'unicité
    with connection.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM users WHERE email = %s", [email])
        if cur.fetchone()[0] > 0:
            raise ValueError("Un compte avec cet email existe déjà.")

    if not temp_password:
        temp_password = generate_temp_password()

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with connection.cursor() as cur:
        cur.execute(
            """INSERT INTO users (user_uuid, email, first_name, last_name, phone,
               password_hash, must_change_pwd, is_active, role_id, language,
               theme_preference, password_changed_at, created_at, updated_at)
               VALUES (%s, %s, %s, %s, %s, %s, 1, 1, %s, %s, 'light', %s, %s, %s)""",
            [str(uuid.uuid4()), email, first_name, last_name, phone,
             hash_password(temp_password), role_id, language, now, now, now],
        )
        return cur.lastrowid, temp_password


def set_user_active(user_id, active):
    with connection.cursor() as cur:
        cur.execute(
            "UPDATE users SET is_active = %s, updated_at = datetime('now') WHERE id = %s",
            [1 if active else 0, user_id],
        )


def unlock_user(user_id):
    """Déverrouille un compte bloqué (réinitialise le compteur d'échecs)."""
    with connection.cursor() as cur:
        cur.execute(
            """UPDATE users SET is_locked = 0, failed_login_count = 0,
               locked_until = NULL, updated_at = datetime('now') WHERE id = %s""",
            [user_id],
        )


def reset_password(user_id):
    """Réinitialise le mot de passe : génère un temporaire, force le changement.
    Retourne le mot de passe temporaire."""
    temp = generate_temp_password()
    with connection.cursor() as cur:
        cur.execute(
            """UPDATE users SET password_hash = %s, must_change_pwd = 1,
               is_locked = 0, failed_login_count = 0, locked_until = NULL,
               updated_at = datetime('now') WHERE id = %s""",
            [hash_password(temp), user_id],
        )
    return temp


def update_user_role(user_id, role_id):
    with connection.cursor() as cur:
        cur.execute(
            "UPDATE users SET role_id = %s, updated_at = datetime('now') WHERE id = %s",
            [role_id, user_id],
        )
