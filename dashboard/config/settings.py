"""
Configuration Django — Module 4 Dashboard SIEM Africa.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# --- Sécurité -----------------------------------------------------------------
# En production, la clé est lue depuis la variable d'environnement DJANGO_SECRET_KEY.
SECRET_KEY = os.environ.get(
    "DJANGO_SECRET_KEY",
    "dev-key-CHANGEZ-MOI-en-production-siem-africa",
)
DEBUG = os.environ.get("DJANGO_DEBUG", "true").lower() == "true"
ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "*").split(",")

# --- Applications -------------------------------------------------------------
INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "core",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.messages.context_processors.messages",
                "core.context_processors.dashboard_context",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

# --- Base de données ----------------------------------------------------------
# IMPORTANT : on pointe vers la base SQLite PARTAGÉE avec l'agent (Module 2/3).
# Le chemin par défaut correspond au déploiement sur la VM ; en développement
# on peut le surcharger via la variable d'environnement SIEM_DB_PATH.
SIEM_DB_PATH = os.environ.get(
    "SIEM_DB_PATH",
    "/var/lib/siem-africa/siem.db",
)

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": SIEM_DB_PATH,
        "OPTIONS": {
            # busy_timeout : attendre jusqu'à 5s si la base est verrouillée
            # par l'agent, plutôt que d'échouer immédiatement.
            "timeout": 5,
            "init_command": "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA synchronous=NORMAL;",
        },
    }
}

# Pas de base technique Django : on désactive les migrations sur la base partagée.
# Les sessions sont stockées côté serveur dans un cache fichier (voir plus bas).

# --- Sessions (sans table en base partagée) -----------------------------------
# On stocke les sessions Django dans des fichiers, pour ne créer AUCUNE table
# dans la base SQLite du Module 2.
SESSION_ENGINE = "django.contrib.sessions.backends.file"
SESSION_FILE_PATH = os.environ.get(
    "SIEM_SESSION_PATH",
    str(BASE_DIR / ".sessions"),
)
SESSION_COOKIE_NAME = "siem_session"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Strict"
SESSION_COOKIE_SECURE = os.environ.get("DJANGO_SECURE_COOKIES", "false").lower() == "true"
SESSION_EXPIRE_AT_BROWSER_CLOSE = False

# --- CSRF ---------------------------------------------------------------------
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = "Strict"

# --- Validation des mots de passe (la nôtre est dans core/auth.py) ------------
AUTH_PASSWORD_VALIDATORS = []

# --- Internationalisation -----------------------------------------------------
LANGUAGE_CODE = "fr"
TIME_ZONE = "Africa/Douala"
USE_I18N = True
USE_TZ = False

# --- Fichiers statiques -------------------------------------------------------
STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Crée le dossier de sessions s'il n'existe pas
os.makedirs(SESSION_FILE_PATH, exist_ok=True)
