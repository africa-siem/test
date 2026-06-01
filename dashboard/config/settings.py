"""
Configuration Django — Module 4 Dashboard SIEM Africa.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# --- Sécurité -----------------------------------------------------------------
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
SIEM_DB_PATH = os.environ.get(
    "SIEM_DB_PATH",
    "/var/lib/siem-africa/siem.db",
)

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": SIEM_DB_PATH,
        "OPTIONS": {
            "timeout": 5,
            "init_command": "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA synchronous=NORMAL;",
        },
    }
}

# --- Sessions -----------------------------------------------------------------
SESSION_ENGINE = "django.contrib.sessions.backends.file"
SESSION_FILE_PATH = os.environ.get(
    "SIEM_SESSION_PATH",
    str(BASE_DIR / ".sessions"),
)
SESSION_COOKIE_NAME = "siem_session"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = os.environ.get("DJANGO_SECURE_COOKIES", "false").lower() == "true"
SESSION_EXPIRE_AT_BROWSER_CLOSE = False

# --- CSRF ---------------------------------------------------------------------
# CSRF_COOKIE_HTTPONLY = False obligatoire : True casse la validation derriere Nginx
CSRF_COOKIE_HTTPONLY = False
CSRF_COOKIE_SAMESITE = "Lax"

# CSRF_TRUSTED_ORIGINS obligatoire avec Django 4.x+ derriere un proxy
_trusted = os.environ.get("DJANGO_TRUSTED_ORIGINS", "")
if _trusted:
    CSRF_TRUSTED_ORIGINS = [o.strip() for o in _trusted.split(",") if o.strip()]
else:
    CSRF_TRUSTED_ORIGINS = ["http://*", "https://*"]

# --- Mots de passe ------------------------------------------------------------
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

# Créer le dossier sessions au démarrage (tolère l'absence de permissions)
try:
    os.makedirs(SESSION_FILE_PATH, exist_ok=True)
except PermissionError:
    pass
