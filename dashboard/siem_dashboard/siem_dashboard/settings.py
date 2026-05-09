"""SIEM Africa Dashboard - settings.py

Config Django pour le dashboard (Module 4).
La BDD est celle du Module 2 (SQLite partagee /var/lib/siem-africa/siem.db).
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# ============================================================================
# Securite
# ============================================================================
SECRET_KEY = os.environ.get(
    "DJANGO_SECRET_KEY",
    "change-me-in-production-12345abcdef67890-replace-via-env-var"
)
DEBUG = os.environ.get("DJANGO_DEBUG", "false").lower() == "true"
ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "*").split(",")

# argon2id pour les passwords (recommandation OWASP)
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]

# ============================================================================
# Apps
# ============================================================================
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",

    # Apps SIEM Africa
    "core",
    "users",
    "alerts",
    "kpi",
    "health",
    "settings_app",
    "about",
    "admin_logs",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.locale.LocaleMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "core.middleware.ThemeMiddleware",
]

ROOT_URLCONF = "siem_dashboard.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "django.template.context_processors.i18n",
                "core.context_processors.dashboard_globals",
            ],
        },
    },
]

WSGI_APPLICATION = "siem_dashboard.wsgi.application"

# ============================================================================
# Base de donnees - pointe sur la BDD M2
# ============================================================================
DB_PATH = os.environ.get("SIEM_DB_PATH", "/var/lib/siem-africa/siem.db")

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": DB_PATH,
        "OPTIONS": {
            "timeout": 20,
        },
    }
}

# ============================================================================
# Auth - email-based
# ============================================================================
AUTH_USER_MODEL = "users.User"

AUTHENTICATION_BACKENDS = [
    "users.auth_backend.EmailBackend",
]

LOGIN_URL = "/login/"
LOGIN_REDIRECT_URL = "/alerts/"
LOGOUT_REDIRECT_URL = "/login/"

SESSION_COOKIE_AGE = 60 * 60 * 8  # 8 heures
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = not DEBUG

# ============================================================================
# i18n
# ============================================================================
LANGUAGE_CODE = "fr"

LANGUAGES = [
    ("fr", "Francais"),
    ("en", "English"),
]

LOCALE_PATHS = [BASE_DIR / "locale"]

TIME_ZONE = "Africa/Douala"
USE_I18N = True
USE_TZ = True

# ============================================================================
# Static
# ============================================================================
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]

DEFAULT_AUTO_FIELD = "django.db.models.AutoField"

# ============================================================================
# SIEM Africa specifique
# ============================================================================
SIEM_OLLAMA_HOST = os.environ.get("SIEM_OLLAMA_HOST", "http://127.0.0.1:11434")
SIEM_AGENT_LOG = os.environ.get("SIEM_AGENT_LOG", "/var/log/siem-africa/agent.log")
SIEM_WAZUH_ALERTS = os.environ.get("SIEM_WAZUH_ALERTS", "/var/ossec/logs/alerts/alerts.json")
SIEM_SMTP_CONFIG = os.environ.get("SIEM_SMTP_CONFIG", "/etc/siem-africa/smtp.env")

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{asctime} [{levelname}] {name} - {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "level": "INFO",
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
}
