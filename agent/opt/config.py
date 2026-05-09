"""SIEM Africa - Agent : Chargement de la configuration."""
import os
from pathlib import Path


def _load_env_file(path):
    """Charge un fichier KEY=VALUE dans os.environ s'il n'y est pas deja."""
    if not Path(path).is_file():
        return
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
    except Exception as exc:  # noqa: BLE001
        print(f"[config] Avertissement : impossible de lire {path} : {exc}")


# Charger la config principale
_load_env_file("/etc/siem-africa/agent.env")
# Charger SMTP (key=value separe pour des questions de permissions)
_load_env_file("/etc/siem-africa/smtp.env")


def get(key, default=None):
    return os.environ.get(key, default)


def get_bool(key, default=False):
    val = os.environ.get(key, str(default)).strip().lower()
    return val in ("true", "1", "yes", "on")


def get_int(key, default=0):
    try:
        return int(os.environ.get(key, default))
    except (TypeError, ValueError):
        return default


# Constantes pratiques
DB_PATH = get("DB_PATH", "/var/lib/siem-africa/siem.db")
LOG_DIR = get("LOG_DIR", "/var/log/siem-africa")
LOG_LEVEL = get("LOG_LEVEL", "INFO")

WAZUH_ALERTS_FILE = get("WAZUH_ALERTS_FILE", "/var/ossec/logs/alerts/alerts.json")
WAZUH_WATCHER_ENABLED = get_bool("WAZUH_WATCHER_ENABLED", True)

SNORT_ALERT_FILE = get("SNORT_ALERT_FILE", "/var/log/snort/alert")
SNORT_WATCHER_ENABLED = get_bool("SNORT_WATCHER_ENABLED", True)

OLLAMA_HOST = get("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_TIMEOUT = get_int("OLLAMA_TIMEOUT", 60)
OLLAMA_HEALTHCHECK_RETRIES = get_int("OLLAMA_HEALTHCHECK_RETRIES", 3)
OLLAMA_HEALTHCHECK_INTERVAL = get_int("OLLAMA_HEALTHCHECK_INTERVAL", 10)

SMTP_HOST = get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = get_int("SMTP_PORT", 587)
SMTP_USER = get("SMTP_USER", "")
SMTP_PASS = get("SMTP_PASS", "")
SMTP_FROM = get("SMTP_FROM", SMTP_USER)
SMTP_TO = get("SMTP_TO", SMTP_USER)
SMTP_USE_TLS = get_bool("SMTP_USE_TLS", True)

EMAIL_ENABLED = get_bool("EMAIL_ENABLED", True)
EMAIL_ALL_ALERTS = get_bool("EMAIL_ALL_ALERTS", True)

AI_DEGRADED_MODE_ALLOWED = get_bool("AI_DEGRADED_MODE_ALLOWED", True)
IP_BLOCK_ENABLED = get_bool("IP_BLOCK_ENABLED", False)
KPI_SNAPSHOT_ENABLED = get_bool("KPI_SNAPSHOT_ENABLED", True)
