"""
SIEM Africa - Agent (Module 3)
Configuration centralisée

Toutes les constantes de chemins et la lecture de l'agent.env.
Les paramètres dynamiques (SMTP, IA, seuils) sont lus depuis la table settings
de la base de données, pas ici.
"""
import os
from pathlib import Path

# ============================================================================
# CHEMINS SYSTEME
# ============================================================================
AGENT_DIR = Path("/opt/siem-africa-agent")
AGENT_ENV_FILE = Path("/etc/siem-africa/agent.env")

# Base de donnees (M2)
DB_PATH = Path("/var/lib/siem-africa/siem.db")

# Logs Wazuh
WAZUH_LOG = Path("/var/ossec/logs/alerts/alerts.json")

# Logs agent
LOG_DIR = Path("/var/log/siem-africa")
LOG_FILE = LOG_DIR / "agent.log"

# Backups BDD (bloc 8)
BACKUP_DIR = Path("/var/backups/siem-africa")

# Templates email (bloc 6)
TEMPLATES_DIR = AGENT_DIR / "notif" / "templates"


# ============================================================================
# UTILISATEUR ET GROUPE UNIX
# ============================================================================
AGENT_USER = "siem-agent"
SIEM_GROUP = "siem-africa"


# ============================================================================
# CONSTANTES METIER
# ============================================================================
# Sévérités valides (cohérent avec schema M2)
SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Niveaux de sévérité (ordre numérique pour comparaisons)
SEVERITY_LEVELS = {
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}

# Sources d'alertes valides
SOURCES = ["wazuh", "snort", "custom"]

# Statuts d'alertes
STATUSES = ["NEW", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE", "IGNORED"]

# Statuts IA
AI_STATUSES = ["not_required", "pending", "cached", "fresh", "failed", "disabled"]


# ============================================================================
# CONFIGURATION RUNTIME (lue depuis agent.env)
# ============================================================================
def load_env():
    """
    Charge les variables depuis /etc/siem-africa/agent.env.
    Retourne un dict avec les valeurs trouvées.
    Le fichier est créé par install_agent.sh.
    """
    env = {}
    if not AGENT_ENV_FILE.exists():
        return env

    try:
        with open(AGENT_ENV_FILE, "r") as f:
            for line in f:
                line = line.strip()
                # Skip commentaires et lignes vides
                if not line or line.startswith("#"):
                    continue
                # Parse KEY=value
                if "=" in line:
                    key, value = line.split("=", 1)
                    key = key.strip()
                    # Trim guillemets si présents
                    value = value.strip().strip('"').strip("'")
                    env[key] = value
    except Exception as e:
        # On laisse passer, le healthcheck remontera le problème
        pass

    return env


# Valeurs runtime (chargées au démarrage)
ENV = load_env()

# Niveau de log : DEBUG, INFO, WARNING, ERROR
LOG_LEVEL = ENV.get("LOG_LEVEL", "INFO")

# Intervalle de polling Wazuh en secondes (fallback si inotify échoue)
WAZUH_POLL_INTERVAL = int(ENV.get("WAZUH_POLL_INTERVAL", "5"))


# ============================================================================
# HELPERS
# ============================================================================
def severity_at_least(severity, minimum):
    """Retourne True si severity >= minimum dans l'ordre INFO < LOW < ... < CRITICAL."""
    if severity not in SEVERITY_LEVELS or minimum not in SEVERITY_LEVELS:
        return False
    return SEVERITY_LEVELS[severity] >= SEVERITY_LEVELS[minimum]
