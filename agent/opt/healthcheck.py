"""
SIEM Africa - Agent (Module 3)
Healthcheck au démarrage

Vérifie que tous les composants externes sont accessibles AVANT que l'agent
ne commence à traiter des alertes. Si un composant non-critique échoue,
l'agent continue en mode dégradé. Si un composant critique échoue,
l'agent peut quand même tourner mais avec des warnings explicites.

Composants vérifiés :
- BDD SQLite accessible (lecture + écriture)
- Fichier alerts.json Wazuh lisible
- Connexion SMTP (optionnel, on ne bloque pas)
- Ollama répond (optionnel, mode dégradé OK)
"""
import sqlite3
import logging

from config import DB_PATH, WAZUH_LOG

logger = logging.getLogger(__name__)


def check_database():
    """Vérifie que la base SQLite est accessible en lecture+écriture.
    Compatible schéma M2 réel : audit_log.action_category NOT NULL."""
    if not DB_PATH.exists():
        logger.error(f"BDD introuvable : {DB_PATH}")
        return False

    try:
        conn = sqlite3.connect(str(DB_PATH), timeout=5)
        cursor = conn.cursor()

        # Vérifier qu'on peut lire
        cursor.execute("SELECT COUNT(*) FROM signatures LIMIT 1")
        nb = cursor.fetchone()[0]

        # Vérifier qu'on peut écrire (avec action_category NOT NULL)
        cursor.execute("""
            INSERT INTO audit_log (action, action_category)
            VALUES ('healthcheck', 'SYSTEM')
        """)
        conn.commit()
        conn.close()

        logger.info(f"DB OK ({nb} signatures en base)")
        return True
    except Exception as e:
        logger.error(f"BDD inaccessible : {e}")
        return False


def check_wazuh_log():
    """Vérifie que alerts.json existe et est lisible."""
    if not WAZUH_LOG.exists():
        logger.warning(f"Fichier Wazuh absent : {WAZUH_LOG}")
        logger.warning("Wazuh ne génère pas encore d'alertes ou pas installé")
        return False

    try:
        # Test de lecture
        with open(WAZUH_LOG, "r") as f:
            f.read(1)  # juste lire 1 octet
        logger.info(f"Wazuh log accessible : {WAZUH_LOG}")
        return True
    except PermissionError:
        logger.error(f"Permission denied sur {WAZUH_LOG} - "
                     f"siem-agent doit etre dans le groupe wazuh")
        return False
    except Exception as e:
        logger.error(f"Erreur lecture {WAZUH_LOG} : {e}")
        return False


def check_smtp_config():
    """
    Vérifie qu'une config SMTP minimale existe en BDD.
    Non bloquant : si pas de SMTP, l'agent fonctionne sans emails.
    """
    try:
        conn = sqlite3.connect(str(DB_PATH), timeout=5)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT key, value FROM settings
            WHERE category = 'smtp'
            AND key IN ('smtp_enabled', 'smtp_host', 'smtp_username',
                        'smtp_password', 'smtp_alert_recipients')
        """)
        rows = cursor.fetchall()
        conn.close()

        config = {key: value for key, value in rows}

        enabled = config.get("smtp_enabled", "false").lower() == "true"
        if not enabled:
            logger.info("SMTP désactivé dans settings")
            return False

        # Vérifier les champs critiques
        missing = []
        for key in ["smtp_host", "smtp_username", "smtp_password", "smtp_alert_recipients"]:
            if not config.get(key, "").strip():
                missing.append(key)

        if missing:
            logger.warning(f"Config SMTP incomplète - manquant : {', '.join(missing)}")
            logger.warning("Les emails seront désactivés tant que la config est incomplète")
            return False

        logger.info(f"SMTP OK ({config['smtp_host']})")
        return True
    except Exception as e:
        logger.warning(f"Impossible de lire la config SMTP : {e}")
        return False


def check_ollama():
    """
    Vérifie que l'API Ollama répond.
    Non bloquant : si Ollama down, l'agent continue sans IA.
    """
    try:
        # Lire la config IA depuis settings
        conn = sqlite3.connect(str(DB_PATH), timeout=5)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT key, value FROM settings
            WHERE key IN ('ai_enabled', 'ai_endpoint')
        """)
        rows = cursor.fetchall()
        conn.close()
        config = {key: value for key, value in rows}

        enabled = config.get("ai_enabled", "false").lower() == "true"
        if not enabled:
            logger.info("IA désactivée dans settings")
            return False

        endpoint = config.get("ai_endpoint", "http://localhost:11434")

        # Test API Ollama
        import urllib.request
        try:
            with urllib.request.urlopen(f"{endpoint}/api/tags", timeout=3) as resp:
                if resp.status == 200:
                    import json
                    data = json.loads(resp.read())
                    models = [m["name"] for m in data.get("models", [])]
                    logger.info(f"Ollama OK - {len(models)} modèles : {models}")
                    return True
        except Exception as e:
            logger.warning(f"Ollama injoignable ({endpoint}) : {e}")
            return False

    except Exception as e:
        logger.warning(f"Healthcheck Ollama échoué : {e}")
        return False


def run_healthcheck():
    """
    Lance tous les healthchecks et retourne un dict d'état.
    Logs en INFO si OK, WARNING ou ERROR sinon.
    """
    logger.info("===== HEALTHCHECK DÉMARRAGE =====")

    results = {
        "db": check_database(),
        "wazuh_log": check_wazuh_log(),
        "smtp": check_smtp_config(),
        "ollama": check_ollama(),
    }

    logger.info(f"Healthcheck : {results}")

    # La BDD est le seul composant vraiment critique
    if not results["db"]:
        logger.error("La BDD est inaccessible, l'agent ne peut pas fonctionner")
        return False, results

    if not results["wazuh_log"]:
        logger.warning("Wazuh log inaccessible, l'agent va tenter de l'ouvrir périodiquement")

    return True, results
