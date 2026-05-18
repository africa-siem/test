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


def _scan_settings(conn, patterns):
    """Helper : scanne settings et retourne dict {key: value} pour les clés matchant un pattern."""
    cursor = conn.cursor()
    where = " OR ".join([f"LOWER(key) LIKE '%{p}%'" for p in patterns])
    cursor.execute(f"SELECT key, value FROM settings WHERE {where}")
    return {k: v for k, v in cursor.fetchall()}


def _find_first(d, candidates):
    """Cherche la première clé trouvée dans d parmi candidates (avec variantes)."""
    for c in candidates:
        for variant in (c, c.lower(), c.upper(), c.replace("_", "."), c.replace(".", "_")):
            if variant in d and d[variant] not in (None, ""):
                return d[variant]
    return None


def check_smtp_config():
    """Vérifie que SMTP est configuré. Tolérant aux noms de clés (M2 peut nommer ses
    clés smtp_password, smtp.password, mail_password, etc.)."""
    try:
        conn = sqlite3.connect(str(DB_PATH), timeout=5)
        config = _scan_settings(conn, ["smtp", "mail", "email", "recipient"])
        conn.close()

        host = _find_first(config, ["smtp_host", "smtp.host", "mail_host", "smtp_server"])
        username = _find_first(config, ["smtp_username", "smtp.username", "smtp_user",
                                        "mail_username", "mail_user"])
        password = _find_first(config, ["smtp_password", "smtp.password", "smtp_pass",
                                        "mail_password"])
        recipients = _find_first(config, ["smtp_alert_recipients", "alert_recipients",
                                          "mail_recipients", "smtp_to", "admin_email",
                                          "notification_email"])

        enabled_raw = _find_first(config, ["smtp_enabled", "smtp.enabled", "mail_enabled"])
        if enabled_raw is None:
            # Si pas de clé enabled mais qu'on a host+user+pwd → on suppose enabled
            enabled = bool(host and username and password)
        else:
            enabled = str(enabled_raw).lower() in ("true", "1", "yes", "on")

        if not enabled:
            logger.info("SMTP désactivé dans settings")
            return False

        missing = [n for n, v in [("host", host), ("username", username),
                                  ("password", password)] if not v]
        if missing:
            logger.warning(f"Config SMTP incomplète, manquant : {missing}")
            logger.warning(f"Clés détectées en BDD : {sorted(config.keys())}")
            return False

        if not recipients:
            logger.warning("Aucun destinataire SMTP - fallback sur l'admin sera utilisé")

        logger.info(f"SMTP OK ({host})")
        return True
    except Exception as e:
        logger.warning(f"Impossible de lire la config SMTP : {e}")
        return False


def check_ollama():
    """Vérifie qu'Ollama répond. Tolérant aux noms de clés en BDD."""
    try:
        conn = sqlite3.connect(str(DB_PATH), timeout=5)
        config = _scan_settings(conn, ["ai", "ollama", "llm"])
        conn.close()

        enabled_raw = _find_first(config, ["ai_enabled", "ai.enabled", "ollama_enabled", "llm_enabled"])
        endpoint = _find_first(config, ["ai_endpoint", "ai.endpoint", "ollama_endpoint",
                                        "ollama_url", "llm_endpoint", "ai_url"])

        if enabled_raw is None:
            enabled = bool(endpoint)
        else:
            enabled = str(enabled_raw).lower() in ("true", "1", "yes", "on")

        if not enabled:
            logger.info("IA désactivée dans settings")
            return False

        if not endpoint:
            endpoint = "http://localhost:11434"
            logger.info(f"Endpoint IA non trouvé en BDD, utilisation par défaut : {endpoint}")

        import urllib.request, json
        try:
            with urllib.request.urlopen(f"{endpoint}/api/tags", timeout=3) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read())
                    models = [m["name"] for m in data.get("models", [])]
                    if not models:
                        logger.warning(f"Ollama OK mais AUCUN MODÈLE installé. "
                                       f"Lancer : ollama pull qwen2.5:3b")
                        return False
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
