"""SIEM Africa - Agent : Verifications au demarrage."""
import time

import requests

import config
import db
from logger import setup_logger


log = setup_logger("healthcheck")


def check_db():
    ok, msg = db.health_check()
    if ok:
        log.info("DB OK")
    else:
        log.error(f"DB KO : {msg}")
    return ok


def check_ollama():
    """Verifie que l'API Ollama repond. Retry selon config."""
    retries = config.OLLAMA_HEALTHCHECK_RETRIES
    interval = config.OLLAMA_HEALTHCHECK_INTERVAL

    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(f"{config.OLLAMA_HOST}/api/tags", timeout=10)
            if resp.status_code == 200:
                models = resp.json().get("models", [])
                names = [m.get("name", "?") for m in models]
                log.info(f"Ollama OK - {len(names)} modeles : {names}")
                return True, names
        except requests.exceptions.RequestException as exc:
            log.warning(f"Ollama tentative {attempt}/{retries} : {exc}")

        if attempt < retries:
            time.sleep(interval)

    log.error(
        f"Ollama KO apres {retries} tentatives. "
        f"L'agent continue en mode degrade (pas d'enrichissement IA)."
    )
    return False, []


def check_smtp_config():
    """Verifie que la config SMTP est presente (pas le test reel ici)."""
    if not config.EMAIL_ENABLED:
        log.info("Email desactive (EMAIL_ENABLED=false)")
        return False
    if not config.SMTP_USER or not config.SMTP_PASS:
        log.warning("Config SMTP incomplete - emails desactives")
        return False
    log.info(f"SMTP configure : {config.SMTP_HOST}:{config.SMTP_PORT}")
    return True


def run_all():
    """Lance tous les checks au demarrage. Retourne dict de resultats."""
    log.info("===== HEALTHCHECK DEMARRAGE =====")
    results = {
        "db": check_db(),
        "ollama": check_ollama()[0],
        "smtp": check_smtp_config(),
    }
    log.info(f"Healthcheck : {results}")

    # On loggue dans audit_log
    try:
        db.audit_log(
            action="agent_boot_healthcheck",
            resource_type="agent",
            details=results,
            level="INFO" if all(results.values()) else "WARN",
        )
    except Exception:  # noqa: BLE001
        pass

    return results


if __name__ == "__main__":
    run_all()
