"""
SIEM Africa - Agent (Module 3) - ai/enricher.py
AIEnricher : thread asynchrone qui enrichit les alertes via Ollama.

Pour chaque alerte avec ai_status='pending' :
1. Vérifie cache ai_explanations (TTL configurable, défaut 7j)
2. Si cache hit → réutilise
3. Si cache miss → appel Ollama avec prompt structuré
4. Parsing JSON défensif
5. Insert dans cache + UPDATE alerts

Mode dégradé : si Ollama répond pas 3 fois → ai_status='failed', agent continue.
"""
import logging
import threading

from db import get_db
from ai.ollama_client import OllamaClient
from ai.parser import parse_ai_response
from ai.prompt import build_prompt

logger = logging.getLogger(__name__)


class AIEnricher(threading.Thread):
    """Thread qui enrichit les alertes via Ollama (asynchrone)."""

    def __init__(self, ai_queue, shutdown_event):
        super().__init__(name="AIEnricher", daemon=True)
        self.queue = ai_queue
        self.shutdown = shutdown_event
        self.db = get_db()
        self.client = None

    def _init_client(self):
        """Initialise le client Ollama depuis les settings."""
        ai_settings = self.db.get_settings_by_category("ai")
        if not ai_settings.get("ai_enabled"):
            return None

        endpoint = ai_settings.get("ai_endpoint", "http://localhost:11434")
        model = ai_settings.get("ai_default_model", "llama3.2:3b")
        try:
            temperature = float(ai_settings.get("ai_temperature", "0.3"))
        except (ValueError, TypeError):
            temperature = 0.3
        max_tokens = ai_settings.get("ai_max_tokens", 300)
        timeout = ai_settings.get("ai_timeout_sec", 60)

        return OllamaClient(
            endpoint=endpoint, default_model=model,
            temperature=temperature, max_tokens=max_tokens, timeout=timeout,
        )

    def run(self):
        logger.info("Démarrage AIEnricher")

        self.client = self._init_client()
        if not self.client:
            logger.warning("IA désactivée dans settings, AIEnricher en standby")
            while not self.shutdown.is_set():
                self.shutdown.wait(timeout=60)
                self.client = self._init_client()
                if self.client:
                    logger.info("IA activée dans settings, AIEnricher actif")
                    break
            else:
                return

        while not self.shutdown.is_set():
            try:
                try:
                    task = self.queue.get(timeout=2)
                except Exception:
                    continue

                if task is None:
                    continue

                self._enrich_alert(task)

            except Exception as e:
                logger.exception(f"Erreur boucle AIEnricher : {e}")

        logger.info("AIEnricher arrêté")

    def _enrich_alert(self, task):
        """Enrichit une alerte via Ollama."""
        alert_id = task["alert_id"]
        signature_id = task["signature_id"]
        event = task.get("event", {})

        ai_settings = self.db.get_settings_by_category("ai")
        model = ai_settings.get("ai_default_model", "llama3.2:3b")
        cache_ttl = ai_settings.get("ai_cache_ttl_hours", 168)

        # 1. Vérifier cache
        if ai_settings.get("ai_cache_enabled", True):
            cached = self.db.get_ai_cache(signature_id, model, ttl_hours=cache_ttl)
            if cached:
                logger.debug(f"Cache IA HIT pour alert #{alert_id}")
                self.db.update_alert_ai(alert_id, {
                    "ai_status": "cached",
                    "ai_description": cached["explanation_fr"],
                    "ai_model_used": cached["ai_model"],
                    "ai_cache_id": cached["id"],
                })
                self.db.increment_ai_cache_hit(cached["id"])
                return

        # 2. Cache miss → appel Ollama
        sig = self.db.get_signature_with_context(signature_id)
        signature_name = sig.get("name", "Unknown") if sig else "Unknown"
        mitre = sig.get("mitre_technique_id") if sig else None

        prompt = build_prompt(
            signature_name=signature_name,
            source=event.get("source", "wazuh"),
            src_ip=event.get("src_ip"),
            severity=event.get("severity", "MEDIUM"),
            description=event.get("description"),
            mitre_technique=mitre,
        )

        success, response, elapsed_ms = self.client.generate(prompt, model=model)

        if not success:
            self.db.update_alert_ai(alert_id, {
                "ai_status": "failed",
                "ai_model_used": model,
            })
            logger.warning(f"Enrichissement IA échoué pour alert #{alert_id}")

            if self.client.consecutive_failures >= 3:
                logger.error("Ollama indisponible (3 échecs consécutifs), mode dégradé")
            return

        # 3. Parser
        parsed = parse_ai_response(response)
        if not parsed:
            logger.warning(f"Réponse IA non parsable pour alert #{alert_id}")
            self.db.update_alert_ai(alert_id, {
                "ai_status": "failed",
                "ai_description": response[:500] if response else None,
                "ai_model_used": model,
            })
            return

        description_fr = parsed.get("description_fr", "").strip()
        if not description_fr:
            description_fr = response[:500]

        # 4. Insert dans cache
        cache_id = self.db.insert_ai_explanation(
            alert_id=alert_id,
            signature_id=signature_id,
            ai_model=model,
            explanation_fr=description_fr,
            prompt_used=prompt[:1000],
            generation_time_ms=elapsed_ms,
        )

        # 5. UPDATE alert
        self.db.update_alert_ai(alert_id, {
            "ai_status": "fresh",
            "ai_description": description_fr,
            "ai_remediation": parsed.get("recommandations"),
            "ai_model_used": model,
            "ai_cache_id": cache_id,
        })

        logger.info(f"Alerte #{alert_id} enrichie par IA ({model}, {elapsed_ms}ms)")
