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
        """Initialise le client Ollama de façon TOLÉRANTE.
        Découvre les settings IA peu importe les noms exacts utilisés par le M2."""
        ai_settings = self._discover_ai_settings()

        # Status enabled : variantes possibles
        enabled = self._first_value(ai_settings, [
            "ai_enabled", "ai.enabled", "ollama_enabled", "llm_enabled"
        ])
        # Si aucune clé enabled trouvée mais qu'on a un endpoint → on suppose enabled
        if enabled is None:
            has_config = self._first_value(ai_settings, [
                "ai_endpoint", "ai.endpoint", "ollama_endpoint", "ollama_url", "llm_endpoint"
            ])
            enabled = True if has_config else False
        else:
            if isinstance(enabled, str):
                enabled = enabled.lower() in ("true", "1", "yes", "on")

        if not enabled:
            logger.info("IA désactivée dans settings")
            return None

        endpoint = self._first_value(ai_settings, [
            "ai_endpoint", "ai.endpoint", "ollama_endpoint", "ollama_url",
            "llm_endpoint", "llm_url", "ai_url"
        ], default="http://localhost:11434")

        model = self._first_value(ai_settings, [
            "ai_default_model", "ai_model", "ai.default_model", "ai.model",
            "ollama_model", "ollama_default_model", "llm_model", "default_model"
        ], default="llama3.2:3b")

        try:
            temperature = float(self._first_value(ai_settings, [
                "ai_temperature", "ai.temperature", "ollama_temperature", "llm_temperature"
            ], default="0.3"))
        except (ValueError, TypeError):
            temperature = 0.3

        try:
            max_tokens = int(self._first_value(ai_settings, [
                "ai_max_tokens", "ai.max_tokens", "ollama_max_tokens", "llm_max_tokens",
                "max_tokens", "num_predict"
            ], default=300))
        except (ValueError, TypeError):
            max_tokens = 300

        try:
            timeout = int(self._first_value(ai_settings, [
                "ai_timeout_sec", "ai_timeout", "ai.timeout_sec", "ollama_timeout"
            ], default=60))
        except (ValueError, TypeError):
            timeout = 60

        logger.info(f"IA configurée : {endpoint} (model={model}, temp={temperature})")
        return OllamaClient(
            endpoint=endpoint, default_model=model,
            temperature=temperature, max_tokens=max_tokens, timeout=timeout,
        )

    def _discover_ai_settings(self):
        """Découvre les settings IA en BDD, sans dépendre de la colonne category."""
        all_settings = {}
        try:
            # D'abord par catégorie
            for cat_name in ("ai", "ollama", "llm"):
                try:
                    cat = self.db.get_settings_by_category(cat_name)
                    if cat:
                        all_settings.update(cat)
                except Exception:
                    pass

            # Scan par nom de clé
            with self.db.cursor() as cur:
                cur.execute("""
                    SELECT key, value, value_type FROM settings
                    WHERE LOWER(key) LIKE '%ai%'
                       OR LOWER(key) LIKE '%ollama%'
                       OR LOWER(key) LIKE '%llm%'
                       OR LOWER(key) LIKE '%model%'
                """)
                for row in cur.fetchall():
                    key, value, vtype = row["key"], row["value"], row["value_type"]
                    if key in all_settings:
                        continue
                    if value is None:
                        all_settings[key] = None
                        continue
                    if vtype in ("bool", "boolean"):
                        all_settings[key] = value.lower() in ("true", "1", "yes", "on")
                    elif vtype in ("int", "integer", "number"):
                        try:
                            all_settings[key] = int(value)
                        except (ValueError, TypeError):
                            all_settings[key] = 0
                    else:
                        all_settings[key] = value
        except Exception as e:
            logger.error(f"Erreur découverte settings IA : {e}")
        return all_settings

    @staticmethod
    def _first_value(settings, keys, default=None):
        """Cherche la première clé trouvée parmi les variantes."""
        for k in keys:
            for variant in (k, k.lower(), k.upper(), k.replace("_", "."), k.replace(".", "_")):
                if variant in settings and settings[variant] not in (None, ""):
                    return settings[variant]
        return default

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

        ai_settings = self._discover_ai_settings()
        model = self._first_value(ai_settings, [
            "ai_default_model", "ai_model", "ollama_model", "default_model"
        ], default="llama3.2:3b")
        try:
            cache_ttl = int(self._first_value(ai_settings, [
                "ai_cache_ttl_hours", "ai_cache_ttl", "ai.cache_ttl_hours"
            ], default=168))
        except (ValueError, TypeError):
            cache_ttl = 168

        cache_enabled = self._first_value(ai_settings, [
            "ai_cache_enabled", "ai.cache_enabled"
        ], default=True)
        if isinstance(cache_enabled, str):
            cache_enabled = cache_enabled.lower() in ("true", "1", "yes", "on")

        # 1. Vérifier cache
        source = event.get("source", "wazuh")
        rule_id = event.get("rule_id")
        if cache_enabled:
            cached = self.db.get_ai_cache(signature_id, model, ttl_hours=cache_ttl,
                                          source=source, rule_id=rule_id)
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
            source=source,
            rule_id=rule_id,
            remediation=parsed.get("recommandations"),
        )

        # 5. UPDATE alert
        self.db.update_alert_ai(alert_id, {
            "ai_status": "fresh",
            "ai_description": description_fr,
            "ai_remediation": parsed.get("recommandations"),
            "ai_model_used": model,
            "ai_cache_id": cache_id,
        })

        # 6. UPDATE signatures.description_fr / remediation_fr
        # Si la signature n'avait pas de description française (typiquement une
        # signature auto-créée), on la remplit pour que les futures requêtes
        # aient toujours une info en français disponible directement dans la table
        # signatures (pas seulement dans ai_signature_cache).
        # La méthode update_signature_description utilise COALESCE pour ne pas
        # écraser une description existante (les 380 signatures du M2 sont préservées).
        try:
            self.db.update_signature_description(
                signature_id=signature_id,
                description_fr=description_fr,
                remediation_fr=parsed.get("recommandations"),
            )
        except Exception as e:
            logger.debug(f"update_signature_description (non bloquant) : {e}")

        logger.info(f"Alerte #{alert_id} enrichie par IA ({model}, {elapsed_ms}ms)")
