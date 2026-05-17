"""
SIEM Africa - Agent (Module 3) - ai/ollama_client.py
Client HTTP pour Ollama.
"""
import time
import logging

logger = logging.getLogger(__name__)


class OllamaClient:
    """Client HTTP minimal pour Ollama API."""

    def __init__(self, endpoint, default_model, temperature=0.3,
                 max_tokens=300, timeout=60):
        self.endpoint = endpoint.rstrip("/")
        self.default_model = default_model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.consecutive_failures = 0

    def is_healthy(self):
        """Vérifie que l'API répond."""
        try:
            import requests
            r = requests.get(f"{self.endpoint}/api/tags", timeout=3)
            return r.status_code == 200
        except Exception:
            return False

    def generate(self, prompt, model=None):
        """
        Appelle Ollama /api/generate.
        Retourne (success: bool, response_text: str, elapsed_ms: int).
        """
        import requests
        model = model or self.default_model
        start = time.time()

        try:
            payload = {
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": self.temperature,
                    "num_predict": self.max_tokens,
                },
            }
            r = requests.post(
                f"{self.endpoint}/api/generate",
                json=payload,
                timeout=self.timeout,
            )
            elapsed_ms = int((time.time() - start) * 1000)

            if r.status_code != 200:
                self.consecutive_failures += 1
                logger.warning(f"Ollama HTTP {r.status_code} : {r.text[:200]}")
                return False, None, elapsed_ms

            data = r.json()
            response = data.get("response", "").strip()
            if not response:
                self.consecutive_failures += 1
                return False, None, elapsed_ms

            self.consecutive_failures = 0
            return True, response, elapsed_ms

        except Exception as e:
            self.consecutive_failures += 1
            elapsed_ms = int((time.time() - start) * 1000)
            logger.error(f"Ollama erreur : {e}")
            return False, None, elapsed_ms
