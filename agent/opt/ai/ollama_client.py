"""SIEM Africa - Agent : Client HTTP pour Ollama."""
import time

import requests

import config
from logger import setup_logger


log = setup_logger("ai.ollama")


class OllamaError(Exception):
    pass


def is_available():
    """Verifie rapidement que Ollama repond (timeout court)."""
    try:
        resp = requests.get(f"{config.OLLAMA_HOST}/api/tags", timeout=3)
        return resp.status_code == 200
    except requests.exceptions.RequestException:
        return False


def list_models():
    try:
        resp = requests.get(f"{config.OLLAMA_HOST}/api/tags", timeout=5)
        if resp.status_code == 200:
            return [m.get("name") for m in resp.json().get("models", [])]
    except requests.exceptions.RequestException:
        pass
    return []


def generate(prompt, model="qwen2.5:3b", temperature=0.3, max_tokens=400):
    """Appelle Ollama en mode 'generate' (synchrone, JSON).

    Retourne (text, response_time_ms) ou leve OllamaError.
    """
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": float(temperature),
            "num_predict": int(max_tokens),
        },
    }

    t0 = time.time()
    try:
        resp = requests.post(
            f"{config.OLLAMA_HOST}/api/generate",
            json=payload,
            timeout=config.OLLAMA_TIMEOUT,
        )
    except requests.exceptions.Timeout as exc:
        raise OllamaError(f"Timeout ({config.OLLAMA_TIMEOUT}s) : {exc}") from exc
    except requests.exceptions.RequestException as exc:
        raise OllamaError(f"Erreur reseau : {exc}") from exc

    elapsed_ms = int((time.time() - t0) * 1000)

    if resp.status_code != 200:
        raise OllamaError(f"HTTP {resp.status_code} : {resp.text[:300]}")

    try:
        data = resp.json()
    except ValueError as exc:
        raise OllamaError(f"Reponse non-JSON : {exc}") from exc

    text = data.get("response", "")
    if not text:
        raise OllamaError("Reponse vide")

    log.debug(f"Ollama {model} : {elapsed_ms}ms - {len(text)} chars")
    return text, elapsed_ms
