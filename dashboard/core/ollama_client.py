"""
Client Ollama — chat IA contextuel pour le dashboard SIEM Africa.

Appelle l'API Ollama locale (http://localhost:11434) pour répondre aux
questions de l'administrateur sur une alerte ou un incident précis.

Principe de robustesse : si Ollama est indisponible (service arrêté, modèle
absent, timeout), on ne plante jamais le dashboard — on renvoie un message
clair indiquant que l'assistant IA est momentanément indisponible.

La configuration (endpoint, modèle, timeout) est lue depuis la table settings
du Module 2, avec des valeurs par défaut raisonnables.
"""
import json
import time
import urllib.request
import urllib.error

from .models import Setting

DEFAULT_ENDPOINT = "http://localhost:11434"
DEFAULT_MODEL = "qwen2.5:3b"
DEFAULT_TIMEOUT = 30


def _setting(key, default):
    try:
        s = Setting.objects.get(key=key)
        return s.value or default
    except Setting.DoesNotExist:
        return default


def get_config():
    return {
        "endpoint": _setting("ai_endpoint", DEFAULT_ENDPOINT).rstrip("/"),
        "model": _setting("ai_default_model", DEFAULT_MODEL),
        "timeout": int(_setting("ai_timeout_sec", str(DEFAULT_TIMEOUT)) or DEFAULT_TIMEOUT),
        "enabled": _setting("ai_enabled", "true").lower() in ("true", "1", "yes"),
    }


def build_context_prompt(alert=None, incident=None, lang="fr"):
    """Construit le contexte système décrivant l'alerte/incident à l'IA."""
    if alert:
        ctx = (
            f"Contexte de l'alerte de sécurité :\n"
            f"- Titre : {alert.get('title', '')}\n"
            f"- Sévérité : {alert.get('severity', '')}\n"
            f"- IP source : {alert.get('src_ip', 'inconnue')}\n"
            f"- Signature : {alert.get('sig_name', '')}\n"
            f"- Description : {alert.get('description', '')}\n"
        )
    elif incident:
        ctx = (
            f"Contexte de l'incident de sécurité :\n"
            f"- Titre : {incident.get('title', '')}\n"
            f"- Sévérité : {incident.get('severity', '')}\n"
            f"- Nombre d'alertes corrélées : {incident.get('alert_count', 0)}\n"
        )
    else:
        ctx = "Contexte général de cybersécurité pour une PME."

    lang_instr = (
        "Réponds en français, clairement, pour un administrateur de PME qui "
        "n'est pas forcément expert en cybersécurité."
        if lang == "fr"
        else "Answer in English, clearly, for an SME administrator who is not "
        "necessarily a cybersecurity expert."
    )
    return (
        f"Tu es un assistant cybersécurité pour la solution SIEM Africa. "
        f"{lang_instr}\n\n{ctx}"
    )


def ask(messages, alert=None, incident=None, lang="fr"):
    """Envoie une conversation à Ollama et retourne (texte, model, duree_ms, ok).

    `messages` est une liste [{"role": "user"/"assistant", "content": "..."}].
    On préfixe le contexte de l'alerte/incident comme message système.
    """
    cfg = get_config()
    if not cfg["enabled"]:
        return (
            "L'assistant IA est désactivé dans les paramètres."
            if lang == "fr" else "The AI assistant is disabled in settings.",
            None, 0, False,
        )

    system = build_context_prompt(alert, incident, lang)
    payload = {
        "model": cfg["model"],
        "messages": [{"role": "system", "content": system}] + messages,
        "stream": False,
    }
    data = json.dumps(payload).encode("utf-8")
    url = cfg["endpoint"] + "/api/chat"

    start = time.time()
    try:
        req = urllib.request.Request(url, data=data,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=cfg["timeout"]) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        elapsed = int((time.time() - start) * 1000)
        text = body.get("message", {}).get("content", "").strip()
        if not text:
            text = ("Je n'ai pas pu générer de réponse."
                    if lang == "fr" else "Could not generate an answer.")
        return text, cfg["model"], elapsed, True
    except (urllib.error.URLError, TimeoutError, OSError):
        msg = (
            "L'assistant IA est momentanément indisponible (le service Ollama "
            "ne répond pas). Réessayez dans un instant."
            if lang == "fr" else
            "The AI assistant is temporarily unavailable (Ollama is not "
            "responding). Please try again shortly."
        )
        return msg, None, 0, False
    except Exception:
        msg = ("Une erreur est survenue avec l'assistant IA."
               if lang == "fr" else "An error occurred with the AI assistant.")
        return msg, None, 0, False
