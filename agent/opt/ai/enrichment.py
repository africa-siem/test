"""SIEM Africa - Agent : Orchestrateur d'enrichissement IA.

Workflow :
  1. Cherche dans signatures (BDD)
  2. Cherche dans le cache IA
  3. Appel Ollama (si disponible)
  4. Sauve dans le cache
  5. Retourne dict avec source ('database', 'ai_cache', 'ai_fresh', 'degraded', 'failed')
"""
import json

import db
from logger import setup_logger
from ai import ollama_client, prompt_builder, response_parser


log = setup_logger("ai.enrichment")


def enrich(source, rule_id, raw_message=None, raw_level=None,
           src_ip=None, dst_ip=None, force=False):
    """Renvoie un dict avec :
        - origin : 'database' | 'ai_cache' | 'ai_fresh' | 'degraded' | 'failed'
        - signature_id : id si trouvee en BDD, sinon None
        - description : str (toujours presente)
        - severity    : str
        - remediation : list[str] | None
        - model_used  : str | None
        - cache_id    : int | None
    """
    # 1. Cherche en BDD (sauf si on force la re-analyse)
    if not force:
        sig = db.find_signature(source, rule_id)
        if sig:
            log.debug(f"Signature {source}/{rule_id} trouvee en BDD ({sig['id']})")
            return {
                "origin": "database",
                "signature_id": sig["id"],
                "description": sig["description"] or sig["title"],
                "severity": sig["severity"],
                "remediation": _split_remediation(sig.get("remediation")),
                "model_used": None,
                "cache_id": None,
            }

    # 2. Cache IA
    sig_hash = db.signature_hash(source, rule_id, raw_message)

    if not force:
        cached = db.find_ai_cache(sig_hash)
        if cached:
            log.debug(f"Hit cache IA ({sig_hash[:12]}...) - {cached['model_used']}")
            return {
                "origin": "ai_cache",
                "signature_id": None,
                "description": cached["ai_description"],
                "severity": cached["ai_severity"],
                "remediation": _safe_json_list(cached.get("ai_remediation")),
                "model_used": cached["model_used"],
                "cache_id": cached["id"],
            }

    # 3. Appel Ollama (si disponible et autorise par settings)
    enabled = db.get_setting_bool("ai_enabled", True)
    enrich_unknown = db.get_setting_bool("ai_enrich_unknown", True)

    if not enabled or not enrich_unknown:
        log.info("Enrichissement IA desactive dans settings - mode degrade")
        return _degraded(source, rule_id, raw_message)

    if not ollama_client.is_available():
        log.warning("Ollama non disponible - mode degrade")
        return _degraded(source, rule_id, raw_message)

    model = db.get_setting("ai_default_model", "qwen2.5:3b")
    prompt = prompt_builder.build(source, rule_id, raw_level, raw_message, src_ip, dst_ip)

    try:
        text, elapsed_ms = ollama_client.generate(prompt, model=model)
    except ollama_client.OllamaError as exc:
        log.error(f"Ollama : {exc}")
        return _degraded(source, rule_id, raw_message, error=str(exc))

    try:
        parsed = response_parser.parse(text)
    except ValueError as exc:
        log.warning(f"Reponse IA non parseable ({model}) : {exc} - text: {text[:200]}")
        return _degraded(source, rule_id, raw_message, error=str(exc))

    # 4. Sauve dans le cache
    cache_id = None
    try:
        cache_id = db.save_ai_cache(
            sig_hash=sig_hash,
            source=source,
            rule_id=rule_id,
            raw_message=raw_message,
            description=parsed["description"],
            remediation_json=json.dumps(parsed["remediation"], ensure_ascii=False),
            severity=parsed["severity"],
            model_used=model,
            response_time_ms=elapsed_ms,
            mitre_tactic=parsed.get("mitre_tactic"),
            mitre_technique=parsed.get("mitre_technique"),
        )
        log.info(
            f"Cache IA sauve {source}/{rule_id} hash={sig_hash[:12]}... "
            f"model={model} {elapsed_ms}ms"
        )
    except Exception as exc:  # noqa: BLE001
        log.error(f"Echec sauvegarde cache IA : {exc}")

    return {
        "origin": "ai_fresh",
        "signature_id": None,
        "description": parsed["description"],
        "severity": parsed["severity"],
        "remediation": parsed["remediation"],
        "model_used": model,
        "cache_id": cache_id,
    }


def _degraded(source, rule_id, raw_message, error=None):
    """Mode degrade : pas d'IA, on retourne quand meme une description minimale."""
    desc = f"Alerte {source}/{rule_id} non repertoriee. Analyse IA indisponible."
    if error:
        desc += f" (Cause: {error[:120]})"
    return {
        "origin": "degraded",
        "signature_id": None,
        "description": desc,
        "severity": "MEDIUM",
        "remediation": [
            "Verifier manuellement le message brut.",
            "Verifier la disponibilite du service Ollama.",
        ],
        "model_used": None,
        "cache_id": None,
    }


def _split_remediation(text):
    """Une signature BDD peut avoir une remediation soit en JSON, soit en texte multiligne."""
    if not text:
        return None
    text = text.strip()
    if text.startswith("["):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
    # Sinon on split sur les retours a la ligne ou les puces
    lines = [l.strip(" -*\t") for l in text.splitlines() if l.strip()]
    return lines or [text]


def _safe_json_list(text):
    if not text:
        return None
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return data
        if isinstance(data, str):
            return [data]
    except (TypeError, json.JSONDecodeError):
        pass
    return [text] if isinstance(text, str) else None
