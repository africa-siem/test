"""SIEM Africa - Agent : Parse la reponse JSON de l'IA."""
import json
import re


VALID_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


def parse(text):
    """Parse une reponse Ollama et retourne un dict normalise.

    Retourne dict ou leve ValueError.
    Le dict contient : description, severity, remediation (list str),
    mitre_tactic, mitre_technique.
    """
    if not text or not text.strip():
        raise ValueError("Reponse vide")

    # Nettoyer les eventuelles balises markdown
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)

    # Extraire le JSON s'il y a du texte autour
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if match:
        cleaned = match.group(0)

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise ValueError(f"JSON invalide : {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("Reponse n'est pas un objet JSON")

    description = (data.get("description") or "").strip()
    if not description:
        raise ValueError("Champ 'description' manquant")

    severity = (data.get("severity") or "").strip().upper()
    if severity not in VALID_SEVERITIES:
        # Defaut prudent
        severity = "MEDIUM"

    remediation = data.get("remediation") or []
    if not isinstance(remediation, list):
        if isinstance(remediation, str):
            remediation = [remediation]
        else:
            remediation = []

    # Nettoyage : on garde des strings non vides
    remediation = [str(r).strip() for r in remediation if r and str(r).strip()]
    if not remediation:
        remediation = ["Verifier l'alerte manuellement avec un analyste."]

    return {
        "description": description,
        "severity": severity,
        "remediation": remediation,
        "mitre_tactic": data.get("mitre_tactic") or None,
        "mitre_technique": data.get("mitre_technique") or None,
    }
