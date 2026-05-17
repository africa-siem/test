"""
SIEM Africa - Agent (Module 3) - ai/prompt.py
Construction du prompt envoyé au LLM.
"""


def build_prompt(signature_name, source, src_ip=None, severity="MEDIUM",
                 description=None, mitre_technique=None):
    """Construit le prompt à envoyer à Ollama."""

    context = f"- Signature : {signature_name}\n"
    context += f"- Source : {source}\n"
    context += f"- Sévérité : {severity}\n"
    if src_ip:
        context += f"- IP source : {src_ip}\n"
    if mitre_technique:
        context += f"- MITRE : {mitre_technique}\n"
    if description:
        context += f"- Description originale : {description[:200]}\n"

    prompt = f"""Tu es un analyste cybersécurité expert pour PME africaine.
Analyse cette alerte de sécurité et produis UNIQUEMENT un JSON valide en français.

CONTEXTE :
{context}

Réponds UNIQUEMENT avec ce JSON (sans ```, sans texte autour) :
{{
  "description_fr": "Explication claire de l'attaque en 2-3 phrases pour un admin non-expert",
  "recommandations": ["action 1", "action 2", "action 3"]
}}"""

    return prompt
