"""SIEM Africa - Agent : Construit les prompts envoyes a Ollama."""

PROMPT_TEMPLATE = """Tu es un analyste cybersecurite expert. Une alerte de securite non repertoriee \
vient d'etre detectee sur un SIEM d'une PME africaine.

INFORMATIONS DE L'ALERTE :
- Source        : {source}
- Rule ID       : {rule_id}
- Niveau brut   : {raw_level}
- Message brut  : {raw_message}
- IP source     : {src_ip}
- IP destination: {dst_ip}

EN FRANCAIS, fournis EXACTEMENT cette structure JSON et RIEN D'AUTRE \
(pas de texte avant ou apres, pas de balises markdown) :

{{
  "description": "<2-3 phrases expliquant clairement l'attaque ou l'evenement, en francais>",
  "severity": "<INFO|LOW|MEDIUM|HIGH|CRITICAL>",
  "remediation": [
    "<recommandation 1, action concrete>",
    "<recommandation 2, action concrete>",
    "<recommandation 3, action concrete>"
  ],
  "mitre_tactic": "<TA0001..TA0043 si tu en deduis un, sinon null>",
  "mitre_technique": "<T1234 si tu en deduis un, sinon null>"
}}

Reponds UNIQUEMENT avec le JSON. Aucun texte autour."""


def build(source, rule_id, raw_level=None, raw_message=None,
          src_ip=None, dst_ip=None):
    """Construit le prompt a envoyer a Ollama."""
    return PROMPT_TEMPLATE.format(
        source=source,
        rule_id=rule_id,
        raw_level=raw_level if raw_level is not None else "?",
        raw_message=(raw_message or "(non disponible)")[:500],
        src_ip=src_ip or "?",
        dst_ip=dst_ip or "?",
    )
