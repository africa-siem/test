"""
SIEM Africa - Agent (Module 3) - ai/parser.py
Parser défensif des réponses du LLM (3 stratégies).
"""
import json
import re


def parse_ai_response(response_text):
    """
    Essaie 3 stratégies pour parser la réponse JSON du LLM.
    Retourne un dict ou None.

    Stratégies :
    1. Parsing direct du texte complet
    2. Extraire le bloc ```json ... ```
    3. Trouver le premier {...} équilibré
    """
    if not response_text:
        return None

    # Stratégie 1 : parsing direct
    try:
        return json.loads(response_text)
    except json.JSONDecodeError:
        pass

    # Stratégie 2 : extraire le JSON entre ```json ... ```
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", response_text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # Stratégie 3 : trouver le premier { ... } équilibré
    start = response_text.find("{")
    if start >= 0:
        depth = 0
        for i in range(start, len(response_text)):
            if response_text[i] == "{":
                depth += 1
            elif response_text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(response_text[start:i+1])
                    except json.JSONDecodeError:
                        break

    return None
