"""
Logique de chat IA avec historique — SIEM Africa Dashboard.

Gère les conversations et messages stockés dans chat_conversations /
chat_messages (créées par chat_db.ensure_chat_tables). Permet de retrouver une
conversation existante pour une alerte/incident, d'y ajouter des messages, et
d'appeler Ollama pour la réponse de l'assistant.
"""
import uuid
from django.db import connection

from . import ollama_client


def _rows(sql, params=None):
    with connection.cursor() as cur:
        cur.execute(sql, params or [])
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]


def get_or_create_conversation(user_id, alert_id=None, incident_id=None, title=""):
    """Récupère la conversation existante pour cette alerte/incident et cet
    utilisateur, ou en crée une nouvelle."""
    if alert_id:
        existing = _rows(
            "SELECT * FROM chat_conversations WHERE user_id=%s AND alert_id=%s AND is_archived=0 LIMIT 1",
            [user_id, alert_id],
        )
    elif incident_id:
        existing = _rows(
            "SELECT * FROM chat_conversations WHERE user_id=%s AND incident_id=%s AND is_archived=0 LIMIT 1",
            [user_id, incident_id],
        )
    else:
        existing = []

    if existing:
        return existing[0]["id"]

    conv_uuid = str(uuid.uuid4())
    with connection.cursor() as cur:
        cur.execute(
            """INSERT INTO chat_conversations (conv_uuid, user_id, alert_id, incident_id, title)
               VALUES (%s, %s, %s, %s, %s)""",
            [conv_uuid, user_id, alert_id, incident_id, title],
        )
        return cur.lastrowid


def get_messages(conversation_id):
    return _rows(
        "SELECT role, content, created_at FROM chat_messages WHERE conversation_id=%s ORDER BY id ASC",
        [conversation_id],
    )


def add_message(conversation_id, role, content, model=None, gen_ms=0):
    with connection.cursor() as cur:
        cur.execute(
            """INSERT INTO chat_messages (conversation_id, role, content, model_used, generation_ms)
               VALUES (%s, %s, %s, %s, %s)""",
            [conversation_id, role, content, model, gen_ms],
        )
        cur.execute(
            "UPDATE chat_conversations SET updated_at=datetime('now') WHERE id=%s",
            [conversation_id],
        )


def send_user_message(conversation_id, user_text, alert_ctx=None, incident_ctx=None, lang="fr"):
    """Ajoute le message utilisateur, interroge Ollama, stocke la réponse.
    Retourne le texte de la réponse de l'assistant."""
    add_message(conversation_id, "user", user_text)

    # Reconstituer l'historique pour donner le fil à Ollama
    history = get_messages(conversation_id)
    messages = [{"role": m["role"], "content": m["content"]} for m in history]

    answer, model, gen_ms, ok = ollama_client.ask(
        messages, alert=alert_ctx, incident=incident_ctx, lang=lang
    )
    add_message(conversation_id, "assistant", answer, model=model, gen_ms=gen_ms)
    return answer, ok
