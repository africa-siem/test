"""
Tables de chat IA — création idempotente.

Conformément à la décision projet, les tables de conversation NE sont PAS
ajoutées aux fichiers SQL du Module 2. C'est le dashboard qui les crée, via
CREATE TABLE IF NOT EXISTS, directement dans la base partagée.

Avantages :
  - M2 reste intact (aucun fichier SQL modifié) ;
  - l'agent M3 n'est pas impacté (ajouter des tables ne gêne aucune requête
    existante) ;
  - idempotent : relancer la création ne casse rien.

Ces tables permettent un chat IA AVEC historique (niveau 2) : l'administrateur
peut rouvrir une conversation et la poursuivre, comme dans une messagerie.
"""
from django.db import connection

CREATE_CONVERSATIONS = """
CREATE TABLE IF NOT EXISTS chat_conversations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    conv_uuid     TEXT    NOT NULL UNIQUE,
    user_id       INTEGER NOT NULL,
    alert_id      INTEGER,
    incident_id   INTEGER,
    title         TEXT,
    created_at    TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_archived   INTEGER NOT NULL DEFAULT 0
);
"""

CREATE_MESSAGES = """
CREATE TABLE IF NOT EXISTS chat_messages (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id  INTEGER NOT NULL,
    role             TEXT    NOT NULL,
    content          TEXT    NOT NULL,
    model_used       TEXT,
    generation_ms    INTEGER,
    created_at       TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""

CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_chat_conv_user ON chat_conversations(user_id);",
    "CREATE INDEX IF NOT EXISTS idx_chat_conv_alert ON chat_conversations(alert_id);",
    "CREATE INDEX IF NOT EXISTS idx_chat_msg_conv ON chat_messages(conversation_id);",
]


def ensure_chat_tables():
    """Crée les tables de chat si elles n'existent pas. Sûr à appeler à chaque
    démarrage (idempotent)."""
    with connection.cursor() as cur:
        cur.execute(CREATE_CONVERSATIONS)
        cur.execute(CREATE_MESSAGES)
        for idx in CREATE_INDEXES:
            cur.execute(idx)
