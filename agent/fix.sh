#!/usr/bin/env bash
# ==============================================================================
#  SIEM AFRICA - Module 3 - Patch v4 (suite v3)
#
#  Le v3 a partiellement marche mais 2 problemes restent :
#    1. signatures.uuid + name sont NOT NULL -> les nouvelles signatures
#       creees par l'agent plantent
#    2. Le test verifiait les vieilles erreurs (faux positif)
#
#  Ce patch :
#    - Cree un trigger SQL qui auto-remplit uuid et name si non fournis
#    - Verifie les erreurs SEULEMENT depuis le dernier restart de l'agent
# ==============================================================================
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

log_step() { echo ""; echo -e "${CYAN}━━━ $* ━━━${NC}"; }
log_ok()   { echo -e "  ${GREEN}✓${NC} $*"; }
log_warn() { echo -e "  ${YELLOW}!${NC} $*"; }
log_err()  { echo -e "  ${RED}✗${NC} $*"; }
log_info() { echo "    $*"; }

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Doit etre execute en root (sudo)${NC}"
    exit 1
fi

DB="/var/lib/siem-africa/siem.db"

clear
echo -e "${CYAN}═══════════════════════════════════════════════════════════"
echo "  SIEM Africa - M3 - Patch v4 (auto-uuid + auto-name)"
echo -e "═══════════════════════════════════════════════════════════${NC}"

# Backup
BACKUP="${DB}.backup-$(date +%Y%m%d-%H%M%S)"
cp "$DB" "$BACKUP"
log_ok "Backup : $BACKUP"

# ============================================================================
# 1. Trigger pour auto-remplir uuid et name
# ============================================================================
log_step "Trigger auto-uuid + auto-name"

# Drop si existe deja
sqlite3 "$DB" "DROP TRIGGER IF EXISTS sig_auto_fill;" 2>&1
log_ok "Ancien trigger supprime (si present)"

# Verifier les colonnes NOT NULL pour adapter
NEEDED_COLS=$(sqlite3 "$DB" "PRAGMA table_info(signatures);" | awk -F'|' '$4 == "1" && $6 != "1" { print $2 }')
echo "  Colonnes NOT NULL detectees :"
echo "$NEEDED_COLS" | sed 's/^/    - /'

# Creer le trigger qui auto-remplit
sqlite3 "$DB" <<'SQL'
CREATE TRIGGER sig_auto_fill
BEFORE INSERT ON signatures
FOR EACH ROW
WHEN NEW.uuid IS NULL OR NEW.uuid = ''
   OR NEW.name IS NULL OR NEW.name = ''
BEGIN
    SELECT RAISE(IGNORE) WHERE 0;
END;
SQL

# Test : SQLite ne supporte pas SET dans BEFORE INSERT directement
# On va plutot patcher la table : faire en sorte que les colonnes acceptent NULL
# OU utiliser des defaults

# Strategie alternative : DROP/RECREATE la contrainte NOT NULL
# C'est compliqué en SQLite (pas d'ALTER MODIFY)
# Solution : on rend les colonnes nullables OU on patche le code Python

# Plus simple : creer un INSTEAD OF trigger sur une vue
# OU laisser SQLite trigger pour mettre des defaults

# Solution finale : trigger AFTER INSERT qui remet a jour uuid et name si vides
# Mais le INSERT plante avant le trigger AFTER

# Solution la plus propre : DEFAULT sur les colonnes
log_info "Strategie : ajouter DEFAULT (uuid/name auto-generes si non fournis)"

# Verifier si uuid/name sont NOT NULL
HAS_UUID_NN=$(sqlite3 "$DB" "PRAGMA table_info(signatures);" | awk -F'|' '$2 == "uuid" && $4 == "1"' | wc -l)
HAS_NAME_NN=$(sqlite3 "$DB" "PRAGMA table_info(signatures);" | awk -F'|' '$2 == "name" && $4 == "1"' | wc -l)

if [ "$HAS_UUID_NN" = "1" ] || [ "$HAS_NAME_NN" = "1" ]; then
    log_warn "Colonnes NOT NULL bloquantes - reconstruction de la table..."

    # Recreer signatures avec les memes colonnes mais sans NOT NULL sur uuid/name
    sqlite3 "$DB" <<'SQL'
BEGIN TRANSACTION;

-- 1. Renommer l'ancienne table
ALTER TABLE signatures RENAME TO signatures_old;

-- 2. Recreer avec uuid/name nullables et DEFAULT
CREATE TABLE signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT DEFAULT (lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' || substr(lower(hex(randomblob(2))),2) || '-' || substr('89ab',abs(random()) % 4 + 1, 1) || substr(lower(hex(randomblob(2))),2) || '-' || lower(hex(randomblob(6)))),
    name TEXT,
    description TEXT,
    description_fr TEXT,
    description_en TEXT,
    source TEXT NOT NULL,
    category_id INTEGER NOT NULL,
    technique_id INTEGER,
    severity TEXT NOT NULL,
    confidence INTEGER NOT NULL DEFAULT 70,
    is_active INTEGER NOT NULL DEFAULT 1,
    is_noisy INTEGER NOT NULL DEFAULT 0,
    is_critical_chain INTEGER NOT NULL DEFAULT 0,
    remediation TEXT,
    remediation_fr TEXT,
    references_url TEXT,
    cve_ids TEXT,
    metadata TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    rule_id TEXT,
    title TEXT,
    mitre_technique_id TEXT,
    mitre_tactic_id TEXT,
    is_enabled INTEGER DEFAULT 1,
    is_unknown INTEGER DEFAULT 0
);

-- 3. Copier les donnees
INSERT INTO signatures
SELECT * FROM signatures_old;

-- 4. Supprimer l'ancienne
DROP TABLE signatures_old;

-- 5. Recreer index
CREATE INDEX IF NOT EXISTS idx_signatures_rule_id ON signatures(source, rule_id);
CREATE INDEX IF NOT EXISTS idx_signatures_source ON signatures(source);

COMMIT;
SQL

    if [ $? -eq 0 ]; then
        log_ok "Table signatures reconstruite (uuid/name nullables)"
    else
        log_err "Echec reconstruction"
        log_info "Restauration depuis backup..."
        cp "$BACKUP" "$DB"
        exit 1
    fi
else
    log_ok "Colonnes uuid/name deja nullables"
fi

# ============================================================================
# 2. Trigger AFTER INSERT pour auto-remplir uuid + name si vides
# ============================================================================
log_step "Trigger auto-fill"

sqlite3 "$DB" "DROP TRIGGER IF EXISTS sig_auto_uuid;" 2>&1 >/dev/null
sqlite3 "$DB" "DROP TRIGGER IF EXISTS sig_auto_name;" 2>&1 >/dev/null

sqlite3 "$DB" <<'SQL'
CREATE TRIGGER sig_auto_uuid
AFTER INSERT ON signatures
WHEN NEW.uuid IS NULL OR NEW.uuid = ''
BEGIN
    UPDATE signatures
    SET uuid = lower(hex(randomblob(4))) || '-' ||
               lower(hex(randomblob(2))) || '-4' ||
               substr(lower(hex(randomblob(2))),2) || '-' ||
               substr('89ab',abs(random()) % 4 + 1, 1) ||
               substr(lower(hex(randomblob(2))),2) || '-' ||
               lower(hex(randomblob(6)))
    WHERE id = NEW.id;
END;

CREATE TRIGGER sig_auto_name
AFTER INSERT ON signatures
WHEN NEW.name IS NULL OR NEW.name = ''
BEGIN
    UPDATE signatures
    SET name = COALESCE(NEW.title, NEW.rule_id, 'unknown-' || NEW.id)
    WHERE id = NEW.id;
END;
SQL

log_ok "Triggers crees (uuid + name auto-remplis)"

# ============================================================================
# 3. Verifier que la categorie 'unknown' existe et est OK
# ============================================================================
log_step "Categorie unknown"

UNKNOWN_ID=$(sqlite3 "$DB" "SELECT id FROM signature_categories WHERE name='unknown' LIMIT 1;" 2>/dev/null)
if [ -z "$UNKNOWN_ID" ]; then
    sqlite3 "$DB" "INSERT INTO signature_categories (name, description) VALUES ('unknown', 'Signatures inconnues auto-creees');"
    UNKNOWN_ID=$(sqlite3 "$DB" "SELECT id FROM signature_categories WHERE name='unknown' LIMIT 1;")
    log_ok "Categorie 'unknown' creee (id=$UNKNOWN_ID)"
else
    log_ok "Categorie 'unknown' presente (id=$UNKNOWN_ID)"
fi

# ============================================================================
# 4. TEST : creer une signature unknown manuellement
# ============================================================================
log_step "Test : creation manuelle d'une signature unknown"

sqlite3 "$DB" "DELETE FROM signatures WHERE source='test_patch_v4';" 2>&1 >/dev/null

TEST_RC=$(sqlite3 "$DB" "
INSERT INTO signatures (source, rule_id, category_id, title, description, severity, confidence, is_enabled, is_unknown)
VALUES ('test_patch_v4', '99999', $UNKNOWN_ID, 'Test patch v4', 'Test creation auto', 'MEDIUM', 50, 1, 1);
" 2>&1)

if [ -z "$TEST_RC" ]; then
    log_ok "Insertion sans uuid/name : succes"

    # Verifier que les triggers ont rempli uuid et name
    AUTO_VALS=$(sqlite3 "$DB" "SELECT 'uuid=' || substr(uuid,1,15) || '... name=' || name FROM signatures WHERE source='test_patch_v4' LIMIT 1;")
    log_info "$AUTO_VALS"

    # Cleanup test
    sqlite3 "$DB" "DELETE FROM signatures WHERE source='test_patch_v4';" 2>&1 >/dev/null
    log_ok "Triggers fonctionnent - INSERT minimal accepte"
else
    log_err "Insertion test a echoue : $TEST_RC"
fi

# ============================================================================
# 5. Redemarrer agent et NOTER l'heure de redemarrage
# ============================================================================
log_step "Redemarrage agent"

systemctl restart siem-agent
RESTART_TIME=$(date '+%Y-%m-%d %H:%M:%S')
sleep 5

if systemctl is-active --quiet siem-agent; then
    log_ok "siem-agent ACTIF (redemarre a $RESTART_TIME)"
else
    log_err "siem-agent KO"
    journalctl -u siem-agent -n 10 --no-pager | tail -5
    exit 1
fi

# ============================================================================
# 6. Observation 30 secondes - SEULEMENT depuis le restart
# ============================================================================
log_step "Observation 30 secondes (logs depuis le restart)"

echo "  Patientez 30 secondes..."
sleep 30

LOG="/var/log/siem-africa/agent.log"

# Compter SEULEMENT les erreurs apres RESTART_TIME
NB_ERR_NEW=$(awk -v t="$RESTART_TIME" '$0 >= t && /\[ERROR\]/' "$LOG" 2>/dev/null | wc -l)
NB_ERR_RULE_NEW=$(awk -v t="$RESTART_TIME" '$0 >= t && /no such column: s\.rule_id/' "$LOG" 2>/dev/null | wc -l)
NB_ERR_UUID_NEW=$(awk -v t="$RESTART_TIME" '$0 >= t && /uuid/' "$LOG" 2>/dev/null | wc -l)

log_info "Erreurs depuis le restart ($RESTART_TIME) :"
log_info "  Total ERROR     : $NB_ERR_NEW"
log_info "  Erreurs rule_id : $NB_ERR_RULE_NEW"
log_info "  Erreurs uuid    : $NB_ERR_UUID_NEW"

if [ "$NB_ERR_RULE_NEW" = "0" ] && [ "$NB_ERR_UUID_NEW" = "0" ]; then
    log_ok "Aucune erreur bloquante depuis le restart"
elif [ "$NB_ERR_NEW" -gt "0" ]; then
    echo ""
    echo "  Dernieres erreurs :"
    awk -v t="$RESTART_TIME" '$0 >= t && /\[ERROR\]/' "$LOG" | tail -5 | sed 's/^/      /'
fi

# Compter alertes inserees
NB_ALERTS=$(sqlite3 "$DB" "SELECT COUNT(*) FROM alerts;" 2>/dev/null)
NB_NEW=$(sqlite3 "$DB" "SELECT COUNT(*) FROM alerts WHERE created_at >= '$RESTART_TIME';" 2>/dev/null)

echo ""
log_info "Alertes en BDD :"
log_info "  Total      : $NB_ALERTS"
log_info "  Depuis restart : $NB_NEW"

if [ "${NB_NEW:-0}" -gt "0" ]; then
    log_ok "🎉 L'agent INSERE BIEN DES ALERTES !"
    echo ""
    echo "  Dernieres alertes :"
    sqlite3 "$DB" "SELECT printf('    #%d [%s] %s', id, severity, substr(title,1,50)) FROM alerts ORDER BY id DESC LIMIT 5;" 2>/dev/null
fi

# ============================================================================
# Resume
# ============================================================================
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════"
echo "  Patch v4 termine"
echo -e "═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "Backup BDD : $BACKUP"
echo ""
echo "Si tout est OK, simuler une attaque :"
echo "  sudo bash ~/test/agent/simulate_attack.sh ssh-brute"
echo ""
echo "Si encore des erreurs, copier-coller les sortie au support."
echo ""
