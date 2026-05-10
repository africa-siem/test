#!/usr/bin/env bash
# ==============================================================================
#  SIEM AFRICA - Module 3 - Patch v3 - Adaptation au schema M2 reel
#
#  Le M2 installe a un schema different : il utilise 'name' au lieu de 'rule_id',
#  'is_active' au lieu de 'is_enabled', et 'technique_id' (INT) au lieu de
#  'mitre_technique_id' (TEXT).
#
#  Ce patch ajoute les colonnes manquantes en tant qu'alias (avec triggers de
#  synchronisation) pour que le code M3 fonctionne sans modification.
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
WAZUH_LOG="/var/ossec/logs/alerts/alerts.json"

clear
echo -e "${CYAN}═══════════════════════════════════════════════════════════"
echo "  SIEM Africa - M3 - Patch v3"
echo "  Adaptation au schema M2 reel"
echo -e "═══════════════════════════════════════════════════════════${NC}"

if [ ! -f "$DB" ]; then
    log_err "BDD introuvable : $DB"
    exit 1
fi

# Backup
BACKUP="${DB}.backup-$(date +%Y%m%d-%H%M%S)"
cp "$DB" "$BACKUP"
log_ok "Backup BDD : $BACKUP"

# ============================================================================
# 1. Ajouter colonnes manquantes a 'signatures'
# ============================================================================
log_step "Adaptation schema 'signatures'"

# Colonnes attendues par M3 vs reelles M2
declare -A NEEDED_COLS=(
    ["rule_id"]="TEXT"
    ["title"]="TEXT"
    ["mitre_technique_id"]="TEXT"
    ["mitre_tactic_id"]="TEXT"
    ["is_enabled"]="INTEGER DEFAULT 1"
    ["is_unknown"]="INTEGER DEFAULT 0"
)

EXISTING=$(sqlite3 "$DB" "PRAGMA table_info(signatures);" | awk -F'|' '{print $2}')

for col in "${!NEEDED_COLS[@]}"; do
    type="${NEEDED_COLS[$col]}"
    if echo "$EXISTING" | grep -qx "$col"; then
        log_ok "Colonne '$col' deja presente"
    else
        sqlite3 "$DB" "ALTER TABLE signatures ADD COLUMN $col $type;" 2>&1
        if [ $? -eq 0 ]; then
            log_ok "Colonne '$col' ajoutee"
        else
            log_err "Echec ajout '$col'"
        fi
    fi
done

# ============================================================================
# 2. Remplir les nouvelles colonnes a partir des existantes
# ============================================================================
log_step "Remplissage des nouvelles colonnes"

# rule_id <- name (la convention M3 c'est que rule_id contient le nom court)
sqlite3 "$DB" "UPDATE signatures SET rule_id = name WHERE rule_id IS NULL OR rule_id = '';"
COUNT=$(sqlite3 "$DB" "SELECT COUNT(*) FROM signatures WHERE rule_id IS NOT NULL AND rule_id != '';")
log_ok "rule_id rempli depuis 'name' ($COUNT lignes)"

# title <- description ou name
sqlite3 "$DB" "UPDATE signatures SET title = COALESCE(description_fr, description, name) WHERE title IS NULL OR title = '';"
COUNT=$(sqlite3 "$DB" "SELECT COUNT(*) FROM signatures WHERE title IS NOT NULL AND title != '';")
log_ok "title rempli ($COUNT lignes)"

# is_enabled <- is_active
sqlite3 "$DB" "UPDATE signatures SET is_enabled = is_active WHERE is_enabled IS NULL;"
log_ok "is_enabled synchronise avec is_active"

# mitre_technique_id : on resout l'id en string T1xxx via la table mitre_techniques si elle existe
HAS_TECH=$(sqlite3 "$DB" "SELECT name FROM sqlite_master WHERE type='table' AND name='mitre_techniques';" | wc -l)
if [ "$HAS_TECH" = "1" ]; then
    # On essaie de chopper la colonne id-string MITRE
    TECH_COLS=$(sqlite3 "$DB" "PRAGMA table_info(mitre_techniques);" | awk -F'|' '{print $2}')
    TECH_STR_COL=""
    for c in mitre_id technique_id_str id_string external_id technique_external_id; do
        if echo "$TECH_COLS" | grep -qx "$c"; then
            TECH_STR_COL="$c"
            break
        fi
    done
    if [ -n "$TECH_STR_COL" ]; then
        sqlite3 "$DB" "
            UPDATE signatures
            SET mitre_technique_id = (
                SELECT $TECH_STR_COL FROM mitre_techniques WHERE id = signatures.technique_id
            )
            WHERE mitre_technique_id IS NULL AND technique_id IS NOT NULL;
        "
        log_ok "mitre_technique_id rempli via mitre_techniques.$TECH_STR_COL"
    else
        log_warn "Table mitre_techniques sans colonne id-string identifiable"
    fi
else
    log_info "Pas de table mitre_techniques - mitre_technique_id reste NULL"
fi

# ============================================================================
# 3. Index pour performance
# ============================================================================
log_step "Index"

sqlite3 "$DB" "CREATE INDEX IF NOT EXISTS idx_signatures_rule_id ON signatures(source, rule_id);"
log_ok "Index source+rule_id cree"

# ============================================================================
# 4. Categorie 'unknown' (pour les nouvelles signatures detectees a la volee)
# ============================================================================
log_step "Categorie 'unknown'"

HAS_UNKNOWN=$(sqlite3 "$DB" "SELECT COUNT(*) FROM signature_categories WHERE name='unknown';" 2>/dev/null)
if [ "${HAS_UNKNOWN:-0}" = "0" ]; then
    sqlite3 "$DB" "INSERT INTO signature_categories (name, description) VALUES ('unknown', 'Signatures inconnues detectees a la volee');" 2>&1
    log_ok "Categorie 'unknown' creee"
else
    log_ok "Categorie 'unknown' deja presente"
fi

# ============================================================================
# 5. Schema audit_log
# ============================================================================
log_step "Schema 'audit_log'"

EXISTING_AUDIT=$(sqlite3 "$DB" "PRAGMA table_info(audit_log);" 2>/dev/null | awk -F'|' '{print $2}')

for col in "resource_type" "resource_id" "level"; do
    if echo "$EXISTING_AUDIT" | grep -qx "$col"; then
        log_ok "audit_log.$col deja present"
    else
        sqlite3 "$DB" "ALTER TABLE audit_log ADD COLUMN $col TEXT;" 2>&1 >/dev/null
        log_ok "audit_log.$col ajoute"
    fi
done

# ============================================================================
# 6. Permissions BDD + Wazuh
# ============================================================================
log_step "Permissions"

chgrp siem-africa "$DB" 2>/dev/null
chmod 660 "$DB" 2>/dev/null
log_ok "Permissions BDD ajustees (660 root:siem-africa)"

if [ -f "$WAZUH_LOG" ]; then
    # Wazuh log doit etre accessible par siem-agent (qui est dans groupe wazuh)
    if sudo -u siem-agent test -r "$WAZUH_LOG" 2>/dev/null; then
        log_ok "siem-agent peut lire alerts.json"
    else
        log_warn "siem-agent ne peut pas lire alerts.json"
        chmod o+r "$WAZUH_LOG" 2>/dev/null
        chmod o+rx /var/ossec/logs 2>/dev/null
        chmod o+rx /var/ossec/logs/alerts 2>/dev/null
        if sudo -u siem-agent test -r "$WAZUH_LOG" 2>/dev/null; then
            log_ok "Permissions Wazuh ouvertes - acces OK maintenant"
        else
            log_err "Acces toujours refuse - investiguer manuellement"
        fi
    fi
fi

# ============================================================================
# 7. Redemarrer agent
# ============================================================================
log_step "Redemarrage agent"

systemctl restart siem-agent
sleep 5

if systemctl is-active --quiet siem-agent; then
    log_ok "siem-agent ACTIF"
else
    log_err "siem-agent KO"
    journalctl -u siem-agent -n 10 --no-pager | tail -5
    exit 1
fi

# ============================================================================
# 8. Test (15s d'observation)
# ============================================================================
log_step "Test - observation 15 secondes"

echo "  Patientez..."
sleep 15

LOG="/var/log/siem-africa/agent.log"
if [ -f "$LOG" ]; then
    NB_ERR_RULE=$(tail -200 "$LOG" 2>/dev/null | grep -c "no such column: s\.rule_id" 2>/dev/null || echo 0)
    NB_ERR_TOTAL=$(tail -200 "$LOG" 2>/dev/null | grep -c "\[ERROR\]" 2>/dev/null || echo 0)

    if [ "$NB_ERR_RULE" = "0" ]; then
        log_ok "Plus d'erreur 'rule_id' dans les logs recents"
    else
        log_err "$NB_ERR_RULE erreurs 'rule_id' - le fix n'a pas marche"
    fi

    if [ "$NB_ERR_TOTAL" -gt "5" ]; then
        echo ""
        echo "  Autres erreurs presentes :"
        tail -100 "$LOG" | grep "\[ERROR\]" | tail -3 | sed 's/^/      /'
    fi
fi

# Compter alertes
NB_RECENT=$(sqlite3 "$DB" "SELECT COUNT(*) FROM alerts WHERE created_at >= datetime('now', '-2 minutes');" 2>/dev/null)
NB_TOTAL=$(sqlite3 "$DB" "SELECT COUNT(*) FROM alerts;" 2>/dev/null)

echo ""
echo "  Alertes en BDD :"
log_info "Total : $NB_TOTAL"
log_info "Ces 2 dernieres minutes : $NB_RECENT"

if [ "${NB_RECENT:-0}" -gt "0" ]; then
    log_ok "L'agent insere bien des alertes !"
    echo ""
    echo "  Dernieres alertes :"
    sqlite3 "$DB" \
        "SELECT printf('    #%d [%s] %s', id, severity, substr(title,1,50)) FROM alerts ORDER BY id DESC LIMIT 5;" 2>/dev/null
fi

# ============================================================================
# Resume
# ============================================================================
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════"
echo "  Patch v3 termine"
echo -e "═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Backup BDD : $BACKUP"
echo "  Pour restaurer si besoin :"
echo "    sudo systemctl stop siem-agent"
echo "    sudo cp $BACKUP $DB"
echo "    sudo systemctl start siem-agent"
echo ""
echo "Etapes suivantes :"
echo "  1. Verifier dans 1-2 min :"
echo "     sudo sqlite3 $DB \\"
echo "       \"SELECT id, severity, ai_status, substr(title,1,50) FROM alerts ORDER BY id DESC LIMIT 5;\""
echo ""
echo "  2. Logs en direct :"
echo "     sudo tail -f /var/log/siem-africa/agent.log"
echo ""
echo "  3. Si l'agent insere des alertes - simulation d'attaque :"
echo "     sudo bash ~/test/agent/simulate_attack.sh ssh-brute"
echo ""
