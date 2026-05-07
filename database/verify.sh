#!/bin/bash
# ============================================================================
# SIEM AFRICA - Module 2 : Vérification de l'installation
# ============================================================================
# Vérifie que tout est correctement installé après install_database.sh
# ============================================================================

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

DB_PATH="/var/lib/siem-africa/siem.db"
SIEM_GROUP="siem-africa"
SIEM_DB_USER="siem-db"

ERRORS=0
WARNINGS=0

check_ok() { echo -e "  ${GREEN}✓${NC} $*"; }
check_fail() { echo -e "  ${RED}✗${NC} $*"; ERRORS=$((ERRORS+1)); }
check_warn() { echo -e "  ${YELLOW}⚠${NC} $*"; WARNINGS=$((WARNINGS+1)); }

echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  SIEM AFRICA - Vérification Module 2 (BDD)${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"

# ----------------------------------------------------------------------------
# 1. Vérifications système
# ----------------------------------------------------------------------------
echo ""
echo "▶ Système"

# Groupe siem-africa
if getent group "$SIEM_GROUP" &>/dev/null; then
    check_ok "Groupe $SIEM_GROUP existe"
else
    check_fail "Groupe $SIEM_GROUP MANQUANT"
fi

# Utilisateur siem-db
if id "$SIEM_DB_USER" &>/dev/null; then
    check_ok "Utilisateur $SIEM_DB_USER existe"
    USER_GROUP=$(id -gn "$SIEM_DB_USER")
    if [ "$USER_GROUP" = "$SIEM_GROUP" ]; then
        check_ok "Groupe principal correct : $USER_GROUP"
    else
        check_warn "Groupe principal : $USER_GROUP (attendu : $SIEM_GROUP)"
    fi
else
    check_fail "Utilisateur $SIEM_DB_USER MANQUANT"
fi

# sqlite3 installé
if command -v sqlite3 >/dev/null 2>&1; then
    check_ok "sqlite3 disponible : $(sqlite3 --version | awk '{print $1}')"
else
    check_fail "sqlite3 MANQUANT"
fi

# argon2 installé
if command -v argon2 >/dev/null 2>&1; then
    check_ok "argon2 disponible"
else
    check_fail "argon2 MANQUANT"
fi

# msmtp installé (NOUVEAU)
if command -v msmtp >/dev/null 2>&1; then
    check_ok "msmtp disponible : $(msmtp --version 2>/dev/null | head -1 | awk '{print $2}' || echo '?')"
else
    check_fail "msmtp MANQUANT (configurer SMTP impossible)"
fi

# mailutils installé (NOUVEAU)
if command -v mail >/dev/null 2>&1; then
    check_ok "mail (mailutils) disponible"
else
    check_warn "mail MANQUANT (commande 'mail' non disponible)"
fi

# ----------------------------------------------------------------------------
# 2. Vérifications fichiers et permissions
# ----------------------------------------------------------------------------
echo ""
echo "▶ Fichiers et permissions"

if [ -f "$DB_PATH" ]; then
    check_ok "BDD existe : $DB_PATH"

    # Permissions
    PERMS=$(stat -c "%a" "$DB_PATH")
    if [ "$PERMS" = "660" ]; then
        check_ok "Permissions BDD : 660"
    else
        check_warn "Permissions BDD : $PERMS (attendu : 660)"
    fi

    # Propriétaire
    OWNER=$(stat -c "%U:%G" "$DB_PATH")
    if [ "$OWNER" = "${SIEM_DB_USER}:${SIEM_GROUP}" ]; then
        check_ok "Propriétaire : $OWNER"
    else
        check_warn "Propriétaire : $OWNER (attendu : ${SIEM_DB_USER}:${SIEM_GROUP})"
    fi

    # Taille
    SIZE=$(du -h "$DB_PATH" | cut -f1)
    check_ok "Taille BDD : $SIZE"
else
    check_fail "BDD MANQUANTE : $DB_PATH"
fi

# Dossiers
for d in /var/lib/siem-africa /var/log/siem-africa /etc/siem-africa; do
    if [ -d "$d" ]; then
        check_ok "Dossier $d existe"
    else
        check_fail "Dossier $d MANQUANT"
    fi
done

# Credentials
if [ -f /root/siem_credentials.txt ]; then
    if grep -q "MODULE 2" /root/siem_credentials.txt; then
        check_ok "Credentials Module 2 sauvegardés"
    else
        check_warn "Section Module 2 absente de /root/siem_credentials.txt"
    fi
else
    check_fail "/root/siem_credentials.txt MANQUANT"
fi

# msmtp.conf (NOUVEAU)
if [ -f /etc/siem-africa/msmtp.conf ]; then
    PERMS=$(stat -c "%a" /etc/siem-africa/msmtp.conf)
    if [ "$PERMS" = "640" ]; then
        check_ok "msmtp.conf (permissions 640)"
    else
        check_warn "msmtp.conf permissions : $PERMS (attendu 640)"
    fi

    if grep -q "^account siem-africa" /etc/siem-africa/msmtp.conf 2>/dev/null; then
        check_ok "msmtp configuré (compte siem-africa actif)"
    else
        check_warn "msmtp non configuré (lancer ./configure_smtp.sh)"
    fi
else
    check_fail "msmtp.conf MANQUANT"
fi

# ----------------------------------------------------------------------------
# 3. Vérifications BDD : structure
# ----------------------------------------------------------------------------
echo ""
echo "▶ Structure BDD"

if [ -f "$DB_PATH" ]; then
    # Mode WAL
    JOURNAL_MODE=$(sqlite3 "$DB_PATH" "PRAGMA journal_mode")
    if [ "$JOURNAL_MODE" = "wal" ]; then
        check_ok "Mode journal : wal"
    else
        check_warn "Mode journal : $JOURNAL_MODE (attendu : wal)"
    fi

    # Tables
    N_TABLES=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    if [ "$N_TABLES" -ge 24 ]; then
        check_ok "Tables : $N_TABLES (≥ 24)"
    else
        check_fail "Tables : $N_TABLES (attendu ≥ 24)"
    fi

    # Vues
    N_VIEWS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM sqlite_master WHERE type='view'")
    if [ "$N_VIEWS" -ge 4 ]; then
        check_ok "Vues : $N_VIEWS (≥ 4)"
    else
        check_warn "Vues : $N_VIEWS (attendu ≥ 4)"
    fi

    # Triggers
    N_TRIG=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger'")
    if [ "$N_TRIG" -ge 9 ]; then
        check_ok "Triggers : $N_TRIG (≥ 9)"
    else
        check_warn "Triggers : $N_TRIG (attendu ≥ 9)"
    fi

    # Index
    N_IDX=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'")
    if [ "$N_IDX" -ge 80 ]; then
        check_ok "Index : $N_IDX (≥ 80)"
    else
        check_warn "Index : $N_IDX (attendu ≥ 80)"
    fi
fi

# ----------------------------------------------------------------------------
# 4. Vérifications BDD : données
# ----------------------------------------------------------------------------
echo ""
echo "▶ Données"

if [ -f "$DB_PATH" ]; then

    check_count() {
        local table="$1"
        local expected="$2"
        local label="$3"
        local count=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM ${table}" 2>/dev/null)
        if [ "$count" = "$expected" ]; then
            check_ok "$label : $count"
        elif [ -z "$count" ]; then
            check_fail "$label : table inexistante"
        else
            check_warn "$label : $count (attendu : $expected)"
        fi
    }

    check_count "mitre_tactics"          "14"  "MITRE Tactics"
    check_count "mitre_techniques"       "137" "MITRE Techniques"
    check_count "signature_categories"   "10"  "Catégories"
    check_count "roles"                  "4"   "Rôles RBAC"
    check_count "alert_filters"          "8"   "Filtres FP"
    check_count "countries"              "4"   "Pays Afrique Centrale"

    N_SIGS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signatures")
    if [ "$N_SIGS" = "380" ]; then
        check_ok "Signatures total : 380"
    else
        check_warn "Signatures : $N_SIGS (attendu : 380)"
    fi

    N_WAZUH=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signatures WHERE source='wazuh'")
    N_SNORT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signatures WHERE source='snort'")
    [ "$N_WAZUH" = "190" ] && check_ok "  └ Wazuh : 190" || check_warn "  └ Wazuh : $N_WAZUH (attendu 190)"
    [ "$N_SNORT" = "190" ] && check_ok "  └ Snort : 190" || check_warn "  └ Snort : $N_SNORT (attendu 190)"

    # Settings essentiels
    AI_MODELS=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='ai_models_available'")
    if [[ "$AI_MODELS" == *"llama3.2"* ]] && [[ "$AI_MODELS" == *"qwen"* ]]; then
        check_ok "Multi-modèles IA : $AI_MODELS"
    else
        check_warn "Setting ai_models_available : $AI_MODELS"
    fi

    THEME=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='theme_default'")
    check_ok "Thème par défaut : $THEME"
fi

# ----------------------------------------------------------------------------
# 5. Vérifications utilisateur admin
# ----------------------------------------------------------------------------
echo ""
echo "▶ Compte admin"

if [ -f "$DB_PATH" ]; then
    ADMIN_INFO=$(sqlite3 -separator "|" "$DB_PATH" "SELECT email, first_name, last_name, must_change_pwd FROM users WHERE role_id = (SELECT id FROM roles WHERE code='ADMIN') LIMIT 1")

    if [ -n "$ADMIN_INFO" ]; then
        EMAIL=$(echo "$ADMIN_INFO" | cut -d'|' -f1)
        FIRST=$(echo "$ADMIN_INFO" | cut -d'|' -f2)
        LAST=$(echo "$ADMIN_INFO" | cut -d'|' -f3)
        MUST_CHANGE=$(echo "$ADMIN_INFO" | cut -d'|' -f4)

        check_ok "Admin trouvé : $EMAIL ($FIRST $LAST)"
        if [ "$MUST_CHANGE" = "1" ]; then
            check_ok "must_change_pwd = 1 (sécurité OK)"
        else
            check_warn "must_change_pwd = 0 (l'admin pourrait ne jamais changer son mdp)"
        fi

        # Vérifier hash argon2id
        HASH=$(sqlite3 "$DB_PATH" "SELECT password_hash FROM users WHERE email='$EMAIL'")
        if [[ "$HASH" == \$argon2id\$* ]]; then
            check_ok "Hash mot de passe : argon2id"
        else
            check_warn "Hash mot de passe : format inattendu"
        fi
    else
        check_fail "Aucun admin trouvé !"
    fi
fi

# ----------------------------------------------------------------------------
# 6. Vérification intégrité Foreign Keys
# ----------------------------------------------------------------------------
echo ""
echo "▶ Intégrité"

if [ -f "$DB_PATH" ]; then
    FK_ERR=$(sqlite3 "$DB_PATH" "PRAGMA foreign_key_check" | wc -l)
    if [ "$FK_ERR" -eq 0 ]; then
        check_ok "Foreign Keys : aucune erreur"
    else
        check_fail "Foreign Keys : $FK_ERR erreur(s)"
        sqlite3 "$DB_PATH" "PRAGMA foreign_key_check" | head -5
    fi

    # Quick check
    INTEGRITY=$(sqlite3 "$DB_PATH" "PRAGMA quick_check")
    if [ "$INTEGRITY" = "ok" ]; then
        check_ok "Quick check : ok"
    else
        check_fail "Quick check : $INTEGRITY"
    fi
fi

# ----------------------------------------------------------------------------
# Résumé
# ----------------------------------------------------------------------------
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Résumé${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"

if [ "$ERRORS" -eq 0 ] && [ "$WARNINGS" -eq 0 ]; then
    echo -e "${GREEN}✅ Installation parfaite : aucune erreur, aucun warning${NC}"
elif [ "$ERRORS" -eq 0 ]; then
    echo -e "${YELLOW}⚠ Installation OK avec $WARNINGS warning(s)${NC}"
    echo "  → Les warnings ne bloquent pas le fonctionnement"
else
    echo -e "${RED}✗ Installation avec problèmes : $ERRORS erreur(s), $WARNINGS warning(s)${NC}"
    echo "  → Corrigez les erreurs avant de continuer (Module 3)"
fi
echo ""

exit $ERRORS
