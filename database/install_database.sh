#!/bin/bash
# ============================================================================
# SIEM AFRICA - Module 2 : Installation de la base de données
# ============================================================================
# Compatible : Ubuntu 22.04 LTS et 24.04 LTS
# Effectue :
#   1. Détection install précédente + désinstallation propre
#   2. Création du groupe siem-africa (FONDATION pour tous les modules)
#   3. Création utilisateur siem-db
#   4. Installation des dépendances (sqlite3, argon2)
#   5. Création BDD dans /var/lib/siem-africa/siem.db
#   6. Chargement schéma + données + signatures + seeds
#   7. Prompts interactifs (email, password, organisation, pays)
#   8. Hash argon2id du mot de passe admin
#   9. Sauvegarde des credentials dans /root/siem_credentials.txt
#  10. Validation finale
# ============================================================================
# IMPORTANT : pas de "set -e" (cause des bugs silencieux)
# IMPORTANT : pas de hardening systemd agressif (cause CHDIR error 200)
# ============================================================================

# ----------------------------------------------------------------------------
# Couleurs pour les logs
# ----------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()      { echo -e "${GREEN}[ OK ]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_err()     { echo -e "${RED}[FAIL]${NC} $*"; }
log_step()    { echo -e "\n${CYAN}━━━ $* ━━━${NC}"; }

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------
SIEM_GROUP="siem-africa"
SIEM_DB_USER="siem-db"
DATA_DIR="/var/lib/siem-africa"
LOG_DIR="/var/log/siem-africa"
CONFIG_DIR="/etc/siem-africa"
DB_PATH="${DATA_DIR}/siem.db"
CREDS_FILE="/root/siem_credentials.txt"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCHEMA_DIR="${SCRIPT_DIR}/schema"
DATA_SQL_DIR="${SCRIPT_DIR}/data"

# ----------------------------------------------------------------------------
# Vérifications initiales
# ----------------------------------------------------------------------------
log_step "Vérifications initiales"

# 1. Root ?
if [ "$EUID" -ne 0 ]; then
    log_err "Ce script doit être exécuté en root (sudo)"
    exit 1
fi
log_ok "Exécuté en root"

# 2. Ubuntu compatible ?
if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [ "$ID" != "ubuntu" ]; then
        log_warn "OS détecté : $ID (testé sur ubuntu)"
    else
        log_ok "OS : Ubuntu $VERSION_ID"
        if [ "$VERSION_ID" != "22.04" ] && [ "$VERSION_ID" != "24.04" ]; then
            log_warn "Version Ubuntu non testée : $VERSION_ID (recommandé : 22.04 ou 24.04)"
        fi
    fi
else
    log_warn "Impossible de détecter l'OS"
fi

# 3. Fichiers SQL présents ?
for f in 00_schema.sql 01_mitre_tactics.sql 02_mitre_techniques.sql \
         03_categories.sql 04_signatures_wazuh.sql 05_signatures_snort.sql \
         06_seed_roles.sql 07_seed_settings.sql 08_seed_filters.sql \
         09_countries.sql 10_kpi_history_seed.sql; do
    target="${DATA_SQL_DIR}/$f"
    [ "$f" = "00_schema.sql" ] && target="${SCHEMA_DIR}/$f"
    if [ ! -f "$target" ]; then
        log_err "Fichier manquant : $target"
        exit 1
    fi
done
log_ok "Tous les fichiers SQL trouvés"

# ----------------------------------------------------------------------------
# Détection install précédente
# ----------------------------------------------------------------------------
log_step "Détection install précédente"

INSTALL_EXISTS=0
if [ -f "$DB_PATH" ]; then
    log_warn "Une BDD existe déjà : $DB_PATH"
    INSTALL_EXISTS=1
fi
if id "$SIEM_DB_USER" &>/dev/null; then
    log_warn "L'utilisateur $SIEM_DB_USER existe déjà"
    INSTALL_EXISTS=1
fi
if getent group "$SIEM_GROUP" &>/dev/null; then
    log_warn "Le groupe $SIEM_GROUP existe déjà"
    INSTALL_EXISTS=1
fi

if [ "$INSTALL_EXISTS" -eq 1 ]; then
    echo ""
    echo -e "${YELLOW}Une installation précédente a été détectée.${NC}"
    echo "Voulez-vous :"
    echo "  1. La supprimer et réinstaller proprement (RECOMMANDÉ)"
    echo "  2. Annuler"
    echo ""
    read -p "Votre choix [1/2] : " REINSTALL_CHOICE

    if [ "$REINSTALL_CHOICE" != "1" ]; then
        log_info "Installation annulée."
        exit 0
    fi

    log_step "Désinstallation propre de l'install précédente"

    # Backup BDD avant suppression
    if [ -f "$DB_PATH" ]; then
        BACKUP="${DB_PATH}.backup.$(date +%Y%m%d-%H%M%S)"
        cp "$DB_PATH" "$BACKUP"
        log_ok "Backup BDD : $BACKUP"
    fi

    # Supprimer la BDD et son dossier
    rm -rf "$DATA_DIR"
    log_ok "Dossier $DATA_DIR supprimé"

    # NOTE: on garde le user et le groupe pour les autres modules qui les utilisent
    # Ils seront recréés s'ils n'existent pas
    log_info "User et groupe siem-* conservés (utilisés par les autres modules)"
fi

# ----------------------------------------------------------------------------
# Installation des dépendances
# ----------------------------------------------------------------------------
log_step "Installation des dépendances"

apt-get update -qq

# sqlite3, argon2 et python3 (pour SMTP via smtplib)
PACKAGES_NEEDED=()
command -v sqlite3 >/dev/null 2>&1 || PACKAGES_NEEDED+=("sqlite3")
command -v argon2 >/dev/null 2>&1   || PACKAGES_NEEDED+=("argon2")
command -v python3 >/dev/null 2>&1  || PACKAGES_NEEDED+=("python3")
dpkg -s ca-certificates >/dev/null 2>&1 || PACKAGES_NEEDED+=("ca-certificates")

if [ ${#PACKAGES_NEEDED[@]} -gt 0 ]; then
    log_info "Installation : ${PACKAGES_NEEDED[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${PACKAGES_NEEDED[@]}" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        log_err "Échec de l'installation des paquets"
        exit 1
    fi
fi

log_ok "sqlite3 : $(sqlite3 --version | awk '{print $1}')"
log_ok "argon2  : disponible"
log_ok "python3 : $(python3 --version | awk '{print $2}')"
log_ok "smtplib : intégré à Python (utilisé par configure_smtp.sh)"

# ----------------------------------------------------------------------------
# Création groupe et utilisateur système
# ----------------------------------------------------------------------------
log_step "Création groupe et utilisateur système"

# Groupe siem-africa (partagé entre tous les modules)
if ! getent group "$SIEM_GROUP" &>/dev/null; then
    groupadd --system "$SIEM_GROUP"
    log_ok "Groupe $SIEM_GROUP créé"
else
    log_ok "Groupe $SIEM_GROUP existe déjà"
fi

# Utilisateur siem-db
if ! id "$SIEM_DB_USER" &>/dev/null; then
    useradd --system \
            --no-create-home \
            --shell /usr/sbin/nologin \
            --gid "$SIEM_GROUP" \
            "$SIEM_DB_USER"
    log_ok "Utilisateur $SIEM_DB_USER créé"
else
    # S'assurer qu'il est bien dans le groupe siem-africa
    usermod -g "$SIEM_GROUP" "$SIEM_DB_USER" 2>/dev/null
    log_ok "Utilisateur $SIEM_DB_USER existe (groupe principal mis à jour)"
fi

# ----------------------------------------------------------------------------
# Création des dossiers
# ----------------------------------------------------------------------------
log_step "Création des dossiers système"

# /var/lib/siem-africa - BDD principale
mkdir -p "$DATA_DIR"
chown "${SIEM_DB_USER}:${SIEM_GROUP}" "$DATA_DIR"
chmod 770 "$DATA_DIR"
log_ok "$DATA_DIR (770 ${SIEM_DB_USER}:${SIEM_GROUP})"

# /var/log/siem-africa - logs (utilisé par tous les modules)
mkdir -p "$LOG_DIR"
chown "${SIEM_DB_USER}:${SIEM_GROUP}" "$LOG_DIR"
chmod 770 "$LOG_DIR"
log_ok "$LOG_DIR (770 ${SIEM_DB_USER}:${SIEM_GROUP})"

# /etc/siem-africa - configs
mkdir -p "$CONFIG_DIR"
chown "root:${SIEM_GROUP}" "$CONFIG_DIR"
chmod 750 "$CONFIG_DIR"
log_ok "$CONFIG_DIR (750 root:${SIEM_GROUP})"

# Fichier log SIEM (vide au départ)
touch /var/log/siem-africa/siem.log
chown "${SIEM_DB_USER}:${SIEM_GROUP}" /var/log/siem-africa/siem.log
chmod 660 /var/log/siem-africa/siem.log

# ----------------------------------------------------------------------------
# Prompts interactifs
# ----------------------------------------------------------------------------
log_step "Configuration de l'administrateur"

echo ""
echo "Quelques informations sont nécessaires pour créer le compte admin."
echo ""

# Email admin (validation regex simple)
while true; do
    read -p "Email administrateur : " ADMIN_EMAIL
    if [[ "$ADMIN_EMAIL" =~ ^[a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        break
    else
        log_warn "Email invalide. Réessayez."
    fi
done

# Prénom et nom
read -p "Prénom : " ADMIN_FIRSTNAME
read -p "Nom : " ADMIN_LASTNAME

# Mot de passe (avec confirmation)
echo ""
echo -e "${YELLOW}ℹ Le mot de passe sera VISIBLE pendant la saisie (pour eviter les fautes de frappe).${NC}"
echo -e "${YELLOW}  Il sera ensuite chiffre avec argon2id avant stockage en BDD.${NC}"
echo ""
while true; do
    read -p "Mot de passe (min 8 caractères) : " ADMIN_PASSWORD
    if [ ${#ADMIN_PASSWORD} -lt 8 ]; then
        log_warn "Trop court (min 8 caractères)"
        continue
    fi
    read -p "Confirmer le mot de passe : " ADMIN_PASSWORD_CONFIRM
    if [ "$ADMIN_PASSWORD" = "$ADMIN_PASSWORD_CONFIRM" ]; then
        break
    else
        log_warn "Les mots de passe ne correspondent pas"
    fi
done

# Organisation
read -p "Nom de l'organisation [PME Africa] : " ORG_NAME
ORG_NAME="${ORG_NAME:-PME Africa}"

# Pays
echo ""
echo "Pays principal du déploiement :"
echo "  1. 🇨🇲 Cameroun"
echo "  2. 🇬🇦 Gabon"
echo "  3. 🇨🇬 Congo (Brazzaville)"
echo "  4. 🇨🇩 République Démocratique du Congo"
echo ""
read -p "Choix [1-4, défaut 1] : " COUNTRY_CHOICE
COUNTRY_CHOICE="${COUNTRY_CHOICE:-1}"

case "$COUNTRY_CHOICE" in
    1) COUNTRY_ID=1; COUNTRY_NAME="Cameroun" ;;
    2) COUNTRY_ID=2; COUNTRY_NAME="Gabon" ;;
    3) COUNTRY_ID=3; COUNTRY_NAME="Congo Brazzaville" ;;
    4) COUNTRY_ID=4; COUNTRY_NAME="RDC" ;;
    *) COUNTRY_ID=1; COUNTRY_NAME="Cameroun" ;;
esac
log_ok "Pays sélectionné : $COUNTRY_NAME"

# ----------------------------------------------------------------------------
# Hash du mot de passe avec argon2id
# ----------------------------------------------------------------------------
log_step "Hash du mot de passe (argon2id)"

# Génération salt aléatoire
SALT=$(head -c 16 /dev/urandom | base64 | tr -d '\n=')

# Hash argon2id (m=65536 KB, t=3 itérations, p=4 threads)
ADMIN_PASSWORD_HASH=$(echo -n "$ADMIN_PASSWORD" | argon2 "$SALT" -id -t 3 -m 16 -p 4 -e 2>/dev/null)

if [ -z "$ADMIN_PASSWORD_HASH" ]; then
    log_err "Échec de la génération du hash argon2"
    exit 1
fi
log_ok "Hash argon2id généré (taille: ${#ADMIN_PASSWORD_HASH})"

# ----------------------------------------------------------------------------
# Création de la BDD
# ----------------------------------------------------------------------------
log_step "Création de la base de données"

# Schéma
log_info "Chargement du schéma..."
sqlite3 "$DB_PATH" < "${SCHEMA_DIR}/00_schema.sql" 2>&1 | grep -v "^wal$"
if [ ! -f "$DB_PATH" ]; then
    log_err "Échec création BDD"
    exit 1
fi
log_ok "Schéma créé (24 tables)"

# Charger les données dans l'ordre
load_sql() {
    local file="$1"
    local label="$2"
    if sqlite3 "$DB_PATH" < "${DATA_SQL_DIR}/${file}" 2>&1 | grep -v "^wal$" | grep -q "Error\|error"; then
        log_err "Erreur lors du chargement de $label"
        return 1
    fi
    log_ok "$label chargé"
}

load_sql "01_mitre_tactics.sql"      "MITRE Tactics (14)"
load_sql "02_mitre_techniques.sql"   "MITRE Techniques (137)"
load_sql "03_categories.sql"         "Catégories (10)"
load_sql "04_signatures_wazuh.sql"   "Signatures Wazuh (190)"
load_sql "05_signatures_snort.sql"   "Signatures Snort (190)"
load_sql "06_seed_roles.sql"         "Rôles RBAC (4)"
load_sql "07_seed_settings.sql"      "Settings (48)"
load_sql "08_seed_filters.sql"       "Filtres FP (6)"
load_sql "09_countries.sql"          "Pays Afrique Centrale (4)"
load_sql "10_kpi_history_seed.sql"   "KPI initialisés (19)"

# ----------------------------------------------------------------------------
# Création de l'admin
# ----------------------------------------------------------------------------
log_step "Création de l'administrateur"

# Échapper les caractères spéciaux pour SQL
ESCAPE_EMAIL=$(printf '%s' "$ADMIN_EMAIL" | sed "s/'/''/g")
ESCAPE_FIRST=$(printf '%s' "$ADMIN_FIRSTNAME" | sed "s/'/''/g")
ESCAPE_LAST=$(printf '%s' "$ADMIN_LASTNAME" | sed "s/'/''/g")
ESCAPE_HASH=$(printf '%s' "$ADMIN_PASSWORD_HASH" | sed "s/'/''/g")
ESCAPE_ORG=$(printf '%s' "$ORG_NAME" | sed "s/'/''/g")

# Insertion en SQL
sqlite3 "$DB_PATH" <<SQL
INSERT INTO users (
    user_uuid, email, first_name, last_name,
    password_hash, must_change_pwd,
    role_id, organization, country_id,
    is_active, is_locked,
    language, timezone, theme_preference
) VALUES (
    lower(hex(randomblob(16))),
    '${ESCAPE_EMAIL}',
    '${ESCAPE_FIRST}',
    '${ESCAPE_LAST}',
    '${ESCAPE_HASH}',
    1,
    (SELECT id FROM roles WHERE code = 'ADMIN'),
    '${ESCAPE_ORG}',
    ${COUNTRY_ID},
    1, 0,
    'fr', 'Africa/Douala', 'dark'
);

-- Mettre à jour le setting organization_name
UPDATE settings SET value = '${ESCAPE_ORG}' WHERE key = 'organization_name';

-- Mettre à jour le setting du pays
UPDATE settings SET value = '${COUNTRY_ID}' WHERE key = 'system_country_id';
SQL

# Vérifier
ADMIN_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM users WHERE role_id = (SELECT id FROM roles WHERE code = 'ADMIN')")
if [ "$ADMIN_COUNT" -eq 0 ]; then
    log_err "Échec de la création de l'admin"
    exit 1
fi
log_ok "Admin créé : $ADMIN_EMAIL"

# ----------------------------------------------------------------------------
# Permissions finales sur la BDD
# ----------------------------------------------------------------------------
log_step "Application des permissions"

chown "${SIEM_DB_USER}:${SIEM_GROUP}" "$DB_PATH"
chmod 660 "$DB_PATH"
log_ok "siem.db : 660 ${SIEM_DB_USER}:${SIEM_GROUP}"

# Fichiers WAL et SHM créés par SQLite
[ -f "${DB_PATH}-wal" ] && chown "${SIEM_DB_USER}:${SIEM_GROUP}" "${DB_PATH}-wal" && chmod 660 "${DB_PATH}-wal"
[ -f "${DB_PATH}-shm" ] && chown "${SIEM_DB_USER}:${SIEM_GROUP}" "${DB_PATH}-shm" && chmod 660 "${DB_PATH}-shm"

# ----------------------------------------------------------------------------
# Sauvegarde des credentials (mode APPEND)
# ----------------------------------------------------------------------------
log_step "Sauvegarde des credentials"

# Créer le fichier s'il n'existe pas
if [ ! -f "$CREDS_FILE" ]; then
    cat > "$CREDS_FILE" <<EOF
═══════════════════════════════════════════════════════════════
  SIEM AFRICA - Credentials
═══════════════════════════════════════════════════════════════
  Date d'installation : $(date '+%Y-%m-%d %H:%M:%S')
  Hôte : $(hostname)
  IP : $(hostname -I | awk '{print $1}')
═══════════════════════════════════════════════════════════════

EOF
    chmod 600 "$CREDS_FILE"
    chown root:root "$CREDS_FILE"
fi

# APPEND la section Module 2
cat >> "$CREDS_FILE" <<EOF

[MODULE 2 - Base de données]
─────────────────────────────────
Date d'installation     : $(date '+%Y-%m-%d %H:%M:%S')
Chemin BDD              : ${DB_PATH}
Propriétaire            : ${SIEM_DB_USER}:${SIEM_GROUP}

Admin email             : ${ADMIN_EMAIL}
Admin nom               : ${ADMIN_FIRSTNAME} ${ADMIN_LASTNAME}
Admin organisation      : ${ORG_NAME}
Admin pays              : ${COUNTRY_NAME} (id=${COUNTRY_ID})
Admin must_change_pwd   : OUI (au premier login)

# Le mot de passe NE FIGURE PAS ici par sécurité.
# Si oublié : sudo ./reset_admin.sh

EOF

log_ok "Credentials sauvegardés : $CREDS_FILE"

# ----------------------------------------------------------------------------
# Validation finale
# ----------------------------------------------------------------------------
log_step "Validation finale"

# Compter ce qui est dans la BDD
N_TABLES=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
N_TACTICS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM mitre_tactics")
N_TECH=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM mitre_techniques")
N_SIGS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signatures")
N_ROLES=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM roles")
N_SETTINGS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM settings")
N_FILTERS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM alert_filters")
N_COUNTRIES=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM countries")
N_USERS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM users")

# FK check
FK_ERRORS=$(sqlite3 "$DB_PATH" "PRAGMA foreign_key_check" | wc -l)

echo ""
echo "  Tables           : $N_TABLES"
echo "  MITRE Tactics    : $N_TACTICS / 14"
echo "  MITRE Techniques : $N_TECH / 137"
echo "  Signatures       : $N_SIGS / 380"
echo "  Rôles            : $N_ROLES / 4"
echo "  Settings         : $N_SETTINGS"
echo "  Filtres FP       : $N_FILTERS / 6"
echo "  Pays             : $N_COUNTRIES / 4"
echo "  Utilisateurs     : $N_USERS"
echo "  FK errors        : $FK_ERRORS"

# ----------------------------------------------------------------------------
# Configuration SMTP optionnelle (utilise configure_smtp.sh)
# ----------------------------------------------------------------------------
log_step "Configuration SMTP (optionnelle)"

echo ""
echo "Voulez-vous configurer SMTP maintenant ?"
echo "Cela permettra :"
echo "  - Recevoir un email de bienvenue (test SMTP)"
echo "  - Préparer les notifications d'alertes du Module 3"
echo ""
echo "  1. Oui, configurer maintenant (recommandé)"
echo "  2. Plus tard (lancer ./configure_smtp.sh quand vous voudrez)"
echo ""
read -p "Choix [1/2, défaut 2] : " SMTP_CHOICE
SMTP_CHOICE="${SMTP_CHOICE:-2}"

SMTP_CONFIGURED=0

SCRIPT_DIR_AUTO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$SMTP_CHOICE" = "1" ]; then
    if [ -x "$SCRIPT_DIR_AUTO/configure_smtp.sh" ]; then
        log_info "Lancement de configure_smtp.sh..."
        echo ""
        if "$SCRIPT_DIR_AUTO/configure_smtp.sh"; then
            SMTP_CONFIGURED=1
        fi
    else
        log_warn "configure_smtp.sh introuvable"
        log_info "Vous pourrez le lancer plus tard : sudo ./configure_smtp.sh"
    fi
else
    log_info "SMTP non configuré (vous pourrez le faire avec ./configure_smtp.sh)"
fi

# ----------------------------------------------------------------------------
# Vérification automatique (verify.sh)
# ----------------------------------------------------------------------------
log_step "Vérification automatique de l'installation"

VERIFY_OK=0
if [ -x "$SCRIPT_DIR_AUTO/verify.sh" ]; then
    if "$SCRIPT_DIR_AUTO/verify.sh"; then
        VERIFY_OK=1
        log_ok "Vérification réussie"
    else
        log_warn "La vérification a relevé des problèmes (voir au-dessus)"
    fi
else
    log_warn "verify.sh introuvable, vérification ignorée"
fi

# ----------------------------------------------------------------------------
# Tests automatiques (run_all_tests.sh)
# ----------------------------------------------------------------------------
log_step "Tests automatiques (98 assertions)"

TESTS_OK=0
TESTS_RESULT=""
if [ -x "$SCRIPT_DIR_AUTO/tests/run_all_tests.sh" ]; then
    echo ""
    if "$SCRIPT_DIR_AUTO/tests/run_all_tests.sh"; then
        TESTS_OK=1
        TESTS_RESULT="✅ TOUS LES TESTS PASSENT"
        log_ok "Tous les tests passent"
    else
        TESTS_RESULT="⚠ CERTAINS TESTS ONT ÉCHOUÉ (voir au-dessus)"
        log_warn "Certains tests ont échoué"
    fi
else
    TESTS_RESULT="⚠ Tests non lancés (run_all_tests.sh introuvable)"
    log_warn "tests/run_all_tests.sh introuvable, tests ignorés"
fi

# Résumé final
echo ""
log_step "Installation terminée"
echo ""
echo -e "${GREEN}┌─────────────────────────────────────────────────────────────┐${NC}"
echo -e "${GREEN}│ ✅ MODULE 2 INSTALLÉ AVEC SUCCÈS                            │${NC}"
echo -e "${GREEN}└─────────────────────────────────────────────────────────────┘${NC}"
echo ""
echo "  📂 Base de données : $DB_PATH"
echo "  👤 Admin           : $ADMIN_EMAIL"
echo "  🌍 Pays            : $COUNTRY_NAME"
echo "  🔐 Credentials     : $CREDS_FILE"
if [ "$SMTP_CONFIGURED" = "1" ]; then
    echo "  📧 SMTP            : ✅ configuré et email de bienvenue envoyé"
else
    echo "  📧 SMTP            : ⚠ non configuré (lancer ./configure_smtp.sh)"
fi
if [ "$VERIFY_OK" = "1" ]; then
    echo "  🔍 Vérification    : ✅ OK"
else
    echo "  🔍 Vérification    : ⚠ problèmes détectés"
fi
if [ "$TESTS_OK" = "1" ]; then
    echo "  🧪 Tests           : ✅ 98/98 assertions OK"
else
    echo "  🧪 Tests           : ⚠ voir résultats ci-dessus"
fi
echo ""
echo "Prochaines étapes :"
if [ "$SMTP_CONFIGURED" != "1" ]; then
    echo "  1. (Optionnel) Configurer SMTP : sudo ./configure_smtp.sh"
    echo "  2. Installer le Module 3 (Agent)"
else
    echo "  1. Installer le Module 3 (Agent)"
fi
echo ""
