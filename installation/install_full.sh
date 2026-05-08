#!/usr/bin/env bash
# ==============================================================================
#  SIEM AFRICA - Module 1 - Installation FULL
#  Wazuh 4.14 (Manager + Indexer + Dashboard) + Snort 2.9
#  Compatible : Ubuntu 20.04 / 22.04 / 24.04
# ==============================================================================
#
#  Pre-requis :
#    - Ubuntu 20.04, 22.04 ou 24.04
#    - 4 Go RAM minimum (8 Go recommande)
#    - 30 Go disque libre
#    - Acces root (sudo)
#    - Connexion Internet
#
#  Usage : sudo ./install_full.sh
# ==============================================================================

# Pas de "set -e" : on gere les erreurs explicitement (regle SIEM Africa)

# ----------------------------------------------------------------------------
# Couleurs et logs
# ----------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()   { echo -e "${GREEN}[ OK ]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_err()  { echo -e "${RED}[FAIL]${NC} $*"; }
log_step() { echo -e "\n${CYAN}━━━ $* ━━━${NC}"; }

# ----------------------------------------------------------------------------
# Variables
# ----------------------------------------------------------------------------
WAZUH_VERSION="4.14"
SNORT_VERSION="2.9"
SIEM_GROUP="siem-africa"
CREDS_FILE="/root/siem_credentials.txt"
LOG_INSTALL="/var/log/siem-africa-install.log"

# ----------------------------------------------------------------------------
# Banner
# ----------------------------------------------------------------------------
clear
echo -e "${CYAN}"
cat <<'BANNER'
═══════════════════════════════════════════════════════════════
  ███████╗██╗███████╗███╗   ███╗     █████╗ ███████╗
  ██╔════╝██║██╔════╝████╗ ████║    ██╔══██╗██╔════╝
  ███████╗██║█████╗  ██╔████╔██║    ███████║█████╗
  ╚════██║██║██╔══╝  ██║╚██╔╝██║    ██╔══██║██╔══╝
  ███████║██║███████╗██║ ╚═╝ ██║    ██║  ██║██║
  ╚══════╝╚═╝╚══════╝╚═╝     ╚═╝    ╚═╝  ╚═╝╚═╝

  Module 1 - Installation FULL
  Wazuh 4.14 (Manager + Indexer + Dashboard) + Snort 2.9
═══════════════════════════════════════════════════════════════
BANNER
echo -e "${NC}"

# ----------------------------------------------------------------------------
# 1. Verifications initiales
# ----------------------------------------------------------------------------
log_step "Verifications initiales"

# Root ?
if [ "$EUID" -ne 0 ]; then
    log_err "Ce script doit etre execute en root (sudo)."
    exit 1
fi
log_ok "Execution en root"

# Detection OS
if [ ! -f /etc/os-release ]; then
    log_err "Impossible de detecter l'OS (pas de /etc/os-release)"
    exit 1
fi

. /etc/os-release
OS_ID="${ID:-unknown}"
OS_VER="${VERSION_ID:-unknown}"

if [ "$OS_ID" != "ubuntu" ]; then
    log_err "OS non supporte : $OS_ID (requis : ubuntu)"
    exit 1
fi

case "$OS_VER" in
    20.04|22.04|24.04)
        log_ok "Ubuntu $OS_VER detecte (supporte)"
        ;;
    *)
        log_warn "Ubuntu $OS_VER non teste (recommande : 20.04, 22.04 ou 24.04)"
        read -p "Continuer quand meme ? [o/N] : " CONFIRM
        if [ "${CONFIRM,,}" != "o" ]; then
            log_info "Installation annulee."
            exit 0
        fi
        ;;
esac

# RAM
RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
if [ "$RAM_MB" -lt 3500 ]; then
    log_warn "RAM detectee : ${RAM_MB} Mo (recommande : 4 Go minimum pour FULL)"
    read -p "Continuer quand meme ? [o/N] : " CONFIRM
    if [ "${CONFIRM,,}" != "o" ]; then
        log_info "Installation annulee. Essayez install_lite.sh"
        exit 0
    fi
else
    log_ok "RAM : ${RAM_MB} Mo"
fi

# Disque
DISK_FREE_GB=$(df -BG / | awk 'NR==2 {print $4}' | tr -d 'G')
if [ "$DISK_FREE_GB" -lt 25 ]; then
    log_warn "Espace libre : ${DISK_FREE_GB} Go (recommande : 30 Go)"
    read -p "Continuer quand meme ? [o/N] : " CONFIRM
    if [ "${CONFIRM,,}" != "o" ]; then
        log_info "Installation annulee."
        exit 0
    fi
else
    log_ok "Espace disque libre : ${DISK_FREE_GB} Go"
fi

# Internet
if ! ping -c 1 -W 3 packages.wazuh.com &>/dev/null; then
    log_warn "Pas de connexion a packages.wazuh.com"
    log_warn "Verifie ta connexion Internet."
    read -p "Continuer quand meme ? [o/N] : " CONFIRM
    if [ "${CONFIRM,,}" != "o" ]; then
        exit 1
    fi
else
    log_ok "Connexion Internet OK"
fi

# ----------------------------------------------------------------------------
# 2. Detection installation precedente
# ----------------------------------------------------------------------------
log_step "Detection installation precedente"

PREVIOUS_INSTALL=0
if dpkg -l | grep -q "wazuh-manager\|wazuh-indexer\|wazuh-dashboard"; then
    log_warn "Une installation Wazuh precedente a ete detectee"
    PREVIOUS_INSTALL=1
fi

if dpkg -l | grep -q "^ii.*snort "; then
    log_warn "Une installation Snort precedente a ete detectee"
    PREVIOUS_INSTALL=1
fi

if [ "$PREVIOUS_INSTALL" = "1" ]; then
    echo ""
    echo "Que voulez-vous faire ?"
    echo "  1. Desinstaller proprement et reinstaller (recommande)"
    echo "  2. Annuler l'installation"
    echo ""
    read -p "Choix [1/2, defaut 2] : " CLEAN_CHOICE
    CLEAN_CHOICE="${CLEAN_CHOICE:-2}"

    if [ "$CLEAN_CHOICE" = "1" ]; then
        log_step "Desinstallation propre"

        # Stop services
        systemctl stop wazuh-dashboard 2>/dev/null
        systemctl stop wazuh-indexer 2>/dev/null
        systemctl stop wazuh-manager 2>/dev/null
        systemctl stop snort 2>/dev/null

        # Purge packages
        apt-get remove --purge -y wazuh-manager wazuh-indexer wazuh-dashboard 2>/dev/null
        apt-get remove --purge -y snort snort-common snort-rules-default 2>/dev/null

        # Clean dirs
        rm -rf /var/ossec /var/lib/wazuh-indexer /etc/wazuh-indexer
        rm -rf /usr/share/wazuh-indexer /usr/share/wazuh-dashboard
        rm -rf /etc/wazuh-dashboard /var/log/wazuh-* /etc/snort

        log_ok "Desinstallation terminee"
    else
        log_info "Installation annulee."
        exit 0
    fi
fi

# ----------------------------------------------------------------------------
# 3. Mise a jour systeme
# ----------------------------------------------------------------------------
log_step "Mise a jour systeme"

export DEBIAN_FRONTEND=noninteractive

apt-get update -y 2>&1 | tee -a "$LOG_INSTALL" | grep -E "Err|Hit|Get" | tail -5

log_ok "apt-get update termine"

# ----------------------------------------------------------------------------
# 4. Installation des dependances
# ----------------------------------------------------------------------------
log_step "Installation des dependances"

DEPS=(
    curl
    wget
    gnupg
    apt-transport-https
    lsb-release
    ca-certificates
    software-properties-common
    net-tools
    jq
    unzip
)

apt-get install -y "${DEPS[@]}" 2>&1 | tee -a "$LOG_INSTALL" >/dev/null

if [ $? -ne 0 ]; then
    log_err "Echec de l'installation des dependances"
    exit 1
fi

log_ok "Dependances installees"

# ----------------------------------------------------------------------------
# 5. Creation du groupe siem-africa
# ----------------------------------------------------------------------------
log_step "Creation du groupe systeme siem-africa"

if getent group "$SIEM_GROUP" >/dev/null; then
    log_info "Groupe $SIEM_GROUP existe deja"
else
    groupadd --system "$SIEM_GROUP"
    log_ok "Groupe $SIEM_GROUP cree"
fi

# ----------------------------------------------------------------------------
# 6. Saisie des informations admin
# ----------------------------------------------------------------------------
log_step "Configuration administrateur"

echo ""
echo -e "${YELLOW}Ces informations seront utilisees pour les credentials Wazuh.${NC}"
echo ""

# Email
while true; do
    read -p "Email administrateur : " ADMIN_EMAIL
    if [[ "$ADMIN_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        break
    else
        log_warn "Email invalide. Reessayez."
    fi
done

# Organisation
read -p "Nom de l'organisation [PME Africa] : " ORG_NAME
ORG_NAME="${ORG_NAME:-PME Africa}"

# Pays
echo ""
echo "Pays principal du deploiement :"
echo "  1. Cameroun"
echo "  2. Gabon"
echo "  3. Congo (Brazzaville)"
echo "  4. RD Congo"
echo ""
read -p "Choix [1-4, defaut 1] : " COUNTRY_CHOICE
COUNTRY_CHOICE="${COUNTRY_CHOICE:-1}"

case "$COUNTRY_CHOICE" in
    1) COUNTRY_NAME="Cameroun"; COUNTRY_CODE="CM" ;;
    2) COUNTRY_NAME="Gabon"; COUNTRY_CODE="GA" ;;
    3) COUNTRY_NAME="Congo"; COUNTRY_CODE="CG" ;;
    4) COUNTRY_NAME="RD Congo"; COUNTRY_CODE="CD" ;;
    *) COUNTRY_NAME="Cameroun"; COUNTRY_CODE="CM" ;;
esac

log_ok "Configuration : $ADMIN_EMAIL | $ORG_NAME | $COUNTRY_NAME"

# ----------------------------------------------------------------------------
# 7. Installation Wazuh 4.14 FULL via le script officiel
# ----------------------------------------------------------------------------
log_step "Installation Wazuh $WAZUH_VERSION (Manager + Indexer + Dashboard)"

log_info "Telechargement de wazuh-install.sh..."
cd /tmp
rm -f wazuh-install.sh wazuh-install-files.tar

curl -sO "https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh"
if [ ! -f wazuh-install.sh ]; then
    log_err "Echec du telechargement de wazuh-install.sh"
    log_info "Verifiez votre connexion ou la version Wazuh ($WAZUH_VERSION)"
    exit 1
fi

chmod +x wazuh-install.sh
log_ok "Script Wazuh telecharge"

log_info "Lancement de l'installation Wazuh (cela peut prendre 10-20 minutes)..."
log_info "Logs detailles : $LOG_INSTALL et /var/log/wazuh-install.log"
echo ""

# -a : all-in-one (Manager + Indexer + Dashboard sur la meme machine)
# -i : ignore les checks (RAM faible, etc.)
bash wazuh-install.sh -a -i 2>&1 | tee -a "$LOG_INSTALL"
WAZUH_EXIT=${PIPESTATUS[0]}

if [ "$WAZUH_EXIT" -ne 0 ]; then
    log_err "L'installation Wazuh a echoue (code $WAZUH_EXIT)"
    log_info "Consulte les logs : /var/log/wazuh-install.log"
    exit 1
fi

log_ok "Wazuh $WAZUH_VERSION installe avec succes"

# Recuperer les credentials Wazuh
WAZUH_PASSWORDS_FILE="/tmp/wazuh-install-files/wazuh-passwords.txt"
WAZUH_TAR="/tmp/wazuh-install-files.tar"

if [ -f "$WAZUH_TAR" ] && [ ! -f "$WAZUH_PASSWORDS_FILE" ]; then
    cd /tmp && tar -xf "$WAZUH_TAR" 2>/dev/null
fi

WAZUH_ADMIN_PASS=""
if [ -f "$WAZUH_PASSWORDS_FILE" ]; then
    WAZUH_ADMIN_PASS=$(grep -A 1 "username: 'admin'" "$WAZUH_PASSWORDS_FILE" | grep "password:" | head -1 | awk -F"'" '{print $2}')
fi

# ----------------------------------------------------------------------------
# 8. Installation Snort 2.9
# ----------------------------------------------------------------------------
log_step "Installation Snort $SNORT_VERSION"

# Detection interface reseau principale
DEFAULT_IFACE=$(ip route | awk '/^default/ {print $5; exit}')
if [ -z "$DEFAULT_IFACE" ]; then
    DEFAULT_IFACE="eth0"
fi

# HOME_NET (reseau local)
LOCAL_NET=$(ip -4 addr show "$DEFAULT_IFACE" | awk '/inet / {print $2; exit}')
if [ -z "$LOCAL_NET" ]; then
    LOCAL_NET="192.168.1.0/24"
fi

log_info "Interface reseau : $DEFAULT_IFACE | HOME_NET : $LOCAL_NET"

# Pre-config Snort en mode non-interactif
echo "snort snort/address_range string $LOCAL_NET" | debconf-set-selections
echo "snort snort/interface string $DEFAULT_IFACE" | debconf-set-selections
echo "snort snort/options string -D -q -l /var/log/snort -c /etc/snort/snort.conf -i $DEFAULT_IFACE" | debconf-set-selections

apt-get install -y snort 2>&1 | tee -a "$LOG_INSTALL" >/dev/null

if [ $? -ne 0 ]; then
    log_warn "Echec installation Snort via apt"
    log_warn "Vous pourrez l'installer manuellement plus tard : sudo apt install snort"
    SNORT_OK=0
else
    log_ok "Snort $SNORT_VERSION installe"
    SNORT_OK=1

    # Demarrer Snort
    systemctl enable snort 2>/dev/null
    systemctl start snort 2>/dev/null

    if systemctl is-active --quiet snort; then
        log_ok "Snort demarre"
    else
        log_warn "Snort non demarre (verifiez : systemctl status snort)"
    fi
fi

# ----------------------------------------------------------------------------
# 9. Verification des services Wazuh
# ----------------------------------------------------------------------------
log_step "Verification des services"

ALL_OK=1

for svc in wazuh-manager wazuh-indexer wazuh-dashboard; do
    if systemctl is-active --quiet "$svc"; then
        log_ok "$svc : actif"
    else
        log_err "$svc : INACTIF"
        ALL_OK=0
    fi
done

# ----------------------------------------------------------------------------
# 10. Sauvegarde des credentials
# ----------------------------------------------------------------------------
log_step "Sauvegarde des credentials"

DASHBOARD_IP=$(hostname -I | awk '{print $1}')

# Creer le fichier credentials s'il n'existe pas
if [ ! -f "$CREDS_FILE" ]; then
    cat > "$CREDS_FILE" <<EOF
═══════════════════════════════════════════════════════════════
  SIEM AFRICA - Credentials
═══════════════════════════════════════════════════════════════
  Date d'installation : $(date '+%Y-%m-%d %H:%M:%S')
  Hote : $(hostname)
  IP : $DASHBOARD_IP
═══════════════════════════════════════════════════════════════

EOF
    chmod 600 "$CREDS_FILE"
    chown root:root "$CREDS_FILE"
fi

# APPEND la section Module 1
cat >> "$CREDS_FILE" <<EOF

[MODULE 1 - Wazuh + Snort]
─────────────────────────────────
Date d'installation     : $(date '+%Y-%m-%d %H:%M:%S')
Mode                    : FULL (Manager + Indexer + Dashboard)
Wazuh version           : ${WAZUH_VERSION}
Snort version           : ${SNORT_VERSION}

Admin email             : ${ADMIN_EMAIL}
Organisation            : ${ORG_NAME}
Pays                    : ${COUNTRY_NAME} (${COUNTRY_CODE})

URL Dashboard Wazuh     : https://${DASHBOARD_IP}
Login Dashboard         : admin
Password Dashboard      : ${WAZUH_ADMIN_PASS:-VOIR /tmp/wazuh-install-files/wazuh-passwords.txt}

Interface reseau Snort  : ${DEFAULT_IFACE}
HOME_NET Snort          : ${LOCAL_NET}

EOF

log_ok "Credentials sauvegardes : $CREDS_FILE"

# ----------------------------------------------------------------------------
# 11. Resume final
# ----------------------------------------------------------------------------
echo ""
log_step "Installation terminee"
echo ""

if [ "$ALL_OK" = "1" ]; then
    echo -e "${GREEN}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${GREEN}│ ✅ MODULE 1 INSTALLE AVEC SUCCES                            │${NC}"
    echo -e "${GREEN}└─────────────────────────────────────────────────────────────┘${NC}"
else
    echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${YELLOW}│ ⚠ MODULE 1 INSTALLE AVEC AVERTISSEMENTS                     │${NC}"
    echo -e "${YELLOW}└─────────────────────────────────────────────────────────────┘${NC}"
fi

echo ""
echo "  📊 Wazuh Manager   : $(systemctl is-active wazuh-manager 2>/dev/null || echo unknown)"
echo "  🗂️  Wazuh Indexer   : $(systemctl is-active wazuh-indexer 2>/dev/null || echo unknown)"
echo "  🖥️  Wazuh Dashboard : $(systemctl is-active wazuh-dashboard 2>/dev/null || echo unknown)"
if [ "$SNORT_OK" = "1" ]; then
    echo "  🛡️  Snort           : $(systemctl is-active snort 2>/dev/null || echo unknown)"
fi
echo "  👥 Groupe systeme  : $SIEM_GROUP"
echo ""
echo "  🌍 Acces Dashboard : https://${DASHBOARD_IP}"
echo "  👤 Login           : admin"
if [ -n "$WAZUH_ADMIN_PASS" ]; then
    echo "  🔐 Password        : $WAZUH_ADMIN_PASS"
else
    echo "  🔐 Password        : voir $CREDS_FILE"
fi
echo ""
echo "  📂 Credentials     : $CREDS_FILE"
echo "  📋 Logs install    : $LOG_INSTALL"
echo ""
echo "Prochaines etapes :"
echo "  1. Ouvrir https://${DASHBOARD_IP} dans un navigateur (accepter le certificat)"
echo "  2. Se connecter avec admin / ${WAZUH_ADMIN_PASS:-<voir credentials>}"
echo "  3. Installer le Module 2 : cd ../database && sudo ./install_database.sh"
echo ""
