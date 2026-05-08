#!/usr/bin/env bash
# ==============================================================================
#  SIEM AFRICA - Module 1 - Installation LITE
#  Wazuh 4.14 (Manager seul, sans Indexer ni Dashboard) + Snort 2.9
#  Compatible : Ubuntu 20.04 / 22.04 / 24.04
# ==============================================================================
#
#  Version legere pour serveurs avec peu de ressources :
#    - 2 Go RAM minimum
#    - 15 Go disque libre
#    - 1 CPU
#
#  Pas de dashboard web : interaction en ligne de commande uniquement.
#  Le dashboard SIEM Africa (Module 4) servira d'interface web.
#
#  Usage : sudo ./install_lite.sh
# ==============================================================================

# Pas de "set -e"

# ----------------------------------------------------------------------------
# Couleurs
# ----------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
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
WAZUH_REPO_VERSION="4.x"
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
  SIEM AFRICA - Module 1 - Installation LITE
  Wazuh 4.14 Manager + Snort 2.9 (sans dashboard web)
═══════════════════════════════════════════════════════════════
BANNER
echo -e "${NC}"

# ----------------------------------------------------------------------------
# 1. Verifications
# ----------------------------------------------------------------------------
log_step "Verifications initiales"

if [ "$EUID" -ne 0 ]; then
    log_err "Ce script doit etre execute en root (sudo)."
    exit 1
fi
log_ok "Execution en root"

if [ ! -f /etc/os-release ]; then
    log_err "Impossible de detecter l'OS"
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
        log_ok "Ubuntu $OS_VER detecte"
        ;;
    *)
        log_warn "Ubuntu $OS_VER non teste"
        read -p "Continuer ? [o/N] : " CONFIRM
        if [ "${CONFIRM,,}" != "o" ]; then exit 0; fi
        ;;
esac

# RAM
RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
if [ "$RAM_MB" -lt 1500 ]; then
    log_warn "RAM detectee : ${RAM_MB} Mo (minimum recommande : 2 Go)"
    read -p "Continuer ? [o/N] : " CONFIRM
    if [ "${CONFIRM,,}" != "o" ]; then exit 0; fi
else
    log_ok "RAM : ${RAM_MB} Mo"
fi

# Disque
DISK_FREE_GB=$(df -BG / | awk 'NR==2 {print $4}' | tr -d 'G')
if [ "$DISK_FREE_GB" -lt 10 ]; then
    log_warn "Espace libre : ${DISK_FREE_GB} Go (recommande : 15 Go)"
    read -p "Continuer ? [o/N] : " CONFIRM
    if [ "${CONFIRM,,}" != "o" ]; then exit 0; fi
else
    log_ok "Espace libre : ${DISK_FREE_GB} Go"
fi

# Internet
if ! ping -c 1 -W 3 packages.wazuh.com &>/dev/null; then
    log_warn "Pas de connexion a packages.wazuh.com"
    read -p "Continuer ? [o/N] : " CONFIRM
    if [ "${CONFIRM,,}" != "o" ]; then exit 1; fi
else
    log_ok "Connexion Internet OK"
fi

# ----------------------------------------------------------------------------
# 2. Detection installation precedente
# ----------------------------------------------------------------------------
log_step "Detection installation precedente"

PREVIOUS_INSTALL=0
if dpkg -l | grep -q "wazuh-manager"; then
    log_warn "Wazuh Manager deja installe"
    PREVIOUS_INSTALL=1
fi
if dpkg -l | grep -q "^ii.*snort "; then
    log_warn "Snort deja installe"
    PREVIOUS_INSTALL=1
fi

if [ "$PREVIOUS_INSTALL" = "1" ]; then
    echo ""
    echo "  1. Desinstaller proprement et reinstaller"
    echo "  2. Annuler"
    echo ""
    read -p "Choix [1/2, defaut 2] : " CLEAN
    CLEAN="${CLEAN:-2}"

    if [ "$CLEAN" = "1" ]; then
        log_step "Desinstallation propre"
        systemctl stop wazuh-manager 2>/dev/null
        systemctl stop snort 2>/dev/null
        apt-get remove --purge -y wazuh-manager 2>/dev/null
        apt-get remove --purge -y snort snort-common snort-rules-default 2>/dev/null
        rm -rf /var/ossec /etc/snort
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
apt-get update -y 2>&1 | tee -a "$LOG_INSTALL" >/dev/null
log_ok "apt-get update termine"

# ----------------------------------------------------------------------------
# 4. Dependances
# ----------------------------------------------------------------------------
log_step "Installation dependances"

apt-get install -y \
    curl wget gnupg apt-transport-https lsb-release ca-certificates \
    software-properties-common net-tools jq unzip \
    2>&1 | tee -a "$LOG_INSTALL" >/dev/null

if [ $? -ne 0 ]; then
    log_err "Echec installation dependances"
    exit 1
fi
log_ok "Dependances installees"

# ----------------------------------------------------------------------------
# 5. Groupe siem-africa
# ----------------------------------------------------------------------------
log_step "Creation groupe siem-africa"

if getent group "$SIEM_GROUP" >/dev/null; then
    log_info "Groupe $SIEM_GROUP existe deja"
else
    groupadd --system "$SIEM_GROUP"
    log_ok "Groupe $SIEM_GROUP cree"
fi

# ----------------------------------------------------------------------------
# 6. Saisie informations admin
# ----------------------------------------------------------------------------
log_step "Configuration administrateur"

while true; do
    read -p "Email administrateur : " ADMIN_EMAIL
    if [[ "$ADMIN_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        break
    else
        log_warn "Email invalide. Reessayez."
    fi
done

read -p "Nom de l'organisation [PME Africa] : " ORG_NAME
ORG_NAME="${ORG_NAME:-PME Africa}"

echo ""
echo "Pays principal :"
echo "  1. Cameroun  2. Gabon  3. Congo  4. RD Congo"
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
# 7. Ajout du depot Wazuh
# ----------------------------------------------------------------------------
log_step "Ajout du depot Wazuh"

# Cle GPG (methode keyring, compatible Ubuntu 20/22/24)
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring \
    --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import 2>&1 | tee -a "$LOG_INSTALL" >/dev/null

chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/${WAZUH_REPO_VERSION}/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list

apt-get update -y 2>&1 | tee -a "$LOG_INSTALL" >/dev/null

if [ $? -ne 0 ]; then
    log_err "Echec ajout depot Wazuh"
    exit 1
fi

log_ok "Depot Wazuh ajoute"

# ----------------------------------------------------------------------------
# 8. Installation Wazuh Manager
# ----------------------------------------------------------------------------
log_step "Installation Wazuh Manager $WAZUH_VERSION"

apt-get install -y wazuh-manager 2>&1 | tee -a "$LOG_INSTALL" >/dev/null

if [ $? -ne 0 ]; then
    log_err "Echec installation Wazuh Manager"
    exit 1
fi

log_ok "Wazuh Manager installe"

# Empecher la mise a jour automatique (recommande Wazuh)
sed -i "s/^# wazuh-manager/wazuh-manager/" /etc/apt/sources.list.d/wazuh.list 2>/dev/null
apt-mark hold wazuh-manager 2>/dev/null

# Demarrer
systemctl daemon-reload
systemctl enable wazuh-manager
systemctl start wazuh-manager

if systemctl is-active --quiet wazuh-manager; then
    log_ok "Wazuh Manager demarre"
else
    log_warn "Wazuh Manager non demarre (verifie : systemctl status wazuh-manager)"
fi

# ----------------------------------------------------------------------------
# 9. Installation Snort 2.9
# ----------------------------------------------------------------------------
log_step "Installation Snort $SNORT_VERSION"

DEFAULT_IFACE=$(ip route | awk '/^default/ {print $5; exit}')
DEFAULT_IFACE="${DEFAULT_IFACE:-eth0}"
LOCAL_NET=$(ip -4 addr show "$DEFAULT_IFACE" | awk '/inet / {print $2; exit}')
LOCAL_NET="${LOCAL_NET:-192.168.1.0/24}"

log_info "Interface : $DEFAULT_IFACE | HOME_NET : $LOCAL_NET"

echo "snort snort/address_range string $LOCAL_NET" | debconf-set-selections
echo "snort snort/interface string $DEFAULT_IFACE" | debconf-set-selections
echo "snort snort/options string -D -q -l /var/log/snort -c /etc/snort/snort.conf -i $DEFAULT_IFACE" | debconf-set-selections

apt-get install -y snort 2>&1 | tee -a "$LOG_INSTALL" >/dev/null

SNORT_OK=0
if [ $? -eq 0 ]; then
    log_ok "Snort installe"
    systemctl enable snort 2>/dev/null
    systemctl start snort 2>/dev/null
    SNORT_OK=1
else
    log_warn "Snort non installe (vous pourrez le faire plus tard : sudo apt install snort)"
fi

# ----------------------------------------------------------------------------
# 10. Sauvegarde credentials
# ----------------------------------------------------------------------------
log_step "Sauvegarde credentials"

DASHBOARD_IP=$(hostname -I | awk '{print $1}')

if [ ! -f "$CREDS_FILE" ]; then
    cat > "$CREDS_FILE" <<EOF
═══════════════════════════════════════════════════════════════
  SIEM AFRICA - Credentials
═══════════════════════════════════════════════════════════════
  Date : $(date '+%Y-%m-%d %H:%M:%S')
  Hote : $(hostname)
  IP : $DASHBOARD_IP
═══════════════════════════════════════════════════════════════

EOF
    chmod 600 "$CREDS_FILE"
    chown root:root "$CREDS_FILE"
fi

cat >> "$CREDS_FILE" <<EOF

[MODULE 1 - Wazuh Manager + Snort]
─────────────────────────────────
Date d'installation     : $(date '+%Y-%m-%d %H:%M:%S')
Mode                    : LITE (Manager seul, sans dashboard)
Wazuh version           : ${WAZUH_VERSION}
Snort version           : ${SNORT_VERSION}

Admin email             : ${ADMIN_EMAIL}
Organisation            : ${ORG_NAME}
Pays                    : ${COUNTRY_NAME} (${COUNTRY_CODE})

Pas de dashboard web    : utiliser le dashboard du Module 4
                          ou /var/ossec/bin/ pour la CLI

Interface Snort         : ${DEFAULT_IFACE}
HOME_NET                : ${LOCAL_NET}

EOF

log_ok "Credentials sauvegardes : $CREDS_FILE"

# ----------------------------------------------------------------------------
# 11. Resume
# ----------------------------------------------------------------------------
echo ""
log_step "Installation terminee"
echo ""
echo -e "${GREEN}┌─────────────────────────────────────────────────────────────┐${NC}"
echo -e "${GREEN}│ ✅ MODULE 1 LITE INSTALLE                                   │${NC}"
echo -e "${GREEN}└─────────────────────────────────────────────────────────────┘${NC}"
echo ""
echo "  📊 Wazuh Manager   : $(systemctl is-active wazuh-manager 2>/dev/null || echo unknown)"
if [ "$SNORT_OK" = "1" ]; then
    echo "  🛡️  Snort           : $(systemctl is-active snort 2>/dev/null || echo unknown)"
fi
echo "  👥 Groupe systeme  : $SIEM_GROUP"
echo ""
echo "  📂 Credentials     : $CREDS_FILE"
echo "  📋 Logs            : $LOG_INSTALL"
echo ""
echo "Note : version LITE sans dashboard web. Le Module 4 fournira le dashboard."
echo ""
echo "Prochaines etapes :"
echo "  1. Verifier : sudo systemctl status wazuh-manager"
echo "  2. Installer le Module 2 : cd ../database && sudo ./install_database.sh"
echo ""
