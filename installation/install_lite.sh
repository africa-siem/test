#!/bin/bash
#===============================================================================
#
#          FILE: install_module1_lite.sh
#
#   DESCRIPTION: SIEM Africa - Module 1 LITE
#                Installation légère : Snort + Wazuh Manager uniquement
#                (pas de Dashboard ni Indexer)
#
#         USAGE: sudo ./install_module1_lite.sh [--lang fr|en]
#
#       CONFIG MINIMALE : 2 Go RAM, 15 Go disque, 1 cœur CPU
#       CONFIG RECOMMANDÉE : 4 Go RAM, 25 Go disque, 2 cœurs CPU
#
#===============================================================================

set -e

#---------------------------------------
# COULEURS
#---------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

#---------------------------------------
# VARIABLES GLOBALES
#---------------------------------------
LOG_FILE="/var/log/siem-install.log"
CREDENTIALS_FILE="/root/siem_credentials.txt"
WAZUH_VERSION="4.7"
SNORT_CONF="/etc/snort/snort.conf"
MIN_RAM=2
MIN_DISK=15
MIN_CPU=1

SIEM_GROUP="siem-africa"
SIEM_IDS_USER="siem-ids"
SIEM_WAZUH_USER="siem-wazuh"

SIEM_IDS_PASSWORD=""
SIEM_WAZUH_PASSWORD=""

LANG_CODE="fr"

#---------------------------------------
# TRADUCTIONS (mêmes clés que full)
#---------------------------------------
t() {
    local key=$1
    if [ "$LANG_CODE" = "en" ]; then
        case "$key" in
            "banner_title")        echo "SIEM AFRICA - MODULE 1 LITE INSTALLATION" ;;
            "section_checks")      echo "[REQUIRED CHECKS]" ;;
            "section_cleanup")     echo "[CHECKING EXISTING INSTALLATION]" ;;
            "section_prep")        echo "[SYSTEM PREPARATION]" ;;
            "section_install")     echo "[INSTALLATION]" ;;
            "root_ok")             echo "Running as root" ;;
            "os_compatible")       echo "Compatible OS" ;;
            "ram_ok")              echo "RAM" ;;
            "disk_ok")             echo "Disk space" ;;
            "cpu_ok")              echo "CPU cores" ;;
            "internet_ok")         echo "Internet OK" ;;
            "checking_internet")   echo "Checking internet..." ;;
            "no_existing")         echo "No existing installation" ;;
            "existing_detected")   echo "Existing installation detected → removing" ;;
            "cleanup_done")        echo "Cleanup done" ;;
            "updating_system")     echo "Updating system..." ;;
            "system_updated")      echo "System updated" ;;
            "installing_deps")     echo "Installing dependencies..." ;;
            "deps_installed")      echo "Dependencies installed" ;;
            "creating_group")      echo "Creating SIEM Africa group and users..." ;;
            "group_created")       echo "Group and users created" ;;
            "installing_snort")    echo "Installing Snort..." ;;
            "snort_installed")     echo "Snort installed" ;;
            "configuring_snort")   echo "Configuring Snort..." ;;
            "snort_configured")    echo "Snort configured" ;;
            "installing_wazuh")    echo "Installing Wazuh Manager only (5-10 minutes)..." ;;
            "wazuh_installed")     echo "Wazuh Manager installed" ;;
            "configuring_integration") echo "Configuring Snort ↔ Wazuh integration..." ;;
            "integration_done")    echo "Integration configured" ;;
            "creating_credentials") echo "Creating credentials file..." ;;
            "credentials_created") echo "Credentials saved to" ;;
            "install_complete")    echo "INSTALLATION COMPLETED" ;;
            "install_aborted")     echo "INSTALLATION ABORTED" ;;
            "reason")              echo "Reason:" ;;
            "log_location")        echo "Log:" ;;
            *)                     echo "$key" ;;
        esac
    else
        case "$key" in
            "banner_title")        echo "SIEM AFRICA - INSTALLATION MODULE 1 LITE" ;;
            "section_checks")      echo "[VÉRIFICATIONS OBLIGATOIRES]" ;;
            "section_cleanup")     echo "[VÉRIFICATION INSTALLATION EXISTANTE]" ;;
            "section_prep")        echo "[PRÉPARATION SYSTÈME]" ;;
            "section_install")     echo "[INSTALLATION]" ;;
            "root_ok")             echo "Exécution en tant que root" ;;
            "os_compatible")       echo "OS compatible" ;;
            "ram_ok")              echo "RAM" ;;
            "disk_ok")             echo "Espace disque" ;;
            "cpu_ok")              echo "Cœurs CPU" ;;
            "internet_ok")         echo "Internet OK" ;;
            "checking_internet")   echo "Vérification connexion Internet..." ;;
            "no_existing")         echo "Aucune installation existante" ;;
            "existing_detected")   echo "Installation existante détectée → suppression" ;;
            "cleanup_done")        echo "Nettoyage terminé" ;;
            "updating_system")     echo "Mise à jour système..." ;;
            "system_updated")      echo "Système mis à jour" ;;
            "installing_deps")     echo "Installation des dépendances..." ;;
            "deps_installed")      echo "Dépendances installées" ;;
            "creating_group")      echo "Création du groupe et users SIEM Africa..." ;;
            "group_created")       echo "Groupe et users créés" ;;
            "installing_snort")    echo "Installation de Snort..." ;;
            "snort_installed")     echo "Snort installé" ;;
            "configuring_snort")   echo "Configuration de Snort..." ;;
            "snort_configured")    echo "Snort configuré" ;;
            "installing_wazuh")    echo "Installation Wazuh Manager seul (5-10 minutes)..." ;;
            "wazuh_installed")     echo "Wazuh Manager installé" ;;
            "configuring_integration") echo "Configuration intégration Snort ↔ Wazuh..." ;;
            "integration_done")    echo "Intégration configurée" ;;
            "creating_credentials") echo "Création du fichier credentials..." ;;
            "credentials_created") echo "Credentials sauvegardés dans" ;;
            "install_complete")    echo "INSTALLATION TERMINÉE" ;;
            "install_aborted")     echo "INSTALLATION ARRÊTÉE" ;;
            "reason")              echo "Raison :" ;;
            "log_location")        echo "Log :" ;;
            *)                     echo "$key" ;;
        esac
    fi
}

#---------------------------------------
# FONCTIONS DE LOG
#---------------------------------------
log()         { echo -e "$1" | tee -a "$LOG_FILE"; }
log_success() { log "${GREEN}[✓]${NC} $1"; }
log_error()   { log "${RED}[✗]${NC} $1"; }
log_info()    { log "${CYAN}[i]${NC} $1"; }
log_warning() { log "${YELLOW}[!]${NC} $1"; }
log_step()    { log "${BLUE}[STEP $1]${NC} $2"; }

abort() {
    echo ""
    echo -e "${RED}╔══════════════════════════════════════════════════════════════════╗${NC}"
    printf "${RED}║${NC}  ${BOLD}%-62s${NC}  ${RED}║${NC}\n" "✗ $(t install_aborted)"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${YELLOW}$(t reason) $1${NC}"
    echo -e "  $(t log_location) $LOG_FILE"
    echo ""
    exit 1
}

generate_password() {
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16
}

#---------------------------------------
# PARSE ARGS
#---------------------------------------
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --lang) LANG_CODE="$2"; shift 2 ;;
            --lang=*) LANG_CODE="${1#*=}"; shift ;;
            *) shift ;;
        esac
    done
    [ "$LANG_CODE" != "fr" ] && [ "$LANG_CODE" != "en" ] && LANG_CODE="fr"
}

choose_language() {
    [ ! -t 0 ] && return 0
    [ -n "${LANG_FORCED:-}" ] && return 0
    echo ""
    echo -e "${CYAN}Choix de la langue / Language selection${NC}"
    echo "  [1] Français (défaut)"
    echo "  [2] English"
    echo -n "  → [1/2] : "
    read -r choice
    case "$choice" in
        2|en|EN) LANG_CODE="en" ;;
        *) LANG_CODE="fr" ;;
    esac
    echo ""
}

#---------------------------------------
# BANNER
#---------------------------------------
show_banner() {
    clear 2>/dev/null || true
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                                                                  ║"
    echo "║         🛡️   SIEM AFRICA - MODULE 1 (LITE)                      ║"
    echo "║                                                                  ║"
    echo "║         Snort IDS + Wazuh Manager                                ║"
    echo "║         (version légère, sans Dashboard)                         ║"
    echo "║                                                                  ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
}

#---------------------------------------
# CHECKS
#---------------------------------------
check_root() {
    [ "$EUID" -ne 0 ] && abort "Must be run as root (sudo)"
    log_success "$(t root_ok)"
}

check_os() {
    [ ! -f /etc/os-release ] && abort "Cannot detect OS"
    # shellcheck disable=SC1091
    . /etc/os-release
    case $ID in
        ubuntu)
            [[ "$VERSION_ID" != "20.04" && "$VERSION_ID" != "22.04" && "$VERSION_ID" != "24.04" ]] && \
                abort "Ubuntu $VERSION_ID not supported"
            log_success "$(t os_compatible) : Ubuntu $VERSION_ID"
            ;;
        debian)
            [[ "$VERSION_ID" != "11" && "$VERSION_ID" != "12" ]] && \
                abort "Debian $VERSION_ID not supported"
            log_success "$(t os_compatible) : Debian $VERSION_ID"
            ;;
        *) abort "OS not supported: $ID" ;;
    esac
}

check_ram() {
    TOTAL_RAM=$(free -g | awk '/^Mem:/{print $2}')
    [ "$TOTAL_RAM" -lt "$MIN_RAM" ] && abort "RAM insuffisante : ${TOTAL_RAM}Go (min ${MIN_RAM}Go)"
    log_success "$(t ram_ok) : ${TOTAL_RAM} Go"
}

check_disk() {
    AVAILABLE=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    [ "$AVAILABLE" -lt "$MIN_DISK" ] && abort "Disque insuffisant : ${AVAILABLE}Go (min ${MIN_DISK}Go)"
    log_success "$(t disk_ok) : ${AVAILABLE} Go"
}

check_cpu() {
    CORES=$(nproc)
    [ "$CORES" -lt "$MIN_CPU" ] && abort "CPU insuffisant : ${CORES} cœur(s)"
    log_success "$(t cpu_ok) : ${CORES}"
}

check_internet() {
    log_info "$(t checking_internet)"
    ping -c 3 8.8.8.8 &>/dev/null || abort "No Internet"
    if ! ping -c 3 google.com &>/dev/null; then
        log_warning "DNS issue - fixing..."
        echo -e "nameserver 8.8.8.8\nnameserver 8.8.4.4" > /etc/resolv.conf
        ping -c 3 google.com &>/dev/null || abort "DNS not working"
    fi
    curl -s --head --connect-timeout 10 https://packages.wazuh.com &>/dev/null || \
        abort "Cannot reach Wazuh repos"
    log_success "$(t internet_ok)"
}

#---------------------------------------
# CLEANUP
#---------------------------------------
cleanup_all() {
    log_info "Nettoyage en cours..."
    systemctl stop snort wazuh-manager filebeat 2>/dev/null || true
    systemctl disable snort wazuh-manager filebeat 2>/dev/null || true
    pkill -9 snort 2>/dev/null || true
    pkill -9 -f 'ossec-' 2>/dev/null || true
    pkill -9 -f 'wazuh-' 2>/dev/null || true

    DEBIAN_FRONTEND=noninteractive apt remove --purge -y \
        snort snort-common snort-rules-default \
        wazuh-manager wazuh-agent filebeat 2>/dev/null || true

    rm -rf /var/ossec /etc/snort /var/log/snort /var/run/snort
    rm -rf /etc/filebeat /var/lib/filebeat /usr/share/filebeat
    rm -f /etc/systemd/system/snort.service

    systemctl daemon-reload
    systemctl reset-failed 2>/dev/null || true
    DEBIAN_FRONTEND=noninteractive apt autoremove -y 2>/dev/null || true

    log_success "$(t cleanup_done)"
}

check_existing() {
    log_info "Vérification installations existantes..."
    if dpkg -l 2>/dev/null | grep -qE "snort|wazuh-manager" || \
       [ -d "/etc/snort" ] || [ -d "/var/ossec" ]; then
        log_warning "$(t existing_detected)"
        cleanup_all
    else
        log_success "$(t no_existing)"
    fi
}

#---------------------------------------
# UPDATE & DEPS
#---------------------------------------
update_system() {
    log_info "$(t updating_system)"
    apt update -qq 2>&1 | tee -a "$LOG_FILE" >/dev/null || abort "APT update failed"
    DEBIAN_FRONTEND=noninteractive apt upgrade -y -qq 2>&1 | tee -a "$LOG_FILE" >/dev/null || \
        log_warning "Upgrade had issues"
    log_success "$(t system_updated)"
}

install_dependencies() {
    log_info "$(t installing_deps)"
    DEBIAN_FRONTEND=noninteractive apt install -y -qq \
        curl wget gnupg apt-transport-https lsb-release ca-certificates \
        software-properties-common net-tools jq iproute2 \
        2>&1 | tee -a "$LOG_FILE" >/dev/null || abort "Failed to install deps"
    log_success "$(t deps_installed)"
}

#---------------------------------------
# CRÉATION GROUPE + USERS
#---------------------------------------
create_siem_group_and_users() {
    log_step "1/4" "$(t creating_group)"

    if ! getent group "$SIEM_GROUP" >/dev/null 2>&1; then
        groupadd "$SIEM_GROUP" || abort "Cannot create group"
    fi

    SIEM_IDS_PASSWORD=$(generate_password)
    if ! id "$SIEM_IDS_USER" >/dev/null 2>&1; then
        useradd -m -s /bin/bash -g "$SIEM_GROUP" "$SIEM_IDS_USER" || abort "Cannot create $SIEM_IDS_USER"
    else
        usermod -g "$SIEM_GROUP" "$SIEM_IDS_USER"
    fi
    echo "$SIEM_IDS_USER:$SIEM_IDS_PASSWORD" | chpasswd
    usermod -aG sudo "$SIEM_IDS_USER" 2>/dev/null || true

    SIEM_WAZUH_PASSWORD=$(generate_password)
    if ! id "$SIEM_WAZUH_USER" >/dev/null 2>&1; then
        useradd -m -s /bin/bash -g "$SIEM_GROUP" "$SIEM_WAZUH_USER" || abort "Cannot create $SIEM_WAZUH_USER"
    else
        usermod -g "$SIEM_GROUP" "$SIEM_WAZUH_USER"
    fi
    echo "$SIEM_WAZUH_USER:$SIEM_WAZUH_PASSWORD" | chpasswd
    usermod -aG sudo "$SIEM_WAZUH_USER" 2>/dev/null || true

    log_success "$(t group_created)"
}

#---------------------------------------
# SNORT
#---------------------------------------
install_snort() {
    log_step "2/4" "$(t installing_snort)"
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    [ -z "$INTERFACE" ] && INTERFACE="eth0"
    echo "snort snort/interface string $INTERFACE" | debconf-set-selections
    echo "snort snort/address_range string any/any" | debconf-set-selections
    echo "snort snort/startup string boot" | debconf-set-selections
    DEBIAN_FRONTEND=noninteractive apt install -y snort 2>&1 | tee -a "$LOG_FILE" >/dev/null || \
        abort "Cannot install Snort"
    log_success "$(t snort_installed)"
}

configure_snort() {
    log_info "$(t configuring_snort)"
    LOCAL_NET=$(ip route | grep -oP 'src \K[\d.]+' | head -1 | sed 's/\.[0-9]*$/.0\/24/')
    [ -z "$LOCAL_NET" ] && LOCAL_NET="192.168.1.0/24"
    if [ -f "$SNORT_CONF" ]; then
        sed -i "s|ipvar HOME_NET any|ipvar HOME_NET $LOCAL_NET|g" "$SNORT_CONF"
        sed -i "s|var HOME_NET any|var HOME_NET $LOCAL_NET|g" "$SNORT_CONF"
    fi
    mkdir -p /var/log/snort /etc/snort/rules
    chown -R "$SIEM_IDS_USER":"$SIEM_GROUP" /var/log/snort /etc/snort 2>/dev/null || true
    chmod 770 /var/log/snort

    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    [ -z "$INTERFACE" ] && INTERFACE="eth0"

    cat > /etc/systemd/system/snort.service <<EOF
[Unit]
Description=SIEM Africa - Snort IDS (Lite)
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/sbin/snort -q -c /etc/snort/snort.conf -i $INTERFACE -A fast
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable snort 2>/dev/null || true
    systemctl start snort 2>/dev/null || log_warning "Snort not started"

    log_success "$(t snort_configured) - Interface: $INTERFACE, HOME_NET: $LOCAL_NET"
}

#---------------------------------------
# WAZUH MANAGER (SEUL, pas de all-in-one)
#---------------------------------------
install_wazuh_manager_only() {
    log_step "3/4" "$(t installing_wazuh)"

    # Ajout dépôt Wazuh
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
        gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import 2>/dev/null
    chmod 644 /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list

    apt update -qq 2>&1 | tee -a "$LOG_FILE" >/dev/null || abort "apt update failed after adding Wazuh repo"

    # Installation Manager seul
    DEBIAN_FRONTEND=noninteractive apt install -y wazuh-manager 2>&1 | tee -a "$LOG_FILE" >/dev/null || \
        abort "Cannot install wazuh-manager"

    if [ ! -d /var/ossec ]; then
        abort "Wazuh Manager installed but /var/ossec missing"
    fi

    systemctl daemon-reload
    systemctl enable wazuh-manager 2>/dev/null || true
    systemctl start wazuh-manager 2>&1 | tee -a "$LOG_FILE" >/dev/null

    sleep 5
    if ! systemctl is-active --quiet wazuh-manager; then
        abort "Wazuh Manager failed to start"
    fi

    # Ajout wazuh au groupe siem-africa
    if id wazuh >/dev/null 2>&1; then
        usermod -aG "$SIEM_GROUP" wazuh 2>/dev/null || true
    fi

    log_success "$(t wazuh_installed)"
}

#---------------------------------------
# INTÉGRATION
#---------------------------------------
configure_integration() {
    log_step "4/4" "$(t configuring_integration)"
    OSSEC_CONF="/var/ossec/etc/ossec.conf"
    [ ! -f "$OSSEC_CONF" ] && abort "ossec.conf not found"

    if ! grep -q "/var/log/snort/alert" "$OSSEC_CONF"; then
        sed -i '/<\/ossec_config>/i \  <localfile>\n    <log_format>snort-full</log_format>\n    <location>/var/log/snort/alert</location>\n  </localfile>' "$OSSEC_CONF"
    fi

    systemctl restart wazuh-manager 2>&1 | tee -a "$LOG_FILE" >/dev/null || \
        abort "Cannot restart wazuh-manager"

    log_success "$(t integration_done)"
}

#---------------------------------------
# CREDENTIALS FILE
#---------------------------------------
create_credentials_file() {
    log_info "$(t creating_credentials)"

    SERVER_IP=$(hostname -I | awk '{print $1}')
    HOSTNAME=$(hostname)
    DATE=$(date '+%Y-%m-%d %H:%M:%S')
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    LOCAL_NET=$(ip route | grep -oP 'src \K[\d.]+' | head -1 | sed 's/\.[0-9]*$/.0\/24/')
    [ -z "$INTERFACE" ] && INTERFACE="eth0"
    [ -z "$LOCAL_NET" ] && LOCAL_NET="192.168.1.0/24"

    cat > "$CREDENTIALS_FILE" <<EOF
╔══════════════════════════════════════════════════════════════════╗
║                SIEM AFRICA - CREDENTIALS                         ║
║                     MODULE 1 - LITE                              ║
╚══════════════════════════════════════════════════════════════════╝

Date installation : $DATE
Mode              : LITE (Snort + Wazuh Manager uniquement)
Serveur IP        : $SERVER_IP
Hostname          : $HOSTNAME
Langue            : $([ "$LANG_CODE" = "en" ] && echo "English" || echo "Français")

══════════════════════════════════════════════════════════════════
USERS SYSTÈME
══════════════════════════════════════════════════════════════════
Username   : $SIEM_IDS_USER
Password   : $SIEM_IDS_PASSWORD
Sudo       : oui
Rôle       : Gestion Snort IDS

Username   : $SIEM_WAZUH_USER
Password   : $SIEM_WAZUH_PASSWORD
Sudo       : oui
Rôle       : Gestion Wazuh SIEM

══════════════════════════════════════════════════════════════════
GROUPE PARTAGÉ
══════════════════════════════════════════════════════════════════
Nom        : $SIEM_GROUP
Usage      : Partage des permissions entre Module 2, 3, 4

══════════════════════════════════════════════════════════════════
PAS DE DASHBOARD WEB DANS CETTE VERSION
══════════════════════════════════════════════════════════════════
La version LITE n'installe PAS le Wazuh Dashboard.
Pour consulter les alertes, utilisez la ligne de commande :

  sudo tail -f /var/ossec/logs/alerts/alerts.json
  sudo tail -f /var/log/snort/alert

Pour avoir le dashboard web, utilisez le script FULL :
  sudo ./install_module1_full.sh

══════════════════════════════════════════════════════════════════
SNORT IDS
══════════════════════════════════════════════════════════════════
Interface  : $INTERFACE
Home Net   : $LOCAL_NET
Config     : /etc/snort/snort.conf
Logs       : /var/log/snort/alert
Service    : systemctl status snort

══════════════════════════════════════════════════════════════════
WAZUH MANAGER
══════════════════════════════════════════════════════════════════
Service    : systemctl status wazuh-manager
Config     : /var/ossec/etc/ossec.conf
Logs       : /var/ossec/logs/ossec.log
Alertes    : /var/ossec/logs/alerts/alerts.json

══════════════════════════════════════════════════════════════════
PORTS UTILISÉS (LITE)
══════════════════════════════════════════════════════════════════
1514  - Wazuh Agent communication
1515  - Wazuh Agent enrollment
55000 - Wazuh API

(Pas de 443 ni 9200 : pas de Dashboard ni Indexer)

══════════════════════════════════════════════════════════════════
FICHIERS IMPORTANTS
══════════════════════════════════════════════════════════════════
$CREDENTIALS_FILE  - Ce fichier
/var/log/siem-install.log          - Log d'installation

══════════════════════════════════════════════════════════════════
COMMANDES DE VÉRIFICATION
══════════════════════════════════════════════════════════════════
État :
  sudo systemctl status snort wazuh-manager

Alertes temps réel :
  sudo tail -f /var/log/snort/alert
  sudo tail -f /var/ossec/logs/alerts/alerts.json

══════════════════════════════════════════════════════════════════
⚠️  Ce fichier contient des mots de passe : chmod 600 appliqué.
══════════════════════════════════════════════════════════════════
EOF

    chmod 600 "$CREDENTIALS_FILE"
    log_success "$(t credentials_created) : $CREDENTIALS_FILE"
}

#---------------------------------------
# RÉSUMÉ FINAL
#---------------------------------------
show_summary() {
    SERVER_IP=$(hostname -I | awk '{print $1}')

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    printf "${GREEN}║${NC}  ${BOLD}%-62s${NC}  ${GREEN}║${NC}\n" "✓ $(t install_complete) (LITE)"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                        UTILISATEURS                                ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  • ${YELLOW}$SIEM_IDS_USER${NC}    / ${GREEN}$SIEM_IDS_PASSWORD${NC}"
    echo -e "  • ${YELLOW}$SIEM_WAZUH_USER${NC}  / ${GREEN}$SIEM_WAZUH_PASSWORD${NC}"
    echo ""

    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                        SERVICES                                    ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    for service in snort wazuh-manager; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            echo -e "  $service : ${GREEN}● Actif${NC}"
        else
            echo -e "  $service : ${RED}○ Inactif${NC}"
        fi
    done
    echo ""

    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                        CREDENTIALS                                 ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Fichier : ${YELLOW}$CREDENTIALS_FILE${NC}"
    echo -e "  Voir    : ${GREEN}sudo cat $CREDENTIALS_FILE${NC}"
    echo ""

    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                   ALERTES TEMPS RÉEL                               ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${GREEN}sudo tail -f /var/log/snort/alert${NC}"
    echo -e "  ${GREEN}sudo tail -f /var/ossec/logs/alerts/alerts.json${NC}"
    echo ""

    echo -e "${YELLOW}  ℹ️  Pas de dashboard web dans LITE. Pour le dashboard : script FULL.${NC}"
    echo ""
}

#---------------------------------------
# MAIN
#---------------------------------------
main() {
    echo "=== SIEM Africa - Module 1 LITE - $(date) ===" > "$LOG_FILE"

    parse_args "$@"
    choose_language
    show_banner

    echo -e "${CYAN}$(t section_checks)${NC}"
    echo "─────────────────────────────────────────────────────────────────"
    check_root
    check_os
    check_ram
    check_disk
    check_cpu
    check_internet
    echo ""

    echo -e "${CYAN}$(t section_cleanup)${NC}"
    echo "─────────────────────────────────────────────────────────────────"
    check_existing
    echo ""

    echo -e "${CYAN}$(t section_prep)${NC}"
    echo "─────────────────────────────────────────────────────────────────"
    update_system
    install_dependencies
    echo ""

    echo -e "${CYAN}$(t section_install)${NC}"
    echo "─────────────────────────────────────────────────────────────────"
    create_siem_group_and_users
    echo ""
    install_snort
    configure_snort
    echo ""
    install_wazuh_manager_only
    echo ""
    configure_integration
    echo ""
    create_credentials_file
    echo ""

    show_summary

    log_info "Installation LITE terminée - $(date)"
}

main "$@"
