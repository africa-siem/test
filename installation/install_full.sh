#!/bin/bash
#===============================================================================
#
#          FILE: install_module1_full.sh
#
#   DESCRIPTION: SIEM Africa - Module 1 FULL
#                Installation complète : Snort + Wazuh (Manager + Indexer + Dashboard)
#
#         USAGE: sudo ./install_module1_full.sh [--lang fr|en]
#
#   COMPORTEMENT :
#   - Si prérequis non rempli → ARRÊT IMMÉDIAT
#   - Si installation existante → PURGE TOTALE puis REINSTALLE
#   - Tous les credentials stockés dans /root/siem_credentials.txt
#
#       CONFIG MINIMALE : 4 Go RAM, 30 Go disque, 2 cœurs CPU
#       CONFIG RECOMMANDÉE : 8 Go RAM, 50 Go disque, 4 cœurs CPU
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
MIN_RAM=4
MIN_DISK=30
MIN_CPU=2
RETRY_COUNT=3

# Groupe et users SIEM Africa
SIEM_GROUP="siem-africa"
SIEM_IDS_USER="siem-ids"       # User qui gère Snort
SIEM_WAZUH_USER="siem-wazuh"   # User qui gère Wazuh

# Mots de passe générés au runtime
SIEM_IDS_PASSWORD=""
SIEM_WAZUH_PASSWORD=""
WAZUH_ADMIN_PASSWORD=""

# Langue (par défaut FR)
LANG_CODE="fr"

#---------------------------------------
# TRADUCTIONS
#---------------------------------------
t() {
    local key=$1
    if [ "$LANG_CODE" = "en" ]; then
        case "$key" in
            "banner_title")        echo "SIEM AFRICA - MODULE 1 FULL INSTALLATION" ;;
            "banner_subtitle")     echo "Snort IDS + Wazuh SIEM (Manager + Indexer + Dashboard)" ;;
            "section_checks")      echo "[REQUIRED CHECKS]" ;;
            "section_cleanup")     echo "[CHECKING EXISTING INSTALLATION]" ;;
            "section_prep")        echo "[SYSTEM PREPARATION]" ;;
            "section_install")     echo "[INSTALLATION]" ;;
            "root_ok")             echo "Running as root" ;;
            "os_compatible")       echo "Compatible OS" ;;
            "ram_ok")              echo "RAM" ;;
            "disk_ok")             echo "Disk space" ;;
            "cpu_ok")              echo "CPU cores" ;;
            "internet_ok")         echo "Internet connection OK" ;;
            "checking_internet")   echo "Checking internet connection..." ;;
            "no_existing")         echo "No existing installation" ;;
            "existing_detected")   echo "Existing installation detected → removing and reinstalling" ;;
            "cleanup_done")        echo "Cleanup completed" ;;
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
            "installing_wazuh")    echo "Installing Wazuh $WAZUH_VERSION (this will take 10-20 minutes)..." ;;
            "wazuh_attempt")       echo "Attempt" ;;
            "wazuh_installed")     echo "Wazuh installed" ;;
            "configuring_integration") echo "Configuring Snort ↔ Wazuh integration..." ;;
            "integration_done")    echo "Integration configured" ;;
            "creating_credentials") echo "Creating credentials file..." ;;
            "credentials_created") echo "Credentials saved to" ;;
            "install_complete")    echo "INSTALLATION COMPLETED SUCCESSFULLY" ;;
            "install_aborted")     echo "INSTALLATION ABORTED" ;;
            "reason")              echo "Reason:" ;;
            "log_location")        echo "Log:" ;;
            "access_dashboard")    echo "WAZUH DASHBOARD ACCESS" ;;
            "url")                 echo "URL" ;;
            "user")                echo "User" ;;
            "users_created")       echo "CREATED USERS" ;;
            "services_status")     echo "SERVICES STATUS" ;;
            "active")              echo "Active" ;;
            "inactive")            echo "Inactive" ;;
            "credentials_heading") echo "CREDENTIALS FILE" ;;
            "all_passwords")       echo "All passwords:" ;;
            "to_view")             echo "To view:" ;;
            "verification_cmds")   echo "VERIFICATION COMMANDS" ;;
            "ports_used")          echo "USED PORTS" ;;
            "important_files")     echo "IMPORTANT FILES" ;;
            "ssl_note")            echo "Note: SSL certificate is self-signed." ;;
            *)                     echo "$key" ;;
        esac
    else
        case "$key" in
            "banner_title")        echo "SIEM AFRICA - INSTALLATION MODULE 1 FULL" ;;
            "banner_subtitle")     echo "Snort IDS + Wazuh SIEM (Manager + Indexer + Dashboard)" ;;
            "section_checks")      echo "[VÉRIFICATIONS OBLIGATOIRES]" ;;
            "section_cleanup")     echo "[VÉRIFICATION INSTALLATION EXISTANTE]" ;;
            "section_prep")        echo "[PRÉPARATION SYSTÈME]" ;;
            "section_install")     echo "[INSTALLATION]" ;;
            "root_ok")             echo "Exécution en tant que root" ;;
            "os_compatible")       echo "OS compatible" ;;
            "ram_ok")              echo "RAM" ;;
            "disk_ok")             echo "Espace disque" ;;
            "cpu_ok")              echo "Cœurs CPU" ;;
            "internet_ok")         echo "Connexion Internet OK" ;;
            "checking_internet")   echo "Vérification connexion Internet..." ;;
            "no_existing")         echo "Aucune installation existante" ;;
            "existing_detected")   echo "Installation existante détectée → suppression et réinstallation" ;;
            "cleanup_done")        echo "Nettoyage terminé" ;;
            "updating_system")     echo "Mise à jour système..." ;;
            "system_updated")      echo "Système mis à jour" ;;
            "installing_deps")     echo "Installation des dépendances..." ;;
            "deps_installed")      echo "Dépendances installées" ;;
            "creating_group")      echo "Création du groupe et des users SIEM Africa..." ;;
            "group_created")       echo "Groupe et users créés" ;;
            "installing_snort")    echo "Installation de Snort..." ;;
            "snort_installed")     echo "Snort installé" ;;
            "configuring_snort")   echo "Configuration de Snort..." ;;
            "snort_configured")    echo "Snort configuré" ;;
            "installing_wazuh")    echo "Installation de Wazuh $WAZUH_VERSION (10-20 minutes)..." ;;
            "wazuh_attempt")       echo "Tentative" ;;
            "wazuh_installed")     echo "Wazuh installé" ;;
            "configuring_integration") echo "Configuration intégration Snort ↔ Wazuh..." ;;
            "integration_done")    echo "Intégration configurée" ;;
            "creating_credentials") echo "Création du fichier credentials..." ;;
            "credentials_created") echo "Credentials sauvegardés dans" ;;
            "install_complete")    echo "INSTALLATION TERMINÉE AVEC SUCCÈS" ;;
            "install_aborted")     echo "INSTALLATION ARRÊTÉE" ;;
            "reason")              echo "Raison :" ;;
            "log_location")        echo "Log :" ;;
            "access_dashboard")    echo "ACCÈS AU DASHBOARD WAZUH" ;;
            "url")                 echo "URL" ;;
            "user")                echo "Utilisateur" ;;
            "users_created")       echo "UTILISATEURS CRÉÉS" ;;
            "services_status")     echo "ÉTAT DES SERVICES" ;;
            "active")              echo "Actif" ;;
            "inactive")            echo "Inactif" ;;
            "credentials_heading") echo "FICHIER CREDENTIALS" ;;
            "all_passwords")       echo "Tous les mots de passe :" ;;
            "to_view")             echo "Pour afficher :" ;;
            "verification_cmds")   echo "COMMANDES DE VÉRIFICATION" ;;
            "ports_used")          echo "PORTS UTILISÉS" ;;
            "important_files")     echo "FICHIERS IMPORTANTS" ;;
            "ssl_note")            echo "Note : Le certificat SSL est auto-signé." ;;
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
log_step()    { log "${BLUE}[$(t section_install) - $1]${NC} $2"; }

#---------------------------------------
# ABORT (arrêt propre)
#---------------------------------------
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

#---------------------------------------
# GÉNÉRATEUR DE MOT DE PASSE
#---------------------------------------
generate_password() {
    # Génère un mot de passe aléatoire de 16 caractères alphanumériques
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16
}

#---------------------------------------
# PARSE ARGUMENTS (--lang fr|en)
#---------------------------------------
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --lang)
                LANG_CODE="$2"
                shift 2
                ;;
            --lang=*)
                LANG_CODE="${1#*=}"
                shift
                ;;
            *)
                shift
                ;;
        esac
    done
    # Validation
    if [ "$LANG_CODE" != "fr" ] && [ "$LANG_CODE" != "en" ]; then
        LANG_CODE="fr"
    fi
}

#---------------------------------------
# CHOIX DE LANGUE INTERACTIF (si --lang absent)
#---------------------------------------
choose_language() {
    # Si appelé depuis un pipe (curl | bash), ne pas demander (défaut FR)
    if [ ! -t 0 ]; then
        return 0
    fi

    # Si la langue a été passée en argument, ne pas redemander
    if [ -n "${LANG_FORCED:-}" ]; then
        return 0
    fi

    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}Choix de la langue / Language selection${NC}                        ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "  [1] Français (défaut)"
    echo "  [2] English"
    echo ""
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
    echo "║         🛡️   SIEM AFRICA - MODULE 1 (FULL)                      ║"
    echo "║                                                                  ║"
    echo "║         Snort IDS + Wazuh (Manager + Indexer + Dashboard)        ║"
    echo "║                                                                  ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
}

#---------------------------------------
# CHECK : ROOT
#---------------------------------------
check_root() {
    if [ "$EUID" -ne 0 ]; then
        abort "$(t reason) Must be run as root (sudo)"
    fi
    log_success "$(t root_ok)"
}

#---------------------------------------
# CHECK : OS SUPPORTÉ
#---------------------------------------
check_os() {
    [ ! -f /etc/os-release ] && abort "Cannot detect OS"
    # shellcheck disable=SC1091
    . /etc/os-release
    case $ID in
        ubuntu)
            [[ "$VERSION_ID" != "20.04" && "$VERSION_ID" != "22.04" && "$VERSION_ID" != "24.04" ]] && \
                abort "Ubuntu $VERSION_ID not supported (20.04, 22.04, 24.04 only)"
            log_success "$(t os_compatible) : Ubuntu $VERSION_ID"
            ;;
        debian)
            [[ "$VERSION_ID" != "11" && "$VERSION_ID" != "12" ]] && \
                abort "Debian $VERSION_ID not supported (11, 12 only)"
            log_success "$(t os_compatible) : Debian $VERSION_ID"
            ;;
        *)
            abort "OS not supported: $ID (Ubuntu/Debian only)"
            ;;
    esac
}

#---------------------------------------
# CHECK : RAM
#---------------------------------------
check_ram() {
    TOTAL_RAM=$(free -g | awk '/^Mem:/{print $2}')
    [ "$TOTAL_RAM" -lt "$MIN_RAM" ] && abort "RAM insuffisante : ${TOTAL_RAM}Go (minimum ${MIN_RAM}Go)"
    log_success "$(t ram_ok) : ${TOTAL_RAM} Go"
}

#---------------------------------------
# CHECK : DISQUE
#---------------------------------------
check_disk() {
    AVAILABLE_DISK=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    [ "$AVAILABLE_DISK" -lt "$MIN_DISK" ] && abort "Disque insuffisant : ${AVAILABLE_DISK}Go (minimum ${MIN_DISK}Go)"
    log_success "$(t disk_ok) : ${AVAILABLE_DISK} Go"
}

#---------------------------------------
# CHECK : CPU
#---------------------------------------
check_cpu() {
    CPU_CORES=$(nproc)
    [ "$CPU_CORES" -lt "$MIN_CPU" ] && abort "CPU insuffisant : ${CPU_CORES} cœur(s) (minimum ${MIN_CPU})"
    log_success "$(t cpu_ok) : ${CPU_CORES}"
}

#---------------------------------------
# CHECK : INTERNET
#---------------------------------------
check_internet() {
    log_info "$(t checking_internet)"
    ping -c 3 8.8.8.8 &>/dev/null || abort "No Internet connection"
    if ! ping -c 3 google.com &>/dev/null; then
        log_warning "DNS issue - fixing..."
        echo -e "nameserver 8.8.8.8\nnameserver 8.8.4.4" > /etc/resolv.conf
        ping -c 3 google.com &>/dev/null || abort "DNS not working"
    fi
    curl -s --head --connect-timeout 10 https://packages.wazuh.com &>/dev/null || \
        abort "Cannot reach Wazuh repositories"
    log_success "$(t internet_ok)"
}

#---------------------------------------
# CLEANUP : PURGE TOTALE
#---------------------------------------
cleanup_all() {
    log_info "Nettoyage complet en cours..."

    # Arrêt des services
    systemctl stop snort wazuh-manager wazuh-indexer wazuh-dashboard filebeat 2>/dev/null || true
    systemctl disable snort wazuh-manager wazuh-indexer wazuh-dashboard filebeat 2>/dev/null || true

    # Kill processus résiduels
    pkill -9 snort 2>/dev/null || true
    pkill -9 -f 'ossec-' 2>/dev/null || true
    pkill -9 -f 'wazuh-' 2>/dev/null || true
    pkill -9 -f 'opensearch' 2>/dev/null || true
    pkill -9 -f 'filebeat' 2>/dev/null || true

    # Suppression des paquets
    DEBIAN_FRONTEND=noninteractive apt remove --purge -y \
        snort snort-common snort-rules-default \
        wazuh-manager wazuh-indexer wazuh-dashboard wazuh-agent \
        filebeat 2>/dev/null || true

    # Suppression des dossiers
    rm -rf /var/ossec
    rm -rf /etc/wazuh-indexer /var/lib/wazuh-indexer /usr/share/wazuh-indexer
    rm -rf /etc/wazuh-dashboard /usr/share/wazuh-dashboard /var/lib/wazuh-dashboard
    rm -rf /etc/filebeat /var/lib/filebeat /usr/share/filebeat
    rm -rf /etc/snort /var/log/snort /var/run/snort

    # Nettoyage fichiers d'install
    rm -f /root/wazuh-install.sh /root/wazuh-install-files.tar
    rm -f wazuh-install.sh wazuh-install-files.tar
    rm -f /etc/systemd/system/snort.service
    rm -f /var/log/wazuh-install.log

    # Reload systemd
    systemctl daemon-reload
    systemctl reset-failed 2>/dev/null || true

    # Nettoyage apt
    DEBIAN_FRONTEND=noninteractive apt autoremove -y 2>/dev/null || true
    DEBIAN_FRONTEND=noninteractive apt clean 2>/dev/null || true

    log_success "$(t cleanup_done)"
}

#---------------------------------------
# CHECK : INSTALLATION EXISTANTE
#---------------------------------------
check_existing() {
    log_info "Vérification installations existantes..."
    if dpkg -l 2>/dev/null | grep -qE "snort|wazuh" || \
       [ -d "/etc/snort" ] || \
       [ -d "/var/ossec" ] || \
       [ -d "/etc/wazuh-indexer" ]; then
        log_warning "$(t existing_detected)"
        cleanup_all
    else
        log_success "$(t no_existing)"
    fi
}

#---------------------------------------
# UPDATE SYSTEM
#---------------------------------------
update_system() {
    log_info "$(t updating_system)"
    apt update -qq 2>&1 | tee -a "$LOG_FILE" >/dev/null || abort "APT update failed"
    DEBIAN_FRONTEND=noninteractive apt upgrade -y -qq 2>&1 | tee -a "$LOG_FILE" >/dev/null || \
        log_warning "System upgrade had issues (continuing...)"
    log_success "$(t system_updated)"
}

#---------------------------------------
# INSTALL DEPENDENCIES
#---------------------------------------
install_dependencies() {
    log_info "$(t installing_deps)"
    DEBIAN_FRONTEND=noninteractive apt install -y -qq \
        curl wget gnupg apt-transport-https lsb-release ca-certificates \
        software-properties-common net-tools jq iproute2 \
        2>&1 | tee -a "$LOG_FILE" >/dev/null || abort "Failed to install dependencies"
    log_success "$(t deps_installed)"
}

#---------------------------------------
# CRÉATION GROUPE + USERS
#---------------------------------------
create_siem_group_and_users() {
    log_step "1/5" "$(t creating_group)"

    # 1. Groupe siem-africa (partagé par Module 2, 3, 4)
    if ! getent group "$SIEM_GROUP" >/dev/null 2>&1; then
        groupadd "$SIEM_GROUP" || abort "Cannot create group $SIEM_GROUP"
    fi

    # 2. User siem-ids (Snort)
    SIEM_IDS_PASSWORD=$(generate_password)
    if ! id "$SIEM_IDS_USER" >/dev/null 2>&1; then
        useradd -m -s /bin/bash -g "$SIEM_GROUP" "$SIEM_IDS_USER" || \
            abort "Cannot create user $SIEM_IDS_USER"
    else
        usermod -g "$SIEM_GROUP" "$SIEM_IDS_USER"
    fi
    echo "$SIEM_IDS_USER:$SIEM_IDS_PASSWORD" | chpasswd
    usermod -aG sudo "$SIEM_IDS_USER" 2>/dev/null || true

    # 3. User siem-wazuh (Wazuh)
    SIEM_WAZUH_PASSWORD=$(generate_password)
    if ! id "$SIEM_WAZUH_USER" >/dev/null 2>&1; then
        useradd -m -s /bin/bash -g "$SIEM_GROUP" "$SIEM_WAZUH_USER" || \
            abort "Cannot create user $SIEM_WAZUH_USER"
    else
        usermod -g "$SIEM_GROUP" "$SIEM_WAZUH_USER"
    fi
    echo "$SIEM_WAZUH_USER:$SIEM_WAZUH_PASSWORD" | chpasswd
    usermod -aG sudo "$SIEM_WAZUH_USER" 2>/dev/null || true

    log_success "$(t group_created)"
    log_info "  - Groupe : $SIEM_GROUP"
    log_info "  - Users  : $SIEM_IDS_USER, $SIEM_WAZUH_USER"
}

#---------------------------------------
# INSTALLATION SNORT
#---------------------------------------
install_snort() {
    log_step "2/5" "$(t installing_snort)"

    # Pré-config : répondre aux prompts debconf de Snort
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    [ -z "$INTERFACE" ] && INTERFACE="eth0"

    echo "snort snort/interface string $INTERFACE" | debconf-set-selections
    echo "snort snort/address_range string any/any" | debconf-set-selections
    echo "snort snort/startup string boot" | debconf-set-selections

    DEBIAN_FRONTEND=noninteractive apt install -y snort 2>&1 | tee -a "$LOG_FILE" >/dev/null || \
        abort "Cannot install Snort"

    log_success "$(t snort_installed)"
}

#---------------------------------------
# CONFIGURATION SNORT
#---------------------------------------
configure_snort() {
    log_info "$(t configuring_snort)"

    # Détection du réseau local
    LOCAL_NET=$(ip route | grep -oP 'src \K[\d.]+' | head -1 | sed 's/\.[0-9]*$/.0\/24/')
    [ -z "$LOCAL_NET" ] && LOCAL_NET="192.168.1.0/24"

    # Config HOME_NET
    if [ -f "$SNORT_CONF" ]; then
        sed -i "s|ipvar HOME_NET any|ipvar HOME_NET $LOCAL_NET|g" "$SNORT_CONF"
        sed -i "s|var HOME_NET any|var HOME_NET $LOCAL_NET|g" "$SNORT_CONF"
    fi

    # Dossiers de logs
    mkdir -p /var/log/snort /etc/snort/rules
    chown -R "$SIEM_IDS_USER":"$SIEM_GROUP" /var/log/snort /etc/snort 2>/dev/null || true
    chmod 770 /var/log/snort

    # Interface de détection
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    [ -z "$INTERFACE" ] && INTERFACE="eth0"

    # Service systemd custom
    cat > /etc/systemd/system/snort.service <<EOF
[Unit]
Description=SIEM Africa - Snort IDS
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
    systemctl start snort 2>/dev/null || log_warning "Snort not started (will be retried)"

    log_success "$(t snort_configured) - Interface: $INTERFACE, HOME_NET: $LOCAL_NET"
}

#---------------------------------------
# INSTALLATION WAZUH (avec retry)
#---------------------------------------
install_wazuh() {
    log_step "3/5" "$(t installing_wazuh)"

    # Téléchargement du script officiel Wazuh
    cd /root || cd /tmp
    curl -sO "https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh" || \
        abort "Cannot download Wazuh installer"
    chmod +x wazuh-install.sh

    local attempt=1
    local success=false

    while [ "$attempt" -le "$RETRY_COUNT" ]; do
        log_info "$(t wazuh_attempt) $attempt/$RETRY_COUNT..."

        if bash wazuh-install.sh -a -i >> "$LOG_FILE" 2>&1; then
            success=true
            break
        fi

        log_warning "$(t wazuh_attempt) $attempt $(t wazuh_attempt)... échouée"

        if [ "$attempt" -lt "$RETRY_COUNT" ]; then
            # Cleanup partiel avant retry
            systemctl stop wazuh-manager wazuh-indexer wazuh-dashboard 2>/dev/null || true
            apt remove --purge -y wazuh-manager wazuh-indexer wazuh-dashboard 2>/dev/null || true
            rm -rf /var/ossec /etc/wazuh-indexer /var/lib/wazuh-indexer wazuh-install-files.tar
            sleep 5
        fi

        attempt=$((attempt + 1))
    done

    if [ "$success" = false ]; then
        abort "Wazuh installation failed after $RETRY_COUNT attempts"
    fi

    log_success "$(t wazuh_installed)"

    # Backup des fichiers d'install Wazuh
    [ -f "wazuh-install-files.tar" ] && cp wazuh-install-files.tar /root/

    # Intégration du user wazuh au groupe siem-africa
    if id wazuh >/dev/null 2>&1; then
        usermod -aG "$SIEM_GROUP" wazuh 2>/dev/null || true
    fi
}

#---------------------------------------
# CONFIGURATION INTÉGRATION SNORT ↔ WAZUH
#---------------------------------------
configure_integration() {
    log_step "4/5" "$(t configuring_integration)"

    OSSEC_CONF="/var/ossec/etc/ossec.conf"
    [ ! -f "$OSSEC_CONF" ] && abort "ossec.conf not found"

    # Ajoute le localfile Snort dans ossec.conf si pas déjà présent
    if ! grep -q "/var/log/snort/alert" "$OSSEC_CONF"; then
        sed -i '/<\/ossec_config>/i \  <localfile>\n    <log_format>snort-full</log_format>\n    <location>/var/log/snort/alert</location>\n  </localfile>' "$OSSEC_CONF"
    fi

    systemctl restart wazuh-manager 2>&1 | tee -a "$LOG_FILE" >/dev/null || \
        abort "Cannot restart wazuh-manager"

    log_success "$(t integration_done)"
}

#---------------------------------------
# EXTRACTION DU MOT DE PASSE ADMIN WAZUH
#---------------------------------------
extract_wazuh_admin_password() {
    WAZUH_ADMIN_PASSWORD="N/A (check /root/wazuh-install-files.tar)"
    if [ -f "/root/wazuh-install-files.tar" ]; then
        mkdir -p /tmp/wazuh-extract
        tar -xf /root/wazuh-install-files.tar -C /tmp/wazuh-extract 2>/dev/null || true
        if [ -f "/tmp/wazuh-extract/wazuh-install-files/wazuh-passwords.txt" ]; then
            # Extraction du mot de passe admin
            WAZUH_ADMIN_PASSWORD=$(grep -A1 "'admin'" /tmp/wazuh-extract/wazuh-install-files/wazuh-passwords.txt 2>/dev/null | \
                grep "password" | head -1 | sed "s/.*password: '//" | sed "s/'.*//")
            [ -z "$WAZUH_ADMIN_PASSWORD" ] && WAZUH_ADMIN_PASSWORD="N/A (check wazuh-passwords.txt)"
        fi
        rm -rf /tmp/wazuh-extract
    fi
}

#---------------------------------------
# CRÉATION DU FICHIER CREDENTIALS
#---------------------------------------
create_credentials_file() {
    log_step "5/5" "$(t creating_credentials)"

    extract_wazuh_admin_password

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
║                     MODULE 1 - FULL                              ║
╚══════════════════════════════════════════════════════════════════╝

Date installation : $DATE
Mode              : FULL (Snort + Wazuh Manager + Indexer + Dashboard)
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
Membres    : $SIEM_IDS_USER, $SIEM_WAZUH_USER, wazuh

══════════════════════════════════════════════════════════════════
WAZUH DASHBOARD
══════════════════════════════════════════════════════════════════
URL        : https://$SERVER_IP
Username   : admin
Password   : $WAZUH_ADMIN_PASSWORD

Certificat : Auto-signé (accepter dans le navigateur)

══════════════════════════════════════════════════════════════════
SNORT IDS
══════════════════════════════════════════════════════════════════
Interface  : $INTERFACE
Home Net   : $LOCAL_NET
Config     : /etc/snort/snort.conf
Logs       : /var/log/snort/alert
Service    : systemctl status snort

══════════════════════════════════════════════════════════════════
WAZUH SIEM
══════════════════════════════════════════════════════════════════
Manager    : systemctl status wazuh-manager
Indexer    : systemctl status wazuh-indexer
Dashboard  : systemctl status wazuh-dashboard
Config     : /var/ossec/etc/ossec.conf
Logs       : /var/ossec/logs/ossec.log
Alertes    : /var/ossec/logs/alerts/alerts.json

══════════════════════════════════════════════════════════════════
PORTS UTILISÉS
══════════════════════════════════════════════════════════════════
443   - Wazuh Dashboard (HTTPS)
1514  - Wazuh Agent communication
1515  - Wazuh Agent enrollment
9200  - Wazuh Indexer (OpenSearch)
55000 - Wazuh API

══════════════════════════════════════════════════════════════════
FICHIERS IMPORTANTS
══════════════════════════════════════════════════════════════════
$CREDENTIALS_FILE       - Ce fichier (lecture via 'cat')
/root/wazuh-install-files.tar    - Backup des fichiers Wazuh
/var/log/siem-install.log        - Log d'installation complet

══════════════════════════════════════════════════════════════════
COMMANDES DE VÉRIFICATION
══════════════════════════════════════════════════════════════════
État des services :
  sudo systemctl status snort wazuh-manager wazuh-indexer wazuh-dashboard

Test Dashboard :
  curl -k -s -o /dev/null -w '%{http_code}' https://localhost

Vérifier les ports :
  sudo ss -tlnp | grep -E '443|1514|1515|9200|55000'

Suivre les alertes en temps réel :
  sudo tail -f /var/log/snort/alert
  sudo tail -f /var/ossec/logs/alerts/alerts.json

══════════════════════════════════════════════════════════════════
⚠️  SÉCURITÉ
══════════════════════════════════════════════════════════════════
- Ce fichier contient des mots de passe : protégez-le (chmod 600)
- Changez tous les mots de passe en production
- Le certificat SSL est auto-signé : utilisez un vrai cert en prod
- Activez la 2FA sur le dashboard dès que possible

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
    printf "${GREEN}║${NC}  ${BOLD}%-62s${NC}  ${GREEN}║${NC}\n" "✓ $(t install_complete)"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                   $(t access_dashboard)                             ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  $(t url)        : ${GREEN}https://${SERVER_IP}${NC}"
    echo -e "  $(t user)       : ${YELLOW}admin${NC}"
    echo -e "  Password   : ${YELLOW}$WAZUH_ADMIN_PASSWORD${NC}"
    echo ""

    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                   $(t users_created)                                ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  • ${YELLOW}$SIEM_IDS_USER${NC}    / ${GREEN}$SIEM_IDS_PASSWORD${NC}    (sudo)"
    echo -e "  • ${YELLOW}$SIEM_WAZUH_USER${NC}  / ${GREEN}$SIEM_WAZUH_PASSWORD${NC}  (sudo)"
    echo -e "  • Groupe   : ${YELLOW}$SIEM_GROUP${NC}"
    echo ""

    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                   $(t services_status)                              ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    for service in snort wazuh-manager wazuh-indexer wazuh-dashboard; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            echo -e "  $service : ${GREEN}● $(t active)${NC}"
        else
            echo -e "  $service : ${RED}○ $(t inactive)${NC}"
        fi
    done
    echo ""

    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                   $(t credentials_heading)                          ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  $(t all_passwords) ${YELLOW}$CREDENTIALS_FILE${NC}"
    echo -e "  $(t to_view) ${GREEN}sudo cat $CREDENTIALS_FILE${NC}"
    echo ""

    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                   $(t ports_used)                                   ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  443    - Wazuh Dashboard (HTTPS)"
    echo -e "  1514   - Wazuh Agent communication"
    echo -e "  1515   - Wazuh Agent enrollment"
    echo -e "  9200   - Wazuh Indexer"
    echo -e "  55000  - Wazuh API"
    echo ""

    echo -e "${YELLOW}  ⚠️  $(t ssl_note)${NC}"
    echo ""
}

#---------------------------------------
# MAIN
#---------------------------------------
main() {
    # Log init
    echo "=== SIEM Africa - Module 1 FULL - $(date) ===" > "$LOG_FILE"

    # Parse args
    parse_args "$@"

    # Interactive language choice (if TTY)
    choose_language

    # Banner
    show_banner

    # Vérifications obligatoires
    echo -e "${CYAN}$(t section_checks)${NC}"
    echo "─────────────────────────────────────────────────────────────────"
    check_root
    check_os
    check_ram
    check_disk
    check_cpu
    check_internet
    echo ""

    # Cleanup si existant
    echo -e "${CYAN}$(t section_cleanup)${NC}"
    echo "─────────────────────────────────────────────────────────────────"
    check_existing
    echo ""

    # Préparation
    echo -e "${CYAN}$(t section_prep)${NC}"
    echo "─────────────────────────────────────────────────────────────────"
    update_system
    install_dependencies
    echo ""

    # Installation
    echo -e "${CYAN}$(t section_install)${NC}"
    echo "─────────────────────────────────────────────────────────────────"
    create_siem_group_and_users
    echo ""
    install_snort
    configure_snort
    echo ""
    install_wazuh
    echo ""
    configure_integration
    echo ""
    create_credentials_file
    echo ""

    # Résumé
    show_summary

    log_info "Installation terminée - $(date)"
}

main "$@"
