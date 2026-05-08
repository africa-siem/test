#!/bin/bash
#===============================================================================
#          FILE: install_full.sh
#   DESCRIPTION: SIEM Africa - Module 1 FULL (mode VERBOSE + port-aware)
#         USAGE: sudo ./install_full.sh [--lang fr|en]
#       CONFIG : 4 Go RAM, 30 Go disque, 2 cœurs CPU
#===============================================================================
# NOTE: set -e DESACTIVE

#--- COULEURS ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; MAGENTA='\033[0;35m'
BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

#--- VARIABLES ---
LOG_FILE="/var/log/siem-install.log"
CREDENTIALS_FILE="/root/siem_credentials.txt"
WAZUH_VERSION="4.7"
SNORT_CONF="/etc/snort/snort.conf"
MIN_RAM=4; MIN_DISK=30; MIN_CPU=2; RETRY_COUNT=3
SIEM_GROUP="siem-africa"
SIEM_IDS_USER="siem-ids"; SIEM_WAZUH_USER="siem-wazuh"
SIEM_IDS_PASSWORD=""; SIEM_WAZUH_PASSWORD=""; WAZUH_ADMIN_PASSWORD=""
LANG_CODE="fr"

# Ports Wazuh à libérer (FULL utilise 443, 1514, 1515, 9200, 9300, 9600, 55000)
WAZUH_PORTS=(443 1514 1515 9200 9300 9600 55000)

#--- LOG ---
log()         { echo -e "$1" | tee -a "$LOG_FILE" 2>/dev/null; }
log_success() { log "${GREEN}[✓]${NC} $1"; }
log_error()   { log "${RED}[✗]${NC} $1"; }
log_info()    { log "${CYAN}[i]${NC} $1"; }
log_warning() { log "${YELLOW}[!]${NC} $1"; }
log_step()    { log "${BLUE}[STEP $1]${NC} $2"; }
log_cmd()     { log "${MAGENTA}[CMD]${NC} ${DIM}$1${NC}"; }
sep()         { echo -e "${DIM}─────────────────────────────────────────────────────────────────${NC}"; }

abort() {
    echo ""
    echo -e "${RED}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║   ✗ INSTALLATION ARRÊTÉE                                       ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo -e "  ${YELLOW}Raison : $1${NC}"
    echo -e "  Log : $LOG_FILE"
    exit 1
}

generate_password() { tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16; }

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --lang) LANG_CODE="$2"; shift 2 ;;
            --lang=*) LANG_CODE="${1#*=}"; shift ;;
            *) shift ;;
        esac
    done
    if [ "$LANG_CODE" != "fr" ] && [ "$LANG_CODE" != "en" ]; then
        LANG_CODE="fr"
    fi
}

show_banner() {
    clear 2>/dev/null || true
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║         🛡️   SIEM AFRICA - MODULE 1 (FULL) - VERBOSE            ║"
    echo "║         Snort + Wazuh (Manager + Indexer + Dashboard)            ║"
    echo "║         Cleanup port-aware activé                                ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

#=========================================================================
# CHECKS PRÉREQUIS
#=========================================================================
check_root() {
    log_info "Vérification droits root (UID actuel : $EUID)..."
    if [ "$EUID" -ne 0 ]; then abort "Doit être lancé en root (sudo)"; fi
    log_success "Exécution en tant que root"
}

check_os() {
    log_info "Détection OS..."
    if [ ! -f /etc/os-release ]; then abort "OS non détecté"; fi
    . /etc/os-release
    log_info "OS : $ID $VERSION_ID ($PRETTY_NAME)"
    case $ID in
        ubuntu)
            if [ "$VERSION_ID" != "20.04" ] && [ "$VERSION_ID" != "22.04" ] && [ "$VERSION_ID" != "24.04" ]; then
                abort "Ubuntu $VERSION_ID non supporté"
            fi
            log_success "OS compatible : Ubuntu $VERSION_ID" ;;
        debian)
            if [ "$VERSION_ID" != "11" ] && [ "$VERSION_ID" != "12" ]; then
                abort "Debian $VERSION_ID non supporté"
            fi
            log_success "OS compatible : Debian $VERSION_ID" ;;
        *) abort "OS non supporté : $ID" ;;
    esac
}

check_ram() {
    log_info "Vérification RAM..."
    TOTAL_RAM=$(free -g | awk '/^Mem:/{print $2}')
    log_info "RAM : ${TOTAL_RAM} Go (min : ${MIN_RAM} Go)"
    if [ "$TOTAL_RAM" -lt "$MIN_RAM" ]; then abort "RAM insuffisante"; fi
    log_success "RAM : ${TOTAL_RAM} Go"
}

check_disk() {
    log_info "Vérification disque..."
    AVAILABLE=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    log_info "Disque libre : ${AVAILABLE} Go (min : ${MIN_DISK} Go)"
    if [ "$AVAILABLE" -lt "$MIN_DISK" ]; then abort "Disque insuffisant"; fi
    log_success "Disque : ${AVAILABLE} Go"
}

check_cpu() {
    log_info "Vérification CPU..."
    CORES=$(nproc)
    log_info "Cœurs : ${CORES} (min : ${MIN_CPU})"
    if [ "$CORES" -lt "$MIN_CPU" ]; then abort "CPU insuffisant"; fi
    log_success "Cœurs : ${CORES}"
}

check_internet() {
    log_info "Test ping 8.8.8.8..."
    if ! ping -c 3 8.8.8.8; then abort "Pas d'Internet"; fi
    log_info "Test ping google.com..."
    if ! ping -c 3 google.com; then
        log_warning "DNS HS - Application correctif..."
        echo -e "nameserver 8.8.8.8\nnameserver 8.8.4.4" > /etc/resolv.conf
        if ! ping -c 3 google.com; then abort "DNS non fonctionnel"; fi
    fi
    log_info "Test packages.wazuh.com..."
    if ! curl -sI --connect-timeout 10 https://packages.wazuh.com; then
        abort "Dépôt Wazuh inaccessible"
    fi
    log_success "Connexion Internet OK"
}

#=========================================================================
# CLEANUP PORT-AWARE
#=========================================================================

# Tue tout processus écoutant sur un port donné
kill_port() {
    local port=$1
    local pids
    pids=$(ss -tlnp 2>/dev/null | awk -v p=":$port" '$4 ~ p {print $NF}' | grep -oP 'pid=\K[0-9]+' | sort -u)
    if [ -z "$pids" ]; then
        pids=$(lsof -ti tcp:"$port" 2>/dev/null)
    fi
    if [ -n "$pids" ]; then
        log_warning "  → Port $port occupé par PID(s) : $pids - kill -9..."
        for pid in $pids; do
            kill -9 "$pid" 2>/dev/null && log_info "    PID $pid tué"
        done
        fuser -k "${port}/tcp" 2>&1 | tee -a "$LOG_FILE"
        sleep 1
    fi
}

ensure_port_free() {
    local port=$1
    if ss -tlnp 2>/dev/null | awk -v p=":$port" '$4 ~ p' | grep -q "."; then
        log_error "  Port $port toujours occupé après cleanup !"
        ss -tlnp 2>/dev/null | grep ":$port "
        return 1
    fi
    return 0
}

cleanup_all() {
    log_warning "Nettoyage complet en cours..."

    log_info "→ Arrêt services..."
    systemctl stop snort wazuh-manager wazuh-indexer wazuh-dashboard filebeat 2>&1 | tee -a "$LOG_FILE"
    systemctl disable snort wazuh-manager wazuh-indexer wazuh-dashboard filebeat 2>&1 | tee -a "$LOG_FILE"

    log_info "→ Kill processus par nom..."
    pkill -9 snort 2>&1 | tee -a "$LOG_FILE"
    pkill -9 -f 'ossec-' 2>&1 | tee -a "$LOG_FILE"
    pkill -9 -f 'wazuh-' 2>&1 | tee -a "$LOG_FILE"
    pkill -9 -f 'opensearch' 2>&1 | tee -a "$LOG_FILE"
    pkill -9 -f 'filebeat' 2>&1 | tee -a "$LOG_FILE"
    sleep 2

    log_info "→ Libération des ports Wazuh (port-aware cleanup)..."
    for port in "${WAZUH_PORTS[@]}"; do
        kill_port "$port"
    done
    sleep 2

    log_info "→ Vérification que les ports sont libres..."
    for port in "${WAZUH_PORTS[@]}"; do
        if ensure_port_free "$port"; then
            log_info "  ✓ Port $port libre"
        else
            log_warning "  ⚠ Port $port encore occupé"
        fi
    done

    log_info "→ Suppression paquets..."
    sep
    DEBIAN_FRONTEND=noninteractive apt remove --purge -y \
        snort snort-common snort-rules-default \
        wazuh-manager wazuh-indexer wazuh-dashboard wazuh-agent \
        filebeat 2>&1 | tee -a "$LOG_FILE"
    sep

    log_info "→ Suppression dossiers..."
    rm -rf /var/ossec /etc/wazuh-indexer /var/lib/wazuh-indexer /usr/share/wazuh-indexer
    rm -rf /etc/wazuh-dashboard /usr/share/wazuh-dashboard /var/lib/wazuh-dashboard
    rm -rf /etc/filebeat /var/lib/filebeat /usr/share/filebeat
    rm -rf /etc/snort /var/log/snort /var/run/snort
    rm -f /root/wazuh-install.sh /root/wazuh-install-files.tar
    rm -f wazuh-install.sh wazuh-install-files.tar
    rm -f /etc/systemd/system/snort.service

    systemctl daemon-reload
    systemctl reset-failed 2>&1 | tee -a "$LOG_FILE"
    DEBIAN_FRONTEND=noninteractive apt autoremove -y 2>&1 | tee -a "$LOG_FILE"
    log_success "Nettoyage terminé"
}

check_existing_installation() {
    log_info "Recherche d'une installation antérieure..."
    log_info "→ Vérification paquets snort/wazuh dans dpkg :"
    dpkg -l 2>/dev/null | grep -E "snort|wazuh" | tee -a "$LOG_FILE" || echo "  (aucun)"
    log_info "→ Vérification dossiers /etc/snort, /var/ossec, /etc/wazuh-indexer :"
    ls -la /etc/snort /var/ossec /etc/wazuh-indexer 2>&1 | tee -a "$LOG_FILE" | head -10
    log_info "→ Vérification ports Wazuh occupés :"
    PORTS_BUSY=false
    for port in "${WAZUH_PORTS[@]}"; do
        if ss -tlnp 2>/dev/null | grep -q ":$port "; then
            log_warning "  Port $port occupé"
            PORTS_BUSY=true
        fi
    done

    if dpkg -l 2>/dev/null | grep -qE "snort|wazuh" || \
       [ -d "/etc/snort" ] || [ -d "/var/ossec" ] || [ -d "/etc/wazuh-indexer" ] || \
       [ "$PORTS_BUSY" = true ]; then
        echo ""
        log_warning "═══════════════════════════════════════════════════════════════════"
        log_warning "  ⚠  INSTALLATION EXISTANTE OU PORTS OCCUPÉS → NETTOYAGE EN COURS"
        log_warning "═══════════════════════════════════════════════════════════════════"
        echo ""
        cleanup_all
        echo ""
        log_success "Système prêt pour une nouvelle installation"
    else
        log_success "Aucune installation antérieure - système propre"
    fi
}

#=========================================================================
# UPDATE & DEPS
#=========================================================================
update_system() {
    log_step "→" "Mise à jour système"
    log_cmd "apt update"
    sep
    apt update 2>&1 | tee -a "$LOG_FILE"
    if [ "${PIPESTATUS[0]}" -ne 0 ]; then sep; abort "Échec apt update"; fi
    sep
    log_cmd "apt upgrade -y"
    sep
    DEBIAN_FRONTEND=noninteractive apt upgrade -y 2>&1 | tee -a "$LOG_FILE"
    sep
    log_success "Système mis à jour"
}

install_dependencies() {
    log_step "→" "Installation dépendances"
    log_cmd "apt install curl wget gnupg lsof psmisc ..."
    sep
    DEBIAN_FRONTEND=noninteractive apt install -y \
        curl wget gnupg apt-transport-https lsb-release ca-certificates \
        software-properties-common net-tools jq iproute2 lsof psmisc 2>&1 | tee -a "$LOG_FILE"
    if [ "${PIPESTATUS[0]}" -ne 0 ]; then sep; abort "Échec dépendances"; fi
    sep
    log_success "Dépendances installées"
}

#=========================================================================
# USERS
#=========================================================================
create_siem_group_and_users() {
    log_step "1/5" "Création groupe et users SIEM Africa"

    log_info "→ Groupe $SIEM_GROUP..."
    if ! getent group "$SIEM_GROUP" >/dev/null 2>&1; then
        log_cmd "groupadd $SIEM_GROUP"
        if ! groupadd "$SIEM_GROUP"; then abort "Création groupe impossible"; fi
        log_success "Groupe créé"
    else
        log_info "Groupe existe déjà"
    fi

    log_info "→ User $SIEM_IDS_USER..."
    SIEM_IDS_PASSWORD=$(generate_password)
    if ! id "$SIEM_IDS_USER" >/dev/null 2>&1; then
        log_cmd "useradd -m -s /bin/bash -g $SIEM_GROUP $SIEM_IDS_USER"
        if ! useradd -m -s /bin/bash -g "$SIEM_GROUP" "$SIEM_IDS_USER"; then
            abort "Création $SIEM_IDS_USER impossible"
        fi
    else
        usermod -g "$SIEM_GROUP" "$SIEM_IDS_USER"
    fi
    echo "$SIEM_IDS_USER:$SIEM_IDS_PASSWORD" | chpasswd
    usermod -aG sudo "$SIEM_IDS_USER" 2>/dev/null
    log_success "$SIEM_IDS_USER configuré"

    log_info "→ User $SIEM_WAZUH_USER..."
    SIEM_WAZUH_PASSWORD=$(generate_password)
    if ! id "$SIEM_WAZUH_USER" >/dev/null 2>&1; then
        log_cmd "useradd -m -s /bin/bash -g $SIEM_GROUP $SIEM_WAZUH_USER"
        if ! useradd -m -s /bin/bash -g "$SIEM_GROUP" "$SIEM_WAZUH_USER"; then
            abort "Création $SIEM_WAZUH_USER impossible"
        fi
    else
        usermod -g "$SIEM_GROUP" "$SIEM_WAZUH_USER"
    fi
    echo "$SIEM_WAZUH_USER:$SIEM_WAZUH_PASSWORD" | chpasswd
    usermod -aG sudo "$SIEM_WAZUH_USER" 2>/dev/null
    log_success "$SIEM_WAZUH_USER configuré"
}

#=========================================================================
# SNORT
#=========================================================================
install_snort() {
    log_step "2/5" "Installation Snort"
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    if [ -z "$INTERFACE" ]; then INTERFACE="eth0"; fi
    log_info "Interface : $INTERFACE"

    echo "snort snort/interface string $INTERFACE" | debconf-set-selections
    echo "snort snort/address_range string any/any" | debconf-set-selections
    echo "snort snort/startup string boot" | debconf-set-selections

    log_cmd "apt install -y snort"
    sep
    DEBIAN_FRONTEND=noninteractive apt install -y snort 2>&1 | tee -a "$LOG_FILE"
    if [ "${PIPESTATUS[0]}" -ne 0 ]; then sep; abort "Échec install Snort"; fi
    sep
    log_success "Snort installé"
}

configure_snort() {
    log_info "Config Snort..."
    LOCAL_NET=$(ip route | grep -oP 'src \K[\d.]+' | head -1 | sed 's/\.[0-9]*$/.0\/24/')
    if [ -z "$LOCAL_NET" ]; then LOCAL_NET="192.168.1.0/24"; fi
    log_info "Réseau local : $LOCAL_NET"

    if [ -f "$SNORT_CONF" ]; then
        sed -i "s|ipvar HOME_NET any|ipvar HOME_NET $LOCAL_NET|g" "$SNORT_CONF"
        sed -i "s|var HOME_NET any|var HOME_NET $LOCAL_NET|g" "$SNORT_CONF"
        grep -E "^(ipvar|var) HOME_NET" "$SNORT_CONF" | tee -a "$LOG_FILE"
    fi

    mkdir -pv /var/log/snort /etc/snort/rules 2>&1 | tee -a "$LOG_FILE"
    chown -R "$SIEM_IDS_USER":"$SIEM_GROUP" /var/log/snort /etc/snort 2>/dev/null
    chmod 770 /var/log/snort

    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    if [ -z "$INTERFACE" ]; then INTERFACE="eth0"; fi

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
    systemctl enable snort 2>&1 | tee -a "$LOG_FILE"
    systemctl start snort 2>&1 | tee -a "$LOG_FILE"
    sleep 2
    systemctl status snort --no-pager 2>&1 | tee -a "$LOG_FILE" | head -10
    log_success "Snort configuré"
}

#=========================================================================
# WAZUH ALL-IN-ONE (avec libération de ports avant chaque tentative)
#=========================================================================
install_wazuh() {
    log_step "3/5" "Installation Wazuh $WAZUH_VERSION (10-20 min)"

    cd /root 2>/dev/null || cd /tmp
    log_info "→ Téléchargement wazuh-install.sh..."
    if ! curl -sO "https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh"; then
        abort "Téléchargement Wazuh échoué"
    fi
    chmod +x wazuh-install.sh
    log_success "Script Wazuh téléchargé"

    local attempt=1
    local success=false

    while [ "$attempt" -le "$RETRY_COUNT" ]; do
        log_info "→ Tentative $attempt/$RETRY_COUNT..."

        # CRITIQUE : Libérer les ports juste avant chaque tentative Wazuh
        log_info "→ Libération préventive des ports Wazuh..."
        for port in "${WAZUH_PORTS[@]}"; do
            kill_port "$port"
        done
        sleep 2

        log_cmd "bash wazuh-install.sh -a -i"
        sep
        bash wazuh-install.sh -a -i 2>&1 | tee -a "$LOG_FILE"
        local rc=${PIPESTATUS[0]}
        sep

        if [ "$rc" -eq 0 ]; then
            success=true
            break
        fi

        log_warning "Tentative $attempt échouée"
        if [ "$attempt" -lt "$RETRY_COUNT" ]; then
            log_info "→ Cleanup port-aware avant retry..."
            systemctl stop wazuh-manager wazuh-indexer wazuh-dashboard 2>/dev/null
            apt remove --purge -y wazuh-manager wazuh-indexer wazuh-dashboard 2>/dev/null
            rm -rf /var/ossec /etc/wazuh-indexer /var/lib/wazuh-indexer wazuh-install-files.tar
            # Libération des ports après cleanup
            for port in "${WAZUH_PORTS[@]}"; do
                kill_port "$port"
            done
            sleep 5
        fi
        attempt=$((attempt + 1))
    done

    if [ "$success" = false ]; then abort "Wazuh échoué après $RETRY_COUNT tentatives"; fi
    log_success "Wazuh installé"

    if [ -f "wazuh-install-files.tar" ]; then cp wazuh-install-files.tar /root/; fi
    if id wazuh >/dev/null 2>&1; then
        usermod -aG "$SIEM_GROUP" wazuh 2>/dev/null
    fi
}

#=========================================================================
# INTÉGRATION
#=========================================================================
configure_integration() {
    log_step "4/5" "Intégration Snort ↔ Wazuh"
    OSSEC_CONF="/var/ossec/etc/ossec.conf"
    if [ ! -f "$OSSEC_CONF" ]; then abort "ossec.conf absent"; fi
    if ! grep -q "/var/log/snort/alert" "$OSSEC_CONF"; then
        log_info "→ Ajout localfile Snort..."
        sed -i '/<\/ossec_config>/i \  <localfile>\n    <log_format>snort-full</log_format>\n    <location>/var/log/snort/alert</location>\n  </localfile>' "$OSSEC_CONF"
        log_success "Bloc localfile ajouté"
    fi
    log_info "→ Restart wazuh-manager..."
    systemctl restart wazuh-manager 2>&1 | tee -a "$LOG_FILE"
    if ! systemctl is-active --quiet wazuh-manager; then abort "Wazuh n'a pas redémarré"; fi
    log_success "Intégration configurée"
}

#=========================================================================
# EXTRACTION PASSWORD ADMIN
#=========================================================================
extract_wazuh_admin_password() {
    WAZUH_ADMIN_PASSWORD="Voir /root/wazuh-install-files.tar"
    if [ -f "/root/wazuh-install-files.tar" ]; then
        mkdir -p /tmp/wazuh-extract
        tar -xf /root/wazuh-install-files.tar -C /tmp/wazuh-extract 2>/dev/null
        if [ -f "/tmp/wazuh-extract/wazuh-install-files/wazuh-passwords.txt" ]; then
            EXTRACTED=$(grep -A1 "'admin'" /tmp/wazuh-extract/wazuh-install-files/wazuh-passwords.txt 2>/dev/null | \
                grep "password" | head -1 | sed "s/.*password: '//" | sed "s/'.*//")
            if [ -n "$EXTRACTED" ]; then WAZUH_ADMIN_PASSWORD="$EXTRACTED"; fi
        fi
        rm -rf /tmp/wazuh-extract
    fi
}

#=========================================================================
# CREDENTIALS
#=========================================================================
create_credentials_file() {
    log_step "5/5" "Création fichier credentials"
    extract_wazuh_admin_password

    SERVER_IP=$(hostname -I | awk '{print $1}')
    DATE=$(date '+%Y-%m-%d %H:%M:%S')
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    LOCAL_NET=$(ip route | grep -oP 'src \K[\d.]+' | head -1 | sed 's/\.[0-9]*$/.0\/24/')
    if [ -z "$INTERFACE" ]; then INTERFACE="eth0"; fi
    if [ -z "$LOCAL_NET" ]; then LOCAL_NET="192.168.1.0/24"; fi

    cat > "$CREDENTIALS_FILE" <<EOF
╔══════════════════════════════════════════════════════════════════╗
║                SIEM AFRICA - CREDENTIALS                         ║
║                     MODULE 1 - FULL                              ║
╚══════════════════════════════════════════════════════════════════╝

Date              : $DATE
Mode              : FULL (Snort + Wazuh complet)
Serveur IP        : $SERVER_IP
Hostname          : $(hostname)

══════════════════════════════════════════════════════════════════
USERS SYSTÈME
══════════════════════════════════════════════════════════════════
$SIEM_IDS_USER     / $SIEM_IDS_PASSWORD     (sudo) - Snort
$SIEM_WAZUH_USER  / $SIEM_WAZUH_PASSWORD  (sudo) - Wazuh
Groupe            : $SIEM_GROUP

══════════════════════════════════════════════════════════════════
WAZUH DASHBOARD
══════════════════════════════════════════════════════════════════
URL        : https://$SERVER_IP
User       : admin
Password   : $WAZUH_ADMIN_PASSWORD

══════════════════════════════════════════════════════════════════
SNORT
══════════════════════════════════════════════════════════════════
Interface  : $INTERFACE
Home Net   : $LOCAL_NET
Logs       : /var/log/snort/alert

══════════════════════════════════════════════════════════════════
PORTS
══════════════════════════════════════════════════════════════════
443   - Wazuh Dashboard
1514  - Wazuh Agent
1515  - Wazuh Enrollment
9200  - Wazuh Indexer
55000 - Wazuh API
EOF

    chmod 600 "$CREDENTIALS_FILE"
    log_success "Credentials sauvegardés : $CREDENTIALS_FILE"
}

#=========================================================================
# RÉSUMÉ
#=========================================================================
show_summary() {
    SERVER_IP=$(hostname -I | awk '{print $1}')
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   ✓ INSTALLATION FULL TERMINÉE                                 ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}DASHBOARD WAZUH${NC}"
    echo -e "  URL      : ${GREEN}https://${SERVER_IP}${NC}"
    echo -e "  User     : ${YELLOW}admin${NC}"
    echo -e "  Password : ${YELLOW}$WAZUH_ADMIN_PASSWORD${NC}"
    echo ""
    echo -e "${CYAN}USERS${NC}"
    echo -e "  • ${YELLOW}$SIEM_IDS_USER${NC}    / ${GREEN}$SIEM_IDS_PASSWORD${NC}"
    echo -e "  • ${YELLOW}$SIEM_WAZUH_USER${NC}  / ${GREEN}$SIEM_WAZUH_PASSWORD${NC}"
    echo ""
    echo -e "${CYAN}SERVICES${NC}"
    for service in snort wazuh-manager wazuh-indexer wazuh-dashboard; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            echo -e "  $service : ${GREEN}● Actif${NC}"
        else
            echo -e "  $service : ${RED}○ Inactif${NC}"
        fi
    done
    echo ""
    echo -e "${CYAN}CREDENTIALS${NC}"
    echo -e "  ${GREEN}sudo cat $CREDENTIALS_FILE${NC}"
    echo ""
}

#=========================================================================
# MAIN
#=========================================================================
main() {
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null
    echo "=== SIEM Africa - Module 1 FULL VERBOSE - $(date) ===" > "$LOG_FILE"

    parse_args "$@"
    show_banner

    echo -e "${CYAN}════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}[VÉRIFICATION DES PRÉREQUIS]${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════════${NC}"
    check_root
    check_os
    check_ram
    check_disk
    check_cpu
    check_internet
    check_existing_installation

    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}[PRÉPARATION SYSTÈME]${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════════${NC}"
    update_system
    install_dependencies

    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}[INSTALLATION]${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════════${NC}"
    create_siem_group_and_users
    install_snort; configure_snort
    install_wazuh
    configure_integration
    create_credentials_file

    show_summary
    log_info "Installation FULL terminée - $(date)"
}

main "$@"
