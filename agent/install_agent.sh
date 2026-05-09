#!/usr/bin/env bash
# ==============================================================================
#  SIEM AFRICA - Module 3 - Installation de l'agent intelligent
#  Compatible : Ubuntu 20.04 / 22.04 / 24.04
# ==============================================================================
#  Pre-requis :
#    - Module 1 installe (Wazuh + Snort + groupe siem-africa)
#    - Module 2 installe (BDD + smtp.env si SMTP utilise)
#    - 4 Go RAM minimum (2 modeles Ollama)
#    - 10 Go disque libre
#
#  Usage : sudo ./install_agent.sh
# ==============================================================================

# Pas de "set -e" (regle SIEM Africa)

# ----------------------------------------------------------------------------
# Couleurs et logs
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
AGENT_USER="siem-agent"
SIEM_GROUP="siem-africa"
AGENT_DIR="/opt/siem-africa-agent"
AGENT_LOG_DIR="/var/log/siem-africa"
AGENT_CONFIG="/etc/siem-africa/agent.env"
SMTP_CONFIG="/etc/siem-africa/smtp.env"
DB_PATH="/var/lib/siem-africa/siem.db"
CREDS_FILE="/root/siem_credentials.txt"
SERVICE_NAME="siem-agent"
LOG_INSTALL="/var/log/siem-africa-install-m3.log"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OLLAMA_MODELS=("qwen2.5:3b" "llama3.2:3b")
OLLAMA_HOST="http://localhost:11434"

# ----------------------------------------------------------------------------
# Banner
# ----------------------------------------------------------------------------
clear
echo -e "${CYAN}"
cat <<'BANNER'
═══════════════════════════════════════════════════════════════
  SIEM AFRICA - Module 3 - Agent Intelligent
  Wazuh + Snort + IA + Email + KPI
═══════════════════════════════════════════════════════════════
BANNER
echo -e "${NC}"

# ----------------------------------------------------------------------------
# 1. Verifications
# ----------------------------------------------------------------------------
log_step "Verifications initiales"

if [ "$EUID" -ne 0 ]; then
    log_err "Doit etre execute en root (sudo)."
    exit 1
fi
log_ok "Execution en root"

. /etc/os-release 2>/dev/null
case "${VERSION_ID:-}" in
    20.04|22.04|24.04) log_ok "Ubuntu ${VERSION_ID}" ;;
    *) log_warn "Ubuntu ${VERSION_ID:-inconnu} non teste"; read -p "Continuer ? [o/N] : " c; [ "${c,,}" != "o" ] && exit 0 ;;
esac

if [ ! -f "$DB_PATH" ]; then
    log_err "BDD inexistante : $DB_PATH"
    log_err "Le Module 2 doit etre installe d'abord."
    log_info "Lancer : cd ../database && sudo ./install_database.sh"
    exit 1
fi
log_ok "BDD detectee : $DB_PATH"

if ! getent group "$SIEM_GROUP" >/dev/null; then
    log_err "Groupe $SIEM_GROUP inexistant. Le Module 1 doit etre installe."
    exit 1
fi
log_ok "Groupe $SIEM_GROUP detecte"

# RAM
RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
if [ "$RAM_MB" -lt 3500 ]; then
    log_warn "RAM : ${RAM_MB} Mo (recommande 4 Go pour 2 modeles)"
    read -p "Continuer ? [o/N] : " c
    [ "${c,,}" != "o" ] && exit 0
else
    log_ok "RAM : ${RAM_MB} Mo"
fi

# Disque
DISK_FREE_GB=$(df -BG / | awk 'NR==2 {print $4}' | tr -d 'G')
if [ "$DISK_FREE_GB" -lt 8 ]; then
    log_warn "Disque libre : ${DISK_FREE_GB} Go (recommande 10 Go)"
    read -p "Continuer ? [o/N] : " c
    [ "${c,,}" != "o" ] && exit 0
else
    log_ok "Disque libre : ${DISK_FREE_GB} Go"
fi

# Internet
if ! ping -c 1 -W 3 ollama.com &>/dev/null; then
    log_warn "Pas de connexion a ollama.com (Ollama non installable)"
    read -p "Continuer ? [o/N] : " c
    [ "${c,,}" != "o" ] && exit 1
else
    log_ok "Connexion Internet OK"
fi

# ----------------------------------------------------------------------------
# 2. Detection installation precedente
# ----------------------------------------------------------------------------
log_step "Detection installation precedente"

PREVIOUS=0
systemctl list-unit-files 2>/dev/null | grep -q "${SERVICE_NAME}.service" && PREVIOUS=1
[ -d "$AGENT_DIR" ] && PREVIOUS=1

if [ "$PREVIOUS" = "1" ]; then
    log_warn "Installation precedente detectee"
    echo "  1. Desinstaller proprement et reinstaller"
    echo "  2. Annuler"
    read -p "Choix [1/2, defaut 2] : " CLEAN
    CLEAN="${CLEAN:-2}"
    if [ "$CLEAN" = "1" ]; then
        log_step "Desinstallation propre"
        systemctl stop "$SERVICE_NAME" 2>/dev/null
        systemctl disable "$SERVICE_NAME" 2>/dev/null
        rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
        systemctl daemon-reload 2>/dev/null
        rm -rf "$AGENT_DIR"
        rm -f /etc/cron.d/siem-africa-kpi
        log_ok "Desinstallation OK"
    else
        log_info "Annule."
        exit 0
    fi
fi

# ----------------------------------------------------------------------------
# 3. Dependances systeme
# ----------------------------------------------------------------------------
log_step "Installation des dependances"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y 2>&1 | tee -a "$LOG_INSTALL" >/dev/null

apt-get install -y \
    python3 python3-pip python3-venv python3-dev \
    sqlite3 curl wget jq inotify-tools iptables cron \
    2>&1 | tee -a "$LOG_INSTALL" >/dev/null

if [ $? -ne 0 ]; then
    log_err "Echec installation dependances"
    exit 1
fi
log_ok "Dependances installees"

# ----------------------------------------------------------------------------
# 4. Utilisateur siem-agent
# ----------------------------------------------------------------------------
log_step "Utilisateur siem-agent"

if id "$AGENT_USER" &>/dev/null; then
    log_info "$AGENT_USER existe deja"
else
    useradd --system --no-create-home --shell /usr/sbin/nologin --gid "$SIEM_GROUP" "$AGENT_USER"
    log_ok "$AGENT_USER cree"
fi

if ! id -nG "$AGENT_USER" | grep -qw "$SIEM_GROUP"; then
    usermod -a -G "$SIEM_GROUP" "$AGENT_USER"
fi
log_ok "$AGENT_USER dans groupe $SIEM_GROUP"

# Lecture alerts.json (Wazuh)
if [ -f /var/ossec/logs/alerts/alerts.json ]; then
    if getent group wazuh >/dev/null; then
        usermod -a -G wazuh "$AGENT_USER" 2>/dev/null && log_ok "$AGENT_USER ajoute au groupe wazuh"
    fi
fi

# Lecture logs Snort
if [ -d /var/log/snort ]; then
    chmod g+rx /var/log/snort 2>/dev/null
    if getent group snort >/dev/null; then
        usermod -a -G snort "$AGENT_USER" 2>/dev/null && log_ok "$AGENT_USER ajoute au groupe snort"
    fi
fi

# ----------------------------------------------------------------------------
# 5. Dossiers
# ----------------------------------------------------------------------------
log_step "Creation des dossiers"

mkdir -p "$AGENT_DIR" "$AGENT_LOG_DIR" "$(dirname "$AGENT_CONFIG")"
chown -R "$AGENT_USER:$SIEM_GROUP" "$AGENT_DIR" "$AGENT_LOG_DIR"
chmod 750 "$AGENT_DIR"
chmod 770 "$AGENT_LOG_DIR"
log_ok "Dossiers crees"

# ----------------------------------------------------------------------------
# 6. Copie du code Python
# ----------------------------------------------------------------------------
log_step "Copie du code"

if [ ! -d "$SCRIPT_DIR/opt" ]; then
    log_err "Dossier opt/ introuvable dans $SCRIPT_DIR"
    exit 1
fi

cp -r "$SCRIPT_DIR/opt/." "$AGENT_DIR/"
chown -R "$AGENT_USER:$SIEM_GROUP" "$AGENT_DIR"
find "$AGENT_DIR" -type d -exec chmod 750 {} \;
find "$AGENT_DIR" -type f -name "*.py" -exec chmod 640 {} \;
chmod 750 "$AGENT_DIR/main.py"

log_ok "Code copie dans $AGENT_DIR"

# ----------------------------------------------------------------------------
# 7. Venv Python
# ----------------------------------------------------------------------------
log_step "Environnement virtuel Python"

cd "$AGENT_DIR"
python3 -m venv venv 2>&1 | tee -a "$LOG_INSTALL" >/dev/null

if [ ! -f "$AGENT_DIR/venv/bin/python" ]; then
    log_err "Echec venv"
    exit 1
fi
log_ok "Venv cree"

log_info "Installation paquets Python..."
"$AGENT_DIR/venv/bin/pip" install --upgrade pip 2>&1 | tail -2 >> "$LOG_INSTALL"

cat > /tmp/m3_requirements.txt <<EOF
requests>=2.31.0
inotify-simple>=1.3.5
EOF

"$AGENT_DIR/venv/bin/pip" install -r /tmp/m3_requirements.txt 2>&1 | tail -3 >> "$LOG_INSTALL"

if [ $? -ne 0 ]; then
    log_err "Echec installation paquets Python"
    exit 1
fi

log_ok "Paquets installes (requests, inotify-simple)"
chown -R "$AGENT_USER:$SIEM_GROUP" "$AGENT_DIR/venv"

# ----------------------------------------------------------------------------
# 8. agent.env
# ----------------------------------------------------------------------------
log_step "Configuration agent.env"

cat > "$AGENT_CONFIG" <<EOF
# SIEM Africa Agent - Configuration
# Genere par install_agent.sh

DB_PATH=$DB_PATH
LOG_DIR=$AGENT_LOG_DIR
LOG_LEVEL=INFO

WAZUH_ALERTS_FILE=/var/ossec/logs/alerts/alerts.json
WAZUH_WATCHER_ENABLED=true

SNORT_ALERT_FILE=/var/log/snort/alert
SNORT_WATCHER_ENABLED=true

OLLAMA_HOST=$OLLAMA_HOST
OLLAMA_TIMEOUT=60
OLLAMA_HEALTHCHECK_RETRIES=3
OLLAMA_HEALTHCHECK_INTERVAL=10

SMTP_CONFIG=$SMTP_CONFIG
EMAIL_ENABLED=true
EMAIL_ALL_ALERTS=true

AI_DEGRADED_MODE_ALLOWED=true
IP_BLOCK_ENABLED=false
KPI_SNAPSHOT_ENABLED=true
EOF

chmod 640 "$AGENT_CONFIG"
chown root:"$SIEM_GROUP" "$AGENT_CONFIG"
log_ok "Configuration sauvegardee"

# ----------------------------------------------------------------------------
# 8b. Settings anti-spam dans la BDD
# ----------------------------------------------------------------------------
log_step "Configuration anti-spam dans la BDD"

# On insere les settings anti-spam (INSERT OR IGNORE pour ne pas ecraser
# d'eventuelles personnalisations existantes)
sqlite3 "$DB_PATH" <<SQL 2>>"$LOG_INSTALL"
INSERT OR IGNORE INTO settings (key, value) VALUES
  ('email_enabled', 'true'),
  ('email_min_severity', 'INFO'),
  ('email_rate_limit_per_hour', '30'),
  ('email_dedup_window_minutes', '5'),
  ('email_digest_enabled', 'true'),
  ('email_digest_interval_minutes', '60'),
  ('ai_enabled', 'true'),
  ('ai_enrich_unknown', 'true'),
  ('ai_default_model', 'qwen2.5:3b'),
  ('ip_block_enabled', 'false');
SQL

if [ $? -eq 0 ]; then
    log_ok "Settings anti-spam configures (rate limit 30/h, dedup 5min, digest 60min)"
else
    log_warn "Echec partiel insertion settings (peut etre des doublons)"
fi

# Creer le dossier d'etat pour le digest persiste sur disque
mkdir -p /var/lib/siem-africa/state
chown -R "$AGENT_USER:$SIEM_GROUP" /var/lib/siem-africa/state
chmod 770 /var/lib/siem-africa/state
log_ok "Dossier state cree pour persistence digest"

# ----------------------------------------------------------------------------
# 9. Verif SMTP
# ----------------------------------------------------------------------------
log_step "Verification SMTP"

SMTP_OK=0
if [ -f "$SMTP_CONFIG" ]; then
    log_ok "SMTP configure"
    SMTP_OK=1
else
    log_warn "$SMTP_CONFIG inexistant - emails desactives"
    log_info "Configurer plus tard : sudo bash ../database/configure_smtp.sh"
fi

# ----------------------------------------------------------------------------
# 10. Ollama
# ----------------------------------------------------------------------------
log_step "Installation Ollama"

OLLAMA_INSTALLED=0
if command -v ollama &>/dev/null; then
    log_ok "Ollama deja present"
    OLLAMA_INSTALLED=1
else
    log_info "Telechargement de Ollama..."
    curl -fsSL https://ollama.com/install.sh -o /tmp/ollama_install.sh 2>/dev/null
    if [ -f /tmp/ollama_install.sh ]; then
        bash /tmp/ollama_install.sh 2>&1 | tail -5 | tee -a "$LOG_INSTALL"
        if command -v ollama &>/dev/null; then
            log_ok "Ollama installe"
            OLLAMA_INSTALLED=1
        else
            log_warn "Ollama non installe correctement"
        fi
    else
        log_warn "Echec telechargement script Ollama"
    fi
fi

if [ "$OLLAMA_INSTALLED" = "1" ]; then
    systemctl enable ollama 2>/dev/null
    systemctl start ollama 2>/dev/null
    sleep 5

    # Test API
    OLLAMA_API_OK=0
    for i in 1 2 3; do
        if curl -fsS "$OLLAMA_HOST/api/tags" >/dev/null 2>&1; then
            OLLAMA_API_OK=1
            break
        fi
        sleep 5
    done

    if [ "$OLLAMA_API_OK" = "1" ]; then
        log_ok "API Ollama repond"
    else
        log_warn "API Ollama ne repond pas (mode degrade au boot agent)"
    fi
fi

# ----------------------------------------------------------------------------
# 11. Modeles
# ----------------------------------------------------------------------------
MODELS_OK=0
if [ "$OLLAMA_INSTALLED" = "1" ]; then
    log_step "Telechargement des modeles"
    log_info "Modeles : ${OLLAMA_MODELS[*]} (~4 Go, peut prendre 5-15 min)"

    for model in "${OLLAMA_MODELS[@]}"; do
        log_info "Pull $model..."
        if ollama pull "$model" 2>&1 | tail -3 | grep -qiE "success|already"; then
            log_ok "$model OK"
            MODELS_OK=$((MODELS_OK + 1))
        else
            sleep 5
            if ollama pull "$model" 2>&1 | tail -3 | grep -qiE "success|already"; then
                log_ok "$model OK (apres retry)"
                MODELS_OK=$((MODELS_OK + 1))
            else
                log_err "Echec $model"
            fi
        fi
    done
    log_info "Modeles : $MODELS_OK/${#OLLAMA_MODELS[@]}"
fi

# ----------------------------------------------------------------------------
# 12. Service systemd
# ----------------------------------------------------------------------------
log_step "Service systemd"

cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=SIEM Africa Agent - Detection et IA
After=network.target wazuh-manager.service ollama.service
Wants=network.target

[Service]
Type=simple
User=$AGENT_USER
Group=$SIEM_GROUP
WorkingDirectory=$AGENT_DIR
EnvironmentFile=$AGENT_CONFIG
ExecStart=$AGENT_DIR/venv/bin/python $AGENT_DIR/main.py
Restart=on-failure
RestartSec=10
StandardOutput=append:$AGENT_LOG_DIR/agent.log
StandardError=append:$AGENT_LOG_DIR/agent.log

NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

chmod 644 "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload
log_ok "Service cree"

# ----------------------------------------------------------------------------
# 13. Cron KPI
# ----------------------------------------------------------------------------
log_step "Cron KPI"

cat > /etc/cron.d/siem-africa-kpi <<EOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
0 * * * * $AGENT_USER $AGENT_DIR/venv/bin/python $AGENT_DIR/kpi/snapshot.py >> $AGENT_LOG_DIR/kpi.log 2>&1
EOF

chmod 644 /etc/cron.d/siem-africa-kpi
log_ok "Cron KPI cree (snapshot horaire)"

# ----------------------------------------------------------------------------
# 14. Demarrage service
# ----------------------------------------------------------------------------
log_step "Demarrage du service"

systemctl enable "$SERVICE_NAME" 2>/dev/null
systemctl start "$SERVICE_NAME"
sleep 4

SERVICE_OK=0
if systemctl is-active --quiet "$SERVICE_NAME"; then
    log_ok "Service ${SERVICE_NAME} actif"
    SERVICE_OK=1
else
    log_warn "Service non actif - voir : journalctl -u ${SERVICE_NAME}"
fi

# ----------------------------------------------------------------------------
# 15. Credentials
# ----------------------------------------------------------------------------
log_step "Credentials Module 3"

cat >> "$CREDS_FILE" <<EOF

[MODULE 3 - Agent intelligent]
─────────────────────────────────
Date d'installation     : $(date '+%Y-%m-%d %H:%M:%S')
Service systemd         : ${SERVICE_NAME}.service
Utilisateur agent       : $AGENT_USER
Groupe                  : $SIEM_GROUP
Dossier agent           : $AGENT_DIR
Logs                    : $AGENT_LOG_DIR/agent.log

Configuration agent     : $AGENT_CONFIG
Configuration SMTP      : $SMTP_CONFIG

Ollama                  : $OLLAMA_HOST
Modeles installes       : ${OLLAMA_MODELS[*]}
Modele par defaut       : qwen2.5:3b (changeable dans dashboard)

Email mode              : Anti-spam actif (rate 30/h + dedup 5min + digest 60min)
Blocage IP              : OFF (configurable dans settings)
Mode degrade IA         : ON (continue si Ollama plante)
Cron KPI                : /etc/cron.d/siem-africa-kpi (horaire)

Commandes utiles :
  sudo systemctl status ${SERVICE_NAME}
  sudo tail -f $AGENT_LOG_DIR/agent.log
  sudo systemctl restart ${SERVICE_NAME}
  curl -s $OLLAMA_HOST/api/tags
  sudo $SCRIPT_DIR/simulate_attack.sh

EOF

chmod 600 "$CREDS_FILE"
log_ok "Credentials sauvegardes"

# ----------------------------------------------------------------------------
# 16. Verification
# ----------------------------------------------------------------------------
log_step "Verification automatique"

VERIFY_OK=0
if [ -x "$SCRIPT_DIR/verify_agent.sh" ]; then
    if "$SCRIPT_DIR/verify_agent.sh"; then
        VERIFY_OK=1
        log_ok "Verification OK"
    else
        log_warn "Verification : problemes detectes"
    fi
fi

# ----------------------------------------------------------------------------
# 17. Tests automatiques
# ----------------------------------------------------------------------------
log_step "Tests automatiques (Module 3)"

TESTS_OK=0
if [ -x "$SCRIPT_DIR/tests/run_all_tests.sh" ]; then
    chmod +x "$SCRIPT_DIR"/tests/*.sh
    if "$SCRIPT_DIR/tests/run_all_tests.sh"; then
        TESTS_OK=1
    else
        log_warn "Certains tests ont echoue"
    fi
fi

# ----------------------------------------------------------------------------
# 18. Resume
# ----------------------------------------------------------------------------
echo ""
log_step "Installation terminee"
echo ""

if [ "$SERVICE_OK" = "1" ] && [ "$TESTS_OK" = "1" ]; then
    echo -e "${GREEN}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${GREEN}│ ✅ MODULE 3 INSTALLE AVEC SUCCES                            │${NC}"
    echo -e "${GREEN}└─────────────────────────────────────────────────────────────┘${NC}"
else
    echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${YELLOW}│ ⚠ MODULE 3 INSTALLE AVEC AVERTISSEMENTS                     │${NC}"
    echo -e "${YELLOW}└─────────────────────────────────────────────────────────────┘${NC}"
fi

echo ""
echo "  ⚙️  Service systemd : $(systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo unknown)"
echo "  🤖 Ollama          : $(curl -fsS "$OLLAMA_HOST/api/tags" >/dev/null 2>&1 && echo "OK" || echo "KO (mode degrade)")"
echo "  📥 Modeles         : $MODELS_OK/${#OLLAMA_MODELS[@]}"
echo "  📧 SMTP            : $([ "$SMTP_OK" = "1" ] && echo "OK" || echo "non configure")"
echo "  🔍 Verification    : $([ "$VERIFY_OK" = "1" ] && echo "OK" || echo "WARN")"
echo "  🧪 Tests           : $([ "$TESTS_OK" = "1" ] && echo "OK" || echo "WARN")"
echo ""
echo "  📂 Credentials     : $CREDS_FILE"
echo "  📋 Logs agent      : $AGENT_LOG_DIR/agent.log"
echo ""
echo -e "${GREEN}✓ Anti-spam Gmail actif :${NC} rate limit 30/h, dedup 5min, digest LOW/MEDIUM toutes les heures."
echo ""
echo "Prochaine etape : Module 4 (dashboard Django)"
echo ""
