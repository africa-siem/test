#!/usr/bin/env bash
# SIEM Africa - Module 3 - Verification post-install
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

PASS=0; FAIL=0
AGENT_DIR="/opt/siem-africa-agent"
LOG_DIR="/var/log/siem-africa"
CONFIG="/etc/siem-africa/agent.env"

echo -e "${CYAN}"
echo "═══════════════════════════════════════════════════════════"
echo "  SIEM AFRICA - Module 3 - Verification"
echo "═══════════════════════════════════════════════════════════"
echo -e "${NC}"

check() {
    local label="$1"
    local cond="$2"
    if eval "$cond"; then
        echo -e "  ${GREEN}✓${NC} $label"
        PASS=$((PASS+1))
    else
        echo -e "  ${RED}✗${NC} $label"
        FAIL=$((FAIL+1))
    fi
}

warn() {
    local label="$1"
    local cond="$2"
    if eval "$cond"; then
        echo -e "  ${GREEN}✓${NC} $label"
        PASS=$((PASS+1))
    else
        echo -e "  ${YELLOW}!${NC} $label"
    fi
}

# === Utilisateur ===
echo "Utilisateur :"
check "User siem-agent existe" "id siem-agent &>/dev/null"
check "siem-agent dans groupe siem-africa" "id -nG siem-agent | grep -qw siem-africa"

# === Dossiers ===
echo ""
echo "Dossiers :"
check "$AGENT_DIR existe" "[ -d '$AGENT_DIR' ]"
check "$LOG_DIR existe" "[ -d '$LOG_DIR' ]"
check "venv Python present" "[ -x '$AGENT_DIR/venv/bin/python' ]"

# === Fichiers Python critiques ===
echo ""
echo "Fichiers Python :"
check "main.py" "[ -f '$AGENT_DIR/main.py' ]"
check "config.py" "[ -f '$AGENT_DIR/config.py' ]"
check "db.py" "[ -f '$AGENT_DIR/db.py' ]"
check "watchers/wazuh_watcher.py" "[ -f '$AGENT_DIR/watchers/wazuh_watcher.py' ]"
check "watchers/snort_watcher.py" "[ -f '$AGENT_DIR/watchers/snort_watcher.py' ]"
check "ai/enrichment.py" "[ -f '$AGENT_DIR/ai/enrichment.py' ]"
check "ai/worker.py" "[ -f '$AGENT_DIR/ai/worker.py' ]"
check "notif/email_sender.py" "[ -f '$AGENT_DIR/notif/email_sender.py' ]"

# === Configuration ===
echo ""
echo "Configuration :"
check "$CONFIG existe" "[ -f '$CONFIG' ]"
warn "/etc/siem-africa/smtp.env existe" "[ -f /etc/siem-africa/smtp.env ]"

# === Service systemd ===
echo ""
echo "Service systemd :"
check "Unit file present" "[ -f /etc/systemd/system/siem-agent.service ]"
check "Service enabled" "systemctl is-enabled siem-agent &>/dev/null"
warn "Service actif" "systemctl is-active --quiet siem-agent"

# === Cron KPI ===
echo ""
echo "Cron :"
check "/etc/cron.d/siem-africa-kpi present" "[ -f /etc/cron.d/siem-africa-kpi ]"

# === Ollama ===
echo ""
echo "Ollama :"
warn "Binaire ollama present" "command -v ollama &>/dev/null"
warn "API Ollama repond" "curl -fsS --max-time 3 http://127.0.0.1:11434/api/tags >/dev/null 2>&1"

# === Resume ===
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo "  Resultat : $PASS validations OK, $FAIL echecs"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

if [ "$FAIL" -eq 0 ]; then
    echo -e "${GREEN}✅ Verification reussie${NC}"
    exit 0
else
    echo -e "${RED}❌ $FAIL probleme(s) detecte(s)${NC}"
    exit 1
fi
