#!/usr/bin/env bash
# SIEM Africa - Module 4 - Verification post-install
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

PASS=0; FAIL=0
DASH_DIR="/opt/siem-africa-dashboard"
LOG_DIR="/var/log/siem-africa"
CONFIG="/etc/siem-africa/dashboard.env"

echo -e "${CYAN}"
echo "═══════════════════════════════════════════════════════════"
echo "  SIEM AFRICA - Module 4 - Verification"
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
check "User siem-dashboard existe" "id siem-dashboard &>/dev/null"
check "siem-dashboard dans groupe siem-africa" "id -nG siem-dashboard | grep -qw siem-africa"

# === Dossiers ===
echo ""
echo "Dossiers :"
check "$DASH_DIR existe" "[ -d '$DASH_DIR' ]"
check "$LOG_DIR existe" "[ -d '$LOG_DIR' ]"
check "venv Python present" "[ -x '$DASH_DIR/venv/bin/python' ]"
check "manage.py present" "[ -f '$DASH_DIR/manage.py' ]"
check "staticfiles/ present" "[ -d '$DASH_DIR/staticfiles' ]"

# === Fichiers Python critiques ===
echo ""
echo "Code Django :"
check "siem_dashboard/settings.py" "[ -f '$DASH_DIR/siem_dashboard/settings.py' ]"
check "users/models.py" "[ -f '$DASH_DIR/users/models.py' ]"
check "core/models.py" "[ -f '$DASH_DIR/core/models.py' ]"
check "alerts/views.py" "[ -f '$DASH_DIR/alerts/views.py' ]"
check "kpi/views.py" "[ -f '$DASH_DIR/kpi/views.py' ]"
check "settings_app/views.py" "[ -f '$DASH_DIR/settings_app/views.py' ]"

# === Configuration ===
echo ""
echo "Configuration :"
check "$CONFIG existe" "[ -f '$CONFIG' ]"
check "DJANGO_SECRET_KEY defini" "grep -q '^DJANGO_SECRET_KEY=' '$CONFIG'"
check "SIEM_DB_PATH defini" "grep -q '^SIEM_DB_PATH=' '$CONFIG'"

# === Service systemd ===
echo ""
echo "Service systemd :"
check "Unit file present" "[ -f /etc/systemd/system/siem-dashboard.service ]"
check "Service enabled" "systemctl is-enabled siem-dashboard &>/dev/null"
warn  "Service actif" "systemctl is-active --quiet siem-dashboard"

# === Nginx ===
echo ""
echo "Nginx :"
check "Site Nginx present" "[ -f /etc/nginx/sites-available/siem-africa ]"
check "Site Nginx enabled" "[ -L /etc/nginx/sites-enabled/siem-africa ]"
check "Config Nginx valide" "nginx -t 2>&1 | grep -q 'syntax is ok'"
warn  "Nginx actif" "systemctl is-active --quiet nginx"

# === Connectivite ===
echo ""
echo "Connectivite :"
warn  "Port 80 ecoute" "ss -tln 2>/dev/null | grep -q ':80 '"
warn  "Port 8000 ecoute (Gunicorn)" "ss -tln 2>/dev/null | grep -q ':8000 '"

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
