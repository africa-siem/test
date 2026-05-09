#!/usr/bin/env bash
# ==============================================================================
#  SIEM AFRICA - Module 4 - Installation du dashboard Django
#  Compatible : Ubuntu 20.04 / 22.04 / 24.04
# ==============================================================================
#  Pre-requis :
#    - Module 1 installe (groupe siem-africa)
#    - Module 2 installe (BDD SQLite a /var/lib/siem-africa/siem.db)
#    - 2 Go RAM minimum
#    - Connexion Internet
#
#  Usage : sudo ./install_dashboard.sh
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
DASH_USER="siem-dashboard"
SIEM_GROUP="siem-africa"
DASH_DIR="/opt/siem-africa-dashboard"
DASH_LOG_DIR="/var/log/siem-africa"
DASH_CONFIG="/etc/siem-africa/dashboard.env"
DB_PATH="/var/lib/siem-africa/siem.db"
CREDS_FILE="/root/siem_credentials.txt"
SERVICE_NAME="siem-dashboard"
NGINX_SITE="/etc/nginx/sites-available/siem-africa"
LOG_INSTALL="/var/log/siem-africa-install-m4.log"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LISTEN_PORT="80"
INTERNAL_PORT="8000"

# ----------------------------------------------------------------------------
# Banner
# ----------------------------------------------------------------------------
clear
echo -e "${CYAN}"
cat <<'BANNER'
═══════════════════════════════════════════════════════════════
  SIEM AFRICA - Module 4 - Dashboard Django
  Web UI + KPI + Health + Settings + Logs
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
    exit 1
fi
log_ok "BDD detectee : $DB_PATH"

if ! getent group "$SIEM_GROUP" >/dev/null; then
    log_err "Groupe $SIEM_GROUP inexistant. Le Module 1 doit etre installe."
    exit 1
fi
log_ok "Groupe $SIEM_GROUP detecte"

# Internet
if ! ping -c 1 -W 3 pypi.org &>/dev/null; then
    log_warn "Pas de connexion internet. L'installation peut echouer."
    read -p "Continuer ? [o/N] : " c
    [ "${c,,}" != "o" ] && exit 1
else
    log_ok "Connexion internet OK"
fi

# ----------------------------------------------------------------------------
# 2. Detection installation precedente
# ----------------------------------------------------------------------------
log_step "Detection installation precedente"

PREVIOUS=0
systemctl list-unit-files 2>/dev/null | grep -q "${SERVICE_NAME}.service" && PREVIOUS=1
[ -d "$DASH_DIR" ] && PREVIOUS=1

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
        rm -rf "$DASH_DIR"
        rm -f "$NGINX_SITE" /etc/nginx/sites-enabled/siem-africa
        log_ok "Desinstallation OK"
    else
        log_info "Annule."
        exit 0
    fi
fi

# ----------------------------------------------------------------------------
# 3. Dependances systeme
# ----------------------------------------------------------------------------
log_step "Installation dependances systeme"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y 2>&1 | tee -a "$LOG_INSTALL" >/dev/null

apt-get install -y \
    python3 python3-pip python3-venv python3-dev \
    nginx \
    sqlite3 curl jq \
    gettext \
    2>&1 | tee -a "$LOG_INSTALL" >/dev/null

if [ $? -ne 0 ]; then
    log_err "Echec installation dependances"
    exit 1
fi
log_ok "Dependances installees (python3, nginx, sqlite3, gettext)"

# ----------------------------------------------------------------------------
# 4. Utilisateur siem-dashboard
# ----------------------------------------------------------------------------
log_step "Utilisateur siem-dashboard"

if id "$DASH_USER" &>/dev/null; then
    log_info "$DASH_USER existe deja"
else
    useradd --system --no-create-home --shell /usr/sbin/nologin --gid "$SIEM_GROUP" "$DASH_USER"
    log_ok "$DASH_USER cree"
fi

if ! id -nG "$DASH_USER" | grep -qw "$SIEM_GROUP"; then
    usermod -a -G "$SIEM_GROUP" "$DASH_USER"
fi
log_ok "$DASH_USER dans groupe $SIEM_GROUP"

# ----------------------------------------------------------------------------
# 5. Dossiers
# ----------------------------------------------------------------------------
log_step "Creation dossiers"

mkdir -p "$DASH_DIR" "$DASH_LOG_DIR" "$(dirname "$DASH_CONFIG")"
chown -R "$DASH_USER:$SIEM_GROUP" "$DASH_DIR" "$DASH_LOG_DIR"
chmod 750 "$DASH_DIR"
chmod 770 "$DASH_LOG_DIR"
log_ok "Dossiers crees"

# ----------------------------------------------------------------------------
# 6. Copie code Django
# ----------------------------------------------------------------------------
log_step "Copie code dashboard"

if [ ! -d "$SCRIPT_DIR/siem_dashboard" ]; then
    log_err "Dossier siem_dashboard/ introuvable dans $SCRIPT_DIR"
    exit 1
fi

cp -r "$SCRIPT_DIR/siem_dashboard/." "$DASH_DIR/"
chown -R "$DASH_USER:$SIEM_GROUP" "$DASH_DIR"
find "$DASH_DIR" -type d -exec chmod 750 {} \;
find "$DASH_DIR" -type f -name "*.py" -exec chmod 640 {} \;
chmod 750 "$DASH_DIR/manage.py"
log_ok "Code copie dans $DASH_DIR"

# ----------------------------------------------------------------------------
# 7. Venv Python + dependances
# ----------------------------------------------------------------------------
log_step "Environnement virtuel Python + dependances"

cd "$DASH_DIR"
python3 -m venv venv 2>&1 | tee -a "$LOG_INSTALL" >/dev/null

if [ ! -f "$DASH_DIR/venv/bin/python" ]; then
    log_err "Echec creation venv"
    exit 1
fi

log_info "Installation paquets Python..."
"$DASH_DIR/venv/bin/pip" install --upgrade pip 2>&1 | tail -2 >> "$LOG_INSTALL"

cat > /tmp/m4_requirements.txt <<EOF
Django>=5.0,<5.2
gunicorn>=21.0
argon2-cffi>=23.0
requests>=2.31.0
EOF

"$DASH_DIR/venv/bin/pip" install -r /tmp/m4_requirements.txt 2>&1 | tail -5 >> "$LOG_INSTALL"

if [ $? -ne 0 ]; then
    log_err "Echec installation paquets Python"
    exit 1
fi
log_ok "Paquets installes (Django, gunicorn, argon2-cffi, requests)"
chown -R "$DASH_USER:$SIEM_GROUP" "$DASH_DIR/venv"

# ----------------------------------------------------------------------------
# 8. dashboard.env (config)
# ----------------------------------------------------------------------------
log_step "Configuration dashboard.env"

# Generer un SECRET_KEY aleatoire
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))")

# Recuperer l'IP locale + ajouter VM IP communes
LOCAL_IP=$(hostname -I | awk '{print $1}')
ALLOWED_HOSTS="localhost,127.0.0.1,${LOCAL_IP}"

cat > "$DASH_CONFIG" <<EOF
# SIEM Africa Dashboard - Configuration
# Genere par install_dashboard.sh

DJANGO_SECRET_KEY=$SECRET_KEY
DJANGO_DEBUG=false
DJANGO_ALLOWED_HOSTS=$ALLOWED_HOSTS,*

SIEM_DB_PATH=$DB_PATH
SIEM_OLLAMA_HOST=http://127.0.0.1:11434
SIEM_AGENT_LOG=/var/log/siem-africa/agent.log
SIEM_WAZUH_ALERTS=/var/ossec/logs/alerts/alerts.json
SIEM_SMTP_CONFIG=/etc/siem-africa/smtp.env
EOF

chmod 640 "$DASH_CONFIG"
chown root:"$SIEM_GROUP" "$DASH_CONFIG"
log_ok "Configuration sauvegardee dans $DASH_CONFIG"

# ----------------------------------------------------------------------------
# 9. Migrations + collectstatic
# ----------------------------------------------------------------------------
log_step "Django : migrations + statics"

cd "$DASH_DIR"

# Charger l'env
set -a
. "$DASH_CONFIG"
set +a

# Migrer (cree juste les tables Django internes : sessions, contenttypes...)
sudo -u "$DASH_USER" -E "$DASH_DIR/venv/bin/python" manage.py migrate --noinput 2>&1 | tail -5 | tee -a "$LOG_INSTALL"

# collectstatic
sudo -u "$DASH_USER" -E "$DASH_DIR/venv/bin/python" manage.py collectstatic --noinput 2>&1 | tail -3 | tee -a "$LOG_INSTALL"

if [ -d "$DASH_DIR/staticfiles" ]; then
    log_ok "Statics collectes ($(find "$DASH_DIR/staticfiles" -type f | wc -l) fichiers)"
else
    log_warn "collectstatic n'a pas cree staticfiles/"
fi

# ----------------------------------------------------------------------------
# 10. Creation admin user interactif
# ----------------------------------------------------------------------------
log_step "Creation utilisateur administrateur"

read -p "Email admin (defaut: admin@siem-africa.local) : " ADMIN_EMAIL
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@siem-africa.local}"

read -p "Nom complet admin (defaut: Administrateur) : " ADMIN_NAME
ADMIN_NAME="${ADMIN_NAME:-Administrateur}"

# Lecture mot de passe sans -s (utilisateur veut voir ce qu'il tape)
read -p "Mot de passe admin (8+ caracteres) : " ADMIN_PASSWORD
echo ""

if [ -z "$ADMIN_PASSWORD" ] || [ ${#ADMIN_PASSWORD} -lt 8 ]; then
    log_err "Mot de passe trop court (minimum 8 caracteres)"
    exit 1
fi

# Creer ou mettre a jour le user
sudo -u "$DASH_USER" -E "$DASH_DIR/venv/bin/python" manage.py shell <<PYEOF | tail -3
from users.models import User
email = "$ADMIN_EMAIL"
name = "$ADMIN_NAME"
pwd = "$ADMIN_PASSWORD"
user = User.objects.filter(email=email).first()
if user:
    user.set_password(pwd)
    user.full_name = name
    user.role = "admin"
    user.is_staff = True
    user.is_superuser = True
    user.is_active = True
    user.save()
    print(f"Admin {email} mis a jour")
else:
    user = User.objects.create_superuser(email=email, password=pwd, full_name=name, role="admin")
    print(f"Admin {email} cree")
PYEOF

log_ok "Admin cree : $ADMIN_EMAIL"

# ----------------------------------------------------------------------------
# 11. Service systemd Gunicorn
# ----------------------------------------------------------------------------
log_step "Service systemd"

cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=SIEM Africa Dashboard - Django + Gunicorn
After=network.target

[Service]
Type=simple
User=$DASH_USER
Group=$SIEM_GROUP
WorkingDirectory=$DASH_DIR
EnvironmentFile=$DASH_CONFIG
ExecStart=$DASH_DIR/venv/bin/gunicorn \\
    --workers 3 \\
    --bind 127.0.0.1:$INTERNAL_PORT \\
    --access-logfile $DASH_LOG_DIR/dashboard-access.log \\
    --error-logfile $DASH_LOG_DIR/dashboard-error.log \\
    --timeout 60 \\
    siem_dashboard.wsgi:application
Restart=on-failure
RestartSec=10

NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

chmod 644 "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload
log_ok "Service systemd cree"

# ----------------------------------------------------------------------------
# 12. Configuration Nginx
# ----------------------------------------------------------------------------
log_step "Configuration Nginx"

cat > "$NGINX_SITE" <<EOF
upstream siem_dashboard {
    server 127.0.0.1:$INTERNAL_PORT fail_timeout=5s;
}

server {
    listen $LISTEN_PORT default_server;
    server_name _;

    client_max_body_size 50m;
    access_log $DASH_LOG_DIR/nginx-access.log;
    error_log $DASH_LOG_DIR/nginx-error.log;

    location /static/ {
        alias $DASH_DIR/staticfiles/;
        expires 7d;
        add_header Cache-Control "public, max-age=604800";
    }

    location / {
        proxy_pass http://siem_dashboard;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_redirect off;
        proxy_read_timeout 90s;
    }
}
EOF

# Activer le site
ln -sf "$NGINX_SITE" /etc/nginx/sites-enabled/siem-africa
# Desactiver le default Nginx pour eviter conflit sur port 80
rm -f /etc/nginx/sites-enabled/default

# Tester la config
if nginx -t 2>&1 | grep -q "syntax is ok"; then
    log_ok "Config Nginx OK"
else
    log_err "Config Nginx invalide :"
    nginx -t 2>&1 | tail -10
    exit 1
fi

# Donner acces a Nginx aux statics
chmod 755 "$DASH_DIR" 2>/dev/null
chmod -R 755 "$DASH_DIR/staticfiles" 2>/dev/null

# ----------------------------------------------------------------------------
# 13. Demarrage services
# ----------------------------------------------------------------------------
log_step "Demarrage services"

systemctl enable "$SERVICE_NAME" 2>/dev/null
systemctl restart "$SERVICE_NAME"
sleep 4

DASH_OK=0
if systemctl is-active --quiet "$SERVICE_NAME"; then
    log_ok "Service ${SERVICE_NAME} actif"
    DASH_OK=1
else
    log_warn "Service non actif - voir : journalctl -u ${SERVICE_NAME}"
    journalctl -u "$SERVICE_NAME" --no-pager -n 20 | tail -10
fi

systemctl restart nginx 2>&1 | tee -a "$LOG_INSTALL" >/dev/null
NGINX_OK=0
if systemctl is-active --quiet nginx; then
    log_ok "Nginx actif"
    NGINX_OK=1
else
    log_warn "Nginx non actif"
fi

# ----------------------------------------------------------------------------
# 14. APPEND credentials Module 4
# ----------------------------------------------------------------------------
log_step "Credentials Module 4"

cat >> "$CREDS_FILE" <<EOF

[MODULE 4 - Dashboard Django]
─────────────────────────────────
Date d'installation     : $(date '+%Y-%m-%d %H:%M:%S')
Service systemd         : ${SERVICE_NAME}.service
Utilisateur dashboard   : $DASH_USER
Groupe                  : $SIEM_GROUP
Dossier dashboard       : $DASH_DIR
Logs                    : $DASH_LOG_DIR/dashboard-*.log

Configuration           : $DASH_CONFIG
Nginx site              : $NGINX_SITE

Admin email             : $ADMIN_EMAIL
Admin password          : $ADMIN_PASSWORD

URL d'acces             : http://${LOCAL_IP}/
URL locale              : http://localhost/

Commandes utiles :
  sudo systemctl status ${SERVICE_NAME}
  sudo systemctl restart ${SERVICE_NAME}
  sudo tail -f $DASH_LOG_DIR/dashboard-error.log
  sudo nginx -t
  sudo systemctl reload nginx

Pour creer un autre admin :
  sudo -u $DASH_USER $DASH_DIR/venv/bin/python $DASH_DIR/manage.py shell

EOF

chmod 600 "$CREDS_FILE"
log_ok "Credentials sauvegardes dans $CREDS_FILE"

# ----------------------------------------------------------------------------
# 15. Verification
# ----------------------------------------------------------------------------
log_step "Verification automatique"

VERIFY_OK=0
if [ -x "$SCRIPT_DIR/verify_dashboard.sh" ]; then
    if "$SCRIPT_DIR/verify_dashboard.sh"; then
        VERIFY_OK=1
        log_ok "Verification OK"
    else
        log_warn "Verification : problemes detectes"
    fi
fi

# ----------------------------------------------------------------------------
# 16. Tests automatiques
# ----------------------------------------------------------------------------
log_step "Tests automatiques (Module 4)"

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
# 17. Resume
# ----------------------------------------------------------------------------
echo ""
log_step "Installation terminee"
echo ""

if [ "$DASH_OK" = "1" ] && [ "$NGINX_OK" = "1" ] && [ "$TESTS_OK" = "1" ]; then
    echo -e "${GREEN}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${GREEN}│ ✅ MODULE 4 INSTALLE AVEC SUCCES                            │${NC}"
    echo -e "${GREEN}└─────────────────────────────────────────────────────────────┘${NC}"
else
    echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${YELLOW}│ ⚠ MODULE 4 INSTALLE AVEC AVERTISSEMENTS                     │${NC}"
    echo -e "${YELLOW}└─────────────────────────────────────────────────────────────┘${NC}"
fi

echo ""
echo "  ⚙️  Service Django  : $(systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo unknown)"
echo "  🌐 Nginx           : $(systemctl is-active nginx 2>/dev/null || echo unknown)"
echo "  🔍 Verification    : $([ "$VERIFY_OK" = "1" ] && echo "OK" || echo "WARN")"
echo "  🧪 Tests           : $([ "$TESTS_OK" = "1" ] && echo "OK" || echo "WARN")"
echo ""
echo -e "${CYAN}🌐 URL d'acces  :${NC}  http://${LOCAL_IP}/"
echo -e "${CYAN}👤 Email admin  :${NC}  $ADMIN_EMAIL"
echo -e "${CYAN}🔑 Password     :${NC}  (defini lors de l'install, voir $CREDS_FILE)"
echo ""
echo "  📂 Credentials  : $CREDS_FILE"
echo "  📋 Logs Django  : $DASH_LOG_DIR/dashboard-error.log"
echo "  📋 Logs Nginx   : $DASH_LOG_DIR/nginx-error.log"
echo ""
echo "Prochaine etape : installer le Module PWA (mobile)"
echo ""
