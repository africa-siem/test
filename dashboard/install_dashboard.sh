#!/usr/bin/env bash
# ============================================================================
# SIEM Africa — Installation du Dashboard (Module 4)
#
# Ce script :
#   1. Vérifie les prérequis (BDD M2, groupe partagé siem-africa)
#   2. Crée l'utilisateur siem-dashboard avec groupe primaire siem-africa
#   3. Installe les dépendances système et le venv Python
#   4. Copie le code, configure dossiers et permissions
#   5. Crée les tables de chat (idempotent)
#   6. Collecte les fichiers statiques
#   7. Installe le service systemd + Nginx
#   8. Append les credentials dans /root/siem_credentials.txt
#
# Usage : sudo bash install_dashboard.sh
# ============================================================================
set -euo pipefail

# --- Configuration ----------------------------------------------------------
APP_USER="siem-dashboard"
SHARED_GROUP="siem-africa"
APP_DIR="/opt/siem-africa/dashboard"
DATA_DIR="/var/lib/siem-africa"
DB_PATH="${DATA_DIR}/siem.db"
REPORTS_DIR="${DATA_DIR}/reports"
SESSIONS_DIR="${DATA_DIR}/sessions"
SERVICE_NAME="siem-dashboard"
BIND_ADDR="127.0.0.1:8000"
NGINX_PORT="80"
CREDENTIALS_FILE="/root/siem_credentials.txt"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[x]${NC} $1"; exit 1; }

if [[ $EUID -ne 0 ]]; then
    err "Ce script doit être lancé en root (sudo)."
fi

# --- Nettoyage complet -------------------------------------------------------
log "Nettoyage de l'installation précédente (si existante)..."
systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload 2>/dev/null || true
if [[ -d "${APP_DIR}" ]]; then
    warn "Suppression de l'ancien code dans ${APP_DIR}..."
    rm -rf "${APP_DIR}"
fi
rm -f "/etc/nginx/sites-enabled/${SERVICE_NAME}"
rm -f "/etc/nginx/sites-available/${SERVICE_NAME}"
nginx -s reload 2>/dev/null || true
log "Nettoyage terminé."

# --- Vérification prérequis (BDD + groupe partagé) ---------------------------
[[ ! -f "${DB_PATH}" ]] && err "Base introuvable : ${DB_PATH} — installez M1 et M2 d'abord."
log "Base de données partagée trouvée : ${DB_PATH}"

if ! getent group "${SHARED_GROUP}" &>/dev/null; then
    err "Groupe partagé '${SHARED_GROUP}' introuvable — installez M1 et M2 d'abord."
fi
log "Groupe partagé '${SHARED_GROUP}' présent."

# --- Dépendances système -----------------------------------------------------
log "Installation des dépendances système..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip nginx >/dev/null
dpkg --configure -a 2>/dev/null || true
apt-get install -f -y -qq 2>/dev/null || true

# --- Utilisateur (groupe primaire = siem-africa) -----------------------------
if ! id "${APP_USER}" &>/dev/null; then
    log "Création de l'utilisateur ${APP_USER} (groupe primaire : ${SHARED_GROUP})..."
    useradd --system --no-create-home --shell /usr/sbin/nologin \
        -g "${SHARED_GROUP}" "${APP_USER}"
else
    log "Utilisateur ${APP_USER} déjà présent — synchronisation du groupe primaire..."
    usermod -g "${SHARED_GROUP}" "${APP_USER}"
    # Supprimer l'ancien groupe personnel s'il traîne (anciennes installations)
    if getent group "${APP_USER}" &>/dev/null; then
        groupdel "${APP_USER}" 2>/dev/null || \
            warn "Groupe personnel '${APP_USER}' n'a pas pu être supprimé (références restantes)."
    fi
fi

# --- Copie de l'application --------------------------------------------------
log "Copie de l'application vers ${APP_DIR}..."
mkdir -p "${APP_DIR}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp -r "${SCRIPT_DIR}/." "${APP_DIR}/"

# --- Environnement Python ----------------------------------------------------
log "Création de l'environnement virtuel Python..."
python3 -m venv "${APP_DIR}/venv"
"${APP_DIR}/venv/bin/pip" install --quiet --upgrade pip
"${APP_DIR}/venv/bin/pip" install --quiet -r "${APP_DIR}/requirements.txt"
"${APP_DIR}/venv/bin/pip" install --quiet gunicorn reportlab openpyxl

# --- Dossiers de données -----------------------------------------------------
mkdir -p "${REPORTS_DIR}" "${SESSIONS_DIR}"

# --- Clé secrète + IP serveur ------------------------------------------------
SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(50))')"
SERVER_IP="$(hostname -I | awk '{print $1}')"
log "IP du serveur détectée : ${SERVER_IP}"

# --- Tables de chat (idempotent) ---------------------------------------------
log "Création des tables de chat (si absentes)..."
SECRET_KEY="${SECRET_KEY}" SIEM_DB_PATH="${DB_PATH}" \
    "${APP_DIR}/venv/bin/python" "${APP_DIR}/manage.py" shell -c \
    "from core.chat_db import ensure_chat_tables; ensure_chat_tables(); print('Tables de chat OK')" \
    2>/dev/null || warn "Création des tables de chat reportée au premier démarrage."

# --- Fichiers statiques ------------------------------------------------------
log "Collecte des fichiers statiques..."
SECRET_KEY="${SECRET_KEY}" SIEM_DB_PATH="${DB_PATH}" \
    "${APP_DIR}/venv/bin/python" "${APP_DIR}/manage.py" collectstatic --noinput >/dev/null

# --- Permissions -------------------------------------------------------------
# Code et dossiers du dashboard : siem-dashboard:siem-africa
chown -R "${APP_USER}:${SHARED_GROUP}" "${APP_DIR}" "${REPORTS_DIR}" "${SESSIONS_DIR}"
# Dossiers d'écriture : rwx pour user et groupe, rien pour autres
chmod -R u+rwX,g+rwX,o-rwx "${REPORTS_DIR}" "${SESSIONS_DIR}"
# La BDD reste propriétaire à M2 (siem-db:siem-africa) — on n'y touche PAS.
# Le user siem-dashboard accède en lecture/écriture via le groupe siem-africa.
log "Permissions appliquées (BDD inchangée, dossiers du dashboard alignés sur ${SHARED_GROUP})."

# --- Service systemd ---------------------------------------------------------
log "Création du service systemd ${SERVICE_NAME}..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<UNIT
[Unit]
Description=SIEM Africa Dashboard
After=network.target

[Service]
Type=simple
User=${APP_USER}
Group=${SHARED_GROUP}
WorkingDirectory=${APP_DIR}
# /run/siem-dashboard auto-créé/supprimé par systemd, sert de HOME à gunicorn
RuntimeDirectory=siem-dashboard
RuntimeDirectoryMode=0750
Environment="HOME=/run/siem-dashboard"
Environment="SIEM_DB_PATH=${DB_PATH}"
Environment="SIEM_REPORTS_PATH=${REPORTS_DIR}"
Environment="SIEM_SESSION_PATH=${SESSIONS_DIR}"
Environment="DJANGO_SECRET_KEY=${SECRET_KEY}"
Environment="DJANGO_DEBUG=false"
Environment="DJANGO_SECURE_COOKIES=false"
Environment="DJANGO_ALLOWED_HOSTS=${SERVER_IP},localhost,127.0.0.1"
Environment="DJANGO_TRUSTED_ORIGINS=http://${SERVER_IP},http://localhost"
ExecStart=${APP_DIR}/venv/bin/gunicorn config.wsgi:application --bind ${BIND_ADDR} --workers 3 --timeout 120
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT

# --- Nginx -------------------------------------------------------------------
log "Configuration de Nginx..."
cat > "/etc/nginx/sites-available/${SERVICE_NAME}" <<NGINX
server {
    listen ${NGINX_PORT};
    server_name _;

    client_max_body_size 10M;

    location /static/ {
        alias ${APP_DIR}/staticfiles/;
        expires 7d;
    }

    location / {
        proxy_pass http://${BIND_ADDR};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
NGINX

ln -sf "/etc/nginx/sites-available/${SERVICE_NAME}" "/etc/nginx/sites-enabled/${SERVICE_NAME}"
rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
nginx -t 2>/dev/null && systemctl reload nginx

# --- Credentials -------------------------------------------------------------
log "Enregistrement des credentials dans ${CREDENTIALS_FILE}..."
touch "${CREDENTIALS_FILE}"
chmod 600 "${CREDENTIALS_FILE}"
# Append uniquement si la section n'existe pas déjà
if ! grep -q "\[MODULE 4 - DASHBOARD\]" "${CREDENTIALS_FILE}" 2>/dev/null; then
    cat >> "${CREDENTIALS_FILE}" <<CREDS

[MODULE 4 - DASHBOARD]
Installation date : $(date '+%Y-%m-%d %H:%M:%S')
URL               : http://${SERVER_IP}/
Service systemd   : ${SERVICE_NAME}
App user          : ${APP_USER} (groupe : ${SHARED_GROUP})
App directory     : ${APP_DIR}
Reports directory : ${REPORTS_DIR}
Sessions directory: ${SESSIONS_DIR}
Django SECRET_KEY : ${SECRET_KEY}
CREDS
else
    warn "Section [MODULE 4 - DASHBOARD] déjà présente — non écrasée."
fi

# --- Démarrage ---------------------------------------------------------------
log "Démarrage du service..."
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}" >/dev/null 2>&1
systemctl start "${SERVICE_NAME}"

sleep 3
if systemctl is-active --quiet "${SERVICE_NAME}"; then
    log "Le dashboard est actif."
    echo ""
    echo "============================================================"
    echo "  Dashboard SIEM Africa installé avec succès"
    echo "============================================================"
    echo "  Accès        : http://${SERVER_IP}/"
    echo "  Service      : systemctl status ${SERVICE_NAME}"
    echo "  Logs         : journalctl -u ${SERVICE_NAME} -f"
    echo "  Credentials  : ${CREDENTIALS_FILE}"
    echo "============================================================"
else
    err "Le service n'a pas démarré. Vérifiez : journalctl -u ${SERVICE_NAME}"
fi
