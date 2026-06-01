#!/usr/bin/env bash
# ============================================================================
# SIEM Africa — Installation du Dashboard (Module 4)
# ============================================================================
# Installe le dashboard Django comme service systemd, servi par Gunicorn
# derrière Nginx. Pointe sur la base SQLite partagée avec l'agent (Module 3).
#
# Usage :   sudo bash install_dashboard.sh
# ============================================================================

set -euo pipefail

# --- Configuration ----------------------------------------------------------
APP_USER="siem-dashboard"
APP_DIR="/opt/siem-africa/dashboard"
DB_PATH="/var/lib/siem-africa/siem.db"
REPORTS_DIR="/var/lib/siem-africa/reports"
SESSIONS_DIR="/var/lib/siem-africa/sessions"
SERVICE_NAME="siem-dashboard"
BIND_ADDR="127.0.0.1:8000"
NGINX_PORT="80"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[x]${NC} $1"; }

if [[ $EUID -ne 0 ]]; then
    err "Ce script doit être lancé en root (sudo)."
    exit 1
fi

# --- Nettoyage complet de toute installation précédente ---------------------
# On supprime TOUJOURS l'ancien code pour éviter les mélanges de versions.
log "Nettoyage de l'installation précédente (si existante)..."
systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload 2>/dev/null || true

# Supprimer l'ancienne application (code + venv)
if [[ -d "${APP_DIR}" ]]; then
    warn "Suppression de l'ancien code dans ${APP_DIR}..."
    rm -rf "${APP_DIR}"
fi

# Supprimer l'ancienne config Nginx
rm -f "/etc/nginx/sites-enabled/${SERVICE_NAME}"
rm -f "/etc/nginx/sites-available/${SERVICE_NAME}"
nginx -s reload 2>/dev/null || true

log "Nettoyage terminé — installation propre du nouveau code"

# --- Vérification de la base partagée ---------------------------------------
if [[ ! -f "${DB_PATH}" ]]; then
    err "Base de données introuvable : ${DB_PATH}"
    err "Installez d'abord le Module 2 (base de données) et le Module 1."
    exit 1
fi
log "Base de données partagée trouvée : ${DB_PATH}"

# --- Dépendances système ----------------------------------------------------
log "Installation des dépendances système..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip nginx >/dev/null
# Réparation éventuelle d'apt
dpkg --configure -a 2>/dev/null || true
apt-get install -f -y -qq 2>/dev/null || true

# --- Utilisateur dédié ------------------------------------------------------
if ! getent group "${APP_USER}" &>/dev/null; then
    groupadd --system "${APP_USER}"
fi
if ! id "${APP_USER}" &>/dev/null; then
    log "Création de l'utilisateur système ${APP_USER}..."
    useradd --system --no-create-home --shell /usr/sbin/nologin -g "${APP_USER}" "${APP_USER}"
else
    log "Utilisateur ${APP_USER} déjà présent."
    # S'assurer que l'utilisateur appartient bien au bon groupe
    usermod -g "${APP_USER}" "${APP_USER}" 2>/dev/null || true
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

# --- Clé secrète Django ------------------------------------------------------
SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(50))')"

# --- IP du serveur (pour CSRF et ALLOWED_HOSTS) ------------------------------
SERVER_IP="$(hostname -I | awk '{print $1}')"
log "IP du serveur détectée : ${SERVER_IP}"

# --- Création des tables de chat (idempotent) -------------------------------
log "Création des tables de chat (si absentes)..."
SECRET_KEY="${SECRET_KEY}" SIEM_DB_PATH="${DB_PATH}" \
    "${APP_DIR}/venv/bin/python" "${APP_DIR}/manage.py" shell -c \
    "from core.chat_db import ensure_chat_tables; ensure_chat_tables(); print('Tables de chat OK')" \
    2>/dev/null || warn "Création des tables de chat reportée au premier démarrage."

# --- Collecte des fichiers statiques ----------------------------------------
log "Collecte des fichiers statiques..."
SECRET_KEY="${SECRET_KEY}" SIEM_DB_PATH="${DB_PATH}" \
    "${APP_DIR}/venv/bin/python" "${APP_DIR}/manage.py" collectstatic --noinput >/dev/null

# --- Permissions -------------------------------------------------------------
chown -R "${APP_USER}:${APP_USER}" "${APP_DIR}" "${REPORTS_DIR}" "${SESSIONS_DIR}"
# L'utilisateur du dashboard doit pouvoir lire/écrire la base partagée
chgrp "${APP_USER}" "${DB_PATH}" 2>/dev/null || true
chmod g+rw "${DB_PATH}" 2>/dev/null || true

# --- Service systemd ---------------------------------------------------------
log "Création du service systemd ${SERVICE_NAME}..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<UNIT
[Unit]
Description=SIEM Africa Dashboard
After=network.target

[Service]
Type=simple
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${APP_DIR}
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
StandardOutput=null
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT

# --- Configuration Nginx -----------------------------------------------------
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
    echo "  Accès        : http://<adresse-du-serveur>/"
    echo "  Service      : systemctl status ${SERVICE_NAME}"
    echo "  Logs         : journalctl -u ${SERVICE_NAME} -f"
    echo "  Connexion    : avec le compte ADMIN créé à l'installation"
    echo "                 du Module 2."
    echo "============================================================"
else
    err "Le service n'a pas démarré. Vérifiez : journalctl -u ${SERVICE_NAME}"
    exit 1
fi
