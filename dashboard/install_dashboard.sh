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

# IP du serveur, utilisée pour CSRF_TRUSTED_ORIGINS (validation des POST login).
# Surchargeable : SERVER_IP=192.168.1.128 sudo bash install_dashboard.sh
SERVER_IP="${SERVER_IP:-$(hostname -I 2>/dev/null | awk '{print $1}')}"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[x]${NC} $1"; }

if [[ $EUID -ne 0 ]]; then
    err "Ce script doit être lancé en root (sudo)."
    exit 1
fi

# --- Détection d'une installation précédente --------------------------------
if systemctl list-unit-files | grep -q "${SERVICE_NAME}.service"; then
    warn "Une installation précédente du dashboard a été détectée."
    warn "Elle va être arrêtée et remplacée proprement."
    systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
fi

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
if ! id "${APP_USER}" &>/dev/null; then
    log "Création de l'utilisateur système ${APP_USER}..."
    useradd --system --no-create-home --shell /usr/sbin/nologin "${APP_USER}"
else
    log "Utilisateur ${APP_USER} déjà présent."
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

# --- Création des tables de chat (idempotent) -------------------------------
log "Création des tables de chat (si absentes)..."
SECRET_KEY="${SECRET_KEY}" SIEM_DB_PATH="${DB_PATH}" \
    "${APP_DIR}/venv/bin/python" "${APP_DIR}/manage.py" shell -c \
    "from core.chat_db import ensure_chat_tables; ensure_chat_tables(); print('Tables de chat OK')" \
    2>/dev/null || warn "Création des tables de chat reportée au premier démarrage."

# --- Rôle ADMIN + user de test (idempotent, auto-adaptatif) -----------------
# Garantit qu'un rôle ADMIN existe (FK obligatoire pour créer un user) et, si
# CREATE_TEST_USER=1, crée un compte de test utilisable par dashboard/tests/.
# Le script détecte seul l'app du modèle User (users.* ou core.*) et les champs
# réellement présents : il fonctionne donc sur les deux versions du dashboard.
#
# Activer le compte de test :   CREATE_TEST_USER=1 sudo bash install_dashboard.sh
# Identifiants par défaut (surchargeables) :
TEST_USER_EMAIL="${TEST_USER_EMAIL:-test-auth@siem-africa.local}"
TEST_USER_PASSWORD="${TEST_USER_PASSWORD:-TestPass1234567!}"
CREATE_TEST_USER="${CREATE_TEST_USER:-0}"

log "Vérification du rôle ADMIN (et compte de test si demandé)..."
SECRET_KEY="${SECRET_KEY}" SIEM_DB_PATH="${DB_PATH}" \
  CREATE_TEST_USER="${CREATE_TEST_USER}" \
  TEST_USER_EMAIL="${TEST_USER_EMAIL}" \
  TEST_USER_PASSWORD="${TEST_USER_PASSWORD}" \
  "${APP_DIR}/venv/bin/python" "${APP_DIR}/manage.py" shell <<'PYEOF' 2>/dev/null || warn "Étape rôle/user de test reportée."
import os, uuid
from datetime import datetime

# 1. Localiser le modèle User quelle que soit l'app (users.* puis core.*)
User = None
for mod in ("users.models", "core.models"):
    try:
        m = __import__(mod, fromlist=["User"])
        User = getattr(m, "User")
        break
    except Exception:
        continue
if User is None:
    print("User introuvable — etape ignoree")
    raise SystemExit(0)

fields = {f.name for f in User._meta.get_fields()}

# 2. Fonction de hash : reutilise celle du projet, sinon argon2 direct
def _hash(pwd):
    for mod in ("core.auth", "users.auth", "core.security"):
        try:
            h = __import__(mod, fromlist=["hash_password"])
            return h.hash_password(pwd)
        except Exception:
            continue
    from argon2 import PasswordHasher
    return PasswordHasher().hash(pwd)

# 3. Garantir le role ADMIN si le modele User a une FK 'role'
role_obj = None
if "role" in fields:
    try:
        RoleModel = User._meta.get_field("role").related_model
        rf = {f.name for f in RoleModel._meta.get_fields()}
        q = RoleModel.objects.filter(code__iexact="ADMIN") if "code" in rf else RoleModel.objects.all()
        role_obj = q.first()
        if role_obj is None:
            kw = {}
            if "code" in rf: kw["code"] = "ADMIN"
            if "name" in rf: kw["name"] = "Administrateur"
            if "permissions" in rf: kw["permissions"] = "*"
            role_obj = RoleModel.objects.create(**kw)
            print("Role ADMIN cree")
        else:
            print("Role ADMIN deja present")
    except Exception as e:
        print("Role ADMIN : etape ignoree (%s)" % e)

# 4. Creer le user de test seulement si demande
if os.environ.get("CREATE_TEST_USER") != "1":
    print("Compte de test non demande (CREATE_TEST_USER!=1)")
    raise SystemExit(0)

email = os.environ["TEST_USER_EMAIL"]
pwd   = os.environ["TEST_USER_PASSWORD"]
User.objects.filter(email=email).delete()

# create_user si le manager l'expose, sinon create() en remplissant les champs presents
if hasattr(User.objects, "create_user"):
    kw = {"email": email, "password": pwd}
    if "full_name" in fields:    kw["full_name"] = "Test Auth"
    if "role" in fields and role_obj is not None: kw["role"] = role_obj
    if "is_staff" in fields:     kw["is_staff"] = True
    if "is_superuser" in fields: kw["is_superuser"] = True
    u = User.objects.create_user(**kw)
    if "must_change_pwd" in fields:
        u.must_change_pwd = 0; u.save()
else:
    kw = {"email": email}
    if "user_uuid" in fields:     kw["user_uuid"] = str(uuid.uuid4())
    if "first_name" in fields:    kw["first_name"] = "Test"
    if "last_name" in fields:     kw["last_name"] = "Auth"
    if "full_name" in fields:     kw["full_name"] = "Test Auth"
    if "password_hash" in fields: kw["password_hash"] = _hash(pwd)
    if "role" in fields and role_obj is not None: kw["role"] = role_obj
    if "is_active" in fields:      kw["is_active"] = 1
    if "is_locked" in fields:      kw["is_locked"] = 0
    if "must_change_pwd" in fields: kw["must_change_pwd"] = 0
    if "language" in fields:       kw["language"] = "fr"
    if "created_at" in fields:     kw["created_at"] = datetime.now().isoformat()
    User.objects.create(**kw)
print("Compte de test pret : %s" % email)
PYEOF

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
Environment="DJANGO_CSRF_TRUSTED_ORIGINS=http://${SERVER_IP},http://localhost,http://127.0.0.1"
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
    if [ "${CREATE_TEST_USER}" = "1" ]; then
    echo "  Compte test  : ${TEST_USER_EMAIL} / ${TEST_USER_PASSWORD}"
    echo "                 (créé pour dashboard/tests/ — à ne pas laisser en prod)"
    fi
    echo "============================================================"
else
    err "Le service n'a pas démarré. Vérifiez : journalctl -u ${SERVICE_NAME}"
    exit 1
fi
