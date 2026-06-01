#!/usr/bin/env bash
# ============================================================================
# SIEM Africa — Réinstallation propre depuis GitHub
# Usage : sudo bash reinstall.sh
# ============================================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[x]${NC} $1"; exit 1; }

[[ $EUID -ne 0 ]] && err "Lancer en root : sudo bash reinstall.sh"

SERVICE_NAME="siem-dashboard"
APP_DIR="/opt/siem-africa/dashboard"
REPO_URL="https://github.com/africa-siem/test.git"
CLONE_DIR="/tmp/siem-clone"
DB_PATH="/var/lib/siem-africa/siem.db"

# ============================================================
# 1. Vérifier la BDD
# ============================================================
[[ ! -f "$DB_PATH" ]] && err "Base introuvable : $DB_PATH — installez M1 et M2 d'abord"
log "Base de données trouvée : $DB_PATH"

# ============================================================
# 2. Arrêt et suppression complète de l'ancienne installation
# ============================================================
log "Arrêt du service existant..."
systemctl stop "$SERVICE_NAME" 2>/dev/null || true
systemctl disable "$SERVICE_NAME" 2>/dev/null || true
rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload 2>/dev/null || true

log "Suppression de l'ancien code..."
rm -rf "$APP_DIR"
rm -rf "$CLONE_DIR"

log "Suppression de l'ancienne config Nginx..."
rm -f "/etc/nginx/sites-enabled/$SERVICE_NAME"
rm -f "/etc/nginx/sites-available/$SERVICE_NAME"
nginx -s reload 2>/dev/null || true

log "Nettoyage terminé."

# ============================================================
# 3. Cloner le dépôt
# ============================================================
log "Clonage du dépôt : $REPO_URL ..."
apt-get install -y -qq git 2>/dev/null || true
git clone "$REPO_URL" "$CLONE_DIR"
log "Clonage terminé."

# ============================================================
# 4. Vérifier que le bon code est présent
# ============================================================
[[ ! -f "$CLONE_DIR/dashboard/core/models.py" ]] && \
    err "dashboard/core/models.py introuvable dans le repo — vérifiez la structure."

[[ ! -f "$CLONE_DIR/dashboard/install_dashboard.sh" ]] && \
    err "dashboard/install_dashboard.sh introuvable dans le repo."

MANAGED=$(grep -c "managed = False" "$CLONE_DIR/dashboard/core/models.py" || echo "0")
[[ "$MANAGED" -eq 0 ]] && err "Mauvaise version détectée — managed=False absent dans models.py"
log "Bon code confirmé ($MANAGED modèles managed=False)"

# ============================================================
# 5. Injecter le settings.py corrigé (fix CSRF)
# ============================================================
log "Application du fix CSRF dans settings.py..."
SETTINGS="$CLONE_DIR/dashboard/config/settings.py"

# Remplacer le bloc CSRF
python3 - << PYEOF
import re

with open("$SETTINGS", "r") as f:
    content = f.read()

# Fix SESSION SameSite
content = content.replace('SESSION_COOKIE_SAMESITE = "Strict"', 'SESSION_COOKIE_SAMESITE = "Lax"')

# Remplacer tout le bloc CSRF
old_csrf = '''# --- CSRF ---------------------------------------------------------------------
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = "Strict"'''

new_csrf = '''# --- CSRF ---------------------------------------------------------------------
# CSRF_COOKIE_HTTPONLY doit rester False pour que le middleware puisse lire
# le token. True casse la validation derriere un proxy Nginx.
CSRF_COOKIE_HTTPONLY = False
CSRF_COOKIE_SAMESITE = "Lax"

# Origines de confiance (obligatoire Django 4.x+ derriere un proxy).
_trusted = os.environ.get("DJANGO_TRUSTED_ORIGINS", "")
if _trusted:
    CSRF_TRUSTED_ORIGINS = [o.strip() for o in _trusted.split(",") if o.strip()]
else:
    CSRF_TRUSTED_ORIGINS = ["http://*", "https://*"]'''

if old_csrf in content:
    content = content.replace(old_csrf, new_csrf)
    print("Fix CSRF applique")
elif "CSRF_TRUSTED_ORIGINS" in content:
    print("Fix CSRF deja present")
else:
    # Ajouter apres SESSION block
    content = content + "\n" + new_csrf + "\n"
    print("Fix CSRF ajoute en fin de fichier")

with open("$SETTINGS", "w") as f:
    f.write(content)
PYEOF

# ============================================================
# 6. Injecter SERVER_IP + TRUSTED_ORIGINS dans install_dashboard.sh
# ============================================================
log "Application du fix SERVER_IP dans install_dashboard.sh..."
INSTALL_SH="$CLONE_DIR/dashboard/install_dashboard.sh"

python3 - << PYEOF
with open("$INSTALL_SH", "r") as f:
    content = f.read()

# Ajouter SERVER_IP apres SECRET_KEY si pas deja present
if "SERVER_IP" not in content:
    old = "SECRET_KEY=\"\$(python3 -c 'import secrets; print(secrets.token_urlsafe(50))')\""
    new = old + '''

# --- IP du serveur (pour CSRF et ALLOWED_HOSTS) ---
SERVER_IP="\$(hostname -I | awk '{print \$1}')"
log "IP du serveur : \${SERVER_IP}"'''
    content = content.replace(old, new, 1)
    print("SERVER_IP ajoute")
else:
    print("SERVER_IP deja present")

# Ajouter TRUSTED_ORIGINS dans le service systemd si pas deja present
if "DJANGO_TRUSTED_ORIGINS" not in content:
    old = 'Environment="DJANGO_SECURE_COOKIES=false"\nExecStart='
    new = 'Environment="DJANGO_SECURE_COOKIES=false"\nEnvironment="DJANGO_ALLOWED_HOSTS=\${SERVER_IP},localhost,127.0.0.1"\nEnvironment="DJANGO_TRUSTED_ORIGINS=http://\${SERVER_IP},http://localhost"\nExecStart='
    content = content.replace(old, new, 1)
    print("DJANGO_TRUSTED_ORIGINS ajoute")
else:
    print("DJANGO_TRUSTED_ORIGINS deja present")

with open("$INSTALL_SH", "w") as f:
    f.write(content)
PYEOF

# ============================================================
# 7. Lancer l'installation
# ============================================================
log "Lancement de l'installation du dashboard..."
cd "$CLONE_DIR/dashboard"
bash install_dashboard.sh

