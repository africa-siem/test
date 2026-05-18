#!/usr/bin/env bash
# ==============================================================================
#  SIEM AFRICA - Module 3 - Installation de l'agent (Bloc 1 - Fondations)
#
#  Ce script :
#    1. Vérifie les prérequis (Ubuntu, Python, BDD M2, Wazuh)
#    2. Crée le groupe Unix siem-africa et l'utilisateur siem-agent
#    3. Crée les dossiers et applique les permissions
#    4. Crée le venv Python et installe les dépendances
#    5. Copie le code Python dans /opt/siem-africa-agent/
#    6. Configure le fichier /etc/siem-africa/agent.env
#    7. Installe le service systemd
#    8. Démarre l'agent et vérifie qu'il tourne
#    9. Append les credentials dans /root/siem_credentials.txt
#
#  Usage : sudo bash install_agent.sh
# ==============================================================================

# IMPORTANT : pas de "set -e" - on gère les erreurs explicitement
# pour éviter les arrêts silencieux

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

log_step() { echo ""; echo -e "${CYAN}━━━ $* ━━━${NC}"; }
log_ok()   { echo -e "  ${GREEN}✓${NC} $*"; }
log_warn() { echo -e "  ${YELLOW}!${NC} $*"; }
log_err()  { echo -e "  ${RED}✗${NC} $*"; }
log_info() { echo "    $*"; }

# ----------------------------------------------------------------------------
# Vérification root
# ----------------------------------------------------------------------------
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Ce script doit être exécuté en root (sudo)${NC}"
    exit 1
fi

clear
echo -e "${CYAN}═══════════════════════════════════════════════════════════"
echo "  SIEM Africa - Module 3 - Installation Agent v5"
echo "  8 blocs (fondations + DB + watcher + processor + IA"
echo "         + email + active response + workers cron)"
echo -e "═══════════════════════════════════════════════════════════${NC}"

# ----------------------------------------------------------------------------
# Constantes
# ----------------------------------------------------------------------------
AGENT_DIR="/opt/siem-africa-agent"
AGENT_USER="siem-agent"
SIEM_GROUP="siem-africa"
LOG_DIR="/var/log/siem-africa"
CONFIG_DIR="/etc/siem-africa"
AGENT_ENV="$CONFIG_DIR/agent.env"
DB_PATH="/var/lib/siem-africa/siem.db"
CREDENTIALS_FILE="/root/siem_credentials.txt"
WAZUH_LOG="/var/ossec/logs/alerts/alerts.json"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ============================================================================
# 1. Désinstallation propre si réinstallation
# ============================================================================
log_step "Vérification d'une installation précédente"

if systemctl is-active --quiet siem-agent 2>/dev/null; then
    log_warn "Une installation précédente est détectée"
    log_info "Arrêt du service en cours..."
    systemctl stop siem-agent 2>/dev/null
    systemctl disable siem-agent 2>/dev/null
    log_ok "Service précédent arrêté"
fi

if [ -d "$AGENT_DIR" ]; then
    log_info "Suppression de l'ancienne installation $AGENT_DIR"
    rm -rf "$AGENT_DIR"
    log_ok "Ancienne installation supprimée"
fi

# ============================================================================
# 2. Prérequis système
# ============================================================================
log_step "Vérification des prérequis"

# Distribution
if [ ! -f /etc/os-release ]; then
    log_err "OS non identifié"
    exit 1
fi
source /etc/os-release

if [ "$ID" != "ubuntu" ]; then
    log_warn "OS non testé : $PRETTY_NAME (continue à vos risques)"
else
    if [[ "$VERSION_ID" =~ ^(20\.04|22\.04|24\.04)$ ]]; then
        log_ok "Ubuntu $VERSION_ID supporté"
    else
        log_warn "Ubuntu $VERSION_ID non testé"
    fi
fi

# Python 3
if ! command -v python3 &>/dev/null; then
    log_err "python3 non installé"
    log_info "Installation : apt install -y python3 python3-venv"
    exit 1
fi
PY_VERSION=$(python3 --version | cut -d' ' -f2)
log_ok "Python $PY_VERSION"

# venv module
if ! python3 -c "import venv" 2>/dev/null; then
    log_warn "python3-venv non installé, installation..."
    apt-get install -y python3-venv 2>&1 | tail -2
fi

# SQLite
if ! command -v sqlite3 &>/dev/null; then
    log_warn "sqlite3 non installé, installation..."
    apt-get install -y sqlite3 2>&1 | tail -2
fi
log_ok "sqlite3 OK"

# BDD M2
if [ ! -f "$DB_PATH" ]; then
    log_err "BDD M2 introuvable : $DB_PATH"
    log_info "Le Module 2 doit être installé avant le Module 3"
    exit 1
fi
log_ok "BDD M2 trouvée : $DB_PATH"

# Wazuh
if [ ! -d /var/ossec ]; then
    log_warn "Wazuh non installé : /var/ossec absent"
    log_warn "L'agent démarrera mais ne traitera aucune alerte"
else
    log_ok "Wazuh détecté"
fi

# ============================================================================
# 3. Groupe siem-africa et utilisateur siem-agent
# ============================================================================
log_step "Création utilisateur et groupe Unix"

# Groupe siem-africa (doit déjà exister depuis le Module 2)
if ! getent group "$SIEM_GROUP" &>/dev/null; then
    log_info "Création du groupe $SIEM_GROUP"
    groupadd --system "$SIEM_GROUP"
    log_ok "Groupe $SIEM_GROUP créé"
else
    log_ok "Groupe $SIEM_GROUP existe"
fi

# User siem-agent
if id "$AGENT_USER" &>/dev/null; then
    log_ok "Utilisateur $AGENT_USER existe"
else
    log_info "Création de l'utilisateur $AGENT_USER"
    useradd --system --no-create-home --shell /usr/sbin/nologin \
            --gid "$SIEM_GROUP" "$AGENT_USER"
    log_ok "Utilisateur $AGENT_USER créé"
fi

# Ajouter siem-agent au groupe wazuh (pour lire alerts.json)
if getent group wazuh &>/dev/null; then
    if ! groups "$AGENT_USER" | grep -q wazuh; then
        usermod -a -G wazuh "$AGENT_USER"
        log_ok "$AGENT_USER ajouté au groupe wazuh"
    else
        log_ok "$AGENT_USER déjà dans le groupe wazuh"
    fi
fi

# Ajouter siem-agent au groupe snort (pour lire le log snort)
if getent group snort &>/dev/null; then
    if ! groups "$AGENT_USER" | grep -q snort; then
        usermod -a -G snort "$AGENT_USER"
        log_ok "$AGENT_USER ajouté au groupe snort"
    fi
fi

log_info "Groupes finaux : $(groups $AGENT_USER | cut -d: -f2)"

# ============================================================================
# 4. Création des dossiers
# ============================================================================
log_step "Création des dossiers"

# Dossier de l'agent
mkdir -p "$AGENT_DIR"
chown "$AGENT_USER:$SIEM_GROUP" "$AGENT_DIR"
chmod 755 "$AGENT_DIR"
log_ok "$AGENT_DIR créé"

# Dossier de logs
mkdir -p "$LOG_DIR"
chown "$AGENT_USER:$SIEM_GROUP" "$LOG_DIR"
chmod 770 "$LOG_DIR"
log_ok "$LOG_DIR créé (logs agent)"

# Dossier de config
mkdir -p "$CONFIG_DIR"
chmod 750 "$CONFIG_DIR"
log_ok "$CONFIG_DIR créé (configuration)"

# Dossier de backup BDD (Bloc 8)
mkdir -p /var/backups/siem-africa
chown "$AGENT_USER:$SIEM_GROUP" /var/backups/siem-africa
chmod 770 /var/backups/siem-africa
log_ok "/var/backups/siem-africa créé (backups BDD)"

# Sudoers pour iptables (Bloc 7 - Active Response)
# siem-agent doit pouvoir exécuter iptables sans password
SUDOERS_FILE="/etc/sudoers.d/siem-agent"
cat > "$SUDOERS_FILE" <<EOF
# SIEM Africa - Agent autorisé à utiliser iptables pour bloquer des IPs
siem-agent ALL=(root) NOPASSWD: /sbin/iptables, /usr/sbin/iptables
EOF
chmod 440 "$SUDOERS_FILE"
log_ok "Sudoers iptables configuré pour $AGENT_USER"

# Permissions sur la BDD (essentiel)
chgrp "$SIEM_GROUP" "$DB_PATH" 2>/dev/null
chmod 660 "$DB_PATH" 2>/dev/null
# Le dossier parent doit etre traversable
chmod 770 "$(dirname $DB_PATH)" 2>/dev/null
chgrp "$SIEM_GROUP" "$(dirname $DB_PATH)" 2>/dev/null
log_ok "Permissions BDD ajustées"

# ============================================================================
# 5. Venv Python
# ============================================================================
log_step "Création du venv Python"

cd "$AGENT_DIR"
python3 -m venv venv 2>&1 | tail -2
if [ ! -x "$AGENT_DIR/venv/bin/python" ]; then
    log_err "Création venv échouée"
    exit 1
fi
log_ok "venv Python créé"

# Mise à jour pip
"$AGENT_DIR/venv/bin/pip" install --upgrade pip 2>&1 | tail -1

# Création requirements.txt
cat > /tmp/m3_requirements.txt <<'EOF'
# Communication HTTP (Ollama API)
requests>=2.31.0

# Surveillance fichier en temps réel (Wazuh alerts.json)
inotify-simple>=1.3.5

# Templates email (futur bloc 6)
jinja2>=3.1.2
EOF

log_info "Installation des paquets Python..."
"$AGENT_DIR/venv/bin/pip" install -r /tmp/m3_requirements.txt 2>&1 | tail -3

# Vérifier que ça a marché
if ! "$AGENT_DIR/venv/bin/python" -c "import requests, inotify_simple, jinja2" 2>/dev/null; then
    log_err "Installation des paquets Python a échoué"
    exit 1
fi
log_ok "Paquets Python installés (requests, inotify-simple, jinja2)"

# ============================================================================
# 6. Copie du code
# ============================================================================
log_step "Copie du code"

if [ ! -d "$SCRIPT_DIR/opt" ]; then
    log_err "Dossier opt/ introuvable dans $SCRIPT_DIR"
    log_info "Le script doit être lancé depuis le dossier agent/"
    exit 1
fi

# Copier le contenu de opt/ vers AGENT_DIR
cp -r "$SCRIPT_DIR/opt/"* "$AGENT_DIR/"

# Permissions
chown -R "$AGENT_USER:$SIEM_GROUP" "$AGENT_DIR"
find "$AGENT_DIR" -type d -exec chmod 755 {} \;
find "$AGENT_DIR" -type f -exec chmod 644 {} \;
chmod 755 "$AGENT_DIR/main.py"

log_ok "Code copié et permissions ajustées"

# ============================================================================
# 7. Configuration agent.env
# ============================================================================
log_step "Configuration agent.env"

if [ ! -f "$AGENT_ENV" ]; then
    cat > "$AGENT_ENV" <<EOF
# SIEM Africa - Agent (Module 3) - Configuration runtime
# Modifiez ce fichier puis redémarrez l'agent :
#   sudo systemctl restart siem-agent

# Niveau de log : DEBUG, INFO, WARNING, ERROR
LOG_LEVEL=INFO

# Intervalle de polling Wazuh si inotify échoue (secondes)
WAZUH_POLL_INTERVAL=5
EOF
    chmod 640 "$AGENT_ENV"
    chgrp "$SIEM_GROUP" "$AGENT_ENV"
    log_ok "$AGENT_ENV créé"
else
    log_ok "$AGENT_ENV existe déjà (non modifié)"
fi

# ============================================================================
# 8. Service systemd
# ============================================================================
log_step "Installation service systemd"

if [ ! -f "$SCRIPT_DIR/systemd/siem-agent.service" ]; then
    log_err "Fichier siem-agent.service introuvable"
    exit 1
fi

cp "$SCRIPT_DIR/systemd/siem-agent.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable siem-agent 2>&1 | grep -v "^Created" | head -2
log_ok "Service systemd installé et activé"

# ============================================================================
# 9. Démarrage du service
# ============================================================================
log_step "Démarrage de l'agent"

systemctl start siem-agent
sleep 4

if systemctl is-active --quiet siem-agent; then
    log_ok "siem-agent ACTIF"

    # Afficher les premières lignes du log pour vérification
    echo ""
    log_info "Premières lignes des logs :"
    journalctl -u siem-agent -n 15 --no-pager 2>/dev/null | tail -10 | sed 's/^/      /'
else
    log_err "siem-agent NON ACTIF"
    log_info "Voir les logs : journalctl -u siem-agent -n 50 --no-pager"
    exit 1
fi

# ============================================================================
# 10. Append credentials
# ============================================================================
log_step "Mise à jour credentials"

if [ -f "$CREDENTIALS_FILE" ]; then
    # Append seulement si la section n'existe pas déjà
    if ! grep -q "\[MODULE 3 - AGENT\]" "$CREDENTIALS_FILE"; then
        cat >> "$CREDENTIALS_FILE" <<EOF

═══════════════════════════════════════════════════════════
[MODULE 3 - AGENT]
═══════════════════════════════════════════════════════════
Utilisateur Unix     : $AGENT_USER (shell /usr/sbin/nologin)
Groupe principal     : $SIEM_GROUP
Groupes additionnels : wazuh, snort
Dossier code         : $AGENT_DIR
Dossier logs         : $LOG_DIR
Config runtime       : $AGENT_ENV
Service systemd      : siem-agent.service
Date installation    : $(date '+%Y-%m-%d %H:%M:%S')

Commandes utiles :
  Status   : sudo systemctl status siem-agent
  Logs     : sudo journalctl -u siem-agent -f
  Logs app : sudo tail -f $LOG_DIR/agent.log
  Restart  : sudo systemctl restart siem-agent
EOF
        log_ok "Section [MODULE 3 - AGENT] ajoutée à $CREDENTIALS_FILE"
    else
        log_ok "Section [MODULE 3 - AGENT] déjà présente"
    fi
else
    log_warn "$CREDENTIALS_FILE introuvable - section non créée"
    log_info "Le Module 1 doit avoir été installé en premier"
fi

# ============================================================================
# Résumé final
# ============================================================================
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════"
echo "  ✓ Installation Agent complète"
echo -e "═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "État du service :"
echo "  ⚙️  siem-agent : $(systemctl is-active siem-agent)"
echo "  📁 Code       : $AGENT_DIR"
echo "  📋 Logs       : $LOG_DIR/agent.log"
echo "  ⚙️  Config    : $AGENT_ENV"
echo "  💾 Backups    : /var/backups/siem-africa/"
echo ""
echo "Commandes utiles :"
echo "  Status agent      : sudo systemctl status siem-agent"
echo "  Logs systemd      : sudo journalctl -u siem-agent -f"
echo "  Logs applicatifs  : sudo tail -f $LOG_DIR/agent.log"
echo "  Redémarrer        : sudo systemctl restart siem-agent"
echo ""
echo "Tests :"
echo "  sudo bash $SCRIPT_DIR/tests/test_bloc_1.sh"
echo "  sudo bash $SCRIPT_DIR/tests/test_all.sh"
echo ""
echo -e "${CYAN}L'agent traite maintenant les alertes Wazuh en temps réel :"
echo "  • Détection (Bloc 3)"
echo "  • Enrichissement BDD (Bloc 4)"
echo "  • Enrichissement IA Ollama (Bloc 5)"
echo "  • Notifications email avec anti-spam (Bloc 6)"
echo "  • Blocage iptables auto pour CRITICAL (Bloc 7)"
echo -e "  • KPI snapshots + backups BDD + récap quotidien (Bloc 8)${NC}"
echo ""
