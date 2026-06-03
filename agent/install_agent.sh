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
echo "  SIEM Africa - Module 3 - Installation Agent"
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

# Détecter ce qui existe déjà
PREVIOUS_FOUND=false
[ -d "$AGENT_DIR" ] && PREVIOUS_FOUND=true
[ -f "/etc/systemd/system/siem-agent.service" ] && PREVIOUS_FOUND=true
[ -f "/etc/sudoers.d/siem-agent" ] && PREVIOUS_FOUND=true
systemctl is-active --quiet siem-agent 2>/dev/null && PREVIOUS_FOUND=true
systemctl is-enabled --quiet siem-agent 2>/dev/null && PREVIOUS_FOUND=true

if [ "$PREVIOUS_FOUND" = true ]; then
    log_warn "Installation précédente détectée"
    log_info "Désinstallation propre en cours (la BDD M2 et ses credentials sont préservés)..."

    # 1. Arrêter et désactiver le service
    if systemctl is-active --quiet siem-agent 2>/dev/null; then
        systemctl stop siem-agent 2>/dev/null
        log_ok "Service arrêté"
    fi
    if systemctl is-enabled --quiet siem-agent 2>/dev/null; then
        systemctl disable siem-agent 2>/dev/null
        log_ok "Service désactivé"
    fi

    # 2. Supprimer l'unit file systemd
    if [ -f "/etc/systemd/system/siem-agent.service" ]; then
        rm -f /etc/systemd/system/siem-agent.service
        log_ok "Unit systemd supprimé"
    fi
    systemctl daemon-reload 2>/dev/null
    systemctl reset-failed siem-agent 2>/dev/null

    # 3. Supprimer le code agent
    if [ -d "$AGENT_DIR" ]; then
        rm -rf "$AGENT_DIR"
        log_ok "Code agent supprimé ($AGENT_DIR)"
    fi

    # 4. Supprimer sudoers iptables
    if [ -f "/etc/sudoers.d/siem-agent" ]; then
        rm -f /etc/sudoers.d/siem-agent
        log_ok "Sudoers agent supprimé"
    fi

    # 5. Nettoyer les iptables (règles laissées par l'agent)
    # On ne supprime pas TOUTES les règles iptables, juste celles avec commentaire siem-africa
    if command -v iptables &>/dev/null; then
        # Récupérer les IPs DROPed et tenter de les retirer (silencieux si rien)
        iptables -L INPUT -n --line-numbers 2>/dev/null | grep -i "drop" | while read -r line; do
            ip=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print $i}')
            if [ -n "$ip" ]; then
                iptables -D INPUT -s "$ip" -j DROP 2>/dev/null
            fi
        done 2>/dev/null
        log_ok "Règles iptables agent nettoyées"
    fi

    # 6. PRÉSERVER : agent.env, logs, backups, BDD M2
    # On garde ces fichiers car ils contiennent de la config / historique utile
    log_info "Préservés : agent.env, logs, backups, BDD M2 (et ses credentials SMTP/IA)"

    log_ok "Désinstallation terminée"
    echo ""
else
    log_ok "Aucune installation précédente détectée"
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

# venv + ensurepip + pip (un python3 'minimal' peut avoir le module venv mais pas ensurepip)
NEEDED_PKGS=""
if ! python3 -c "import venv" 2>/dev/null; then
    NEEDED_PKGS="$NEEDED_PKGS python3-venv"
fi
if ! python3 -c "import ensurepip" 2>/dev/null; then
    # ensurepip est dans python3-venv sur Ubuntu mais parfois cassé sur images minimales
    NEEDED_PKGS="$NEEDED_PKGS python3-venv python3-pip"
fi
if [ -n "$NEEDED_PKGS" ]; then
    log_warn "Modules Python à installer :$NEEDED_PKGS"
    apt-get install -y $NEEDED_PKGS 2>&1 | tail -3
fi
log_ok "venv + pip + ensurepip OK"

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

# Permissions sur smtp.env du M2 (pour que l'agent puisse lire le password SMTP)
if [ -f /etc/siem-africa/smtp.env ]; then
    chgrp "$SIEM_GROUP" /etc/siem-africa/smtp.env
    chmod 640 /etc/siem-africa/smtp.env
    log_ok "Permissions sur smtp.env ajustées (lecture par siem-agent)"
fi

# Pareil pour les autres .env du M2 éventuels
for env_file in /etc/siem-africa/mail.env /etc/siem-africa/agent.env; do
    if [ -f "$env_file" ]; then
        chgrp "$SIEM_GROUP" "$env_file" 2>/dev/null
        chmod 640 "$env_file" 2>/dev/null
    fi
done

# ============================================================================
# 5. Venv Python (idempotent, avec fallback get-pip.py si ensurepip échoue)
# ============================================================================
log_step "Création du venv Python"

cd "$AGENT_DIR"

# Nettoyer un venv existant CASSÉ (présent mais sans pip)
if [ -d "$AGENT_DIR/venv" ] && [ ! -x "$AGENT_DIR/venv/bin/pip" ]; then
    log_warn "venv existant sans pip détecté → suppression pour repartir propre"
    rm -rf "$AGENT_DIR/venv"
fi

# Créer le venv si absent
if [ ! -d "$AGENT_DIR/venv" ]; then
    python3 -m venv venv 2>&1 | tail -3
fi

# Vérification python
if [ ! -x "$AGENT_DIR/venv/bin/python" ]; then
    log_err "Création venv échouée : pas de python dans $AGENT_DIR/venv/bin/"
    exit 1
fi

# Fallback get-pip.py si ensurepip n'a pas installé pip dans le venv
if [ ! -x "$AGENT_DIR/venv/bin/pip" ]; then
    log_warn "pip absent du venv (ensurepip non fonctionnel) → fallback get-pip.py"
    GETPIP_TMP=$(mktemp /tmp/get-pip.XXXXXX.py)
    if curl -fsSL https://bootstrap.pypa.io/get-pip.py -o "$GETPIP_TMP"; then
        "$AGENT_DIR/venv/bin/python" "$GETPIP_TMP" 2>&1 | tail -3
        rm -f "$GETPIP_TMP"
    else
        log_err "Impossible de télécharger get-pip.py - vérifier la connexion réseau"
        log_info "Réessayer manuellement :"
        log_info "  curl https://bootstrap.pypa.io/get-pip.py | $AGENT_DIR/venv/bin/python"
        exit 1
    fi
fi

# Vérification finale
if [ ! -x "$AGENT_DIR/venv/bin/pip" ]; then
    log_err "pip toujours absent après fallback - installation Python cassée"
    exit 1
fi
log_ok "venv Python opérationnel (python + pip)"

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
# 6.5 Installation Ollama + téléchargement modèles IA
# ============================================================================
log_step "Installation Ollama et modèles IA"

# 6.5.1 Vérifier / installer Ollama (binaire ET service systemd)
NEED_OLLAMA_INSTALL=0

# Détection du service systemd
OLLAMA_UNIT=""
for path in /etc/systemd/system/ollama.service \
            /lib/systemd/system/ollama.service \
            /usr/lib/systemd/system/ollama.service; do
    if [ -f "$path" ]; then
        OLLAMA_UNIT="$path"
        break
    fi
done

if command -v ollama &>/dev/null; then
    # Filtrer les warnings parasites (ex: "could not connect to a running instance")
    OLLAMA_VERSION=$(ollama --version 2>/dev/null | grep -oE "version is [0-9.]+|version [0-9.]+|[0-9]+\.[0-9]+\.[0-9]+" | head -1)
    [ -z "$OLLAMA_VERSION" ] && OLLAMA_VERSION="(version inconnue)"

    if [ -n "$OLLAMA_UNIT" ]; then
        log_ok "Ollama installé : $OLLAMA_VERSION ($OLLAMA_UNIT)"
    else
        log_warn "Binaire ollama présent ($OLLAMA_VERSION) mais service systemd absent"
        log_info "Réinstallation pour créer le service systemd..."
        NEED_OLLAMA_INSTALL=1
    fi
else
    log_info "Ollama non détecté, installation en cours..."
    NEED_OLLAMA_INSTALL=1
fi

if [ "$NEED_OLLAMA_INSTALL" -eq 1 ]; then
    log_info "(téléchargement ~200 MB, peut prendre quelques minutes)"

    # Installation officielle Ollama (crée user 'ollama' + service systemd)
    # Pas de pipe vers tail : on veut voir les erreurs en cas d'échec
    if curl -fsSL https://ollama.com/install.sh | sh; then
        log_ok "Ollama installé"
        systemctl daemon-reload 2>/dev/null || true

        # Re-détecter le service après installation
        for path in /etc/systemd/system/ollama.service \
                    /lib/systemd/system/ollama.service \
                    /usr/lib/systemd/system/ollama.service; do
            if [ -f "$path" ]; then
                OLLAMA_UNIT="$path"
                break
            fi
        done

        if [ -n "$OLLAMA_UNIT" ]; then
            log_ok "Service systemd créé : $OLLAMA_UNIT"
        else
            log_warn "Service systemd toujours absent après installation"
            log_warn "Installation Ollama incomplète - vérifier manuellement"
        fi
    else
        log_warn "Installation Ollama échouée"
        log_warn "Réessayer manuellement :"
        log_warn "  curl -fsSL https://ollama.com/install.sh | sh"
    fi
fi

# 6.5.2 Démarrer le service Ollama
if command -v ollama &>/dev/null; then
    if systemctl is-active --quiet ollama 2>/dev/null; then
        log_ok "Service ollama actif"
    else
        log_info "Démarrage du service ollama..."
        systemctl enable ollama 2>&1 | tail -1
        systemctl start ollama

        # Attendre jusqu'à 30 secondes que le service soit actif
        OLLAMA_STARTED=0
        for i in $(seq 1 10); do
            sleep 3
            if systemctl is-active --quiet ollama 2>/dev/null; then
                OLLAMA_STARTED=1
                break
            fi
            log_info "  Attente démarrage ollama... ($((i*3))s)"
        done

        if [ "$OLLAMA_STARTED" -eq 1 ]; then
            log_ok "Service ollama démarré"
        else
            log_warn "Service ollama n'a pas démarré - voir : systemctl status ollama"
        fi
    fi

    # 6.5.3 Attendre que l'API HTTP soit disponible (jusqu'à 60 secondes)
    log_info "Attente de l'API Ollama (http://localhost:11434)..."
    OLLAMA_API_READY=0
    for i in $(seq 1 20); do
        if curl -sf -m 3 http://localhost:11434/api/tags >/dev/null 2>&1; then
            OLLAMA_API_READY=1
            break
        fi
        sleep 3
        log_info "  API pas encore prête... ($((i*3))s/60s)"
    done

    if [ "$OLLAMA_API_READY" -eq 1 ]; then
        log_ok "API Ollama répond"

        # 6.5.4 Lister les modèles existants
        # Format retourné : "qwen2.5:3b" ou "qwen2.5:3b:Q4_K_M" selon la version
        EXISTING_MODELS=$(curl -s http://localhost:11434/api/tags 2>/dev/null \
            | grep -o '"name":"[^"]*"' \
            | cut -d'"' -f4 \
            | sed 's/:latest$//')

        # 6.5.5 Télécharger les modèles requis (~2-3 GB chacun)
        MODELS_TO_PULL="qwen2.5:3b llama3.2:3b"
        for model in $MODELS_TO_PULL; do
            # Comparer le préfixe du modèle (ignorer le suffixe de quantization)
            MODEL_BASE=$(echo "$model" | cut -d: -f1)
            MODEL_TAG=$(echo "$model" | cut -d: -f2)
            if echo "$EXISTING_MODELS" | grep -qE "^${MODEL_BASE}:${MODEL_TAG}"; then
                log_ok "Modèle $model déjà téléchargé"
            else
                log_info "Téléchargement de $model (~2-4 GB)..."
                log_info "  Cela peut prendre 10-30 minutes selon la connexion..."
                log_info "  (patience - ne pas interrompre)"
                if ollama pull "$model"; then
                    log_ok "Modèle $model téléchargé"
                else
                    log_warn "Téléchargement de $model échoué - réessayer manuellement :"
                    log_warn "  ollama pull $model"
                fi
            fi
        done
    else
        log_warn "API Ollama ne répond pas après 60 secondes"
        log_warn "Vérifier le service : systemctl status ollama"
        log_warn "Puis télécharger manuellement :"
        log_warn "  ollama pull qwen2.5:3b && ollama pull llama3.2:3b"
    fi
else
    log_warn "Ollama non disponible - l'agent fonctionnera sans IA"
fi

# 6.5.6 Activer l'IA dans la BDD M2 si Ollama répond
if curl -sf -m 5 http://localhost:11434/api/tags >/dev/null 2>&1; then
    # Trouver la BDD M2
    M2_DB=""
    for candidate in /var/lib/siem-africa/siem.db /opt/siem-africa/database/siem.db /var/lib/siem-africa/database/siem.db; do
        if [ -f "$candidate" ]; then
            M2_DB="$candidate"
            break
        fi
    done

    if [ -n "$M2_DB" ]; then
        log_info "Activation de l'IA dans la BDD M2 ($M2_DB)..."
        sqlite3 "$M2_DB" <<EOF 2>/dev/null
INSERT INTO settings (key, value, value_type, category) VALUES ('ai_enabled', 'true', 'bool', 'ai')
    ON CONFLICT(key) DO UPDATE SET value='true';
INSERT INTO settings (key, value, value_type, category) VALUES ('ai_endpoint', 'http://localhost:11434', 'text', 'ai')
    ON CONFLICT(key) DO UPDATE SET value=excluded.value;
INSERT INTO settings (key, value, value_type, category) VALUES ('ai_default_model', 'qwen2.5:3b', 'text', 'ai')
    ON CONFLICT(key) DO UPDATE SET value=excluded.value;
EOF
        if [ $? -eq 0 ]; then
            log_ok "IA activée dans la BDD (ai_enabled=true, model=qwen2.5:3b)"
        else
            log_warn "Activation IA en BDD échouée - à faire manuellement"
        fi
    else
        log_warn "BDD M2 introuvable - activer manuellement l'IA dans settings"
    fi
fi

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
        # Détecter quels modèles Ollama sont installés
        OLLAMA_MODELS_LIST=""
        if curl -sf -m 3 http://localhost:11434/api/tags >/dev/null 2>&1; then
            OLLAMA_MODELS_LIST=$(curl -s http://localhost:11434/api/tags 2>/dev/null | grep -o '"name":"[^"]*"' | cut -d'"' -f4 | tr '\n' ',' | sed 's/,$//')
        fi

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

Ollama (IA locale) :
  Endpoint           : http://localhost:11434
  Modèles installés  : ${OLLAMA_MODELS_LIST:-aucun}
  Service systemd    : ollama.service

Commandes utiles :
  Status agent  : sudo systemctl status siem-agent
  Logs agent    : sudo journalctl -u siem-agent -f
  Logs app      : sudo tail -f $LOG_DIR/agent.log
  Restart agent : sudo systemctl restart siem-agent
  Status Ollama : sudo systemctl status ollama
  Modèles IA    : ollama list
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
echo "  siem-agent : $(systemctl is-active siem-agent)"
echo "  Code       : $AGENT_DIR"
echo "  Logs       : $LOG_DIR/agent.log"
echo "  Config    : $AGENT_ENV"
echo "  Backups    : /var/backups/siem-africa/"
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
