#!/bin/bash
# ============================================================================
# SIEM AFRICA - Module 2 : Configuration SMTP (msmtp)
# ============================================================================
# Configure msmtp pour relayer les emails via Gmail, Outlook ou un serveur custom.
# Met à jour les settings BDD et fait un test d'envoi.
# ============================================================================

# Couleurs
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

# Configuration
CONFIG_DIR="/etc/siem-africa"
MSMTP_CONF="${CONFIG_DIR}/msmtp.conf"
DB_PATH="/var/lib/siem-africa/siem.db"
CREDS_FILE="/root/siem_credentials.txt"
SIEM_GROUP="siem-africa"
LOG_FILE="/var/log/siem-africa/msmtp.log"

# ----------------------------------------------------------------------------
# Vérifications préalables
# ----------------------------------------------------------------------------
if [ "$EUID" -ne 0 ]; then
    log_err "Ce script doit être exécuté en root (sudo)"
    exit 1
fi

if ! command -v msmtp >/dev/null 2>&1; then
    log_err "msmtp n'est pas installé. Lancez d'abord install_database.sh"
    exit 1
fi

if [ ! -f "$DB_PATH" ]; then
    log_err "BDD non trouvée. Lancez d'abord install_database.sh"
    exit 1
fi

# ----------------------------------------------------------------------------
# Bannière
# ----------------------------------------------------------------------------
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  SIEM AFRICA - Configuration SMTP${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Cette procédure configure le relais SMTP pour les notifications email."
echo "Vous aurez besoin d'un compte email expéditeur :"
echo ""
echo "  📧 Gmail : utilisez un App Password (pas votre mot de passe normal)"
echo "             https://myaccount.google.com/apppasswords"
echo ""
echo "  📧 Outlook : utilisez un App Password également"
echo "             https://account.microsoft.com/security/app-passwords"
echo ""

# ----------------------------------------------------------------------------
# Détecter une config existante
# ----------------------------------------------------------------------------
if grep -q "^account siem-africa" "$MSMTP_CONF" 2>/dev/null; then
    log_warn "Une configuration SMTP existe déjà"
    read -p "Voulez-vous la remplacer ? [o/N] : " REPLACE
    if [[ ! "$REPLACE" =~ ^[oOyY]$ ]]; then
        log_info "Annulé."
        exit 0
    fi
fi

# ----------------------------------------------------------------------------
# Choix du fournisseur SMTP
# ----------------------------------------------------------------------------
log_step "Type de serveur SMTP"

echo ""
echo "  1. Gmail (smtp.gmail.com:587)"
echo "  2. Outlook / Office 365 (smtp.office365.com:587)"
echo "  3. SendGrid (smtp.sendgrid.net:587)"
echo "  4. Autre (configurer manuellement)"
echo ""
read -p "Choix [1-4] : " SMTP_CHOICE

case "$SMTP_CHOICE" in
    1)
        SMTP_HOST="smtp.gmail.com"
        SMTP_PORT="587"
        SMTP_LABEL="Gmail"
        ;;
    2)
        SMTP_HOST="smtp.office365.com"
        SMTP_PORT="587"
        SMTP_LABEL="Outlook/Office365"
        ;;
    3)
        SMTP_HOST="smtp.sendgrid.net"
        SMTP_PORT="587"
        SMTP_LABEL="SendGrid"
        ;;
    4)
        read -p "Hôte SMTP : " SMTP_HOST
        read -p "Port (587 par défaut) : " SMTP_PORT
        SMTP_PORT="${SMTP_PORT:-587}"
        SMTP_LABEL="Custom ($SMTP_HOST)"
        ;;
    *)
        log_err "Choix invalide"
        exit 1
        ;;
esac

log_ok "Serveur : $SMTP_LABEL"

# ----------------------------------------------------------------------------
# Saisie des credentials
# ----------------------------------------------------------------------------
log_step "Identifiants du compte expéditeur"

# Email expéditeur
while true; do
    read -p "Email expéditeur (compte qui enverra les alertes) : " SMTP_FROM
    if [[ "$SMTP_FROM" =~ ^[a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        break
    else
        log_warn "Email invalide. Réessayez."
    fi
done

# Username (souvent identique à l'email)
read -p "Nom d'utilisateur SMTP [par défaut: $SMTP_FROM] : " SMTP_USER
SMTP_USER="${SMTP_USER:-$SMTP_FROM}"

# Mot de passe (App Password)
while true; do
    read -s -p "Mot de passe / App Password : " SMTP_PASS
    echo ""
    if [ ${#SMTP_PASS} -ge 6 ]; then
        break
    else
        log_warn "Trop court (min 6 caractères)"
    fi
done

# Nom d'expéditeur (affiché dans les emails)
read -p "Nom d'expéditeur affiché [SIEM Africa] : " FROM_NAME
FROM_NAME="${FROM_NAME:-SIEM Africa}"

# Destinataires des alertes
while true; do
    read -p "Email(s) destinataire(s) des alertes (séparés par des virgules) : " RECIPIENTS
    if [ -n "$RECIPIENTS" ]; then
        break
    else
        log_warn "Au moins un destinataire requis"
    fi
done

# Sévérité minimale
echo ""
echo "Sévérité minimale pour envoyer un email :"
echo "  1. CRITICAL uniquement (recommandé pour PME)"
echo "  2. HIGH et plus"
echo "  3. MEDIUM et plus"
echo "  4. Tout (LOW inclus)"
echo ""
read -p "Choix [1-4, défaut 1] : " SEV_CHOICE
SEV_CHOICE="${SEV_CHOICE:-1}"

case "$SEV_CHOICE" in
    1) MIN_SEVERITY="CRITICAL" ;;
    2) MIN_SEVERITY="HIGH" ;;
    3) MIN_SEVERITY="MEDIUM" ;;
    4) MIN_SEVERITY="LOW" ;;
    *) MIN_SEVERITY="CRITICAL" ;;
esac

log_ok "Sévérité minimale : $MIN_SEVERITY"

# ----------------------------------------------------------------------------
# Génération du fichier msmtp.conf
# ----------------------------------------------------------------------------
log_step "Génération du fichier de configuration"

# Sauvegarde de l'ancien fichier
if [ -f "$MSMTP_CONF" ]; then
    cp "$MSMTP_CONF" "${MSMTP_CONF}.backup.$(date +%Y%m%d-%H%M%S)"
fi

# Nouveau fichier
cat > "$MSMTP_CONF" <<EOF
# ============================================================================
# SIEM AFRICA - Configuration msmtp
# Généré le : $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================================

defaults
auth           on
tls            on
tls_starttls   on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile        ${LOG_FILE}
timeout        30

account siem-africa
host           ${SMTP_HOST}
port           ${SMTP_PORT}
from           ${SMTP_FROM}
user           ${SMTP_USER}
password       ${SMTP_PASS}

account default : siem-africa
EOF

# Permissions strictes (contient le mot de passe)
chmod 640 "$MSMTP_CONF"
chown "root:${SIEM_GROUP}" "$MSMTP_CONF"
log_ok "msmtp.conf créé : $MSMTP_CONF"

# ----------------------------------------------------------------------------
# Test d'envoi
# ----------------------------------------------------------------------------
log_step "Test d'envoi"

# Premier destinataire pour le test
TEST_RECIPIENT=$(echo "$RECIPIENTS" | cut -d',' -f1 | tr -d ' ')
HOSTNAME_VM=$(hostname)
IP_VM=$(hostname -I | awk '{print $1}')

# Composer le mail de test
TEST_MESSAGE=$(cat <<EOF
From: ${FROM_NAME} <${SMTP_FROM}>
To: ${TEST_RECIPIENT}
Subject: ✅ SIEM Africa - Test SMTP réussi
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<html>
<body style="font-family: Arial, sans-serif;">
<h2 style="color: #2EA043;">✅ Test SMTP réussi</h2>
<p>Bonjour,</p>
<p>Ce message confirme que la configuration SMTP de votre <strong>SIEM Africa</strong> fonctionne correctement.</p>
<table border="0" cellpadding="5" style="background:#f0f0f0;">
<tr><td><strong>Serveur SMTP</strong></td><td>${SMTP_HOST}:${SMTP_PORT}</td></tr>
<tr><td><strong>Hôte SIEM</strong></td><td>${HOSTNAME_VM} (${IP_VM})</td></tr>
<tr><td><strong>Date du test</strong></td><td>$(date '+%Y-%m-%d %H:%M:%S')</td></tr>
<tr><td><strong>Sévérité minimale</strong></td><td>${MIN_SEVERITY}</td></tr>
</table>
<p>Vous recevrez désormais les notifications d'alertes ${MIN_SEVERITY}+ à cette adresse.</p>
<hr>
<p style="color: #666; font-size: 12px;">
SIEM Africa - Solution de cybersécurité pour PME africaines<br>
🇨🇲 🇬🇦 🇨🇬 🇨🇩
</p>
</body>
</html>
EOF
)

log_info "Envoi d'un email de test à : $TEST_RECIPIENT"
log_info "(Vérifiez aussi votre dossier SPAM si non reçu)"
echo ""

# Envoi avec capture des erreurs
echo "$TEST_MESSAGE" | msmtp --read-recipients "$TEST_RECIPIENT" 2>&1 | tee /tmp/msmtp-test.log
SEND_RC=$?

if [ "$SEND_RC" -eq 0 ]; then
    log_ok "Email envoyé avec succès !"
    SMTP_OK=1
else
    log_err "Échec de l'envoi (code retour: $SEND_RC)"
    echo ""
    echo "Erreurs possibles :"
    echo "  - Mot de passe incorrect (utilisez un App Password pour Gmail/Outlook)"
    echo "  - Authentification 2FA non configurée"
    echo "  - Pare-feu bloquant le port ${SMTP_PORT}"
    echo "  - DNS ne résout pas ${SMTP_HOST}"
    echo ""
    log_info "Logs détaillés : ${LOG_FILE}"
    log_info "Dernière erreur :"
    tail -5 /tmp/msmtp-test.log
    SMTP_OK=0
fi

rm -f /tmp/msmtp-test.log

# ----------------------------------------------------------------------------
# Mise à jour des settings dans la BDD
# ----------------------------------------------------------------------------
log_step "Mise à jour des settings BDD"

# Échapper pour SQL
ESC_HOST=$(printf '%s' "$SMTP_HOST" | sed "s/'/''/g")
ESC_FROM=$(printf '%s' "$SMTP_FROM" | sed "s/'/''/g")
ESC_USER=$(printf '%s' "$SMTP_USER" | sed "s/'/''/g")
ESC_FNAME=$(printf '%s' "$FROM_NAME" | sed "s/'/''/g")
ESC_RECIP=$(printf '%s' "$RECIPIENTS" | sed "s/'/''/g")

sqlite3 "$DB_PATH" <<SQL
UPDATE settings SET value = '${ESC_HOST}'    WHERE key = 'smtp_host';
UPDATE settings SET value = '${SMTP_PORT}'    WHERE key = 'smtp_port';
UPDATE settings SET value = '${ESC_FROM}'    WHERE key = 'smtp_from_email';
UPDATE settings SET value = '${ESC_FNAME}'   WHERE key = 'smtp_from_name';
UPDATE settings SET value = '${ESC_USER}'    WHERE key = 'smtp_username';
-- Ne PAS stocker le mdp en BDD (déjà dans /etc/siem-africa/msmtp.conf)
UPDATE settings SET value = ''                WHERE key = 'smtp_password';
UPDATE settings SET value = '${ESC_RECIP}'   WHERE key = 'smtp_alert_recipients';
UPDATE settings SET value = '${MIN_SEVERITY}' WHERE key = 'smtp_min_severity';
UPDATE settings SET value = 'true'            WHERE key = 'smtp_enabled';
UPDATE settings SET value = 'true'            WHERE key = 'smtp_use_tls';
SQL

log_ok "Settings BDD mis à jour"

# ----------------------------------------------------------------------------
# Sauvegarde dans /root/siem_credentials.txt
# ----------------------------------------------------------------------------
log_step "Sauvegarde des credentials"

# APPEND la section SMTP
cat >> "$CREDS_FILE" <<EOF

[MODULE 2 - SMTP]
─────────────────────────────────
Date de configuration   : $(date '+%Y-%m-%d %H:%M:%S')
Type de serveur         : $SMTP_LABEL
Hôte                    : $SMTP_HOST:$SMTP_PORT
Email expéditeur        : $SMTP_FROM
Nom expéditeur affiché  : $FROM_NAME
Destinataires           : $RECIPIENTS
Sévérité minimale       : $MIN_SEVERITY
Test d'envoi            : $([ "$SMTP_OK" = "1" ] && echo "✓ RÉUSSI" || echo "✗ ÉCHEC")
Fichier config          : $MSMTP_CONF
Logs                    : $LOG_FILE

# Le mot de passe SMTP est stocké uniquement dans $MSMTP_CONF
# (permissions 640 root:siem-africa, lisible seulement par root et le groupe SIEM)
# Pour le voir : sudo cat $MSMTP_CONF | grep password

EOF

log_ok "Credentials SMTP sauvegardés dans $CREDS_FILE"

# ----------------------------------------------------------------------------
# Résumé
# ----------------------------------------------------------------------------
log_step "Résumé"

echo ""
if [ "$SMTP_OK" = "1" ]; then
    echo -e "${GREEN}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${GREEN}│ ✅ SMTP CONFIGURÉ ET TESTÉ AVEC SUCCÈS                      │${NC}"
    echo -e "${GREEN}└─────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo "  📧 Vérifiez votre boîte $TEST_RECIPIENT (et SPAM)"
    echo "  📝 Configuration : $MSMTP_CONF"
    echo "  📜 Logs SMTP    : $LOG_FILE"
    echo ""
    echo "Pour envoyer un email manuellement :"
    echo "  echo \"Test\" | mail -s \"Sujet\" $TEST_RECIPIENT"
else
    echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${YELLOW}│ ⚠ SMTP CONFIGURÉ MAIS TEST ÉCHOUÉ                           │${NC}"
    echo -e "${YELLOW}└─────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo "  La configuration est sauvegardée mais le test n'est pas passé."
    echo "  Vérifiez :"
    echo "    1. App Password correct ?"
    echo "    2. Autoriser les apps moins sécurisées (si compte standard) ?"
    echo "    3. Port $SMTP_PORT ouvert dans le firewall ?"
    echo ""
    echo "  Pour réessayer : sudo ./configure_smtp.sh"
    echo "  Pour debug : sudo cat $LOG_FILE"
fi
echo ""
