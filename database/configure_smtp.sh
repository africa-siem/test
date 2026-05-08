#!/bin/bash
# ============================================================================
# SIEM AFRICA - Configuration SMTP (Python smtplib)
# ============================================================================
# Approche qui FONCTIONNAIT dans la version précédente du projet :
#   - Python + smtplib direct (au lieu de msmtp + heredoc)
#   - Procédure Gmail intégrée dans le terminal
#   - Test email simple et fiable
#   - Détection précise des erreurs SMTP
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
log_info() { echo -e "${CYAN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[ATTENTION]${NC} $1"; }
log_err()  { echo -e "${RED}[ERREUR]${NC} $1"; }

# Configuration
SIEM_GROUP="siem-africa"
SIEM_DB_USER="siem-db"
DB_PATH="/var/lib/siem-africa/siem.db"
CONFIG_DIR="/etc/siem-africa"
LOG_DIR="/var/log/siem-africa"
SMTP_CONF="${CONFIG_DIR}/smtp.env"
CREDS_FILE="/root/siem_credentials.txt"

# ----------------------------------------------------------------------------
# Vérifications préalables
# ----------------------------------------------------------------------------
clear
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  ${BOLD}SIEM AFRICA — Configuration SMTP${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo ""

# Root ?
if [ "$EUID" -ne 0 ]; then
    log_err "Lancez avec : sudo bash configure_smtp.sh"
    exit 1
fi

# Python disponible ?
if ! command -v python3 >/dev/null 2>&1; then
    log_warn "Python3 non installé, installation..."
    apt-get install -y python3 >/dev/null 2>&1
fi

# BDD existe ?
if [ ! -f "$DB_PATH" ]; then
    log_err "BDD inexistante : $DB_PATH"
    log_err "Lancez d'abord : sudo ./install_database.sh"
    exit 1
fi
log_ok "BDD trouvée : $DB_PATH"
log_ok "Python3 : $(python3 --version)"

mkdir -p "$CONFIG_DIR" "$LOG_DIR"
chown root:"$SIEM_GROUP" "$CONFIG_DIR" 2>/dev/null
chown "${SIEM_DB_USER}:${SIEM_GROUP}" "$LOG_DIR" 2>/dev/null

# ----------------------------------------------------------------------------
# Affichage de la procédure Gmail
# ----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  PROCEDURE — Obtenir le mot de passe d'application Gmail${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}Etape 1${NC} — Connectez-vous sur Gmail"
echo -e "    Ouvrez : ${CYAN}https://gmail.com${NC}"
echo -e "    Utilisez l'email qui va ENVOYER les alertes"
echo ""
echo -e "  ${BOLD}Etape 2${NC} — Activez la validation en 2 etapes"
echo -e "    1. Cliquez sur votre photo en haut a droite"
echo -e "    2. Cliquez 'Gerer votre compte Google'"
echo -e "    3. Menu gauche → cliquez 'Securite'"
echo -e "    4. Cherchez 'Validation en 2 etapes' → Activez-la"
echo ""
echo -e "  ${BOLD}Etape 3${NC} — Creez le mot de passe application"
echo -e "    1. Toujours dans 'Securite'"
echo -e "    2. Cherchez 'Mots de passe des applications'"
echo -e "       Ou allez directement sur :"
echo -e "       ${CYAN}https://myaccount.google.com/apppasswords${NC}"
echo -e "    3. Dans le champ Nom → tapez : ${BOLD}SIEM Africa${NC}"
echo -e "    4. Cliquez 'Creer'"
echo -e "    5. Google affiche un code de 16 caracteres :"
echo -e "       ${BOLD}abcd efgh ijkl mnop${NC}"
echo -e "    6. ${RED}COPIEZ CE CODE — il disparait si vous fermez la fenetre${NC}"
echo ""
echo -e "  ${BOLD}Note${NC} — Le meme email peut envoyer ET recevoir les alertes."
echo -e "  Vous pouvez utiliser une seule adresse Gmail pour les deux."
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Confirmation
read -p "  Avez-vous votre code de 16 caracteres ? (oui/non) : " HAS_PWD
if [[ ! "$HAS_PWD" =~ ^(oui|o|yes|y|OUI|O|Y)$ ]]; then
    echo ""
    log_warn "Suivez d'abord la procedure ci-dessus pour generer votre code Gmail"
    log_warn "Puis relancez : sudo bash configure_smtp.sh"
    exit 0
fi

# ----------------------------------------------------------------------------
# Question 1 : Email expéditeur
# ----------------------------------------------------------------------------
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}Question 1/3${NC} — Email qui ENVOIE les alertes"
echo -e "  (Votre adresse Gmail)"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

while true; do
    read -p "  Gmail : " SMTP_USER
    if [[ "$SMTP_USER" =~ ^[a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        log_ok "Email expediteur : $SMTP_USER"
        break
    else
        log_warn "Email invalide. Reessayez."
    fi
done

# ----------------------------------------------------------------------------
# Question 2 : Mot de passe application
# ----------------------------------------------------------------------------
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}Question 2/3${NC} — Mot de passe application Gmail"
echo -e "  C'est le code de 16 caracteres genere par Google."
echo -e "  Pour le creer : ${CYAN}https://myaccount.google.com/apppasswords${NC}"
echo -e "  Il est different de votre mot de passe Gmail normal !"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "${YELLOW}  ℹ Le mot de passe sera VISIBLE pendant la saisie (pour eviter les fautes).${NC}"
echo -e "${YELLOW}    Il sera ensuite stocke dans /etc/siem-africa/smtp.env (640 root:siem-africa).${NC}"
echo ""

while true; do
    read -p "  Mot de passe application (16 caracteres) : " SMTP_PASS
    # Retirer les espaces (Google affiche avec des espaces)
    SMTP_PASS=$(echo "$SMTP_PASS" | tr -d ' ')
    if [ ${#SMTP_PASS} -ge 8 ]; then
        log_ok "Mot de passe enregistre (longueur : ${#SMTP_PASS})"
        break
    else
        log_warn "Trop court (attendu 16 caracteres). Reessayez."
    fi
done

# ----------------------------------------------------------------------------
# Question 3 : Email destinataire
# ----------------------------------------------------------------------------
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}Question 3/3${NC} — Email qui RECOIT les alertes"
echo -e "  Peut etre le meme que l'expediteur."
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Récupérer l'email admin par défaut
ADMIN_DEFAULT=$(sqlite3 "$DB_PATH" "SELECT email FROM users WHERE role_id = (SELECT id FROM roles WHERE code='ADMIN') LIMIT 1")

if [ -n "$ADMIN_DEFAULT" ]; then
    read -p "  Email destinataire [defaut: $ADMIN_DEFAULT] : " ALERT_EMAIL
    ALERT_EMAIL="${ALERT_EMAIL:-$ADMIN_DEFAULT}"
else
    while true; do
        read -p "  Email destinataire : " ALERT_EMAIL
        if [[ "$ALERT_EMAIL" =~ ^[a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            break
        else
            log_warn "Email invalide. Reessayez."
        fi
    done
fi
log_ok "Email destinataire : $ALERT_EMAIL"

# ----------------------------------------------------------------------------
# Confirmation
# ----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}RECAPITULATIF${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  Email expediteur  : ${BOLD}$SMTP_USER${NC}"
echo -e "  Email destinataire: ${BOLD}$ALERT_EMAIL${NC}"
echo -e "  Mot de passe      : ${BOLD}***************${NC}"
echo -e "  Serveur SMTP      : smtp.gmail.com:587 (TLS)"
echo ""
read -p "  Confirmer ? (oui/non) : " CONFIRM
if [[ ! "$CONFIRM" =~ ^(oui|o|yes|y|OUI|O|Y)$ ]]; then
    log_warn "Annule. Relancez quand vous voulez."
    exit 0
fi

# ----------------------------------------------------------------------------
# Sauvegarde de la configuration
# ----------------------------------------------------------------------------
echo ""
log_info "Sauvegarde de la configuration..."

cat > "$SMTP_CONF" <<EOF
# SIEM Africa - Configuration SMTP
# Genere le $(date '+%Y-%m-%d %H:%M:%S')

SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=$SMTP_USER
SMTP_PASSWORD=$SMTP_PASS
SMTP_FROM=$SMTP_USER
SMTP_FROM_NAME=SIEM Africa
ALERT_EMAIL=$ALERT_EMAIL
SMTP_USE_TLS=true
EOF

chmod 640 "$SMTP_CONF"
chown root:"$SIEM_GROUP" "$SMTP_CONF"
log_ok "Config sauvegardee : $SMTP_CONF"

# Mettre à jour les settings BDD
sqlite3 "$DB_PATH" <<SQL
UPDATE settings SET value = 'smtp.gmail.com'  WHERE key = 'smtp_host';
UPDATE settings SET value = '587'             WHERE key = 'smtp_port';
UPDATE settings SET value = '$SMTP_USER'      WHERE key = 'smtp_username';
UPDATE settings SET value = '$SMTP_USER'      WHERE key = 'smtp_from_email';
UPDATE settings SET value = '$ALERT_EMAIL'    WHERE key = 'smtp_alert_recipients';
UPDATE settings SET value = 'true'            WHERE key = 'smtp_enabled';
UPDATE settings SET value = 'true'            WHERE key = 'smtp_use_tls';
SQL
log_ok "Settings BDD mis a jour"

# ----------------------------------------------------------------------------
# Test : envoi d'email avec Python smtplib
# ----------------------------------------------------------------------------
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}TEST — Envoi d'un email de verification${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

log_info "Connexion a Gmail SMTP..."

# Récupérer infos
ADMIN_FIRST=$(sqlite3 "$DB_PATH" "SELECT COALESCE(first_name, 'Admin') FROM users WHERE email='$ALERT_EMAIL' LIMIT 1")
ADMIN_FIRST=${ADMIN_FIRST:-"Admin"}
ORG_NAME=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='organization_name'")
COUNTRY_NAME=$(sqlite3 "$DB_PATH" "SELECT c.name_fr FROM countries c JOIN settings s ON s.value = CAST(c.id AS TEXT) WHERE s.key='system_country_id'" 2>/dev/null)
COUNTRY_NAME=${COUNTRY_NAME:-"Cameroun"}
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')

# Script Python qui envoie l'email
RESULT=$(python3 - <<PYTHON
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate
import sys

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "$SMTP_USER"
SMTP_PASS = "$SMTP_PASS"
ALERT_EMAIL = "$ALERT_EMAIL"

subject = "Test SIEM Africa - Configuration SMTP reussie"
text_body = """Bonjour $ADMIN_FIRST,

Cet email confirme que la configuration SMTP de SIEM Africa
fonctionne correctement.

CONFIGURATION TESTEE :
- Date du test : $(date '+%Y-%m-%d %H:%M:%S')
- Hote : $HOSTNAME ($IP_ADDR)
- Pays : $COUNTRY_NAME
- Organisation : $ORG_NAME
- Serveur SMTP : smtp.gmail.com:587 (TLS)
- Expediteur : $SMTP_USER
- Destinataire : $ALERT_EMAIL

LE MODULE 3 (Agent) pourra envoyer des alertes critiques
a cette adresse en utilisant cette configuration.

PROCHAINES ETAPES :
1. Installer le Module 3 (Agent IA + Ollama)
2. Installer le Module 4 (Dashboard Django)
3. Tester avec une attaque simulee

---
SIEM Africa
Solution panafricaine de cybersecurite pour PME
Cameroun - Gabon - Congo - RDC
"""

try:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"SIEM Africa <{SMTP_USER}>"
    msg["To"] = ALERT_EMAIL
    msg["Date"] = formatdate(localtime=True)
    msg.attach(MIMEText(text_body, "plain", "utf-8"))

    context = ssl.create_default_context()
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, [ALERT_EMAIL], msg.as_string())

    print("SUCCESS")
except smtplib.SMTPAuthenticationError as e:
    print(f"AUTH_ERROR")
    sys.stderr.write(f"Detail: {e}\n")
except smtplib.SMTPConnectError as e:
    print(f"CONNECT_ERROR")
    sys.stderr.write(f"Detail: {e}\n")
except smtplib.SMTPException as e:
    print(f"SMTP_ERROR: {e}")
except Exception as e:
    print(f"ERROR: {e}")
PYTHON
)

# ----------------------------------------------------------------------------
# Affichage du résultat
# ----------------------------------------------------------------------------
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if echo "$RESULT" | grep -q "SUCCESS"; then
    echo -e "  ${GREEN}${BOLD}✅ EMAIL ENVOYE AVEC SUCCES !${NC}"
    echo ""
    echo -e "  ${BOLD}Verifiez votre boite mail :${NC} $ALERT_EMAIL"
    echo -e "  Si rien n'arrive, regardez dans ${BOLD}SPAM${NC}."
    echo ""
    echo -e "  ${GREEN}La configuration SMTP est operationnelle.${NC}"
    echo -e "  Les alertes critiques seront envoyees automatiquement"
    echo -e "  quand le Module 3 (Agent) detectera des incidents."

    # Sauvegarder dans credentials.txt
    if [ -f "$CREDS_FILE" ]; then
        # Supprimer ancienne section SMTP si elle existe
        sed -i '/^\[MODULE 2 - SMTP\]/,/^$/d' "$CREDS_FILE" 2>/dev/null

        cat >> "$CREDS_FILE" <<EOF

[MODULE 2 - SMTP]
─────────────────────────────────
Date config        : $(date '+%Y-%m-%d %H:%M:%S')
SMTP Host          : smtp.gmail.com
SMTP Port          : 587 (TLS)
Email expediteur   : $SMTP_USER
Email destinataire : $ALERT_EMAIL
Config SMTP        : $SMTP_CONF

# Pour reconfigurer : sudo ./configure_smtp.sh

EOF
        log_ok "Credentials mis a jour : $CREDS_FILE"
    fi

    EXIT_CODE=0
else
    echo -e "  ${RED}${BOLD}✗ ECHEC DE L'ENVOI${NC}"
    echo ""

    if echo "$RESULT" | grep -q "AUTH_ERROR"; then
        echo -e "  ${YELLOW}Cause : Mot de passe incorrect.${NC}"
        echo ""
        echo -e "  Verifiez :"
        echo -e "  • Vous utilisez un mot de passe ${BOLD}APPLICATION${NC} (16 chars)"
        echo -e "  • PAS votre mot de passe Gmail normal"
        echo -e "  • Validation en 2 etapes activee"
        echo -e "  • Pas d'espaces dans le mot de passe (le script les retire)"
        echo ""
        echo -e "  Generez un nouveau mot de passe :"
        echo -e "  ${CYAN}https://myaccount.google.com/apppasswords${NC}"
    elif echo "$RESULT" | grep -q "CONNECT_ERROR"; then
        echo -e "  ${YELLOW}Cause : Impossible de se connecter au serveur Gmail.${NC}"
        echo ""
        echo -e "  Verifiez :"
        echo -e "  • Connexion internet"
        echo -e "  • Pare-feu n'autorise pas le port 587"
        echo -e "  • Pas de proxy entreprise qui bloque SMTP"
    else
        echo -e "  ${YELLOW}Detail : $RESULT${NC}"
    fi
    echo ""
    echo -e "  ${BOLD}Pour reessayer :${NC}"
    echo -e "  sudo bash configure_smtp.sh"

    EXIT_CODE=1
fi

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

exit $EXIT_CODE
