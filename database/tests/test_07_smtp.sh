#!/bin/bash
# Test 07 : Configuration SMTP (msmtp + mailutils)
DB_PATH="${DB_PATH:-/var/lib/siem-africa/siem.db}"
PASS=0; FAIL=0

t() {
    if [ "$3" = "$2" ]; then echo "  ✓ $1"; PASS=$((PASS+1));
    else echo "  ✗ $1 : got '$3', expected '$2'"; FAIL=$((FAIL+1)); fi
}

echo "▶ Test 07 : SMTP (msmtp)"

# msmtp installé
if command -v msmtp >/dev/null 2>&1; then
    echo "  ✓ msmtp installé"
    PASS=$((PASS+1))
else
    echo "  ✗ msmtp NON installé"
    FAIL=$((FAIL+1))
fi

# mailutils installé
if command -v mail >/dev/null 2>&1; then
    echo "  ✓ mail (mailutils) installé"
    PASS=$((PASS+1))
else
    echo "  ✗ mail (mailutils) NON installé"
    FAIL=$((FAIL+1))
fi

# Fichier de config existe
MSMTP_CONF="/etc/siem-africa/msmtp.conf"
if [ -f "$MSMTP_CONF" ]; then
    echo "  ✓ $MSMTP_CONF existe"
    PASS=$((PASS+1))

    # Permissions 640
    PERMS=$(stat -c "%a" "$MSMTP_CONF")
    t "Permissions msmtp.conf 640" "640" "$PERMS"

    # Propriétaire root:siem-africa
    OWNER=$(stat -c "%U:%G" "$MSMTP_CONF")
    t "Propriétaire msmtp.conf" "root:siem-africa" "$OWNER"
else
    echo "  ✗ msmtp.conf MANQUANT"
    FAIL=$((FAIL+1))
fi

# Logfile existe
LOG_FILE="/var/log/siem-africa/msmtp.log"
if [ -f "$LOG_FILE" ]; then
    echo "  ✓ Log file existe : $LOG_FILE"
    PASS=$((PASS+1))
else
    echo "  ⚠ Log file absent (sera créé au 1er envoi)"
fi

# CA certificates
if [ -f /etc/ssl/certs/ca-certificates.crt ]; then
    echo "  ✓ CA certificates présents"
    PASS=$((PASS+1))
else
    echo "  ✗ CA certificates manquants"
    FAIL=$((FAIL+1))
fi

# Settings BDD cohérents
echo ""
echo "  Settings SMTP en BDD :"

SMTP_HOST=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='smtp_host'")
echo "  ℹ smtp_host : ${SMTP_HOST:-(non configuré)}"

SMTP_PORT=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='smtp_port'")
echo "  ℹ smtp_port : ${SMTP_PORT:-(non configuré)}"

SMTP_FROM=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='smtp_from_email'")
if [ -n "$SMTP_FROM" ]; then
    echo "  ✓ smtp_from_email configuré : $SMTP_FROM"
    PASS=$((PASS+1))
else
    echo "  ⚠ smtp_from_email vide (lancer ./configure_smtp.sh)"
fi

# Vérifier qu'un compte siem-africa existe dans msmtp.conf
if [ -f "$MSMTP_CONF" ] && grep -q "^account siem-africa" "$MSMTP_CONF" 2>/dev/null; then
    echo "  ✓ Compte msmtp 'siem-africa' configuré"
    PASS=$((PASS+1))

    # Tester msmtp en lecture (sans envoyer)
    if msmtp --pretend --read-recipients <<<"From: test@test.com
To: nobody@nowhere.com
Subject: test
" --account=siem-africa 2>&1 | grep -q "host\|recipient"; then
        echo "  ✓ Configuration msmtp lue avec succès"
        PASS=$((PASS+1))
    else
        echo "  ⚠ Impossible de lire la config msmtp"
    fi
else
    echo "  ⚠ msmtp non configuré (compte 'siem-africa' absent)"
    echo "    → Lancez : sudo ./configure_smtp.sh"
fi

echo ""
echo "  Résultat : $PASS passés, $FAIL échoués"
exit $FAIL
