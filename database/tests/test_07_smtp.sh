#!/bin/bash
# Test 07 : Configuration SMTP (Python smtplib)
DB_PATH="${DB_PATH:-/var/lib/siem-africa/siem.db}"
SMTP_CONF="${SMTP_CONF:-/etc/siem-africa/smtp.env}"
PASS=0; FAIL=0; WARN=0

t() {
    if [ "$3" = "$2" ]; then echo "  ✓ $1"; PASS=$((PASS+1));
    else echo "  ✗ $1 : got '$3', expected '$2'"; FAIL=$((FAIL+1)); fi
}

w() { echo "  ⚠ $1"; WARN=$((WARN+1)); }

echo "▶ Test 07 : Configuration SMTP (Python smtplib)"

# Python3 disponible
if command -v python3 >/dev/null 2>&1; then
    echo "  ✓ python3 disponible : $(python3 --version)"
    PASS=$((PASS+1))
else
    echo "  ✗ python3 non installé"
    FAIL=$((FAIL+1))
fi

# Module smtplib (intégré à Python standard)
if python3 -c "import smtplib" 2>/dev/null; then
    echo "  ✓ Module smtplib disponible"
    PASS=$((PASS+1))
else
    echo "  ✗ Module smtplib indisponible (Python incomplet)"
    FAIL=$((FAIL+1))
fi

# Settings BDD
SMTP_EN=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='smtp_enabled'")
t "smtp_enabled = true" "true" "$SMTP_EN"

# Settings SMTP de base
for key in smtp_host smtp_port; do
    VALUE=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='$key'")
    if [ -n "$VALUE" ]; then
        echo "  ✓ Setting $key configuré : $VALUE"
        PASS=$((PASS+1))
    else
        w "Setting $key vide"
    fi
done

# Settings SMTP utilisateur (peut être vide si pas configuré)
SMTP_USER=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='smtp_username'")
if [ -n "$SMTP_USER" ] && [ "$SMTP_USER" != "" ]; then
    echo "  ✓ smtp_username configuré : $SMTP_USER"
    PASS=$((PASS+1))
else
    w "smtp_username vide (lancer configure_smtp.sh)"
fi

# Config SMTP
if [ -f "$SMTP_CONF" ]; then
    echo "  ✓ Fichier $SMTP_CONF existe"
    PASS=$((PASS+1))

    PERMS=$(stat -c "%a" "$SMTP_CONF")
    if [ "$PERMS" = "640" ] || [ "$PERMS" = "660" ]; then
        echo "  ✓ Permissions smtp.env : $PERMS"
        PASS=$((PASS+1))
    else
        w "Permissions smtp.env : $PERMS (attendu 640)"
    fi

    OWNER=$(stat -c "%U:%G" "$SMTP_CONF")
    echo "  ✓ Propriétaire smtp.env : $OWNER"
    PASS=$((PASS+1))
else
    w "$SMTP_CONF inexistant (lancer ./configure_smtp.sh pour configurer)"
fi

# Dossier logs
if [ -d /var/log/siem-africa ]; then
    echo "  ✓ Dossier logs SIEM existe"
    PASS=$((PASS+1))
else
    echo "  ✗ /var/log/siem-africa MANQUANT"
    FAIL=$((FAIL+1))
fi

echo ""
if [ "$WARN" -gt 0 ]; then
    echo "  ℹ $WARN warning(s) - SMTP peut nécessiter une configuration via configure_smtp.sh"
fi
echo "  Résultat : $PASS passés, $FAIL échoués"
exit $FAIL
