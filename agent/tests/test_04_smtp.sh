#!/usr/bin/env bash
# Test 04 : SMTP - config presente et test d'envoi
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS=0; FAIL=0
SMTP_ENV="/etc/siem-africa/smtp.env"
VENV_PY="/opt/siem-africa-agent/venv/bin/python"
AGENT_DIR="/opt/siem-africa-agent"

echo "═══════════════════════════════════════════════"
echo "  Test 04 : SMTP"
echo "═══════════════════════════════════════════════"

# 1. Fichier smtp.env existe
if [ -f "$SMTP_ENV" ]; then
    echo -e "  ${GREEN}✓${NC} $SMTP_ENV present"
    PASS=$((PASS+1))
else
    echo -e "  ${YELLOW}!${NC} $SMTP_ENV absent (SMTP non configure - test skip)"
    echo "  Resultat : 0 passes, 0 echoues (skip)"
    exit 0
fi

# 2. Permissions OK
PERMS=$(stat -c '%a' "$SMTP_ENV" 2>/dev/null)
if [ "$PERMS" = "640" ] || [ "$PERMS" = "600" ]; then
    echo -e "  ${GREEN}✓${NC} Permissions $PERMS OK"
    PASS=$((PASS+1))
else
    echo -e "  ${YELLOW}!${NC} Permissions $PERMS (recommande 640)"
fi

# 3. siem-agent peut lire le fichier
if sudo -u siem-agent test -r "$SMTP_ENV" 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} siem-agent peut lire smtp.env"
    PASS=$((PASS+1))
else
    echo -e "  ${RED}✗${NC} siem-agent ne peut pas lire smtp.env"
    FAIL=$((FAIL+1))
fi

# 4. Variables critiques presentes
for v in SMTP_HOST SMTP_PORT SMTP_USER SMTP_PASS SMTP_TO; do
    if grep -q "^${v}=" "$SMTP_ENV"; then
        echo -e "  ${GREEN}✓${NC} $v defini"
        PASS=$((PASS+1))
    else
        echo -e "  ${RED}✗${NC} $v manquant"
        FAIL=$((FAIL+1))
    fi
done

# 5. Test d'envoi reel (optionnel, demande confirmation)
echo ""
echo "  Test d'envoi reel d'un email :"
echo "  (skip dans run_all_tests, lancer manuellement avec --send)"

if [ "$1" = "--send" ]; then
    cd "$AGENT_DIR"
    RC=$(sudo -u siem-agent "$VENV_PY" -c "
import sys; sys.path.insert(0, '.')
from notif.email_sender import send_test_email
print('OK' if send_test_email() else 'KO')
" 2>&1)
    if echo "$RC" | grep -q "^OK$"; then
        echo -e "  ${GREEN}✓${NC} Email envoye - verifier la boite"
        PASS=$((PASS+1))
    else
        echo -e "  ${RED}✗${NC} Echec envoi : $RC"
        FAIL=$((FAIL+1))
    fi
fi

echo ""
echo "  Resultat : $PASS passes, $FAIL echoues"
exit $FAIL
