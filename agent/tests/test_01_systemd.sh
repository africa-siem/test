#!/usr/bin/env bash
# Test 01 : Service systemd siem-agent.service
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS=0; FAIL=0

echo "═══════════════════════════════════════════════"
echo "  Test 01 : Service systemd"
echo "═══════════════════════════════════════════════"

# 1. Unit file existe
if [ -f /etc/systemd/system/siem-agent.service ]; then
    echo -e "  ${GREEN}✓${NC} Unit file present"
    PASS=$((PASS+1))
else
    echo -e "  ${RED}✗${NC} Unit file absent"
    FAIL=$((FAIL+1))
fi

# 2. Unit file enabled
if systemctl is-enabled siem-agent &>/dev/null; then
    echo -e "  ${GREEN}✓${NC} Service active au boot"
    PASS=$((PASS+1))
else
    echo -e "  ${RED}✗${NC} Service non active au boot"
    FAIL=$((FAIL+1))
fi

# 3. Service actif
if systemctl is-active --quiet siem-agent; then
    echo -e "  ${GREEN}✓${NC} Service en cours d'execution"
    PASS=$((PASS+1))
else
    echo -e "  ${YELLOW}!${NC} Service non actif (peut etre normal en cours d'install)"
fi

# 4. Pas d'erreur recente
ERRS=$(journalctl -u siem-agent --since "5 minutes ago" -p err --no-pager 2>/dev/null | wc -l)
if [ "$ERRS" -lt 2 ]; then
    echo -e "  ${GREEN}✓${NC} Pas d'erreur recente dans les logs"
    PASS=$((PASS+1))
else
    echo -e "  ${YELLOW}!${NC} $ERRS lignes d'erreur recentes (verifier journalctl -u siem-agent)"
fi

echo ""
echo "  Resultat : $PASS passes, $FAIL echoues"
exit $FAIL
