#!/usr/bin/env bash
# Test 01 : Django manage.py check + tables BDD presentes
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS=0; FAIL=0
DASH_DIR="/opt/siem-africa-dashboard"
DB="/var/lib/siem-africa/siem.db"

echo "═══════════════════════════════════════════════"
echo "  Test 01 : Django check + BDD"
echo "═══════════════════════════════════════════════"

if [ ! -x "$DASH_DIR/venv/bin/python" ]; then
    echo -e "  ${RED}✗${NC} venv introuvable"
    echo "  Resultat : 0 passes, 1 echoues"
    exit 1
fi

# Test 1 : manage.py check
cd "$DASH_DIR"
RC=$(sudo -u siem-dashboard \
    EnvironmentFile=/etc/siem-africa/dashboard.env \
    bash -c "set -a; . /etc/siem-africa/dashboard.env; set +a; $DASH_DIR/venv/bin/python manage.py check 2>&1")

if echo "$RC" | grep -q "no issues"; then
    echo -e "  ${GREEN}✓${NC} manage.py check passe"
    PASS=$((PASS+1))
else
    echo -e "  ${RED}✗${NC} manage.py check echoue"
    echo "$RC" | tail -10
    FAIL=$((FAIL+1))
fi

# Test 2 : tables critiques presentes
for tbl in users alerts signatures ai_signature_cache settings audit_log email_logs; do
    if sqlite3 "$DB" ".schema $tbl" 2>/dev/null | grep -q "CREATE TABLE"; then
        echo -e "  ${GREEN}✓${NC} Table '$tbl' presente"
        PASS=$((PASS+1))
    else
        echo -e "  ${RED}✗${NC} Table '$tbl' absente"
        FAIL=$((FAIL+1))
    fi
done

# Test 3 : au moins un user admin existe
RC=$(sqlite3 "$DB" "SELECT COUNT(*) FROM users WHERE is_superuser=1 AND is_active=1;" 2>/dev/null)
if [ "${RC:-0}" -ge "1" ]; then
    echo -e "  ${GREEN}✓${NC} Au moins 1 admin actif ($RC)"
    PASS=$((PASS+1))
else
    echo -e "  ${RED}✗${NC} Aucun admin actif"
    FAIL=$((FAIL+1))
fi

echo ""
echo "  Resultat : $PASS passes, $FAIL echoues"
exit $FAIL
