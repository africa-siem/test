#!/usr/bin/env bash
# Test 03 : Acces a la BDD SQLite par l'agent
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS=0; FAIL=0
VENV_PY="/opt/siem-africa-agent/venv/bin/python"
AGENT_DIR="/opt/siem-africa-agent"
DB="/var/lib/siem-africa/siem.db"

echo "═══════════════════════════════════════════════"
echo "  Test 03 : Acces BDD"
echo "═══════════════════════════════════════════════"

# 1. BDD existe
if [ -f "$DB" ]; then
    echo -e "  ${GREEN}✓${NC} BDD trouvee : $DB"
    PASS=$((PASS+1))
else
    echo -e "  ${RED}✗${NC} BDD absente : $DB"
    FAIL=$((FAIL+1))
    echo "  Resultat : $PASS passes, $FAIL echoues"
    exit $FAIL
fi

# 2. siem-agent peut lire la BDD
RC=$(sudo -u siem-agent sqlite3 "$DB" "SELECT COUNT(*) FROM signatures;" 2>&1)
if echo "$RC" | grep -qE '^[0-9]+$'; then
    echo -e "  ${GREEN}✓${NC} Lecture BDD OK ($RC signatures)"
    PASS=$((PASS+1))
else
    echo -e "  ${RED}✗${NC} Lecture BDD KO : $RC"
    FAIL=$((FAIL+1))
fi

# 3. siem-agent peut ecrire (insert dummy + delete)
RC=$(sudo -u siem-agent sqlite3 "$DB" "INSERT INTO audit_log (action, resource_type, level) VALUES ('agent_test', 'test', 'INFO'); SELECT changes(); DELETE FROM audit_log WHERE action='agent_test' AND resource_type='test';" 2>&1)
if echo "$RC" | grep -q "^1$"; then
    echo -e "  ${GREEN}✓${NC} Ecriture BDD OK"
    PASS=$((PASS+1))
else
    echo -e "  ${YELLOW}!${NC} Ecriture BDD : $RC"
fi

# 4. health_check.py s'execute
cd "$AGENT_DIR"
RC=$(sudo -u siem-agent "$VENV_PY" -c "
import sys; sys.path.insert(0, '.')
import db
ok, msg = db.health_check()
print('OK' if ok else f'KO: {msg}')
" 2>&1)
if echo "$RC" | grep -q "^OK$"; then
    echo -e "  ${GREEN}✓${NC} db.health_check() OK"
    PASS=$((PASS+1))
else
    echo -e "  ${RED}✗${NC} db.health_check() KO : $RC"
    FAIL=$((FAIL+1))
fi

# 5. Tables critiques existent
for tbl in alerts signatures ai_signature_cache settings audit_log; do
    if sudo -u siem-agent sqlite3 "$DB" ".schema $tbl" 2>&1 | grep -q "CREATE TABLE"; then
        echo -e "  ${GREEN}✓${NC} Table '$tbl' presente"
        PASS=$((PASS+1))
    else
        echo -e "  ${RED}✗${NC} Table '$tbl' absente"
        FAIL=$((FAIL+1))
    fi
done

echo ""
echo "  Resultat : $PASS passes, $FAIL echoues"
exit $FAIL
