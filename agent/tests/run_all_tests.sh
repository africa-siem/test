#!/usr/bin/env bash
# SIEM Africa - Module 3 - Lance tous les tests
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOTAL_PASS=0; TOTAL_FAIL=0; SUITES_OK=0; SUITES_KO=0

echo -e "${CYAN}"
echo "═══════════════════════════════════════════════════════════"
echo "  SIEM AFRICA - Module 3 - Tests automatiques"
echo "═══════════════════════════════════════════════════════════"
echo -e "${NC}"

for test_script in "$SCRIPT_DIR"/test_*.sh; do
    [ -f "$test_script" ] || continue
    chmod +x "$test_script"

    "$test_script"
    rc=$?

    if [ $rc -eq 0 ]; then
        SUITES_OK=$((SUITES_OK + 1))
    else
        SUITES_KO=$((SUITES_KO + 1))
    fi
    echo ""
done

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo "  Suites OK : $SUITES_OK"
echo "  Suites KO : $SUITES_KO"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

if [ "$SUITES_KO" -eq 0 ]; then
    echo -e "${GREEN}✅ Tous les tests passent.${NC}"
    exit 0
else
    echo -e "${RED}❌ $SUITES_KO suite(s) ont echoue.${NC}"
    exit 1
fi
