#!/bin/bash
# ============================================================================
# SIEM AFRICA - Module 2 : Lance tous les tests
# ============================================================================

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export DB_PATH="${DB_PATH:-/var/lib/siem-africa/siem.db}"

if [ ! -f "$DB_PATH" ]; then
    echo -e "${RED}✗ BDD inexistante : $DB_PATH${NC}"
    echo "Lancez d'abord : sudo ./install_database.sh"
    exit 1
fi

echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  SIEM AFRICA - Tests Module 2${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo "  BDD testée : $DB_PATH"
echo ""

TOTAL_PASS=0
TOTAL_FAIL=0
FAILED_TESTS=()

run_test() {
    local script="$1"
    local label="$2"

    if [ ! -x "$script" ]; then
        chmod +x "$script"
    fi

    output=$("$script" 2>&1)
    rc=$?

    echo "$output"

    pass=$(echo "$output" | grep -E "Résultat : [0-9]+ passés" | grep -oE "[0-9]+ passés" | grep -oE "[0-9]+")
    fail=$(echo "$output" | grep -E "Résultat : [0-9]+ passés, [0-9]+ échoués" | grep -oE "[0-9]+ échoués" | grep -oE "[0-9]+")
    pass=${pass:-0}
    fail=${fail:-0}

    TOTAL_PASS=$((TOTAL_PASS + pass))
    TOTAL_FAIL=$((TOTAL_FAIL + fail))

    if [ "$rc" -ne 0 ]; then
        FAILED_TESTS+=("$label")
    fi

    echo ""
}

# Lancer chaque test
for test_file in "$SCRIPT_DIR"/test_*.sh; do
    if [ -f "$test_file" ]; then
        run_test "$test_file" "$(basename $test_file)"
    fi
done

# Résumé final
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  RÉSUMÉ FINAL${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Tests passés : ${GREEN}${TOTAL_PASS}${NC}"
echo -e "  Tests échoués: ${RED}${TOTAL_FAIL}${NC}"
echo ""

if [ "$TOTAL_FAIL" -eq 0 ]; then
    echo -e "${GREEN}┌─────────────────────────────────────────────────────────┐${NC}"
    echo -e "${GREEN}│ ✅ TOUS LES TESTS SONT PASSÉS - Module 2 prêt !         │${NC}"
    echo -e "${GREEN}└─────────────────────────────────────────────────────────┘${NC}"
    exit 0
else
    echo -e "${RED}┌─────────────────────────────────────────────────────────┐${NC}"
    echo -e "${RED}│ ✗ DES TESTS ONT ÉCHOUÉ - Vérifiez l'installation       │${NC}"
    echo -e "${RED}└─────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo "Tests en échec :"
    for t in "${FAILED_TESTS[@]}"; do
        echo "  - $t"
    done
    exit 1
fi
