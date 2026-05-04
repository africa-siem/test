#!/bin/bash
# Test 02 : Signatures (380 attendues)
DB_PATH="${DB_PATH:-/var/lib/siem-africa/siem.db}"
PASS=0; FAIL=0

t() {
    if [ "$3" = "$2" ]; then echo "  ✓ $1"; PASS=$((PASS+1));
    else echo "  ✗ $1 : got '$3', expected '$2'"; FAIL=$((FAIL+1)); fi
}

echo "▶ Test 02 : Signatures"

# Total
N=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signatures")
t "380 signatures total" "380" "$N"

# Wazuh
N=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signatures WHERE source='wazuh'")
t "190 signatures Wazuh" "190" "$N"

# Snort
N=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signatures WHERE source='snort'")
t "190 signatures Snort" "190" "$N"

# Toutes ont une catégorie valide
N=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signatures s LEFT JOIN signature_categories sc ON s.category_id = sc.id WHERE sc.id IS NULL")
t "Toutes les sigs ont une catégorie valide" "0" "$N"

# Sévérités
for sev in CRITICAL HIGH MEDIUM LOW INFO; do
    N=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signatures WHERE severity='$sev'")
    if [ "$N" -gt 0 ]; then
        echo "  ✓ Sévérité $sev : $N signatures"
        PASS=$((PASS+1))
    else
        echo "  ⚠ Sévérité $sev : aucune signature"
    fi
done

# UUID uniques
N_DUP=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) - COUNT(DISTINCT uuid) FROM signatures")
t "UUIDs uniques" "0" "$N_DUP"

# CVE référencées
N_CVE=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signatures WHERE cve_ids IS NOT NULL")
echo "  ℹ CVE référencées : $N_CVE signatures"

echo ""
echo "  Résultat : $PASS passés, $FAIL échoués"
exit $FAIL
