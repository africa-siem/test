#!/bin/bash
# Test 03 : MITRE ATT&CK
DB_PATH="${DB_PATH:-/var/lib/siem-africa/siem.db}"
PASS=0; FAIL=0

t() {
    if [ "$3" = "$2" ]; then echo "  ✓ $1"; PASS=$((PASS+1));
    else echo "  ✗ $1 : got '$3', expected '$2'"; FAIL=$((FAIL+1)); fi
}

echo "▶ Test 03 : MITRE ATT&CK"

# Tactiques
N=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM mitre_tactics")
t "14 tactiques MITRE" "14" "$N"

# Techniques
N=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM mitre_techniques")
t "137 techniques MITRE" "137" "$N"

# Techniques essentielles
for tech in T1110 T1078 T1190 T1059 T1003 T1486 T1496; do
    N=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM mitre_techniques WHERE technique_id='$tech'")
    t "Technique $tech présente" "1" "$N"
done

# Toutes les techniques ont une tactique valide
N=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM mitre_techniques mt LEFT JOIN mitre_tactics mta ON mt.tactic_id = mta.id WHERE mta.id IS NULL")
t "FK techniques→tactiques OK" "0" "$N"

# Au moins 5 sigs mappées à une technique
N=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM signatures WHERE technique_id IS NOT NULL")
if [ "$N" -ge 100 ]; then
    echo "  ✓ Signatures mappées à MITRE : $N"
    PASS=$((PASS+1))
else
    echo "  ⚠ Seulement $N signatures mappées MITRE"
fi

echo ""
echo "  Résultat : $PASS passés, $FAIL échoués"
exit $FAIL
