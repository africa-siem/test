#!/bin/bash
# Test 01 : Schéma BDD
DB_PATH="${DB_PATH:-/var/lib/siem-africa/siem.db}"
PASS=0; FAIL=0

t() {
    local label="$1"; local expected="$2"; local actual="$3"
    if [ "$actual" = "$expected" ]; then
        echo "  ✓ $label"; PASS=$((PASS+1))
    else
        echo "  ✗ $label : got '$actual', expected '$expected'"; FAIL=$((FAIL+1))
    fi
}

echo "▶ Test 01 : Schéma BDD"

[ ! -f "$DB_PATH" ] && { echo "  ✗ BDD inexistante : $DB_PATH"; exit 1; }

# Tables
N=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
t "25 tables présentes" "25" "$N"

# Tables critiques
for tbl in alerts signatures users roles settings countries kpi_history audit_log; do
    EXISTS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='$tbl'")
    t "Table '$tbl' existe" "1" "$EXISTS"
done

# Vues
N=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM sqlite_master WHERE type='view'")
t "Au moins 4 vues" "4" "$N"

# Triggers
N=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger'")
t "11 triggers" "11" "$N"

# WAL
J=$(sqlite3 "$DB_PATH" "PRAGMA journal_mode")
t "Mode WAL activé" "wal" "$J"

# FK
FK=$(sqlite3 "$DB_PATH" "PRAGMA foreign_key_check" | wc -l)
t "Foreign keys OK" "0" "$FK"

echo ""
echo "  Résultat : $PASS passés, $FAIL échoués"
exit $FAIL
