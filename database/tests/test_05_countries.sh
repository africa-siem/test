#!/bin/bash
# Test 05 : Pays Afrique Centrale (NOUVEAU - demande encadreur)
DB_PATH="${DB_PATH:-/var/lib/siem-africa/siem.db}"
PASS=0; FAIL=0

t() {
    if [ "$3" = "$2" ]; then echo "  ✓ $1"; PASS=$((PASS+1));
    else echo "  ✗ $1 : got '$3', expected '$2'"; FAIL=$((FAIL+1)); fi
}

echo "▶ Test 05 : Pays Afrique Centrale (4 pays)"

# Total
N=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM countries")
t "4 pays présents" "4" "$N"

# Chaque pays
for code in CM GA CG CD; do
    N=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM countries WHERE code_iso2='$code'")
    t "Pays $code" "1" "$N"
done

# Cameroun avec stats cyber
N_INC=$(sqlite3 "$DB_PATH" "SELECT cyberattack_increase_pct FROM countries WHERE code_iso2='CM'")
echo "  ℹ Cameroun : +${N_INC}% de cyberattaques (2020-2023)"

N_LOSS=$(sqlite3 "$DB_PATH" "SELECT cyberattack_loss_million_usd FROM countries WHERE code_iso2='CM'")
echo "  ℹ Cameroun : ${N_LOSS}M\$ de pertes"

# Population totale
TOTAL_POP=$(sqlite3 "$DB_PATH" "SELECT SUM(population)/1000000 FROM countries WHERE is_active=1")
echo "  ℹ Population totale 4 pays : ${TOTAL_POP}M habitants"

# PIB total
TOTAL_GDP=$(sqlite3 "$DB_PATH" "SELECT SUM(gdp_usd_billion) FROM countries WHERE is_active=1")
echo "  ℹ PIB combiné : ${TOTAL_GDP}Mrd \$"

# Tous actifs
N_ACT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM countries WHERE is_active=1")
t "4 pays actifs" "4" "$N_ACT"

# Tous ont un nom_fr
N_FR=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM countries WHERE name_fr IS NULL OR name_fr=''")
t "Tous ont un name_fr" "0" "$N_FR"

# Tous ont une autorité cyber
N_AUTH=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM countries WHERE cyber_authority IS NOT NULL")
t "Autorités cyber renseignées" "4" "$N_AUTH"

# Admin a bien un country_id
ADMIN_CTRY=$(sqlite3 "$DB_PATH" "SELECT country_id FROM users WHERE role_id = (SELECT id FROM roles WHERE code='ADMIN') LIMIT 1")
if [ -n "$ADMIN_CTRY" ] && [ "$ADMIN_CTRY" != "" ]; then
    CTRY_NAME=$(sqlite3 "$DB_PATH" "SELECT name_fr FROM countries WHERE id=$ADMIN_CTRY")
    echo "  ✓ Admin assigné au pays : $CTRY_NAME"
    PASS=$((PASS+1))
else
    echo "  ⚠ Admin sans pays assigné"
fi

echo ""
echo "  Résultat : $PASS passés, $FAIL échoués"
exit $FAIL
