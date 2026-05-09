#!/usr/bin/env bash
# Test 04 : ANTI-REGRESSION bug v1 #2 - settings ne doit JAMAIS renvoyer 500
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS=0; FAIL=0
URL="http://127.0.0.1"
COOKIES="/tmp/m4_test_cookies.txt"
DB="/var/lib/siem-africa/siem.db"

echo "═══════════════════════════════════════════════"
echo "  Test 04 : Anti-regression bug v1 (settings 500)"
echo "═══════════════════════════════════════════════"

if ! systemctl is-active --quiet nginx 2>/dev/null; then
    echo -e "  ${YELLOW}!${NC} Nginx non actif - test saute"
    exit 0
fi

# Setup user admin
TEST_EMAIL="test-set-$(date +%s)@siem-africa.local"
TEST_PASSWORD="TestPass1234!"

sudo -u siem-dashboard bash -c "
    set -a; . /etc/siem-africa/dashboard.env; set +a
    cd /opt/siem-africa-dashboard
    /opt/siem-africa-dashboard/venv/bin/python manage.py shell <<PYEOF >/dev/null 2>&1
from users.models import User
User.objects.filter(email='$TEST_EMAIL').delete()
User.objects.create_user(email='$TEST_EMAIL', password='$TEST_PASSWORD', full_name='Test', role='admin', is_staff=True, is_superuser=True)
PYEOF
"

# Login
rm -f $COOKIES
curl -s --max-time 5 -c "$COOKIES" "$URL/login/" -o /tmp/login_page.html
CSRF=$(grep csrfmiddlewaretoken /tmp/login_page.html | grep -oP 'value="[^"]+"' | head -1 | cut -d'"' -f2)
curl -s --max-time 5 -b "$COOKIES" -c "$COOKIES" -X POST \
  -H "Referer: $URL/login/" \
  --data-urlencode "csrfmiddlewaretoken=$CSRF" \
  --data-urlencode "username=$TEST_EMAIL" \
  --data-urlencode "password=$TEST_PASSWORD" \
  -o /dev/null "$URL/login/"

# Test 1 : /settings/ retourne 200 (pas 500)
HTTP=$(curl -s --max-time 5 -b "$COOKIES" -o /dev/null -w "%{http_code}" "$URL/settings/")
if [ "$HTTP" = "200" ]; then
    echo -e "  ${GREEN}✓${NC} /settings/ : HTTP 200 (PAS 500)"
    PASS=$((PASS+1))
else
    echo -e "  ${RED}✗${NC} /settings/ : HTTP $HTTP (BUG v1 NON FIXE !)"
    FAIL=$((FAIL+1))
fi

# Test 2 : /settings/ contient bien les sections
HTML=$(curl -s --max-time 5 -b "$COOKIES" "$URL/settings/")
for keyword in "Email" "Intelligence" "email_enabled" "ai_default_model" "btn-test-smtp" "btn-test-model"; do
    if echo "$HTML" | grep -q "$keyword"; then
        echo -e "  ${GREEN}✓${NC} /settings/ contient '$keyword'"
        PASS=$((PASS+1))
    else
        echo -e "  ${RED}✗${NC} /settings/ ne contient pas '$keyword'"
        FAIL=$((FAIL+1))
    fi
done

# Test 3 : /settings/ resiste a une BDD avec settings corrompus
# On ajoute un setting avec une valeur bizarre, et on verifie que la page ne plante pas
sqlite3 "$DB" "INSERT OR REPLACE INTO settings (key, value) VALUES ('email_rate_limit_per_hour', 'NOT_A_NUMBER');" 2>/dev/null

HTTP=$(curl -s --max-time 5 -b "$COOKIES" -o /dev/null -w "%{http_code}" "$URL/settings/")
if [ "$HTTP" = "200" ]; then
    echo -e "  ${GREEN}✓${NC} /settings/ tolere les valeurs invalides (PAS 500)"
    PASS=$((PASS+1))
else
    echo -e "  ${RED}✗${NC} /settings/ HTTP $HTTP avec valeur invalide"
    FAIL=$((FAIL+1))
fi

# Restaurer
sqlite3 "$DB" "INSERT OR REPLACE INTO settings (key, value) VALUES ('email_rate_limit_per_hour', '30');" 2>/dev/null

# Cleanup
sqlite3 "$DB" "DELETE FROM users WHERE email='$TEST_EMAIL';" 2>/dev/null
rm -f $COOKIES /tmp/login_page.html

echo ""
echo "  Resultat : $PASS passes, $FAIL echoues"
exit $FAIL
