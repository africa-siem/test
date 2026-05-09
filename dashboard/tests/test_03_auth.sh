#!/usr/bin/env bash
# Test 03 : Login / logout via curl
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS=0; FAIL=0
URL="http://127.0.0.1"
COOKIES="/tmp/m4_test_cookies.txt"
DB="/var/lib/siem-africa/siem.db"

echo "═══════════════════════════════════════════════"
echo "  Test 03 : Authentification"
echo "═══════════════════════════════════════════════"

if ! systemctl is-active --quiet nginx 2>/dev/null; then
    echo -e "  ${YELLOW}!${NC} Nginx non actif - test saute"
    exit 0
fi

# Recuperer un email admin existant (pour le test, on cree un user dedie)
TEST_EMAIL="test-auth-$(date +%s)@siem-africa.local"
TEST_PASSWORD="TestPass1234567!"

# Creer le user via Django shell
sudo -u siem-dashboard bash -c "
    set -a; . /etc/siem-africa/dashboard.env; set +a
    cd /opt/siem-africa-dashboard
    /opt/siem-africa-dashboard/venv/bin/python manage.py shell <<PYEOF >/dev/null 2>&1
from users.models import User
User.objects.filter(email='$TEST_EMAIL').delete()
User.objects.create_user(email='$TEST_EMAIL', password='$TEST_PASSWORD', full_name='Test Auth', role='admin', is_staff=True, is_superuser=True)
PYEOF
"

# Verif que le user existe
COUNT=$(sqlite3 "$DB" "SELECT COUNT(*) FROM users WHERE email='$TEST_EMAIL';" 2>/dev/null)
if [ "$COUNT" = "1" ]; then
    echo -e "  ${GREEN}✓${NC} User test cree ($TEST_EMAIL)"
    PASS=$((PASS+1))
else
    echo -e "  ${RED}✗${NC} User test non cree"
    FAIL=$((FAIL+1))
    echo "  Resultat : $PASS passes, $FAIL echoues"
    exit $FAIL
fi

rm -f $COOKIES

# 1. Recuperer CSRF token
curl -s --max-time 5 -c "$COOKIES" "$URL/login/" -o /tmp/login_page.html
CSRF=$(grep csrfmiddlewaretoken /tmp/login_page.html | grep -oP 'value="[^"]+"' | head -1 | cut -d'"' -f2)

if [ -n "$CSRF" ]; then
    echo -e "  ${GREEN}✓${NC} CSRF token recupere"
    PASS=$((PASS+1))
else
    echo -e "  ${RED}✗${NC} CSRF token introuvable"
    FAIL=$((FAIL+1))
fi

# 2. Login
HTTP=$(curl -s --max-time 5 -b "$COOKIES" -c "$COOKIES" -X POST \
  -H "Referer: $URL/login/" \
  --data-urlencode "csrfmiddlewaretoken=$CSRF" \
  --data-urlencode "username=$TEST_EMAIL" \
  --data-urlencode "password=$TEST_PASSWORD" \
  -o /dev/null -w "%{http_code}" \
  "$URL/login/")

if [ "$HTTP" = "302" ]; then
    echo -e "  ${GREEN}✓${NC} Login reussi (HTTP 302)"
    PASS=$((PASS+1))
else
    echo -e "  ${RED}✗${NC} Login echoue (HTTP $HTTP)"
    FAIL=$((FAIL+1))
fi

# 3. Acces page protegee
HTTP=$(curl -s --max-time 5 -b "$COOKIES" -o /dev/null -w "%{http_code}" "$URL/alerts/")
if [ "$HTTP" = "200" ]; then
    echo -e "  ${GREEN}✓${NC} /alerts/ accessible apres login"
    PASS=$((PASS+1))
else
    echo -e "  ${RED}✗${NC} /alerts/ HTTP $HTTP (attendu 200)"
    FAIL=$((FAIL+1))
fi

# 4. Bad password rejete
rm -f $COOKIES
curl -s --max-time 5 -c "$COOKIES" "$URL/login/" -o /tmp/login_page.html
CSRF=$(grep csrfmiddlewaretoken /tmp/login_page.html | grep -oP 'value="[^"]+"' | head -1 | cut -d'"' -f2)

HTTP=$(curl -s --max-time 5 -b "$COOKIES" -c "$COOKIES" -X POST \
  -H "Referer: $URL/login/" \
  --data-urlencode "csrfmiddlewaretoken=$CSRF" \
  --data-urlencode "username=$TEST_EMAIL" \
  --data-urlencode "password=WRONG_PASSWORD" \
  -o /dev/null -w "%{http_code}" \
  "$URL/login/")

if [ "$HTTP" = "200" ]; then
    echo -e "  ${GREEN}✓${NC} Mauvais password rejete (HTTP 200, page de login renvoyee)"
    PASS=$((PASS+1))
else
    echo -e "  ${YELLOW}!${NC} Mauvais password : HTTP $HTTP"
fi

# Cleanup user test
sqlite3 "$DB" "DELETE FROM users WHERE email='$TEST_EMAIL';" 2>/dev/null
rm -f $COOKIES /tmp/login_page.html

echo ""
echo "  Resultat : $PASS passes, $FAIL echoues"
exit $FAIL
