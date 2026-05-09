#!/usr/bin/env bash
# Test 05 : Endpoints API (KPI + admin logs) + bouton test SMTP
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS=0; FAIL=0
URL="http://127.0.0.1"
COOKIES="/tmp/m4_test_cookies.txt"
DB="/var/lib/siem-africa/siem.db"

echo "═══════════════════════════════════════════════"
echo "  Test 05 : Endpoints API + Test SMTP"
echo "═══════════════════════════════════════════════"

if ! systemctl is-active --quiet nginx 2>/dev/null; then
    echo -e "  ${YELLOW}!${NC} Nginx non actif - test saute"
    exit 0
fi

# Setup admin
TEST_EMAIL="test-api-$(date +%s)@siem-africa.local"
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

# === KPI API endpoints ===
echo "  Endpoints KPI (JSON) :"
for endpoint in alerts-by-severity alerts-timeline alerts-by-status top-attackers top-signatures ai-efficiency; do
    HTTP=$(curl -s --max-time 5 -b "$COOKIES" -o /tmp/api_resp.json -w "%{http_code}" "$URL/kpi/api/${endpoint}/")
    if [ "$HTTP" = "200" ]; then
        # Verifier que c'est du JSON valide
        if jq empty /tmp/api_resp.json 2>/dev/null; then
            echo -e "    ${GREEN}✓${NC} /kpi/api/${endpoint}/ : JSON valide"
            PASS=$((PASS+1))
        else
            echo -e "    ${RED}✗${NC} /kpi/api/${endpoint}/ : reponse pas JSON"
            FAIL=$((FAIL+1))
        fi
    else
        echo -e "    ${RED}✗${NC} /kpi/api/${endpoint}/ : HTTP $HTTP"
        FAIL=$((FAIL+1))
    fi
done

# === Admin logs API ===
echo ""
echo "  Endpoint admin logs :"
HTTP=$(curl -s --max-time 5 -b "$COOKIES" -o /tmp/log_tail.json -w "%{http_code}" "$URL/admin-logs/api/agent-log-tail/")
if [ "$HTTP" = "200" ] && jq empty /tmp/log_tail.json 2>/dev/null; then
    echo -e "    ${GREEN}✓${NC} /admin-logs/api/agent-log-tail/ : JSON OK"
    PASS=$((PASS+1))
else
    echo -e "    ${RED}✗${NC} /admin-logs/api/agent-log-tail/ : HTTP $HTTP"
    FAIL=$((FAIL+1))
fi

# === Test SMTP via POST ===
echo ""
echo "  Bouton Test SMTP (POST) :"
# Le SMTP est probablement non configure sur la VM, on teste juste que l'endpoint repond JSON propre
HTTP=$(curl -s --max-time 35 -b "$COOKIES" -o /tmp/smtp_resp.json -w "%{http_code}" \
  -X POST -H "X-CSRFToken: $CSRF" \
  "$URL/settings/test-smtp/")

if [ "$HTTP" = "200" ]; then
    if jq -r '.ok' /tmp/smtp_resp.json 2>/dev/null | grep -qE 'true|false'; then
        echo -e "    ${GREEN}✓${NC} /settings/test-smtp/ : reponse JSON valide"
        PASS=$((PASS+1))
        # Detail
        echo "      Reponse : $(jq -r '.message' /tmp/smtp_resp.json | head -c 100)"
    else
        echo -e "    ${YELLOW}!${NC} /settings/test-smtp/ : JSON malforme"
    fi
else
    echo -e "    ${RED}✗${NC} /settings/test-smtp/ : HTTP $HTTP"
    FAIL=$((FAIL+1))
fi

# === Pages principales accessibles ===
echo ""
echo "  Pages principales (avec login) :"
for page in alerts kpi health settings about admin-logs profile; do
    HTTP=$(curl -s --max-time 5 -b "$COOKIES" -o /dev/null -w "%{http_code}" "$URL/$page/")
    if [ "$HTTP" = "200" ]; then
        echo -e "    ${GREEN}✓${NC} /$page/ : HTTP 200"
        PASS=$((PASS+1))
    else
        echo -e "    ${RED}✗${NC} /$page/ : HTTP $HTTP"
        FAIL=$((FAIL+1))
    fi
done

# Cleanup
sqlite3 "$DB" "DELETE FROM users WHERE email='$TEST_EMAIL';" 2>/dev/null
rm -f $COOKIES /tmp/login_page.html /tmp/api_resp.json /tmp/log_tail.json /tmp/smtp_resp.json

echo ""
echo "  Resultat : $PASS passes, $FAIL echoues"
exit $FAIL
