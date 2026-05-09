#!/usr/bin/env bash
# Test 02 : pages publiques + statics repondent
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS=0; FAIL=0
URL="http://127.0.0.1"

echo "═══════════════════════════════════════════════"
echo "  Test 02 : Pages publiques"
echo "═══════════════════════════════════════════════"

# Verifier que Nginx tourne
if ! systemctl is-active --quiet nginx 2>/dev/null; then
    echo -e "  ${YELLOW}!${NC} Nginx non actif - test saute"
    echo "  Resultat : 0 passes, 0 echoues (skip)"
    exit 0
fi

check_url() {
    local label="$1"
    local path="$2"
    local expected="$3"

    local code=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" "${URL}${path}")
    if [ "$code" = "$expected" ]; then
        echo -e "  ${GREEN}✓${NC} $label : HTTP $code"
        PASS=$((PASS+1))
    else
        echo -e "  ${RED}✗${NC} $label : HTTP $code (attendu $expected)"
        FAIL=$((FAIL+1))
    fi
}

# /login/ doit etre 200
check_url "GET /login/"                  "/login/"            "200"
# Sans login, les pages protegees doivent rediriger (302)
check_url "GET / (root)"                 "/"                  "302"
check_url "GET /alerts/ (sans login)"    "/alerts/"           "302"
check_url "GET /kpi/ (sans login)"       "/kpi/"              "302"
check_url "GET /health/ (sans login)"    "/health/"           "302"
check_url "GET /settings/ (sans login)"  "/settings/"         "302"

# Statics
check_url "Static dashboard.css"         "/static/css/dashboard.css"   "200"
check_url "Static theme-light.css"       "/static/css/theme-light.css" "200"
check_url "Static theme-dark.css"        "/static/css/theme-dark.css"  "200"
check_url "Static theme.js"              "/static/js/theme.js"         "200"
check_url "Static dashboard.js"          "/static/js/dashboard.js"     "200"

# 404
check_url "GET /not-found-xyz/"          "/not-found-xyz/"    "404"

echo ""
echo "  Resultat : $PASS passes, $FAIL echoues"
exit $FAIL
