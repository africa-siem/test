#!/usr/bin/env bash
# ============================================================================
# SIEM Africa — Tests du Dashboard (Module 4)
# Compatible avec les URLs françaises du nouveau code
#
# Usage : sudo bash test_dashboard.sh [URL_BASE]
# Exemple : sudo bash test_dashboard.sh http://192.168.1.128
# ============================================================================

set -uo pipefail

BASE_URL="${1:-http://localhost}"
ADMIN_EMAIL="admin@siemafrica.cm"
ADMIN_PASS="Admin@SiemAfrica2026"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✓${NC} $1"; PASSES=$((PASSES+1)); }
fail() { echo -e "  ${RED}✗${NC} $1"; FAILURES=$((FAILURES+1)); }
info() { echo -e "  ${YELLOW}→${NC} $1"; }
sep()  { echo -e "${CYAN}═══════════════════════════════════════════════${NC}"; }

PASSES=0; FAILURES=0; SUITES_OK=0; SUITES_KO=0
COOKIE_JAR="/tmp/siem_test_cookies_$$"
trap "rm -f ${COOKIE_JAR}" EXIT

suite_start() { sep; echo -e "${CYAN}  Test $1 : $2${NC}"; sep; SUITE_FAILS=0; }
suite_end()   {
    if [[ $SUITE_FAILS -eq 0 ]]; then
        SUITES_OK=$((SUITES_OK+1))
    else
        SUITES_KO=$((SUITES_KO+1))
    fi
}

check_http() {
    local label="$1" url="$2" expected="$3" cookies="${4:-}"
    local args=("-s" "-o" "/dev/null" "-w" "%{http_code}" "--max-time" "10")
    [[ -n "$cookies" ]] && args+=("-b" "$cookies")
    local code
    code=$(curl "${args[@]}" "${BASE_URL}${url}" 2>/dev/null || echo "000")
    if [[ "$code" == "$expected" ]]; then
        ok "${label} : HTTP ${code}"
    else
        fail "${label} : HTTP ${code} (attendu ${expected})"
        SUITE_FAILS=$((SUITE_FAILS+1))
    fi
    echo "$code"
}

check_contains() {
    local label="$1" url="$2" needle="$3" cookies="${4:-}"
    local args=("-s" "-L" "--max-time" "10")
    [[ -n "$cookies" ]] && args+=("-b" "$cookies")
    local body
    body=$(curl "${args[@]}" "${BASE_URL}${url}" 2>/dev/null || echo "")
    if echo "$body" | grep -q "$needle"; then
        ok "${label} contient '${needle}'"
    else
        fail "${label} ne contient pas '${needle}'"
        SUITE_FAILS=$((SUITE_FAILS+1))
    fi
}

# ============================================================================
# TEST 01 : Service et page de login
# ============================================================================
suite_start "01" "Service actif + Page de login"

code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${BASE_URL}/" 2>/dev/null || echo "000")
if [[ "$code" == "200" || "$code" == "302" ]]; then
    ok "Serveur répond (HTTP ${code})"
else
    fail "Serveur ne répond pas (HTTP ${code})"
    SUITE_FAILS=$((SUITE_FAILS+1))
fi

check_contains "Page login" "/" "siem_session\|connexion\|Connexion\|login\|SIEM Africa" ""

suite_end

# ============================================================================
# TEST 02 : Authentification
# ============================================================================
suite_start "02" "Authentification (login/logout)"

# Récupérer le token CSRF
LOGIN_PAGE=$(curl -s -c "${COOKIE_JAR}" --max-time 10 "${BASE_URL}/" 2>/dev/null || echo "")
CSRF=$(echo "$LOGIN_PAGE" | grep -oP 'csrfmiddlewaretoken.*?value=["'"'"']\K[^"'"'"']+' | head -1)

if [[ -z "$CSRF" ]]; then
    # Essayer aussi depuis le cookie
    CSRF=$(grep "csrftoken" "${COOKIE_JAR}" 2>/dev/null | awk '{print $NF}' | head -1)
fi

if [[ -n "$CSRF" ]]; then
    ok "Token CSRF récupéré"
else
    fail "Token CSRF introuvable"
    SUITE_FAILS=$((SUITE_FAILS+1))
    info "Vérifier que le dashboard est bien démarré"
fi

# Tentative de login
if [[ -n "$CSRF" ]]; then
    LOGIN_RESP=$(curl -s -c "${COOKIE_JAR}" -b "${COOKIE_JAR}" \
        -X POST "${BASE_URL}/connexion/" \
        -d "email=${ADMIN_EMAIL}&password=${ADMIN_PASS}&csrfmiddlewaretoken=${CSRF}" \
        -H "Referer: ${BASE_URL}/" \
        -w "\n%{http_code}" \
        --max-time 10 2>/dev/null || echo -e "\n000")

    LOGIN_CODE=$(echo "$LOGIN_RESP" | tail -1)

    if [[ "$LOGIN_CODE" == "302" || "$LOGIN_CODE" == "200" ]]; then
        ok "Login accepté (HTTP ${LOGIN_CODE})"
    else
        fail "Login refusé (HTTP ${LOGIN_CODE})"
        SUITE_FAILS=$((SUITE_FAILS+1))
        info "Email : ${ADMIN_EMAIL} / Pass : ${ADMIN_PASS}"
        info "Vérifier que le compte ADMIN existe dans la BDD"
    fi
fi

# Vérifier accès dashboard après login
DASH_CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "${COOKIE_JAR}" \
    -L --max-time 10 "${BASE_URL}/tableau-de-bord/" 2>/dev/null || echo "000")
if [[ "$DASH_CODE" == "200" ]]; then
    ok "Tableau de bord accessible après login (HTTP 200)"
else
    fail "Tableau de bord inaccessible après login (HTTP ${DASH_CODE})"
    SUITE_FAILS=$((SUITE_FAILS+1))
fi

suite_end

# ============================================================================
# TEST 03 : Pages principales (URLs françaises)
# ============================================================================
suite_start "03" "Pages principales (URLs françaises)"

declare -A PAGES=(
    ["/tableau-de-bord/"]="Tableau de bord"
    ["/alertes/"]="Alertes"
    ["/incidents/"]="Incidents"
    ["/ips-bloquees/"]="IPs bloquées"
    ["/signatures/"]="Signatures"
    ["/assistant-ia/"]="Assistant IA"
    ["/parametres/"]="Paramètres"
    ["/rapports/"]="Rapports"
    ["/journal-audit/"]="Journal audit"
    ["/profil/"]="Profil"
)

for url in "${!PAGES[@]}"; do
    label="${PAGES[$url]}"
    code=$(curl -s -o /dev/null -w "%{http_code}" -b "${COOKIE_JAR}" \
        --max-time 10 "${BASE_URL}${url}" 2>/dev/null || echo "000")
    if [[ "$code" == "200" ]]; then
        ok "${label} (${url}) : HTTP 200"
    else
        fail "${label} (${url}) : HTTP ${code} (attendu 200)"
        SUITE_FAILS=$((SUITE_FAILS+1))
    fi
done

suite_end

# ============================================================================
# TEST 04 : Contenu page Paramètres
# ============================================================================
suite_start "04" "Contenu page Paramètres"

SETTINGS_BODY=$(curl -s -b "${COOKIE_JAR}" -L --max-time 10 \
    "${BASE_URL}/parametres/" 2>/dev/null || echo "")

for needle in "smtp" "ai" "Notifications\|Email\|SMTP" "Intelligence\|IA\|Ollama" "Enregistrer\|Sauvegarder\|save"; do
    if echo "$SETTINGS_BODY" | grep -iq "$needle"; then
        ok "Paramètres contient '${needle}'"
    else
        fail "Paramètres ne contient pas '${needle}'"
        SUITE_FAILS=$((SUITE_FAILS+1))
    fi
done

suite_end

# ============================================================================
# TEST 05 : Gestion utilisateurs (ADMIN)
# ============================================================================
suite_start "05" "Gestion utilisateurs"

USERS_CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "${COOKIE_JAR}" \
    --max-time 10 "${BASE_URL}/utilisateurs/" 2>/dev/null || echo "000")
if [[ "$USERS_CODE" == "200" ]]; then
    ok "Page utilisateurs accessible (HTTP 200)"
else
    fail "Page utilisateurs inaccessible (HTTP ${USERS_CODE})"
    SUITE_FAILS=$((SUITE_FAILS+1))
fi

# Créer un utilisateur test
CSRF2=$(grep "csrftoken" "${COOKIE_JAR}" 2>/dev/null | awk '{print $NF}' | head -1)
if [[ -n "$CSRF2" ]]; then
    CREATE_CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "${COOKIE_JAR}" \
        -X POST "${BASE_URL}/utilisateurs/" \
        -d "action=create&email=testuser_$$@siemafrica.cm&first_name=Test&last_name=User&role_id=3&language=fr&csrfmiddlewaretoken=${CSRF2}" \
        -H "Referer: ${BASE_URL}/utilisateurs/" \
        --max-time 10 2>/dev/null || echo "000")
    if [[ "$CREATE_CODE" == "200" || "$CREATE_CODE" == "302" ]]; then
        ok "Création utilisateur test : HTTP ${CREATE_CODE}"
    else
        fail "Création utilisateur test : HTTP ${CREATE_CODE}"
        SUITE_FAILS=$((SUITE_FAILS+1))
    fi
fi

suite_end

# ============================================================================
# TEST 06 : Chat IA (endpoint AJAX)
# ============================================================================
suite_start "06" "Endpoints Chat IA"

CSRF3=$(grep "csrftoken" "${COOKIE_JAR}" 2>/dev/null | awk '{print $NF}' | head -1)

# Assistant IA page
AI_CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "${COOKIE_JAR}" \
    --max-time 10 "${BASE_URL}/assistant-ia/" 2>/dev/null || echo "000")
if [[ "$AI_CODE" == "200" ]]; then
    ok "Page assistant IA accessible"
else
    fail "Page assistant IA inaccessible (HTTP ${AI_CODE})"
    SUITE_FAILS=$((SUITE_FAILS+1))
fi

# Endpoint chat (doit répondre 400 si message vide, pas 302 ni 500)
if [[ -n "$CSRF3" ]]; then
    CHAT_CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "${COOKIE_JAR}" \
        -X POST "${BASE_URL}/assistant-ia/chat/" \
        -d "message=&csrfmiddlewaretoken=${CSRF3}" \
        -H "Referer: ${BASE_URL}/assistant-ia/" \
        --max-time 10 2>/dev/null || echo "000")
    if [[ "$CHAT_CODE" == "400" || "$CHAT_CODE" == "200" ]]; then
        ok "Endpoint chat IA répond correctement (HTTP ${CHAT_CODE})"
    else
        fail "Endpoint chat IA : HTTP ${CHAT_CODE} (attendu 400 ou 200)"
        SUITE_FAILS=$((SUITE_FAILS+1))
    fi
fi

suite_end

# ============================================================================
# TEST 07 : Génération rapport
# ============================================================================
suite_start "07" "Rapports PDF/Excel"

REPORTS_CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "${COOKIE_JAR}" \
    --max-time 10 "${BASE_URL}/rapports/" 2>/dev/null || echo "000")
if [[ "$REPORTS_CODE" == "200" ]]; then
    ok "Page rapports accessible (HTTP 200)"
else
    fail "Page rapports inaccessible (HTTP ${REPORTS_CODE})"
    SUITE_FAILS=$((SUITE_FAILS+1))
fi

CSRF4=$(grep "csrftoken" "${COOKIE_JAR}" 2>/dev/null | awk '{print $NF}' | head -1)
if [[ -n "$CSRF4" ]]; then
    GEN_CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "${COOKIE_JAR}" \
        --max-time 30 "${BASE_URL}/rapports/generer/?format=pdf&days=7" 2>/dev/null || echo "000")
    if [[ "$GEN_CODE" == "302" || "$GEN_CODE" == "200" ]]; then
        ok "Génération rapport PDF : HTTP ${GEN_CODE}"
    else
        fail "Génération rapport PDF : HTTP ${GEN_CODE}"
        SUITE_FAILS=$((SUITE_FAILS+1))
    fi
fi

suite_end

# ============================================================================
# TEST 08 : Sécurité — redirection si non connecté
# ============================================================================
suite_start "08" "Sécurité — redirection si non connecté"

for url in "/tableau-de-bord/" "/alertes/" "/utilisateurs/" "/parametres/"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
        "${BASE_URL}${url}" 2>/dev/null || echo "000")
    if [[ "$code" == "302" || "$code" == "301" ]]; then
        ok "Non connecté → ${url} redirige (HTTP ${code})"
    else
        fail "Non connecté → ${url} : HTTP ${code} (attendu 302)"
        SUITE_FAILS=$((SUITE_FAILS+1))
    fi
done

suite_end

# ============================================================================
# RÉSUMÉ
# ============================================================================
sep
echo ""
echo -e "  Passes   : ${GREEN}${PASSES}${NC}"
echo -e "  Échecs   : ${RED}${FAILURES}${NC}"
echo ""
sep
echo -e "  Suites OK : ${GREEN}${SUITES_OK}${NC}"
echo -e "  Suites KO : ${RED}${SUITES_KO}${NC}"
sep
echo ""

if [[ $SUITES_KO -eq 0 ]]; then
    echo -e "${GREEN}✅ Tous les tests sont passés.${NC}"
    exit 0
else
    echo -e "${RED}❌ ${SUITES_KO} suite(s) ont échoué.${NC}"
    exit 1
fi
