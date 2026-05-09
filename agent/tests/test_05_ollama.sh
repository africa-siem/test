#!/usr/bin/env bash
# Test 05 : Ollama actif + modeles installes
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS=0; FAIL=0

echo "═══════════════════════════════════════════════"
echo "  Test 05 : Ollama"
echo "═══════════════════════════════════════════════"

# 1. Binaire ollama
if command -v ollama &>/dev/null; then
    echo -e "  ${GREEN}✓${NC} Ollama installe"
    PASS=$((PASS+1))
else
    echo -e "  ${YELLOW}!${NC} Ollama absent (mode degrade - test skip)"
    echo "  Resultat : 0 passes, 0 echoues (skip)"
    exit 0
fi

# 2. Service systemd
if systemctl is-active --quiet ollama 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} Service ollama actif"
    PASS=$((PASS+1))
elif pgrep -f "ollama serve" >/dev/null; then
    echo -e "  ${GREEN}✓${NC} Process ollama serve detecte"
    PASS=$((PASS+1))
else
    echo -e "  ${YELLOW}!${NC} Ollama non actif"
fi

# 3. API repond
if curl -fsS --max-time 5 http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} API Ollama repond"
    PASS=$((PASS+1))
else
    echo -e "  ${RED}✗${NC} API Ollama injoignable"
    FAIL=$((FAIL+1))
    echo "  Resultat : $PASS passes, $FAIL echoues"
    exit $FAIL
fi

# 4. Modeles installes
MODELS=$(curl -fsS http://127.0.0.1:11434/api/tags 2>/dev/null | jq -r '.models[].name' 2>/dev/null)
if echo "$MODELS" | grep -q "qwen2.5:3b"; then
    echo -e "  ${GREEN}✓${NC} Modele qwen2.5:3b present"
    PASS=$((PASS+1))
else
    echo -e "  ${YELLOW}!${NC} qwen2.5:3b absent"
fi

if echo "$MODELS" | grep -q "llama3.2:3b"; then
    echo -e "  ${GREEN}✓${NC} Modele llama3.2:3b present"
    PASS=$((PASS+1))
else
    echo -e "  ${YELLOW}!${NC} llama3.2:3b absent"
fi

# 5. Test inference rapide (optionnel - tres long)
if [ "$1" = "--inference" ]; then
    echo "  Test inference (peut prendre 10-30s)..."
    RESP=$(curl -fsS http://127.0.0.1:11434/api/generate \
        -H "Content-Type: application/json" \
        -d '{"model":"qwen2.5:3b","prompt":"Dis bonjour en francais","stream":false}' \
        --max-time 60 2>&1)
    if echo "$RESP" | jq -r '.response' 2>/dev/null | grep -qi "bonjour\|salut\|hello"; then
        echo -e "  ${GREEN}✓${NC} Inference fonctionne"
        PASS=$((PASS+1))
    else
        echo -e "  ${YELLOW}!${NC} Inference KO : $(echo "$RESP" | head -c 150)"
    fi
fi

echo ""
echo "  Resultat : $PASS passes, $FAIL echoues"
exit $FAIL
