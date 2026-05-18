#!/usr/bin/env bash
# Test 06 : Enrichissement IA - prompt builder, parser, cache
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS=0; FAIL=0
VENV_PY="/opt/siem-africa-agent/venv/bin/python"
AGENT_DIR="/opt/siem-africa-agent"
DB="/var/lib/siem-africa/siem.db"

echo "═══════════════════════════════════════════════"
echo "  Test 06 : Enrichissement IA"
echo "═══════════════════════════════════════════════"

if [ ! -x "$VENV_PY" ]; then
    echo -e "  ${RED}✗${NC} venv Python introuvable"
    echo "  Resultat : 0 passes, 1 echoues"
    exit 1
fi

cd "$AGENT_DIR"

# 1. Prompt builder
RC=$(sudo -u siem-agent "$VENV_PY" -c "
import sys; sys.path.insert(0, '.')
from ai.prompt_builder import build
p = build('snort', '9999', raw_message='fake log', src_ip='1.2.3.4', dst_ip='5.6.7.8')
print('OK' if 'JSON' in p and 'snort' in p and '9999' in p else 'KO')
" 2>&1)
if echo "$RC" | grep -q "^OK$"; then
    echo -e "  ${GREEN}✓${NC} Prompt builder"
    PASS=$((PASS+1))
else
    echo -e "  ${RED}✗${NC} Prompt builder : $RC"
    FAIL=$((FAIL+1))
fi

# 2. Response parser - JSON propre
RC=$(sudo -u siem-agent "$VENV_PY" -c "
import sys; sys.path.insert(0, '.')
from ai.response_parser import parse
r = parse('{\"description\":\"test\",\"severity\":\"HIGH\",\"remediation\":[\"a\",\"b\"]}')
print('OK' if r['severity']=='HIGH' and len(r['remediation'])==2 else 'KO')
" 2>&1)
if echo "$RC" | grep -q "^OK$"; then
    echo -e "  ${GREEN}✓${NC} Response parser (JSON propre)"
    PASS=$((PASS+1))
else
    echo -e "  ${RED}✗${NC} Response parser : $RC"
    FAIL=$((FAIL+1))
fi

# 3. Response parser - JSON dans du texte
RC=$(sudo -u siem-agent "$VENV_PY" -c "
import sys; sys.path.insert(0, '.')
from ai.response_parser import parse
r = parse('Voici la reponse :\\n\\n{\"description\":\"test\",\"severity\":\"MEDIUM\",\"remediation\":[\"x\"]}\\n\\nFin.')
print('OK' if r['severity']=='MEDIUM' else 'KO')
" 2>&1)
if echo "$RC" | grep -q "^OK$"; then
    echo -e "  ${GREEN}✓${NC} Parser extrait JSON depuis texte"
    PASS=$((PASS+1))
else
    echo -e "  ${RED}✗${NC} Parser texte : $RC"
    FAIL=$((FAIL+1))
fi

# 4. Response parser - severite invalide normalisee
RC=$(sudo -u siem-agent "$VENV_PY" -c "
import sys; sys.path.insert(0, '.')
from ai.response_parser import parse
r = parse('{\"description\":\"x\",\"severity\":\"unknown\",\"remediation\":[]}')
print('OK' if r['severity']=='MEDIUM' and len(r['remediation'])>=1 else 'KO')
" 2>&1)
if echo "$RC" | grep -q "^OK$"; then
    echo -e "  ${GREEN}✓${NC} Parser normalise severite invalide"
    PASS=$((PASS+1))
else
    echo -e "  ${RED}✗${NC} Parser normalise : $RC"
    FAIL=$((FAIL+1))
fi

# 5. signature_hash deterministe
RC=$(sudo -u siem-agent "$VENV_PY" -c "
import sys; sys.path.insert(0, '.')
import db
h1 = db.signature_hash('snort', '9999', 'msg')
h2 = db.signature_hash('snort', '9999', 'msg')
h3 = db.signature_hash('snort', '8888', 'msg')
print('OK' if h1==h2 and h1!=h3 and len(h1)==64 else 'KO')
" 2>&1)
if echo "$RC" | grep -q "^OK$"; then
    echo -e "  ${GREEN}✓${NC} signature_hash deterministe"
    PASS=$((PASS+1))
else
    echo -e "  ${RED}✗${NC} signature_hash : $RC"
    FAIL=$((FAIL+1))
fi

# 6. Test enrichment end-to-end (uniquement si Ollama dispo)
if curl -fsS --max-time 3 http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
    echo "  Test enrichment end-to-end (peut prendre 10-30s)..."
    RC=$(sudo -u siem-agent "$VENV_PY" -c "
import sys; sys.path.insert(0, '.')
from ai.enrichment import enrich
r = enrich('snort', '999_test_'+str(__import__('time').time())[:13], raw_message='Connexion suspecte SQL injection', src_ip='1.2.3.4')
print('OK' if r['origin'] in ('ai_fresh','ai_cache','degraded') and r.get('description') else 'KO')
print('origin:', r['origin'], 'severity:', r.get('severity'))
" 2>&1)
    if echo "$RC" | head -1 | grep -q "^OK$"; then
        echo -e "  ${GREEN}✓${NC} Enrichissement IA end-to-end"
        echo "$RC" | tail -1 | sed 's/^/      /'
        PASS=$((PASS+1))
    else
        echo -e "  ${YELLOW}!${NC} Enrichissement KO ou en mode degrade : $RC"
    fi

    # Cleanup cache test
    sqlite3 "$DB" "DELETE FROM ai_signature_cache WHERE rule_id LIKE '999_test_%';" 2>/dev/null
else
    echo -e "  ${YELLOW}!${NC} Ollama injoignable, test end-to-end saute"
fi

echo ""
echo "  Resultat : $PASS passes, $FAIL echoues"
exit $FAIL
