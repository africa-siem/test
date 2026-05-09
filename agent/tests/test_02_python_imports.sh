#!/usr/bin/env bash
# Test 02 : Imports Python (tous les modules de l'agent)
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS=0; FAIL=0
VENV_PY="/opt/siem-africa-agent/venv/bin/python"
AGENT_DIR="/opt/siem-africa-agent"

echo "═══════════════════════════════════════════════"
echo "  Test 02 : Imports Python"
echo "═══════════════════════════════════════════════"

if [ ! -x "$VENV_PY" ]; then
    echo -e "  ${RED}✗${NC} venv Python introuvable : $VENV_PY"
    echo "  Resultat : 0 passes, 1 echoues"
    exit 1
fi

# Test que tous les modules s'importent
RC=$(cd "$AGENT_DIR" && sudo -u siem-agent "$VENV_PY" -c "
import sys
sys.path.insert(0, '.')
import config
import db
import logger
import health_check
from watchers import wazuh_watcher, snort_watcher
from processor import alert_processor
from ai import ollama_client, prompt_builder, response_parser, enrichment, worker
from notif import email_sender
from kpi import snapshot
import ip_blocker
print('OK')
" 2>&1)

if echo "$RC" | grep -q "^OK$"; then
    echo -e "  ${GREEN}✓${NC} Tous les imports passent"
    PASS=$((PASS+1))
else
    echo -e "  ${RED}✗${NC} Echec import : $RC"
    FAIL=$((FAIL+1))
fi

# Test que requests + inotify_simple sont installes
RC=$(sudo -u siem-agent "$VENV_PY" -c "
import requests
import inotify_simple
print('OK')
" 2>&1)
if echo "$RC" | grep -q "^OK$"; then
    echo -e "  ${GREEN}✓${NC} requests + inotify_simple installes"
    PASS=$((PASS+1))
else
    echo -e "  ${RED}✗${NC} Dependance manquante : $RC"
    FAIL=$((FAIL+1))
fi

echo ""
echo "  Resultat : $PASS passes, $FAIL echoues"
exit $FAIL
