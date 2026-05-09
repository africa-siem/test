#!/usr/bin/env bash
# Test 07 : Simulation d'attaque (faux event Wazuh -> alerte creee)
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS=0; FAIL=0
DB="/var/lib/siem-africa/siem.db"
WAZUH_ALERTS="/var/ossec/logs/alerts/alerts.json"

echo "═══════════════════════════════════════════════"
echo "  Test 07 : Simulation d'attaque"
echo "═══════════════════════════════════════════════"

# 1. Service actif
if ! systemctl is-active --quiet siem-agent; then
    echo -e "  ${YELLOW}!${NC} Service siem-agent non actif - test saute"
    echo "  Resultat : 0 passes, 0 echoues (skip)"
    exit 0
fi
echo -e "  ${GREEN}✓${NC} siem-agent actif"
PASS=$((PASS+1))

# 2. Wazuh alerts.json existe
if [ ! -f "$WAZUH_ALERTS" ]; then
    echo -e "  ${YELLOW}!${NC} $WAZUH_ALERTS absent - test saute"
    echo "  Resultat : $PASS passes, $FAIL echoues"
    exit 0
fi

# 3. Compter les alertes avant
COUNT_BEFORE=$(sqlite3 "$DB" "SELECT COUNT(*) FROM alerts;" 2>/dev/null || echo 0)
echo "  Alertes en BDD avant : $COUNT_BEFORE"

# 4. Injecter un faux event Wazuh
RULE_ID="999998"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.000+0000")
FAKE_ALERT=$(cat <<EOF
{"timestamp":"$TIMESTAMP","rule":{"id":"$RULE_ID","level":7,"description":"Test alerte simulee Module 3"},"agent":{"name":"test-agent"},"data":{"srcip":"192.168.99.99","dstip":"10.0.0.1"},"full_log":"Test simulation Module 3 SIEM Africa"}
EOF
)

echo "$FAKE_ALERT" >> "$WAZUH_ALERTS"
echo -e "  ${GREEN}✓${NC} Faux event Wazuh injecte (rule_id=$RULE_ID)"
PASS=$((PASS+1))

# 5. Attendre que l'agent traite (5-30s pour signature inconnue + IA)
echo "  Attente du traitement (max 60s)..."
DETECTED=0
for i in $(seq 1 60); do
    NEW_COUNT=$(sqlite3 "$DB" "SELECT COUNT(*) FROM alerts;" 2>/dev/null || echo 0)
    if [ "$NEW_COUNT" -gt "$COUNT_BEFORE" ]; then
        # Verifier qu'il y a bien une alerte avec notre rule_id
        FOUND=$(sqlite3 "$DB" "SELECT COUNT(*) FROM alerts WHERE signature_id IN (SELECT id FROM signatures WHERE rule_id='$RULE_ID');" 2>/dev/null || echo 0)
        if [ "$FOUND" -ge 1 ]; then
            DETECTED=1
            break
        fi
    fi
    sleep 1
done

if [ "$DETECTED" = "1" ]; then
    echo -e "  ${GREEN}✓${NC} Alerte detectee et inseree apres ${i}s"
    PASS=$((PASS+1))

    # Detail de l'alerte
    echo ""
    echo "  Details de l'alerte :"
    sqlite3 -header -column "$DB" "
        SELECT a.id, a.severity, a.ai_status, substr(a.title, 1, 50) as title
          FROM alerts a
          JOIN signatures s ON s.id = a.signature_id
         WHERE s.rule_id = '$RULE_ID'
         ORDER BY a.id DESC LIMIT 1
    " 2>&1 | sed 's/^/    /'
else
    echo -e "  ${RED}✗${NC} Pas d'alerte creee apres 60s"
    FAIL=$((FAIL+1))
    echo "  Voir : journalctl -u siem-agent -n 30"
fi

# 6. Cleanup
sqlite3 "$DB" "DELETE FROM alerts WHERE signature_id IN (SELECT id FROM signatures WHERE rule_id='$RULE_ID'); DELETE FROM signatures WHERE rule_id='$RULE_ID'; DELETE FROM ai_signature_cache WHERE rule_id='$RULE_ID';" 2>/dev/null
echo "  Cleanup OK"

echo ""
echo "  Resultat : $PASS passes, $FAIL echoues"
exit $FAIL
