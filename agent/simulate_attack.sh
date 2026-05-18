#!/usr/bin/env bash
# SIEM Africa - Module 3 - Simulation d'attaques pour test/demo
#
# Usage : sudo ./simulate_attack.sh [type]
#   types : ssh-brute (defaut) | sql-inject | port-scan | unknown | all

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Doit etre execute en root (sudo)${NC}"
    exit 1
fi

WAZUH_ALERTS="/var/ossec/logs/alerts/alerts.json"
TYPE="${1:-ssh-brute}"

if [ ! -f "$WAZUH_ALERTS" ]; then
    echo -e "${RED}Fichier $WAZUH_ALERTS absent. Wazuh est-il installe ?${NC}"
    exit 1
fi

echo -e "${CYAN}"
echo "═══════════════════════════════════════════════════════════"
echo "  SIEM AFRICA - Simulateur d'attaques"
echo "═══════════════════════════════════════════════════════════"
echo -e "${NC}"
echo "Type : $TYPE"
echo "Cible : $WAZUH_ALERTS"
echo ""

inject() {
    local rule_id="$1"
    local level="$2"
    local description="$3"
    local srcip="$4"
    local fulllog="$5"

    local ts=$(date -u +"%Y-%m-%dT%H:%M:%S.%3N+0000")
    local alert=$(cat <<EOF
{"timestamp":"$ts","rule":{"id":"$rule_id","level":$level,"description":"$description","groups":["test","simulation"]},"agent":{"name":"sim-agent","ip":"$srcip"},"data":{"srcip":"$srcip","dstip":"10.0.0.1"},"full_log":"$fulllog"}
EOF
)

    echo "$alert" >> "$WAZUH_ALERTS"
    echo -e "  ${GREEN}✓${NC} Injecte rule_id=$rule_id ($description)"
}

case "$TYPE" in
    ssh-brute)
        echo "Simulation : Brute-force SSH"
        inject "5712" "10" "SSHD authentication failed" "203.0.113.42" "Failed password for invalid user admin from 203.0.113.42 port 4444 ssh2"
        inject "5712" "10" "SSHD authentication failed" "203.0.113.42" "Failed password for invalid user root from 203.0.113.42 port 4445 ssh2"
        inject "5712" "10" "SSHD authentication failed" "203.0.113.42" "Failed password for invalid user test from 203.0.113.42 port 4446 ssh2"
        inject "5712" "10" "SSHD authentication failed" "203.0.113.42" "Failed password for invalid user oracle from 203.0.113.42 port 4447 ssh2"
        inject "5712" "10" "SSHD authentication failed" "203.0.113.42" "Failed password for invalid user mysql from 203.0.113.42 port 4448 ssh2"
        ;;
    sql-inject)
        echo "Simulation : SQL Injection"
        inject "31106" "10" "SQL injection attempt" "198.51.100.10" "GET /products?id=1' OR 1=1-- HTTP/1.1"
        inject "31106" "10" "SQL injection attempt" "198.51.100.10" "GET /admin?user=admin' UNION SELECT * FROM users-- HTTP/1.1"
        ;;
    port-scan)
        echo "Simulation : Port scan"
        inject "5503" "5" "Multiple connection attempts (port scan)" "192.0.2.50" "Multiple connections from 192.0.2.50 to ports 22, 23, 80, 443, 3389, 8080"
        ;;
    unknown)
        echo "Simulation : Signature INCONNUE (declenchera l'IA)"
        UNKNOWN_RULE="999$RANDOM"
        inject "$UNKNOWN_RULE" "8" "Cryptominer XMRig process detected" "172.16.99.5" "Process /tmp/.xmr-stak detected with 100% CPU usage on agent srv-prod-01"
        echo ""
        echo -e "  ${YELLOW}!${NC} L'agent va appeler Ollama pour enrichir cette alerte (peut prendre 5-30s)"
        ;;
    all)
        echo "Simulation : TOUS les types"
        $0 ssh-brute
        echo ""
        $0 sql-inject
        echo ""
        $0 port-scan
        echo ""
        $0 unknown
        exit 0
        ;;
    *)
        echo -e "${RED}Type inconnu : $TYPE${NC}"
        echo "Usage : $0 [ssh-brute|sql-inject|port-scan|unknown|all]"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}─────────────────────────────────────────────────────────${NC}"
echo "Verifications a faire :"
echo "  1. Voir les alertes creees :"
echo "     sqlite3 /var/lib/siem-africa/siem.db 'SELECT id, severity, ai_status, substr(title,1,60) FROM alerts ORDER BY id DESC LIMIT 10;'"
echo ""
echo "  2. Voir les logs de l'agent :"
echo "     sudo journalctl -u siem-agent -n 30 --no-pager"
echo ""
echo "  3. Ouvrir Gmail pour verifier les emails recus"
echo ""
