#!/usr/bin/env bash
# ==============================================================================
#  SIEM Africa - Simulation d'attaque
#  Injecte de faux events Wazuh pour tester l'agent
#
#  Usage : sudo bash simulate_attack.sh [type]
#    type = ssh-brute (défaut) | sql-inject | port-scan | mixed
# ==============================================================================

if [ "$EUID" -ne 0 ]; then
    echo "Doit être exécuté en root"
    exit 1
fi

WAZUH_LOG=/var/ossec/logs/alerts/alerts.json
if [ ! -f "$WAZUH_LOG" ]; then
    echo "Wazuh log introuvable : $WAZUH_LOG"
    exit 1
fi

TYPE="${1:-ssh-brute}"

inject_event() {
    echo "$1" >> "$WAZUH_LOG"
}

echo "Simulation d'attaque type : $TYPE"
echo "Injection dans : $WAZUH_LOG"
echo ""

case "$TYPE" in
    ssh-brute)
        echo "→ 10 tentatives SSH brute force depuis 203.0.113.42"
        for i in $(seq 1 10); do
            TS=$(date -Iseconds)
            inject_event "{\"timestamp\":\"${TS}\",\"rule\":{\"id\":\"5712\",\"level\":10,\"description\":\"sshd brute force trying to get access\",\"groups\":[\"sshd\",\"authentication_failures\"]},\"agent\":{\"id\":\"000\",\"name\":\"localhost\"},\"id\":\"sim-${RANDOM}\",\"data\":{\"srcip\":\"203.0.113.42\",\"srcuser\":\"root\",\"srcport\":\"45678\"},\"decoder\":{\"name\":\"sshd\"}}"
            sleep 1
        done
        ;;
    sql-inject)
        echo "→ 5 tentatives SQL injection sur Apache"
        for i in $(seq 1 5); do
            TS=$(date -Iseconds)
            inject_event "{\"timestamp\":\"${TS}\",\"rule\":{\"id\":\"31103\",\"level\":12,\"description\":\"SQL injection attempt\",\"groups\":[\"apache\",\"sql_injection\"]},\"agent\":{\"id\":\"000\",\"name\":\"localhost\"},\"id\":\"sim-${RANDOM}\",\"data\":{\"srcip\":\"198.51.100.23\",\"url\":\"/admin?id=1' OR 1=1--\"},\"decoder\":{\"name\":\"apache-accesslog\"}}"
            sleep 1
        done
        ;;
    port-scan)
        echo "→ 8 events port scan depuis 192.0.2.85"
        for i in $(seq 1 8); do
            TS=$(date -Iseconds)
            PORT=$((1000 + RANDOM % 60000))
            inject_event "{\"timestamp\":\"${TS}\",\"rule\":{\"id\":\"40601\",\"level\":8,\"description\":\"Port scan detected\",\"groups\":[\"recon\"]},\"agent\":{\"id\":\"000\",\"name\":\"localhost\"},\"id\":\"sim-${RANDOM}\",\"data\":{\"srcip\":\"192.0.2.85\",\"dstport\":\"${PORT}\"},\"decoder\":{\"name\":\"firewall\"}}"
            sleep 1
        done
        ;;
    mixed)
        echo "→ Attaque coordonnée : 3 types depuis 3 IPs"
        bash "$0" ssh-brute &
        bash "$0" sql-inject &
        bash "$0" port-scan &
        wait
        ;;
    *)
        echo "Type inconnu : $TYPE"
        echo "Types valides : ssh-brute, sql-inject, port-scan, mixed"
        exit 1
        ;;
esac

echo ""
echo "Attaque simulée. Vérifiez :"
echo "  tail -20 /var/log/siem-africa/agent.log"
echo "  sqlite3 /var/lib/siem-africa/siem.db 'SELECT id,severity,title,src_ip,event_count FROM alerts ORDER BY id DESC LIMIT 10;'"
