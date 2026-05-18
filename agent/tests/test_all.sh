#!/usr/bin/env bash
# ==============================================================================
#  SIEM Africa - Module 3 - Tests COMPLETS (tous les blocs)
#
#  Vérifie que tous les 8 blocs sont opérationnels.
#  À lancer après installation et 30s d'attente.
# ==============================================================================

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Doit être exécuté en root (sudo)${NC}"
    exit 1
fi

AGENT_DIR="/opt/siem-africa-agent"
LOG_FILE="/var/log/siem-africa/agent.log"
DB_PATH="/var/lib/siem-africa/siem.db"
PASS=0
FAIL=0

t_ok() { echo -e "  ${GREEN}✓${NC} $*"; PASS=$((PASS+1)); }
t_fail() { echo -e "  ${RED}✗${NC} $*"; FAIL=$((FAIL+1)); }
t_warn() { echo -e "  ${YELLOW}!${NC} $*"; }

echo -e "${CYAN}═══════════════════════════════════════════════════════════"
echo "  Tests Agent SIEM Africa - Tous les blocs"
echo -e "═══════════════════════════════════════════════════════════${NC}"

# ============================================================================
# Service systemd
# ============================================================================
echo ""
echo "1. Service systemd"
if systemctl is-active --quiet siem-agent; then
    t_ok "Service siem-agent ACTIF"
else
    t_fail "Service siem-agent INACTIF"
    echo "    journalctl -u siem-agent -n 30"
    exit 1
fi

# ============================================================================
# Logs : healthcheck + threads
# ============================================================================
echo ""
echo "2. Logs - Healthcheck"
if grep -q "HEALTHCHECK" "$LOG_FILE" 2>/dev/null; then
    t_ok "Healthcheck exécuté"
else
    t_fail "Healthcheck absent des logs"
fi

if grep -q "DB OK" "$LOG_FILE" 2>/dev/null; then
    t_ok "BDD accessible"
else
    t_fail "BDD non accessible"
fi

echo ""
echo "3. Logs - Threads démarrés"
for thread in WazuhWatcher AlertProcessor AIEnricher EmailWorker BlockWorker UnblockerWorker KPISnapshotter DBBackup DailyRecapWorker; do
    if grep -q "$thread démarré\|$thread demarre" "$LOG_FILE" 2>/dev/null; then
        t_ok "Thread $thread démarré"
    else
        t_warn "Thread $thread non démarré (peut être normal si désactivé)"
    fi
done

# ============================================================================
# BDD - tables et contenu
# ============================================================================
echo ""
echo "4. BDD - Tables touchées"

# Test : insert audit_log a marché
NB_AUDIT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM audit_log WHERE action='agent_start';" 2>/dev/null)
if [ -n "$NB_AUDIT" ] && [ "$NB_AUDIT" -gt 0 ]; then
    t_ok "audit_log : $NB_AUDIT lignes agent_start"
else
    t_fail "audit_log : pas de ligne agent_start"
fi

# ============================================================================
# Sudoers iptables
# ============================================================================
echo ""
echo "5. Sudoers iptables (Bloc 7)"
if [ -f /etc/sudoers.d/siem-agent ]; then
    t_ok "/etc/sudoers.d/siem-agent existe"

    # Tester que siem-agent peut exécuter iptables sans password
    if sudo -u siem-agent sudo -n iptables -L INPUT >/dev/null 2>&1; then
        t_ok "siem-agent peut exécuter sudo iptables"
    else
        t_fail "siem-agent NE peut PAS exécuter sudo iptables"
    fi
else
    t_fail "/etc/sudoers.d/siem-agent absent"
fi

# ============================================================================
# Dossier backup
# ============================================================================
echo ""
echo "6. Dossier backup BDD (Bloc 8)"
if [ -d /var/backups/siem-africa ]; then
    t_ok "/var/backups/siem-africa existe"
else
    t_fail "/var/backups/siem-africa manquant"
fi

# ============================================================================
# Erreurs dans les logs
# ============================================================================
echo ""
echo "7. Erreurs dans les logs"
NB_ERR=$(grep -c "\[ERROR\]" "$LOG_FILE" 2>/dev/null || echo "0")
if [ "$NB_ERR" = "0" ]; then
    t_ok "Aucune erreur"
elif [ "$NB_ERR" -lt 3 ]; then
    t_warn "$NB_ERR erreurs (acceptable au démarrage)"
else
    t_fail "$NB_ERR erreurs - voir tail -50 $LOG_FILE | grep ERROR"
fi

# ============================================================================
# Test fonctionnel : injection d'une fausse alerte Wazuh
# ============================================================================
echo ""
echo "8. Test fonctionnel : injection alerte Wazuh"

WAZUH_LOG=/var/ossec/logs/alerts/alerts.json
if [ -w "$WAZUH_LOG" ] || sudo -u root test -w "$WAZUH_LOG" 2>/dev/null; then
    # Compter alertes avant
    NB_BEFORE=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM alerts;" 2>/dev/null || echo "0")

    # Injection (SSH brute force, rule 5712 doit exister dans signatures)
    TIMESTAMP=$(date -Iseconds)
    cat >> "$WAZUH_LOG" << EOF
{"timestamp":"${TIMESTAMP}","rule":{"id":"5712","level":10,"description":"sshd: brute force trying to get access to the system. Authentication failed.","groups":["syslog","sshd","authentication_failures"]},"agent":{"id":"000","name":"localhost"},"manager":{"name":"localhost"},"id":"test-$(date +%s)","data":{"srcip":"203.0.113.42","srcuser":"root","srcport":"45678"},"location":"/var/log/auth.log","decoder":{"name":"sshd"}}
EOF
    t_ok "Event injecté dans $WAZUH_LOG"

    # Attendre 5s pour que l'agent traite
    sleep 5

    # Compter alertes après
    NB_AFTER=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM alerts;" 2>/dev/null || echo "0")

    if [ "$NB_AFTER" -gt "$NB_BEFORE" ]; then
        t_ok "Nouvelle alerte créée en BDD ($NB_BEFORE → $NB_AFTER)"

        # Détail de la nouvelle alerte
        echo ""
        echo "   Dernière alerte :"
        sqlite3 -header "$DB_PATH" "SELECT id, severity, title, src_ip, status FROM alerts ORDER BY id DESC LIMIT 1;" 2>/dev/null | sed 's/^/      /'
    else
        t_fail "Aucune alerte créée (count : $NB_BEFORE → $NB_AFTER)"
        echo "    Vérifier : tail -30 $LOG_FILE"
    fi
else
    t_warn "Impossible d'écrire dans $WAZUH_LOG (Wazuh non installé ?)"
fi

# ============================================================================
# Résumé
# ============================================================================
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════"
echo "  Résultats"
echo -e "═══════════════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}Réussis : $PASS${NC}"
if [ "$FAIL" -gt 0 ]; then
    echo -e "  ${RED}Échoués : $FAIL${NC}"
else
    echo -e "  ${GREEN}Échoués : 0${NC}"
fi

echo ""
if [ "$FAIL" = "0" ]; then
    echo -e "${GREEN}✓ AGENT COMPLET VALIDÉ${NC}"
    exit 0
else
    echo -e "${RED}✗ Échec - corriger les problèmes${NC}"
    echo ""
    echo "Diagnostic :"
    echo "  systemctl status siem-agent"
    echo "  journalctl -u siem-agent -n 50 --no-pager"
    echo "  tail -50 $LOG_FILE"
    exit 1
fi
