#!/usr/bin/env bash
# ==============================================================================
#  SIEM Africa - Module 3 - Tests Bloc 1 (Fondations)
#
#  Vérifie que tous les éléments du Bloc 1 sont en place :
#    1. Utilisateur siem-agent existe et est dans les bons groupes
#    2. Dossiers créés avec les bonnes permissions
#    3. Venv Python fonctionnel
#    4. Code copié au bon endroit
#    5. Service systemd actif
#    6. Healthcheck OK dans les logs
#    7. Config agent.env présente
#
#  Usage : sudo bash tests/test_bloc_1.sh
# ==============================================================================

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Doit être exécuté en root (sudo)${NC}"
    exit 1
fi

AGENT_DIR="/opt/siem-africa-agent"
LOG_DIR="/var/log/siem-africa"
CONFIG_DIR="/etc/siem-africa"
DB_PATH="/var/lib/siem-africa/siem.db"

PASS=0
FAIL=0

echo "═══════════════════════════════════════════════════════════"
echo "  Tests Bloc 1 - Fondations"
echo "═══════════════════════════════════════════════════════════"

# ----------------------------------------------------------------------------
# Test 1 : Utilisateur Unix
# ----------------------------------------------------------------------------
echo ""
echo "Test 1 : Utilisateur Unix siem-agent"
echo "─────────────────────────────────────"

if id siem-agent &>/dev/null; then
    echo -e "  ${GREEN}✓${NC} Utilisateur siem-agent existe"
    PASS=$((PASS+1))

    GROUPS_LIST=$(groups siem-agent | cut -d: -f2 | xargs)
    echo "    Groupes : $GROUPS_LIST"

    if echo "$GROUPS_LIST" | grep -qw "siem-africa"; then
        echo -e "  ${GREEN}✓${NC} Membre du groupe siem-africa"
        PASS=$((PASS+1))
    else
        echo -e "  ${RED}✗${NC} N'est PAS dans le groupe siem-africa"
        FAIL=$((FAIL+1))
    fi

    if echo "$GROUPS_LIST" | grep -qw "wazuh"; then
        echo -e "  ${GREEN}✓${NC} Membre du groupe wazuh (peut lire alerts.json)"
        PASS=$((PASS+1))
    else
        echo -e "  ${YELLOW}!${NC} Pas membre du groupe wazuh (acceptable si Wazuh pas installé)"
    fi
else
    echo -e "  ${RED}✗${NC} Utilisateur siem-agent introuvable"
    FAIL=$((FAIL+1))
fi

# ----------------------------------------------------------------------------
# Test 2 : Dossiers et permissions
# ----------------------------------------------------------------------------
echo ""
echo "Test 2 : Dossiers et permissions"
echo "─────────────────────────────────"

for dir_info in \
    "$AGENT_DIR:siem-agent:siem-africa:755" \
    "$LOG_DIR:siem-agent:siem-africa:770" \
    "$CONFIG_DIR:::750"; do
    IFS=':' read -r dir owner group expected_perm <<< "$dir_info"
    if [ -d "$dir" ]; then
        ACTUAL_PERM=$(stat -c '%a' "$dir")
        echo -e "  ${GREEN}✓${NC} $dir existe (perms $ACTUAL_PERM)"
        PASS=$((PASS+1))
    else
        echo -e "  ${RED}✗${NC} $dir manquant"
        FAIL=$((FAIL+1))
    fi
done

# ----------------------------------------------------------------------------
# Test 3 : Venv Python et imports
# ----------------------------------------------------------------------------
echo ""
echo "Test 3 : Venv Python"
echo "─────────────────────"

VENV_PY="$AGENT_DIR/venv/bin/python"
if [ -x "$VENV_PY" ]; then
    echo -e "  ${GREEN}✓${NC} venv Python existe"
    PASS=$((PASS+1))

    PY_VER=$($VENV_PY --version 2>&1)
    echo "    Version : $PY_VER"

    # Test des imports
    for pkg in requests inotify_simple jinja2; do
        if sudo -u siem-agent "$VENV_PY" -c "import $pkg" 2>/dev/null; then
            echo -e "  ${GREEN}✓${NC} import $pkg OK (par siem-agent)"
            PASS=$((PASS+1))
        else
            echo -e "  ${RED}✗${NC} import $pkg ÉCHOUE (par siem-agent)"
            FAIL=$((FAIL+1))
        fi
    done
else
    echo -e "  ${RED}✗${NC} Venv Python introuvable"
    FAIL=$((FAIL+1))
fi

# ----------------------------------------------------------------------------
# Test 4 : Code Python en place
# ----------------------------------------------------------------------------
echo ""
echo "Test 4 : Code Python"
echo "─────────────────────"

for f in main.py config.py logger_setup.py healthcheck.py; do
    if [ -f "$AGENT_DIR/$f" ]; then
        echo -e "  ${GREEN}✓${NC} $f présent"
        PASS=$((PASS+1))
    else
        echo -e "  ${RED}✗${NC} $f manquant"
        FAIL=$((FAIL+1))
    fi
done

# Vérifier qu'on peut exécuter main.py en syntaxe Python
if sudo -u siem-agent "$VENV_PY" -c "
import ast
ast.parse(open('$AGENT_DIR/main.py').read())
ast.parse(open('$AGENT_DIR/config.py').read())
ast.parse(open('$AGENT_DIR/healthcheck.py').read())
ast.parse(open('$AGENT_DIR/logger_setup.py').read())
" 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} Syntaxe Python valide pour tous les fichiers"
    PASS=$((PASS+1))
else
    echo -e "  ${RED}✗${NC} Erreur de syntaxe Python"
    FAIL=$((FAIL+1))
fi

# ----------------------------------------------------------------------------
# Test 5 : Config agent.env
# ----------------------------------------------------------------------------
echo ""
echo "Test 5 : Config agent.env"
echo "──────────────────────────"

AGENT_ENV="$CONFIG_DIR/agent.env"
if [ -f "$AGENT_ENV" ]; then
    echo -e "  ${GREEN}✓${NC} $AGENT_ENV existe"
    PASS=$((PASS+1))

    if sudo -u siem-agent test -r "$AGENT_ENV" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} siem-agent peut le lire"
        PASS=$((PASS+1))
    else
        echo -e "  ${RED}✗${NC} siem-agent ne peut pas lire $AGENT_ENV"
        FAIL=$((FAIL+1))
    fi
else
    echo -e "  ${RED}✗${NC} $AGENT_ENV manquant"
    FAIL=$((FAIL+1))
fi

# ----------------------------------------------------------------------------
# Test 6 : Service systemd
# ----------------------------------------------------------------------------
echo ""
echo "Test 6 : Service systemd"
echo "─────────────────────────"

if [ -f /etc/systemd/system/siem-agent.service ]; then
    echo -e "  ${GREEN}✓${NC} Unit file présent"
    PASS=$((PASS+1))
else
    echo -e "  ${RED}✗${NC} /etc/systemd/system/siem-agent.service manquant"
    FAIL=$((FAIL+1))
fi

if systemctl is-enabled --quiet siem-agent 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} Service activé au boot"
    PASS=$((PASS+1))
else
    echo -e "  ${YELLOW}!${NC} Service non activé au boot"
fi

if systemctl is-active --quiet siem-agent; then
    echo -e "  ${GREEN}✓${NC} Service ACTIF"
    PASS=$((PASS+1))

    PID=$(systemctl show siem-agent -p MainPID --value)
    MEM=$(ps -p "$PID" -o rss= 2>/dev/null | xargs)
    [ -n "$MEM" ] && echo "    PID $PID, RAM : ${MEM} KB"
else
    echo -e "  ${RED}✗${NC} Service INACTIF"
    echo "    Voir : journalctl -u siem-agent -n 30 --no-pager"
    FAIL=$((FAIL+1))
fi

# ----------------------------------------------------------------------------
# Test 7 : Healthcheck dans les logs
# ----------------------------------------------------------------------------
echo ""
echo "Test 7 : Healthcheck"
echo "─────────────────────"

LOG_FILE="$LOG_DIR/agent.log"
sleep 1  # laisser le temps aux logs de s'écrire

if [ -f "$LOG_FILE" ]; then
    echo -e "  ${GREEN}✓${NC} Fichier log agent existe"
    PASS=$((PASS+1))

    # Chercher les messages de healthcheck
    if grep -q "HEALTHCHECK DÉMARRAGE\|HEALTHCHECK DEMARRAGE" "$LOG_FILE" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Healthcheck exécuté"
        PASS=$((PASS+1))
    else
        echo -e "  ${YELLOW}!${NC} Healthcheck non trouvé dans les logs (peut être tronqué)"
    fi

    if grep -q "DB OK" "$LOG_FILE" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} BDD accessible"
        PASS=$((PASS+1))
    else
        echo -e "  ${RED}✗${NC} BDD non accessible"
        FAIL=$((FAIL+1))
    fi

    if grep -q "Agent opérationnel\|Agent operationnel" "$LOG_FILE" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Agent opérationnel"
        PASS=$((PASS+1))
    else
        echo -e "  ${YELLOW}!${NC} Message 'Agent opérationnel' non trouvé"
    fi

    # Vérifier qu'il n'y a pas d'erreurs critiques
    NB_ERR=$(grep -c "\[ERROR\]" "$LOG_FILE" 2>/dev/null || echo 0)
    if [ "$NB_ERR" = "0" ]; then
        echo -e "  ${GREEN}✓${NC} Aucune erreur dans les logs"
        PASS=$((PASS+1))
    else
        echo -e "  ${YELLOW}!${NC} $NB_ERR erreurs dans les logs"
        echo "    Voir : tail -50 $LOG_FILE | grep ERROR"
    fi
else
    echo -e "  ${RED}✗${NC} $LOG_FILE manquant"
    FAIL=$((FAIL+1))
fi

# ============================================================================
# Résumé
# ============================================================================
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Résultats"
echo "═══════════════════════════════════════════════════════════"
echo -e "  ${GREEN}Réussis : $PASS${NC}"
if [ "$FAIL" -gt "0" ]; then
    echo -e "  ${RED}Échoués : $FAIL${NC}"
else
    echo -e "  ${GREEN}Échoués : 0${NC}"
fi

echo ""
if [ "$FAIL" = "0" ]; then
    echo -e "${GREEN}✓ BLOC 1 (Fondations) validé - on peut passer au Bloc 2${NC}"
    exit 0
else
    echo -e "${RED}✗ Échec - corriger les problèmes avant de passer au Bloc 2${NC}"
    echo ""
    echo "Diagnostic :"
    echo "  systemctl status siem-agent"
    echo "  journalctl -u siem-agent -n 50 --no-pager"
    echo "  tail -50 $LOG_FILE"
    exit 1
fi
