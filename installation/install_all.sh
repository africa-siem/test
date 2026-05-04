#!/bin/bash
#===============================================================================
#
#          FILE: install_module1.sh
#
#   DESCRIPTION: SIEM Africa - Module 1 - Menu de choix LITE/FULL
#
#         USAGE: sudo ./install_module1.sh
#
#   Ce script propose un choix interactif entre :
#     - LITE : Snort + Wazuh Manager (4 Go RAM, pas de Dashboard)
#     - FULL : Snort + Wazuh complet (8 Go RAM, Dashboard inclus)
#
#   Il lance ensuite le bon script selon le choix.
#
#===============================================================================

set -e

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

#---------------------------------------
# Vérification root
#---------------------------------------
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}✗ Ce script doit être exécuté avec sudo.${NC}"
    echo ""
    echo "   Relancez : sudo ./install_module1.sh"
    exit 1
fi

#---------------------------------------
# Banner
#---------------------------------------
clear 2>/dev/null || true
echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                                                                  ║"
echo "║         🛡️   SIEM AFRICA - MODULE 1                             ║"
echo "║                                                                  ║"
echo "║              Snort IDS + Wazuh SIEM                              ║"
echo "║                                                                  ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""

#---------------------------------------
# Choix de la langue
#---------------------------------------
echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
echo -e "  ${BOLD}Choix de la langue / Language selection${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "    [1] Français (défaut)"
echo "    [2] English"
echo ""
echo -n "  → Choix [1/2] : "
read -r LANG_CHOICE

case "$LANG_CHOICE" in
    2|en|EN) LANG_CODE="en" ;;
    *) LANG_CODE="fr" ;;
esac

echo ""

#---------------------------------------
# Texte bilingue
#---------------------------------------
if [ "$LANG_CODE" = "en" ]; then
    T_MODE_CHOICE="INSTALLATION MODE SELECTION"
    T_LITE="Snort + Wazuh Manager only (command-line)"
    T_LITE_REQ="Minimum: 2 GB RAM, 15 GB disk, 1 CPU"
    T_LITE_USE="Best for: light servers, no web dashboard needed"
    T_FULL="Snort + Wazuh full (Manager + Indexer + Dashboard)"
    T_FULL_REQ="Minimum: 4 GB RAM, 30 GB disk, 2 CPUs"
    T_FULL_USE="Best for: production, web dashboard included"
    T_CHOICE="Your choice [1/2]:"
    T_INVALID="Invalid choice. Restart the script."
    T_STARTING="Starting"
    T_INSTALL="installation..."
    T_NOT_FOUND="not found in"
    T_MAKE_EXE="Make it executable:"
else
    T_MODE_CHOICE="CHOIX DU MODE D'INSTALLATION"
    T_LITE="Snort + Wazuh Manager seul (ligne de commande)"
    T_LITE_REQ="Minimum : 2 Go RAM, 15 Go disque, 1 CPU"
    T_LITE_USE="Idéal pour : serveurs légers, sans dashboard web"
    T_FULL="Snort + Wazuh complet (Manager + Indexer + Dashboard)"
    T_FULL_REQ="Minimum : 4 Go RAM, 30 Go disque, 2 CPU"
    T_FULL_USE="Idéal pour : production, dashboard web inclus"
    T_CHOICE="Votre choix [1/2] :"
    T_INVALID="Choix invalide. Relancez le script."
    T_STARTING="Démarrage de l'installation"
    T_INSTALL=""
    T_NOT_FOUND="introuvable dans"
    T_MAKE_EXE="Rendez-le exécutable :"
fi

#---------------------------------------
# Menu mode lite/full
#---------------------------------------
echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
echo -e "  ${BOLD}$T_MODE_CHOICE${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${YELLOW}[1] LITE${NC} - $T_LITE"
echo -e "           ${CYAN}$T_LITE_REQ${NC}"
echo -e "           ${CYAN}$T_LITE_USE${NC}"
echo ""
echo -e "  ${GREEN}[2] FULL${NC} - $T_FULL"
echo -e "           ${CYAN}$T_FULL_REQ${NC}"
echo -e "           ${CYAN}$T_FULL_USE${NC}"
echo ""
echo -n "  → $T_CHOICE "
read -r MODE_CHOICE
echo ""

case "$MODE_CHOICE" in
    1|lite|LITE)
        TARGET_SCRIPT="${SCRIPT_DIR}/install_module1_lite.sh"
        MODE_NAME="LITE"
        ;;
    2|full|FULL)
        TARGET_SCRIPT="${SCRIPT_DIR}/install_module1_full.sh"
        MODE_NAME="FULL"
        ;;
    *)
        echo -e "${RED}✗ $T_INVALID${NC}"
        exit 1
        ;;
esac

#---------------------------------------
# Vérification existence du script cible
#---------------------------------------
if [ ! -f "$TARGET_SCRIPT" ]; then
    echo -e "${RED}✗ $(basename "$TARGET_SCRIPT") $T_NOT_FOUND $SCRIPT_DIR${NC}"
    exit 1
fi

if [ ! -x "$TARGET_SCRIPT" ]; then
    echo -e "${YELLOW}⚠  $T_MAKE_EXE chmod +x $(basename "$TARGET_SCRIPT")${NC}"
    chmod +x "$TARGET_SCRIPT"
fi

#---------------------------------------
# Lancement
#---------------------------------------
echo -e "${GREEN}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "  ${BOLD}$T_STARTING $MODE_NAME $T_INSTALL${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════════${NC}"
echo ""
sleep 1

# Passer la langue au script appelé pour éviter de la redemander
export LANG_FORCED=1
exec "$TARGET_SCRIPT" --lang "$LANG_CODE"
