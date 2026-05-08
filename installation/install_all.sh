#!/usr/bin/env bash
# ==============================================================================
#  SIEM AFRICA - Module 1 - Installateur principal (menu)
#  Lance install_full.sh ou install_lite.sh selon le choix de l'utilisateur
#  Compatible : Ubuntu 20.04 / 22.04 / 24.04
# ==============================================================================
#
#  Usage : sudo ./install_all.sh
# ==============================================================================

# Pas de "set -e"

# ----------------------------------------------------------------------------
# Couleurs
# ----------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ----------------------------------------------------------------------------
# Detection du dossier du script (pour fonctionner depuis n'importe ou)
# ----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ----------------------------------------------------------------------------
# Verifications de base
# ----------------------------------------------------------------------------
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[FAIL]${NC} Ce script doit etre execute en root (sudo)."
    exit 1
fi

if [ ! -f /etc/os-release ]; then
    echo -e "${RED}[FAIL]${NC} Impossible de detecter l'OS."
    exit 1
fi

. /etc/os-release
OS_VER="${VERSION_ID:-unknown}"

# ----------------------------------------------------------------------------
# Banner
# ----------------------------------------------------------------------------
clear
echo -e "${CYAN}"
cat <<'BANNER'
═══════════════════════════════════════════════════════════════════
  ███████╗██╗███████╗███╗   ███╗     █████╗ ███████╗
  ██╔════╝██║██╔════╝████╗ ████║    ██╔══██╗██╔════╝
  ███████╗██║█████╗  ██╔████╔██║    ███████║█████╗
  ╚════██║██║██╔══╝  ██║╚██╔╝██║    ██╔══██║██╔══╝
  ███████║██║███████╗██║ ╚═╝ ██║    ██║  ██║██║
  ╚══════╝╚═╝╚══════╝╚═╝     ╚═╝    ╚═╝  ╚═╝╚═╝

  Module 1 - Wazuh 4.14 + Snort 2.9
  Installateur pour Ubuntu 20.04 / 22.04 / 24.04
═══════════════════════════════════════════════════════════════════
BANNER
echo -e "${NC}"

# ----------------------------------------------------------------------------
# Affichage des specs systeme
# ----------------------------------------------------------------------------
RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
CPU_COUNT=$(nproc 2>/dev/null || echo "?")
DISK_FREE_GB=$(df -BG / | awk 'NR==2 {print $4}' | tr -d 'G')

echo -e "${BOLD}Systeme detecte :${NC}"
echo "  OS              : Ubuntu $OS_VER"
echo "  RAM             : ${RAM_MB} Mo"
echo "  CPU             : ${CPU_COUNT} cores"
echo "  Disque libre    : ${DISK_FREE_GB} Go"
echo ""

# ----------------------------------------------------------------------------
# Menu langue (futur)
# ----------------------------------------------------------------------------
echo -e "${CYAN}Langue / Language :${NC}"
echo "  [1] Francais"
echo "  [2] English (a venir)"
echo ""
read -p "  Choix [1/2] : " LANG_CHOICE
LANG_CHOICE="${LANG_CHOICE:-1}"
# Pour l'instant on reste en francais quel que soit le choix

# ----------------------------------------------------------------------------
# Menu mode d'installation
# ----------------------------------------------------------------------------
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  CHOIX DU MODE D'INSTALLATION${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${YELLOW}[1] LITE${NC}  - Snort + Wazuh Manager seul (ligne de commande)"
echo -e "         Minimum : 2 Go RAM, 15 Go disque, 1 CPU"
echo -e "         Ideal pour : serveurs legers, sans dashboard web"
echo ""
echo -e "  ${GREEN}[2] FULL${NC}  - Snort + Wazuh complet (Manager + Indexer + Dashboard)"
echo -e "         Minimum : 4 Go RAM, 30 Go disque, 2 CPU"
echo -e "         Ideal pour : production, dashboard web inclus"
echo ""
read -p "  Votre choix [1/2] : " MODE_CHOICE

# ----------------------------------------------------------------------------
# Lancement du sous-script selon le choix
# ----------------------------------------------------------------------------
case "$MODE_CHOICE" in
    1)
        TARGET_SCRIPT="install_lite.sh"
        ;;
    2)
        TARGET_SCRIPT="install_full.sh"
        ;;
    *)
        echo -e "${RED}[FAIL]${NC} Choix invalide : '$MODE_CHOICE' (attendu 1 ou 2)"
        exit 1
        ;;
esac

# Verifier que le script cible existe
if [ ! -f "$SCRIPT_DIR/$TARGET_SCRIPT" ]; then
    echo -e "${RED}[FAIL]${NC} Le fichier $TARGET_SCRIPT est introuvable dans $SCRIPT_DIR"
    echo -e "${YELLOW}[INFO]${NC} Verifie que tous les fichiers du repo sont bien presents."
    exit 1
fi

# Rendre executable
chmod +x "$SCRIPT_DIR/$TARGET_SCRIPT"

echo ""
echo -e "${GREEN}[ OK ]${NC} Lancement de $TARGET_SCRIPT..."
echo ""
sleep 1

# Lancer le script (le sudo a deja ete utilise pour install_all.sh)
bash "$SCRIPT_DIR/$TARGET_SCRIPT"
EXIT_CODE=$?

exit $EXIT_CODE
