#!/bin/bash
# Test 06 : Settings (NOUVEAU - multi-modèles IA + theme toggle)
DB_PATH="${DB_PATH:-/var/lib/siem-africa/siem.db}"
PASS=0; FAIL=0

t() {
    if [ "$3" = "$2" ]; then echo "  ✓ $1"; PASS=$((PASS+1));
    else echo "  ✗ $1 : got '$3', expected '$2'"; FAIL=$((FAIL+1)); fi
}

echo "▶ Test 06 : Settings dynamiques"

# Settings minimum
N=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM settings")
if [ "$N" -ge 40 ]; then
    echo "  ✓ Au moins 40 settings : $N"
    PASS=$((PASS+1))
else
    echo "  ✗ Seulement $N settings (attendu ≥ 40)"
    FAIL=$((FAIL+1))
fi

# Settings IA critiques
echo ""
echo "  Settings IA :"

AI_MODELS=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='ai_models_available'")
if [[ "$AI_MODELS" == *"llama"* ]] && [[ "$AI_MODELS" == *"qwen"* ]]; then
    echo "  ✓ Multi-modèles : $AI_MODELS"
    PASS=$((PASS+1))
else
    echo "  ✗ ai_models_available : $AI_MODELS"
    FAIL=$((FAIL+1))
fi

AI_DEFAULT=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='ai_default_model'")
echo "  ℹ Modèle par défaut : $AI_DEFAULT"

AI_PROV=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='ai_provider'")
t "Provider IA = ollama" "ollama" "$AI_PROV"

# Settings UI
echo ""
echo "  Settings UI :"

THEME=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='theme_default'")
echo "  ℹ Thème par défaut : $THEME"

TOGGLE=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='allow_theme_toggle'")
t "Toggle dark/light activé" "true" "$TOGGLE"

LANG=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='default_language'")
t "Langue par défaut = fr" "fr" "$LANG"

# Settings SMTP
echo ""
echo "  Settings SMTP :"

SMTP_EN=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='smtp_enabled'")
t "SMTP activé" "true" "$SMTP_EN"

SMTP_SEV=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='smtp_min_severity'")
echo "  ℹ Sévérité min email : $SMTP_SEV"

# Settings retention
echo ""
echo "  Settings rétention :"

RET_AL=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='retention_alerts_days'")
echo "  ℹ Rétention alertes : ${RET_AL} jours"

RET_AUDIT=$(sqlite3 "$DB_PATH" "SELECT value FROM settings WHERE key='retention_audit_log_days'")
echo "  ℹ Rétention audit_log : ${RET_AUDIT} jours (1 an = conformité)"

# Filtres FP
echo ""
echo "  Filtres FP :"

N_FILT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM alert_filters WHERE is_active=1")
t "8 filtres FP actifs" "8" "$N_FILT"

# Catégories de settings
echo ""
echo "  Catégories de settings :"
sqlite3 "$DB_PATH" "SELECT '  - ' || category || ' (' || COUNT(*) || ')' FROM settings GROUP BY category ORDER BY category"

echo ""
echo "  Résultat : $PASS passés, $FAIL échoués"
exit $FAIL
