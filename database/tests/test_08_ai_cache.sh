#!/usr/bin/env bash
# ==============================================================================
# Test 08 : Enrichissement IA (table ai_signature_cache + champs alerts ai_*)
# ==============================================================================

DB_PATH="${DB_PATH:-/var/lib/siem-africa/siem.db}"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [ "$actual" = "$expected" ]; then
        echo -e "  ${GREEN}✓${NC} $desc"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗${NC} $desc (attendu: '$expected', obtenu: '$actual')"
        FAIL=$((FAIL + 1))
    fi
}

assert_ge() {
    local desc="$1" expected="$2" actual="$3"
    if [ "$actual" -ge "$expected" ] 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $desc ($actual ≥ $expected)"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗${NC} $desc (attendu: ≥$expected, obtenu: '$actual')"
        FAIL=$((FAIL + 1))
    fi
}

run_sql() {
    sqlite3 "$DB_PATH" "$1" 2>/dev/null
}

echo ""
echo "═══════════════════════════════════════════════"
echo "  Test 08 : Enrichissement IA (cache + alerts)"
echo "═══════════════════════════════════════════════"

# ----------------------------------------------------------------------------
# A. Table ai_signature_cache existe et a la bonne structure
# ----------------------------------------------------------------------------
echo ""
echo "A. Table ai_signature_cache"

EXISTS=$(run_sql "SELECT name FROM sqlite_master WHERE type='table' AND name='ai_signature_cache';")
assert_eq "Table existe" "ai_signature_cache" "$EXISTS"

# Champs critiques
for col in signature_hash source rule_id ai_description ai_remediation ai_severity model_used used_count; do
    FOUND=$(run_sql "SELECT name FROM pragma_table_info('ai_signature_cache') WHERE name='$col';")
    assert_eq "Champ '$col' présent" "$col" "$FOUND"
done

# Index sur signature_hash (UNIQUE)
HASH_UNIQUE=$(run_sql "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='ai_signature_cache' AND sql LIKE '%signature_hash%' LIMIT 1;")
[ -n "$HASH_UNIQUE" ] && assert_eq "Index sur signature_hash existe" "yes" "yes" || assert_eq "Index sur signature_hash existe" "yes" "no"

# ----------------------------------------------------------------------------
# B. Champs ai_* sur la table alerts
# ----------------------------------------------------------------------------
echo ""
echo "B. Champs ai_* sur alerts"

for col in ai_status ai_description ai_remediation ai_severity ai_model_used ai_processed_at ai_cache_id; do
    FOUND=$(run_sql "SELECT name FROM pragma_table_info('alerts') WHERE name='$col';")
    assert_eq "alerts.$col présent" "$col" "$FOUND"
done

# Default value de ai_status
DEFAULT_STATUS=$(run_sql "SELECT \"dflt_value\" FROM pragma_table_info('alerts') WHERE name='ai_status';")
assert_eq "alerts.ai_status default = 'not_required'" "'not_required'" "$DEFAULT_STATUS"

# ----------------------------------------------------------------------------
# C. Triggers
# ----------------------------------------------------------------------------
echo ""
echo "C. Triggers IA"

for trg in trg_aicache_updated_at trg_aicache_increment_usage; do
    FOUND=$(run_sql "SELECT name FROM sqlite_master WHERE type='trigger' AND name='$trg';")
    assert_eq "Trigger '$trg' existe" "$trg" "$FOUND"
done

# ----------------------------------------------------------------------------
# D. Settings IA / UI - bonnes valeurs par défaut
# ----------------------------------------------------------------------------
echo ""
echo "D. Settings - valeurs par défaut"

# Modèle IA = qwen2.5:3b
MODEL=$(run_sql "SELECT value FROM settings WHERE key='ai_default_model';")
assert_eq "ai_default_model = qwen2.5:3b" "qwen2.5:3b" "$MODEL"

# Thème = light
THEME=$(run_sql "SELECT value FROM settings WHERE key='theme_default';")
assert_eq "theme_default = light" "light" "$THEME"

# Langue = fr
LANG=$(run_sql "SELECT value FROM settings WHERE key='default_language';")
assert_eq "default_language = fr" "fr" "$LANG"

# Async activé
ASYNC=$(run_sql "SELECT value FROM settings WHERE key='ai_async_enabled';")
assert_eq "ai_async_enabled = true" "true" "$ASYNC"

# Enrichissement signatures inconnues activé
ENRICH=$(run_sql "SELECT value FROM settings WHERE key='ai_enrich_unknown';")
assert_eq "ai_enrich_unknown = true" "true" "$ENRICH"

# Healthcheck Ollama
HC=$(run_sql "SELECT value FROM settings WHERE key='ai_healthcheck_on_boot';")
assert_eq "ai_healthcheck_on_boot = true" "true" "$HC"

# Toggle langue autorisé
LANGTGL=$(run_sql "SELECT value FROM settings WHERE key='allow_language_toggle';")
assert_eq "allow_language_toggle = true" "true" "$LANGTGL"

# Modèles disponibles contiennent qwen2.5:3b ET llama3.2:3b
MODELS=$(run_sql "SELECT value FROM settings WHERE key='ai_models_available';")
echo "$MODELS" | grep -q "qwen2.5:3b" && assert_eq "ai_models_available contient qwen2.5:3b" "yes" "yes" || assert_eq "ai_models_available contient qwen2.5:3b" "yes" "no"
echo "$MODELS" | grep -q "llama3.2:3b" && assert_eq "ai_models_available contient llama3.2:3b" "yes" "yes" || assert_eq "ai_models_available contient llama3.2:3b" "yes" "no"

# ----------------------------------------------------------------------------
# E. Test fonctionnel : insertion/lecture du cache
# ----------------------------------------------------------------------------
echo ""
echo "E. Test fonctionnel cache"

# Insérer une fausse analyse IA
run_sql "INSERT INTO ai_signature_cache (signature_hash, source, rule_id, raw_message, ai_description, ai_remediation, ai_severity, model_used)
         VALUES ('test_hash_001', 'wazuh', '99999', 'TEST', 'Description test', '[\"Reco 1\",\"Reco 2\"]', 'HIGH', 'qwen2.5:3b');"

ROWS=$(run_sql "SELECT COUNT(*) FROM ai_signature_cache WHERE signature_hash='test_hash_001';")
assert_eq "Insertion cache OK" "1" "$ROWS"

# Test contrainte UNIQUE sur signature_hash
DUP_OUTPUT=$(sqlite3 "$DB_PATH" "INSERT INTO ai_signature_cache (signature_hash, source, rule_id, ai_description, ai_remediation, ai_severity, model_used)
         VALUES ('test_hash_001', 'wazuh', '99999', 'dup', '[]', 'LOW', 'qwen2.5:3b');" 2>&1)
if echo "$DUP_OUTPUT" | grep -qi "unique\|constraint"; then
    assert_eq "Contrainte UNIQUE signature_hash" "ok" "ok"
else
    assert_eq "Contrainte UNIQUE signature_hash" "ok" "fail"
fi

# Cleanup
run_sql "DELETE FROM ai_signature_cache WHERE signature_hash='test_hash_001';"

# ----------------------------------------------------------------------------
# Récap
# ----------------------------------------------------------------------------
echo ""
echo "═══════════════════════════════════════════════"
echo "  Résultat : $PASS passés, $FAIL échoués"
exit $FAIL
