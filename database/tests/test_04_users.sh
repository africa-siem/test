#!/bin/bash
# Test 04 : Utilisateurs et rôles
DB_PATH="${DB_PATH:-/var/lib/siem-africa/siem.db}"
PASS=0; FAIL=0

t() {
    if [ "$3" = "$2" ]; then echo "  ✓ $1"; PASS=$((PASS+1));
    else echo "  ✗ $1 : got '$3', expected '$2'"; FAIL=$((FAIL+1)); fi
}

echo "▶ Test 04 : Utilisateurs et RBAC"

# 4 rôles
N=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM roles")
t "4 rôles RBAC" "4" "$N"

# Chaque rôle existe
for role in ADMIN ANALYST OPERATOR VIEWER; do
    N=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM roles WHERE code='$role'")
    t "Rôle $role" "1" "$N"
done

# Permissions JSON valide pour ADMIN
P=$(sqlite3 "$DB_PATH" "SELECT json_valid(permissions) FROM roles WHERE code='ADMIN'")
t "Permissions ADMIN sont JSON valide" "1" "$P"

# Au moins 1 admin créé
N=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM users WHERE role_id = (SELECT id FROM roles WHERE code='ADMIN')")
if [ "$N" -ge 1 ]; then
    echo "  ✓ $N admin(s) créé(s)"
    PASS=$((PASS+1))
else
    echo "  ✗ Aucun admin"
    FAIL=$((FAIL+1))
fi

# Vérifier que l'admin a un hash argon2id
HASH=$(sqlite3 "$DB_PATH" "SELECT password_hash FROM users WHERE role_id = (SELECT id FROM roles WHERE code='ADMIN') LIMIT 1")
if [[ "$HASH" == \$argon2id\$* ]]; then
    echo "  ✓ Hash mot de passe : argon2id"
    PASS=$((PASS+1))
else
    echo "  ✗ Hash format invalide : ${HASH:0:30}..."
    FAIL=$((FAIL+1))
fi

# Admin doit changer son mot de passe au 1er login
MUST=$(sqlite3 "$DB_PATH" "SELECT must_change_pwd FROM users WHERE role_id = (SELECT id FROM roles WHERE code='ADMIN') LIMIT 1")
t "must_change_pwd = 1" "1" "$MUST"

# Admin actif et non verrouillé
ACT=$(sqlite3 "$DB_PATH" "SELECT is_active FROM users WHERE role_id = (SELECT id FROM roles WHERE code='ADMIN') LIMIT 1")
LOCK=$(sqlite3 "$DB_PATH" "SELECT is_locked FROM users WHERE role_id = (SELECT id FROM roles WHERE code='ADMIN') LIMIT 1")
t "Admin actif" "1" "$ACT"
t "Admin pas verrouillé" "0" "$LOCK"

echo ""
echo "  Résultat : $PASS passés, $FAIL échoués"
exit $FAIL
