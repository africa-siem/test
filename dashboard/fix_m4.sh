#!/usr/bin/env bash
# fix_m4.sh — Diagnostique la VM réelle et corrige les tests M4 automatiquement.
# A lancer sur la VM :  sudo bash fix_m4.sh
set -uo pipefail

APP_DIR="/opt/siem-africa-dashboard"
ENV_FILE="/etc/siem-africa/dashboard.env"
TESTS_DIR="$HOME/test/dashboard/tests"
PY="$APP_DIR/venv/bin/python"
G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; N='\033[0m'

[ -d "$TESTS_DIR" ] || TESTS_DIR="/root/test/dashboard/tests"
echo -e "${G}=== fix_m4 : diagnostic de la VM ===${N}"

# --- 1. Détecter le vrai champ de login (username vs email) ------------------
LOGIN_TPL=$(find "$APP_DIR/templates" -name "login.html" 2>/dev/null | head -1)
LOGIN_FIELD="username"
if [ -n "$LOGIN_TPL" ]; then
    if grep -qE "name=[\"']email[\"']" "$LOGIN_TPL" && ! grep -qE "name=[\"']username[\"']" "$LOGIN_TPL"; then
        LOGIN_FIELD="email"
    fi
    echo -e "${G}[+]${NC} Template login : $LOGIN_TPL"
fi
echo -e "${G}[+]${NC} Champ de login détecté : ${Y}$LOGIN_FIELD${N}"

# --- 2. Découvrir comment créer un user (introspection du modèle réel) -------
echo -e "${G}[+]${NC} Introspection du modèle User..."
INTRO=$(cd "$APP_DIR" && sudo -u siem-dashboard bash -c "
set -a; . '$ENV_FILE' 2>/dev/null; set +a
'$PY' manage.py shell <<'PYEOF' 2>&1
from users.models import User
m = User._meta
fields = [f.name for f in m.get_fields()]
print('FIELDS=' + ','.join(fields))
print('HAS_CREATE_USER=' + str(hasattr(User.objects, 'create_user')))
print('USERNAME_FIELD=' + getattr(User, 'USERNAME_FIELD', 'NONE'))
PYEOF
")
echo "$INTRO" | grep -E "FIELDS=|HAS_CREATE_USER=|USERNAME_FIELD=" || { echo -e "${R}[x] Introspection impossible :${N}"; echo "$INTRO" | tail -15; exit 1; }

HAS_CU=$(echo "$INTRO" | grep "HAS_CREATE_USER=" | cut -d= -f2)
FIELDS=$(echo "$INTRO" | grep "FIELDS=" | cut -d= -f2)
echo -e "${G}[+]${NC} create_user disponible : ${Y}$HAS_CU${N}"

# --- 3. Construire le bloc de création adapté --------------------------------
NEWBLOCK=$(mktemp)
has() { echo ",$FIELDS," | grep -q ",$1,"; }

if [ "$HAS_CU" = "True" ]; then
    # Manager standard : on tente create_user avec les champs qui existent
    {
      echo "from users.models import User"
      echo "User.objects.filter(email='\$TEST_EMAIL').delete()"
      ARGS="email='\$TEST_EMAIL', password='\$TEST_PASSWORD'"
      has full_name  && ARGS="$ARGS, full_name='Test Auth'"
      has role       && ARGS="$ARGS, role='admin'"
      has is_staff   && ARGS="$ARGS, is_staff=True"
      has is_superuser && ARGS="$ARGS, is_superuser=True"
      has must_change_pwd && echo "u = User.objects.create_user($ARGS)" || echo "User.objects.create_user($ARGS)"
      has must_change_pwd && echo "u.must_change_pwd = 0; u.save()"
    } > "$NEWBLOCK"
else
    # Pas de manager : create() direct avec hash argon2
    {
      echo "import uuid"
      echo "from datetime import datetime"
      echo "from users.models import User"
      # localiser hash_password
      echo "try:"
      echo "    from core.auth import hash_password"
      echo "except Exception:"
      echo "    from argon2 import PasswordHasher"
      echo "    hash_password = lambda p: PasswordHasher().hash(p)"
      echo "kw = dict(email='\$TEST_EMAIL', first_name='Test', last_name='Auth')"
      has user_uuid     && echo "kw['user_uuid'] = str(uuid.uuid4())"
      has password_hash && echo "kw['password_hash'] = hash_password('\$TEST_PASSWORD')"
      has is_active     && echo "kw['is_active'] = 1"
      has is_locked     && echo "kw['is_locked'] = 0"
      has must_change_pwd && echo "kw['must_change_pwd'] = 0"
      has language      && echo "kw['language'] = 'fr'"
      has created_at    && echo "kw['created_at'] = datetime.now().isoformat()"
      # role FK
      if has role; then
        echo "from users.models import User as _U"
        echo "RoleModel = _U._meta.get_field('role').related_model"
        echo "r = RoleModel.objects.filter(code__iexact='ADMIN').first() or RoleModel.objects.create(code='ADMIN', name='Administrateur', permissions='*')"
        echo "kw['role'] = r"
      fi
      echo "User.objects.filter(email='\$TEST_EMAIL').delete()"
      echo "User.objects.create(**kw)"
    } > "$NEWBLOCK"
fi

echo -e "${G}[+]${NC} Bloc de création généré :"
sed 's/^/      /' "$NEWBLOCK"

# --- 4. Patcher les 3 scripts ------------------------------------------------
for f in test_03_auth.sh test_04_settings_no500.sh test_05_test_smtp.sh; do
    FILE="$TESTS_DIR/$f"
    [ -f "$FILE" ] || { echo -e "${Y}[!]${NC} $f absent"; continue; }
    cp "$FILE" "$FILE.bak.$(date +%s)"
    python3 - "$FILE" "$NEWBLOCK" "$LOGIN_FIELD" <<'PYEOF'
import re, sys
path, blockfile, login_field = sys.argv[1], sys.argv[2], sys.argv[3]
src = open(path, encoding='utf-8').read()
block = open(blockfile, encoding='utf-8').read().rstrip('\n')

# Remplacer le bloc de création (de "from users.models" jusqu'à create_user(...))
pat = re.compile(
    r"from users\.models import User\s*\n"
    r"User\.objects\.filter\(email='\$TEST_EMAIL'\)\.delete\(\)\s*\n"
    r"User\.objects\.create_user\([^\n]*\)\s*\n",
    re.MULTILINE)
src, n = pat.subn(block + "\n", src)

# Corriger le champ POST du login si besoin (username -> email)
if login_field == "email":
    src = src.replace('--data-urlencode "username=$TEST_EMAIL"',
                      '--data-urlencode "email=$TEST_EMAIL"')

open(path, 'w', encoding='utf-8').write(src)
print(f"   {path} : {n} bloc(s) remplacé(s), login_field={login_field}")
PYEOF
    echo -e "${G}[+]${NC} $f patché (.bak créé)"
done
rm -f "$NEWBLOCK"
echo ""
echo -e "${G}=== Terminé. Relance :  cd $TESTS_DIR && sudo bash run_all_tests.sh ===${N}"
