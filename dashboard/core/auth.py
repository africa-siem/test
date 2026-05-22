"""
Authentification custom — SIEM Africa Dashboard.

On n'utilise pas le système auth.User de Django (qui exigerait ses propres
tables). On vérifie directement la table `users` du Module 2 avec le hash
argon2id, et on applique la politique de sécurité (tentatives, blocage,
expiration du mot de passe).

La session Django stocke uniquement l'id utilisateur ; le helper
`get_current_user(request)` recharge l'objet User à chaque requête.
"""
from datetime import datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

from .models import User

# --- Politique de sécurité (valeurs par défaut, surchargeable via settings) --
MAX_FAILED_ATTEMPTS = 5        # tentatives avant blocage
LOCKOUT_MINUTES = 30           # durée du blocage
PASSWORD_EXPIRY_DAYS = 90      # expiration du mot de passe
SESSION_HOURS = 2              # durée de session (inactivité)
MIN_PASSWORD_LENGTH = 12       # longueur minimale

_hasher = PasswordHasher()

# Format SQLite des timestamps : "YYYY-MM-DD HH:MM:SS"
SQLITE_FMT = "%Y-%m-%d %H:%M:%S"


def now_sqlite():
    return datetime.now().strftime(SQLITE_FMT)


def sqlite_future(minutes=0, hours=0, days=0):
    return (datetime.now() + timedelta(minutes=minutes, hours=hours, days=days)).strftime(SQLITE_FMT)


def _parse(ts):
    """Parse un timestamp SQLite (tolérant aux variantes ISO)."""
    if not ts:
        return None
    ts = ts.strip().replace("T", " ").rstrip("Z")
    ts = ts.split(".")[0]  # retire les microsecondes éventuelles
    try:
        return datetime.strptime(ts, SQLITE_FMT)
    except ValueError:
        return None


def hash_password(plain):
    """Génère un hash argon2id."""
    return _hasher.hash(plain)


def verify_password(plain, hashed):
    """Vérifie un mot de passe contre un hash argon2id."""
    try:
        return _hasher.verify(hashed, plain)
    except (VerifyMismatchError, InvalidHashError, Exception):
        return False


class AuthResult:
    """Résultat d'une tentative d'authentification."""
    def __init__(self, ok, user=None, error=None, code=None):
        self.ok = ok
        self.user = user
        self.error = error      # message lisible (FR)
        self.code = code        # code machine : 'bad_credentials', 'locked', etc.


def authenticate(email, password):
    """Tente d'authentifier un utilisateur par email + mot de passe.

    Applique la politique : compte actif, non verrouillé, incrément du
    compteur d'échecs, blocage automatique au-delà du seuil.
    """
    email = (email or "").strip().lower()
    try:
        user = User.objects.select_related("role").get(email=email)
    except User.DoesNotExist:
        return AuthResult(False, error="Email ou mot de passe incorrect.", code="bad_credentials")

    # Compte désactivé
    if not user.is_active:
        return AuthResult(False, error="Ce compte est désactivé. Contactez un administrateur.", code="inactive")

    # Compte verrouillé : vérifier si le blocage est encore actif
    if user.is_locked:
        locked_until = _parse(user.locked_until)
        if locked_until and datetime.now() < locked_until:
            reste = int((locked_until - datetime.now()).total_seconds() // 60) + 1
            return AuthResult(
                False,
                error=f"Compte verrouillé. Réessayez dans {reste} minute(s).",
                code="locked",
            )
        # Le blocage a expiré : on déverrouille
        user.is_locked = 0
        user.failed_login_count = 0
        user.locked_until = None
        user.save(update_fields=["is_locked", "failed_login_count", "locked_until"])

    # Vérifier le mot de passe
    if not verify_password(password, user.password_hash):
        user.failed_login_count = (user.failed_login_count or 0) + 1
        fields = ["failed_login_count"]
        if user.failed_login_count >= MAX_FAILED_ATTEMPTS:
            user.is_locked = 1
            user.locked_until = sqlite_future(minutes=LOCKOUT_MINUTES)
            fields += ["is_locked", "locked_until"]
            user.save(update_fields=fields)
            return AuthResult(
                False,
                error=f"Trop de tentatives. Compte verrouillé {LOCKOUT_MINUTES} minutes.",
                code="locked",
            )
        user.save(update_fields=fields)
        restant = MAX_FAILED_ATTEMPTS - user.failed_login_count
        return AuthResult(
            False,
            error=f"Email ou mot de passe incorrect. {restant} tentative(s) restante(s).",
            code="bad_credentials",
        )

    # Succès : réinitialiser le compteur et tracer la connexion
    user.failed_login_count = 0
    user.is_locked = 0
    user.locked_until = None
    user.last_login_at = now_sqlite()
    user.save(update_fields=["failed_login_count", "is_locked", "locked_until", "last_login_at"])

    return AuthResult(True, user=user)


def password_expired(user):
    """Vrai si le mot de passe a dépassé sa durée de validité."""
    changed = _parse(user.password_changed_at)
    if not changed:
        return False
    return datetime.now() > changed + timedelta(days=PASSWORD_EXPIRY_DAYS)


def validate_password_strength(pwd):
    """Valide la complexité d'un mot de passe. Retourne une liste d'erreurs (FR).
    Liste vide = mot de passe valide."""
    errors = []
    if len(pwd) < MIN_PASSWORD_LENGTH:
        errors.append(f"Au moins {MIN_PASSWORD_LENGTH} caractères.")
    if not any(c.isupper() for c in pwd):
        errors.append("Au moins une majuscule.")
    if not any(c.islower() for c in pwd):
        errors.append("Au moins une minuscule.")
    if not any(c.isdigit() for c in pwd):
        errors.append("Au moins un chiffre.")
    if not any(not c.isalnum() for c in pwd):
        errors.append("Au moins un caractère spécial.")
    return errors


# --- Helpers de session -------------------------------------------------------
SESSION_KEY = "siem_user_id"


def login_session(request, user):
    """Enregistre l'utilisateur dans la session Django."""
    request.session[SESSION_KEY] = user.id
    request.session.set_expiry(SESSION_HOURS * 3600)


def logout_session(request):
    request.session.flush()


def get_current_user(request):
    """Recharge l'utilisateur courant depuis la session. None si non connecté."""
    uid = request.session.get(SESSION_KEY)
    if not uid:
        return None
    try:
        return User.objects.select_related("role").get(id=uid, is_active=1)
    except User.DoesNotExist:
        return None
