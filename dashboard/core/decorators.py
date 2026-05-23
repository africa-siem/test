"""
Décorateurs de protection des vues — SIEM Africa Dashboard.
"""
from functools import wraps
from django.shortcuts import redirect

from .auth import get_current_user, password_expired


def login_required(view):
    """Exige une session valide. Redirige vers le login sinon.
    Gère aussi le changement de mot de passe forcé et l'expiration."""
    @wraps(view)
    def wrapper(request, *args, **kwargs):
        user = get_current_user(request)
        if not user:
            return redirect("login")

        # Changement de mot de passe forcé (1ère connexion ou expiration)
        path = request.path
        exempt = path.startswith("/profil/changer-mot-de-passe") or path.startswith("/deconnexion")
        if not exempt:
            if user.must_change_pwd == 1:
                return redirect("force_password_change")
            if password_expired(user):
                return redirect("force_password_change")

        request.current_user = user
        return view(request, *args, **kwargs)
    return wrapper


def permission_required(resource, action):
    """Exige une permission précise (ex : permission_required('users','create'))."""
    def decorator(view):
        @wraps(view)
        def wrapper(request, *args, **kwargs):
            user = get_current_user(request)
            if not user:
                return redirect("login")
            if not user.can(resource, action):
                return redirect("dashboard")  # accès refusé → retour dashboard
            request.current_user = user
            return view(request, *args, **kwargs)
        return wrapper
    return decorator
