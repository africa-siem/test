"""SIEM Africa - Vues auth + profil."""
from django.contrib import messages
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView, LogoutView
from django.http import HttpResponseRedirect
from django.shortcuts import render, redirect
from django.utils import timezone

from .forms import EmailLoginForm, ProfileForm


# ============================================================================
class EmailLoginView(LoginView):
    """Login par email."""

    form_class = EmailLoginForm
    template_name = "users/login.html"
    redirect_authenticated_user = True

    def form_valid(self, form):
        user = form.get_user()
        login(self.request, user)

        try:
            user.last_login_at = timezone.now()
            user.save(update_fields=["last_login_at"])
        except Exception:  # noqa: BLE001
            pass

        try:
            from core.models import AuditLog
            AuditLog.objects.create(
                user=user, action="user_login", resource_type="user",
                resource_id=str(user.id), level="INFO",
                ip_address=self.request.META.get("REMOTE_ADDR", ""),
            )
        except Exception:  # noqa: BLE001
            pass

        messages.success(self.request, f"Bienvenue {user.get_short_name()} !")
        return HttpResponseRedirect(self.get_success_url())

    def form_invalid(self, form):
        messages.error(self.request, "Email ou mot de passe invalide.")
        return super().form_invalid(form)


# ============================================================================
class CustomLogoutView(LogoutView):
    next_page = "users:login"

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            try:
                from core.models import AuditLog
                AuditLog.objects.create(
                    user=request.user, action="user_logout",
                    resource_type="user", resource_id=str(request.user.id),
                    level="INFO",
                )
            except Exception:  # noqa: BLE001
                pass
        return super().dispatch(request, *args, **kwargs)


# ============================================================================
@login_required
def profile_view(request):
    """Mon profil - editer theme, langue, password."""
    if request.method == "POST":
        form = ProfileForm(request.POST, instance=request.user)
        if form.is_valid():
            user = form.save(commit=False)
            new_pwd = form.cleaned_data.get("new_password")
            if new_pwd:
                user.set_password(new_pwd)
            user.save()

            if new_pwd:
                authenticated_user = authenticate(
                    request, username=user.email, password=new_pwd
                )
                if authenticated_user:
                    login(request, authenticated_user)

            messages.success(request, "Profil mis a jour.")
            return redirect("users:profile")
    else:
        form = ProfileForm(instance=request.user)

    return render(request, "users/profile.html", {"form": form})
