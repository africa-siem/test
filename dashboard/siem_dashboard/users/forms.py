"""SIEM Africa - Forms login + profile."""
from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from .models import User


class EmailLoginForm(AuthenticationForm):
    """Login par email."""

    username = forms.EmailField(
        label="Email",
        widget=forms.EmailInput(attrs={
            "class": "form-control form-control-lg",
            "placeholder": "votre.email@entreprise.com",
            "autofocus": True,
            "autocomplete": "email",
        }),
    )
    password = forms.CharField(
        label="Mot de passe",
        widget=forms.PasswordInput(attrs={
            "class": "form-control form-control-lg",
            "placeholder": "••••••••",
            "autocomplete": "current-password",
        }),
    )

    error_messages = {
        "invalid_login": "Email ou mot de passe incorrect.",
        "inactive": "Ce compte est desactive.",
    }


class ProfileForm(forms.ModelForm):
    new_password = forms.CharField(
        label="Nouveau mot de passe",
        required=False,
        widget=forms.PasswordInput(attrs={
            "class": "form-control",
            "placeholder": "Laisser vide pour ne pas changer",
            "autocomplete": "new-password",
        }),
        help_text="Au moins 8 caracteres.",
    )
    confirm_password = forms.CharField(
        label="Confirmer le nouveau mot de passe",
        required=False,
        widget=forms.PasswordInput(attrs={
            "class": "form-control", "autocomplete": "new-password",
        }),
    )

    class Meta:
        model = User
        fields = ["full_name", "theme_preference", "language_preference"]
        widgets = {
            "full_name": forms.TextInput(attrs={"class": "form-control"}),
            "theme_preference": forms.Select(attrs={"class": "form-select"}),
            "language_preference": forms.Select(attrs={"class": "form-select"}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["theme_preference"].choices = [
            ("light", "Clair"), ("dark", "Sombre"),
        ]
        self.fields["language_preference"].choices = [
            ("fr", "Francais"), ("en", "English"),
        ]

    def clean(self):
        cleaned = super().clean()
        new_pwd = cleaned.get("new_password")
        confirm = cleaned.get("confirm_password")

        if new_pwd or confirm:
            if new_pwd != confirm:
                raise ValidationError("Les deux mots de passe ne correspondent pas.")
            try:
                validate_password(new_pwd, self.instance)
            except ValidationError as exc:
                self.add_error("new_password", exc)

        return cleaned
