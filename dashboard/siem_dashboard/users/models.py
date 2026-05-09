"""SIEM Africa - User model (auth par email).

Pointe sur la table 'users' creee par le Module 2.
"""
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Un email est requis")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        if password:
            user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("role", "admin")
        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """Utilisateur du dashboard - utilise la table users du M2."""

    email = models.EmailField(unique=True, max_length=255)
    full_name = models.CharField(max_length=255, blank=True, null=True)
    role = models.CharField(max_length=50, default="viewer")

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    theme_preference = models.CharField(max_length=10, default="light")
    language_preference = models.CharField(max_length=5, default="fr")

    last_login_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["full_name"]

    class Meta:
        db_table = "users"
        managed = False
        ordering = ["email"]

    def __str__(self):
        return self.email

    def get_full_name(self):
        return self.full_name or self.email

    def get_short_name(self):
        return (self.full_name or self.email).split()[0]

    @property
    def is_admin(self):
        return self.role == "admin" or self.is_superuser

    @property
    def is_analyst(self):
        return self.role in ("admin", "analyst") or self.is_superuser
