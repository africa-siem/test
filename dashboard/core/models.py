"""
Modèles Django — Module 4 Dashboard SIEM Africa.

IMPORTANT : tous les modèles sont en `managed = False`.
Django NE crée JAMAIS, NE migre JAMAIS et NE modifie JAMAIS ces tables.
Elles appartiennent au Module 2 (base SQLite partagée avec l'agent Module 3).
Django se contente de lire et écrire dedans en respectant le schéma existant.
"""
from django.db import models


class Role(models.Model):
    """Rôle RBAC. Quatre rôles M2 : ADMIN, ANALYST, OPERATOR, VIEWER."""
    id = models.AutoField(primary_key=True)
    code = models.TextField(unique=True)
    name = models.TextField()
    description = models.TextField(null=True, blank=True)
    description_fr = models.TextField(null=True, blank=True)
    permissions = models.TextField()
    is_system = models.IntegerField(default=0)
    created_at = models.TextField(null=True, blank=True)
    updated_at = models.TextField(null=True, blank=True)

    class Meta:
        managed = False
        db_table = "roles"

    def __str__(self):
        return self.code


class User(models.Model):
    """Utilisateur du dashboard, mappé sur la table `users` du Module 2.
    L'auth n'utilise pas auth.User de Django : on vérifie le hash argon2id
    via le backend custom (voir auth.py)."""
    id = models.AutoField(primary_key=True)
    user_uuid = models.TextField(unique=True)
    email = models.TextField(unique=True)
    first_name = models.TextField(null=True, blank=True)
    last_name = models.TextField(null=True, blank=True)
    phone = models.TextField(null=True, blank=True)
    password_hash = models.TextField()
    password_changed_at = models.TextField(null=True, blank=True)
    must_change_pwd = models.IntegerField(default=1)
    is_active = models.IntegerField(default=1)
    is_locked = models.IntegerField(default=0)
    failed_login_count = models.IntegerField(default=0)
    locked_until = models.TextField(null=True, blank=True)
    role = models.ForeignKey(Role, on_delete=models.DO_NOTHING, db_column="role_id")
    organization = models.TextField(null=True, blank=True)
    department = models.TextField(null=True, blank=True)
    country_id = models.IntegerField(null=True, blank=True)
    language = models.TextField(default="fr")
    timezone = models.TextField(default="Africa/Douala")
    theme_preference = models.TextField(default="dark")
    last_login_at = models.TextField(null=True, blank=True)
    last_login_ip = models.TextField(null=True, blank=True)
    metadata = models.TextField(null=True, blank=True)
    created_at = models.TextField(null=True, blank=True)
    updated_at = models.TextField(null=True, blank=True)
    deleted_at = models.TextField(null=True, blank=True)

    class Meta:
        managed = False
        db_table = "users"

    def __str__(self):
        return self.email

    @property
    def full_name(self):
        parts = [p for p in [self.first_name, self.last_name] if p]
        return " ".join(parts) if parts else self.email

    @property
    def initials(self):
        a = (self.first_name or self.email or "?")[:1].upper()
        b = (self.last_name or "")[:1].upper()
        return (a + b) or "?"

    def permissions_dict(self):
        import json
        try:
            return json.loads(self.role.permissions)
        except (ValueError, TypeError, AttributeError):
            return {}

    def can(self, resource, action):
        return action in self.permissions_dict().get(resource, [])

    def has_resource(self, resource):
        return bool(self.permissions_dict().get(resource))

    @property
    def is_admin(self):
        return self.role.code == "ADMIN"

    @property
    def is_viewer(self):
        return self.role.code == "VIEWER"


class UserSession(models.Model):
    """Session applicative, mappée sur `user_sessions` du Module 2."""
    id = models.AutoField(primary_key=True)
    session_token = models.TextField(unique=True)
    user = models.ForeignKey(User, on_delete=models.DO_NOTHING, db_column="user_id")
    ip_address = models.TextField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    created_at = models.TextField(null=True, blank=True)
    expires_at = models.TextField()
    last_activity = models.TextField(null=True, blank=True)
    is_active = models.IntegerField(default=1)

    class Meta:
        managed = False
        db_table = "user_sessions"


class Setting(models.Model):
    """Paramètre runtime, mappé sur `settings` du Module 2."""
    id = models.AutoField(primary_key=True)
    key = models.TextField(unique=True)
    value = models.TextField(null=True, blank=True)
    value_type = models.TextField(default="text")
    enum_values = models.TextField(null=True, blank=True)
    category = models.TextField()
    description = models.TextField(null=True, blank=True)
    description_fr = models.TextField(null=True, blank=True)
    is_sensitive = models.IntegerField(default=0)
    is_editable = models.IntegerField(default=1)
    updated_by = models.IntegerField(null=True, blank=True)
    created_at = models.TextField(null=True, blank=True)
    updated_at = models.TextField(null=True, blank=True)
    deleted_at = models.TextField(null=True, blank=True)

    class Meta:
        managed = False
        db_table = "settings"

    def __str__(self):
        return self.key
