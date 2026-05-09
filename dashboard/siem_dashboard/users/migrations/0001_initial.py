"""Migration initiale pour l'app users.

Le model User pointe sur la table 'users' creee par le M2 (managed=False).
Cette migration declare juste le model a Django sans creer/modifier de table.
"""
from django.db import migrations, models
from django.contrib.auth.models import PermissionsMixin


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("auth", "0012_alter_user_first_name_max_length"),
    ]

    operations = [
        migrations.CreateModel(
            name="User",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("password", models.CharField(max_length=128, verbose_name="password")),
                ("last_login", models.DateTimeField(blank=True, null=True, verbose_name="last login")),
                ("is_superuser", models.BooleanField(default=False)),
                ("email", models.EmailField(max_length=255, unique=True)),
                ("full_name", models.CharField(blank=True, max_length=255, null=True)),
                ("role", models.CharField(default="viewer", max_length=50)),
                ("is_active", models.BooleanField(default=True)),
                ("is_staff", models.BooleanField(default=False)),
                ("theme_preference", models.CharField(default="light", max_length=10)),
                ("language_preference", models.CharField(default="fr", max_length=5)),
                ("last_login_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("groups", models.ManyToManyField(blank=True, related_name="user_set", related_query_name="user", to="auth.group", verbose_name="groups")),
                ("user_permissions", models.ManyToManyField(blank=True, related_name="user_set", related_query_name="user", to="auth.permission", verbose_name="user permissions")),
            ],
            options={
                "db_table": "users",
                "managed": False,
                "ordering": ["email"],
            },
        ),
    ]
