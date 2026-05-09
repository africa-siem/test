"""Migration initiale pour l'app core.

Tous les models pointent sur des tables creees par le M2 (managed=False).
Cette migration ne cree aucune table.
"""
from django.db import migrations


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("users", "0001_initial"),
    ]

    operations = []
