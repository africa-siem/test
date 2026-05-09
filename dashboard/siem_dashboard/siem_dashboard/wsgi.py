"""WSGI - point d'entree pour Gunicorn."""
import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "siem_dashboard.settings")
application = get_wsgi_application()
