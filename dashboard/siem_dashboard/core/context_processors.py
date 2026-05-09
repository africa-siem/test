"""SIEM Africa - Context processors (variables globales dans templates)."""
from django.conf import settings as dj_settings


def dashboard_globals(request):
    return {
        "current_theme": getattr(request, "theme", "light"),
        "current_language": getattr(request, "LANGUAGE_CODE", "fr"),
        "DASHBOARD_NAME": "SIEM Africa",
        "DASHBOARD_VERSION": "1.0",
        "DEBUG": dj_settings.DEBUG,
    }
