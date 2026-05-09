"""SIEM Africa - URLs racine."""
from django.contrib import admin
from django.urls import include, path
from django.views.generic import RedirectView
from django.views.i18n import set_language


urlpatterns = [
    path("django-admin/", admin.site.urls),

    # Page d'accueil = redirige vers les alertes
    path("", RedirectView.as_view(url="/alerts/", permanent=False), name="home"),

    # i18n
    path("set-language/", set_language, name="set_language"),

    # Apps
    path("", include("users.urls")),
    path("alerts/", include("alerts.urls")),
    path("kpi/", include("kpi.urls")),
    path("health/", include("health.urls")),
    path("settings/", include("settings_app.urls")),
    path("about/", include("about.urls")),
    path("admin-logs/", include("admin_logs.urls")),
]


handler404 = "core.views.error_404"
handler500 = "core.views.error_500"
handler403 = "core.views.error_403"
