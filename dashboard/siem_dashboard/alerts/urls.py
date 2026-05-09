"""URLs de l'app alerts."""
from django.urls import path

from . import views


app_name = "alerts"

urlpatterns = [
    path("", views.list_view, name="list"),
    path("<int:alert_id>/", views.detail_view, name="detail"),
    path("<int:alert_id>/re-analyze/", views.re_analyze_view, name="re_analyze"),
    path("<int:alert_id>/status/", views.update_status_view, name="update_status"),
]
