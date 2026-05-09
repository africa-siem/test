"""URLs settings."""
from django.urls import path
from . import views

app_name = "settings_app"

urlpatterns = [
    path("", views.home, name="home"),
    path("test-smtp/", views.test_smtp, name="test_smtp"),
    path("test-model/", views.test_model, name="test_model"),
]
