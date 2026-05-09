"""URLs Health."""
from django.urls import path
from . import views

app_name = "health"

urlpatterns = [
    path("", views.status, name="status"),
]
