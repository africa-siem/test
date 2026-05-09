"""URLs admin_logs."""
from django.urls import path
from . import views

app_name = "admin_logs"

urlpatterns = [
    path("", views.home, name="home"),
    path("api/agent-log-tail/", views.api_agent_log_tail, name="api_agent_log_tail"),
]
