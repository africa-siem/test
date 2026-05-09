"""URLs KPI."""
from django.urls import path
from . import views

app_name = "kpi"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    # API endpoints pour ApexCharts
    path("api/alerts-by-severity/", views.api_alerts_by_severity, name="api_alerts_by_severity"),
    path("api/alerts-timeline/",    views.api_alerts_timeline,    name="api_alerts_timeline"),
    path("api/alerts-by-status/",   views.api_alerts_by_status,   name="api_alerts_by_status"),
    path("api/top-attackers/",      views.api_top_attackers,      name="api_top_attackers"),
    path("api/top-signatures/",     views.api_top_signatures,     name="api_top_signatures"),
    path("api/ai-efficiency/",      views.api_ai_efficiency,      name="api_ai_efficiency"),
]
