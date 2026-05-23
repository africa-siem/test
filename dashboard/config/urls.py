"""URLs — Module 4 Dashboard SIEM Africa."""
from django.urls import path
from core import views

urlpatterns = [
    path("", views.login_view, name="login"),
    path("connexion/", views.login_view, name="login_alt"),
    path("deconnexion/", views.logout_view, name="logout"),
    path("changer-mot-de-passe/", views.force_password_change, name="force_password_change"),
    path("profil/", views.profile_view, name="profile"),
    path("profil/changer-mot-de-passe/", views.change_password_view, name="change_password"),
    path("tableau-de-bord/", views.dashboard_view, name="dashboard"),

    path("alertes/", views.alerts_list_view, name="alerts_list"),
    path("alertes/<int:alert_id>/", views.alert_detail_view, name="alert_detail"),
    path("alertes/<int:alert_id>/chat/", views.alert_chat_api, name="alert_chat"),

    path("incidents/", views.incidents_list_view, name="incidents_list"),
    path("incidents/<int:incident_id>/", views.incident_detail_view, name="incident_detail"),
    path("incidents/<int:incident_id>/chat/", views.incident_chat_api, name="incident_chat"),

    path("ips-bloquees/", views.blocked_ips_view, name="blocked_ips"),
    path("signatures/", views.signatures_view, name="signatures"),
    path("utilisateurs/", views.users_view, name="users"),
    path("assistant-ia/", views.ai_assistant_view, name="ai_assistant"),
    path("assistant-ia/chat/", views.ai_assistant_chat_api, name="ai_assistant_chat"),

    # Lot 5
    path("parametres/", views.settings_view, name="settings"),
    path("journal-audit/", views.audit_log_view, name="audit_log"),
    path("rapports/", views.reports_view, name="reports"),
    path("rapports/generer/", views.report_generate_view, name="report_generate"),
    path("rapports/<int:report_id>/telecharger/", views.report_download_view, name="report_download"),
]
