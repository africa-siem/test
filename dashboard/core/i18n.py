"""
Internationalisation légère FR/EN — SIEM Africa Dashboard.

On n'utilise pas le système gettext de Django (lourd : fichiers .po, compilation)
pour rester simple et sans dépendance externe. Un dictionnaire Python suffit
pour le périmètre du dashboard. La langue vient de la préférence utilisateur
(users.language) ou du paramètre ?lang= / de la session.
"""

TRANSLATIONS = {
    # --- Général ---
    "app_name": {"fr": "SIEM Africa", "en": "SIEM Africa"},
    "dashboard": {"fr": "Tableau de bord", "en": "Dashboard"},
    "login": {"fr": "Connexion", "en": "Login"},
    "logout": {"fr": "Déconnexion", "en": "Logout"},
    "email": {"fr": "Adresse e-mail", "en": "Email address"},
    "password": {"fr": "Mot de passe", "en": "Password"},
    "sign_in": {"fr": "Se connecter", "en": "Sign in"},
    "remember_me": {"fr": "Se souvenir de moi", "en": "Remember me"},
    "welcome": {"fr": "Bienvenue", "en": "Welcome"},
    "save": {"fr": "Enregistrer", "en": "Save"},
    "cancel": {"fr": "Annuler", "en": "Cancel"},
    "loading": {"fr": "Chargement...", "en": "Loading..."},

    # --- Menu ---
    "menu_surveillance": {"fr": "Surveillance", "en": "Monitoring"},
    "menu_security": {"fr": "Sécurité", "en": "Security"},
    "menu_administration": {"fr": "Administration", "en": "Administration"},
    "menu_alerts": {"fr": "Alertes", "en": "Alerts"},
    "menu_incidents": {"fr": "Incidents", "en": "Incidents"},
    "menu_blocked_ips": {"fr": "IPs bloquées", "en": "Blocked IPs"},
    "menu_signatures": {"fr": "Signatures", "en": "Signatures"},
    "menu_users": {"fr": "Utilisateurs", "en": "Users"},
    "menu_settings": {"fr": "Paramètres", "en": "Settings"},
    "menu_reports": {"fr": "Rapports", "en": "Reports"},
    "menu_audit": {"fr": "Journal d'audit", "en": "Audit log"},
    "menu_ai_assistant": {"fr": "Assistant IA", "en": "AI Assistant"},
    "menu_profile": {"fr": "Mon profil", "en": "My profile"},

    # --- Login ---
    "login_subtitle": {"fr": "Connectez-vous à votre espace de sécurité",
                       "en": "Sign in to your security workspace"},
    "login_error_generic": {"fr": "Échec de la connexion.", "en": "Login failed."},

    # --- Changement de mot de passe ---
    "change_pwd_title": {"fr": "Changer votre mot de passe", "en": "Change your password"},
    "change_pwd_forced": {"fr": "Vous devez changer votre mot de passe avant de continuer.",
                          "en": "You must change your password before continuing."},
    "current_password": {"fr": "Mot de passe actuel", "en": "Current password"},
    "new_password": {"fr": "Nouveau mot de passe", "en": "New password"},
    "confirm_password": {"fr": "Confirmer le mot de passe", "en": "Confirm password"},
    "update": {"fr": "Mettre à jour", "en": "Update"},
    "pwd_rules_title": {"fr": "Votre mot de passe doit contenir :",
                        "en": "Your password must contain:"},
    "pwd_mismatch": {"fr": "Les deux mots de passe ne correspondent pas.",
                     "en": "The two passwords do not match."},
    "pwd_wrong_current": {"fr": "Le mot de passe actuel est incorrect.",
                          "en": "Current password is incorrect."},
    "pwd_changed_ok": {"fr": "Mot de passe mis à jour avec succès.",
                       "en": "Password updated successfully."},

    # --- Profil ---
    "profile_title": {"fr": "Mon profil", "en": "My profile"},
    "profile_info": {"fr": "Informations personnelles", "en": "Personal information"},
    "profile_prefs": {"fr": "Préférences", "en": "Preferences"},
    "profile_security": {"fr": "Sécurité", "en": "Security"},
    "first_name": {"fr": "Prénom", "en": "First name"},
    "last_name": {"fr": "Nom", "en": "Last name"},
    "phone": {"fr": "Téléphone", "en": "Phone"},
    "language": {"fr": "Langue", "en": "Language"},
    "theme": {"fr": "Thème", "en": "Theme"},
    "theme_dark": {"fr": "Sombre", "en": "Dark"},
    "theme_light": {"fr": "Clair", "en": "Light"},
    "theme_auto": {"fr": "Automatique", "en": "Auto"},
    "role": {"fr": "Rôle", "en": "Role"},
    "last_login": {"fr": "Dernière connexion", "en": "Last login"},
    "profile_saved": {"fr": "Profil enregistré.", "en": "Profile saved."},
    "change_my_password": {"fr": "Changer mon mot de passe", "en": "Change my password"},

    # --- Rôles (libellés) ---
    "role_ADMIN": {"fr": "Administrateur", "en": "Administrator"},
    "role_ANALYST": {"fr": "Analyste sécurité", "en": "Security analyst"},
    "role_OPERATOR": {"fr": "Opérateur SOC", "en": "SOC operator"},

    # --- Alertes / Incidents (Lot 3) ---
    "alerts_title": {"fr": "Alertes", "en": "Alerts"},
    "incidents_title": {"fr": "Incidents", "en": "Incidents"},
    "filter_severity": {"fr": "Sévérité", "en": "Severity"},
    "filter_status": {"fr": "Statut", "en": "Status"},
    "filter_source": {"fr": "Source", "en": "Source"},
    "filter_period": {"fr": "Période", "en": "Period"},
    "filter_all": {"fr": "Toutes", "en": "All"},
    "filter_apply": {"fr": "Filtrer", "en": "Filter"},
    "filter_reset": {"fr": "Réinitialiser", "en": "Reset"},
    "search_placeholder": {"fr": "Rechercher (IP, titre, signature)...", "en": "Search (IP, title, signature)..."},
    "col_time": {"fr": "Date", "en": "Date"},
    "col_severity": {"fr": "Sévérité", "en": "Severity"},
    "col_title": {"fr": "Alerte", "en": "Alert"},
    "col_source": {"fr": "Source", "en": "Source"},
    "col_ip": {"fr": "IP source", "en": "Source IP"},
    "col_country": {"fr": "Pays", "en": "Country"},
    "col_count": {"fr": "Occur.", "en": "Count"},
    "col_status": {"fr": "Statut", "en": "Status"},
    "col_actions": {"fr": "Actions", "en": "Actions"},
    "no_alerts": {"fr": "Aucune alerte ne correspond aux filtres.", "en": "No alert matches the filters."},
    "no_incidents": {"fr": "Aucun incident.", "en": "No incident."},
    "view_detail": {"fr": "Détail", "en": "Detail"},
    "page_of": {"fr": "Page", "en": "Page"},
    "previous": {"fr": "Précédent", "en": "Previous"},
    "next": {"fr": "Suivant", "en": "Next"},
    "results_total": {"fr": "résultats", "en": "results"},
    # Détail alerte
    "alert_detail": {"fr": "Détail de l'alerte", "en": "Alert detail"},
    "incident_detail": {"fr": "Détail de l'incident", "en": "Incident detail"},
    "tech_context": {"fr": "Contexte technique", "en": "Technical context"},
    "recommendations": {"fr": "Recommandations", "en": "Recommendations"},
    "related_alerts": {"fr": "Alertes liées (même IP)", "en": "Related alerts (same IP)"},
    "correlated_alerts": {"fr": "Alertes corrélées", "en": "Correlated alerts"},
    "action_ack": {"fr": "Acquitter", "en": "Acknowledge"},
    "action_resolve": {"fr": "Résoudre", "en": "Resolve"},
    "action_fp": {"fr": "Faux positif", "en": "False positive"},
    "action_investigate": {"fr": "Investiguer", "en": "Investigate"},
    "ai_chat_title": {"fr": "Discuter avec l'IA", "en": "Chat with AI"},
    "ai_chat_placeholder": {"fr": "Posez une question sur cette alerte...", "en": "Ask a question about this alert..."},
    "ai_chat_send": {"fr": "Envoyer", "en": "Send"},
    "ai_chat_empty": {"fr": "Posez une question à l'assistant pour obtenir des explications ou des conseils.", "en": "Ask the assistant a question to get explanations or advice."},
    "ai_thinking": {"fr": "L'assistant réfléchit...", "en": "The assistant is thinking..."},
    "back_to_list": {"fr": "Retour à la liste", "en": "Back to list"},

    # --- Lot 4 ---
    "blocked_ips_title": {"fr": "IPs bloquées", "en": "Blocked IPs"},
    "signatures_title": {"fr": "Signatures", "en": "Signatures"},
    "users_title": {"fr": "Utilisateurs", "en": "Users"},
    "ai_assistant_title": {"fr": "Assistant IA", "en": "AI Assistant"},
    "col_reason": {"fr": "Raison", "en": "Reason"},
    "col_blocked_at": {"fr": "Bloquée le", "en": "Blocked at"},
    "col_expires": {"fr": "Expire le", "en": "Expires at"},
    "col_active": {"fr": "Active", "en": "Active"},
    "action_unblock": {"fr": "Débloquer", "en": "Unblock"},
    "block_ip_manual": {"fr": "Bloquer une IP", "en": "Block an IP"},
    "active_only": {"fr": "Actives seulement", "en": "Active only"},
    "yes": {"fr": "Oui", "en": "Yes"},
    "no": {"fr": "Non", "en": "No"},
    "no_blocked_ips": {"fr": "Aucune IP bloquée.", "en": "No blocked IP."},
    "col_name": {"fr": "Nom", "en": "Name"},
    "col_category": {"fr": "Catégorie", "en": "Category"},
    "col_hits": {"fr": "Déclenchements", "en": "Triggers"},
    "no_signatures": {"fr": "Aucune signature.", "en": "No signature."},
    "col_email": {"fr": "Email", "en": "Email"},
    "col_role": {"fr": "Rôle", "en": "Role"},
    "col_last_login": {"fr": "Dernière connexion", "en": "Last login"},
    "create_user": {"fr": "Créer un utilisateur", "en": "Create a user"},
    "user_active": {"fr": "Actif", "en": "Active"},
    "user_locked": {"fr": "Verrouillé", "en": "Locked"},
    "user_inactive": {"fr": "Désactivé", "en": "Inactive"},
    "action_deactivate": {"fr": "Désactiver", "en": "Deactivate"},
    "action_activate": {"fr": "Réactiver", "en": "Reactivate"},
    "action_unlock_user": {"fr": "Déverrouiller", "en": "Unlock"},
    "action_reset_pwd": {"fr": "Réinit. MDP", "en": "Reset pwd"},
    "temp_password_notice": {"fr": "Mot de passe temporaire (à transmettre)", "en": "Temporary password (to share)"},
    "new_conversation": {"fr": "Nouvelle conversation", "en": "New conversation"},
    "conversations_history": {"fr": "Mes conversations", "en": "My conversations"},
    "no_conversations": {"fr": "Aucune conversation. Posez une question pour commencer.", "en": "No conversation yet. Ask a question to start."},
    "ai_ask_anything": {"fr": "Posez votre question à l'assistant cybersécurité...", "en": "Ask the cybersecurity assistant anything..."},

    # --- Lot 5 ---
    "settings_title": {"fr": "Paramètres", "en": "Settings"},
    "audit_title": {"fr": "Journal d'audit", "en": "Audit log"},
    "reports_title": {"fr": "Rapports", "en": "Reports"},
    "save_settings": {"fr": "Enregistrer les modifications", "en": "Save changes"},
    "secret_hint": {"fr": "Laisser vide pour ne pas changer", "en": "Leave empty to keep unchanged"},
    "generate_report": {"fr": "Générer un rapport", "en": "Generate a report"},
    "generate_pdf": {"fr": "Générer PDF", "en": "Generate PDF"},
    "generate_excel": {"fr": "Générer Excel", "en": "Generate Excel"},
    "download": {"fr": "Télécharger", "en": "Download"},
    "no_reports": {"fr": "Aucun rapport généré pour l'instant.", "en": "No report generated yet."},
    "col_format": {"fr": "Format", "en": "Format"},
    "col_size": {"fr": "Taille", "en": "Size"},
    "col_generated": {"fr": "Généré le", "en": "Generated"},
    "col_action": {"fr": "Action", "en": "Action"},
    "col_date": {"fr": "Date", "en": "Date"},
    "col_user": {"fr": "Utilisateur", "en": "User"},
    "col_event": {"fr": "Action", "en": "Action"},
    "col_target": {"fr": "Cible", "en": "Target"},
    "no_audit": {"fr": "Aucune entrée dans le journal.", "en": "No audit entry."},
    "period_7d": {"fr": "7 jours", "en": "7 days"},
    "period_30d": {"fr": "30 jours", "en": "30 days"},
    "role_VIEWER": {"fr": "Lecteur (Direction)", "en": "Viewer (Management)"},
}


def t(key, lang="fr"):
    """Traduit une clé. Retourne la clé elle-même si non trouvée (aide au debug)."""
    entry = TRANSLATIONS.get(key)
    if not entry:
        return key
    return entry.get(lang, entry.get("fr", key))


def get_lang(request):
    """Détermine la langue : ?lang= > session > préférence user > 'fr'."""
    lang = request.GET.get("lang")
    if lang in ("fr", "en"):
        request.session["lang"] = lang
        return lang
    if request.session.get("lang") in ("fr", "en"):
        return request.session["lang"]
    user = getattr(request, "current_user", None)
    if user and user.language in ("fr", "en"):
        return user.language
    return "fr"
