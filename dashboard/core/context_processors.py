"""
Context processor — injecte les données communes dans tous les templates :
utilisateur courant, langue, fonction de traduction, structure du menu.
"""
from .auth import get_current_user
from .i18n import t as translate, get_lang


def dashboard_context(request):
    user = getattr(request, "current_user", None) or get_current_user(request)
    lang = get_lang(request)

    # Fonction de traduction utilisable dans les templates : {{ t.menu_alerts }}
    class T:
        def __getattr__(self, key):
            return translate(key, lang)
        def __getitem__(self, key):
            return translate(key, lang)

    # Clair par défaut (direction "Ink"). La préférence utilisateur prime ;
    # "auto" ou l'absence de préférence retombe sur le clair.
    theme = (user.theme_preference if user else None) or "light"

    return {
        "current_user": user,
        "lang": lang,
        "t": T(),
        "theme": theme,
        "menu": _build_menu(user, lang) if user else [],
    }


def _build_menu(user, lang):
    """Construit le menu latéral en fonction des permissions du rôle.
    Chaque entrée n'apparaît que si l'utilisateur a le droit 'view' associé."""
    from .i18n import t

    def item(key, url_name, icon, resource=None, badge=None, roles=None):
        # roles : si fourni, l'item n'est visible que pour ces codes de rôle
        if roles is not None:
            visible = user.role.code in roles
        else:
            visible = (resource is None) or user.has_resource(resource)
        return {
            "label": t(key, lang),
            "url_name": url_name,
            "icon": icon,
            "visible": visible,
            "badge": badge,
        }

    sections = [
        {
            "title": t("menu_surveillance", lang),
            "items": [
                item("dashboard", "dashboard", "grid"),
                item("menu_alerts", "alerts_list", "alert", resource="alerts"),
                item("menu_incidents", "incidents_list", "bug", resource="alerts"),
                # Assistant IA : seulement les rôles autorisés à chatter (ADMIN, ANALYST)
                item("menu_ai_assistant", "ai_assistant", "robot", roles=["ADMIN", "ANALYST"]),
            ],
        },
        {
            "title": t("menu_security", lang),
            "items": [
                item("menu_blocked_ips", "blocked_ips", "shield", resource="blocked_ips"),
                item("menu_signatures", "signatures", "fingerprint", resource="alerts"),
            ],
        },
        {
            "title": t("menu_administration", lang),
            "items": [
                item("menu_users", "users", "users", resource="users"),
                item("menu_settings", "settings", "gear", resource="settings"),
                item("menu_reports", "reports", "file", resource="reports"),
                item("menu_audit", "audit_log", "clock", resource="audit"),
            ],
        },
    ]

    # On masque une section entière si aucun de ses items n'est visible
    visible_sections = []
    for s in sections:
        visible_items = [it for it in s["items"] if it["visible"]]
        if visible_items:
            visible_sections.append({"title": s["title"], "items": visible_items})
    return visible_sections
