"""
Vues — Module 4 Dashboard SIEM Africa (Lot 1).

Couvre : login, logout, changement de mot de passe forcé, dashboard d'accueil
(squelette, sera enrichi au Lot 2), page profil.
"""
from django.shortcuts import render, redirect
from django.contrib import messages

from .auth import (
    authenticate, login_session, logout_session, get_current_user,
    verify_password, hash_password, validate_password_strength, now_sqlite,
)
from .decorators import login_required
from .i18n import t, get_lang


def _client_ip(request):
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")


def login_view(request):
    """Page de connexion. Email + mot de passe."""
    # Déjà connecté ? → dashboard
    if get_current_user(request):
        return redirect("dashboard")

    lang = get_lang(request)
    if request.method == "POST":
        email = request.POST.get("email", "")
        password = request.POST.get("password", "")
        result = authenticate(email, password)
        if result.ok:
            login_session(request, result.user)
            # Tracer l'IP de connexion
            result.user.last_login_ip = _client_ip(request)
            result.user.save(update_fields=["last_login_ip"])
            # Mot de passe à changer ?
            if result.user.must_change_pwd == 1:
                return redirect("force_password_change")
            return redirect("dashboard")
        else:
            messages.error(request, result.error)

    return render(request, "login.html", {"lang": lang})


@login_required
def logout_view(request):
    logout_session(request)
    return redirect("login")


def force_password_change(request):
    """Changement de mot de passe forcé (1ère connexion ou expiration)."""
    user = get_current_user(request)
    if not user:
        return redirect("login")

    lang = get_lang(request)
    if request.method == "POST":
        current = request.POST.get("current_password", "")
        new = request.POST.get("new_password", "")
        confirm = request.POST.get("confirm_password", "")

        errors = []
        if not verify_password(current, user.password_hash):
            errors.append(t("pwd_wrong_current", lang))
        if new != confirm:
            errors.append(t("pwd_mismatch", lang))
        errors += validate_password_strength(new)

        if errors:
            for e in errors:
                messages.error(request, e)
        else:
            user.password_hash = hash_password(new)
            user.must_change_pwd = 0
            user.password_changed_at = now_sqlite()
            user.save(update_fields=["password_hash", "must_change_pwd", "password_changed_at"])
            messages.success(request, t("pwd_changed_ok", lang))
            return redirect("dashboard")

    return render(request, "force_password_change.html", {"lang": lang, "forced": True})


@login_required
def dashboard_view(request):
    """Tableau de bord d'accueil avec indicateurs réels.
    Deux variantes : technique (ADMIN/ANALYST/OPERATOR) et business (VIEWER)."""
    import json
    from . import stats

    user = request.current_user

    if user.is_viewer:
        # --- Vue DIRIGEANT (business, simplifiée) ---
        seven = stats.alerts_last_7_days()
        score = stats.security_score()
        context = {
            "is_viewer": True,
            "score": score,
            "blocked_week": stats.blocked_ips_count(active_only=False),
            "compromations": stats.compromations_count(168),
            "chart_labels": json.dumps([d["date"][5:] for d in seven]),
            "chart_data": json.dumps([d["count"] for d in seven]),
        }
        return render(request, "dashboard_viewer.html", context)

    # --- Vue technique (ADMIN / ANALYST / OPERATOR) ---
    sev = stats.severity_counts(24)
    prev = stats.severity_counts_prev(24)
    seven = stats.alerts_last_7_days()
    score = stats.security_score()

    context = {
        "is_viewer": False,
        "sev": sev,
        "trend_critical": stats.trend(sev["CRITICAL"], prev["CRITICAL"]),
        "trend_high": stats.trend(sev["HIGH"], prev["HIGH"]),
        "trend_medium": stats.trend(sev["MEDIUM"], prev["MEDIUM"]),
        "trend_low": stats.trend(sev["LOW"], prev["LOW"]),
        "score": score,
        "chart_labels": json.dumps([d["date"][5:] for d in seven]),
        "chart_data": json.dumps([d["count"] for d in seven]),
        "top_categories": stats.top_categories(24, 5),
        "top_ips": stats.top_attacking_ips(24, 10),
        "recent_alerts": stats.recent_critical_alerts(5),
        "services": stats.service_status(),
        "attacks_by_country": stats.attacks_by_country(168, 20),
        "alerts_total": stats.alerts_total(24),
        "incidents_open": stats.incidents_open_count(),
        "blocked_active": stats.blocked_ips_count(active_only=True),
    }
    return render(request, "dashboard.html", context)


@login_required
def profile_view(request):
    """Page Mon profil : infos perso + préférences (langue, thème)."""
    user = request.current_user
    lang = get_lang(request)

    if request.method == "POST":
        user.first_name = request.POST.get("first_name", user.first_name)
        user.last_name = request.POST.get("last_name", user.last_name)
        user.phone = request.POST.get("phone", user.phone)
        new_lang = request.POST.get("language", user.language)
        if new_lang in ("fr", "en"):
            user.language = new_lang
            request.session["lang"] = new_lang
        new_theme = request.POST.get("theme_preference", user.theme_preference)
        if new_theme in ("dark", "light", "auto"):
            user.theme_preference = new_theme
        user.save(update_fields=[
            "first_name", "last_name", "phone", "language", "theme_preference"
        ])
        messages.success(request, t("profile_saved", lang))
        return redirect("profile")

    return render(request, "profile.html", {"u": user})


@login_required
def change_password_view(request):
    """Changement de mot de passe volontaire depuis le profil."""
    return force_password_change(request)


# ============================================================================
# LOT 3 : Alertes, Incidents, Chat IA contextuel
# ============================================================================
from django.http import JsonResponse
from .decorators import permission_required
from . import queries, chat
from .i18n import get_lang as _get_lang


@login_required
def alerts_list_view(request):
    """Liste paginée des alertes avec filtres."""
    user = request.current_user
    if not user.can("alerts", "view"):
        return redirect("dashboard")

    # Filtres depuis la query string
    severity = request.GET.get("severity") or None
    status = request.GET.get("status") or None
    source = request.GET.get("source") or None
    search = request.GET.get("q") or None
    period = request.GET.get("period") or None
    try:
        page = max(1, int(request.GET.get("page", 1)))
    except ValueError:
        page = 1

    period_hours = {"24h": 24, "7d": 168, "30d": 720}.get(period)
    per_page = 25
    rows, total = queries.list_alerts(
        severity=severity, status=status, source=source, search=search,
        period_hours=period_hours, page=page, per_page=per_page,
    )
    total_pages = max(1, (total + per_page - 1) // per_page)

    return render(request, "alerts_list.html", {
        "active_page": "alerts",
        "alerts": rows,
        "total": total,
        "page": page,
        "total_pages": total_pages,
        "has_prev": page > 1,
        "has_next": page < total_pages,
        "prev_page": page - 1,
        "next_page": page + 1,
        "f_severity": severity or "",
        "f_status": status or "",
        "f_source": source or "",
        "f_search": search or "",
        "f_period": period or "",
        "can_act": user.can("alerts", "acknowledge"),
    })


@login_required
def alert_detail_view(request, alert_id):
    """Détail d'une alerte + actions + bloc chat IA."""
    user = request.current_user
    if not user.can("alerts", "view"):
        return redirect("dashboard")

    alert = queries.get_alert(alert_id)
    if not alert:
        return redirect("alerts_list")

    # Actions POST (acquitter, résoudre, FP)
    if request.method == "POST" and user.can("alerts", "acknowledge"):
        action = request.POST.get("action")
        mapping = {
            "acknowledge": "ACKNOWLEDGED",
            "resolve": "RESOLVED",
            "false_positive": "FALSE_POSITIVE",
            "investigate": "INVESTIGATING",
        }
        # Vérifier les permissions fines
        allowed = True
        if action in ("resolve",) and not user.can("alerts", "resolve"):
            allowed = False
        if action == "false_positive" and not user.can("alerts", "mark_fp"):
            allowed = False
        if action in mapping and allowed:
            queries.update_alert_status(
                alert_id, mapping[action], user=user,
                notes=request.POST.get("notes", ""),
            )
        return redirect("alert_detail", alert_id=alert_id)

    related = queries.related_alerts(alert.get("src_ip"), alert_id, 5)

    # Chat IA : visible seulement pour les rôles autorisés (ADMIN, ANALYST)
    can_chat = user.role.code in ("ADMIN", "ANALYST")
    messages_chat = []
    if can_chat:
        chat.__name__  # noop pour garder l'import
        from .chat_db import ensure_chat_tables
        ensure_chat_tables()
        conv_id = chat.get_or_create_conversation(
            user.id, alert_id=alert_id,
            title=f"Alerte #{alert_id} — {alert.get('title', '')[:40]}",
        )
        messages_chat = chat.get_messages(conv_id)

    return render(request, "alert_detail.html", {
        "active_page": "alerts",
        "a": alert,
        "related": related,
        "can_act": user.can("alerts", "acknowledge"),
        "can_resolve": user.can("alerts", "resolve"),
        "can_fp": user.can("alerts", "mark_fp"),
        "can_chat": can_chat,
        "chat_messages": messages_chat,
    })


@login_required
def alert_chat_api(request, alert_id):
    """Endpoint AJAX : envoie une question à l'IA sur une alerte."""
    user = request.current_user
    if user.role.code not in ("ADMIN", "ANALYST"):
        return JsonResponse({"ok": False, "error": "Non autorisé"}, status=403)
    if request.method != "POST":
        return JsonResponse({"ok": False, "error": "Méthode invalide"}, status=405)

    question = (request.POST.get("message") or "").strip()
    if not question:
        return JsonResponse({"ok": False, "error": "Message vide"}, status=400)

    alert = queries.get_alert(alert_id)
    if not alert:
        return JsonResponse({"ok": False, "error": "Alerte introuvable"}, status=404)

    from .chat_db import ensure_chat_tables
    ensure_chat_tables()
    lang = _get_lang(request)
    conv_id = chat.get_or_create_conversation(
        user.id, alert_id=alert_id,
        title=f"Alerte #{alert_id} — {alert.get('title', '')[:40]}",
    )
    alert_ctx = {
        "title": alert.get("title"), "severity": alert.get("severity"),
        "src_ip": alert.get("src_ip"), "sig_name": alert.get("sig_name"),
        "description": alert.get("sig_desc_fr") or alert.get("description"),
    }
    answer, ok = chat.send_user_message(conv_id, question, alert_ctx=alert_ctx, lang=lang)
    return JsonResponse({"ok": ok, "answer": answer})


@login_required
def incidents_list_view(request):
    user = request.current_user
    if not user.can("alerts", "view"):
        return redirect("dashboard")
    status = request.GET.get("status") or None
    severity = request.GET.get("severity") or None
    try:
        page = max(1, int(request.GET.get("page", 1)))
    except ValueError:
        page = 1
    per_page = 25
    rows, total = queries.list_incidents(status=status, severity=severity, page=page, per_page=per_page)
    total_pages = max(1, (total + per_page - 1) // per_page)
    return render(request, "incidents_list.html", {
        "active_page": "incidents",
        "incidents": rows, "total": total, "page": page, "total_pages": total_pages,
        "has_prev": page > 1, "has_next": page < total_pages,
        "prev_page": page - 1, "next_page": page + 1,
        "f_status": status or "", "f_severity": severity or "",
    })


@login_required
def incident_detail_view(request, incident_id):
    user = request.current_user
    if not user.can("alerts", "view"):
        return redirect("dashboard")
    incident = queries.get_incident(incident_id)
    if not incident:
        return redirect("incidents_list")
    can_chat = user.role.code in ("ADMIN", "ANALYST")
    messages_chat = []
    if can_chat:
        from .chat_db import ensure_chat_tables
        ensure_chat_tables()
        conv_id = chat.get_or_create_conversation(
            user.id, incident_id=incident_id,
            title=f"Incident #{incident_id}",
        )
        messages_chat = chat.get_messages(conv_id)
    return render(request, "incident_detail.html", {
        "active_page": "incidents",
        "i": incident, "can_chat": can_chat, "chat_messages": messages_chat,
    })


@login_required
def incident_chat_api(request, incident_id):
    user = request.current_user
    if user.role.code not in ("ADMIN", "ANALYST"):
        return JsonResponse({"ok": False, "error": "Non autorisé"}, status=403)
    if request.method != "POST":
        return JsonResponse({"ok": False, "error": "Méthode invalide"}, status=405)
    question = (request.POST.get("message") or "").strip()
    if not question:
        return JsonResponse({"ok": False, "error": "Message vide"}, status=400)
    incident = queries.get_incident(incident_id)
    if not incident:
        return JsonResponse({"ok": False, "error": "Introuvable"}, status=404)
    from .chat_db import ensure_chat_tables
    ensure_chat_tables()
    lang = _get_lang(request)
    conv_id = chat.get_or_create_conversation(user.id, incident_id=incident_id, title=f"Incident #{incident_id}")
    inc_ctx = {
        "title": incident.get("title"), "severity": incident.get("severity"),
        "alert_count": incident.get("alert_count"),
    }
    answer, ok = chat.send_user_message(conv_id, question, incident_ctx=inc_ctx, lang=lang)
    return JsonResponse({"ok": ok, "answer": answer})


# ============================================================================
# LOT 4 : IPs bloquées, Signatures, Utilisateurs, Assistant IA
# ============================================================================
from . import user_admin
from django.contrib import messages as dj_messages


def _paginate(request, per_page=25):
    try:
        return max(1, int(request.GET.get("page", 1)))
    except ValueError:
        return 1


@login_required
def blocked_ips_view(request):
    user = request.current_user
    if not user.can("blocked_ips", "view"):
        return redirect("dashboard")

    # Actions (déblocage / blocage manuel) si autorisé
    can_unblock = user.can("blocked_ips", "unblock")
    if request.method == "POST" and can_unblock:
        action = request.POST.get("action")
        if action == "unblock":
            queries.unblock_ip(request.POST.get("block_id"), user=user)
        elif action == "block":
            ip = (request.POST.get("ip") or "").strip()
            if ip:
                queries.block_ip_manual(ip, request.POST.get("reason", "Blocage manuel"), user=user)
        return redirect("blocked_ips")

    active_only = request.GET.get("active") == "1"
    search = request.GET.get("q") or None
    page = _paginate(request)
    per_page = 25
    rows, total = queries.list_blocked_ips(active_only=active_only, search=search, page=page, per_page=per_page)
    total_pages = max(1, (total + per_page - 1) // per_page)

    return render(request, "blocked_ips.html", {
        "active_page": "blocked_ips",
        "ips": rows, "total": total, "page": page, "total_pages": total_pages,
        "has_prev": page > 1, "has_next": page < total_pages,
        "prev_page": page - 1, "next_page": page + 1,
        "active_only": active_only, "f_search": search or "",
        "can_unblock": can_unblock,
    })


@login_required
def signatures_view(request):
    user = request.current_user
    if not user.has_resource("alerts"):  # signatures liées à la surveillance
        return redirect("dashboard")

    source = request.GET.get("source") or None
    severity = request.GET.get("severity") or None
    cat = request.GET.get("category") or None
    search = request.GET.get("q") or None
    page = _paginate(request)
    per_page = 25
    rows, total = queries.list_signatures(
        source=source, severity=severity,
        category_id=int(cat) if cat else None, search=search,
        page=page, per_page=per_page,
    )
    total_pages = max(1, (total + per_page - 1) // per_page)

    return render(request, "signatures.html", {
        "active_page": "signatures",
        "signatures": rows, "total": total, "page": page, "total_pages": total_pages,
        "has_prev": page > 1, "has_next": page < total_pages,
        "prev_page": page - 1, "next_page": page + 1,
        "categories": queries.signature_categories(),
        "f_source": source or "", "f_severity": severity or "",
        "f_category": cat or "", "f_search": search or "",
    })


@login_required
def users_view(request):
    """Gestion des utilisateurs. ADMIN uniquement."""
    user = request.current_user
    if not user.can("users", "create"):
        return redirect("dashboard")

    new_temp_password = None
    new_user_email = None

    if request.method == "POST":
        action = request.POST.get("action")
        try:
            if action == "create":
                uid, temp = user_admin.create_user(
                    email=request.POST.get("email"),
                    first_name=request.POST.get("first_name"),
                    last_name=request.POST.get("last_name"),
                    role_id=int(request.POST.get("role_id")),
                    language=request.POST.get("language", "fr"),
                    phone=request.POST.get("phone"),
                )
                queries._audit(user, "user_create", "users", uid)
                new_temp_password = temp
                new_user_email = request.POST.get("email")
                dj_messages.success(request, "Utilisateur créé avec succès.")
            elif action == "deactivate":
                user_admin.set_user_active(request.POST.get("user_id"), False)
                dj_messages.success(request, "Utilisateur désactivé.")
            elif action == "activate":
                user_admin.set_user_active(request.POST.get("user_id"), True)
                dj_messages.success(request, "Utilisateur réactivé.")
            elif action == "unlock":
                user_admin.unlock_user(request.POST.get("user_id"))
                dj_messages.success(request, "Compte déverrouillé.")
            elif action == "reset_password":
                temp = user_admin.reset_password(request.POST.get("user_id"))
                new_temp_password = temp
                dj_messages.success(request, "Mot de passe réinitialisé.")
        except ValueError as e:
            dj_messages.error(request, str(e))

    return render(request, "users.html", {
        "active_page": "users",
        "users": queries.list_users(),
        "roles": queries.all_roles(),
        "new_temp_password": new_temp_password,
        "new_user_email": new_user_email,
        "current_user_id": user.id,
    })


@login_required
def ai_assistant_view(request):
    """Page Assistant IA dédiée : liste des conversations + chat libre.
    ADMIN et ANALYST uniquement."""
    user = request.current_user
    if user.role.code not in ("ADMIN", "ANALYST"):
        return redirect("dashboard")

    from .chat_db import ensure_chat_tables
    ensure_chat_tables()

    from django.db import connection
    with connection.cursor() as cur:
        cur.execute(
            """SELECT id, title, alert_id, incident_id, updated_at
               FROM chat_conversations
               WHERE user_id = %s AND is_archived = 0
               ORDER BY updated_at DESC LIMIT 50""",
            [user.id],
        )
        cols = [c[0] for c in cur.description]
        conversations = [dict(zip(cols, r)) for r in cur.fetchall()]

    # Conversation active (sélectionnée ou nouvelle générale)
    conv_id = request.GET.get("conv")
    active_conv = None
    chat_messages = []
    if conv_id:
        active_conv = int(conv_id)
        chat_messages = chat.get_messages(active_conv)

    return render(request, "ai_assistant.html", {
        "active_page": "ai_assistant",
        "conversations": conversations,
        "active_conv": active_conv,
        "chat_messages": chat_messages,
    })


@login_required
def ai_assistant_chat_api(request):
    """Chat libre (sans contexte d'alerte) depuis la page Assistant IA."""
    user = request.current_user
    if user.role.code not in ("ADMIN", "ANALYST"):
        return JsonResponse({"ok": False, "error": "Non autorisé"}, status=403)
    if request.method != "POST":
        return JsonResponse({"ok": False, "error": "Méthode invalide"}, status=405)
    question = (request.POST.get("message") or "").strip()
    if not question:
        return JsonResponse({"ok": False, "error": "Message vide"}, status=400)

    from .chat_db import ensure_chat_tables
    ensure_chat_tables()
    lang = _get_lang(request)

    conv_id = request.POST.get("conv_id")
    if conv_id:
        conv_id = int(conv_id)
    else:
        # Nouvelle conversation libre
        conv_id = chat.get_or_create_conversation(
            user.id, title=question[:50],
        )
    answer, ok = chat.send_user_message(conv_id, question, lang=lang)
    return JsonResponse({"ok": ok, "answer": answer, "conv_id": conv_id})


# ============================================================================
# LOT 5 : Paramètres, Rapports, Journal d'audit
# ============================================================================
from . import settings_admin, reports as reports_mod
from django.http import FileResponse, Http404
import os


@login_required
def settings_view(request):
    """Page Paramètres (6 onglets). ADMIN uniquement."""
    user = request.current_user
    if not user.can("settings", "edit"):
        return redirect("dashboard")

    if request.method == "POST":
        n = settings_admin.update_settings(request.POST, user=user)
        queries._audit(user, "settings_update", "settings", None)
        dj_messages.success(request, f"{n} paramètre(s) mis à jour.")
        return redirect("settings")

    grouped = settings_admin.get_settings_by_category()
    # Ordre des onglets
    tab_order = ["smtp", "ai", "alerting", "correlation", "retention", "system"]
    tab_labels = {
        "smtp": "Notifications email", "ai": "Intelligence artificielle",
        "alerting": "Réponse active", "correlation": "Corrélation",
        "retention": "Rétention", "system": "Système",
    }
    tabs = [(c, tab_labels.get(c, c), grouped.get(c, [])) for c in tab_order if c in grouped]

    return render(request, "settings.html", {
        "active_page": "settings",
        "tabs": tabs,
    })


@login_required
def audit_log_view(request):
    """Journal d'audit. ADMIN + ANALYST (lecture)."""
    user = request.current_user
    if not user.can("audit", "view"):
        return redirect("dashboard")

    cat = request.GET.get("category") or None
    email = request.GET.get("email") or None
    page = _paginate(request)
    per_page = 50
    rows, total = settings_admin.list_audit(action_category=cat, user_email=email, page=page, per_page=per_page)
    total_pages = max(1, (total + per_page - 1) // per_page)

    return render(request, "audit_log.html", {
        "active_page": "audit",
        "logs": rows, "total": total, "page": page, "total_pages": total_pages,
        "has_prev": page > 1, "has_next": page < total_pages,
        "prev_page": page - 1, "next_page": page + 1,
        "categories": settings_admin.audit_categories(),
        "f_category": cat or "", "f_email": email or "",
    })


@login_required
def reports_view(request):
    """Liste des rapports + génération."""
    user = request.current_user
    if not user.has_resource("reports"):
        return redirect("dashboard")
    can_generate = user.can("reports", "generate")
    return render(request, "reports.html", {
        "active_page": "reports",
        "reports": reports_mod.list_reports(50),
        "can_generate": can_generate,
    })


@login_required
def report_generate_view(request):
    """Génère un rapport PDF ou Excel."""
    user = request.current_user
    if not user.can("reports", "generate"):
        return redirect("reports")
    fmt = request.GET.get("format", "pdf")
    days = int(request.GET.get("days", 7))
    lang = _get_lang(request)
    try:
        if fmt == "excel":
            reports_mod.generate_excel(days=days, lang=lang)
        else:
            reports_mod.generate_pdf(days=days, lang=lang)
        queries._audit(user, "report_generate", "reports", None)
        dj_messages.success(request, "Rapport généré avec succès.")
    except Exception as e:
        dj_messages.error(request, f"Erreur lors de la génération : {e}")
    return redirect("reports")


@login_required
def report_download_view(request, report_id):
    """Télécharge un rapport généré."""
    user = request.current_user
    if not user.has_resource("reports"):
        return redirect("dashboard")
    path, fmt = reports_mod.get_report_path(report_id)
    if not path or not os.path.exists(path):
        raise Http404("Rapport introuvable")
    return FileResponse(open(path, "rb"), as_attachment=True, filename=os.path.basename(path))
