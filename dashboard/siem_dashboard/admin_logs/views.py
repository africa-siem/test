"""SIEM Africa - Vues Admin Logs.

Visible uniquement aux admins. Affiche :
  - audit_log (actions des users)
  - email_logs (notifications)
  - tail du fichier /var/log/siem-africa/agent.log
"""
from datetime import timedelta
from pathlib import Path

from django.conf import settings as dj_settings
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import JsonResponse
from django.shortcuts import render
from django.utils import timezone

from core.models import AuditLog, EmailLog


def admin_required(view_func):
    return user_passes_test(
        lambda u: u.is_authenticated and u.is_admin,
        login_url="/login/",
    )(view_func)


# ============================================================================
# Page principale
# ============================================================================
@login_required
@admin_required
def home(request):
    """Page admin logs avec onglets."""
    tab = request.GET.get("tab", "audit")

    # Filtres communs
    period = request.GET.get("period", "24h")
    now = timezone.now()
    if period == "24h":
        since = now - timedelta(hours=24)
    elif period == "7d":
        since = now - timedelta(days=7)
    elif period == "30d":
        since = now - timedelta(days=30)
    else:
        since = None

    # Audit log (limite a 500 lignes)
    audit_qs = AuditLog.objects.select_related("user").order_by("-created_at")
    if since:
        audit_qs = audit_qs.filter(created_at__gte=since)
    audit_logs = list(audit_qs[:500])

    # Email logs
    email_qs = EmailLog.objects.order_by("-created_at")
    if since:
        email_qs = email_qs.filter(created_at__gte=since)
    email_logs = list(email_qs[:500])

    # Stats emails
    email_stats = {
        "total": len(email_logs),
        "sent": sum(1 for e in email_logs if e.status == "sent"),
        "rate_limited": sum(1 for e in email_logs if e.status == "rate_limited"),
        "failed": sum(1 for e in email_logs if e.status not in ("sent", "rate_limited")),
    }

    # Agent log (lecture sur disque)
    agent_log_lines = _read_agent_log_tail(lines=200)

    return render(request, "admin_logs/home.html", {
        "tab": tab,
        "period": period,
        "audit_logs": audit_logs,
        "email_logs": email_logs,
        "email_stats": email_stats,
        "agent_log_lines": agent_log_lines,
    })


# ============================================================================
# Helpers
# ============================================================================
def _read_agent_log_tail(lines=200):
    """Lit les N dernieres lignes du log agent."""
    log_path = Path(dj_settings.SIEM_AGENT_LOG)
    if not log_path.is_file():
        return [{
            "level": "WARN",
            "text": f"Fichier {log_path} introuvable.",
            "timestamp": "",
        }]

    try:
        # Lecture des dernieres lignes
        result = []
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            # Lit tout puis garde les dernieres
            all_lines = f.readlines()
            tail = all_lines[-lines:]
            for line in tail:
                line = line.rstrip()
                if not line:
                    continue
                # Detect level
                level = "INFO"
                lower = line.lower()
                if "[error]" in lower or "[fail]" in lower or "error" in lower:
                    level = "ERROR"
                elif "[warn]" in lower or "warning" in lower:
                    level = "WARN"
                elif "[debug]" in lower:
                    level = "DEBUG"
                result.append({"level": level, "text": line, "timestamp": ""})
        return result
    except (OSError, PermissionError) as exc:
        return [{
            "level": "ERROR",
            "text": f"Lecture impossible : {exc}",
            "timestamp": "",
        }]


# ============================================================================
# API endpoint pour rafraichir le tail du log agent (AJAX)
# ============================================================================
@login_required
@admin_required
def api_agent_log_tail(request):
    """Retourne les dernieres lignes du log agent en JSON."""
    lines = int(request.GET.get("lines", 200))
    lines = min(max(lines, 10), 1000)
    return JsonResponse({"lines": _read_agent_log_tail(lines=lines)})
