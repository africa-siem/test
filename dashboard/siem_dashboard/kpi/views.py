"""SIEM Africa - Vues KPI.

  - dashboard : page principale avec graphiques ApexCharts
  - api_chart_data : endpoint JSON pour les charts (AJAX)
"""
import json
from datetime import timedelta, date

from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.http import JsonResponse
from django.shortcuts import render
from django.utils import timezone

from core.models import Alert, AISignatureCache, KpiHistory


# ============================================================================
# Page principale
# ============================================================================
@login_required
def dashboard(request):
    """Dashboard KPI avec stats globales (les charts sont remplis en AJAX)."""
    now = timezone.now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = now - timedelta(days=7)
    month_start = now - timedelta(days=30)

    qs_today = Alert.objects.filter(created_at__gte=today_start)
    qs_week = Alert.objects.filter(created_at__gte=week_start)
    qs_month = Alert.objects.filter(created_at__gte=month_start)

    # Cards principales
    stats = {
        "alerts_today": qs_today.count(),
        "alerts_critical_today": qs_today.filter(severity="CRITICAL").count(),
        "alerts_high_today": qs_today.filter(severity="HIGH").count(),
        "alerts_week": qs_week.count(),
        "alerts_resolved_week": qs_week.filter(status="RESOLVED").count(),
        "alerts_false_positive_week": qs_week.filter(status="FALSE_POSITIVE").count(),
        "alerts_month": qs_month.count(),

        # IA
        "ai_cache_total": AISignatureCache.objects.count(),
        "ai_cache_validated": AISignatureCache.objects.filter(is_validated=True).count(),
        "ai_processed_today": qs_today.exclude(ai_status="not_required").exclude(ai_status="pending").count(),

        # Attaquants uniques
        "unique_attackers_today": qs_today.exclude(src_ip__isnull=True).exclude(src_ip="").values("src_ip").distinct().count(),
        "unique_attackers_week": qs_week.exclude(src_ip__isnull=True).exclude(src_ip="").values("src_ip").distinct().count(),

        # Taux de resolution
        "resolution_rate": _calc_resolution_rate(qs_week),
        "false_positive_rate": _calc_fp_rate(qs_week),
    }

    return render(request, "kpi/dashboard.html", {"stats": stats})


def _calc_resolution_rate(qs):
    total = qs.count()
    if total == 0:
        return 0
    resolved = qs.filter(status="RESOLVED").count()
    return round((resolved / total) * 100, 1)


def _calc_fp_rate(qs):
    total = qs.count()
    if total == 0:
        return 0
    fp = qs.filter(status="FALSE_POSITIVE").count()
    return round((fp / total) * 100, 1)


# ============================================================================
# API endpoints pour les charts (JSON)
# ============================================================================
@login_required
def api_alerts_by_severity(request):
    """Donut chart : repartition des alertes par severite (24h)."""
    since = timezone.now() - timedelta(hours=24)
    rows = (
        Alert.objects.filter(created_at__gte=since)
        .values("severity")
        .annotate(count=Count("id"))
    )
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for r in rows:
        if r["severity"] in counts:
            counts[r["severity"]] = r["count"]

    return JsonResponse({
        "series": [counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"], counts["INFO"]],
        "labels": ["Critical", "High", "Medium", "Low", "Info"],
        "colors": ["#dc3545", "#fd7e14", "#ffc107", "#198754", "#6c757d"],
    })


@login_required
def api_alerts_timeline(request):
    """Line chart : nombre d'alertes par heure sur les 7 derniers jours."""
    days = int(request.GET.get("days", 7))
    days = min(max(days, 1), 30)
    since = timezone.now() - timedelta(days=days)

    # Group par jour (SQLite-friendly)
    from django.db.models.functions import TruncDate
    rows = (
        Alert.objects.filter(created_at__gte=since)
        .annotate(day=TruncDate("created_at"))
        .values("day")
        .annotate(count=Count("id"))
        .order_by("day")
    )

    # Construire la serie pour chaque jour de la fenetre
    today = timezone.now().date()
    data = {}
    for r in rows:
        day = r["day"]
        if day:
            data[day.isoformat()] = r["count"]

    series = []
    categories = []
    for i in range(days, -1, -1):
        d = today - timedelta(days=i)
        categories.append(d.strftime("%d/%m"))
        series.append(data.get(d.isoformat(), 0))

    return JsonResponse({
        "categories": categories,
        "series": [{"name": "Alertes", "data": series}],
    })


@login_required
def api_alerts_by_status(request):
    """Donut chart : repartition par statut (semaine)."""
    since = timezone.now() - timedelta(days=7)
    rows = (
        Alert.objects.filter(created_at__gte=since)
        .values("status")
        .annotate(count=Count("id"))
    )
    counts = {"NEW": 0, "ACKNOWLEDGED": 0, "INVESTIGATING": 0, "RESOLVED": 0, "FALSE_POSITIVE": 0}
    for r in rows:
        if r["status"] in counts:
            counts[r["status"]] = r["count"]

    return JsonResponse({
        "series": [counts["NEW"], counts["ACKNOWLEDGED"], counts["INVESTIGATING"],
                   counts["RESOLVED"], counts["FALSE_POSITIVE"]],
        "labels": ["Nouvelles", "Vues", "En cours", "Resolues", "Faux positifs"],
        "colors": ["#0d6efd", "#6c757d", "#ffc107", "#198754", "#dc3545"],
    })


@login_required
def api_top_attackers(request):
    """Bar chart : top 10 IP attaquantes (semaine)."""
    since = timezone.now() - timedelta(days=7)
    rows = (
        Alert.objects.filter(created_at__gte=since)
        .exclude(src_ip__isnull=True).exclude(src_ip="")
        .values("src_ip")
        .annotate(count=Count("id"))
        .order_by("-count")[:10]
    )

    return JsonResponse({
        "categories": [r["src_ip"] for r in rows],
        "series": [{"name": "Alertes", "data": [r["count"] for r in rows]}],
    })


@login_required
def api_top_signatures(request):
    """Bar chart : top 10 signatures declenchees (semaine)."""
    since = timezone.now() - timedelta(days=7)
    rows = (
        Alert.objects.filter(created_at__gte=since)
        .select_related("signature")
        .values("signature__title")
        .annotate(count=Count("id"))
        .order_by("-count")[:10]
    )

    return JsonResponse({
        "categories": [r["signature__title"][:50] or "?" for r in rows],
        "series": [{"name": "Occurrences", "data": [r["count"] for r in rows]}],
    })


@login_required
def api_ai_efficiency(request):
    """Donut chart : repartition origine description (BDD vs cache vs fresh)."""
    since = timezone.now() - timedelta(days=7)
    qs = Alert.objects.filter(created_at__gte=since)

    bdd = qs.filter(ai_status="not_required").count()
    cache = qs.filter(ai_status="cached").count()
    fresh = qs.filter(ai_status="fresh").count()
    failed = qs.filter(ai_status="failed").count()

    return JsonResponse({
        "series": [bdd, cache, fresh, failed],
        "labels": ["📚 Knowledge Base", "🤖 AI Cache", "🤖 AI Fresh", "⚠️ Failed"],
        "colors": ["#6c757d", "#0aa2c0", "#0d6efd", "#dc3545"],
    })
