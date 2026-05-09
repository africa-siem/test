"""SIEM Africa - Vues Alerts.

  - list_view  : liste paginee + filtres + DataTables
  - detail_view: detail d'une alerte + boutons actions
  - re_analyze : relance l'enrichissement IA via Ollama
  - update_status : marquer alerte (vue, fausse, resolue)
"""
import json
import re
import threading
from datetime import timedelta

from django.conf import settings as dj_settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404, redirect
from django.utils import timezone
from django.views.decorators.http import require_POST

from core.models import Alert, AuditLog, Setting


# ============================================================================
# LISTE
# ============================================================================
@login_required
def list_view(request):
    """Liste des alertes avec filtres simples + DataTables (cote client)."""

    severity = request.GET.get("severity", "")
    status = request.GET.get("status", "")
    period = request.GET.get("period", "24h")  # 24h | 7d | 30d | all

    qs = Alert.objects.select_related("signature").order_by("-created_at")

    if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        qs = qs.filter(severity=severity)

    if status in ("NEW", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"):
        qs = qs.filter(status=status)

    now = timezone.now()
    if period == "24h":
        qs = qs.filter(created_at__gte=now - timedelta(hours=24))
    elif period == "7d":
        qs = qs.filter(created_at__gte=now - timedelta(days=7))
    elif period == "30d":
        qs = qs.filter(created_at__gte=now - timedelta(days=30))

    alerts = list(qs[:1000])  # garde-fou : max 1000 lignes en memoire

    stats = {
        "total": len(alerts),
        "critical": sum(1 for a in alerts if a.severity == "CRITICAL"),
        "high": sum(1 for a in alerts if a.severity == "HIGH"),
        "new": sum(1 for a in alerts if a.status == "NEW"),
        "ai_pending": sum(1 for a in alerts if a.ai_status == "pending"),
    }

    return render(request, "alerts/list.html", {
        "alerts": alerts,
        "stats": stats,
        "filter_severity": severity,
        "filter_status": status,
        "filter_period": period,
    })


# ============================================================================
# DETAIL
# ============================================================================
@login_required
def detail_view(request, alert_id):
    """Detail d'une alerte + remediation IA + boutons actions."""
    alert = get_object_or_404(
        Alert.objects.select_related("signature", "ai_cache"),
        pk=alert_id,
    )

    # Auto-marquer comme vue si NEW
    if alert.status == "NEW":
        try:
            alert.status = "ACKNOWLEDGED"
            alert.acknowledged_by = request.user
            alert.acknowledged_at = timezone.now()
            alert.save(update_fields=["status", "acknowledged_by", "acknowledged_at"])
        except Exception:  # noqa: BLE001
            pass

    enriched = None
    if alert.enriched_data:
        try:
            enriched = json.loads(alert.enriched_data)
        except (json.JSONDecodeError, TypeError):
            enriched = {"text": alert.enriched_data[:1000]}

    return render(request, "alerts/detail.html", {
        "alert": alert,
        "enriched": enriched,
    })


# ============================================================================
# RE-ANALYZE
# ============================================================================
@login_required
@require_POST
def re_analyze_view(request, alert_id):
    """Force une nouvelle analyse IA pour cette alerte."""
    alert = get_object_or_404(Alert, pk=alert_id)
    user = request.user

    if not user.is_analyst:
        messages.error(request, "Droit insuffisant pour relancer une analyse.")
        return redirect("alerts:detail", alert_id=alert_id)

    # Marquer pending
    alert.ai_status = "pending"
    alert.ai_description = "Re-analyse en cours..."
    alert.save(update_fields=["ai_status", "ai_description"])

    # Invalider le cache lie
    if alert.ai_cache_id:
        try:
            alert.ai_cache.delete()
        except Exception:  # noqa: BLE001
            pass

    # Lancer le worker async
    threading.Thread(
        target=_re_analyze_worker, args=(alert.id,), daemon=True
    ).start()

    AuditLog.objects.create(
        user=user, action="alert_reanalyze", resource_type="alert",
        resource_id=str(alert.id), level="INFO",
        details=f"Re-analyse forcee par {user.email}",
    )

    messages.success(request, "Re-analyse lancee. La page se rafraichira dans 10s.")
    return redirect("alerts:detail", alert_id=alert_id)


def _re_analyze_worker(alert_id):
    """Thread qui appelle Ollama et met a jour l'alerte."""
    import requests

    try:
        alert = Alert.objects.select_related("signature").get(pk=alert_id)
    except Alert.DoesNotExist:
        return

    sig = alert.signature
    raw_msg = (alert.description or alert.title or "")[:500]

    prompt = (
        "Tu es un analyste cybersecurite expert. Une alerte vient d'etre detectee.\n\n"
        f"ALERTE :\n- Source : {sig.source}\n- Rule ID : {sig.rule_id}\n"
        f"- Severite : {alert.severity}\n- Message : {raw_msg}\n"
        f"- IP src : {alert.src_ip or '?'}\n- IP dst : {alert.dst_ip or '?'}\n\n"
        "EN FRANCAIS, fournis EXACTEMENT ce JSON et rien d'autre :\n"
        '{"description":"<2-3 phrases>",'
        '"severity":"<INFO|LOW|MEDIUM|HIGH|CRITICAL>",'
        '"remediation":["<reco 1>","<reco 2>","<reco 3>"]}'
    )

    model = Setting.get("ai_default_model", "qwen2.5:3b")
    try:
        resp = requests.post(
            f"{dj_settings.SIEM_OLLAMA_HOST}/api/generate",
            json={
                "model": model, "prompt": prompt, "stream": False,
                "options": {"temperature": 0.3, "num_predict": 400},
            },
            timeout=60,
        )
        if resp.status_code == 200:
            text = resp.json().get("response", "")
            parsed = _parse_ai_response(text)
            if parsed:
                alert.ai_status = "fresh"
                alert.ai_description = parsed["description"]
                alert.ai_severity = parsed["severity"]
                alert.ai_remediation = json.dumps(
                    parsed["remediation"], ensure_ascii=False
                )
                alert.ai_model_used = model
                alert.ai_processed_at = timezone.now()
                alert.save()
                return
    except Exception:  # noqa: BLE001
        pass

    alert.ai_status = "failed"
    alert.ai_description = "Echec de la re-analyse. Verifier qu'Ollama est actif."
    alert.save(update_fields=["ai_status", "ai_description"])


def _parse_ai_response(text):
    """Parse defensif de la reponse JSON Ollama."""
    if not text:
        return None
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        text = match.group(0)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    desc = (data.get("description") or "").strip()
    if not desc:
        return None
    severity = (data.get("severity") or "MEDIUM").upper()
    if severity not in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
        severity = "MEDIUM"
    remediation = data.get("remediation") or []
    if not isinstance(remediation, list):
        remediation = [str(remediation)] if remediation else []
    remediation = [str(r).strip() for r in remediation if r and str(r).strip()]
    if not remediation:
        remediation = ["Verifier l'alerte manuellement."]
    return {"description": desc, "severity": severity, "remediation": remediation}


# ============================================================================
# UPDATE STATUS (resolu / faux positif)
# ============================================================================
@login_required
@require_POST
def update_status_view(request, alert_id):
    """Marque une alerte (resolved, false_positive, investigating)."""
    alert = get_object_or_404(Alert, pk=alert_id)
    new_status = request.POST.get("status", "").upper()
    notes = request.POST.get("notes", "").strip()

    valid = {"ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}
    if new_status not in valid:
        messages.error(request, "Statut invalide.")
        return redirect("alerts:detail", alert_id=alert_id)

    if not request.user.is_analyst:
        messages.error(request, "Droit insuffisant.")
        return redirect("alerts:detail", alert_id=alert_id)

    alert.status = new_status
    if notes:
        alert.resolution_notes = notes
    if new_status in ("RESOLVED", "FALSE_POSITIVE"):
        alert.resolved_at = timezone.now()
    alert.save()

    AuditLog.objects.create(
        user=request.user, action=f"alert_status_{new_status.lower()}",
        resource_type="alert", resource_id=str(alert.id),
        level="INFO",
        details=f"Statut: {new_status}. Notes: {notes[:200]}",
    )

    label = {
        "ACKNOWLEDGED": "marquee comme vue",
        "INVESTIGATING": "marquee en investigation",
        "RESOLVED": "marquee resolue",
        "FALSE_POSITIVE": "marquee comme faux positif",
    }[new_status]

    messages.success(request, f"Alerte #{alert.id} {label}.")
    return redirect("alerts:detail", alert_id=alert_id)
