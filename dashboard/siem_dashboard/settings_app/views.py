"""SIEM Africa - Vues Settings.

Bug v1 fix : la page settings ne doit JAMAIS renvoyer 500.
Toutes les operations sont enveloppees dans des try/except.

  - home : page principale avec tous les reglages
  - test_smtp : envoie un email test
  - test_model : test rapide d'inference Ollama
"""
import requests

from django.conf import settings as dj_settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.views.decorators.http import require_POST

from core.models import Setting, AuditLog


def admin_required(view_func):
    """Decorator : seuls les admins ont acces."""
    return user_passes_test(
        lambda u: u.is_authenticated and u.is_admin,
        login_url="/login/",
    )(view_func)


# ============================================================================
# Definition des reglages affichables
# Chaque dict = un setting avec ses metadonnees
# ============================================================================
SETTINGS_SCHEMA = [
    {
        "section": "Email",
        "icon": "bi-envelope",
        "fields": [
            {"key": "email_enabled",              "type": "bool",   "label": "Notifications email", "default": "true"},
            {"key": "email_min_severity",         "type": "choice", "label": "Severite minimale pour email",
             "default": "INFO", "choices": ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]},
            {"key": "email_rate_limit_per_hour",  "type": "int",    "label": "Rate limit (emails/heure)",
             "default": "30", "help": "0 = pas de limite"},
            {"key": "email_dedup_window_minutes", "type": "int",    "label": "Dedup (minutes)",
             "default": "5",  "help": "0 = pas de dedup"},
            {"key": "email_digest_enabled",       "type": "bool",   "label": "Digest LOW/MEDIUM",  "default": "true"},
            {"key": "email_digest_interval_minutes", "type": "int", "label": "Intervalle digest (min)", "default": "60"},
        ],
    },
    {
        "section": "Intelligence Artificielle",
        "icon": "bi-cpu",
        "fields": [
            {"key": "ai_enabled",                "type": "bool",   "label": "Activer l'enrichissement IA", "default": "true"},
            {"key": "ai_default_model",          "type": "choice", "label": "Modele par defaut",
             "default": "qwen2.5:3b", "choices": ["qwen2.5:3b", "llama3.2:3b"]},
            {"key": "ai_enrich_unknown",         "type": "bool",   "label": "Enrichir les signatures inconnues", "default": "true"},
        ],
    },
    {
        "section": "Securite",
        "icon": "bi-shield",
        "fields": [
            {"key": "ip_block_enabled", "type": "bool", "label": "Blocage IP automatique (CRITICAL)",
             "default": "false", "help": "Off par defaut. Risque de bloquer une IP legitime."},
        ],
    },
]


# ============================================================================
# Page principale
# ============================================================================
@login_required
@admin_required
def home(request):
    """Page parametres."""
    if request.method == "POST":
        return _handle_save(request)

    # Lecture (best effort - on ne plante JAMAIS sur cette page)
    sections = []
    for section in SETTINGS_SCHEMA:
        fields = []
        for field in section["fields"]:
            try:
                value = Setting.get(field["key"], field["default"])
            except Exception:  # noqa: BLE001
                value = field["default"]
            fields.append({**field, "value": value})
        sections.append({
            "section": section["section"],
            "icon": section["icon"],
            "fields": fields,
        })

    # Modeles Ollama disponibles (pour le bouton "Tester")
    available_models = []
    try:
        resp = requests.get(f"{dj_settings.SIEM_OLLAMA_HOST}/api/tags", timeout=2)
        if resp.status_code == 200:
            available_models = [m.get("name") for m in resp.json().get("models", [])]
    except requests.exceptions.RequestException:
        pass

    return render(request, "settings/home.html", {
        "sections": sections,
        "available_models": available_models,
    })


def _handle_save(request):
    """Traite le POST du formulaire de sauvegarde."""
    saved = 0
    errors = []

    for section in SETTINGS_SCHEMA:
        for field in section["fields"]:
            key = field["key"]
            field_type = field["type"]

            if field_type == "bool":
                # Les checkboxes sont absentes du POST quand decoche
                value = "true" if request.POST.get(key) == "on" else "false"
            else:
                value = request.POST.get(key, "").strip()
                if field_type == "int":
                    try:
                        int(value)
                    except (TypeError, ValueError):
                        errors.append(f"{field['label']} : valeur entiere invalide")
                        continue
                elif field_type == "choice":
                    if value not in field.get("choices", []):
                        errors.append(f"{field['label']} : valeur invalide")
                        continue

            try:
                Setting.set(key, value, description=field["label"])
                saved += 1
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{key} : {exc}")

    try:
        AuditLog.objects.create(
            user=request.user, action="settings_updated", resource_type="settings",
            resource_id="(global)", level="INFO",
            details=f"{saved} reglages mis a jour",
        )
    except Exception:  # noqa: BLE001
        pass

    if errors:
        messages.warning(
            request,
            f"{saved} reglages sauves, {len(errors)} erreur(s) : " + "; ".join(errors[:3])
        )
    else:
        messages.success(request, f"{saved} reglages sauvegardes.")

    return redirect("settings_app:home")


# ============================================================================
# Test SMTP - bug v1 #3 fixe (envoi via Python smtplib)
# ============================================================================
@login_required
@admin_required
@require_POST
def test_smtp(request):
    """Envoie un email test au destinataire configure."""
    import smtplib
    import ssl
    from email.message import EmailMessage
    from pathlib import Path

    smtp_path = Path(dj_settings.SIEM_SMTP_CONFIG)
    if not smtp_path.is_file():
        return JsonResponse({
            "ok": False,
            "message": f"Fichier {smtp_path} introuvable. Configurer le SMTP d'abord.",
        })

    # Charger les vars
    cfg = {}
    try:
        with open(smtp_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    cfg[k.strip()] = v.strip().strip("'\"")
    except OSError as exc:
        return JsonResponse({"ok": False, "message": f"Lecture impossible : {exc}"})

    host = cfg.get("SMTP_HOST")
    port = int(cfg.get("SMTP_PORT", "587"))
    user = cfg.get("SMTP_USER")
    password = cfg.get("SMTP_PASS")
    to = cfg.get("SMTP_TO") or user
    use_tls = cfg.get("SMTP_USE_TLS", "true").lower() == "true"

    if not all([host, port, user, password, to]):
        return JsonResponse({
            "ok": False,
            "message": "Config SMTP incomplete (manque host/port/user/pass/to)",
        })

    msg = EmailMessage()
    msg["From"] = cfg.get("SMTP_FROM", user)
    msg["To"] = to
    msg["Subject"] = "[SIEM Africa] Test SMTP"
    msg.set_content(
        "Cet email confirme que la configuration SMTP fonctionne.\n\n"
        f"Host : {host}:{port}\n"
        f"User : {user}\n"
        f"Destinataire : {to}\n\n"
        "Si vous recevez ce message, vos notifications SIEM Africa fonctionnent.\n"
    )

    try:
        if port == 465:
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, context=ctx, timeout=30) as smtp:
                smtp.login(user, password)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=30) as smtp:
                if use_tls:
                    smtp.starttls(context=ssl.create_default_context())
                smtp.login(user, password)
                smtp.send_message(msg)

        AuditLog.objects.create(
            user=request.user, action="smtp_test_sent", resource_type="smtp",
            level="INFO", details=f"Email test envoye a {to}",
        )
        return JsonResponse({"ok": True, "message": f"Email envoye a {to}. Verifier la boite."})

    except smtplib.SMTPAuthenticationError as exc:
        return JsonResponse({"ok": False, "message": f"Authentification refusee : {exc}"})
    except smtplib.SMTPException as exc:
        return JsonResponse({"ok": False, "message": f"Erreur SMTP : {exc}"})
    except OSError as exc:
        return JsonResponse({"ok": False, "message": f"Reseau : {exc}"})


# ============================================================================
# Test modele IA
# ============================================================================
@login_required
@admin_required
@require_POST
def test_model(request):
    """Lance une mini-inference sur un modele Ollama."""
    model = request.POST.get("model", "").strip()
    if not model:
        return JsonResponse({"ok": False, "message": "Modele non specifie"})

    prompt = (
        "Repondre en francais avec exactement cette phrase : "
        "'Le test fonctionne. Modele en ligne.'"
    )

    try:
        resp = requests.post(
            f"{dj_settings.SIEM_OLLAMA_HOST}/api/generate",
            json={
                "model": model, "prompt": prompt, "stream": False,
                "options": {"temperature": 0.1, "num_predict": 50},
            },
            timeout=60,
        )
        if resp.status_code != 200:
            return JsonResponse({
                "ok": False,
                "message": f"HTTP {resp.status_code} : {resp.text[:200]}",
            })

        data = resp.json()
        text = (data.get("response") or "").strip()
        elapsed_ms = int(data.get("total_duration", 0) / 1_000_000)

        return JsonResponse({
            "ok": True,
            "message": f"Modele {model} repond ({elapsed_ms} ms)",
            "response": text[:300],
        })
    except requests.exceptions.Timeout:
        return JsonResponse({"ok": False, "message": "Timeout (60s) - modele trop lent"})
    except requests.exceptions.RequestException as exc:
        return JsonResponse({"ok": False, "message": f"Erreur reseau : {exc}"})
