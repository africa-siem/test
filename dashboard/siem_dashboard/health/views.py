"""SIEM Africa - Vues Health.

Verifie l'etat de chaque composant :
  - DB SQLite (acces)
  - Service Wazuh (alerts.json mtime)
  - Service Snort (alert log mtime)
  - Service Ollama (API ping + modeles)
  - SMTP (config presente)
  - Agent (process actif)
"""
import os
import shutil
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

import requests

from django.conf import settings as dj_settings
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.utils import timezone

from core.models import Alert, EmailLog, Setting


# ============================================================================
# Page principale
# ============================================================================
@login_required
def status(request):
    """Page sante - status temps reel de chaque composant."""
    components = [
        _check_db(),
        _check_wazuh(),
        _check_snort(),
        _check_ollama(),
        _check_smtp(),
        _check_agent(),
    ]

    # Stats systeme
    system_stats = _get_system_stats()

    # Stats activite recente
    activity = _get_activity_stats()

    return render(request, "health/status.html", {
        "components": components,
        "system_stats": system_stats,
        "activity": activity,
    })


# ============================================================================
# Checkers
# ============================================================================
def _check_db():
    """Verifie l'acces a la BDD."""
    try:
        Alert.objects.count()  # query simple
        return {
            "name": "Base de donnees SQLite",
            "icon": "bi-database",
            "status": "up",
            "message": "Acces lecture/ecriture OK",
            "details": [("Path", dj_settings.DB_PATH)],
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "name": "Base de donnees SQLite",
            "icon": "bi-database",
            "status": "down",
            "message": str(exc)[:200],
            "details": [],
        }


def _check_wazuh():
    """Verifie que Wazuh genere des alertes (mtime alerts.json recent)."""
    path = Path(dj_settings.SIEM_WAZUH_ALERTS)
    if not path.is_file():
        return {
            "name": "Wazuh Manager",
            "icon": "bi-shield-shaded",
            "status": "down",
            "message": f"Fichier introuvable : {path}",
            "details": [],
        }

    try:
        stat = path.stat()
        mtime = datetime.fromtimestamp(stat.st_mtime)
        age = datetime.now() - mtime
        size_mb = stat.st_size / 1024 / 1024

        # Si pas de modif depuis > 1h, on signale degraded
        if age > timedelta(hours=1):
            status = "degraded"
            message = f"Pas d'activite depuis {_format_age(age)}"
        else:
            status = "up"
            message = f"Derniere activite il y a {_format_age(age)}"

        return {
            "name": "Wazuh Manager",
            "icon": "bi-shield-shaded",
            "status": status,
            "message": message,
            "details": [
                ("Fichier", str(path)),
                ("Taille", f"{size_mb:.1f} MB"),
                ("Derniere maj", mtime.strftime("%Y-%m-%d %H:%M:%S")),
            ],
        }
    except OSError as exc:
        return {
            "name": "Wazuh Manager",
            "icon": "bi-shield-shaded",
            "status": "down",
            "message": str(exc),
            "details": [],
        }


def _check_snort():
    """Verifie le log Snort."""
    path = Path("/var/log/snort/alert")
    if not path.is_file():
        return {
            "name": "Snort IDS",
            "icon": "bi-radar",
            "status": "degraded",
            "message": f"Fichier {path} absent",
            "details": [],
        }

    try:
        stat = path.stat()
        mtime = datetime.fromtimestamp(stat.st_mtime)
        age = datetime.now() - mtime
        size_kb = stat.st_size / 1024

        return {
            "name": "Snort IDS",
            "icon": "bi-radar",
            "status": "up" if age < timedelta(days=1) else "degraded",
            "message": f"Log mis a jour il y a {_format_age(age)}",
            "details": [
                ("Fichier", str(path)),
                ("Taille", f"{size_kb:.1f} KB"),
                ("Derniere maj", mtime.strftime("%Y-%m-%d %H:%M:%S")),
            ],
        }
    except OSError as exc:
        return {
            "name": "Snort IDS",
            "icon": "bi-radar",
            "status": "down",
            "message": str(exc),
            "details": [],
        }


def _check_ollama():
    """Verifie l'API Ollama + liste les modeles."""
    try:
        resp = requests.get(f"{dj_settings.SIEM_OLLAMA_HOST}/api/tags", timeout=3)
        if resp.status_code != 200:
            raise requests.exceptions.RequestException(f"HTTP {resp.status_code}")
        data = resp.json()
        models = [m.get("name", "?") for m in data.get("models", [])]
        return {
            "name": "Ollama (IA locale)",
            "icon": "bi-cpu",
            "status": "up",
            "message": f"{len(models)} modele(s) installe(s)",
            "details": [
                ("API", dj_settings.SIEM_OLLAMA_HOST),
                ("Modeles", ", ".join(models) or "(aucun)"),
                ("Modele par defaut", Setting.get("ai_default_model", "qwen2.5:3b")),
            ],
        }
    except requests.exceptions.RequestException as exc:
        return {
            "name": "Ollama (IA locale)",
            "icon": "bi-cpu",
            "status": "down",
            "message": f"API ne repond pas : {exc}",
            "details": [
                ("API", dj_settings.SIEM_OLLAMA_HOST),
                ("Mode degrade", "Active (l'agent continue sans IA)"),
            ],
        }


def _check_smtp():
    """Verifie la config SMTP."""
    smtp_path = Path(dj_settings.SIEM_SMTP_CONFIG)
    if not smtp_path.is_file():
        return {
            "name": "SMTP (notifications email)",
            "icon": "bi-envelope",
            "status": "down",
            "message": f"Fichier {smtp_path} absent",
            "details": [],
        }

    try:
        # Lit le fichier sans le copier en memoire
        config = {}
        with open(smtp_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    config[k.strip()] = v.strip().strip("'\"")

        return {
            "name": "SMTP (notifications email)",
            "icon": "bi-envelope",
            "status": "up",
            "message": f"Configure : {config.get('SMTP_HOST', '?')}",
            "details": [
                ("Host", config.get("SMTP_HOST", "?")),
                ("Port", config.get("SMTP_PORT", "?")),
                ("User", config.get("SMTP_USER", "?")),
                ("Destinataire", config.get("SMTP_TO", "?")),
            ],
        }
    except (OSError, PermissionError) as exc:
        return {
            "name": "SMTP",
            "icon": "bi-envelope",
            "status": "degraded",
            "message": f"Lecture impossible : {exc}",
            "details": [],
        }


def _check_agent():
    """Verifie que l'agent siem-agent est actif via systemctl."""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "siem-agent"],
            capture_output=True, text=True, timeout=5,
        )
        active = result.stdout.strip() == "active"

        # Recuperer aussi le pid via systemctl show
        details = [("Service", "siem-agent.service")]
        if active:
            try:
                show = subprocess.run(
                    ["systemctl", "show", "siem-agent", "--property=MainPID,ActiveEnterTimestamp,MemoryCurrent"],
                    capture_output=True, text=True, timeout=5,
                )
                for line in show.stdout.strip().split("\n"):
                    if "=" in line:
                        k, _, v = line.partition("=")
                        if k == "MainPID":
                            details.append(("PID", v))
                        elif k == "ActiveEnterTimestamp":
                            details.append(("Demarre", v))
                        elif k == "MemoryCurrent" and v.isdigit():
                            details.append(("Memoire", f"{int(v) / 1024 / 1024:.1f} MB"))
            except (OSError, subprocess.SubprocessError):
                pass

        return {
            "name": "Agent SIEM Africa (siem-agent)",
            "icon": "bi-robot",
            "status": "up" if active else "down",
            "message": "Service actif" if active else f"Statut : {result.stdout.strip()}",
            "details": details,
        }
    except (FileNotFoundError, subprocess.SubprocessError) as exc:
        return {
            "name": "Agent SIEM Africa",
            "icon": "bi-robot",
            "status": "degraded",
            "message": f"systemctl indisponible : {exc}",
            "details": [],
        }


# ============================================================================
# Helpers
# ============================================================================
def _format_age(delta):
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} min"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h"
    days = hours // 24
    return f"{days}j"


def _get_system_stats():
    """Stats CPU / RAM / Disque (best effort)."""
    stats = {}
    try:
        with open("/proc/loadavg") as f:
            stats["load"] = f.read().split()[0]
    except OSError:
        stats["load"] = "?"

    try:
        with open("/proc/meminfo") as f:
            mem = {}
            for line in f:
                k, _, v = line.partition(":")
                mem[k.strip()] = v.strip()
            total = int(mem.get("MemTotal", "0").split()[0])
            avail = int(mem.get("MemAvailable", "0").split()[0])
            used_pct = ((total - avail) / total * 100) if total else 0
            stats["mem_used_pct"] = round(used_pct, 1)
            stats["mem_total_mb"] = total // 1024
    except (OSError, ValueError, IndexError):
        stats["mem_used_pct"] = 0
        stats["mem_total_mb"] = 0

    try:
        usage = shutil.disk_usage("/")
        stats["disk_used_pct"] = round((usage.used / usage.total) * 100, 1)
        stats["disk_total_gb"] = usage.total // (1024 ** 3)
        stats["disk_free_gb"] = usage.free // (1024 ** 3)
    except OSError:
        stats["disk_used_pct"] = 0
        stats["disk_total_gb"] = 0
        stats["disk_free_gb"] = 0

    return stats


def _get_activity_stats():
    """Compte les events recents."""
    now = timezone.now()
    h1 = now - timedelta(hours=1)
    return {
        "alerts_last_hour": Alert.objects.filter(created_at__gte=h1).count(),
        "emails_last_hour": EmailLog.objects.filter(created_at__gte=h1, status="sent").count(),
        "emails_failed_last_hour": EmailLog.objects.filter(
            created_at__gte=h1
        ).exclude(status="sent").count(),
    }
