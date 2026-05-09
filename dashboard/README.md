# SIEM Africa - Module 4 - Dashboard Django

Interface web complete pour le SIEM Africa : alertes, KPI, sante systeme,
parametres, logs admin.

## Prerequis

- **Module 1** installe (Wazuh + Snort + groupe `siem-africa`)
- **Module 2** installe (BDD SQLite a `/var/lib/siem-africa/siem.db`)
- **Module 3** recommande (agent qui genere les alertes)
- **Ubuntu** 20.04 / 22.04 / 24.04
- **2 Go RAM minimum**

## Installation

```bash
cd ~/dashboard
chmod +x install_dashboard.sh verify_dashboard.sh tests/*.sh
sudo ./install_dashboard.sh
```

L'installeur :

1. Verifie tous les prerequis
2. Installe les dependances (Python, Nginx, Gunicorn)
3. Cree l'utilisateur `siem-dashboard`
4. Copie le code dans `/opt/siem-africa-dashboard/`
5. Cree un venv Python avec Django + Gunicorn
6. Applique les migrations Django (sessions, contenttypes...)
7. Demande email + mot de passe admin (stockes dans `/root/siem_credentials.txt`)
8. Configure Gunicorn (port 8000) + Nginx (port 80)
9. Demarre les services
10. Lance les tests automatiques

## URLs principales

| URL | Page | Acces |
|---|---|---|
| `/` | Redirige vers `/alerts/` | Tous |
| `/login/` | Connexion | Public |
| `/alerts/` | Liste des alertes (DataTables) | Tous |
| `/alerts/<id>/` | Detail alerte + bouton Re-analyser | Tous |
| `/kpi/` | Tableau de bord KPI (6 graphiques ApexCharts) | Tous |
| `/health/` | Sante systeme (Wazuh, Snort, Ollama, SMTP, agent) | Tous |
| `/settings/` | Reglages + Test SMTP + Test modele IA | Admins |
| `/about/` | Presentation (4 pays + stats) | Tous |
| `/admin-logs/` | Audit + emails + log agent live | Admins |
| `/profile/` | Mon profil (theme, langue, password) | Tous |
| `/django-admin/` | Admin Django (debug) | Superusers |

## Architecture

```
                    Internet / LAN
                          │
                          ▼
                  ┌──────────────┐
                  │    Nginx     │  port 80 (reverse proxy + statics)
                  └──────┬───────┘
                         │
                  ┌──────┴───────┐
                  │  Gunicorn    │  port 8000 (3 workers)
                  └──────┬───────┘
                         │
                  ┌──────┴───────┐
                  │    Django    │  apps : core, users, alerts, kpi,
                  │              │         health, settings_app,
                  │              │         about, admin_logs
                  └──────┬───────┘
                         │
                  ┌──────┴───────┐
                  │   SQLite     │  /var/lib/siem-africa/siem.db
                  │  (M2 owned)  │  partagee avec M2 et M3
                  └──────────────┘
```

**Pourquoi Nginx en plus de Gunicorn ?** Nginx sert les statics tres rapidement
et fait office de reverse proxy. Gunicorn fait tourner Django.

## Caracteristiques

- **Theme light/dark** (toggle dans la navbar)
- **Multilingue** : FR (defaut) + EN (menus)
- **Responsive** : mobile + tablette + desktop
- **DataTables** : recherche, tri, pagination sur les listes
- **ApexCharts** : 6 graphiques sur la page KPI
- **Auto-refresh** : pages alerts/health (10-30s)
- **Tests automatiques** : 5 suites de tests anti-regression

## Bugs v1 corriges

| Bug | Fix |
|---|---|
| Pas de description dans l'UI | `Alert.get_description()` priorite IA, fallback BDD, fallback dynamique |
| `/settings/` renvoyait HTTP 500 | Toutes les operations en `try/except`, fallbacks systematiques |
| Agent n'envoyait pas d'email | Module 3 corrige + bouton **Test SMTP** dans `/settings/` |
| L'IA ne repondait pas | Bouton **Re-analyser** + bouton **Tester ce modele** |

## Verification

```bash
sudo ./verify_dashboard.sh           # Verification rapide post-install
sudo ./tests/run_all_tests.sh        # 5 suites de tests
```

## Commandes utiles

```bash
# Status
sudo systemctl status siem-dashboard

# Logs
sudo tail -f /var/log/siem-africa/dashboard-error.log
sudo tail -f /var/log/siem-africa/nginx-error.log

# Restart
sudo systemctl restart siem-dashboard
sudo systemctl reload nginx

# Recreer un admin (si oublie)
sudo -u siem-dashboard /opt/siem-africa-dashboard/venv/bin/python \
    /opt/siem-africa-dashboard/manage.py shell

# Acces shell Django
cd /opt/siem-africa-dashboard
sudo -u siem-dashboard bash -c "
    set -a; . /etc/siem-africa/dashboard.env; set +a
    /opt/siem-africa-dashboard/venv/bin/python manage.py shell
"
```

## Configuration

| Fichier | Role |
|---|---|
| `/etc/siem-africa/dashboard.env` | Config Django (SECRET_KEY, paths, etc.) |
| `/etc/nginx/sites-available/siem-africa` | Config Nginx |
| `/etc/systemd/system/siem-dashboard.service` | Unit systemd Gunicorn |
| Table `settings` (BDD) | Reglages dynamiques (changeables via `/settings/`) |

## Tests automatiques (5 suites)

| # | Suite | Verifie |
|---|---|---|
| 1 | `test_01_django_check.sh` | `manage.py check` + tables critiques + admin existe |
| 2 | `test_02_pages_load.sh` | `/login/`, `/alerts/`, statics, 404 |
| 3 | `test_03_auth.sh` | Login flow complet (CSRF + cookies + bad password) |
| 4 | `test_04_settings_no500.sh` | **ANTI-REGRESSION bug v1** + valeur BDD invalide tolerees |
| 5 | `test_05_test_smtp.sh` | Tous les endpoints API (KPI + admin logs) + bouton SMTP |

## Desinstallation

```bash
sudo systemctl stop siem-dashboard
sudo systemctl disable siem-dashboard
sudo rm /etc/systemd/system/siem-dashboard.service
sudo rm /etc/nginx/sites-enabled/siem-africa
sudo rm /etc/nginx/sites-available/siem-africa
sudo systemctl daemon-reload
sudo systemctl reload nginx
sudo rm -rf /opt/siem-africa-dashboard
sudo rm /etc/siem-africa/dashboard.env  # optionnel
```
