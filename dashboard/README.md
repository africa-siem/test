# SIEM Africa — Module 4 : Dashboard (Lots 1 à 5 — complet)

Interface web Django pour consulter et piloter la solution SIEM Africa.
Ce dépôt correspond au **Lot 1** : authentification, connexion, changement de
mot de passe forcé, layout général et page profil.

## Ce que contient le Lot 1

- Connexion par email + mot de passe (hash argon2id)
- Politique de sécurité : 5 tentatives max, blocage 30 min, session 2 h,
  expiration du mot de passe à 90 jours
- Changement de mot de passe obligatoire à la première connexion
- Layout responsive avec menu latéral qui s'adapte au rôle de l'utilisateur
- Thème sombre / clair
- Bilingue français / anglais (bascule dynamique)
- Page « Mon profil » (préférences langue, thème, infos personnelles)


## Ce que contient le Lot 2 (tableau de bord)

- Tableau de bord ADMIN/ANALYST/OPERATOR : 4 compteurs de sévérité avec
  tendance vs période précédente, graphique des alertes sur 7 jours (Chart.js),
  score de sécurité 0-100, dernières alertes critiques, top catégories
  d'attaques, top IPs attaquantes avec pays, état des services
- Tableau de bord DIRIGEANT (VIEWER) : score en grand avec message rassurant
  adapté au niveau, 3 indicateurs business (attaques bloquées, compromissions,
  disponibilité), graphique d'évolution des menaces (thème violet)
- Auto-refresh automatique toutes les 30 secondes
- Chart.js embarqué en local (static/js/chart.umd.js) — fonctionne hors ligne
- Tous les indicateurs calculés en temps réel depuis les tables (pas de
  dépendance au worker kpi_history)


## Ce que contient le Lot 3 (alertes, incidents, chat IA)

- Liste des alertes paginée (25/page) avec filtres : sévérité, statut, source,
  période, recherche texte (IP, titre, signature)
- Tags visuels : HONEYPOT, CORRÉLÉE, INCONNUE
- Détail d'une alerte : contexte technique, technique MITRE ATT&CK,
  recommandations numérotées, alertes liées (même IP), actions (acquitter,
  investiguer, résoudre, faux positif) selon le rôle
- Liste et détail des incidents avec alertes corrélées
- Chat IA contextuel AVEC historique (niveau 2) sur les pages de détail
  alerte et incident, réservé aux rôles ADMIN et ANALYST
- Les tables de chat (chat_conversations, chat_messages) sont créées
  automatiquement par le dashboard (CREATE TABLE IF NOT EXISTS) sans modifier
  les fichiers SQL du Module 2
- Dégradation gracieuse : si Ollama est indisponible, le chat affiche un
  message clair au lieu de planter


## Ce que contient le Lot 4 (IPs, signatures, utilisateurs, assistant IA)

- IPs bloquées : liste filtrable (actives/toutes), déblocage manuel, blocage
  manuel d'une IP. Le dashboard marque le déblocage ; l'agent M3 applique la
  règle iptables.
- Signatures : consultation des 380 signatures (Wazuh + Snort) avec filtres
  source/sévérité/catégorie/recherche et compteur de déclenchements.
- Utilisateurs (ADMIN uniquement) : création de comptes avec mot de passe
  temporaire généré automatiquement, activation/désactivation, déverrouillage,
  réinitialisation de mot de passe. Un admin ne peut pas se désactiver lui-même.
- Assistant IA dédié (ADMIN + ANALYST) : page de chat avec historique des
  conversations dans une barre latérale, comme une messagerie. On rouvre une
  conversation et on poursuit le fil.


## Ce que contient le Lot 5 (paramètres, rapports, audit, déploiement)

- Paramètres (ADMIN seul) : 6 onglets (Notifications email/SMTP, IA, Réponse
  active, Corrélation, Rétention, Système). Les mots de passe ne sont jamais
  réaffichés ; laisser vide pour conserver la valeur existante.
- Rapports : génération PDF (reportlab) et Excel (openpyxl) sur 7 ou 30 jours,
  liste des rapports avec téléchargement. Génération automatique prévue chaque
  lundi à 8h (via tâche planifiée côté agent/cron).
- Journal d'audit (ADMIN + ANALYST) : consultation des actions tracées, avec
  filtres par catégorie et par utilisateur.
- Script d'installation install_dashboard.sh : déploiement complet en service
  systemd + Gunicorn + Nginx, création des tables de chat, utilisateur dédié,
  détection et remplacement propre d'une installation précédente.

## Déploiement en production (sur la VM)

```bash
sudo bash install_dashboard.sh
```

Le script installe tout, pointe sur /var/lib/siem-africa/siem.db, et démarre
le service. Le dashboard est ensuite accessible sur http://<serveur>/ avec le
compte ADMIN créé à l'installation du Module 2.

## Prérequis

- Python 3.10 ou supérieur
- La base SQLite du Module 2 doit exister (avec au moins un compte ADMIN)

## Installation en développement

```bash
# 1. Installer les dépendances
pip install -r requirements.txt

# 2. Indiquer le chemin de la base partagée (Module 2)
export SIEM_DB_PATH="/chemin/vers/siem.db"

# 3. Lancer le serveur de développement
python3 manage.py runserver 0.0.0.0:8000
```

Le dashboard est alors accessible sur http://localhost:8000

## Variables d'environnement

| Variable | Rôle | Défaut |
|----------|------|--------|
| `SIEM_DB_PATH` | Chemin de la base SQLite partagée | `/var/lib/siem-africa/siem.db` |
| `DJANGO_SECRET_KEY` | Clé secrète Django (à définir en production) | clé de dev |
| `DJANGO_DEBUG` | Mode debug (`true`/`false`) | `true` |
| `DJANGO_ALLOWED_HOSTS` | Hôtes autorisés, séparés par virgule | `*` |
| `SIEM_SESSION_PATH` | Dossier de stockage des sessions | `.sessions/` |

## Architecture du code

```
config/          Configuration Django (settings, urls, wsgi)
core/
  models.py      Modèles mappés sur les tables du Module 2 (managed = False)
  auth.py        Authentification argon2id + politique de sécurité
  decorators.py  Protection des vues (login_required, permission_required)
  i18n.py        Traductions FR / EN
  context_processors.py  Données communes aux templates (menu, user, langue)
  views.py       Vues : login, logout, changement MDP, dashboard, profil
templates/       Gabarits HTML
static/css/      Feuille de style (thèmes sombre / clair)
```

## Points importants

- **Aucune migration Django** : tous les modèles sont en `managed = False`.
  Django ne crée ni ne modifie jamais les tables ; il lit et écrit dans les
  tables existantes du Module 2. La base reste partagée avec l'agent (Module 3)
  sans risque de conflit de schéma.
- **Mode WAL** activé sur SQLite pour permettre à l'agent (qui écrit) et au
  dashboard (qui lit/écrit) de coexister sans verrouillage prolongé.
- **Sessions stockées en fichiers** (pas en base) pour ne créer aucune table
  supplémentaire dans la base du Module 2.

## Lots suivants (à venir)

- Lot 2 : tableau de bord avec indicateurs, graphiques et carte des attaques
- Lot 3 : alertes, incidents et chat IA contextuel
- Lot 4 : IPs bloquées, signatures, gestion des utilisateurs
- Lot 5 : paramètres, rapports PDF/Excel, audit, script d'installation
