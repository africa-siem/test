# Module 2 — Base de données

> **SIEM Africa** — Module de gestion de la base de données SQLite

## 🎯 Présentation

Ce module crée la base de données centrale du SIEM Africa. Elle stocke :

- Les **alertes** détectées par Wazuh et Snort
- Le référentiel **MITRE ATT&CK** (14 tactiques, 137 techniques)
- **380 signatures** de détection (190 Wazuh + 190 Snort)
- Les **utilisateurs** du dashboard (RBAC à 4 rôles)
- Les **paramètres** dynamiques (multi-modèles IA, thème, SMTP...)
- Les **4 pays cibles** d'Afrique Centrale
- L'historique des **KPI** quotidiens
- Le **journal d'audit** complet

## 🏗️ Architecture

```
/var/lib/siem-africa/
├── siem.db          ← Base SQLite principale (660 siem-db:siem-africa)
├── siem.db-wal      ← Write-Ahead Log (concurrence)
└── siem.db-shm      ← Shared memory

/var/log/siem-africa/  ← Logs partagés tous modules (770)
/etc/siem-africa/      ← Configurations partagées (750)
/root/siem_credentials.txt  ← Credentials générés (600)
```

## 📊 Schéma

| Domaine | Tables |
|---|---|
| **Détection** | mitre_tactics, mitre_techniques, signature_categories, signatures |
| **Événements** | raw_events, alerts, incidents, assets |
| **Réponse** | alert_filters, blocked_ips, ai_explanations |
| **Honeypot/Threat Intel** | honeypot_hits, ip_reputation, threat_intel |
| **Workflow (RBAC)** | roles, users, user_sessions, notifications |
| **Audit & Config** | audit_log, email_logs, settings, reports |
| **Marché cible & KPI** | countries, kpi_history |

**Total : 24 tables, 4 vues, 9 triggers, 87 index**

## 🚀 Installation

### Prérequis

- Ubuntu 22.04 LTS ou 24.04 LTS
- Module 1 (Wazuh + Snort) installé
- Droits root (sudo)

### Lancement

```bash
cd ~/africa-siem/database
chmod +x install_database.sh verify.sh tests/*.sh
sudo ./install_database.sh
```

Le script vous demandera :

1. Un email administrateur
2. Prénom et nom
3. Mot de passe (min 8 caractères, hashé en argon2id)
4. Nom de l'organisation
5. Pays principal (Cameroun, Gabon, Congo, ou RDC)

### Vérification

```bash
sudo ./verify.sh
```

Vérifie que :
- Le groupe `siem-africa` existe
- L'utilisateur `siem-db` existe
- La BDD est créée avec les bonnes permissions
- Les 380 signatures sont chargées
- Les 4 pays sont présents
- L'admin est créé avec un hash argon2id

### Tests de régression

```bash
sudo ./tests/run_all_tests.sh
```

Lance les 7 suites de tests :

| # | Test | Vérifie |
|---|---|---|
| 01 | Schéma | 24 tables, 4 vues, 9 triggers, FK OK, mode WAL |
| 02 | Signatures | 380 signatures, FK valides, UUIDs uniques |
| 03 | MITRE | 14 tactiques, 137 techniques, mappings |
| 04 | Users | 4 rôles, admin créé, hash argon2id, must_change_pwd=1 |
| 05 | Pays | 4 pays Afrique Centrale, données complètes |
| 06 | Settings | Multi-modèles IA, theme toggle, SMTP, rétention |
| 07 | SMTP | msmtp installé, config valide |

### Configuration SMTP

Le Module 2 installe **msmtp** (relais SMTP léger). Pour le configurer :

```bash
sudo ./configure_smtp.sh
```

L'assistant interactif vous demandera :

1. **Type de serveur** : Gmail, Outlook/Office365, SendGrid, ou Custom
2. **Email expéditeur** (compte qui envoie les alertes)
3. **Mot de passe** (App Password recommandé)
4. **Destinataires** des alertes
5. **Sévérité minimale** pour envoyer un email

À la fin, un email de test est envoyé pour valider la config.

#### Pour Gmail (le plus courant)

1. Activez la **double authentification** sur votre compte Gmail
2. Créez un **App Password** : https://myaccount.google.com/apppasswords
3. Sélectionnez "Mail" → "Autre" → "SIEM Africa"
4. Copiez le mot de passe à 16 caractères généré
5. Lancez `./configure_smtp.sh` et utilisez ce mot de passe

#### Pour Outlook/Office 365

1. Activez la **double authentification**
2. Créez un **App Password** : https://account.microsoft.com/security/app-passwords
3. Lancez `./configure_smtp.sh` et utilisez ce mot de passe

#### Test manuel

```bash
echo "Test SIEM Africa" | mail -s "Test" votre-email@example.com
```

#### Logs SMTP

```bash
sudo tail -f /var/log/siem-africa/msmtp.log
```

## 🛡️ Sécurité

### Permissions

```
Groupe siem-africa (système)  ← partagé entre tous les modules
├── User siem-db               ← propriétaire BDD
├── User siem-agent            ← Module 3 (lecture+écriture BDD)
└── User siem-dashboard        ← Module 4 (lecture+écriture BDD)
```

### Mots de passe

- Hash : **argon2id** (recommandé OWASP)
- Paramètres : `m=65536, t=3, p=4`
- Salt : 16 octets aléatoires (urandom)
- Sel inclus dans le hash (format PHC)

### Audit

Toutes les actions importantes sont loggées dans `audit_log` :
- Connexions utilisateur (succès et échecs)
- Modifications d'alertes
- Création/modification d'utilisateurs
- Changements de configuration
- Actions IA

## ⚙️ Configuration dynamique

Les paramètres de SIEM Africa sont stockés dans la table `settings` et modifiables depuis le dashboard sans redémarrage :

### Multi-modèles IA ⭐

```sql
ai_models_available = 'llama3.2:3b,qwen2.5:3b'  -- Modèles dispo
ai_default_model    = 'llama3.2:3b'               -- Par défaut
```

L'admin peut basculer entre les modèles depuis `/settings/`.

### Thème dark/light ⭐

```sql
theme_default       = 'dark'
allow_theme_toggle  = 'true'  -- Utilisateur peut basculer
```

### SMTP

```sql
smtp_host           = 'smtp.gmail.com'
smtp_port           = '587'
smtp_min_severity   = 'CRITICAL'  -- Email seulement sur CRITICAL
```

## 🌍 Marché cible — 4 pays Afrique Centrale

| Pays | Capital | Population | PIB | Autorité cyber |
|---|---|---|---|---|
| 🇨🇲 Cameroun | Yaoundé | 28 M | 47 Mrd $ | ANTIC (loi 2010) |
| 🇬🇦 Gabon | Libreville | 2,4 M | 21 Mrd $ | ANINF (loi 2023) |
| 🇨🇬 Congo Brazzaville | Brazzaville | 6 M | 14 Mrd $ | ANSSI (loi 2019) |
| 🇨🇩 RDC | Kinshasa | 102 M | 65 Mrd $ | ANSI-RDC (loi 2019) |

**Total** : 138,4 millions d'habitants, 147 milliards $ de PIB combiné.

Cadre régional : **CEMAC + CEEAC**, programme **UE SDBA** (Safe Digital Boost for Africa).

## 🔧 Désinstallation

Pour repartir de zéro :

```bash
# Arrêt des services qui utilisent la BDD
sudo systemctl stop siem-agent 2>/dev/null
sudo systemctl stop siem-dashboard 2>/dev/null

# Suppression
sudo rm -rf /var/lib/siem-africa
sudo userdel siem-db 2>/dev/null
# NE PAS supprimer le groupe siem-africa s'il est utilisé par M3 ou M4

# Réinstallation
sudo ./install_database.sh
```

## 📂 Structure des fichiers

```
database/
├── install_database.sh       # Script d'installation
├── verify.sh                 # Vérification post-install
├── README.md                 # Ce fichier
│
├── schema/
│   └── 00_schema.sql         # Structure complète (24 tables)
│
├── data/
│   ├── 01_mitre_tactics.sql      # 14 tactiques
│   ├── 02_mitre_techniques.sql   # 137 techniques
│   ├── 03_categories.sql         # 10 catégories
│   ├── 04_signatures_wazuh.sql   # 190 sigs Wazuh
│   ├── 05_signatures_snort.sql   # 190 sigs Snort
│   ├── 06_seed_roles.sql         # 4 rôles RBAC
│   ├── 07_seed_settings.sql      # 48 settings
│   ├── 08_seed_filters.sql       # 6 filtres FP
│   ├── 09_countries.sql          # 4 pays
│   └── 10_kpi_history_seed.sql   # 19 KPI initialisés
│
└── tests/
    ├── run_all_tests.sh
    ├── test_01_schema.sh
    ├── test_02_signatures.sh
    ├── test_03_mitre.sh
    ├── test_04_users.sh
    ├── test_05_countries.sh
    └── test_06_settings.sh
```

## 🔍 Commandes utiles

### Voir le contenu

```bash
# Compter les alertes par sévérité
sudo sqlite3 /var/lib/siem-africa/siem.db "SELECT severity, COUNT(*) FROM alerts GROUP BY severity;"

# Voir les utilisateurs
sudo sqlite3 /var/lib/siem-africa/siem.db "SELECT email, must_change_pwd FROM users;"

# Voir les settings IA
sudo sqlite3 /var/lib/siem-africa/siem.db "SELECT key, value FROM settings WHERE category='ai';"

# Voir les KPI du jour
sudo sqlite3 /var/lib/siem-africa/siem.db "SELECT * FROM v_kpi_summary;"
```

### Sauvegarde

```bash
# Backup à chaud (mode WAL)
sudo sqlite3 /var/lib/siem-africa/siem.db ".backup /tmp/siem-backup.db"

# Restauration
sudo systemctl stop siem-agent siem-dashboard
sudo cp /tmp/siem-backup.db /var/lib/siem-africa/siem.db
sudo chown siem-db:siem-africa /var/lib/siem-africa/siem.db
sudo chmod 660 /var/lib/siem-africa/siem.db
sudo systemctl start siem-agent siem-dashboard
```

## 🐛 Dépannage

### "readonly database"

```bash
# Vérifier les permissions
ls -la /var/lib/siem-africa/

# Si nécessaire, corriger :
sudo chown siem-db:siem-africa /var/lib/siem-africa/siem.db*
sudo chmod 660 /var/lib/siem-africa/siem.db*
```

### Admin oublié son mot de passe

```bash
# Lancer le helper de reset
sudo ./reset_admin.sh
```

### BDD corrompue

```bash
# Vérifier l'intégrité
sudo sqlite3 /var/lib/siem-africa/siem.db "PRAGMA integrity_check;"

# Si problème : restaurer depuis backup
ls -la /var/lib/siem-africa/*.backup.*
```

## 📚 Voir aussi

- `../installation/` — Module 1 (Wazuh + Snort)
- `../agent/` — Module 3 (Agent IA)
- `../dashboard/` — Module 4 (Dashboard Django)
- [Documentation MITRE ATT&CK](https://attack.mitre.org/)
- [Documentation Wazuh](https://documentation.wazuh.com/)

---

**Version** : 3.0.0
**Compatibilité** : Ubuntu 22.04 LTS et 24.04 LTS
**Licence** : MIT
