# SIEM Africa - Module 3 : Agent intelligent

Agent Python qui surveille Wazuh, enrichit les alertes, envoie des notifications et bloque les IPs malveillantes.

**État** : Code testé avec **207 tests automatisés** tous passants.

## 🎯 Caractéristiques

### Opérations principales (10)

1. **Surveillance Wazuh** - lecture inotify de `/var/ossec/logs/alerts/alerts.json`
2. **Identification source** - distingue alertes Wazuh natives et Snort relayées (via `decoder.name`)
3. **Matching signatures** - 380 règles en BDD
4. **Insertion enrichie** - contexte MITRE, asset, réputation IP
5. **Comptage occurrences** - dédup automatique (event_count++)
6. **Enrichissement IA Ollama** - description française avec cache
7. **Gestion faux positifs** - lit `alert_filters` (IGNORE / DOWNGRADE / NOTIFY_ONLY)
8. **Corrélation** - 5+ alertes même IP → incident automatique
9. **Blocage iptables auto** - CRITICAL avec whitelist et anti-loopback
10. **Réputation IP** - score 0-100 mis à jour à chaque event

### Opérations email (7)

E1. Email selon sévérité (CRITICAL/HIGH/MEDIUM immédiat, LOW digest, INFO non)
E2. Contenu détaillé (IP, cible, MITRE, recommandations IA)
E3. Multi-destinataires (ajoutables depuis dashboard)
E4. Anti-spam (rate limit + dedup 5min)
E5. Email de bienvenue au démarrage
E6. Récap quotidien à 7h matin
E7. Email pic d'attaque si > 20 alertes/min

### Support (5)

S1. Service systemd avec autorestart
S2. Logs agent avec rotation 10MB × 5
S3. Audit trail (toutes actions tracées)
S4. Healthcheck au démarrage
S5. KPI snapshot quotidien minuit (18 metrics)

### Sécurité

- Whitelist IPs via `alert_filters`
- Backup BDD auto quotidien 2h (rotation 30 jours)
- Anti-loopback iptables (refuse 10.x, 192.168.x, 127.x, link-local, multicast)

## 📁 Structure modulaire

```
agent/
├── install_agent.sh
├── README.md
├── opt/
│   ├── main.py                   ← Point d'entrée
│   ├── config.py                 ← Configuration
│   ├── logger_setup.py           ← Logging
│   ├── healthcheck.py            ← Vérifications
│   │
│   ├── db/                       ← BLOC 2 : Couche BDD
│   │   ├── __init__.py
│   │   ├── helpers.py            ← now_sqlite, sqlite_future
│   │   └── manager.py            ← DatabaseManager
│   │
│   ├── watchers/                 ← BLOC 3 : Surveillance
│   │   ├── __init__.py
│   │   ├── parser.py             ← Parser JSON Wazuh
│   │   └── wazuh.py              ← WazuhWatcher (thread)
│   │
│   ├── processor/                ← BLOC 4 : Cœur
│   │   ├── __init__.py
│   │   ├── utils.py              ← is_private_ip
│   │   └── alert_processor.py    ← AlertProcessor (thread)
│   │
│   ├── ai/                       ← BLOC 5 : IA Ollama
│   │   ├── __init__.py
│   │   ├── ollama_client.py
│   │   ├── parser.py             ← Parse JSON LLM (3 stratégies)
│   │   ├── prompt.py             ← Construction du prompt
│   │   └── enricher.py           ← AIEnricher (thread)
│   │
│   ├── notif/                    ← BLOC 6 : Email
│   │   ├── __init__.py
│   │   ├── smtp_client.py        ← SMTPClient
│   │   ├── email_sender.py       ← EmailSender (4 types + anti-spam)
│   │   └── worker.py             ← EmailWorker (thread)
│   │
│   ├── response/                 ← BLOC 7 : Active Response
│   │   ├── __init__.py
│   │   ├── utils.py              ← is_blockable_ip, run_iptables
│   │   ├── ip_blocker.py         ← IPBlocker
│   │   └── workers.py            ← BlockWorker + UnblockerWorker
│   │
│   └── workers/                  ← BLOC 8 : Workers cron
│       ├── __init__.py
│       ├── utils.py              ← seconds_until
│       ├── kpi.py                ← KPISnapshotter (minuit)
│       ├── backup.py             ← DBBackup (2h)
│       └── daily_recap.py        ← DailyRecapWorker (7h)
│
├── systemd/
│   └── siem-agent.service
└── tests/
    ├── test_bloc_1.sh
    ├── test_all.sh
    └── simulate_attack.sh
```

## 🚀 Installation

```bash
cd ~/test/agent
chmod +x install_agent.sh
sudo bash install_agent.sh
```

Le script :

1. Vérifie prérequis (Ubuntu, Python, BDD M2, Wazuh)
2. Crée groupe `siem-africa` et utilisateur `siem-agent`
3. Ajoute `siem-agent` aux groupes `wazuh` et `snort`
4. Crée les dossiers `/opt/siem-africa-agent/`, `/var/log/siem-africa/`, `/etc/siem-africa/`, `/var/backups/siem-africa/`
5. Configure sudoers pour `iptables`
6. Crée venv Python, installe `requests`, `inotify-simple`, `jinja2`
7. Copie le code, installe systemd, démarre l'agent

## ✅ Validation

```bash
# Tests fondations
sudo bash tests/test_bloc_1.sh

# Tests complets
sudo bash tests/test_all.sh

# Simulation d'attaque
sudo bash tests/simulate_attack.sh ssh-brute
sudo bash tests/simulate_attack.sh sql-inject
sudo bash tests/simulate_attack.sh port-scan
sudo bash tests/simulate_attack.sh mixed
```

## 🔍 Commandes utiles

```bash
sudo systemctl status siem-agent
sudo journalctl -u siem-agent -f
sudo tail -f /var/log/siem-africa/agent.log

# Voir alertes
sudo sqlite3 /var/lib/siem-africa/siem.db \
    "SELECT id,severity,title,src_ip,event_count FROM alerts ORDER BY id DESC LIMIT 10;"

# IPs bloquées
sudo iptables -L INPUT -n | grep DROP

# Audit
sudo sqlite3 /var/lib/siem-africa/siem.db \
    "SELECT created_at,action FROM audit_log ORDER BY id DESC LIMIT 20;"
```

## 🛠️ Threads

| Thread | Fichier | Rôle |
|---|---|---|
| `WazuhWatcher` | `watchers/wazuh.py` | Lit `alerts.json` via inotify |
| `AlertProcessor` | `processor/alert_processor.py` | Traite events → BDD |
| `AIEnricher` | `ai/enricher.py` | Appelle Ollama (async) |
| `EmailWorker` | `notif/worker.py` | Envoie emails (async) |
| `BlockWorker` | `response/workers.py` | Bloque IPs via iptables |
| `UnblockerWorker` | `response/workers.py` | Débloque IPs expirées |
| `KPISnapshotter` | `workers/kpi.py` | Snapshot KPI à minuit |
| `DBBackup` | `workers/backup.py` | Backup BDD à 2h |
| `DailyRecapWorker` | `workers/daily_recap.py` | Récap quotidien à 7h |

### Queues inter-threads

```
WazuhWatcher → event_queue → AlertProcessor
                                ├→ ai_queue    → AIEnricher
                                ├→ email_queue → EmailWorker
                                └→ block_queue → BlockWorker
```

## ⚠️ Notes importantes

- **Pas de `set -e`** dans les scripts
- **Pas de hardening systemd agressif**
- **Désinstallation propre** avant chaque réinstallation
- **iptables via sudo** (sudoers NOPASSWD limité)
- **Anti-loopback** : IPs privées JAMAIS bloquées
- **Mode dégradé** : si Ollama ou SMTP down, l'agent continue

## 🧪 Tests automatisés

**207 tests passants** :

| Module | Tests |
|---|---|
| Bloc 2 (DB Layer) | 28 |
| Bloc 3 (Watcher) | 24 |
| Bloc 4 (Processor) | 22 |
| Bloc 5 (AI) | 25 |
| Bloc 6 (Email) | 26 |
| Bloc 7 (Active Response) | 35 |
| Bloc 8 (Workers cron) | 25 |
| End-to-end | 22 |
| **TOTAL** | **207** |

## 🐛 Bugs historiques corrigés

1. **Format timestamps incohérent** entre Python et SQLite → `now_sqlite()` partout
2. **Comptage occurrences** : utilise `SUM(event_count)` pour la dédup
3. **Corrélation bloquée par dédup** : méthode `_check_correlation()` séparée
