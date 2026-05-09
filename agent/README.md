# SIEM Africa - Module 3 - Agent intelligent

Agent Python qui surveille **Wazuh** et **Snort**, enrichit chaque alerte inconnue
avec une **IA locale (Ollama)** et envoie une **notification email** pour chaque alerte.

## Prerequis

- **Module 1** installe (Wazuh + Snort + groupe `siem-africa`)
- **Module 2** installe (BDD SQLite + signatures + table `ai_signature_cache`)
- **Ubuntu** 20.04 / 22.04 / 24.04
- **4 Go RAM** minimum (pour les 2 modeles Ollama)
- **10 Go disque libre** (modeles ~4 Go + dependances)
- Connexion Internet (pour telecharger Ollama et les modeles)

## Installation

```bash
cd ~/agent
chmod +x install_agent.sh verify_agent.sh simulate_attack.sh tests/*.sh
sudo ./install_agent.sh
```

Le script :

1. Verifie tous les prerequis
2. Detecte une eventuelle installation precedente et propose la desinstallation
3. Cree l'utilisateur `siem-agent` (membre des groupes `siem-africa`, `wazuh`, `snort`)
4. Cree les dossiers `/opt/siem-africa-agent` et `/var/log/siem-africa`
5. Cree un venv Python avec `requests` et `inotify-simple`
6. Genere `/etc/siem-africa/agent.env`
7. **Installe Ollama** (script officiel) puis **telecharge `qwen2.5:3b` ET `llama3.2:3b`**
8. Cree le service systemd `siem-agent.service`
9. Cree le cron `/etc/cron.d/siem-africa-kpi` (snapshot horaire)
10. Demarre le service
11. Lance `verify_agent.sh` puis `tests/run_all_tests.sh`
12. Append une section `[MODULE 3]` dans `/root/siem_credentials.txt`

## Architecture

```
   alerts.json              /var/log/snort/alert
        │                            │
        ▼                            ▼
 ┌──────────────┐            ┌──────────────┐
 │ WazuhWatcher │            │ SnortWatcher │   inotify + fallback polling 5s
 └──────┬───────┘            └──────┬───────┘
        │                            │
        └────────────┬───────────────┘
                     ▼
              ┌───────────────┐
              │ AlertProcessor│
              └───┬───────┬───┘
                  │       │
   sig connue     │       │   sig inconnue
   (BDD)          │       │
                  ▼       ▼
       Insert + notifier   Insert ai_status='pending'
                           + push dans ai_queue
                                   │
                                   ▼
                            ┌─────────────┐
                            │  AIWorker   │ ──► Ollama (qwen2.5:3b)
                            └──────┬──────┘
                                   ▼
                  Update alerte + notifier
                                   │
                  ┌────────────────┴────────────────┐
                  ▼                                 ▼
          severity CRITICAL/HIGH         severity LOW/MEDIUM/INFO
                  │                                 │
        ┌─────────┴─────────┐                       ▼
        ▼                   ▼                ┌──────────────┐
    dedup hit ?       rate limit ?           │ digest.json  │ (persiste)
    skip              skip                   └──────┬───────┘
        │                   │                       │
        └─────────┬─────────┘                       ▼
                  ▼                           DigestWorker
            email_sender.send()           (1 email recap/heure)
            (immediat)
```

**Pourquoi async ?** L'enrichissement IA prend 5-30 secondes. Si on attendait avant
d'inserer l'alerte, le watcher serait bloque. La solution : on insere immediatement
avec `ai_status='pending'` (l'utilisateur voit l'alerte dans le dashboard en temps
reel), et l'AIWorker remplit les champs IA en arriere-plan.

**Pourquoi 3 protections email ?** Wazuh peut generer 30-100 alertes/h sans attaque
(audit, rootcheck...). Sans protection, Gmail bloque le compte pour spam apres ~50
emails consecutifs. Le combo dedup + rate limit + digest garantit max 30 emails/h
pour les alertes critiques + 1 email recap/h pour les autres.

## Verification

```bash
sudo ./verify_agent.sh           # Verification rapide post-install
sudo ./tests/run_all_tests.sh    # Lance les 7 suites de tests
```

## Simulation d'attaque (pour la demo / soutenance)

```bash
sudo ./simulate_attack.sh ssh-brute     # Brute force SSH (5 events)
sudo ./simulate_attack.sh sql-inject    # Tentative SQL injection
sudo ./simulate_attack.sh port-scan     # Scan de ports
sudo ./simulate_attack.sh unknown       # Signature INCONNUE -> Ollama
sudo ./simulate_attack.sh all           # TOUS les types
```

## Commandes utiles

```bash
# Status
sudo systemctl status siem-agent

# Logs en direct
sudo journalctl -u siem-agent -f

# Logs fichier (avec rotation)
sudo tail -f /var/log/siem-africa/agent.log

# Restart
sudo systemctl restart siem-agent

# Voir les alertes les plus recentes
sqlite3 /var/lib/siem-africa/siem.db \
  "SELECT id, severity, ai_status, substr(title,1,60) FROM alerts ORDER BY id DESC LIMIT 20;"

# Voir le cache IA
sqlite3 /var/lib/siem-africa/siem.db \
  "SELECT model_used, used_count, substr(ai_description,1,80) FROM ai_signature_cache ORDER BY id DESC LIMIT 10;"

# KPI snapshot manuel
sudo -u siem-agent /opt/siem-africa-agent/venv/bin/python \
  /opt/siem-africa-agent/kpi/snapshot.py

# Health check manuel
sudo -u siem-agent /opt/siem-africa-agent/venv/bin/python \
  /opt/siem-africa-agent/health_check.py

# Ollama : modeles installes
curl -s http://127.0.0.1:11434/api/tags | jq '.models[].name'
```

## Configuration

| Fichier | Role |
|---|---|
| `/etc/siem-africa/agent.env` | Tuning agent (paths, timeouts, etc.) |
| `/etc/siem-africa/smtp.env`  | Credentials SMTP (640 root:siem-africa) |
| Table `settings` (BDD)       | Reglages dynamiques (modele IA, IP block, etc.) |

## Mode degrade IA

Si Ollama n'est pas disponible (service down, modeles absents...), l'agent continue
de tourner sans crash :

- **Signature connue** : alerte enrichie depuis la BDD comme d'habitude
- **Signature inconnue** : alerte stockee avec `ai_status='failed'` et description fallback
- Le dashboard affichera un bouton **"Re-analyser"** pour declencher une nouvelle tentative

L'agent ne crashe **jamais** parce que Ollama est en panne.

## Email & Anti-spam

L'agent envoie un email pour les alertes selon **3 niveaux de protection automatique** :

### 1. Rate limit (max 30 emails/heure)

Si plus de 30 emails ont ete envoyes dans la derniere heure (lu depuis `email_logs`),
les emails suivants sont sautes pendant l'heure courante. **L'alerte reste enregistree
dans la BDD** (visible dans le dashboard), seul l'email est saute.

Configurable : `email_rate_limit_per_hour` dans la table `settings` (defaut 30, 0 = pas de limite).

### 2. Dedup (5 minutes par signature)

Si la meme signature a deja declenche un email dans les 5 dernieres minutes, on saute
l'email pour eviter d'inonder la boite avec 50 emails identiques. La premiere alerte
est notifiee, les suivantes sont enregistrees en BDD sans email.

Configurable : `email_dedup_window_minutes` dans `settings` (defaut 5, 0 = pas de dedup).

### 3. Digest LOW/MEDIUM (resume horaire)

Les alertes **LOW** et **MEDIUM** ne sont **pas envoyees individuellement**. Elles sont
accumulees dans `/var/lib/siem-africa/state/digest.json`, et le `DigestWorker` envoie
**un seul email recapitulatif toutes les heures** avec la liste.

Les alertes **CRITICAL** et **HIGH** sont toujours envoyees immediatement (apres dedup
et rate limit).

Configurable :
- `email_digest_enabled` dans `settings` (defaut `true`)
- `email_digest_interval_minutes` dans `settings` (defaut 60)

### Personnaliser : seuil de severite

Pour ne recevoir QUE les alertes au-dessus d'un certain niveau :

```bash
sqlite3 /var/lib/siem-africa/siem.db \
  "UPDATE settings SET value='HIGH' WHERE key='email_min_severity';"
```

Valeurs : `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.

## Tests

| # | Suite                  | Verifie                                       |
|---|------------------------|-----------------------------------------------|
| 1 | systemd                | Unit file, enabled, actif, pas d'erreurs      |
| 2 | python_imports         | Tous les modules importent + venv propre      |
| 3 | db_access              | siem-agent peut lire+ecrire BDD               |
| 4 | smtp                   | smtp.env present + variables critiques        |
| 5 | ollama                 | API + 2 modeles + (optionnel) inference       |
| 6 | ai_enrichment          | Prompt builder + parser + cache + end-to-end  |
| 7 | simulation             | Injection event Wazuh -> alerte creee en BDD  |

## Logs

- `/var/log/siem-africa/agent.log` (rotation 5 Mo, 5 backups)
- `journalctl -u siem-agent` (capture stdout/stderr)
- `/var/log/siem-africa/kpi.log` (snapshots horaires)

## Desinstallation

```bash
sudo systemctl stop siem-agent
sudo systemctl disable siem-agent
sudo rm /etc/systemd/system/siem-agent.service
sudo systemctl daemon-reload
sudo rm -rf /opt/siem-africa-agent
sudo rm /etc/cron.d/siem-africa-kpi
sudo rm /etc/siem-africa/agent.env   # Optionnel
```
