# SIEM Africa - Module 3 (Agent) - Bloc 1 : Fondations

## 🎯 Objectif du Bloc 1

Préparer **toute l'infrastructure** de l'agent : structure du projet, installation système, utilisateurs Unix, venv Python, service systemd, healthcheck.

**À la fin de ce bloc** : l'agent démarre, fait son healthcheck, log "Agent opérationnel" — mais **ne traite encore aucune alerte** (c'est pour les blocs suivants).

## 📁 Structure créée

```
agent/
├── install_agent.sh              ← Script d'installation
├── README_BLOC_1.md              ← Ce fichier
├── opt/                          ← Code Python (sera copié dans /opt/siem-africa-agent/)
│   ├── main.py                   ← Point d'entrée
│   ├── config.py                 ← Configuration centralisée
│   ├── logger_setup.py           ← Logging avec rotation 10MB x 5
│   ├── healthcheck.py            ← Vérifications démarrage
│   ├── db/                       ← (Bloc 2)
│   ├── watchers/                 ← (Bloc 3)
│   ├── processor/                ← (Bloc 4)
│   ├── ai/                       ← (Bloc 5)
│   ├── notif/                    ← (Bloc 6)
│   ├── response/                 ← (Bloc 7)
│   └── workers/                  ← (Bloc 8)
├── systemd/
│   └── siem-agent.service        ← Unit systemd
└── tests/
    └── test_bloc_1.sh            ← Tests de validation du bloc
```

## 🚀 Installation

```bash
# Sur ta VM (depuis le repo cloné)
cd ~/test/agent
chmod +x install_agent.sh
sudo bash install_agent.sh
```

Le script va :

1. Vérifier les prérequis (Ubuntu, Python, BDD M2, Wazuh)
2. Créer le groupe Unix `siem-africa` (si pas existant) et l'utilisateur `siem-agent`
3. Ajouter `siem-agent` aux groupes `wazuh` et `snort` (pour lire leurs logs)
4. Créer les dossiers :
   - `/opt/siem-africa-agent/` (code)
   - `/var/log/siem-africa/` (logs)
   - `/etc/siem-africa/` (config)
5. Créer le venv Python et installer `requests`, `inotify-simple`, `jinja2`
6. Copier le code Python
7. Créer le fichier `/etc/siem-africa/agent.env` (config runtime)
8. Installer le service systemd et le démarrer
9. Append les credentials dans `/root/siem_credentials.txt`

## ✅ Validation

```bash
sudo bash tests/test_bloc_1.sh
```

Le script teste 7 catégories :

| Test | Vérification |
|---|---|
| 1 | Utilisateur Unix siem-agent + groupes |
| 2 | Dossiers et permissions |
| 3 | Venv Python + imports |
| 4 | Code Python en place |
| 5 | Config agent.env |
| 6 | Service systemd actif |
| 7 | Healthcheck OK dans les logs |

**Tous les tests doivent être verts avant de passer au Bloc 2.**

## 🔍 Commandes utiles

```bash
# Voir l'état du service
sudo systemctl status siem-agent

# Voir les logs systemd
sudo journalctl -u siem-agent -f

# Voir les logs applicatifs
sudo tail -f /var/log/siem-africa/agent.log

# Redémarrer
sudo systemctl restart siem-agent

# Voir la config
cat /etc/siem-africa/agent.env
```

## 📋 Ce qui apparaît dans les logs au démarrage

```
2026-05-16 09:34:00 [INFO] [main] ============================================================
2026-05-16 09:34:00 [INFO] [main] SIEM AFRICA AGENT - Démarrage
2026-05-16 09:34:00 [INFO] [main] ============================================================
2026-05-16 09:34:00 [INFO] [healthcheck] ===== HEALTHCHECK DÉMARRAGE =====
2026-05-16 09:34:00 [INFO] [healthcheck] DB OK (380 signatures en base)
2026-05-16 09:34:00 [INFO] [healthcheck] Wazuh log accessible : /var/ossec/logs/alerts/alerts.json
2026-05-16 09:34:00 [WARNING] [healthcheck] SMTP désactivé dans settings
2026-05-16 09:34:00 [INFO] [healthcheck] Ollama OK - 2 modèles : ['llama3.2:3b', 'qwen2.5:3b']
2026-05-16 09:34:00 [INFO] [healthcheck] Healthcheck : {'db': True, 'wazuh_log': True, 'smtp': False, 'ollama': True}
2026-05-16 09:34:00 [INFO] [main] Agent opérationnel (Bloc 1 - fondations uniquement)
```

## ⚠️ Important

L'agent au stade Bloc 1 :

- ✅ **Démarre proprement**
- ✅ **Fait son healthcheck**
- ✅ **Reste actif** (heartbeat toutes les 60s)
- ❌ **Ne traite AUCUNE alerte** (c'est pour le Bloc 3+)
- ❌ **N'envoie AUCUN email** (c'est pour le Bloc 6)
- ❌ **Ne bloque AUCUNE IP** (c'est pour le Bloc 7)

C'est **normal**. Le Bloc 1 sert juste à valider que les fondations marchent.

## 🚀 Prochaine étape : Bloc 2

Une fois `test_bloc_1.sh` 100% vert, on passe au **Bloc 2 — DB Layer** : encapsuler toutes les opérations BDD dans une classe `DatabaseManager` qui parle correctement au schéma M2 (uuid auto, name fourni, etc.).
