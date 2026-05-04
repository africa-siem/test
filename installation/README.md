# 🛡️ SIEM Africa - Module 1

**Installation automatique de Snort IDS + Wazuh SIEM**

---

## 📦 Contenu

```
module-1/
├── install_module1.sh         ← Menu interactif (choix LITE/FULL)
├── install_module1_lite.sh    ← Installation légère (Snort + Wazuh Manager)
├── install_module1_full.sh    ← Installation complète (avec Dashboard web)
└── README.md                  ← Ce fichier
```

---

## 🚀 Utilisation

### Option 1 : Menu interactif (recommandé)

```bash
sudo ./install_module1.sh
```

Le script te demande :
1. La langue (FR / EN)
2. Le mode (LITE / FULL)

Puis lance l'installation complète.

### Option 2 : Direct

```bash
# Mode LITE (sans dashboard)
sudo ./install_module1_lite.sh

# Mode FULL (avec dashboard)
sudo ./install_module1_full.sh

# Avec langue forcée
sudo ./install_module1_full.sh --lang en
```

---

## ⚙️ Prérequis

### LITE
| Élément | Minimum |
|---|---|
| OS | Ubuntu 20.04/22.04/24.04 ou Debian 11/12 |
| RAM | 2 Go |
| Disque | 15 Go |
| CPU | 1 cœur |
| Internet | Oui (pour télécharger Wazuh) |

### FULL
| Élément | Minimum |
|---|---|
| OS | Ubuntu 20.04/22.04/24.04 ou Debian 11/12 |
| RAM | 4 Go (8 Go recommandé) |
| Disque | 30 Go |
| CPU | 2 cœurs (4 recommandé) |
| Internet | Oui |

---

## 🔧 Ce qui est installé

### LITE
- **Snort IDS** (détection d'intrusions réseau)
- **Wazuh Manager** (analyse des alertes, pas d'interface web)
- Intégration Snort → Wazuh (Wazuh lit les alertes Snort)

### FULL
- Tout ce qui est dans LITE
- **Wazuh Indexer** (stockage des alertes, OpenSearch)
- **Wazuh Dashboard** (interface web HTTPS)

---

## 👥 Users créés

Dans les deux modes, 2 users système sont créés :

| User | Rôle | Mot de passe |
|---|---|---|
| `siem-ids` | Gestion Snort | **Généré aléatoirement** (16 caractères) |
| `siem-wazuh` | Gestion Wazuh | **Généré aléatoirement** (16 caractères) |

Les deux sont :
- Membres du groupe `siem-africa` (partagé avec les modules suivants)
- Ajoutés au groupe `sudo`

Les mots de passe sont **affichés à la fin** et **stockés** dans `/root/siem_credentials.txt`.

---

## 🔐 Fichier credentials

Tous les secrets sont dans :

```
/root/siem_credentials.txt
```

Lecture :

```bash
sudo cat /root/siem_credentials.txt
```

Permissions : `600` (root uniquement).

---

## 🔄 Auto-cleanup

Si une installation précédente est détectée, les scripts la **suppriment automatiquement** avant de réinstaller. Pas besoin de faire le ménage à la main.

**Ce qui est détecté et purgé :**
- Paquets `snort`, `wazuh-manager`, `wazuh-indexer`, `wazuh-dashboard`, `filebeat`
- Dossiers `/etc/snort`, `/var/ossec`, `/var/lib/wazuh-indexer`, etc.
- Services systemd (`snort.service`, `wazuh-*.service`)
- Processus résiduels

---

## 📊 Vérification post-install

### Services

```bash
# Mode LITE
sudo systemctl status snort wazuh-manager

# Mode FULL
sudo systemctl status snort wazuh-manager wazuh-indexer wazuh-dashboard
```

### Ports

```bash
# Mode LITE : 1514, 1515, 55000
# Mode FULL : + 443, 9200
sudo ss -tlnp | grep -E '443|1514|1515|9200|55000'
```

### Alertes temps réel

```bash
# Snort
sudo tail -f /var/log/snort/alert

# Wazuh (agrégé)
sudo tail -f /var/ossec/logs/alerts/alerts.json
```

### Dashboard (FULL uniquement)

Ouvrir dans un navigateur :

```
https://<IP_SERVEUR>
```

- User : `admin`
- Password : voir `/root/siem_credentials.txt`

**Note** : certificat auto-signé → accepter l'avertissement du navigateur.

---

## 🐛 En cas de problème

### Logs d'installation

```bash
sudo tail -50 /var/log/siem-install.log
```

### Logs Snort

```bash
sudo journalctl -u snort -n 50
sudo tail -20 /var/log/snort/alert
```

### Logs Wazuh

```bash
sudo journalctl -u wazuh-manager -n 50
sudo tail -20 /var/ossec/logs/ossec.log
```

### Relancer avec purge forcée

Il suffit de relancer le script, il détectera et nettoiera automatiquement :

```bash
sudo ./install_module1.sh
```

---

## 🎯 Prochaine étape

Une fois le Module 1 installé et fonctionnel, passer au **Module 2** qui crée la base de données SQLite avec 20 tables, 14 tactiques MITRE ATT&CK et 417 signatures de détection.

---

## ⚡ Fichiers importants (post-install)

| Fichier | Rôle |
|---|---|
| `/root/siem_credentials.txt` | Tous les mots de passe |
| `/root/wazuh-install-files.tar` | Backup fichiers Wazuh (FULL uniquement) |
| `/var/log/siem-install.log` | Log complet de l'install |
| `/etc/snort/snort.conf` | Config Snort |
| `/var/ossec/etc/ossec.conf` | Config Wazuh |
| `/var/log/snort/alert` | Alertes Snort brutes |
| `/var/ossec/logs/alerts/alerts.json` | Alertes Wazuh (JSON) |
