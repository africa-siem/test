# Installation du Dashboard SIEM Africa (Module 4)

## Important — à lire avant d'installer

Ce dossier contient UNIQUEMENT le dashboard. Il ne doit PAS contenir :
- de dossier `tests/`
- de fichier `verify.sh` ou `verify_dashboard.sh`
- de dossier `siem_dashboard/`

Si ces éléments sont présents dans votre dépôt, supprimez-les : ils
proviennent d'une ancienne version et font échouer les vérifications.

## Contenu attendu du dossier

    config/   core/   templates/   static/
    manage.py   requirements.txt   creer_base_test.py
    install_dashboard.sh   README.md   .gitignore

## Installation sur la VM (3 étapes)

1. Se placer dans le dossier dashboard :

    cd dashboard

2. Vérifier que la base de données existe :

    ls -l /var/lib/siem-africa/siem.db

   Si ce fichier n'existe pas, installez d'abord les Modules 1 et 2.

3. Lancer l'installation :

    sudo bash install_dashboard.sh

Le script installe les dépendances, crée l'environnement Python, met en
place le service systemd et la configuration Nginx, puis démarre le
dashboard. À la fin, il affiche l'adresse d'accès.

## Après installation

- Vérifier l'état du service :   sudo systemctl status siem-dashboard
- Voir les logs en direct :       sudo journalctl -u siem-dashboard -f
- Accès navigateur :              http://<adresse-de-la-VM>/
- Connexion :                     compte ADMIN créé à l'installation du Module 2

## En cas d'erreur

Copiez le message affiché par le script et les dernières lignes des logs :

    sudo journalctl -u siem-dashboard -n 50 --no-pager
