-- ============================================================================
-- SIEM AFRICA - 190 Signatures Wazuh (ENRICHIES)
-- ============================================================================
-- Chaque signature inclut désormais :
--   - description_fr : 1-2 phrases claires expliquant l'attaque
--   - remediation_fr : 2-3 recommandations actionnables
-- 
-- IDs Wazuh : utilisent les vraies plages numériques :
--   5xxx : authentification (SSH, sudo, login)
--   31xxx : web attacks
--   60xxx : Windows events
--   87xxx : rootkit detection
--   100xxx-200xxx : custom SIEM Africa rules
-- ============================================================================

INSERT INTO signatures (
    id, uuid, name,
    description_fr, description_en, source,
    category_id, technique_id,
    severity, confidence, is_active, is_noisy, is_critical_chain, cve_ids,
    remediation_fr
) VALUES
(5500, '5558c24e-a477-44f4-8d8a-d4bfccc33b6f', 'SSHD: Failed password attempt', 'Un utilisateur a saisi un mot de passe incorrect lors d''une connexion SSH. Isolé, c''est normal — répété, c''est suspect.', 'Échec d''''''''authentification SSH', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'LOW', 60, 1, 1, 0, NULL, '1. Vérifier si l''utilisateur concerné est légitime
2. Si nombreux échecs, investiguer l''IP source via les logs
3. Activer fail2ban si pas déjà en place'),
(5501, '41d6a34b-86eb-4166-b247-af9f3d95a881', 'SSHD: Login session opened', 'Un utilisateur s''est connecté avec succès au serveur en SSH. Événement normal à des fins de traçabilité.', 'Session SSH ouverte', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1078'), 'INFO', 50, 1, 1, 0, NULL, '1. Aucune action nécessaire - événement informationnel
2. Vérifier que la connexion correspond à un horaire et utilisateur attendus'),
(5502, '303c93c3-5e0d-4236-bace-c09e64a1050e', 'SSHD: Login session closed', 'Un utilisateur a fermé sa session SSH. Événement normal de fin de connexion.', 'Session SSH fermée', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1078'), 'INFO', 50, 1, 1, 0, NULL, '1. Aucune action nécessaire - événement informationnel'),
(5503, '741a0c4c-5ac6-4bcb-896f-900ba65914df', 'PAM: User authentication failed', 'Le module PAM a refusé une authentification. Cela peut être SSH, sudo, login console ou tout service utilisant PAM.', 'Échec authentification PAM', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'LOW', 60, 1, 1, 0, NULL, '1. Identifier le service à l''origine via les logs (/var/log/auth.log)
2. Vérifier si l''utilisateur ciblé existe et n''est pas verrouillé
3. Surveiller les tentatives répétées sur le même compte'),
(5710, '7aa939eb-5fb7-4f6c-a738-7f862d6c8e48', 'Attempt to login using non-existent user', 'Un attaquant tente de se connecter en SSH avec un nom d''utilisateur qui n''existe pas sur le serveur. Signe typique de scan d''attaque automatisé.', 'Login avec utilisateur inexistant', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'MEDIUM', 70, 1, 1, 0, NULL, '1. L''IP source sera bloquée si les tentatives se répètent
2. Vérifier les logs SSH pour identifier la liste des noms tentés
3. Désactiver SSH sur le port 22 standard et utiliser un port non-standard'),
(5711, '6edc9aed-26f4-42b5-8e34-3ade1e50b8aa', 'Multiple SSHD authentication failures', 'Plusieurs tentatives d''authentification SSH ont échoué dans un court laps de temps. Forte présomption d''attaque par force brute.', 'Multiples échecs SSH', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 85, 1, 0, 0, NULL, '1. L''IP source sera automatiquement bloquée par l''agent
2. Vérifier les logs SSH pour identifier le compte ciblé
3. Renforcer la politique de mots de passe ou activer l''authentification par clé SSH'),
(5712, '800a617a-b3f2-45fc-bc30-9c571dffc430', 'SSHD brute force trying to get access', 'Attaque par force brute SSH en cours : un attaquant essaie un grand nombre de mots de passe différents depuis la même adresse IP. S''il réussit, il prend le contrôle du serveur.', 'Tentative de force brute SSH', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'CRITICAL', 90, 1, 0, 1, NULL, '1. L''IP attaquante est automatiquement bloquée par le pare-feu (action déjà effectuée)
2. Vérifier qu''aucune connexion réussie n''a eu lieu : grep ''Accepted'' /var/log/auth.log
3. Désactiver l''authentification SSH par mot de passe et n''autoriser que les clés SSH'),
(5715, '6a2363c3-a747-46ab-b13e-1ef98705b778', 'SSHD authentication success', 'Authentification SSH réussie. Événement normal à conserver pour la traçabilité.', 'Authentification SSH réussie', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1078'), 'INFO', 50, 1, 1, 0, NULL, '1. Aucune action nécessaire - événement informationnel
2. Vérifier que la connexion correspond à un utilisateur et horaire attendus'),
(5716, 'def80be1-9b6b-4eae-bfd8-107b87e41714', 'SSHD authentication failed', 'Une authentification SSH a échoué. Si isolé, peut être une simple erreur de frappe — si répété, c''est suspect.', 'Échec d''''''''authentification SSH', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'MEDIUM', 70, 1, 1, 0, NULL, '1. Identifier l''utilisateur et l''IP source dans les logs
2. Si répété, l''agent bloquera automatiquement l''IP
3. Recommander au propriétaire du compte de vérifier son mot de passe'),
(5719, '7e22b224-aade-4aa0-afe5-a018805a7f5f', 'SSHD: User account locked', 'Un compte utilisateur SSH a été verrouillé après trop d''échecs successifs. C''est une protection automatique qui s''est déclenchée.', 'Compte SSH verrouillé', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 80, 1, 0, 0, NULL, '1. Identifier le compte concerné et la cause (utilisateur légitime ou attaque ?)
2. Si attaque : l''IP est probablement déjà bloquée par l''agent
3. Si utilisateur légitime : débloquer le compte avec faillock ou pam_tally2'),
(5720, 'fc685567-da0b-4072-bb2f-5f9e2c73ad2c', 'Multiple authentication failures from same source', 'Plusieurs tentatives d''authentification ont échoué depuis la même IP source. Forte présomption d''attaque automatisée.', 'Multiples échecs depuis la même source', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 85, 1, 0, 0, NULL, '1. L''IP source sera bloquée automatiquement
2. Vérifier les comptes ciblés dans les logs
3. Activer la double authentification (2FA) sur les comptes sensibles'),
(5722, '509a0e23-0dfc-4845-aedf-e34d9110a49c', 'Multiple SSHD attempts on different accounts', 'Un attaquant tente d''accéder à plusieurs comptes différents depuis la même IP. C''est du ''password spraying'' : test d''un mot de passe courant sur de nombreux comptes.', 'Tentatives sur différents comptes SSH', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.003'), 'CRITICAL', 90, 1, 0, 1, NULL, '1. L''IP est automatiquement bloquée par l''agent
2. Identifier la liste des comptes ciblés et alerter leurs propriétaires
3. Forcer le changement de mot de passe sur les comptes faibles'),
(5723, '87ffc2a0-dac8-4410-94bc-8242dddb3ef2', 'Successful login after multiple failures', 'Un compte vient de se connecter avec succès APRÈS plusieurs échecs. Cela peut indiquer une attaque par force brute réussie — incident potentiellement grave.', 'Login réussi après plusieurs échecs', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. CRITIQUE : isoler ce compte immédiatement (changer le mot de passe, désactiver)
2. Auditer toutes les actions effectuées par ce compte depuis la connexion
3. Vérifier l''absence de modification système, ajout d''utilisateur ou rootkit'),
(5724, '2f15681e-6ee4-44ef-a5bd-844c1f0461f2', 'First time user logged in', 'Un utilisateur se connecte pour la première fois sur ce serveur. À vérifier si c''est attendu.', 'Premier login d''''''''un utilisateur', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1078'), 'MEDIUM', 60, 1, 0, 0, NULL, '1. Vérifier auprès du propriétaire du compte que la connexion est légitime
2. S''assurer que la création du compte est récente et autorisée
3. Documenter cette première connexion dans le journal des accès'),
(5402, 'b5eed99e-79f8-4129-bd4f-78752d74ae00', 'Sudo: command executed', 'Une commande a été exécutée avec sudo (privilèges administrateur). Événement de traçabilité normal mais à surveiller.', 'Commande sudo exécutée', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1548.003'), 'INFO', 50, 1, 1, 0, NULL, '1. Aucune action immédiate - événement informationnel
2. Vérifier que la commande sudo correspond aux activités attendues de l''utilisateur'),
(5403, 'e603c6e3-c69e-4339-814a-0a87eccc0e50', 'Sudo: failed authentication', 'Une authentification sudo a échoué : l''utilisateur a saisi un mauvais mot de passe pour obtenir les droits admin.', 'Échec authentification sudo', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. Vérifier si c''est une erreur ou une tentative d''élévation de privilèges
2. Si répété sur le même compte, considérer un compte compromis
3. Activer l''historique sudo : Defaults log_input,log_output dans /etc/sudoers'),
(5404, '38b33845-9bb7-4ebb-b23a-c87382d29e09', 'Sudo: incorrect password attempts', 'Plusieurs tentatives sudo avec mauvais mot de passe. Suspect : un attaquant qui a accès au compte essaie de devenir admin.', 'Tentatives sudo avec mauvais mot de passe', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : vérifier si le compte n''est pas compromis (changer le mot de passe)
2. Examiner l''historique des commandes de cet utilisateur
3. Restreindre sudo aux seules commandes nécessaires via sudoers'),
(5405, 'bb98cac8-10e7-429d-84f8-eb620e8d0713', 'Sudo: user not in sudoers', 'Un utilisateur a tenté sudo sans être autorisé dans le fichier sudoers. Indique soit une erreur de configuration, soit une tentative d''élévation de privilèges malveillante.', 'Utilisateur non autorisé à sudo', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1068'), 'HIGH', 80, 1, 0, 0, NULL, '1. Vérifier qui est cet utilisateur et pourquoi il tente sudo
2. Si tentative malveillante, isoler le compte immédiatement
3. Auditer le fichier /etc/sudoers et les fichiers /etc/sudoers.d/'),
(5301, 'db7e9911-7ab7-453a-9937-fb84dbdbdd23', 'Login: New session', 'Une nouvelle session de login console s''est ouverte (hors SSH). Événement normal.', 'Nouvelle session login', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1078'), 'INFO', 50, 1, 1, 0, NULL, '1. Aucune action - événement informationnel'),
(5302, '700f3972-f441-42ec-b503-ba8bf50a46c7', 'Login: Failed login', 'Une tentative de login console a échoué. Si répétée, c''est suspect (accès physique au serveur ?).', 'Échec de login', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'LOW', 60, 1, 1, 0, NULL, '1. Vérifier qui a accès physique au serveur
2. Si répété : examiner les logs et les caméras de surveillance du local
3. Considérer un verrouillage de la console après échecs'),
(5303, '2f563de3-0f25-443b-8114-7f1158e5b539', 'Login: Multiple failed logins', 'Plusieurs échecs de login console successifs. Quelqu''un essaie probablement de forcer l''accès physique.', 'Multiples échecs de login', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 80, 1, 0, 0, NULL, '1. Vérifier physiquement qui se trouve devant le serveur
2. Activer fail2ban-console ou pam_tally2 pour bloquer après N échecs
3. Restreindre l''accès au local serveur'),
(60106, 'e2df80ae-d427-4c36-8dc9-29842541e210', 'Windows: Failed login attempt', 'Échec d''authentification sur un poste Windows. Si isolé : erreur utilisateur. Si répété : tentative d''intrusion.', 'Échec login Windows', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'MEDIUM', 70, 1, 1, 0, NULL, '1. Identifier le compte et l''IP source dans les logs Windows
2. Activer le verrouillage automatique des comptes après N échecs
3. Sensibiliser les utilisateurs à ne pas partager leurs identifiants'),
(60107, 'e84d316f-d1e0-4e6c-bdfe-e188b552ce1e', 'Windows: Successful login', 'Connexion Windows réussie. Événement normal de traçabilité.', 'Login Windows réussi', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1078'), 'INFO', 50, 1, 1, 0, NULL, '1. Aucune action nécessaire - événement informationnel'),
(60108, 'e9ef7cee-e186-4364-a0bf-c87c565e531f', 'Windows: Multiple failed logins', 'Plusieurs échecs d''authentification Windows consécutifs. Présomption d''attaque par force brute.', 'Multiples échecs Windows', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 85, 1, 0, 0, NULL, '1. L''IP source sera bloquée si possible
2. Examiner les logs Event Viewer (Security log)
3. Imposer une politique de mots de passe complexes via GPO'),
(60109, 'b8614c7b-f8bf-4175-8b00-83a69f6ad66c', 'Windows: Logon outside business hours', 'Connexion Windows en dehors des heures de bureau. Peut être un employé en télétravail ou un attaquant utilisant un compte volé.', 'Login Windows hors heures', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1078'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. Contacter le propriétaire du compte pour confirmation
2. Vérifier la géolocalisation de l''IP source
3. Mettre en place des restrictions horaires par GPO si possible'),
(60204, '2484914d-40e6-4fbc-8fd1-aa469ff5a15f', 'Windows: Logon with explicit credentials', 'Connexion Windows avec credentials explicites (un utilisateur s''authentifie pour un autre). Comportement légitime ou suspect selon le contexte.', 'Login Windows avec credentials explicites', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1078'), 'MEDIUM', 65, 1, 0, 0, NULL, '1. Identifier le compte source et le compte cible
2. Vérifier la légitimité du basculement de compte
3. Surveiller l''utilisation des comptes admin'),
(60123, '15b2bb65-3bb4-4056-9007-3fa3f69790f0', 'Windows: Account lockout', 'Un compte Windows a été automatiquement verrouillé suite à trop d''échecs. C''est la protection qui a joué.', 'Verrouillage de compte Windows', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 80, 1, 0, 0, NULL, '1. Identifier le compte verrouillé et alerter son propriétaire
2. Vérifier l''IP source des tentatives (attaque externe ?)
3. Réinitialiser le compte une fois la cause confirmée bénigne'),
(60124, '914d0ec8-94ba-4ea8-bb57-4fd0906c5983', 'Windows: User account changed', 'Le compte d''un utilisateur Windows a été modifié (mot de passe, groupes, etc.). Toujours à valider.', 'Compte utilisateur Windows modifié', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1098'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. Vérifier qui a fait la modification et pourquoi
2. Si non autorisée, considérer une compromission de l''Active Directory
3. Auditer les logs d''événements 4720-4738 dans Event Viewer'),
(60125, '55165fc6-b94d-40a9-b8d1-8d72eddf16ca', 'Windows: Privileged group membership change', 'Un compte a été ajouté ou retiré d''un groupe privilégié (Administrators, Domain Admins, etc.). C''est une opération sensible qui doit être validée.', 'Modification d''''''''appartenance groupe privilégié', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1098'), 'CRITICAL', 90, 1, 0, 1, NULL, '1. URGENT : vérifier que cette modification est autorisée et tracée
2. Si non autorisée : retirer immédiatement et investiguer l''origine
3. Activer la journalisation des modifications d''AD (audit policy)'),
(5401, '73b2c578-3568-4da9-b736-6f80e6c95ee2', 'Sudo: privileged command', 'Une commande sudo privilégiée a été exécutée. À conserver pour la traçabilité.', 'Commande sudo privilégiée', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1548.003'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. Vérifier que la commande correspond à une opération attendue
2. Activer l''historique des commandes sudo via auditd'),
(40104, '826af0bc-d907-41fc-ac02-a0763f122821', 'FTP: Authentication failed', 'Échec d''authentification FTP. Le protocole FTP n''est pas chiffré : à éviter en production.', 'Échec authentification FTP', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'LOW', 60, 1, 1, 0, NULL, '1. Migrer vers SFTP (SSH File Transfer) ou FTPS
2. Si FTP nécessaire : restreindre par IP source au pare-feu
3. Surveiller la fréquence d''échecs pour détecter une attaque'),
(40105, '4a3fbd38-bb2f-4466-899a-3024a0b209df', 'FTP: Multiple authentication failures', 'Plusieurs échecs FTP successifs. Forte présomption d''attaque par force brute sur ce protocole vulnérable.', 'Multiples échecs FTP', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 80, 1, 0, 0, NULL, '1. L''IP attaquante est automatiquement bloquée
2. Désactiver FTP si non utilisé (port 21)
3. Si impossible, ajouter des règles fail2ban spécifiques FTP'),
(40106, 'e0bc22c7-6bbe-4cf2-926b-31b47baff913', 'FTP: Successful login from suspicious IP', 'Connexion FTP réussie depuis une IP suspecte (IP marquée comme malveillante en réputation). Possible compromission.', 'Login FTP réussi depuis IP suspecte', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1078'), 'CRITICAL', 90, 1, 0, 0, NULL, '1. URGENT : isoler le compte FTP utilisé
2. Vérifier les fichiers récemment téléversés/téléchargés via FTP
3. Désactiver FTP en clair et passer à SFTP'),
(40110, 'c0e1774b-57fd-4620-9b9f-4d2cf4aafcb0', 'VSFTPD: Authentication failure', 'Échec d''authentification sur le serveur VSFTPD. À surveiller si répété.', 'Échec d''''''''authentification VSFTPD', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'LOW', 60, 1, 1, 0, NULL, '1. Vérifier la légitimité de la tentative
2. Désactiver VSFTPD si non utilisé
3. Sinon, configurer le bannissement automatique'),
(40111, '85abf690-a09d-4d1c-a08d-e17a94f46b08', 'ProFTPD: Login failure', 'Échec de login sur ProFTPD. Surveiller la répétition.', 'Échec login ProFTPD', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'LOW', 60, 1, 1, 0, NULL, '1. Configurer fail2ban-proftpd pour bloquer les attaques
2. Désactiver ProFTPD si non utilisé'),
(50101, '9b443259-3826-43c5-b67a-31e0f0374d9c', 'MySQL: Authentication failed', 'Échec d''authentification MySQL. Une base de données est exposée et quelqu''un tente d''y accéder.', 'Échec authentification MySQL', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. Vérifier que MySQL n''est pas exposé sur Internet (bind-address dans my.cnf)
2. Forcer SSL/TLS pour toutes les connexions MySQL
3. Limiter les accès par IP avec --skip-networking ou bind-address=127.0.0.1'),
(50102, 'fadb410e-5af6-447b-966e-217246c55de6', 'MySQL: Brute force attempt', 'Tentative de force brute sur MySQL. Très critique car la BDD contient probablement des données sensibles.', 'Tentative de force brute MySQL', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 85, 1, 0, 0, NULL, '1. URGENT : vérifier que MySQL n''est pas accessible depuis Internet
2. Bloquer l''IP source immédiatement au pare-feu
3. Auditer les comptes MySQL et leurs privilèges (REVOKE excessive permissions)'),
(50103, '3e761b2e-1cdc-4f0f-a05f-1b10ac72d363', 'MySQL: Successful login from new location', 'Connexion MySQL réussie depuis un emplacement inhabituel. Vérifier la légitimité.', 'Login MySQL depuis nouvelle localisation', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1078'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. Identifier l''utilisateur MySQL et l''IP source
2. Vérifier si la connexion correspond à une activité attendue
3. Activer SSL pour les connexions MySQL si pas déjà fait'),
(50201, 'aedb85ee-822a-49de-b44f-97df86979b66', 'PostgreSQL: Authentication failure', 'Échec d''authentification PostgreSQL. À surveiller.', 'Échec authentification PostgreSQL', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. Vérifier l''exposition réseau de PostgreSQL (listen_addresses)
2. Configurer pg_hba.conf pour restreindre les IP sources
3. Activer SSL dans postgresql.conf'),
(50202, '18c9352a-8cab-4b23-807e-57f42eefb4ae', 'PostgreSQL: Brute force attempt', 'Attaque par force brute sur PostgreSQL. Très critique pour les données.', 'Force brute PostgreSQL', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 85, 1, 0, 0, NULL, '1. URGENT : bloquer l''IP source
2. Vérifier les logs PostgreSQL (pg_log)
3. Activer pg_hba.conf en mode ''hostssl'' uniquement'),
(31100, '80cface3-22d7-4fc6-a346-b8f66e6fbbc1', 'Web attack: SQL Injection attempt', 'Tentative d''injection SQL détectée sur l''application web. L''attaquant essaie d''extraire ou modifier des données de la BDD via le navigateur.', 'Tentative d''''''''injection SQL', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 85, 1, 0, 0, 'CVE-2023-12345', '1. L''IP est automatiquement bloquée si CRITICAL
2. Vérifier les logs du serveur web (Apache/Nginx) pour identifier l''URL ciblée
3. Mettre à jour le code applicatif (paramètres SQL préparés)
4. Installer un Web Application Firewall (ModSecurity, fail2ban-apache)'),
(31101, '3bfb3699-59c0-454c-ac1a-56b021b1e0c5', 'Web attack: SQL Injection (UNION-based)', 'Injection SQL avancée (UNION-based) : l''attaquant extrait directement des données de la BDD par le navigateur. Très grave.', 'Injection SQL UNION-based', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'CRITICAL', 90, 1, 0, 1, NULL, '1. URGENT : analyser les logs pour estimer les données exfiltrées
2. Bloquer l''IP source au pare-feu
3. Auditer le code applicatif et appliquer des requêtes paramétrées partout'),
(31102, 'd4651072-3974-457a-8a37-3bd4d3887173', 'Web attack: SQL Injection (Time-based blind)', 'Injection SQL aveugle (Time-based blind) : technique avancée d''extraction sans message d''erreur. Témoigne d''un attaquant sophistiqué.', 'Injection SQL time-based blind', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'CRITICAL', 90, 1, 0, 1, NULL, '1. URGENT : présence d''un attaquant ciblé et expert
2. Isoler l''application web et auditer le code
3. Activer un WAF (Web Application Firewall) en mode bloquant'),
(31103, '691f7222-ade3-40d1-a7b6-673cb63a6f7c', 'Web attack: XSS attempt detected', 'Tentative de XSS (Cross-Site Scripting) : l''attaquant essaie d''injecter du JavaScript malveillant pour voler les cookies des utilisateurs.', 'Tentative de XSS', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. Identifier la page vulnérable dans les logs web
2. Corriger le code applicatif (échapper toutes les sorties HTML)
3. Configurer les en-têtes Content-Security-Policy et HttpOnly sur les cookies'),
(31104, 'f078931a-6c7a-415f-9a50-6247b4dba0f8', 'Web attack: Reflected XSS', 'XSS réfléchi : l''attaquant essaie de faire cliquer un utilisateur sur un lien piégé. Si réussi, il vole la session.', 'XSS réfléchi', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. Identifier la page vulnérable et la corriger
2. Sensibiliser les utilisateurs à ne pas cliquer sur les liens suspects
3. Activer un WAF qui bloque les patterns XSS'),
(31105, '5a0ce001-2749-4484-bbc9-3228981cd586', 'Web attack: Stored XSS', 'XSS stocké : du code malveillant a été injecté dans la BDD et s''exécute pour tous les visiteurs. Très grave.', 'XSS stocké', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'CRITICAL', 90, 1, 0, 0, NULL, '1. URGENT : retirer le contenu malveillant de la BDD
2. Identifier et corriger la page vulnérable
3. Auditer toute la BDD pour d''autres injections'),
(31106, '96627ce2-8174-4f54-9fb1-6ad4026e6284', 'Web attack: Path traversal attempt', 'Tentative de Path Traversal : l''attaquant essaie d''accéder à des fichiers système comme /etc/passwd via l''URL (avec ../../../).', 'Tentative de path traversal', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 85, 1, 0, 0, NULL, '1. Vérifier les logs pour la cible exacte
2. Mettre à jour l''application web
3. Configurer le serveur web pour rejeter les ''../'' dans les URLs'),
(31107, '18f08e45-312c-4146-b4a1-dc654007ec55', 'Web attack: Local File Inclusion (LFI)', 'Local File Inclusion (LFI) : l''attaquant lit des fichiers du serveur via l''application. Préliminaire à une compromission.', 'Local File Inclusion', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'CRITICAL', 90, 1, 0, 1, NULL, '1. URGENT : l''application est vulnérable
2. Patcher le code (validation stricte des chemins)
3. Limiter les fichiers accessibles à l''application'),
(31108, '651b2800-3075-4336-a511-8394d6298e76', 'Web attack: Remote File Inclusion (RFI)', 'Remote File Inclusion (RFI) : l''attaquant essaie de faire exécuter un script malveillant hébergé ailleurs. Quasi-toujours suivi d''une compromission.', 'Remote File Inclusion', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'CRITICAL', 90, 1, 0, 1, NULL, '1. URGENT : possible code malveillant déjà téléchargé
2. Désactiver allow_url_include dans PHP
3. Auditer le serveur pour fichiers étrangers'),
(31109, 'f848a945-c494-48b5-89b2-a2972b784677', 'Web attack: Command injection attempt', 'Injection de commande système via l''application web : l''attaquant essaie d''exécuter des commandes shell sur le serveur. Très critique.', 'Tentative d''''''''injection de commande', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : risque de RCE (Remote Code Execution)
2. Vérifier l''existence de processus suspects sur le serveur
3. Patcher l''application immédiatement'),
(31110, 'd7198d5f-9924-43c7-8789-5635a0dd6ecd', 'Web attack: Web shell upload detected', 'Téléversement de web shell : l''attaquant essaie d''uploader un fichier qui lui permettra d''exécuter des commandes à distance. Très grave.', 'Upload de web shell détecté', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1505.003'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : possible web shell déjà installé
2. Rechercher les fichiers récents : find /var/www -mtime -1 -name ''*.php''
3. Auditer les permissions et désactiver l''upload si possible'),
(31111, 'd8d13e50-5d73-4da7-9ff4-816d7d84de35', 'Web attack: Sensitive file access (.git, .env)', 'Tentative d''accès à des fichiers sensibles (.git, .env, .htaccess). L''attaquant cherche des secrets exposés par erreur.', 'Accès fichier sensible', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 85, 1, 0, 0, NULL, '1. Vérifier qu''aucun fichier .git ou .env n''est exposé
2. Configurer le serveur web pour bloquer ces fichiers
3. Auditer les fichiers exposés avec : curl https://site.com/.env'),
(31112, 'd33a4df4-cdf5-45a5-a6c2-4f210a0d1b6d', 'Web attack: WordPress brute force', 'Attaque par force brute sur l''admin WordPress. Tentative de prendre le contrôle du site.', 'Force brute WordPress', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 80, 1, 0, 0, NULL, '1. L''IP est bloquée automatiquement
2. Installer un plugin de sécurité WordPress (Wordfence, iThemes)
3. Renommer la page de login wp-login.php
4. Activer la 2FA pour les comptes administrateurs'),
(31113, 'b0a0e43d-8d26-4b00-9fc3-6704169a8dcf', 'Web attack: WordPress XML-RPC abuse', 'Abus de l''API XML-RPC de WordPress : technique pour faire de la force brute massive sans déclencher les protections classiques.', 'Abus XML-RPC WordPress', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 80, 1, 0, 0, NULL, '1. Désactiver XML-RPC si non utilisé : Disallow /xmlrpc.php
2. Si nécessaire, restreindre par IP
3. Installer un plugin de protection XML-RPC'),
(31114, '6e226b4c-3a5b-487d-afdf-8acfbf69613c', 'Web attack: Joomla admin brute force', 'Force brute sur l''admin Joomla. Tentative de compromission du site.', 'Force brute Joomla admin', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 80, 1, 0, 0, NULL, '1. Restreindre l''accès admin par IP
2. Activer la double authentification Joomla
3. Renommer la page admin (composants tiers)'),
(31115, '6e89bb59-1aaf-4cd9-9958-6adbe7c19f46', 'Web attack: Drupal SQLi (Drupalgeddon)', 'Exploitation de Drupalgeddon : vulnérabilité critique connue de Drupal. Si non patché, le serveur peut être compromis en quelques secondes.', 'SQLi Drupal (Drupalgeddon)', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'CRITICAL', 95, 1, 0, 1, 'CVE-2014-3704', '1. URGENT : mettre à jour Drupal immédiatement
2. Vérifier l''absence de backdoor déjà installée
3. Auditer les comptes administrateurs Drupal'),
(31116, '49fb8880-e2d2-4b72-898b-ce81561a0058', 'Web attack: Apache Struts2 RCE', 'Exploitation Apache Struts (CVE-2017-5638 et autres). Vulnérabilité critique d''exécution de code.', 'RCE Apache Struts2', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'CRITICAL', 95, 1, 0, 1, 'CVE-2017-5638', '1. URGENT : patcher Struts ou retirer l''application
2. Vérifier les processus suspects sur le serveur
3. Auditer les fichiers récents pour backdoors'),
(31117, '085f9224-5402-4581-84bb-2d1f4eeda14c', 'Web attack: Log4Shell exploitation', 'Exploitation Log4Shell (CVE-2021-44228). Vulnérabilité critique mondiale qui permet d''exécuter du code via les logs d''une application Java.', 'Exploitation Log4Shell', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'CRITICAL', 100, 1, 0, 1, 'CVE-2021-44228', '1. URGENT : mettre à jour log4j vers >= 2.17.0
2. Vérifier toutes les applications Java
3. Bloquer l''IP source immédiatement'),
(31118, '6dc0020d-2bee-433b-80be-fc001240238f', 'Web attack: Spring4Shell', 'Exploitation Spring4Shell (CVE-2022-22965). Vulnérabilité critique de Spring Framework permettant l''exécution de code.', 'Exploitation Spring4Shell', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'CRITICAL', 95, 1, 0, 1, 'CVE-2022-22965', '1. URGENT : mettre à jour Spring Framework
2. Vérifier les applications Java exposées
3. Bloquer l''IP source'),
(31119, '30e58b01-3a25-48e6-88f5-7747e44e8495', 'Web attack: Suspicious User-Agent', 'Le User-Agent du navigateur est suspect (sqlmap, nikto, scanner, etc.). Indique un outil d''attaque automatisé.', 'User-Agent suspect (sqlmap, nikto)', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'MEDIUM', 70, 1, 1, 0, NULL, '1. Bloquer les User-Agents d''outils d''attaque dans Apache/Nginx
2. Examiner les autres requêtes de cette IP
3. Considérer un WAF en amont'),
(31120, '88f52fd2-7207-4c22-a511-3237c9afa182', 'Web attack: HTTP Request Smuggling', 'HTTP Request Smuggling : technique avancée qui exploite les différences entre proxy et serveur pour contourner les contrôles.', 'HTTP Request Smuggling', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'CRITICAL', 90, 1, 0, 0, NULL, '1. URGENT : vérifier la configuration du reverse proxy
2. Mettre à jour les composants HTTP (Apache, Nginx, HAProxy)
3. Activer un WAF capable de détecter le smuggling'),
(31121, 'ce5e321d-c659-443e-a71e-eb9cad30be4a', 'Web attack: SSRF attempt', 'SSRF (Server-Side Request Forgery) : l''attaquant force le serveur à faire des requêtes vers des cibles internes ou cloud (metadata AWS, etc.).', 'Tentative de SSRF', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 85, 1, 0, 0, NULL, '1. Auditer le code applicatif pour les fonctions de requête HTTP
2. Restreindre les URL accessibles depuis le serveur
3. Bloquer les requêtes vers 169.254.169.254 (metadata cloud)'),
(31122, 'c707a09d-7e85-460a-add1-15603c8c8756', 'Web attack: XML External Entity (XXE)', 'Attaque XXE (XML External Entity) : l''attaquant exploite le parsing XML pour lire des fichiers ou faire du SSRF.', 'XML External Entity', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 85, 1, 0, 0, NULL, '1. Désactiver le chargement d''entités externes dans le parseur XML
2. Mettre à jour les bibliothèques XML
3. Préférer JSON au XML quand possible'),
(31123, '7bdafced-2576-48cb-92db-79429ad88372', 'Web attack: Deserialization vulnerability', 'Exploitation d''une vulnérabilité de désérialisation. Permet souvent l''exécution de code arbitraire.', 'Vulnérabilité de désérialisation', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'CRITICAL', 90, 1, 0, 0, NULL, '1. URGENT : risque de RCE
2. Identifier et patcher l''application vulnérable
3. Auditer les composants Java/PHP/.NET de désérialisation'),
(31124, '58e708fa-41d5-4111-9db4-3e329a6cf33e', 'Web attack: phpMyAdmin attack', 'Attaque sur phpMyAdmin. Tentative d''accéder à l''interface d''administration de la BDD.', 'Attaque sur phpMyAdmin', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : phpMyAdmin ne doit JAMAIS être exposé en clair
2. Restreindre l''accès par IP ou via VPN
3. Renommer le chemin par défaut (/phpmyadmin → /db-admin-xyz)'),
(31125, '3cc93a32-e6c0-475f-ace6-79d54074ae03', 'Web attack: Apache Tomcat manager attack', 'Attaque sur le manager Apache Tomcat. Cherche à déployer une application malveillante.', 'Attaque sur Tomcat manager', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 85, 1, 0, 0, NULL, '1. Désactiver l''interface manager si non utilisée
2. Si nécessaire, restreindre par IP dans tomcat-users.xml
3. Changer le mot de passe par défaut'),
(31126, '536c0182-76aa-4350-be6b-c91babf71e19', 'Web attack: Suspicious file upload', 'Tentative de téléversement de fichier suspect. Vérifier les permissions.', 'Upload de fichier suspect', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1505.003'), 'HIGH', 80, 1, 0, 0, NULL, '1. Vérifier les fichiers récemment uploadés
2. Restreindre les types de fichiers acceptés
3. Stocker les uploads hors de la racine web'),
(31127, 'bf0d4408-9ed7-496b-ac2e-c5b0a46175c2', 'Web attack: Multiple 404 errors (scanning)', 'Nombreuses erreurs 404 successives. Indique un scan de l''application à la recherche de pages cachées.', 'Multiples erreurs 404 (scanning)', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'MEDIUM', 70, 1, 1, 0, NULL, '1. Identifier l''IP source dans les logs
2. Bloquer après N erreurs 404 (mod_evasive, fail2ban)
3. Auditer les chemins recherchés pour détecter une exposition'),
(31128, '04f918cb-afce-4e51-a12d-7ebb2c142c01', 'Web attack: HTTP method abuse (PUT, DELETE)', 'Utilisation de méthodes HTTP inhabituelles (PUT, DELETE, TRACE). Souvent signe d''attaque.', 'Abus de méthode HTTP', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. Désactiver les méthodes HTTP non nécessaires dans Apache/Nginx
2. Auditer si l''application a vraiment besoin de PUT/DELETE
3. Restreindre par IP les méthodes d''écriture'),
(31129, '1f3a6b3f-41b5-413d-994c-7a0704d62e6d', 'Web attack: Authentication bypass attempt', 'Tentative de contournement d''authentification : l''attaquant essaie des techniques connues (SQL injection sur login, manipulation de tokens, etc.).', 'Tentative de bypass auth', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 85, 1, 0, 0, NULL, '1. Vérifier les logs pour identifier la méthode utilisée
2. Renforcer le mécanisme d''authentification (2FA, captcha)
3. Activer la journalisation détaillée des tentatives'),
(31130, 'b8a136b9-90b4-4392-ab3c-f7c1fb906a0b', 'Web attack: Cookie manipulation', 'Manipulation suspecte de cookies. L''attaquant essaie probablement de modifier sa session pour usurper un autre utilisateur.', 'Manipulation de cookie', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. Vérifier que les cookies de session sont signés (HMAC)
2. Activer les flags HttpOnly et Secure
3. Régénérer les sessions après login'),
(31131, '51dc2538-199e-4c86-a0f5-a747ba065207', 'Web attack: CSRF attempt', 'Tentative de CSRF (Cross-Site Request Forgery) : l''attaquant essaie de faire faire des actions à un utilisateur connecté à son insu.', 'Tentative de CSRF', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. Vérifier la présence de tokens CSRF dans tous les formulaires
2. Activer SameSite=Strict sur les cookies
3. Auditer le code applicatif'),
(31132, 'da2fb7de-78ff-496f-a169-8fc587907ca1', 'Web attack: HTTP flood (DoS)', 'HTTP Flood : grand nombre de requêtes pour saturer le serveur. C''est une attaque DDoS de couche 7.', 'HTTP flood (DoS)', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1499'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : activer un anti-DDoS (Cloudflare, mod_evasive)
2. Bloquer les IP source si identifiables
3. Mettre en place un rate limiting au niveau Nginx/Apache'),
(31133, 'e233a15b-1472-43fa-9860-c477ed74e5c7', 'Web attack: Slowloris attack', 'Attaque Slowloris : l''attaquant maintient de nombreuses connexions ouvertes pour épuiser les ressources du serveur web.', 'Attaque Slowloris', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1499'), 'HIGH', 85, 1, 0, 0, NULL, '1. Configurer le timeout Apache/Nginx au minimum
2. Activer mod_reqtimeout dans Apache
3. Limiter le nombre de connexions par IP'),
(31134, '25f27e74-0e2a-4d2c-941a-2ef9dbcf645b', 'Web attack: WebDAV exploitation attempt', 'Tentative d''exploitation WebDAV : l''attaquant utilise les méthodes WebDAV pour téléverser ou modifier des fichiers.', 'Exploitation WebDAV', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. Désactiver WebDAV si non utilisé
2. Si nécessaire, restreindre par IP et authentification
3. Vérifier les fichiers récemment modifiés'),
(87501, 'aba32e85-4072-40de-8952-56cd77b44eeb', 'Rootkit: Hidden process detected', 'Un rootkit a été détecté : un processus essaie de se cacher du système. Compromission grave et avancée.', 'Processus caché détecté (rootkit)', 'wazuh', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1027'), 'CRITICAL', 90, 1, 0, 1, NULL, '1. URGENT : isoler le serveur du réseau
2. Lancer une analyse complète avec chkrootkit et rkhunter
3. Considérer une réinstallation complète après préservation des preuves'),
(87502, 'dfb682c0-a039-486b-bf87-d2341f53c25b', 'Rootkit: Hidden file in /tmp', 'Fichier caché trouvé dans /tmp. Probablement un fichier de malware ou de backdoor.', 'Fichier caché dans /tmp', 'wazuh', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1027'), 'CRITICAL', 90, 1, 0, 0, NULL, '1. Identifier le fichier (find /tmp -name ''.*'' -type f)
2. Analyser son contenu avant suppression
3. Vérifier les processus l''utilisant : lsof'),
(87503, 'e89500b0-9489-41c8-b7f8-e9d05ec673ca', 'Rootkit: Hidden port detected', 'Un port réseau ouvert n''apparaît pas dans la liste des connexions classiques. Signe typique de rootkit avec backdoor.', 'Port caché détecté', 'wazuh', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1027'), 'CRITICAL', 90, 1, 0, 1, NULL, '1. URGENT : isoler le serveur
2. Comparer netstat avec ss et lsof pour identifier le port caché
3. Analyse forensique requise'),
(87504, 'defe2263-80de-4353-bb49-14249982475d', 'Rootkit: Trojan binary detected', 'Un binaire de troyen connu a été détecté sur le système.', 'Binaire trojan détecté', 'wazuh', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1027'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : isoler le serveur
2. Supprimer le binaire et analyser sa provenance
3. Vérifier la persistance (cron, systemd, init)'),
(87505, 'e1f143d5-e9a1-4f7e-abfe-e69210da842a', 'Rootkit: Modified system binary', 'Un binaire système (ls, ps, netstat, etc.) a été modifié. Très typique d''une compromission par rootkit.', 'Binaire système modifié', 'wazuh', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1027'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : isoler le serveur
2. Réinstaller les paquets concernés : apt-get install --reinstall coreutils procps
3. Analyse forensique complète requise'),
(100001, '3aeaf9a7-5142-4481-b65a-5c071ba90aeb', 'Malware: Known malware hash detected', 'Un hash de malware connu a été détecté sur le système. La signature provient d''une base de menaces connues.', 'Hash de malware connu détecté', 'wazuh', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1027'), 'CRITICAL', 100, 1, 0, 1, NULL, '1. URGENT : isoler le fichier identifié
2. Vérifier sa provenance et son chemin d''exécution
3. Analyser le système pour persistance et propagation'),
(100002, '25ffc298-96f6-4e99-9965-afed4a00fd6e', 'Malware: Suspicious file extension (.exe in /tmp)', 'Un exécutable (.exe) a été trouvé dans un dossier temporaire (/tmp). Très suspect sur un système Linux.', 'Extension suspecte dans /tmp', 'wazuh', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1027'), 'HIGH', 80, 1, 0, 0, NULL, '1. Identifier le fichier et sa source
2. Vérifier s''il est en cours d''exécution
3. Supprimer après analyse'),
(100003, 'eff69d9c-6436-4482-a15b-d388c70348d6', 'Malware: ELF binary in unusual location', 'Un binaire ELF a été détecté dans un emplacement inhabituel. Souvent signe de malware.', 'Binaire ELF dans emplacement inhabituel', 'wazuh', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1027'), 'HIGH', 75, 1, 0, 0, NULL, '1. Identifier le binaire
2. Vérifier sa signature et son auteur
3. Si malveillant, isoler et nettoyer'),
(100004, '4de2db4a-2037-4002-b0bc-e626ac3fbcde', 'Ransomware: Mass file encryption detected', 'Activité de ransomware détectée : chiffrement massif de fichiers. URGENCE ABSOLUE.', 'Chiffrement massif de fichiers (ransomware)', 'wazuh', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'CRITICAL', 100, 1, 0, 1, NULL, '1. URGENT : déconnecter le serveur du réseau IMMÉDIATEMENT
2. Identifier le processus malveillant : ps auxf
3. Préserver les preuves pour analyse forensique
4. Restaurer depuis la dernière sauvegarde saine'),
(100005, '969c294b-895a-41c8-99e4-ba44d5747653', 'Ransomware: Ransom note detected', 'Une note de rançon a été détectée sur le système. Le ransomware a déjà commencé à chiffrer les fichiers.', 'Note de rançon détectée', 'wazuh', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'CRITICAL', 100, 1, 0, 1, NULL, '1. URGENT : déconnecter le serveur du réseau
2. NE PAS payer la rançon
3. Contacter immédiatement les autorités (CERT, ANSSI)
4. Restaurer depuis la dernière sauvegarde saine'),
(100006, 'c186052d-ff04-4fd1-a26e-3a9b46fcfaa4', 'Ransomware: Shadow copy deletion', 'Suppression des Volume Shadow Copies détectée. Le ransomware empêche la récupération de fichiers.', 'Suppression de shadow copies', 'wazuh', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1490'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : déconnecter le serveur
2. Le ransomware est en cours d''exécution
3. Activer la sauvegarde immutable pour éviter ces scénarios'),
(100007, 'bf845d6b-0cb3-4abb-b547-2bda557870be', 'Cryptominer: Mining pool connection', 'Connexion vers un pool de cryptominage détectée. Quelqu''un utilise votre serveur pour miner de la cryptomonnaie.', 'Connexion à pool de minage', 'wazuh', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1496'), 'HIGH', 90, 1, 0, 1, NULL, '1. Identifier le processus minier
2. Bloquer les IPs des pools de mining au pare-feu
3. Vérifier comment l''attaquant a accédé au serveur
4. Surveiller la charge CPU anormale'),
(100008, '3cabd864-a661-4a8e-9f36-6849afd12cf2', 'Cryptominer: Process detected (xmrig)', 'Processus de cryptominage XMRig détecté. Le serveur est utilisé sans votre consentement.', 'Processus de minage détecté', 'wazuh', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1496'), 'HIGH', 90, 1, 0, 0, NULL, '1. URGENT : tuer le processus xmrig
2. Vérifier la persistance (cron, systemd, /etc/profile.d/)
3. Auditer les comptes utilisateurs récents'),
(100009, 'e56ad78d-a142-48c3-864f-b6723337bb26', 'Cryptominer: High CPU usage by unknown process', 'Utilisation CPU anormalement élevée par un processus inconnu. Possible cryptomining ou processus malveillant.', 'CPU élevé par processus inconnu', 'wazuh', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1496'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. Identifier le processus : top, htop, ps auxf
2. Vérifier la légitimité
3. Si suspect, isoler et analyser'),
(100010, 'a402174a-c8be-4cd5-b256-dde348c6ab89', 'Backdoor: Reverse shell detected', 'Reverse shell détecté : un attaquant a établi une connexion sortante depuis votre serveur vers son infrastructure. Compromission active.', 'Reverse shell détecté', 'wazuh', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : isoler le serveur du réseau
2. Identifier le processus à l''origine
3. Tracer l''IP de destination
4. Analyse forensique complète'),
(100011, '28068b01-acf3-46dc-b8e2-d196f1d0dd35', 'Backdoor: Bind shell detected', 'Bind shell détecté : un attaquant écoute sur un port pour recevoir des connexions. Backdoor active.', 'Bind shell détecté', 'wazuh', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 95, 1, 0, 0, NULL, '1. URGENT : identifier le port et le processus
2. Tuer le processus et fermer le port
3. Analyser comment l''attaquant a obtenu l''accès'),
(100012, '54f4053a-b59a-413a-ae1e-d3f64bd617ba', 'Trojan: Known trojan signature', 'Signature de troyen connu détectée dans un processus actif.', 'Signature trojan connue', 'wazuh', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1027'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : isoler le serveur
2. Identifier et tuer le processus
3. Analyse forensique requise'),
(100013, '4a739649-6aca-4674-bd07-4d85bf40fd50', 'Worm: Self-replicating behavior', 'Comportement de ver auto-réplicant détecté : un programme se duplique sur d''autres machines.', 'Comportement de ver auto-réplicant', 'wazuh', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1080'), 'CRITICAL', 90, 1, 0, 0, NULL, '1. URGENT : isoler le serveur du réseau
2. Identifier le binaire à l''origine
3. Auditer les machines voisines'),
(100014, 'b7009b91-f922-42c7-b76f-ed5320122545', 'Botnet: C2 communication detected', 'Communication Command & Control (C2) détectée : le serveur dialogue avec un attaquant distant. Compromission active grave.', 'Communication C2 botnet', 'wazuh', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : isoler le serveur
2. Tracer l''IP du C2 (ThreatIntel)
3. Identifier le processus client
4. Analyse forensique'),
(100015, '89498d69-cdb6-48da-b509-665e8d8749e1', 'Suspicious: Encoded PowerShell command', 'Commande PowerShell encodée détectée. Souvent utilisée par les attaquants pour masquer leurs actions.', 'Commande PowerShell encodée', 'wazuh', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1059.001'), 'HIGH', 85, 1, 0, 0, NULL, '1. Décoder la commande pour analyse
2. Vérifier le contexte d''exécution
3. Activer PowerShell logging et ScriptBlock logging'),
(100016, '00c23e66-6dff-4667-b047-b9628b1d6b8f', 'Suspicious: Base64 encoded payload', 'Payload encodé en Base64 détecté. Tactique classique d''obfuscation utilisée par les malwares.', 'Payload base64 suspect', 'wazuh', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1027'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. Décoder pour identifier le contenu
2. Vérifier le processus à l''origine
3. Bloquer si malveillant'),
(100017, '5630c66b-340c-4405-98b3-799df274c601', 'Suspicious: Curl/wget downloading executable', 'Utilisation de curl/wget pour télécharger un exécutable. Comportement souvent associé aux malwares post-exploitation.', 'Curl/wget téléchargeant exécutable', 'wazuh', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1105'), 'HIGH', 80, 1, 0, 0, NULL, '1. Identifier le fichier téléchargé et son URL
2. Vérifier s''il a été exécuté
3. Analyser le binaire avant action'),
(100018, '74324dec-f54c-4de5-b1ae-f1bdf1415848', 'Suspicious: Direct IP HTTP download', 'Téléchargement HTTP direct vers une IP (pas un nom de domaine). Très suspect.', 'Téléchargement HTTP par IP directe', 'wazuh', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1105'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. Vérifier le destinataire et le contenu
2. Bloquer le téléchargement si malveillant
3. Identifier le processus à l''origine'),
(100019, '910fa7a9-0107-45fb-9c40-d00a5d6d54d2', 'Suspicious: Process from /tmp execution', 'Exécution d''un programme depuis /tmp. Légitime parfois mais souvent signe de compromission.', 'Exécution depuis /tmp', 'wazuh', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1059.004'), 'HIGH', 80, 1, 0, 0, NULL, '1. Vérifier l''identité et la signature du fichier
2. Si suspect, tuer le processus et l''analyser
3. Monter /tmp en noexec si possible'),
(100020, 'aeb49fc7-2c56-459c-aa15-859811cd9037', 'Suspicious: Memory injection detected', 'Injection de code en mémoire détectée. Technique avancée d''évasion utilisée par les malwares modernes.', 'Injection mémoire détectée', 'wazuh', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1055'), 'CRITICAL', 90, 1, 0, 1, NULL, '1. URGENT : isoler le serveur
2. Capture mémoire pour analyse forensique
3. Anti-malware nouvelle génération requis'),
(110001, '2168f99b-a543-4d26-86f3-627038c60fb1', 'Network: Port scan detected (TCP SYN)', 'Scan de ports TCP SYN détecté : un attaquant cartographie les services ouverts de votre serveur. Préliminaire à une attaque ciblée.', 'Scan de ports TCP SYN détecté', 'wazuh', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'MEDIUM', 75, 1, 1, 0, NULL, '1. L''IP source sera bloquée par l''agent
2. Identifier les ports scannés pour évaluer la cible
3. Restreindre les services exposés au strict nécessaire'),
(110002, 'f4ead343-97d6-41d5-9564-4af9d6e98f04', 'Network: Port scan detected (TCP FIN)', 'Scan TCP FIN : technique furtive pour cartographier les ports tout en évitant certains firewalls.', 'Scan de ports TCP FIN', 'wazuh', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'MEDIUM', 75, 1, 1, 0, NULL, '1. Bloquer l''IP source
2. Auditer la configuration du pare-feu
3. Surveiller les autres tentatives de la même IP'),
(110003, '34786590-d9b7-48c8-bed5-d445fe76425e', 'Network: UDP port scan', 'Scan UDP de ports. L''attaquant cherche les services UDP exposés (DNS, SNMP, etc.).', 'Scan de ports UDP', 'wazuh', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. Bloquer l''IP source
2. Restreindre les services UDP au strict nécessaire
3. Vérifier la configuration SNMP (community strings)'),
(110004, '4dfe536d-1e12-4a36-b0b7-6c46eab3303b', 'Network: Service version scan', 'Scan de versions de services : l''attaquant essaie d''identifier les logiciels et versions pour trouver des vulnérabilités.', 'Scan de version de services', 'wazuh', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'HIGH', 80, 1, 0, 0, NULL, '1. Bloquer l''IP source
2. Masquer les bannières de service si possible
3. Vérifier que tous les services sont à jour'),
(110005, '9f9d2c31-3371-4560-8ec7-9701e310fa83', 'Network: OS fingerprinting attempt', 'Tentative de fingerprinting OS : l''attaquant identifie votre système d''exploitation pour préparer une attaque ciblée.', 'Tentative d''''''''OS fingerprinting', 'wazuh', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'MEDIUM', 75, 1, 0, 0, NULL, '1. Bloquer l''IP source
2. Configurer le système pour ne pas révéler son OS
3. Préparer des correctifs OS à jour'),
(110006, '1a3730aa-087a-40f6-b696-f24f18f6310d', 'Network: ARP scan', 'Scan ARP sur le réseau local. Quelqu''un essaie d''identifier les machines présentes.', 'Scan ARP', 'wazuh', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'LOW', 60, 1, 1, 0, NULL, '1. Vérifier qui est sur le réseau interne
2. Activer la détection ARP spoofing
3. Si externe, problème de fuite réseau'),
(110007, '92a723c3-0cf3-43ee-8052-b1608f6be232', 'Network: Ping sweep detected', 'Balayage ping : envoi de ping vers toute une plage d''IPs. Reconnaissance préliminaire.', 'Ping sweep détecté', 'wazuh', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'LOW', 60, 1, 1, 0, NULL, '1. Activité courante mais à surveiller
2. Bloquer ICMP entrant si possible
3. Identifier l''origine'),
(110008, '7034bc40-07ab-4005-8648-33766c3c6cb0', 'Network: Stealth scan (NULL flags)', 'Scan NULL flags : technique furtive de scan utilisée par nmap. Indique un attaquant expérimenté.', 'Scan furtif (NULL flags)', 'wazuh', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'HIGH', 80, 1, 0, 0, NULL, '1. Bloquer l''IP source
2. Renforcer la configuration du pare-feu
3. Surveiller les actions suivantes'),
(110009, '2a3145f8-d5fc-4558-b8f9-2037d648d46d', 'Network: Xmas scan', 'Scan Xmas : tous les flags TCP allumés. Technique de scan avancée.', 'Xmas scan', 'wazuh', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'HIGH', 80, 1, 0, 0, NULL, '1. Bloquer l''IP source
2. Examiner les autres requêtes de cette IP
3. Renforcer le pare-feu'),
(110010, 'c6951292-cf8c-4921-9920-6ce8bf348a29', 'Network: ACK scan', 'Scan ACK : technique pour mapper les règles de firewall.', 'ACK scan', 'wazuh', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. Bloquer l''IP source
2. Auditer la configuration du pare-feu
3. Implémenter du stateful inspection'),
(110011, 'bde62fbd-9b3e-4d6d-8511-82e3f2da9d9e', 'Network: Idle/Zombie scan', 'Scan via machine zombie : l''attaquant utilise une 3ème machine pour scanner anonymement.', 'Idle/Zombie scan', 'wazuh', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'HIGH', 80, 1, 0, 0, NULL, '1. Bloquer l''IP zombie identifiée
2. Surveiller les activités liées
3. Renforcer le monitoring réseau'),
(110012, '5d5e11bf-2a72-4a8c-8034-f208077efbbb', 'Network: SMB enumeration', 'Énumération SMB détectée : l''attaquant liste les partages réseau Windows.', 'Énumération SMB', 'wazuh', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1135'), 'HIGH', 80, 1, 0, 0, NULL, '1. Désactiver SMBv1 et v2 (vulnérables)
2. Restreindre l''accès SMB par IP
3. Activer l''authentification SMB obligatoire'),
(110013, '09b3b591-80f5-43c0-a6b9-216e9659019b', 'Network: SNMP enumeration', 'Énumération SNMP : l''attaquant essaie de récupérer des infos système via SNMP (souvent avec ''public'' comme community).', 'Énumération SNMP', 'wazuh', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. Changer les community strings SNMP par défaut
2. Désactiver SNMP si non utilisé
3. Restreindre l''accès par IP'),
(110014, '678a5649-91d9-432b-ae18-be6ed1ab0d0c', 'Network: DNS zone transfer attempt', 'Tentative de transfert de zone DNS : l''attaquant veut récupérer la liste complète de vos sous-domaines.', 'Tentative de transfert de zone DNS', 'wazuh', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1135'), 'HIGH', 85, 1, 0, 0, NULL, '1. Désactiver les transferts de zone non autorisés
2. Restreindre AXFR à vos serveurs DNS uniquement
3. Audit DNS périodique'),
(110015, 'dc8913bf-214b-4e6b-af1f-27e6599fc38a', 'Network: NetBIOS enumeration', 'Énumération NetBIOS : l''attaquant essaie d''identifier les machines Windows et leurs services.', 'Énumération NetBIOS', 'wazuh', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1135'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. Désactiver NetBIOS si non utilisé
2. Bloquer le port 137 au pare-feu externe
3. Audit des services Windows exposés'),
(5104, '0b6456f2-5d29-4d4d-b3ee-c59d6e126ded', 'Sudoers file modified', 'Le fichier /etc/sudoers a été modifié. C''est une opération sensible : un attaquant peut s''octroyer des droits admin.', 'Fichier sudoers modifié', 'wazuh', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1548.003'), 'CRITICAL', 90, 1, 0, 1, NULL, '1. URGENT : vérifier qui a modifié le fichier (auth.log)
2. Comparer avec la dernière sauvegarde de sudoers
3. Si non autorisé, retirer les modifications immédiatement'),
(5105, '4fef64ff-200b-4626-afdd-33aaa0686080', 'User added to sudo group', 'Un utilisateur a été ajouté au groupe sudo. C''est une élévation de privilèges qui doit être validée.', 'Utilisateur ajouté au groupe sudo', 'wazuh', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1068'), 'CRITICAL', 90, 1, 0, 0, NULL, '1. URGENT : vérifier la légitimité de l''ajout
2. Si non autorisé, retirer l''utilisateur : deluser <user> sudo
3. Identifier qui a fait l''opération'),
(120001, '495d0773-67b4-4cb0-b8a1-376078185f56', 'Privilege escalation: Suspicious sudo usage', 'Utilisation suspecte de sudo : commandes, fréquence ou horaire inhabituels.', 'Usage sudo suspect', 'wazuh', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1548.003'), 'HIGH', 85, 1, 0, 0, NULL, '1. Examiner les commandes sudo récentes : journalctl _COMM=sudo
2. Vérifier la légitimité auprès de l''utilisateur
3. Restreindre les commandes sudo autorisées'),
(120002, '9a519a54-adea-4d4f-840f-e49fd044a79e', 'Privilege escalation: setuid binary execution', 'Exécution d''un binaire setuid : permet d''exécuter du code avec les droits du propriétaire (souvent root). Voie classique d''escalade.', 'Exécution binaire setuid', 'wazuh', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1548.001'), 'HIGH', 80, 1, 0, 0, NULL, '1. Identifier le binaire concerné
2. Vérifier sa légitimité
3. Auditer tous les setuid : find / -perm -4000 2>/dev/null'),
(120003, 'dc2d011d-f479-4ed2-8ca9-b4e703621d3c', 'Privilege escalation: New setuid file created', 'Création d''un nouveau fichier setuid. Si non autorisé, c''est typiquement une backdoor d''escalade de privilèges.', 'Nouveau fichier setuid', 'wazuh', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1548.001'), 'HIGH', 85, 1, 0, 0, NULL, '1. URGENT : identifier le fichier et son créateur
2. Si non autorisé, retirer le bit setuid : chmod -s
3. Surveiller pour persistance'),
(120004, '5b0d2401-23bf-466d-966c-be84ba2ed2e3', 'Privilege escalation: Kernel exploit attempt', 'Tentative d''exploit du noyau Linux. Si réussi, l''attaquant obtient root.', 'Tentative d''''''''exploit kernel', 'wazuh', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1068'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : vérifier la version du noyau
2. Appliquer les correctifs disponibles
3. Considérer le serveur comme compromis'),
(120005, '79d420cb-2e9b-4e4d-9611-1fd4538a8d9e', 'Privilege escalation: DirtyPipe exploit (CVE-2022-0847)', 'Exploitation de DirtyPipe (CVE-2022-0847) : faille critique permettant à un utilisateur normal de devenir root.', 'Exploit DirtyPipe', 'wazuh', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1068'), 'CRITICAL', 100, 1, 0, 1, 'CVE-2022-0847', '1. URGENT : mettre à jour le noyau Linux >= 5.16.11
2. Considérer le serveur compromis si l''exploit a réussi
3. Auditer les modifications récentes du système'),
(120006, 'a1ce3839-f5e5-4337-866a-2d3b8b30ef75', 'Privilege escalation: PwnKit exploit (CVE-2021-4034)', 'Exploitation de PwnKit (CVE-2021-4034) : faille critique de polkit permettant l''escalade de privilèges.', 'Exploit PwnKit', 'wazuh', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1068'), 'CRITICAL', 100, 1, 0, 1, 'CVE-2021-4034', '1. URGENT : mettre à jour le paquet polkit
2. Vérifier les utilisateurs créés récemment
3. Auditer les actions des comptes non admin'),
(120007, '66d5356e-be8a-4240-87f5-17464c2177b2', 'Privilege escalation: Capabilities abuse', 'Abus des capabilities Linux : technique d''escalade alternative aux droits root classiques.', 'Abus de capabilities Linux', 'wazuh', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1068'), 'HIGH', 85, 1, 0, 0, NULL, '1. Auditer les capabilities : getcap -r / 2>/dev/null
2. Retirer les capabilities non nécessaires
3. Mettre à jour les paquets concernés'),
(120008, '1de2e37a-6948-46b9-86df-b05e5b788187', 'Privilege escalation: Container escape attempt', 'Tentative d''évasion d''un conteneur Docker/LXC. L''attaquant essaie de sortir du conteneur pour accéder à l''hôte.', 'Tentative d''''''''évasion container', 'wazuh', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1068'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : isoler le conteneur
2. Mettre à jour Docker/runc
3. Vérifier la configuration de sécurité du conteneur (no privileged mode)'),
(120009, 'ddc2c800-30ef-417f-aac3-c0498ee53256', 'Privilege escalation: Token manipulation (Windows)', 'Manipulation de token Windows : technique d''escalade de privilèges Windows.', 'Manipulation de token Windows', 'wazuh', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1068'), 'HIGH', 85, 1, 0, 0, NULL, '1. Identifier le processus impliqué
2. Examiner les logs Windows Security
3. Activer SELinux/AppArmor équivalent (PolicyKit, etc.)'),
(120010, '8046ade7-7ad8-40f8-b7e8-15b90f0f2d5a', 'Privilege escalation: UAC bypass attempt', 'Tentative de contournement de l''UAC (User Account Control) Windows.', 'Bypass UAC', 'wazuh', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1068'), 'HIGH', 85, 1, 0, 0, NULL, '1. Maintenir l''UAC au niveau le plus restrictif
2. Identifier l''application source
3. Auditer les logs Windows'),
(120011, 'f27fa1ef-f742-4e1e-8369-3995d6996912', 'Privilege escalation: Service permissions modified', 'Modification des permissions d''un service système. Permet souvent l''escalade de privilèges.', 'Permissions de service modifiées', 'wazuh', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1574'), 'HIGH', 80, 1, 0, 0, NULL, '1. Identifier le service modifié
2. Restaurer les permissions par défaut
3. Vérifier qui a fait la modification'),
(120012, '4421d4ba-9dbf-40d0-8a44-aa2cc6cb8ab2', 'Privilege escalation: Scheduled task with SYSTEM', 'Création d''une tâche planifiée s''exécutant en SYSTEM. Voie classique d''escalade.', 'Tâche planifiée avec SYSTEM', 'wazuh', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1068'), 'HIGH', 85, 1, 0, 0, NULL, '1. Identifier la tâche créée
2. Si non autorisée, supprimer
3. Auditer toutes les tâches planifiées'),
(120013, 'ae9b9642-ffaa-4cd6-9736-8ea4076e72cd', 'Privilege escalation: Sudo wildcard abuse', 'Abus de wildcard dans sudo : technique pour exécuter des commandes non autorisées via les jokers.', 'Abus sudo avec wildcard', 'wazuh', 5, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1548.003'), 'HIGH', 80, 1, 0, 0, NULL, '1. Auditer le fichier sudoers pour les wildcards dangereux
2. Remplacer * par les chemins absolus
3. Restreindre les commandes sudo au strict nécessaire'),
(130001, '4220d93e-20fa-47f9-9c10-0b6e3c8c05e1', 'Data exfiltration: Large outbound data transfer', 'Volume important de données envoyé vers Internet. Possible exfiltration de données par un attaquant.', 'Transfert sortant volumineux', 'wazuh', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1041'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : identifier la destination du transfert
2. Bloquer la connexion si malveillante
3. Tracer le processus à l''origine'),
(130002, 'f0ceac45-2289-4bd9-b8aa-f4c4d6c7103e', 'Data exfiltration: DNS tunneling detected', 'Tunneling DNS détecté : technique d''exfiltration où les données sont encodées dans des requêtes DNS.', 'Tunneling DNS détecté', 'wazuh', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.004'), 'CRITICAL', 90, 1, 0, 1, NULL, '1. URGENT : bloquer le serveur DNS de destination
2. Inspecter les noms de domaine résolus récemment
3. Activer une analyse DNS approfondie'),
(130003, '4aeba63f-a526-4701-bc93-124542ec7a0a', 'Data exfiltration: Upload to cloud storage', 'Upload vers un service de stockage cloud (Dropbox, Google Drive, etc.). Peut être légitime ou exfiltration.', 'Upload vers stockage cloud', 'wazuh', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1567'), 'HIGH', 75, 1, 0, 0, NULL, '1. Vérifier la légitimité avec l''utilisateur
2. Si non autorisé, bloquer le service au pare-feu
3. Politique DLP (Data Loss Prevention)'),
(130004, '1081419a-7767-423c-83ba-4030f6cab0c2', 'Data exfiltration: Tor traffic detected', 'Trafic Tor détecté depuis votre réseau. Souvent associé à de l''exfiltration ou à des activités malveillantes.', 'Trafic Tor détecté', 'wazuh', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1090'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. Vérifier la légitimité (employé légitime ?)
2. Bloquer Tor au pare-feu si non autorisé
3. Auditer la machine source'),
(130005, 'ab09ca5f-1f97-4078-a9f0-7a877b3d4ef2', 'Data exfiltration: Pastebin upload', 'Upload vers Pastebin ou service similaire. Tactique classique pour exfiltrer des secrets/credentials.', 'Upload vers Pastebin', 'wazuh', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1567'), 'HIGH', 80, 1, 0, 0, NULL, '1. Bloquer Pastebin au pare-feu d''entreprise
2. Vérifier ce qui a été uploadé
3. Renforcer la politique DLP'),
(130006, 'b246bd72-683a-43bc-96f3-c08197c10a9f', 'Data exfiltration: Suspicious HTTPS to file sharing', 'Trafic HTTPS suspect vers un service de partage de fichiers.', 'HTTPS vers file sharing', 'wazuh', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1567'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. Vérifier la légitimité de la destination
2. Inspecter le trafic SSL si possible
3. Restreindre les services autorisés'),
(130007, '06ba5627-7583-47b6-b3e3-067194e3847d', 'Data exfiltration: ICMP data tunneling', 'Tunneling de données dans des paquets ICMP. Technique d''exfiltration furtive.', 'Tunneling de données via ICMP', 'wazuh', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.004'), 'HIGH', 85, 1, 0, 0, NULL, '1. URGENT : bloquer l''ICMP sortant ou le limiter
2. Identifier le processus à l''origine
3. Inspecter les paquets ICMP'),
(130008, '119d8b45-cf10-4eda-853e-6ba3c1880058', 'Data exfiltration: Compressed archive sent externally', 'Archive compressée envoyée vers l''extérieur. Tactique classique d''exfiltration de masse.', 'Archive envoyée à l''''''''extérieur', 'wazuh', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1041'), 'HIGH', 80, 1, 0, 0, NULL, '1. Vérifier le contenu et le destinataire
2. Si non autorisé, bloquer et analyser
3. Activer le DLP'),
(130009, '104719bd-01d9-44d0-95cd-8ec8b06da898', 'Data exfiltration: Database dump detected', 'Dump de base de données détecté : possible exfiltration massive de données client.', 'Dump de base de données', 'wazuh', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1005'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : identifier qui dump et où va la donnée
2. Si malveillant : isoler la BDD
3. Notifier la CNIL si données personnelles concernées'),
(130010, '6ec061db-7e8c-4bef-92a5-c2a1f1789380', 'Data exfiltration: Email with sensitive data', 'Email contenant des données sensibles envoyé. Possible fuite d''information.', 'Email avec données sensibles', 'wazuh', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1114'), 'HIGH', 80, 1, 0, 0, NULL, '1. Identifier l''expéditeur et le destinataire
2. Vérifier la légitimité
3. Mettre en place un DLP email'),
(140001, '74f1c9f1-4b7f-4e99-b613-3777477d5f7d', 'Lateral movement: SSH from internal IP to multiple hosts', 'Une machine interne se connecte en SSH à plusieurs autres machines. Tactique de mouvement latéral après compromission.', 'SSH interne vers multiples hôtes', 'wazuh', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1021.004'), 'HIGH', 85, 1, 0, 0, NULL, '1. URGENT : isoler la machine source
2. Investiguer la compromission initiale
3. Auditer les comptes utilisés'),
(140002, '6f996277-d290-404b-a9f0-88ac80b5160c', 'Lateral movement: PsExec usage detected', 'Utilisation de PsExec détectée : outil Microsoft souvent abusé pour exécuter des commandes à distance dans un mouvement latéral.', 'PsExec détecté', 'wazuh', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1210'), 'CRITICAL', 90, 1, 0, 0, NULL, '1. URGENT : identifier l''origine et la destination
2. Vérifier les comptes utilisés
3. Restreindre l''utilisation de PsExec via GPO'),
(140003, '9c835069-9d68-4b87-8cc7-e2332f56346b', 'Lateral movement: WMI execution', 'Exécution via WMI : technique légitime mais souvent abusée pour mouvement latéral discret.', 'Exécution WMI', 'wazuh', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1210'), 'HIGH', 85, 1, 0, 0, NULL, '1. Examiner les processus créés via WMI
2. Identifier la machine source
3. Activer le logging WMI'),
(140004, '4af3f8b8-a5b3-4036-8f3e-3b4dcba186de', 'Lateral movement: SMB connection from non-admin', 'Connexion SMB depuis un compte non-admin vers plusieurs serveurs. Suspect.', 'Connexion SMB non-admin', 'wazuh', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1210'), 'HIGH', 80, 1, 0, 0, NULL, '1. Identifier le compte source
2. Vérifier sa légitimité
3. Restreindre les accès SMB'),
(140005, '43b5497d-5ff7-4b57-972b-f9ecc7be662c', 'Lateral movement: Pass-the-hash attempt', 'Tentative de Pass-the-Hash : l''attaquant réutilise le hash de mot de passe Windows sans le connaître. Technique avancée.', 'Pass-the-hash', 'wazuh', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1210'), 'CRITICAL', 90, 1, 0, 1, NULL, '1. URGENT : compromission Active Directory probable
2. Réinitialiser les comptes affectés
3. Activer Credential Guard sur Windows'),
(140006, '1cae714f-f3ec-44e2-af72-b8081812875f', 'Lateral movement: Pass-the-ticket attempt', 'Tentative de Pass-the-Ticket : réutilisation d''un ticket Kerberos volé.', 'Pass-the-ticket Kerberos', 'wazuh', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1210'), 'CRITICAL', 90, 1, 0, 1, NULL, '1. URGENT : compromission AD avancée
2. Réinitialiser les comptes
3. Réinitialiser le mot de passe KRBTGT'),
(140007, '978aa2b3-9022-439e-8399-73c1148908df', 'Lateral movement: RDP from internal network', 'Connexion RDP depuis le réseau interne. Vérifier la légitimité.', 'RDP depuis réseau interne', 'wazuh', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1021.001'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. Vérifier que la connexion est attendue
2. Restreindre RDP aux IP autorisées
3. Activer RDP via VPN seulement'),
(140008, '78f30eb9-f646-489f-a822-2b104d71a06d', 'Lateral movement: WinRM execution', 'Utilisation de WinRM pour exécution distante. Tactique classique post-compromission.', 'Exécution WinRM', 'wazuh', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1210'), 'HIGH', 85, 1, 0, 0, NULL, '1. Identifier la machine source
2. Vérifier l''autorisation
3. Restreindre WinRM via GPO'),
(140009, 'ffa5f3d8-574d-41c3-81aa-d24020ac83b0', 'Lateral movement: Network share enumeration', 'Énumération de partages réseau. Indique un attaquant en phase de reconnaissance.', 'Énumération de partages réseau', 'wazuh', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1135'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. Identifier la source de l''énumération
2. Restreindre les permissions sur les partages
3. Auditer les accès'),
(140010, '51818ee4-7c85-4718-aea9-642bb8bbab00', 'Lateral movement: SMB MS17-010 (EternalBlue)', 'Tentative d''exploitation de MS17-010 (EternalBlue) : vulnérabilité SMB qui a causé WannaCry. Très critique si non patché.', 'Exploitation EternalBlue', 'wazuh', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1210'), 'CRITICAL', 100, 1, 0, 1, 'CVE-2017-0144', '1. URGENT : vérifier que le patch MS17-010 est appliqué
2. Désactiver SMBv1
3. Bloquer SMB en sortie d''Internet'),
(140011, '8f4cd37f-f1ec-4af8-bad1-213bf1826280', 'Lateral movement: SAMR enumeration', 'Énumération SAMR : l''attaquant liste les comptes et groupes Active Directory.', 'Énumération SAMR', 'wazuh', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1135'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. Restreindre les requêtes SAMR aux comptes admin
2. Activer l''audit AD
3. Identifier la source'),
(140012, 'f50ce360-bdbc-4a82-b224-29314dacf41c', 'Lateral movement: BloodHound activity', 'Activité BloodHound détectée : outil de cartographie AD utilisé par les attaquants pour planifier leur progression.', 'Activité BloodHound', 'wazuh', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1135'), 'HIGH', 85, 1, 0, 0, NULL, '1. URGENT : un attaquant cartographie l''AD
2. Identifier la machine source
3. Réviser les ACL et chemins d''attaque'),
(140013, '7b0d10cd-b449-48e4-95bb-ddf1ba4b676c', 'Lateral movement: Mimikatz signature detected', 'Signature de Mimikatz détectée : outil classique pour extraire des credentials Windows en mémoire.', 'Signature Mimikatz', 'wazuh', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1210'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : la machine est compromise
2. Isoler immédiatement et changer les credentials
3. Activer Credential Guard'),
(140014, 'aa20fe00-e6a8-4464-935c-efec19d9f78c', 'Lateral movement: DCSync attack', 'Attaque DCSync : l''attaquant force un contrôleur de domaine à lui envoyer tous les hashes de mots de passe AD.', 'Attaque DCSync', 'wazuh', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1210'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : compromission AD totale
2. Réinitialiser tous les comptes
3. Réinitialiser KRBTGT 2 fois'),
(140015, '24223cdb-702b-4862-8d80-5b1185c7632b', 'Lateral movement: Kerberoasting attempt', 'Tentative de Kerberoasting : extraction de tickets Kerberos de comptes de service pour casser leurs mots de passe hors ligne.', 'Tentative de Kerberoasting', 'wazuh', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1210'), 'HIGH', 85, 1, 0, 0, NULL, '1. Identifier les comptes de service ciblés
2. Renforcer les mots de passe des comptes service (25+ caractères)
3. Utiliser des comptes gMSA quand possible'),
(150001, '781aa67d-e3a0-44ce-a2ea-b1abe47fe9c4', 'Persistence: New systemd service created', 'Création d''un nouveau service systemd. Doit être validé sinon c''est une backdoor.', 'Nouveau service systemd', 'wazuh', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1543.002'), 'HIGH', 85, 1, 0, 0, NULL, '1. Identifier le service créé : systemctl list-units --type=service --all
2. Si non autorisé, désactiver et supprimer
3. Vérifier le binaire associé'),
(150002, '350cbfcb-56cb-450f-801b-0b9d0d18a0ad', 'Persistence: Suspicious cron job added', 'Nouvelle tâche cron suspecte ajoutée. Tactique classique de persistance.', 'Cron suspect ajouté', 'wazuh', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1053.003'), 'HIGH', 85, 1, 0, 0, NULL, '1. Auditer crontab -l pour chaque utilisateur
2. Examiner /etc/cron.* pour entrées suspectes
3. Si non autorisée, supprimer'),
(150003, 'c4513172-cb84-4d8e-908e-7315ea81d8b3', 'Persistence: bashrc modified', 'Le fichier .bashrc d''un utilisateur a été modifié. Peut contenir une commande malveillante exécutée à chaque login.', 'bashrc modifié', 'wazuh', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1547'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. Examiner le contenu du .bashrc concerné
2. Comparer avec une version saine
3. Auditer les autres fichiers de profil shell'),
(150004, 'c1584705-5354-4df5-9fc5-2204fc4a36e9', 'Persistence: SSH authorized_keys modified', 'Le fichier authorized_keys SSH a été modifié. Une nouvelle clé peut donner un accès permanent à un attaquant.', 'authorized_keys SSH modifié', 'wazuh', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1547'), 'CRITICAL', 90, 1, 0, 1, NULL, '1. URGENT : examiner la nouvelle clé ajoutée
2. Si non autorisée, retirer immédiatement
3. Auditer toutes les clés autorisées'),
(150005, '18f9896f-07f2-41d5-9d82-e44cfb446ee3', 'Persistence: New init.d script', 'Nouveau script init.d créé. Méthode de persistance classique.', 'Nouveau script init.d', 'wazuh', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1547'), 'HIGH', 85, 1, 0, 0, NULL, '1. Vérifier le contenu du script
2. Si malveillant, désactiver et supprimer
3. Auditer /etc/init.d/'),
(150006, 'd49fa5be-a8b7-4278-9ece-b4199d9e8108', 'Persistence: rc.local modified', 'Le fichier rc.local a été modifié. S''exécute au démarrage, voie classique de persistance.', 'rc.local modifié', 'wazuh', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1547'), 'HIGH', 80, 1, 0, 0, NULL, '1. Vérifier le contenu de /etc/rc.local
2. Si malveillant, retirer la ligne et redémarrer
3. Comparer avec une sauvegarde'),
(150007, '08904ad7-181a-4176-8b6b-e7502b89b90f', 'Persistence: New user account created', 'Création d''un nouveau compte utilisateur. À valider sinon c''est une backdoor.', 'Nouveau compte utilisateur', 'wazuh', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1136.001'), 'HIGH', 80, 1, 0, 0, NULL, '1. Identifier qui a créé le compte (auth.log)
2. Vérifier la légitimité
3. Si non autorisé, désactiver : usermod -L <user>'),
(150008, '4668ccff-1bd2-4c05-907e-9fc31266fd78', 'Persistence: User added to admin group', 'Un utilisateur a été ajouté au groupe admin (root, wheel, sudo). Très sensible.', 'Utilisateur ajouté au groupe admin', 'wazuh', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1098'), 'CRITICAL', 90, 1, 0, 0, NULL, '1. URGENT : vérifier la légitimité
2. Si non autorisé, retirer immédiatement
3. Auditer les modifications de /etc/group'),
(150009, '1ddf66c7-f5b2-4185-a214-75dc50b937aa', 'Persistence: Web shell installed', 'Un web shell a été installé : fichier qui permet à un attaquant d''exécuter des commandes via le navigateur.', 'Web shell installé', 'wazuh', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1505.003'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : identifier le fichier (find /var/www -name ''*.php'' -mtime -1)
2. Supprimer le web shell
3. Patcher la vulnérabilité d''upload
4. Auditer tous les fichiers récents'),
(150010, '3b55f04e-0ef2-4476-ba88-2e7ab8d93234', 'Persistence: Registry Run key (Windows)', 'Nouvelle clé Run dans le registre Windows. Voie classique de persistance malware.', 'Clé Run du registre Windows', 'wazuh', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1547'), 'HIGH', 80, 1, 0, 0, NULL, '1. Identifier la clé et le programme qu''elle lance
2. Si malveillant, supprimer via regedit
3. Activer le monitoring du registre'),
(150011, '5a4663ba-4b5e-4338-9cc7-3ae6f359a155', 'Persistence: Scheduled task created', 'Création d''une tâche planifiée Windows. À valider.', 'Tâche planifiée créée', 'wazuh', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1053.003'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. Examiner la tâche : schtasks /query
2. Vérifier le binaire qu''elle lance
3. Si malveillant, supprimer'),
(150012, 'e43ee5d3-195d-47f6-8e41-779daa4cd570', 'Persistence: WMI event subscription', 'Souscription d''événement WMI : technique de persistance Windows furtive utilisée par des malwares avancés.', 'Souscription événement WMI', 'wazuh', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1546'), 'HIGH', 85, 1, 0, 0, NULL, '1. URGENT : malware sophistiqué probable
2. Lister les souscriptions : Get-WMIObject -Namespace root\Subscription
3. Supprimer les entrées malveillantes'),
(150013, '4f74b365-8acc-4d18-b509-c3b6473993ed', 'Persistence: Service binary replaced', 'Le binaire d''un service système a été remplacé. Très typique de compromission profonde.', 'Binaire de service remplacé', 'wazuh', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1574'), 'CRITICAL', 90, 1, 0, 0, NULL, '1. URGENT : isoler le serveur
2. Restaurer le binaire depuis une source saine
3. Analyse forensique complète'),
(150014, 'bc6fec83-9706-4d73-963e-060a5053bea3', 'Persistence: Login script modified', 'Script de login modifié. S''exécute à chaque connexion utilisateur.', 'Script de login modifié', 'wazuh', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1547'), 'HIGH', 80, 1, 0, 0, NULL, '1. Examiner les scripts modifiés
2. Comparer avec une version saine
3. Auditer /etc/profile, /etc/bash.bashrc, etc.'),
(150015, 'c926623e-f451-44a4-a809-b127dcce7bec', 'Persistence: PAM module modified', 'Module PAM modifié. Compromis très profond car PAM est au cœur de l''authentification Linux.', 'Module PAM modifié', 'wazuh', 8, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1547'), 'CRITICAL', 90, 1, 0, 1, NULL, '1. URGENT : compromission grave probable
2. Restaurer les modules PAM
3. Considérer une réinstallation du système'),
(160001, 'c1c57d6f-0961-4d52-a4d0-bd8d57f8b317', 'Honeypot: SSH connection attempt on port 2222', 'Connexion sur le port honeypot SSH (2222). Toute connexion ici est une tentative d''attaque par définition.', 'Connexion SSH honeypot', 'wazuh', 9, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 95, 1, 0, 0, NULL, '1. L''IP source est automatiquement bloquée
2. Tracer l''IP via ThreatIntel
3. Examiner les credentials testés'),
(160002, '9acd9acf-845b-4228-944a-51536885b1de', 'Honeypot: HTTP request on port 8888', 'Requête HTTP sur le honeypot (port 8888). Indique une attaque ou un scan ciblé.', 'Requête HTTP sur honeypot', 'wazuh', 9, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 95, 1, 0, 0, NULL, '1. L''IP source est bloquée
2. Examiner la requête pour identifier l''attaque ciblée
3. Renforcer la défense sur le service réel'),
(160003, '604fa9b8-9678-47fa-ad0f-717f85b007dc', 'Honeypot: MySQL connection on port 3307', 'Connexion sur le honeypot MySQL (port 3307). Tentative d''attaque sur les bases de données.', 'Connexion MySQL honeypot', 'wazuh', 9, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 95, 1, 0, 0, NULL, '1. L''IP est bloquée
2. Vérifier que la vraie BDD n''est pas exposée
3. Auditer la configuration MySQL'),
(160004, '848f41aa-7422-4d2c-9fa3-314856ce1d27', 'Honeypot: Multiple credential attempts', 'Multiples tentatives de credentials sur honeypot. Force brute confirmée.', 'Multiples tentatives credentials', 'wazuh', 9, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'CRITICAL', 100, 1, 0, 1, NULL, '1. L''IP est bloquée définitivement
2. Analyser les credentials testés (dictionnaire utilisé)
3. Vérifier qu''aucun de ces credentials n''est utilisé réellement'),
(160005, '02574f18-4d36-413b-baab-2975c21b9e39', 'Honeypot: Suspicious payload submitted', 'Payload suspect envoyé au honeypot. Tentative d''exploitation directe.', 'Payload suspect soumis', 'wazuh', 9, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'CRITICAL', 100, 1, 0, 1, NULL, '1. URGENT : analyser le payload pour identifier la vulnérabilité ciblée
2. Vérifier que le système réel n''est pas vulnérable
3. Bloquer l''IP source'),
(5125, '80e3c4f4-0449-44a3-9332-56d47e5be11b', 'Failed SSH key authentication', 'Échec d''authentification SSH par clé. L''utilisateur essaie une clé non autorisée.', 'Échec authentification clé SSH', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'LOW', 60, 1, 1, 0, NULL, '1. Vérifier la légitimité de la tentative
2. Examiner les clés autorisées : ~/.ssh/authorized_keys
3. Surveiller la fréquence pour détecter une attaque'),
(5126, '5ee61300-f33d-45bc-9e22-c275b99f1197', 'SSH from blacklisted IP', 'Connexion SSH tentée depuis une IP marquée comme malveillante (en liste noire).', 'SSH depuis IP blacklistée', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1078'), 'CRITICAL', 95, 1, 0, 0, NULL, '1. URGENT : l''IP est connue comme malveillante
2. Bloquer définitivement au pare-feu
3. Vérifier qu''aucune connexion n''a réussi'),
(5127, 'dccebeb7-435c-45a1-a162-a0787956f46e', 'Account locked after multiple failures', 'Un compte a été verrouillé suite à de nombreuses tentatives échouées.', 'Compte verrouillé après échecs', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 85, 1, 0, 0, NULL, '1. Identifier l''IP attaquante et la bloquer
2. Débloquer le compte une fois la menace passée
3. Renforcer la sécurité (clés SSH, 2FA)'),
(5128, '9614306d-d663-44bb-885a-9b940c5f7f06', 'Login from new geolocation', 'Login réussi depuis une géolocalisation inhabituelle. Possible compte volé.', 'Login depuis nouvelle géolocalisation', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1078'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. URGENT : contacter l''utilisateur pour confirmation
2. Si non légitime, verrouiller le compte immédiatement
3. Activer la 2FA'),
(5129, '97abf3e8-2989-4742-a2e2-feaa5c69c1b7', 'Concurrent sessions same user', 'Plusieurs sessions simultanées pour le même utilisateur. Peut être normal (téléphone + PC) ou suspect.', 'Sessions concurrentes même user', 'wazuh', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1078'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. Vérifier auprès de l''utilisateur
2. Si non légitime, terminer toutes les sessions et changer le mot de passe
3. Auditer les sessions actives'),
(31135, '4a599695-ce6a-4ab7-81dc-66d121726d31', 'Web: SQL injection blocked by WAF', 'Tentative d''injection SQL bloquée par le WAF. La défense a fonctionné mais l''attaque doit être tracée.', 'Injection SQL bloquée par WAF', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'MEDIUM', 70, 1, 1, 0, NULL, '1. Examiner les logs WAF pour identifier l''attaquant
2. Bloquer l''IP source
3. Vérifier que le code applicatif est aussi sécurisé'),
(31136, '53655c50-1b05-4952-a928-d16c3bcee107', 'Web: ModSecurity rule triggered', 'Une règle ModSecurity (WAF) s''est déclenchée. À analyser pour évaluer la sévérité.', 'Règle ModSecurity déclenchée', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'MEDIUM', 70, 1, 1, 0, NULL, '1. Examiner le détail de la règle déclenchée
2. Si attaque confirmée, bloquer l''IP
3. Ajuster les règles ModSecurity si faux positif'),
(31137, '24f8c32e-a92e-4e83-9c66-b6bcb4437af2', 'Web: Excessive 5xx errors (server stress)', 'Nombreuses erreurs 5xx : le serveur web est en difficulté. Possible attaque DoS ou problème applicatif.', 'Excès d''''''''erreurs 5xx', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1499'), 'HIGH', 75, 1, 0, 0, NULL, '1. Vérifier la charge du serveur (top, htop)
2. Examiner les logs applicatifs pour erreurs
3. Si attaque, activer un anti-DDoS'),
(31138, '06f6b21b-b48f-4c11-8355-07c959776ca1', 'Web: Suspicious referer header', 'Header Referer suspect dans les requêtes web. Possible tentative d''exploitation.', 'Header Referer suspect', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'LOW', 60, 1, 1, 0, NULL, '1. Examiner le Referer et l''URL ciblée
2. Bloquer les Referer connus comme malveillants
3. Filtrer au niveau du WAF'),
(31139, '98f7d5af-42c0-4890-9f30-6047fd1f5164', 'Web: Login bypass attempt', 'Tentative de contournement de l''authentification web. L''attaquant essaie d''accéder à des zones protégées sans se connecter.', 'Tentative de bypass de login', 'wazuh', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 85, 1, 0, 0, NULL, '1. URGENT : vérifier qu''aucun accès n''a abouti
2. Auditer le code d''authentification
3. Bloquer l''IP source'),
(100021, 'bce0ba00-fab4-4427-81c9-a963406d1b7f', 'Malware: Suspicious DLL injection', 'Injection DLL suspecte détectée. Technique utilisée par les malwares pour s''attacher à des processus légitimes.', 'Injection DLL suspecte', 'wazuh', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1055'), 'CRITICAL', 90, 1, 0, 0, NULL, '1. URGENT : identifier le processus affecté
2. Capture mémoire pour analyse
3. Restaurer le système si compromission confirmée'),
(100022, 'a75ca5b5-e687-41e3-90bf-de8dd9088650', 'Malware: Living-off-the-Land binary abuse', 'Utilisation suspecte d''un binaire système (Living-off-the-Land). Technique d''évasion qui utilise des outils légitimes du système.', 'Abus de binaire LOLBin', 'wazuh', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1027'), 'HIGH', 80, 1, 0, 0, NULL, '1. Identifier le binaire utilisé (certutil, regsvr32, mshta, etc.)
2. Vérifier le contexte d''utilisation
3. Activer le logging détaillé'),
(100023, '1b8461a9-19a5-459f-abf0-ffe29557a4c2', 'Malware: Cobalt Strike beacon detected', 'Beacon Cobalt Strike détecté : framework d''attaque commercial très utilisé par les groupes APT.', 'Beacon Cobalt Strike', 'wazuh', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : compromission par groupe APT probable
2. Isoler la machine immédiatement
3. Analyse forensique professionnelle requise'),
(100024, '42b57869-c300-4367-9fb1-09068743079b', 'Malware: Mimikatz signature in process', 'Signature de Mimikatz dans un processus en mémoire. Vol de credentials Windows en cours.', 'Mimikatz dans processus', 'wazuh', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1027'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : la machine est compromise
2. Isoler immédiatement
3. Réinitialiser TOUS les credentials utilisés sur cette machine'),
(100025, '762f6ebb-f151-4d2f-896c-0f0cf3a19adc', 'Malware: Empire framework detected', 'Framework Empire détecté : autre framework d''attaque post-exploitation très utilisé.', 'Framework Empire détecté', 'wazuh', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : compromission active
2. Isoler la machine
3. Analyse forensique');

-- ============================================================================
-- Total : 190 signatures Wazuh enrichies
-- ============================================================================