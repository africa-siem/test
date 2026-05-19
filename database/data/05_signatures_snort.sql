-- ============================================================================
-- SIEM AFRICA - 190 Signatures Snort (ENRICHIES)
-- ============================================================================
-- Chaque signature inclut désormais :
--   - description_fr : 1-2 phrases claires expliquant l'attaque
--   - remediation_fr : 2-3 recommandations actionnables
-- 
-- SIDs Snort customs : 1000001 à 1000190
-- (Plage SID >= 1000001 réservée aux règles personnalisées)
-- ============================================================================

INSERT INTO signatures (
    id, uuid, name,
    description_fr, description_en, source,
    category_id, technique_id,
    severity, confidence, is_active, is_noisy, is_critical_chain, cve_ids,
    remediation_fr
) VALUES
(1000001, 'd0dcebde-3b00-4d5a-b99a-c44c02b736c1', 'SQL Injection - UNION SELECT', 'Tentative d''injection SQL avec UNION SELECT : technique permettant à l''attaquant d''extraire le contenu de la base de données via les URLs du site.', 'Détection : SQL Injection - UNION SELECT', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. L''IP source sera bloquée par l''agent
2. Identifier l''URL ciblée dans les logs web (Apache/Nginx)
3. Corriger l''application en utilisant des requêtes SQL préparées
4. Installer un Web Application Firewall (ModSecurity)'),
(1000002, '0ebe372a-a805-4a6e-84b3-cc4026e0b43e', 'SQL Injection - OR 1=1', 'Injection SQL avec le motif ''OR 1=1'' : tentative classique de contournement d''authentification ou d''extraction de données.', 'Détection : SQL Injection - OR 1=1', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. L''IP source est bloquée par l''agent
2. Identifier et corriger la page vulnérable
3. Auditer le code applicatif (requêtes paramétrées partout)'),
(1000003, '32c0690d-eb07-49f7-bddc-fa076dcb891a', 'SQL Injection - DROP TABLE', 'Tentative d''injection SQL avec DROP TABLE : l''attaquant cherche à SUPPRIMER une table entière de la base de données. Très dangereux.', 'Détection : SQL Injection - DROP TABLE', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : risque de perte de données
2. Bloquer l''IP immédiatement
3. Vérifier l''intégrité de la BDD
4. Restaurer depuis la dernière sauvegarde si nécessaire'),
(1000004, 'fe462d20-9447-4813-b86f-596a3ddd4d01', 'SQL Injection - INSERT INTO', 'Injection SQL avec INSERT INTO : l''attaquant tente d''insérer des données malveillantes (faux comptes, contenu piégé).', 'Détection : SQL Injection - INSERT INTO', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. L''IP est bloquée par l''agent
2. Vérifier les insertions récentes en BDD
3. Auditer le code applicatif'),
(1000005, 'e07b9dd1-7f37-4e09-8833-f582d1cb4a76', 'SQL Injection - UPDATE SET', 'Injection SQL avec UPDATE SET : l''attaquant tente de modifier des données existantes (changer un mot de passe, élever des privilèges).', 'Détection : SQL Injection - UPDATE SET', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : vérifier les modifications récentes en BDD
2. Bloquer l''IP
3. Auditer les comptes admin pour modifications suspectes'),
(1000006, '9adb5fe8-af73-454b-bac0-74e29ce3a266', 'SQL Injection - DELETE FROM', 'Injection SQL avec DELETE FROM : tentative de suppression de données. Très grave.', 'Détection : SQL Injection - DELETE FROM', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : vérifier l''intégrité des données
2. Bloquer l''IP source
3. Restaurer si nécessaire depuis sauvegarde'),
(1000007, '5b624f66-9aa7-486a-b80c-b933d22a54be', 'SQL Injection - sqlmap user-agent', 'User-Agent sqlmap détecté : un attaquant utilise l''outil professionnel sqlmap pour automatiser des injections SQL.', 'Détection : SQL Injection - sqlmap user-agent', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : attaquant outillé et déterminé
2. Bloquer l''IP source immédiatement
3. Bloquer le User-Agent ''sqlmap'' au niveau Nginx/Apache
4. Vérifier que le WAF est actif'),
(1000008, 'c8369b9f-b7f8-4a15-93ed-39657ec15842', 'SQL Injection - blind boolean', 'Injection SQL aveugle (blind boolean) : technique avancée d''extraction sans message d''erreur, plus lente mais furtive.', 'Détection : SQL Injection - blind boolean', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : attaquant expérimenté
2. Bloquer l''IP
3. Vérifier les requêtes lentes anormales dans les logs'),
(1000009, '4d4553b5-de96-4379-a3ee-cf58197c87ec', 'SQL Injection - time-based', 'Injection SQL time-based : technique avancée utilisant des délais (SLEEP) pour extraire les données.', 'Détection : SQL Injection - time-based', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : technique d''attaque sophistiquée
2. Bloquer l''IP
3. Auditer les requêtes longues vers la BDD'),
(1000010, '54da82cd-c562-4910-9585-e10cd6eaa5c3', 'SQL Injection - error-based', 'Injection SQL error-based : l''attaquant force des erreurs SQL pour révéler des informations sur la base.', 'Détection : SQL Injection - error-based', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. Bloquer l''IP source
2. Désactiver l''affichage des erreurs SQL en production
3. Corriger l''application (try/catch)'),
(1000011, 'f9734f7f-95ea-4e60-8862-33ad322eb70a', 'XSS - <script> tag', 'Tentative d''XSS avec balise <script> : injection de JavaScript malveillant qui s''exécutera dans le navigateur des visiteurs.', 'Détection : XSS - <script> tag', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. L''IP est bloquée par l''agent
2. Identifier et corriger la page vulnérable
3. Échapper toutes les sorties HTML utilisateur
4. Activer Content-Security-Policy (CSP)'),
(1000012, 'e053e52e-7036-498e-9240-7e052d1d0da7', 'XSS - onerror handler', 'XSS via handler onerror : technique pour exécuter du JS via les événements d''erreur d''image.', 'Détection : XSS - onerror handler', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. Bloquer l''IP source
2. Filtrer les handlers d''événements en entrée
3. Activer CSP strict'),
(1000013, '9d379ae9-6caa-44c1-a1f2-5e29ca10785f', 'XSS - javascript: protocol', 'XSS via protocole javascript: : tentative d''injecter du code via les URLs.', 'Détection : XSS - javascript: protocol', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. Valider et filtrer toutes les URLs
2. Bloquer le préfixe javascript:
3. Activer CSP'),
(1000014, '40c13efc-e1c2-4f47-921d-ae529d6b4af9', 'XSS - alert() call', 'XSS avec appel alert() : test classique de validation de XSS par un attaquant.', 'Détection : XSS - alert() call', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. L''attaquant teste la vulnérabilité - bloquer rapidement
2. Corriger la page concernée
3. Auditer les autres pages similaires'),
(1000015, 'fb711c0e-1867-4d3e-9e85-e174e4f5bc37', 'XSS - document.cookie', 'XSS visant document.cookie : tentative de VOL des cookies de session des utilisateurs.', 'Détection : XSS - document.cookie', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : vol de session ciblé
2. Configurer les cookies en HttpOnly + Secure
3. Régénérer les sessions
4. Patcher la page vulnérable'),
(1000016, '23f182d9-28e2-4fe2-ae25-1bb4207919da', 'XSS - eval() call', 'XSS avec eval() : exécution de code arbitraire dans le navigateur de la victime.', 'Détection : XSS - eval() call', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. Bloquer l''IP source
2. Bannir eval() du code applicatif
3. Activer CSP avec ''unsafe-eval'' interdit'),
(1000017, '37c2184e-57d5-49fc-ae36-abbefbdd938c', 'XSS - DOM-based', 'XSS DOM-based : injection côté client sans envoi au serveur. Plus difficile à détecter.', 'Détection : XSS - DOM-based', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. Auditer le code JavaScript client
2. Échapper les données utilisateur en JS
3. Activer CSP'),
(1000018, 'c8889991-ac48-4b14-8694-62c5006ac03c', 'XSS - encoded payload', 'XSS avec payload encodé : technique d''évasion pour contourner les filtres.', 'Détection : XSS - encoded payload', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. Bloquer l''IP
2. Renforcer le WAF avec décodage avant analyse
3. Filtrer les caractères spéciaux multi-encodés'),
(1000019, '7f43e867-0507-4cf6-b438-63dcecbd9977', 'Path Traversal - ../../../etc/passwd', 'Tentative de Path Traversal vers /etc/passwd : l''attaquant veut lire le fichier des utilisateurs Linux. Préliminaire à une compromission.', 'Détection : Path Traversal - ../../../etc/passwd', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : l''application est vulnérable
2. Bloquer l''IP source
3. Corriger l''application (validation stricte des chemins)
4. Configurer le serveur web pour rejeter ''../'' dans les URLs'),
(1000020, '3a8b88e2-d726-4beb-94a0-f57335f00240', 'Path Traversal - URL encoded', 'Path Traversal avec encodage URL (%2e%2e) : technique d''évasion pour contourner les filtres simples.', 'Détection : Path Traversal - URL encoded', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. Bloquer l''IP
2. Activer le décodage URL avant validation
3. Mettre à jour le WAF'),
(1000021, '1478b206-9d2b-490a-bb94-5e71cee2d4bd', 'Path Traversal - double encoded', 'Path Traversal double-encodé : technique avancée pour contourner les WAF basiques.', 'Détection : Path Traversal - double encoded', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : attaquant expérimenté
2. Bloquer l''IP
3. Renforcer le WAF avec décodage récursif'),
(1000022, '1afce396-dbb8-49b3-a166-f515b9e1997c', 'Path Traversal - Windows drive', 'Path Traversal Windows (C:\ ou \..\..\) : l''attaquant essaie d''accéder à des fichiers Windows.', 'Détection : Path Traversal - Windows drive', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. Bloquer l''IP
2. Vérifier que les serveurs Windows ne sont pas exposés
3. Filtrer les caractères de chemin Windows'),
(1000023, '2aa0e5e9-41bf-472b-bafc-41d67dfea093', 'LFI - PHP wrapper', 'LFI avec PHP wrapper (php://filter, expect://) : technique avancée pour lire ou exécuter des fichiers.', 'Détection : LFI - PHP wrapper', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : risque d''exécution de code
2. Désactiver allow_url_include dans php.ini
3. Patcher l''application'),
(1000024, '20258e55-ade3-4920-afcc-45868eb75bdc', 'LFI - /proc/self/environ', 'LFI vers /proc/self/environ : l''attaquant tente de lire les variables d''environnement du processus web.', 'Détection : LFI - /proc/self/environ', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : peut révéler des credentials
2. Patcher l''application web
3. Restreindre les fichiers accessibles'),
(1000025, '64555c60-4960-4057-b4ab-4fd84e887757', 'LFI - log poisoning', 'LFI avec log poisoning : technique sophistiquée pour exécuter du code via les fichiers de log.', 'Détection : LFI - log poisoning', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : risque de RCE
2. Vérifier les fichiers de log accessibles
3. Patcher l''application immédiatement'),
(1000026, '2dfd51a6-8dfc-4f94-939e-a8b50a31dc40', 'RFI - external URL include', 'RFI avec URL externe : l''attaquant inclut un script malveillant hébergé sur son serveur. Compromission quasi-certaine.', 'Détection : RFI - external URL include', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : compromission probable
2. Bloquer l''IP immédiatement
3. Vérifier les fichiers récents sur le serveur
4. Désactiver allow_url_include'),
(1000027, '46c7befd-2a1c-4050-934a-01f355658f6b', 'RFI - data:// wrapper', 'RFI via wrapper data:// : technique pour injecter du code malveillant directement dans l''URL.', 'Détection : RFI - data:// wrapper', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : risque de RCE
2. Patcher l''application
3. Configurer PHP pour interdire les wrappers'),
(1000028, '3bcf4182-fc65-40f9-b28a-08a98616f9f8', 'Command Injection - ; cat /etc/passwd', 'Injection de commande shell (cat /etc/passwd) : l''attaquant tente de lister les utilisateurs du serveur via l''application web.', 'Détection : Command Injection - ; cat /etc/passwd', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : compromission imminente
2. Bloquer l''IP
3. Patcher l''application web
4. Auditer les processus créés'),
(1000029, '3d039fc9-9188-4c0b-8b2a-eb5d561a7235', 'Command Injection - | nc backdoor', 'Injection de commande avec backdoor netcat : l''attaquant ouvre une porte dérobée réseau.', 'Détection : Command Injection - | nc backdoor', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : backdoor probable
2. Bloquer l''IP
3. Vérifier les processus nc/netcat actifs
4. Auditer les ports en écoute'),
(1000030, '4361faa7-9c28-4dbc-b782-a5fd04c6e6ea', 'Command Injection - `whoami`', 'Injection de commande avec backticks `whoami` : test classique pour vérifier l''exécution de commandes.', 'Détection : Command Injection - `whoami`', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. Bloquer l''IP source
2. Vérifier que l''application n''exécute pas de shell
3. Auditer le code (éviter shell_exec, exec, system)'),
(1000031, 'bfff3f84-307f-4f78-9522-a48507980b41', 'Command Injection - $(id)', 'Injection avec substitution de commande $(id) : variante avancée pour identifier les privilèges du processus web.', 'Détection : Command Injection - $(id)', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. Bloquer l''IP
2. Identifier la page vulnérable et la corriger
3. Auditer le code applicatif'),
(1000032, 'da7e5d07-7e15-4140-80f9-6842674752e2', 'Web shell - eval($_POST', 'Tentative d''upload d''un web shell PHP avec eval($_POST). Si réussi, l''attaquant contrôle le serveur via le navigateur.', 'Détection : Web shell - eval($_POST', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1505.003'), 'CRITICAL', 90, 1, 0, 1, NULL, '1. URGENT : risque de compromission totale
2. Bloquer l''IP
3. Auditer les fichiers récents sur /var/www
4. Désactiver eval() dans PHP si possible'),
(1000033, '96da55dc-e2a4-4e00-b9fa-ca7c84725ff7', 'Web shell - system($_GET', 'Web shell PHP avec system($_GET) : permet à l''attaquant d''exécuter n''importe quelle commande via une simple URL.', 'Détection : Web shell - system($_GET', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1505.003'), 'CRITICAL', 90, 1, 0, 1, NULL, '1. URGENT : potentiel webshell installé
2. Rechercher : find /var/www -name ''*.php'' -mtime -1 | xargs grep system
3. Bloquer l''IP
4. Auditer l''application'),
(1000034, '4d9c1037-17e3-432a-bdbd-a7de6e1cebc6', 'Web shell - cmd.jsp', 'Web shell JSP (cmd.jsp) détecté : équivalent du web shell PHP pour les serveurs Java.', 'Détection : Web shell - cmd.jsp', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1505.003'), 'CRITICAL', 90, 1, 0, 1, NULL, '1. URGENT : compromission du serveur Java
2. Identifier et supprimer le fichier JSP
3. Auditer Tomcat/JBoss/WebLogic'),
(1000035, '40842ca9-4270-4ee7-9b30-fc52155ead6f', 'Web shell - China Chopper', 'Web shell China Chopper détecté : web shell très utilisé par des groupes APT chinois.', 'Détection : Web shell - China Chopper', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1505.003'), 'CRITICAL', 90, 1, 0, 1, NULL, '1. URGENT : possible attaque APT
2. Isoler le serveur
3. Analyse forensique requise
4. Considérer la compromission complète'),
(1000036, '5713d939-0448-4b99-a495-554f9979bd4b', 'Web shell - WSO shell', 'Web shell WSO détecté : web shell PHP populaire avec interface graphique complète pour l''attaquant.', 'Détection : Web shell - WSO shell', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1505.003'), 'CRITICAL', 90, 1, 0, 1, NULL, '1. URGENT : compromission grave
2. Identifier et supprimer le fichier
3. Auditer toute l''application web
4. Réinitialiser tous les credentials du serveur'),
(1000037, '743856db-49e7-4243-84e9-2c53bf1691c9', 'WordPress brute force', 'Attaque par force brute sur WordPress (/wp-login.php). Tentative de prendre le contrôle du site.', 'Détection : WordPress brute force', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. L''IP est bloquée par l''agent
2. Installer Wordfence ou iThemes Security
3. Renommer wp-login.php avec un plugin
4. Activer la double authentification (2FA)'),
(1000038, '31bc349c-5d30-4e7d-9871-3f67d0222c15', 'WordPress XML-RPC abuse', 'Abus de XML-RPC WordPress : technique pour faire de la force brute massive en évitant les protections classiques.', 'Détection : WordPress XML-RPC abuse', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. Désactiver XML-RPC : Disallow: /xmlrpc.php
2. Ou bloquer l''IP source
3. Vérifier que le mot de passe admin est fort'),
(1000039, '3eae876b-2456-4d3b-b4f1-3dcba47b3517', 'WordPress wp-config access', 'Tentative d''accès à wp-config.php : fichier contenant les credentials de la base WordPress. Très critique.', 'Détection : WordPress wp-config access', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : si réussi, les credentials BDD sont volés
2. Vérifier les permissions du fichier (644 ou plus restrictif)
3. Bloquer l''IP
4. Changer le mot de passe BDD si exposition confirmée'),
(1000040, '15754650-c178-4e4e-af75-7436edfc2f72', 'Joomla admin login attack', 'Force brute sur l''admin Joomla (/administrator). Tentative de compromission du CMS.', 'Détection : Joomla admin login attack', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'HIGH', 80, 1, 0, 0, NULL, '1. L''IP est bloquée
2. Restreindre l''admin par IP via .htaccess
3. Activer la 2FA Joomla
4. Mettre à jour Joomla et tous les composants'),
(1000041, '80da0c29-ac03-422f-bccb-92adaf94e5fb', 'Drupal Drupalgeddon (CVE-2014-3704)', 'Exploitation de Drupalgeddon (CVE-2014-3704) : faille critique permettant l''exécution de code à distance sur Drupal 7.', 'Détection : Drupal Drupalgeddon (CVE-2014-3704)', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'CRITICAL', 90, 1, 0, 1, 'CVE-2014-3704', '1. URGENT : mettre à jour Drupal IMMÉDIATEMENT
2. Si compromis, restaurer depuis sauvegarde
3. Auditer les comptes et fichiers ajoutés
4. Bloquer l''IP source'),
(1000042, '072a6981-46f6-40b1-bcbc-571b26b8d5b6', 'Apache Struts2 RCE (CVE-2017-5638)', 'Exploitation Apache Struts 2 (CVE-2017-5638) : vulnérabilité critique permettant d''exécuter du code via l''en-tête Content-Type.', 'Détection : Apache Struts2 RCE (CVE-2017-5638)', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'CRITICAL', 90, 1, 0, 1, 'CVE-2017-5638', '1. URGENT : patcher Struts 2 vers >= 2.5.10.1
2. Si non patchable, désactiver l''application
3. Vérifier les processus suspects
4. Bloquer l''IP attaquante'),
(1000043, '1f35d94d-213f-4820-a5ea-c259a315e71c', 'Log4Shell exploit (CVE-2021-44228)', 'Exploitation Log4Shell (CVE-2021-44228) : vulnérabilité critique mondiale dans log4j permettant l''exécution de code à distance.', 'Détection : Log4Shell exploit (CVE-2021-44228)', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1505.003'), 'CRITICAL', 90, 1, 0, 1, 'CVE-2021-44228', '1. URGENT : mettre à jour log4j >= 2.17.0
2. Vérifier TOUTES les applications Java de l''organisation
3. Bloquer l''IP source
4. Si compromis : analyse forensique'),
(1000044, '9d665992-aae9-415a-8de8-5eb1fbb14fc8', 'Spring4Shell exploit (CVE-2022-22965)', 'Exploitation Spring4Shell (CVE-2022-22965) : vulnérabilité critique de Spring Framework permettant RCE.', 'Détection : Spring4Shell exploit (CVE-2022-22965)', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1505.003'), 'CRITICAL', 90, 1, 0, 1, 'CVE-2022-22965', '1. URGENT : mettre à jour Spring Framework
2. Vérifier les applications Spring exposées
3. Bloquer l''IP
4. Auditer les processus'),
(1000045, 'cdd38151-139e-4eef-b368-b86b5c997891', 'Confluence OGNL injection (CVE-2022-26134)', 'Exploitation Confluence OGNL (CVE-2022-26134) : faille critique permettant l''exécution de code sur Confluence.', 'Détection : Confluence OGNL injection (CVE-2022-26134)', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'CRITICAL', 90, 1, 0, 1, 'CVE-2022-26134', '1. URGENT : mettre à jour Confluence
2. Si non patchable, mettre l''instance hors ligne
3. Bloquer l''IP
4. Analyse forensique si compromis'),
(1000046, '4ba46936-62a7-46c4-9b64-1bfd180d2cea', 'Citrix ADC exploit (CVE-2019-19781)', 'Exploitation Citrix ADC (CVE-2019-19781) : faille critique permettant la prise de contrôle des passerelles Citrix.', 'Détection : Citrix ADC exploit (CVE-2019-19781)', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'CRITICAL', 90, 1, 0, 1, 'CVE-2019-19781', '1. URGENT : patcher Citrix ADC/Gateway
2. Vérifier les fichiers /var/vpn/ pour backdoors
3. Réinitialiser les credentials VPN
4. Bloquer l''IP attaquante'),
(1000047, 'e5fbdd7d-5475-4f75-bcc7-b5b6d39b6544', 'Pulse Secure VPN exploit (CVE-2019-11510)', 'Exploitation Pulse Secure VPN (CVE-2019-11510) : faille critique permettant la lecture de fichiers et le vol de credentials.', 'Détection : Pulse Secure VPN exploit (CVE-2019-11510)', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'CRITICAL', 90, 1, 0, 1, 'CVE-2019-11510', '1. URGENT : patcher Pulse Secure
2. Réinitialiser TOUS les credentials VPN
3. Vérifier les comptes créés récemment
4. Analyse forensique'),
(1000048, 'b5cdef3d-ddd6-4d1d-b932-e8ce383c3e52', 'F5 BIG-IP TMUI exploit (CVE-2020-5902)', 'Exploitation F5 BIG-IP TMUI (CVE-2020-5902) : faille permettant l''exécution de code sur les load balancers F5.', 'Détection : F5 BIG-IP TMUI exploit (CVE-2020-5902)', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'CRITICAL', 90, 1, 0, 1, 'CVE-2020-5902', '1. URGENT : patcher BIG-IP
2. Restreindre l''accès à TMUI
3. Bloquer l''IP
4. Vérifier les configurations modifiées'),
(1000049, '2a9cbeaa-5248-40ed-8c42-e3a0002ad56b', 'ProxyShell exchange (CVE-2021-34473)', 'Exploitation ProxyShell (CVE-2021-34473) : chaîne d''exploits Exchange permettant RCE en post-auth puis pre-auth.', 'Détection : ProxyShell exchange (CVE-2021-34473)', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1505.003'), 'CRITICAL', 90, 1, 0, 1, 'CVE-2021-34473', '1. URGENT : patcher Exchange Server immédiatement
2. Vérifier l''absence de web shells dans /aspnet_client/
3. Réinitialiser tous les credentials Exchange
4. Bloquer l''IP'),
(1000050, 'a31ba9a5-677e-407e-b648-e26286b3e3ba', 'PrintNightmare exploit (CVE-2021-34527)', 'Exploitation PrintNightmare (CVE-2021-34527) : faille critique du service Print Spooler permettant l''escalade SYSTEM.', 'Détection : PrintNightmare exploit (CVE-2021-34527)', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'CRITICAL', 90, 1, 0, 1, 'CVE-2021-34527', '1. URGENT : patcher Windows immédiatement
2. Désactiver le service Spooler si non utilisé
3. Vérifier les comptes admin récemment créés
4. Bloquer l''IP'),
(1000051, 'd1b757ee-3384-4a1e-8bc3-251e16217db9', 'Nmap TCP SYN scan', 'Scan Nmap TCP SYN détecté : reconnaissance des ports ouverts via paquets SYN. Phase préliminaire d''une attaque.', 'Détection scanning : Nmap TCP SYN scan', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'HIGH', 75, 1, 1, 0, NULL, '1. L''IP source est bloquée par l''agent
2. Identifier les ports scannés dans les logs
3. Limiter les services exposés au strict nécessaire
4. Activer un IDS au niveau périmètre'),
(1000052, '17f6d8ef-aff8-4d11-9743-39fd3a533c98', 'Nmap TCP FIN scan', 'Scan Nmap TCP FIN : technique furtive contournant certains pare-feu.', 'Détection scanning : Nmap TCP FIN scan', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'HIGH', 75, 1, 1, 0, NULL, '1. L''IP est bloquée
2. Auditer la configuration pare-feu
3. Activer le stateful inspection'),
(1000053, 'aef6c41a-ed7d-4c51-942b-3d101757dd01', 'Nmap NULL scan', 'Scan Nmap NULL flags : scan furtif sans aucun flag TCP. Indique un attaquant expérimenté.', 'Détection scanning : Nmap NULL scan', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'HIGH', 75, 1, 1, 0, NULL, '1. L''IP est bloquée
2. Renforcer la détection au pare-feu
3. Investiguer les autres tentatives de cette IP'),
(1000054, '265ce59a-f75e-41b8-9d67-58efc38015bc', 'Nmap Xmas scan', 'Scan Nmap Xmas tree : tous les flags TCP allumés. Technique de scan avancée.', 'Détection scanning : Nmap Xmas scan', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'HIGH', 75, 1, 1, 0, NULL, '1. L''IP est bloquée
2. Examiner les actions ultérieures de cette IP
3. Renforcer le firewall'),
(1000055, 'a7442f12-d718-4de4-ba46-f7b121ec23d4', 'Nmap UDP scan', 'Scan Nmap UDP : recherche des services UDP exposés (DNS, SNMP, etc.).', 'Détection scanning : Nmap UDP scan', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'HIGH', 75, 1, 1, 0, NULL, '1. L''IP est bloquée
2. Vérifier les services UDP exposés
3. Restreindre SNMP, NTP, DNS aux IP autorisées'),
(1000056, 'e0adb5b0-d2d3-4b30-ab87-f0cbeaf1d1bc', 'Nmap version scan', 'Scan de versions Nmap : l''attaquant identifie les logiciels et versions pour cibler des vulnérabilités connues.', 'Détection scanning : Nmap version scan', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'HIGH', 75, 1, 1, 0, NULL, '1. URGENT : préparation d''attaque ciblée
2. Masquer les bannières de service
3. Vérifier que tous les services sont à jour
4. Bloquer l''IP'),
(1000057, 'f87c4773-d7d6-4c63-8f9d-0780857baaeb', 'Nmap OS detection', 'Détection d''OS via Nmap : l''attaquant identifie votre système d''exploitation.', 'Détection scanning : Nmap OS detection', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'HIGH', 75, 1, 1, 0, NULL, '1. L''IP est bloquée
2. Configurer le système pour masquer son OS si possible
3. Préparer des correctifs OS à jour'),
(1000058, '9908cf24-c79a-4678-8665-84f13d42aea5', 'Nmap script scan (--script)', 'Scan avec scripts Nmap NSE : exécution de scripts d''attaque automatisés contre les services exposés.', 'Détection scanning : Nmap script scan (--script)', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'HIGH', 75, 1, 1, 0, NULL, '1. URGENT : l''attaquant cherche activement des vulnérabilités
2. Bloquer l''IP
3. Identifier les scripts utilisés dans les logs IDS
4. Patcher les services concernés'),
(1000059, '66032121-95c8-467b-ac12-cbfac51d1db7', 'Masscan high-speed scan', 'Scan haute-vitesse Masscan détecté : scan Internet-scale, l''attaquant balaye de grandes plages d''IP rapidement.', 'Détection scanning : Masscan high-speed scan', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'HIGH', 75, 1, 1, 0, NULL, '1. L''IP source est bloquée
2. Considérer que l''attaquant scanne le monde entier (pas ciblé)
3. Mais s''il revient, c''est ciblé'),
(1000060, '4c2604ba-d8e5-4dfb-8900-8b5d2596dca3', 'ZMap scan', 'Scan ZMap détecté : scanner haute-vitesse utilisé pour la recherche académique mais aussi par les attaquants.', 'Détection scanning : ZMap scan', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'HIGH', 75, 1, 1, 0, NULL, '1. L''IP est bloquée
2. Vérifier l''origine (université ou attaquant)
3. Restreindre les services exposés'),
(1000061, 'e7ef0a07-5256-4182-b2a3-1407749bb5d5', 'Unicornscan', 'Scan Unicornscan : scanner alternatif à Nmap, plus rapide pour les grands réseaux.', 'Détection scanning : Unicornscan', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'HIGH', 75, 1, 1, 0, NULL, '1. L''IP est bloquée
2. Auditer les services exposés
3. Renforcer la détection IDS'),
(1000062, '81420e65-24a7-4364-953d-765ce9ccacd9', 'Hping3 custom packets', 'Paquets Hping3 personnalisés : outil permettant de forger des paquets sur mesure, souvent utilisé pour les tests d''évasion.', 'Détection scanning : Hping3 custom packets', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'MEDIUM', 75, 1, 1, 0, NULL, '1. L''IP est bloquée
2. Examiner les patterns de paquets dans les logs IDS
3. Attaquant probablement expérimenté'),
(1000063, '5b967bed-9e18-4c9a-8e2a-f6918772cdbb', 'Port sweep - 22 multiple hosts', 'Balayage du port 22 (SSH) sur plusieurs hôtes. L''attaquant cherche des serveurs SSH à compromettre.', 'Détection scanning : Port sweep - 22 multiple hosts', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'HIGH', 75, 1, 1, 0, NULL, '1. L''IP est bloquée
2. Surveiller les autres machines internes pour activité SSH
3. Considérer le changement de port SSH par défaut'),
(1000064, '0f6dc0ff-2662-47f0-a3db-6ad213390a5c', 'Port sweep - 80 multiple hosts', 'Balayage du port 80 (HTTP) sur plusieurs hôtes : recherche de serveurs web.', 'Détection scanning : Port sweep - 80 multiple hosts', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'HIGH', 75, 1, 1, 0, NULL, '1. L''IP est bloquée
2. Examiner les requêtes web associées
3. Vérifier l''exposition des services web'),
(1000065, '9d8755d2-8c5e-4a2a-9173-726b49257704', 'Port sweep - 443 multiple hosts', 'Balayage du port 443 (HTTPS) : recherche de serveurs web sécurisés.', 'Détection scanning : Port sweep - 443 multiple hosts', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'HIGH', 75, 1, 1, 0, NULL, '1. L''IP est bloquée
2. Activer le rate limiting au niveau TLS
3. Auditer les certificats exposés'),
(1000066, '850d79e6-53c7-4e52-9499-eae15e58b6b9', 'Port sweep - 3389 multiple hosts', 'Balayage du port 3389 (RDP) : recherche de serveurs Windows accessibles à distance. Très ciblé.', 'Détection scanning : Port sweep - 3389 multiple hosts', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'HIGH', 75, 1, 1, 0, NULL, '1. URGENT : RDP exposé est une menace majeure
2. Bloquer l''IP
3. Masquer RDP derrière un VPN
4. Activer Network Level Authentication (NLA)'),
(1000067, '7f55d1dd-9920-4a6d-ad8b-602a9c1ed655', 'Port sweep - 445 multiple hosts', 'Balayage du port 445 (SMB) : recherche de partages Windows. Vecteur d''attaque très utilisé (WannaCry, EternalBlue).', 'Détection scanning : Port sweep - 445 multiple hosts', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'HIGH', 75, 1, 1, 0, NULL, '1. URGENT : SMB ne doit JAMAIS être exposé sur Internet
2. Bloquer SMB au pare-feu d''entrée
3. Vérifier que les patchs MS17-010 sont appliqués
4. Bloquer l''IP'),
(1000068, '9b1a615b-4272-47cf-bb80-b4fff94ff502', 'ARP scan', 'Scan ARP sur le réseau local : reconnaissance des machines présentes.', 'Détection scanning : ARP scan', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'HIGH', 75, 1, 1, 0, NULL, '1. Si interne : compromission probable d''une machine du réseau
2. Activer la détection ARP spoofing
3. Identifier la machine source'),
(1000069, '67e01c18-f0a9-40fb-89b9-1e2275f91c3f', 'ICMP ping sweep', 'ICMP ping sweep : balayage par ping pour cartographier les machines vivantes.', 'Détection scanning : ICMP ping sweep', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'MEDIUM', 75, 1, 1, 0, NULL, '1. Bloquer l''IP
2. Désactiver ICMP en entrée si non nécessaire
3. Restreindre la réponse aux pings'),
(1000070, '92b45f77-8747-4c4c-9d3d-4adf32041bf3', 'TCP connect scan', 'Scan TCP connect (sans techniques furtives) : scan basique mais efficace.', 'Détection scanning : TCP connect scan', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'HIGH', 75, 1, 1, 0, NULL, '1. L''IP est bloquée
2. Surveiller les actions ultérieures
3. Renforcer le pare-feu'),
(1000071, 'c37f99b2-2fe1-4535-b3fc-25b5a4cff02c', 'SMB enumeration', 'Énumération SMB : l''attaquant liste les partages réseau Windows accessibles.', 'Détection scanning : SMB enumeration', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'HIGH', 75, 1, 1, 0, NULL, '1. URGENT : SMB exposé
2. Désactiver SMBv1 (vulnérable)
3. Restreindre l''accès SMB par IP
4. Activer l''authentification obligatoire'),
(1000072, '0e79b090-df39-40a0-aed0-312700296f53', 'SNMP enumeration (community public)', 'Énumération SNMP avec la community ''public'' : récupération d''infos système via SNMP mal configuré.', 'Détection scanning : SNMP enumeration (community public)', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'HIGH', 75, 1, 1, 0, NULL, '1. URGENT : changer immédiatement la community ''public''
2. Désactiver SNMP si non utilisé
3. Utiliser SNMPv3 avec authentification
4. Bloquer SNMP sur le port 161 si exposition externe'),
(1000073, '09c575ab-1830-43d5-9658-7063af1506c4', 'SNMP brute force', 'Force brute sur SNMP : tentative de deviner la community string.', 'Détection scanning : SNMP brute force', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'HIGH', 75, 1, 1, 0, NULL, '1. L''IP est bloquée
2. Migrer vers SNMPv3 avec mot de passe complexe
3. Restreindre SNMP aux IP autorisées'),
(1000074, 'ed1c5a95-4c66-4d67-b00e-e26510450511', 'DNS zone transfer (AXFR)', 'Tentative de transfert de zone DNS (AXFR) : récupération complète des sous-domaines.', 'Détection scanning : DNS zone transfer (AXFR)', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'HIGH', 75, 1, 1, 0, NULL, '1. URGENT : peut exposer toute votre infrastructure DNS
2. Désactiver AXFR sauf vers serveurs DNS autorisés
3. Auditer la configuration BIND/PowerDNS'),
(1000075, '4afbc73b-4689-4a49-baef-8a49f2b861c8', 'NetBIOS enumeration', 'Énumération NetBIOS : identification des machines Windows et services.', 'Détection scanning : NetBIOS enumeration', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'HIGH', 75, 1, 1, 0, NULL, '1. Désactiver NetBIOS si non utilisé
2. Bloquer les ports 137-139 au pare-feu externe
3. Auditer les services exposés'),
(1000076, 'c281c039-2807-4bcb-82ec-915926aeebbe', 'RPC enumeration', 'Énumération RPC : recherche de services Windows exposés via RPC.', 'Détection scanning : RPC enumeration', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'HIGH', 75, 1, 1, 0, NULL, '1. Restreindre RPC aux IP autorisées
2. Bloquer le port 135 en externe
3. Audit Windows régulier'),
(1000077, '1ca55558-49d6-4ee1-bc09-132ad3fd8783', 'LDAP enumeration', 'Énumération LDAP : tentative de lister les comptes Active Directory.', 'Détection scanning : LDAP enumeration', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'HIGH', 75, 1, 1, 0, NULL, '1. URGENT : protéger l''Active Directory
2. Désactiver les requêtes LDAP anonymes
3. Restreindre LDAP par IP
4. Activer LDAP signing'),
(1000078, '0ac3c960-4d75-424f-8a45-2d6786cdc1a0', 'Kerberos enumeration', 'Énumération Kerberos : recherche des comptes valides via les réponses Kerberos.', 'Détection scanning : Kerberos enumeration', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'HIGH', 75, 1, 1, 0, NULL, '1. Activer la pre-authentification Kerberos sur tous les comptes
2. Auditer les tentatives Kerberos (Event ID 4768)
3. Bloquer l''IP'),
(1000079, 'f5b9a07a-de2a-490b-aea4-dde976657dd4', 'MySQL banner grab', 'Récupération de bannière MySQL : identification de la version pour cibler des vulnérabilités.', 'Détection scanning : MySQL banner grab', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'MEDIUM', 75, 1, 1, 0, NULL, '1. MySQL ne doit pas être exposé en externe
2. Bind-address=127.0.0.1 dans my.cnf
3. Si nécessaire externe, restreindre par IP'),
(1000080, '7f5daad9-596e-4a9a-98d8-1a3758e442aa', 'PostgreSQL banner grab', 'Récupération de bannière PostgreSQL : identification de la version.', 'Détection scanning : PostgreSQL banner grab', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'MEDIUM', 75, 1, 1, 0, NULL, '1. PostgreSQL ne doit pas être exposé en externe
2. Configurer pg_hba.conf strictement
3. Activer SSL obligatoire'),
(1000081, '84f0699b-7872-423a-b8be-be7f1cce63cc', 'Cobalt Strike beacon HTTP traffic', 'Trafic HTTP Cobalt Strike détecté : framework d''attaque commercial très utilisé par les groupes APT et ransomware.', 'Malware/C2 : Cobalt Strike beacon HTTP traffic', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : compromission probable par groupe APT
2. Identifier la machine source du trafic
3. L''isoler immédiatement
4. Analyse forensique professionnelle requise'),
(1000082, 'c0ab7d76-f1d5-4bf0-b161-f238b250695d', 'Cobalt Strike beacon HTTPS traffic', 'Trafic HTTPS Cobalt Strike : variante chiffrée du beacon C2. Plus difficile à détecter.', 'Malware/C2 : Cobalt Strike beacon HTTPS traffic', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : compromission grave
2. Isoler la machine source
3. Analyse forensique'),
(1000083, '6d0de163-69ba-49fa-9c38-bcce32ea3aeb', 'Cobalt Strike DNS beacon', 'Beacon DNS Cobalt Strike : C2 furtif via requêtes DNS. Technique très utilisée par les APT.', 'Malware/C2 : Cobalt Strike DNS beacon', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.004'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : compromission APT probable
2. Isoler la machine source
3. Bloquer le domaine C2 dans le DNS
4. Audit forensique'),
(1000084, '13b13833-d19a-41ee-9ada-3d70f85010ca', 'Empire framework HTTP C2', 'Trafic C2 Empire framework : framework PowerShell post-exploitation très utilisé.', 'Malware/C2 : Empire framework HTTP C2', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : compromission Windows active
2. Isoler la machine
3. Auditer PowerShell logs
4. Réinitialiser tous les credentials'),
(1000085, 'f76bf544-585f-41a3-8f41-09a5c93a5028', 'Metasploit Meterpreter HTTP', 'Trafic Metasploit Meterpreter via HTTP : l''attaquant contrôle une machine compromise.', 'Malware/C2 : Metasploit Meterpreter HTTP', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : compromission active
2. Isoler la machine source
3. Identifier et tuer le processus meterpreter
4. Analyse forensique'),
(1000086, 'e6037f43-5d27-4920-b8b2-3cf8fc8c2126', 'Meterpreter reverse_tcp', 'Reverse TCP Meterpreter : connexion sortante vers l''attaquant. Compromission active.', 'Malware/C2 : Meterpreter reverse_tcp', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : isoler la machine immédiatement
2. Tracer l''IP de destination
3. Identifier le processus malveillant
4. Réinitialiser les credentials'),
(1000087, 'a35a4a34-f768-4ddb-af76-627e5963a834', 'Meterpreter reverse_https', 'Reverse HTTPS Meterpreter : variante chiffrée plus furtive.', 'Malware/C2 : Meterpreter reverse_https', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : compromission active
2. Isoler la machine
3. Analyse forensique
4. Bloquer l''IP du C2 au pare-feu'),
(1000088, '551ec5ee-9b49-4afc-af43-79cfb874030b', 'Sliver C2 implant', 'Trafic Sliver C2 : framework C2 open-source très utilisé en 2023-2024 par les attaquants.', 'Malware/C2 : Sliver C2 implant', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 90, 1, 0, 1, NULL, '1. URGENT : compromission moderne probable
2. Isoler la machine
3. Audit forensique
4. Bloquer l''IP du C2'),
(1000089, 'cbafcf5d-08e7-4ead-be37-4ee97e786f3f', 'Mythic C2 traffic', 'Trafic Mythic C2 : framework C2 modulaire utilisé par les pentesters et attaquants.', 'Malware/C2 : Mythic C2 traffic', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 90, 1, 0, 1, NULL, '1. URGENT : compromission active
2. Isoler la machine
3. Audit forensique'),
(1000090, 'af72c5df-15a1-4f34-a713-e7e7a7f42f45', 'Brute Ratel C2', 'Trafic Brute Ratel C2 : framework C2 commercial alternatif à Cobalt Strike, très évasif.', 'Malware/C2 : Brute Ratel C2', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 90, 1, 0, 1, NULL, '1. URGENT : attaquant outillé et discret
2. Isoler la machine
3. Analyse forensique avancée requise'),
(1000091, 'd212ccd3-a771-4779-99b1-0e357c620230', 'Generic reverse shell connection', 'Reverse shell générique détecté : connexion sortante typique d''une compromission.', 'Malware/C2 : Generic reverse shell connection', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 90, 1, 0, 1, NULL, '1. URGENT : isoler la machine
2. Identifier le processus à l''origine
3. Tracer l''IP de destination
4. Investigation forensique'),
(1000092, '8db94724-4615-4b36-800c-f57ce6fbea15', 'Generic bind shell', 'Bind shell détecté : l''attaquant écoute sur un port pour recevoir des connexions de contrôle.', 'Malware/C2 : Generic bind shell', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 90, 1, 0, 1, NULL, '1. URGENT : identifier le port et le processus
2. Tuer le processus
3. Analyser comment l''attaquant a établi le bind shell'),
(1000093, '079059a3-0ab9-4a92-aa23-a53697990190', 'Netcat reverse shell pattern', 'Reverse shell Netcat : pattern classique d''utilisation de netcat pour backdoor.', 'Malware/C2 : Netcat reverse shell pattern', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 90, 1, 0, 0, NULL, '1. URGENT : compromission active
2. Identifier et tuer le processus nc
3. Désactiver netcat si pas nécessaire'),
(1000094, '4f1a4dc1-5a9f-4795-8424-7f386f1573f9', 'Socat reverse shell pattern', 'Reverse shell Socat : alternative plus sophistiquée à netcat avec support SSL.', 'Malware/C2 : Socat reverse shell pattern', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 90, 1, 0, 0, NULL, '1. URGENT : compromission active
2. Identifier et tuer le processus socat
3. Vérifier l''accès au système'),
(1000095, 'ba4e6173-55d7-4b42-a9a5-7f54866ebcb2', 'Python reverse shell pattern', 'Reverse shell Python : technique courante car Python est installé partout.', 'Malware/C2 : Python reverse shell pattern', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 90, 1, 0, 0, NULL, '1. URGENT : compromission active
2. Identifier le processus Python suspect
3. Auditer les modifications système'),
(1000096, '872b534f-daa8-4826-a487-016cf9b12532', 'Bash reverse shell pattern', 'Reverse shell Bash : technique simple sans outil externe (bash > /dev/tcp/...).', 'Malware/C2 : Bash reverse shell pattern', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 90, 1, 0, 0, NULL, '1. URGENT : compromission active
2. Identifier le processus bash suspect
3. Auditer l''historique shell des utilisateurs'),
(1000097, '66b47c50-5568-4bac-8fa4-3e3ce09ff548', 'PowerShell reverse shell', 'Reverse shell PowerShell : technique très utilisée sur Windows post-compromission.', 'Malware/C2 : PowerShell reverse shell', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 90, 1, 0, 0, NULL, '1. URGENT : compromission Windows
2. Isoler la machine
3. Activer Constrained Language Mode
4. Audit PowerShell logging'),
(1000098, '175d3fb4-13f5-4a7f-8017-88fdecca65eb', 'PHP reverse shell', 'Reverse shell PHP : souvent installé via web shell pour permettre un contrôle complet.', 'Malware/C2 : PHP reverse shell', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 90, 1, 0, 0, NULL, '1. URGENT : web shell PHP probable
2. Identifier le fichier PHP malveillant
3. Le supprimer
4. Patcher la vulnérabilité d''upload'),
(1000099, '6f29fca0-6255-4fe1-ad9e-9db691f7efc0', 'Tor exit node connection', 'Connexion vers un noeud de sortie Tor : peut indiquer une exfiltration ou trafic suspect.', 'Malware/C2 : Tor exit node connection', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. Vérifier la légitimité (test ou attaque ?)
2. Bloquer Tor au pare-feu d''entreprise
3. Auditer la machine source'),
(1000100, 'e2ea52b5-5908-4fd0-99c5-42075f041e08', 'Tor entry guard connection', 'Connexion vers un noeud Tor d''entrée : utilisateur du réseau anonyme.', 'Malware/C2 : Tor entry guard connection', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. Vérifier la légitimité
2. Politique d''entreprise sur Tor
3. Bloquer si non autorisé'),
(1000101, '8d118175-226c-49b7-8b51-293e06e4e76d', 'Cryptominer pool - Monero', 'Connexion vers un pool de minage Monero : exploitation du serveur pour miner XMR.', 'Malware/C2 : Cryptominer pool - Monero', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1496'), 'HIGH', 90, 1, 0, 1, NULL, '1. Identifier et tuer le processus de minage
2. Bloquer les pools de mining au pare-feu
3. Vérifier comment l''attaquant a obtenu l''accès
4. Surveiller la charge CPU'),
(1000102, '63c9cd2b-793c-451c-b783-e1344ad5b94b', 'Cryptominer pool - Bitcoin', 'Connexion vers un pool de minage Bitcoin.', 'Malware/C2 : Cryptominer pool - Bitcoin', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1496'), 'HIGH', 85, 1, 0, 0, NULL, '1. Identifier et tuer le processus de mining
2. Bloquer les pools Bitcoin
3. Audit complet'),
(1000103, 'c5f8a127-b63d-41b5-9ed8-0dc0b9945a58', 'Cryptominer pool - generic', 'Connexion vers un pool de minage générique : trafic typique de mining détecté.', 'Malware/C2 : Cryptominer pool - generic', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1496'), 'HIGH', 85, 1, 0, 0, NULL, '1. Identifier le processus minier
2. Bloquer le pool
3. Audit de la machine source'),
(1000104, '360a4b31-28c2-43bd-bef2-c1ca760ab43c', 'Mirai botnet traffic', 'Trafic botnet Mirai : famille de malware IoT qui forme des réseaux de DDoS massifs.', 'Malware/C2 : Mirai botnet traffic', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : machine IoT compromise
2. Isoler la machine
3. Réinitialiser aux paramètres usine
4. Changer le mot de passe par défaut'),
(1000105, 'a8be1826-304a-4855-8ce1-e373fa6933ff', 'Emotet C2 traffic', 'Trafic C2 Emotet : malware bancaire devenu plateforme de distribution. Compromission grave.', 'Malware/C2 : Emotet C2 traffic', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : compromission Emotet
2. Isoler la machine
3. Auditer les credentials Outlook/email
4. Vérifier la propagation aux autres machines'),
(1000106, 'e930a799-89f3-4605-a981-0e7ba6578ec6', 'TrickBot C2 traffic', 'Trafic C2 TrickBot : malware bancaire utilisé comme précurseur de ransomware.', 'Malware/C2 : TrickBot C2 traffic', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : ransomware peut suivre
2. Isoler la machine
3. Auditer les machines connectées
4. Sauvegardes hors ligne immédiates'),
(1000107, '7991a2e4-af78-4108-800b-be25a2c9f17d', 'IcedID C2 traffic', 'Trafic C2 IcedID : malware bancaire et loader d''autres malwares.', 'Malware/C2 : IcedID C2 traffic', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : compromission active
2. Isoler la machine
3. Analyse forensique'),
(1000108, 'bbf97f0a-fab0-480a-b7c4-a6c0fbdedfb2', 'Qakbot C2 traffic', 'Trafic C2 Qakbot : malware bancaire actif et persistant.', 'Malware/C2 : Qakbot C2 traffic', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : compromission Qakbot
2. Isoler la machine
3. Analyse forensique
4. Vérifier les autres machines'),
(1000109, '85b73192-9971-4102-9172-106494972430', 'Ursnif C2 traffic', 'Trafic C2 Ursnif : malware bancaire et voleur d''informations.', 'Malware/C2 : Ursnif C2 traffic', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : vol de credentials probable
2. Isoler la machine
3. Réinitialiser tous les credentials de la machine'),
(1000110, '917a4cf3-04eb-4f48-83c8-0ccb1056ce17', 'AsyncRAT C2 traffic', 'Trafic C2 AsyncRAT : RAT (Remote Access Trojan) très utilisé en 2023-2024.', 'Malware/C2 : AsyncRAT C2 traffic', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : contrôle à distance par attaquant
2. Isoler la machine
3. Analyse forensique'),
(1000111, '1cc51033-31bf-46e4-bb46-f1d4ef80959a', 'RedLine stealer traffic', 'Trafic RedLine Stealer : malware voleur d''informations (mots de passe, cookies, cryptos).', 'Malware/C2 : RedLine stealer traffic', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : credentials volés probables
2. Isoler la machine
3. Réinitialiser TOUS les mots de passe utilisés sur cette machine
4. Notifier l''utilisateur'),
(1000112, '8a426ded-a948-4290-bbac-8a199e7a0966', 'Vidar stealer traffic', 'Trafic Vidar Stealer : malware voleur similaire à RedLine.', 'Malware/C2 : Vidar stealer traffic', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.001'), 'CRITICAL', 95, 1, 0, 1, NULL, '1. URGENT : credentials volés
2. Isoler la machine
3. Réinitialiser tous les credentials
4. Vérifier les comptes bancaires'),
(1000113, 'af45b6b7-d7c7-4c8d-9ce1-a85252b9038c', 'WannaCry SMB exploit', 'Exploitation SMB WannaCry : tentative d''infection par le ransomware WannaCry qui exploite EternalBlue.', 'Malware/C2 : WannaCry SMB exploit', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'CRITICAL', 100, 1, 0, 1, NULL, '1. URGENT : vérifier le patch MS17-010 (KB4012212)
2. Bloquer SMB en externe immédiatement
3. Isoler les machines vulnérables
4. Désactiver SMBv1'),
(1000114, 'c376a484-bea8-445d-b10c-009a4ff28d28', 'NotPetya propagation', 'Propagation NotPetya : ransomware destructeur qui se propage comme un ver.', 'Malware/C2 : NotPetya propagation', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'CRITICAL', 100, 1, 0, 1, NULL, '1. URGENT : isoler le réseau immédiatement
2. Patcher MS17-010 partout
3. Isoler chaque machine compromise
4. Restaurer depuis sauvegardes hors ligne'),
(1000115, '781605ec-3397-41c9-b9e1-bd539ddb9800', 'Conti ransomware traffic', 'Trafic ransomware Conti : famille active de ransomware-as-a-service.', 'Malware/C2 : Conti ransomware traffic', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'CRITICAL', 100, 1, 0, 1, NULL, '1. URGENT : déconnecter le serveur du réseau
2. NE PAS payer la rançon
3. Notifier les autorités
4. Restaurer depuis sauvegardes saines'),
(1000116, 'c6daf219-2b2c-4782-a0b1-3a5bd99d0ba0', 'LockBit ransomware traffic', 'Trafic ransomware LockBit : famille très active de ransomware en 2023-2024.', 'Malware/C2 : LockBit ransomware traffic', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'CRITICAL', 100, 1, 0, 1, NULL, '1. URGENT : déconnecter du réseau
2. Préserver les preuves
3. Notifier les autorités
4. Restaurer depuis sauvegardes'),
(1000117, '8ebac5bb-d05e-4887-a6c4-0f2c0e7a9e89', 'BlackCat/ALPHV ransomware', 'Trafic ransomware BlackCat/ALPHV : ransomware moderne écrit en Rust, très évasif.', 'Malware/C2 : BlackCat/ALPHV ransomware', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1486'), 'CRITICAL', 100, 1, 0, 1, NULL, '1. URGENT : déconnecter du réseau IMMÉDIATEMENT
2. Préserver les preuves
3. Notifier autorités (ANSSI, CERT)
4. Restaurer depuis sauvegardes saines uniquement'),
(1000118, '3530f26e-373b-4b16-a364-843fa2e49fe3', 'DNS tunneling - large TXT records', 'Tunneling DNS via TXT records volumineux : exfiltration de données via DNS.', 'Malware/C2 : DNS tunneling - large TXT records', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.004'), 'HIGH', 85, 1, 0, 0, NULL, '1. URGENT : exfiltration en cours
2. Identifier la machine source
3. Bloquer le domaine de destination
4. Activer DNS inspection'),
(1000119, '48b06527-811b-4430-9d55-1a2362c2d291', 'DNS tunneling - rapid queries', 'Tunneling DNS via requêtes rapides : exfiltration furtive de données.', 'Malware/C2 : DNS tunneling - rapid queries', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.004'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : exfiltration probable
2. Identifier la machine source
3. Inspecter les domaines résolus récemment'),
(1000120, '7c451d29-78a1-448f-b29f-2030bcfc8bb4', 'ICMP tunneling - large payload', 'Tunneling ICMP avec payload anormalement grand : exfiltration de données via paquets ping.', 'Malware/C2 : ICMP tunneling - large payload', 'snort', 3, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1071.004'), 'HIGH', 85, 1, 0, 0, NULL, '1. URGENT : exfiltration via ICMP
2. Bloquer l''ICMP sortant ou le restreindre
3. Identifier le processus à l''origine'),
(1000121, '0cc76859-d4d2-4516-a6fa-897eea9be71e', 'SSH brute force - many failed attempts', 'Force brute SSH avec nombreux échecs : attaque par dictionnaire ou test de mots de passe communs.', 'Brute force : SSH brute force - many failed attempts', 'snort', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 85, 1, 0, 0, NULL, '1. L''IP est bloquée par l''agent
2. Désactiver l''auth par mot de passe (clés SSH uniquement)
3. Renommer le port SSH
4. Activer fail2ban'),
(1000122, '002a25e8-f1ca-44ef-b15f-cf990eccaa45', 'SSH credential stuffing', 'Credential stuffing SSH : l''attaquant teste des credentials volés sur d''autres sites.', 'Brute force : SSH credential stuffing', 'snort', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 85, 1, 0, 0, NULL, '1. L''IP est bloquée
2. Sensibiliser les utilisateurs à ne pas réutiliser les mots de passe
3. Activer la 2FA SSH
4. Auditer les comptes ciblés'),
(1000123, 'db5ece70-dd79-4b31-84b0-990db2f90730', 'FTP brute force', 'Force brute FTP : protocole non chiffré, attaquant cible les credentials.', 'Brute force : FTP brute force', 'snort', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 85, 1, 0, 0, NULL, '1. URGENT : migrer vers SFTP
2. Bloquer l''IP
3. Désactiver FTP si non essentiel'),
(1000124, '17c90670-ad21-4e4a-9fb8-4d22fe4ad7a5', 'FTP anonymous login from external', 'Login FTP anonyme depuis Internet : exposition de données potentielles.', 'Brute force : FTP anonymous login from external', 'snort', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 85, 1, 0, 0, NULL, '1. URGENT : désactiver FTP anonyme
2. Vérifier ce qui est accessible anonymement
3. Migrer vers SFTP avec authentification'),
(1000125, '616ac888-19cf-435c-a788-7c240f84e7d3', 'Telnet brute force', 'Force brute Telnet : protocole non chiffré, à ABSOLUMENT éviter.', 'Brute force : Telnet brute force', 'snort', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 85, 1, 0, 0, NULL, '1. URGENT : désactiver Telnet immédiatement
2. Migrer vers SSH
3. Bloquer le port 23
4. Audit des équipements utilisant Telnet'),
(1000126, 'dcbfb3e8-b872-4ab6-b434-6fef207697b3', 'Telnet from external network', 'Connexion Telnet depuis Internet : protocole obsolète et dangereux exposé.', 'Brute force : Telnet from external network', 'snort', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 85, 1, 0, 0, NULL, '1. URGENT : Telnet ne doit JAMAIS être exposé
2. Bloquer le port 23 au pare-feu d''entrée
3. Migrer vers SSH
4. Auditer les équipements legacy'),
(1000127, '220f1478-a8af-4e00-bc3a-0d850a9db651', 'RDP brute force', 'Force brute RDP (Remote Desktop) : très ciblé car donne contrôle complet du serveur Windows.', 'Brute force : RDP brute force', 'snort', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 85, 1, 0, 0, NULL, '1. URGENT : RDP ne doit pas être directement exposé
2. Masquer RDP derrière un VPN
3. Activer Network Level Authentication (NLA)
4. Bloquer l''IP, activer Account Lockout Policy'),
(1000128, '1937cbe1-e0f5-46c6-a4ec-3a254980a846', 'RDP from suspicious country', 'Connexion RDP depuis un pays suspect : géolocalisation inhabituelle pour votre activité.', 'Brute force : RDP from suspicious country', 'snort', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 85, 1, 0, 0, NULL, '1. Vérifier la légitimité avec l''utilisateur
2. Bloquer les pays non concernés au niveau pare-feu
3. Si non légitime, isoler le compte'),
(1000129, 'b7528c9a-f4c4-4cb4-bdba-c5fa77950d2b', 'MySQL brute force', 'Force brute MySQL : tentative de prendre le contrôle de la base de données.', 'Brute force : MySQL brute force', 'snort', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 85, 1, 0, 0, NULL, '1. URGENT : MySQL ne doit pas être exposé
2. Bind-address=127.0.0.1
3. Si nécessaire externe, restreindre par IP
4. Forcer SSL'),
(1000130, '949df567-7c64-42e8-b074-cf9b7987af65', 'MySQL root login attempt', 'Tentative de login MySQL en tant que ''root'' : compte super-utilisateur ciblé.', 'Brute force : MySQL root login attempt', 'snort', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 85, 1, 0, 0, NULL, '1. URGENT : isoler MySQL
2. Désactiver le login root distant
3. Renforcer le mot de passe root
4. Audit des autres comptes admin'),
(1000131, '019c5226-8cc5-4fa7-a36f-74d57f07e28d', 'PostgreSQL brute force', 'Force brute PostgreSQL : tentative de compromission de la BDD.', 'Brute force : PostgreSQL brute force', 'snort', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 85, 1, 0, 0, NULL, '1. Vérifier l''exposition réseau de PostgreSQL
2. Configurer pg_hba.conf en mode ''hostssl'' strict
3. Activer SSL obligatoire'),
(1000132, 'b3f3ecca-f04d-42cc-9378-0bc31fb932d7', 'MSSQL sa account brute force', 'Force brute sur le compte ''sa'' MSSQL : compte super-admin SQL Server ciblé.', 'Brute force : MSSQL sa account brute force', 'snort', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 85, 1, 0, 0, NULL, '1. URGENT : isoler MSSQL
2. Désactiver ''sa'' si possible
3. Renforcer le mot de passe sa
4. Migrer vers Windows Authentication'),
(1000133, '35880791-4161-491f-927e-b356ddee49a1', 'VNC brute force', 'Force brute VNC : protocole de bureau à distance avec authentification souvent faible.', 'Brute force : VNC brute force', 'snort', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 85, 1, 0, 0, NULL, '1. URGENT : VNC ne doit pas être exposé
2. Bloquer le port 5900
3. Si nécessaire, utiliser VNC over SSH ou VPN'),
(1000134, '9c2ef603-68b3-4747-ba99-ce75188b8c89', 'SMB authentication brute force', 'Force brute SMB : tentative de credentials Windows pour accéder aux partages.', 'Brute force : SMB authentication brute force', 'snort', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 85, 1, 0, 0, NULL, '1. URGENT : SMB exposé est très risqué
2. Bloquer SMB en externe
3. Désactiver SMBv1
4. Activer SMB signing'),
(1000135, 'a1b74a77-11c4-4b9d-9d04-8d3486d9e27d', 'LDAP brute force', 'Force brute LDAP : tentative sur Active Directory.', 'Brute force : LDAP brute force', 'snort', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 85, 1, 0, 0, NULL, '1. URGENT : protéger l''AD
2. Restreindre LDAP par IP
3. Activer LDAP signing et channel binding
4. Auditer les comptes ciblés'),
(1000136, 'ea4de69f-15c9-475e-ad7b-4156bd25ed9b', 'Kerberos pre-auth brute force (AS-REP)', 'Force brute Kerberos AS-REP : technique ''AS-REP Roasting'' contre les comptes sans pre-auth.', 'Brute force : Kerberos pre-auth brute force (AS-REP)', 'snort', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 85, 1, 0, 0, NULL, '1. URGENT : activer la pre-authentification sur TOUS les comptes
2. Auditer les comptes sans pre-auth requise
3. Bloquer l''IP
4. Renforcer les mots de passe AD'),
(1000137, '5f6cda7d-1c06-4255-9be8-0c56e9d2c516', 'OpenVPN authentication failure spike', 'Pic d''échecs OpenVPN : tentative de brute force du VPN d''entreprise.', 'Brute force : OpenVPN authentication failure spike', 'snort', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 85, 1, 0, 0, NULL, '1. L''IP est bloquée
2. Activer la 2FA sur OpenVPN
3. Renforcer les certificats client
4. Activer fail2ban OpenVPN'),
(1000138, '7a339df6-9b11-4f72-9b41-758362382ef1', 'WireGuard handshake spike', 'Pic de handshakes WireGuard : tentatives sur le VPN moderne.', 'Brute force : WireGuard handshake spike', 'snort', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 85, 1, 0, 0, NULL, '1. Auditer les clés autorisées
2. Bloquer les IP suspectes
3. Restreindre par IP source si possible'),
(1000139, '61358886-a421-4284-9add-6d07d46c1f2e', 'SMTP AUTH brute force', 'Force brute SMTP AUTH : utilisation du serveur de mail comme relais spam.', 'Brute force : SMTP AUTH brute force', 'snort', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 85, 1, 0, 0, NULL, '1. L''IP est bloquée
2. Vérifier les comptes mail compromis
3. Activer le rate limiting SMTP
4. Désactiver les comptes inutilisés'),
(1000140, 'de817961-8572-4618-a886-d9a623e4ea33', 'POP3 authentication brute force', 'Force brute POP3 : tentative de vol d''emails.', 'Brute force : POP3 authentication brute force', 'snort', 1, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1110.001'), 'HIGH', 85, 1, 0, 0, NULL, '1. L''IP est bloquée
2. Migrer vers IMAP/POP3 over SSL
3. Activer fail2ban-postfix'),
(1000141, '09816bb9-297a-4d4e-94d1-3683ef3ba94b', 'Large outbound HTTP POST', 'Requête HTTP POST volumineuse sortante : possible exfiltration de données.', 'Exfiltration : Large outbound HTTP POST', 'snort', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1041'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : identifier le destinataire et le contenu
2. Bloquer la connexion si malveillante
3. Auditer la machine source'),
(1000142, 'fa5ce183-2382-4042-b158-23d80f29654e', 'Large outbound HTTPS data', 'Trafic HTTPS sortant volumineux : exfiltration chiffrée probable.', 'Exfiltration : Large outbound HTTPS data', 'snort', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1041'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : exfiltration en cours probablement
2. Identifier la machine source
3. Analyser les destinations récurrentes
4. Activer un proxy d''inspection SSL'),
(1000143, '5fa2d198-6368-4d77-9600-60bc84336916', 'Upload to Pastebin', 'Upload vers Pastebin : exfiltration de secrets ou de données.', 'Exfiltration : Upload to Pastebin', 'snort', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1041'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : bloquer Pastebin au pare-feu
2. Vérifier ce qui a été uploadé
3. Activer DLP (Data Loss Prevention)'),
(1000144, '880294f6-adb0-4e08-9ca1-3e201917d1f9', 'Upload to Discord webhook', 'Upload vers webhook Discord : technique récente d''exfiltration via service légitime.', 'Exfiltration : Upload to Discord webhook', 'snort', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1041'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : bloquer les webhooks Discord
2. Identifier la machine source
3. Auditer les credentials'),
(1000145, 'ec6f6f14-6472-45a4-ac1a-8c45da8f6133', 'Upload to Telegram bot API', 'Upload vers Telegram Bot API : exfiltration via messagerie.', 'Exfiltration : Upload to Telegram bot API', 'snort', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1041'), 'HIGH', 80, 1, 0, 0, NULL, '1. Bloquer api.telegram.org au pare-feu
2. Audit machine source
3. Vérifier les bots actifs'),
(1000146, 'f0423410-d903-4109-a6a7-335fbdd5013d', 'Upload to Mega.nz', 'Upload vers Mega.nz : service de cloud anonyme souvent utilisé pour exfiltrer.', 'Exfiltration : Upload to Mega.nz', 'snort', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1041'), 'HIGH', 80, 1, 0, 0, NULL, '1. Bloquer mega.nz au pare-feu d''entreprise
2. Audit machine source
3. Politique DLP'),
(1000147, '4116483e-7e44-454c-ba48-90918cae108f', 'Upload to anonfiles.com', 'Upload vers anonfiles.com : service d''hébergement anonyme.', 'Exfiltration : Upload to anonfiles.com', 'snort', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1041'), 'HIGH', 80, 1, 0, 0, NULL, '1. Bloquer anonfiles.com
2. Audit machine source
3. Vérifier les fichiers récents'),
(1000148, 'b375806b-2138-4f30-b2b2-7868209870fd', 'Upload to Dropbox API', 'Upload anormal vers Dropbox API : exfiltration via service légitime.', 'Exfiltration : Upload to Dropbox API', 'snort', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1041'), 'HIGH', 80, 1, 0, 0, NULL, '1. Vérifier la légitimité avec l''utilisateur
2. Audit des fichiers uploadés
3. Politique DLP entreprise'),
(1000149, '1d4a0807-dc96-41dd-9b92-ab6f09ee1752', 'Upload to Google Drive (anomalous)', 'Upload anormal vers Google Drive : exfiltration via service légitime.', 'Exfiltration : Upload to Google Drive (anomalous)', 'snort', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1041'), 'HIGH', 80, 1, 0, 0, NULL, '1. Vérifier la légitimité
2. Bloquer Drive si non autorisé
3. Politique DLP'),
(1000150, '3b897b43-d72d-4b4d-bfa7-e001426e5804', 'Upload to OneDrive (anomalous)', 'Upload anormal vers OneDrive : exfiltration via service Microsoft.', 'Exfiltration : Upload to OneDrive (anomalous)', 'snort', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1041'), 'HIGH', 80, 1, 0, 0, NULL, '1. Vérifier la légitimité
2. Restreindre OneDrive à l''usage professionnel
3. Activer DLP Microsoft'),
(1000151, '33869110-0b85-4dac-b85f-65379b8d002a', 'GitHub gist creation', 'Création de Gist GitHub : exfiltration de code ou secrets.', 'Exfiltration : GitHub gist creation', 'snort', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1041'), 'HIGH', 80, 1, 0, 0, NULL, '1. Bloquer gist.github.com si non utilisé professionnellement
2. Audit des Gists créés
3. Recherche de secrets dans le code source'),
(1000152, '690a82d5-4e59-4392-82be-a8d82d5071c3', 'Database dump exfiltration pattern', 'Pattern de dump de base de données : exfiltration massive en cours.', 'Exfiltration : Database dump exfiltration pattern', 'snort', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1041'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : exfiltration de données client probable
2. Identifier la requête source
3. Bloquer la connexion
4. Notifier la CNIL si données personnelles'),
(1000153, '145883bd-24de-4437-9351-f3e997bedd52', 'Compressed archive exfiltration', 'Archive compressée envoyée externe : exfiltration de masse possible.', 'Exfiltration : Compressed archive exfiltration', 'snort', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1041'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : examiner l''archive si possible
2. Bloquer la connexion
3. Identifier la machine source
4. Audit forensique'),
(1000154, '2f5c7705-b0f3-458e-89d7-3a039888b355', 'Email with bulk attachments outside', 'Email avec nombreuses pièces jointes vers externe : exfiltration ou compromission de compte mail.', 'Exfiltration : Email with bulk attachments outside', 'snort', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1041'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : vérifier la légitimité
2. Si compromis, isoler le compte mail
3. Auditer les emails envoyés'),
(1000155, 'fca8c33a-85bf-47ca-b07a-d70de31fc887', 'ICMP data exfiltration', 'Exfiltration via ICMP : données encodées dans des paquets ping.', 'Exfiltration : ICMP data exfiltration', 'snort', 6, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1041'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : bloquer ICMP sortant
2. Identifier le processus à l''origine
3. Audit forensique de la machine'),
(1000156, '8a12de95-d8d6-46cc-ba10-de88a97974f5', 'SYN flood attack', 'Attaque SYN flood : saturation des connexions TCP. Attaque DDoS classique.', 'Denial of Service : SYN flood attack', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1499'), 'HIGH', 85, 1, 0, 0, NULL, '1. Activer SYN cookies
2. Configurer un rate limiting
3. Considérer un service anti-DDoS (Cloudflare, OVH)
4. Bloquer les IP source si identifiables'),
(1000157, 'f2e7ebf5-f555-4f20-a34d-f9f420bc5cd3', 'UDP flood attack', 'Attaque UDP flood : saturation par paquets UDP.', 'Denial of Service : UDP flood attack', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1499'), 'HIGH', 85, 1, 0, 0, NULL, '1. Bloquer le trafic UDP non nécessaire
2. Configurer le rate limiting UDP
3. Service anti-DDoS upstream'),
(1000158, 'fe9d3ad7-a63b-4dfe-a1f9-191966b70fda', 'ICMP flood attack', 'Attaque ICMP flood : saturation par pings.', 'Denial of Service : ICMP flood attack', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1499'), 'HIGH', 85, 1, 0, 0, NULL, '1. Bloquer ou limiter ICMP entrant
2. Configurer le rate limiting
3. Service anti-DDoS'),
(1000159, '9904053f-72ba-4f0c-8f06-abcdb2033709', 'HTTP GET flood (Slowloris)', 'Attaque Slowloris : connexions HTTP lentes pour saturer le serveur.', 'Denial of Service : HTTP GET flood (Slowloris)', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1499'), 'HIGH', 85, 1, 0, 0, NULL, '1. Réduire les timeouts Apache/Nginx
2. Activer mod_reqtimeout sur Apache
3. Limiter les connexions par IP
4. Reverse proxy avec protection'),
(1000160, '8a15e52e-ab9d-4ee5-82b3-88cc1bd93b3c', 'HTTP POST slow body', 'Attaque HTTP POST slow : envoi très lent du body de requête.', 'Denial of Service : HTTP POST slow body', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1499'), 'HIGH', 85, 1, 0, 0, NULL, '1. Configurer un timeout maximum pour les requêtes POST
2. Limiter le nombre de connexions par IP
3. WAF avec détection de slow attacks'),
(1000161, 'b77f9c5a-95f6-4747-bcc0-1a76ce3be4d9', 'DNS amplification attack', 'Amplification DNS : utilisation de serveurs DNS publics pour amplifier l''attaque vers une cible.', 'Denial of Service : DNS amplification attack', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1499'), 'HIGH', 85, 1, 0, 0, NULL, '1. Désactiver la récursion DNS publique si pas nécessaire
2. Limiter les réponses ANY
3. Implémenter RRL (Response Rate Limiting)'),
(1000162, 'cb6ec226-915e-439f-95e4-57adf615b738', 'NTP amplification attack', 'Amplification NTP : utilisation de la commande ''monlist'' pour amplifier des attaques.', 'Denial of Service : NTP amplification attack', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1499'), 'HIGH', 85, 1, 0, 0, NULL, '1. URGENT : patcher NTP
2. Désactiver les commandes monlist
3. Restreindre l''accès NTP'),
(1000163, '44b7da2f-fab9-44ca-a7b7-acd68e8cc228', 'SSDP amplification attack', 'Amplification SSDP : utilisation du protocole SSDP exposé.', 'Denial of Service : SSDP amplification attack', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1499'), 'HIGH', 85, 1, 0, 0, NULL, '1. URGENT : ne pas exposer SSDP en externe
2. Bloquer le port 1900 UDP
3. Audit des équipements IoT'),
(1000164, 'e976d14a-6ed7-4a1b-af2a-3da2fcf890b0', 'Memcached amplification', 'Amplification Memcached : très puissante (facteur d''amplification x50000).', 'Denial of Service : Memcached amplification', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1499'), 'HIGH', 85, 1, 0, 0, NULL, '1. URGENT : memcached ne doit JAMAIS être exposé
2. Bind-address=127.0.0.1
3. Bloquer le port 11211'),
(1000165, '0f077143-ebf8-4153-b60e-41644fdfb8c6', 'Connection rate exceeded threshold', 'Taux de connexions dépassant le seuil : DDoS probable.', 'Denial of Service : Connection rate exceeded threshold', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1499'), 'HIGH', 85, 1, 0, 0, NULL, '1. Activer le rate limiting
2. Identifier les IP en tête
3. Bloquer les IP suspectes
4. Service anti-DDoS'),
(1000166, 'af528da9-7a51-44c1-a0d5-478930e19e4c', 'PsExec service install on remote host', 'Installation de service PsExec distant : technique classique de mouvement latéral.', 'Mouvement latéral : PsExec service install on remote host', 'snort', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1210'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : isoler la machine source ET destination
2. Identifier le compte utilisé
3. Restreindre PsExec via GPO
4. Auditer les services Windows récemment créés'),
(1000167, 'b675e073-87c1-40d0-ae82-19052147dfde', 'WMI remote execution', 'Exécution WMI distante : technique post-compromission pour exécuter du code à distance.', 'Mouvement latéral : WMI remote execution', 'snort', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1210'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : compromission active
2. Identifier source et destination
3. Activer WMI logging
4. Restreindre WMI via GPO'),
(1000168, 'b448afa3-b37e-419c-ae7c-6f8e6a814e1a', 'WinRM remote shell', 'Shell WinRM distant : exécution à distance via PowerShell remoting.', 'Mouvement latéral : WinRM remote shell', 'snort', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1210'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : compromission active
2. Restreindre WinRM aux administrateurs
3. Activer PowerShell logging
4. Auditer les connexions WinRM'),
(1000169, '792db8df-32f1-4228-a5db-5c1db5457e61', 'SMB lateral connection chain', 'Chaîne de connexions SMB latérales : un attaquant se déplace de machine en machine.', 'Mouvement latéral : SMB lateral connection chain', 'snort', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1210'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : compromission étendue
2. Identifier toutes les machines touchées
3. Réinitialiser les credentials utilisés
4. Activer Network Segmentation'),
(1000170, '02a08ce3-4841-45f3-8bb7-36f88c40c85b', 'Pass-the-hash NTLM relay', 'Pass-the-Hash NTLM relay : réutilisation de hash de mot de passe Windows.', 'Mouvement latéral : Pass-the-hash NTLM relay', 'snort', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1210'), 'CRITICAL', 90, 1, 0, 1, NULL, '1. URGENT : compromission AD avancée
2. Activer SMB signing partout
3. Activer LDAP channel binding
4. Audit complet des authentifications NTLM'),
(1000171, '07e07379-fb69-4b97-bdc1-238cae38b2dd', 'Pass-the-ticket Kerberos abuse', 'Pass-the-Ticket Kerberos : réutilisation de tickets Kerberos volés.', 'Mouvement latéral : Pass-the-ticket Kerberos abuse', 'snort', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1210'), 'CRITICAL', 90, 1, 0, 1, NULL, '1. URGENT : compromission AD avancée
2. Réinitialiser le mot de passe KRBTGT (2 fois)
3. Réinitialiser les comptes utilisateurs concernés
4. Activer Protected Users group'),
(1000172, '1cff429f-66aa-4b6d-b915-8f3c037f94fd', 'BloodHound LDAP enumeration', 'Énumération LDAP par BloodHound : cartographie de l''AD par un attaquant.', 'Mouvement latéral : BloodHound LDAP enumeration', 'snort', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1210'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : un attaquant prépare son attaque
2. Identifier la machine source
3. Audit des chemins d''attaque AD
4. Renforcer les ACL AD'),
(1000173, '4cb41423-2251-4731-856d-0701eab5138a', 'Mimikatz signature in network', 'Mimikatz signature détectée dans le réseau : outil de vol de credentials Windows.', 'Mouvement latéral : Mimikatz signature in network', 'snort', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1210'), 'CRITICAL', 90, 1, 0, 1, NULL, '1. URGENT : compromission grave
2. Isoler la machine source
3. Réinitialiser TOUS les credentials utilisés sur cette machine
4. Activer Credential Guard'),
(1000174, 'f50c826c-4926-4b50-9391-1ad310b85818', 'Kerberoasting (TGS-REP request)', 'Kerberoasting : demande de TGS pour casser le hash hors-ligne.', 'Mouvement latéral : Kerberoasting (TGS-REP request)', 'snort', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1210'), 'HIGH', 80, 1, 0, 0, NULL, '1. Renforcer les mots de passe des comptes service (25+ caractères)
2. Utiliser des comptes gMSA (Managed Service Accounts)
3. Auditer les comptes avec SPN
4. Activer Active Directory Tier Model'),
(1000175, 'cf60e75a-a7f4-4345-a527-c608f3b95302', 'DCSync replication request', 'Requête de réplication DCSync : tentative de récupérer tous les hashes du domaine.', 'Mouvement latéral : DCSync replication request', 'snort', 7, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1210'), 'CRITICAL', 90, 1, 0, 1, NULL, '1. URGENT : compromission AD TOTALE
2. Identifier la machine et le compte source
3. Réinitialiser KRBTGT 2 fois
4. Réinitialiser TOUS les comptes admin
5. Audit complet AD'),
(1000176, '9d3ee79f-fb8e-4b04-8795-52a5c2977643', 'Email - suspicious attachment .exe', 'Email avec pièce jointe .exe : très suspect, format d''exécutable Windows.', 'Phishing : Email - suspicious attachment .exe', 'snort', 10, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1566'), 'HIGH', 80, 1, 0, 0, NULL, '1. Bloquer les .exe en pièce jointe au niveau mail
2. Filtrer les extensions dangereuses
3. Sensibiliser les utilisateurs'),
(1000177, '819b5391-ebc1-45bb-822b-eebdf11d2a4b', 'Email - suspicious attachment .scr', 'Email avec pièce jointe .scr : format de screensaver Windows, souvent malveillant.', 'Phishing : Email - suspicious attachment .scr', 'snort', 10, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1566'), 'HIGH', 80, 1, 0, 0, NULL, '1. Bloquer les .scr en pièce jointe
2. Filtrer les extensions à risque
3. Antivirus à jour'),
(1000178, '5a7cef12-a348-456d-883f-7d0873a3b709', 'Email - suspicious attachment .iso', 'Email avec pièce jointe .iso : technique récente pour contourner les filtres antivirus.', 'Phishing : Email - suspicious attachment .iso', 'snort', 10, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1566'), 'HIGH', 80, 1, 0, 0, NULL, '1. Bloquer les .iso en pièce jointe
2. Sensibiliser : un fichier .iso d''origine inconnue est suspect
3. Antivirus capable d''analyser les ISO'),
(1000179, '51661c2b-cce1-4620-9e5f-a64dc5ab35e9', 'Email - office macro download', 'Email avec document Office contenant des macros : vecteur classique d''infection.', 'Phishing : Email - office macro download', 'snort', 10, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1566'), 'HIGH', 80, 1, 0, 0, NULL, '1. Désactiver les macros par défaut
2. Sensibiliser les utilisateurs : ne jamais activer les macros
3. Filtrer les .docm/.xlsm
4. Antivirus à jour'),
(1000180, '7307b7fa-03dd-4fa1-9141-49f6523dbd6e', 'Email - phishing URL pattern', 'URL de phishing détectée : tentative de vol de credentials par site frauduleux.', 'Phishing : Email - phishing URL pattern', 'snort', 10, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1566'), 'HIGH', 80, 1, 0, 0, NULL, '1. Bloquer l''URL au niveau pare-feu/proxy
2. Sensibiliser les utilisateurs
3. Activer SafeBrowsing'),
(1000181, 'c96a9bea-a189-4a2b-833a-7d1ddd0fbc1f', 'Email - homograph domain (IDN)', 'Domaine homograph (caractères Unicode similaires) : technique de phishing par confusion visuelle.', 'Phishing : Email - homograph domain (IDN)', 'snort', 10, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1566'), 'HIGH', 80, 1, 0, 0, NULL, '1. Bloquer le domaine au DNS d''entreprise
2. Sensibiliser : vérifier l''URL avant de cliquer
3. Activer les IDN homograph protection navigateur'),
(1000182, 'a69322ad-fce2-4d33-ac63-1121a0d6aede', 'Email - typosquatting domain', 'Domaine typosquatting (faute de frappe) : imitation d''un domaine légitime.', 'Phishing : Email - typosquatting domain', 'snort', 10, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1566'), 'HIGH', 80, 1, 0, 0, NULL, '1. Bloquer le domaine
2. Enregistrer les typosquats de votre marque
3. Sensibilisation des utilisateurs'),
(1000183, '08ccbcf0-3c8e-446e-b549-c229ec64a273', 'Email - suspicious sender DKIM fail', 'Email avec échec DKIM : signature cryptographique invalide, expéditeur usurpé probable.', 'Phishing : Email - suspicious sender DKIM fail', 'snort', 10, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1566'), 'HIGH', 80, 1, 0, 0, NULL, '1. Bloquer ou marquer en quarantaine
2. Activer DMARC en mode quarantine ou reject
3. Sensibiliser sur l''usurpation d''identité'),
(1000184, '16258ce4-45b3-4b0f-93ce-8951af67c4f5', 'Email - bulk recipient (spam)', 'Email envoyé en masse depuis votre serveur : compte mail probablement compromis pour spam.', 'Phishing : Email - bulk recipient (spam)', 'snort', 10, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1566'), 'HIGH', 80, 1, 0, 0, NULL, '1. URGENT : isoler le compte mail
2. Réinitialiser le mot de passe
3. Activer la 2FA
4. Vérifier les règles de transfert automatique'),
(1000185, '535ce86f-1193-4753-a11d-4c647ecfbbd2', 'Email - link to credential harvesting page', 'Lien vers page de credential harvesting : phishing classique visant à voler les identifiants.', 'Phishing : Email - link to credential harvesting page', 'snort', 10, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1566'), 'HIGH', 80, 1, 0, 0, NULL, '1. Bloquer l''URL
2. Sensibiliser les utilisateurs
3. Vérifier qui a cliqué et alerter
4. Si credentials saisis, les réinitialiser'),
(1000186, 'b5358b99-4a5f-4fd3-83af-132d11201cc2', 'Suspicious user-agent - curl from server', 'User-Agent curl depuis le serveur : un programme légitime ou un malware fait des requêtes HTTP.', 'Détection : Suspicious user-agent - curl from server', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. Identifier le processus source
2. Vérifier la légitimité
3. Si malveillant, bloquer et investiguer'),
(1000187, 'd1746640-1526-46d3-ad02-e4c33d2a38bc', 'Suspicious user-agent - wget anomaly', 'User-Agent wget anormal : téléchargement automatique suspect.', 'Détection : Suspicious user-agent - wget anomaly', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. Identifier le processus source
2. Auditer les fichiers téléchargés récemment
3. Si malveillant, isoler la machine'),
(1000188, '81e7b3c0-6c43-4b24-abb2-58aef979e105', 'HTTP HEAD method scanning', 'Scan par méthode HTTP HEAD : technique pour énumérer rapidement des URLs.', 'Détection : HTTP HEAD method scanning', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'LOW', 60, 1, 0, 0, NULL, '1. Surveiller pour escalade vers d''autres attaques
2. Bloquer l''IP si volume important
3. Activer rate limiting'),
(1000189, '6da4a2e1-8208-487f-a369-6de286a5f0f0', 'HTTP OPTIONS enumeration', 'Énumération via méthode HTTP OPTIONS : recherche des méthodes HTTP autorisées.', 'Détection : HTTP OPTIONS enumeration', 'snort', 4, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1046'), 'LOW', 60, 1, 0, 0, NULL, '1. Désactiver OPTIONS si non nécessaire
2. Filtrer au niveau du WAF
3. Surveiller pour escalade'),
(1000190, '04e01804-5ae2-45ac-86cb-74e33b182a34', 'CGI scanning attempt', 'Scan CGI : recherche de scripts CGI vulnérables (ancien mais encore présent).', 'Détection : CGI scanning attempt', 'snort', 2, (SELECT id FROM mitre_techniques WHERE technique_id = 'T1190'), 'MEDIUM', 70, 1, 0, 0, NULL, '1. L''IP est bloquée
2. Désactiver CGI si non nécessaire
3. Si nécessaire, patcher les scripts CGI');

-- ============================================================================
-- Total : 190 signatures Snort enrichies
-- ============================================================================