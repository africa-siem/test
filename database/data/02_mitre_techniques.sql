-- ============================================================================
-- SIEM AFRICA - 137 Techniques MITRE ATT&CK
-- ============================================================================
-- Source : https://attack.mitre.org/techniques/enterprise/
-- Notation : Une technique parent (ex: T1110) peut avoir des sous-techniques
-- (T1110.001, T1110.002...). On référence les principales.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- TA0043 - Reconnaissance (10 techniques)
-- ----------------------------------------------------------------------------
INSERT INTO mitre_techniques (technique_id, name, description_fr, tactic_id, is_subtechnique, parent_technique) VALUES
('T1595', 'Active Scanning', 'Scan actif des cibles (port scan, vuln scan)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0043'), 0, NULL),
('T1595.001', 'Scanning IP Blocks', 'Scan de plages d''IPs', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0043'), 1, 'T1595'),
('T1595.002', 'Vulnerability Scanning', 'Scan de vulnérabilités', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0043'), 1, 'T1595'),
('T1592', 'Gather Victim Host Information', 'Collecte d''info sur les hôtes cibles', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0043'), 0, NULL),
('T1589', 'Gather Victim Identity Information', 'Collecte d''info sur les identités (emails, noms)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0043'), 0, NULL),
('T1590', 'Gather Victim Network Information', 'Collecte d''info réseau (DNS, IP ranges)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0043'), 0, NULL),
('T1591', 'Gather Victim Org Information', 'Collecte d''info organisationnelle', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0043'), 0, NULL),
('T1598', 'Phishing for Information', 'Phishing pour collecter des informations', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0043'), 0, NULL),
('T1597', 'Search Closed Sources', 'Recherche dans des sources fermées (forums dark web)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0043'), 0, NULL),
('T1593', 'Search Open Websites/Domains', 'Recherche dans sources ouvertes (Google, social)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0043'), 0, NULL);

-- ----------------------------------------------------------------------------
-- TA0042 - Resource Development (7 techniques)
-- ----------------------------------------------------------------------------
INSERT INTO mitre_techniques (technique_id, name, description_fr, tactic_id, is_subtechnique, parent_technique) VALUES
('T1583', 'Acquire Infrastructure', 'Acquisition d''infrastructure (serveurs C2)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0042'), 0, NULL),
('T1586', 'Compromise Accounts', 'Compromission de comptes (réseaux sociaux, email)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0042'), 0, NULL),
('T1584', 'Compromise Infrastructure', 'Compromission d''infrastructure tierce', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0042'), 0, NULL),
('T1587', 'Develop Capabilities', 'Développement de malware/exploits', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0042'), 0, NULL),
('T1585', 'Establish Accounts', 'Création de comptes pour l''attaque (faux profils)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0042'), 0, NULL),
('T1588', 'Obtain Capabilities', 'Acquisition d''outils (exploit kits, malware)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0042'), 0, NULL),
('T1608', 'Stage Capabilities', 'Mise en place des outils sur infrastructure', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0042'), 0, NULL);

-- ----------------------------------------------------------------------------
-- TA0001 - Initial Access (9 techniques)
-- ----------------------------------------------------------------------------
INSERT INTO mitre_techniques (technique_id, name, description_fr, tactic_id, is_subtechnique, parent_technique) VALUES
('T1189', 'Drive-by Compromise', 'Compromission par site web piégé', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0001'), 0, NULL),
('T1190', 'Exploit Public-Facing Application', 'Exploit d''application publique (web app)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0001'), 0, NULL),
('T1133', 'External Remote Services', 'Accès via services exposés (VPN, SSH, RDP)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0001'), 0, NULL),
('T1200', 'Hardware Additions', 'Ajout de matériel malveillant (USB, dongles)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0001'), 0, NULL),
('T1566', 'Phishing', 'Phishing par email pour obtenir un accès', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0001'), 0, NULL),
('T1566.001', 'Spearphishing Attachment', 'Phishing avec pièce jointe malveillante', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0001'), 1, 'T1566'),
('T1566.002', 'Spearphishing Link', 'Phishing avec lien malveillant', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0001'), 1, 'T1566'),
('T1078', 'Valid Accounts', 'Utilisation de comptes valides (volés ou défaut)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0001'), 0, NULL),
('T1078.001', 'Default Accounts', 'Comptes par défaut non modifiés', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0001'), 1, 'T1078');

-- ----------------------------------------------------------------------------
-- TA0002 - Execution (10 techniques)
-- ----------------------------------------------------------------------------
INSERT INTO mitre_techniques (technique_id, name, description_fr, tactic_id, is_subtechnique, parent_technique) VALUES
('T1059', 'Command and Scripting Interpreter', 'Exécution via CLI/scripts (bash, PowerShell)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0002'), 0, NULL),
('T1059.001', 'PowerShell', 'Exécution PowerShell malveillante', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0002'), 1, 'T1059'),
('T1059.003', 'Windows Command Shell', 'Exécution cmd.exe', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0002'), 1, 'T1059'),
('T1059.004', 'Unix Shell', 'Exécution bash/sh malveillante', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0002'), 1, 'T1059'),
('T1059.006', 'Python', 'Exécution Python malveillante', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0002'), 1, 'T1059'),
('T1106', 'Native API', 'Appel direct d''API système', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0002'), 0, NULL),
('T1053', 'Scheduled Task/Job', 'Tâche planifiée (cron, scheduled task)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0002'), 0, NULL),
('T1053.003', 'Cron', 'Cron malveillant (Linux)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0002'), 1, 'T1053'),
('T1204', 'User Execution', 'Exécution déclenchée par l''utilisateur (clic)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0002'), 0, NULL),
('T1569', 'System Services', 'Exécution via services système', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0002'), 0, NULL);

-- ----------------------------------------------------------------------------
-- TA0003 - Persistence (10 techniques)
-- ----------------------------------------------------------------------------
INSERT INTO mitre_techniques (technique_id, name, description_fr, tactic_id, is_subtechnique, parent_technique) VALUES
('T1098', 'Account Manipulation', 'Modification de comptes pour persister', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0003'), 0, NULL),
('T1547', 'Boot or Logon Autostart Execution', 'Démarrage auto au boot/login', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0003'), 0, NULL),
('T1136', 'Create Account', 'Création de nouveau compte', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0003'), 0, NULL),
('T1136.001', 'Local Account', 'Création de compte local', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0003'), 1, 'T1136'),
('T1543', 'Create or Modify System Process', 'Création/modif de service système', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0003'), 0, NULL),
('T1543.002', 'Systemd Service', 'Service systemd malveillant (Linux)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0003'), 1, 'T1543'),
('T1546', 'Event Triggered Execution', 'Exécution déclenchée par événement', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0003'), 0, NULL),
('T1574', 'Hijack Execution Flow', 'Détournement de flux d''exécution (DLL hijacking)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0003'), 0, NULL),
('T1505', 'Server Software Component', 'Composants serveur malveillants (web shells)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0003'), 0, NULL),
('T1505.003', 'Web Shell', 'Web shell malveillant', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0003'), 1, 'T1505');

-- ----------------------------------------------------------------------------
-- TA0004 - Privilege Escalation (10 techniques)
-- ----------------------------------------------------------------------------
INSERT INTO mitre_techniques (technique_id, name, description_fr, tactic_id, is_subtechnique, parent_technique) VALUES
('T1548', 'Abuse Elevation Control Mechanism', 'Abus des mécanismes d''élévation', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0004'), 0, NULL),
('T1548.001', 'Setuid and Setgid', 'Abus de setuid/setgid (Linux)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0004'), 1, 'T1548'),
('T1548.003', 'Sudo and Sudo Caching', 'Abus de sudo', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0004'), 1, 'T1548'),
('T1134', 'Access Token Manipulation', 'Manipulation de tokens d''accès', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0004'), 0, NULL),
('T1611', 'Escape to Host', 'Évasion de container vers hôte', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0004'), 0, NULL),
('T1068', 'Exploitation for Privilege Escalation', 'Exploit pour élévation (kernel exploit)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0004'), 0, NULL),
('T1055', 'Process Injection', 'Injection de code dans un processus', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0004'), 0, NULL),
('T1053.005', 'Scheduled Task', 'Tâche planifiée pour PE (Windows)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0004'), 1, 'T1053'),
('T1078.003', 'Local Accounts', 'Comptes locaux pour PE', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0004'), 1, 'T1078'),
('T1484', 'Domain Policy Modification', 'Modification de policies domaine', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0004'), 0, NULL);

-- ----------------------------------------------------------------------------
-- TA0005 - Defense Evasion (10 techniques)
-- ----------------------------------------------------------------------------
INSERT INTO mitre_techniques (technique_id, name, description_fr, tactic_id, is_subtechnique, parent_technique) VALUES
('T1140', 'Deobfuscate/Decode Files or Information', 'Déobfuscation pour exécution', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0005'), 0, NULL),
('T1222', 'File and Directory Permissions Modification', 'Modif de permissions pour évasion', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0005'), 0, NULL),
('T1564', 'Hide Artifacts', 'Masquage d''artefacts (fichiers cachés)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0005'), 0, NULL),
('T1562', 'Impair Defenses', 'Désactivation des outils de sécurité', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0005'), 0, NULL),
('T1562.001', 'Disable or Modify Tools', 'Désactivation antivirus/firewall', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0005'), 1, 'T1562'),
('T1070', 'Indicator Removal', 'Suppression des indicateurs (logs)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0005'), 0, NULL),
('T1070.002', 'Clear Linux or Mac System Logs', 'Effacement de logs Linux/Mac', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0005'), 1, 'T1070'),
('T1070.004', 'File Deletion', 'Suppression de fichiers de preuves', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0005'), 1, 'T1070'),
('T1027', 'Obfuscated Files or Information', 'Obfuscation de fichiers/code', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0005'), 0, NULL),
('T1218', 'System Binary Proxy Execution', 'Exécution via binaires système légitimes', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0005'), 0, NULL);

-- ----------------------------------------------------------------------------
-- TA0006 - Credential Access (10 techniques)
-- ----------------------------------------------------------------------------
INSERT INTO mitre_techniques (technique_id, name, description_fr, tactic_id, is_subtechnique, parent_technique) VALUES
('T1110', 'Brute Force', 'Force brute sur mots de passe', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0006'), 0, NULL),
('T1110.001', 'Password Guessing', 'Devinage de mot de passe (dictionary attack)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0006'), 1, 'T1110'),
('T1110.003', 'Password Spraying', 'Password spraying (1 mot sur N comptes)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0006'), 1, 'T1110'),
('T1555', 'Credentials from Password Stores', 'Vol de credentials dans gestionnaires', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0006'), 0, NULL),
('T1212', 'Exploitation for Credential Access', 'Exploit pour vol de credentials', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0006'), 0, NULL),
('T1187', 'Forced Authentication', 'Authentification forcée (NTLM relay)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0006'), 0, NULL),
('T1056', 'Input Capture', 'Capture d''input (keylogging)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0006'), 0, NULL),
('T1056.001', 'Keylogging', 'Keylogger', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0006'), 1, 'T1056'),
('T1003', 'OS Credential Dumping', 'Dump de credentials OS (LSASS, /etc/shadow)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0006'), 0, NULL),
('T1003.008', '/etc/passwd and /etc/shadow', 'Lecture de /etc/shadow Linux', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0006'), 1, 'T1003');

-- ----------------------------------------------------------------------------
-- TA0007 - Discovery (10 techniques)
-- ----------------------------------------------------------------------------
INSERT INTO mitre_techniques (technique_id, name, description_fr, tactic_id, is_subtechnique, parent_technique) VALUES
('T1087', 'Account Discovery', 'Découverte de comptes système', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0007'), 0, NULL),
('T1087.001', 'Local Account', 'Découverte de comptes locaux', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0007'), 1, 'T1087'),
('T1083', 'File and Directory Discovery', 'Énumération de fichiers/dossiers', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0007'), 0, NULL),
('T1046', 'Network Service Discovery', 'Découverte de services réseau (port scan)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0007'), 0, NULL),
('T1135', 'Network Share Discovery', 'Découverte de partages réseau', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0007'), 0, NULL),
('T1057', 'Process Discovery', 'Énumération des processus', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0007'), 0, NULL),
('T1018', 'Remote System Discovery', 'Découverte de systèmes distants', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0007'), 0, NULL),
('T1518', 'Software Discovery', 'Énumération de logiciels installés', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0007'), 0, NULL),
('T1082', 'System Information Discovery', 'Collecte d''info système (uname, OS)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0007'), 0, NULL),
('T1033', 'System Owner/User Discovery', 'Découverte de l''utilisateur courant', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0007'), 0, NULL);

-- ----------------------------------------------------------------------------
-- TA0008 - Lateral Movement (8 techniques)
-- ----------------------------------------------------------------------------
INSERT INTO mitre_techniques (technique_id, name, description_fr, tactic_id, is_subtechnique, parent_technique) VALUES
('T1210', 'Exploitation of Remote Services', 'Exploit de services distants', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0008'), 0, NULL),
('T1534', 'Internal Spearphishing', 'Phishing interne (compte compromis)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0008'), 0, NULL),
('T1570', 'Lateral Tool Transfer', 'Transfert latéral d''outils', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0008'), 0, NULL),
('T1563', 'Remote Service Session Hijacking', 'Hijacking de session distante', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0008'), 0, NULL),
('T1021', 'Remote Services', 'Mouvement via services distants', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0008'), 0, NULL),
('T1021.001', 'Remote Desktop Protocol', 'RDP malveillant', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0008'), 1, 'T1021'),
('T1021.004', 'SSH', 'SSH pour mouvement latéral', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0008'), 1, 'T1021'),
('T1080', 'Taint Shared Content', 'Infection de contenu partagé', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0008'), 0, NULL);

-- ----------------------------------------------------------------------------
-- TA0009 - Collection (10 techniques)
-- ----------------------------------------------------------------------------
INSERT INTO mitre_techniques (technique_id, name, description_fr, tactic_id, is_subtechnique, parent_technique) VALUES
('T1560', 'Archive Collected Data', 'Compression des données collectées', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0009'), 0, NULL),
('T1119', 'Automated Collection', 'Collecte automatisée par scripts', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0009'), 0, NULL),
('T1115', 'Clipboard Data', 'Capture du presse-papiers', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0009'), 0, NULL),
('T1530', 'Data from Cloud Storage', 'Vol depuis stockage cloud', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0009'), 0, NULL),
('T1213', 'Data from Information Repositories', 'Vol depuis dépôts (Confluence, SharePoint)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0009'), 0, NULL),
('T1005', 'Data from Local System', 'Vol depuis système local', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0009'), 0, NULL),
('T1039', 'Data from Network Shared Drive', 'Vol depuis partages réseau', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0009'), 0, NULL),
('T1025', 'Data from Removable Media', 'Vol depuis supports amovibles (USB)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0009'), 0, NULL),
('T1074', 'Data Staged', 'Stockage temporaire avant exfiltration', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0009'), 0, NULL),
('T1114', 'Email Collection', 'Collecte d''emails', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0009'), 0, NULL);

-- ----------------------------------------------------------------------------
-- TA0011 - Command and Control (10 techniques)
-- ----------------------------------------------------------------------------
INSERT INTO mitre_techniques (technique_id, name, description_fr, tactic_id, is_subtechnique, parent_technique) VALUES
('T1071', 'Application Layer Protocol', 'Communication via protocole applicatif (HTTP)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0011'), 0, NULL),
('T1071.001', 'Web Protocols', 'C2 via HTTP/HTTPS', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0011'), 1, 'T1071'),
('T1071.004', 'DNS', 'C2 via DNS tunneling', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0011'), 1, 'T1071'),
('T1132', 'Data Encoding', 'Encodage des communications C2', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0011'), 0, NULL),
('T1573', 'Encrypted Channel', 'Canal C2 chiffré', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0011'), 0, NULL),
('T1008', 'Fallback Channels', 'Canaux C2 de secours', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0011'), 0, NULL),
('T1105', 'Ingress Tool Transfer', 'Téléchargement d''outils sur la cible', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0011'), 0, NULL),
('T1104', 'Multi-Stage Channels', 'C2 multi-étapes', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0011'), 0, NULL),
('T1095', 'Non-Application Layer Protocol', 'C2 via protocoles bas niveau (ICMP)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0011'), 0, NULL),
('T1090', 'Proxy', 'Communication via proxy', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0011'), 0, NULL);

-- ----------------------------------------------------------------------------
-- TA0010 - Exfiltration (8 techniques)
-- ----------------------------------------------------------------------------
INSERT INTO mitre_techniques (technique_id, name, description_fr, tactic_id, is_subtechnique, parent_technique) VALUES
('T1020', 'Automated Exfiltration', 'Exfiltration automatisée', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0010'), 0, NULL),
('T1030', 'Data Transfer Size Limits', 'Découpage en petits transferts', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0010'), 0, NULL),
('T1048', 'Exfiltration Over Alternative Protocol', 'Exfiltration via protocole alternatif', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0010'), 0, NULL),
('T1041', 'Exfiltration Over C2 Channel', 'Exfiltration via canal C2', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0010'), 0, NULL),
('T1011', 'Exfiltration Over Other Network Medium', 'Exfiltration via autre support', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0010'), 0, NULL),
('T1052', 'Exfiltration Over Physical Medium', 'Exfiltration physique (USB)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0010'), 0, NULL),
('T1567', 'Exfiltration Over Web Service', 'Exfiltration via service web (cloud storage)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0010'), 0, NULL),
('T1029', 'Scheduled Transfer', 'Transferts planifiés (anti-détection)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0010'), 0, NULL);

-- ----------------------------------------------------------------------------
-- TA0040 - Impact (15 techniques)
-- ----------------------------------------------------------------------------
INSERT INTO mitre_techniques (technique_id, name, description_fr, tactic_id, is_subtechnique, parent_technique) VALUES
('T1531', 'Account Access Removal', 'Suppression d''accès aux comptes (déni d''accès)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0040'), 0, NULL),
('T1485', 'Data Destruction', 'Destruction de données', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0040'), 0, NULL),
('T1486', 'Data Encrypted for Impact', 'Chiffrement pour rançon (RANSOMWARE)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0040'), 0, NULL),
('T1565', 'Data Manipulation', 'Manipulation de données', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0040'), 0, NULL),
('T1491', 'Defacement', 'Défiguration de site web', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0040'), 0, NULL),
('T1561', 'Disk Wipe', 'Effacement de disque', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0040'), 0, NULL),
('T1499', 'Endpoint Denial of Service', 'Déni de service sur endpoint', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0040'), 0, NULL),
('T1495', 'Firmware Corruption', 'Corruption de firmware', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0040'), 0, NULL),
('T1490', 'Inhibit System Recovery', 'Empêche la récupération (delete shadows)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0040'), 0, NULL),
('T1498', 'Network Denial of Service', 'DDoS réseau', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0040'), 0, NULL),
('T1496', 'Resource Hijacking', 'Détournement de ressources (cryptomining)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0040'), 0, NULL),
('T1489', 'Service Stop', 'Arrêt de services critiques', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0040'), 0, NULL),
('T1529', 'System Shutdown/Reboot', 'Arrêt/redémarrage forcé', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0040'), 0, NULL),
('T1657', 'Financial Theft', 'Vol financier (fraude bancaire)', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0040'), 0, NULL),
('T1499.001', 'OS Exhaustion Flood', 'Inondation de ressources OS', (SELECT id FROM mitre_tactics WHERE tactic_id = 'TA0040'), 1, 'T1499');
