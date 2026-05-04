-- ============================================================================
-- SIEM AFRICA - 14 Tactiques MITRE ATT&CK
-- ============================================================================
-- Source : https://attack.mitre.org/tactics/enterprise/
-- Version MITRE : 14.1 (octobre 2024)
-- ============================================================================

INSERT INTO mitre_tactics (tactic_id, name, description, description_fr, display_order) VALUES
('TA0043', 'Reconnaissance',
    'The adversary is trying to gather information they can use to plan future operations.',
    'L''attaquant cherche à recueillir des informations sur la cible pour planifier ses opérations.',
    1),

('TA0042', 'Resource Development',
    'The adversary is trying to establish resources they can use to support operations.',
    'L''attaquant établit l''infrastructure nécessaire à son attaque (serveurs C2, comptes, malware).',
    2),

('TA0001', 'Initial Access',
    'The adversary is trying to get into your network.',
    'L''attaquant tente de pénétrer dans le réseau cible (phishing, exploits, accès volés).',
    3),

('TA0002', 'Execution',
    'The adversary is trying to run malicious code.',
    'L''attaquant tente d''exécuter du code malveillant sur le système compromis.',
    4),

('TA0003', 'Persistence',
    'The adversary is trying to maintain their foothold.',
    'L''attaquant cherche à maintenir son accès même après un redémarrage ou un changement de mot de passe.',
    5),

('TA0004', 'Privilege Escalation',
    'The adversary is trying to gain higher-level permissions.',
    'L''attaquant tente d''obtenir des privilèges plus élevés (admin/root) sur le système.',
    6),

('TA0005', 'Defense Evasion',
    'The adversary is trying to avoid being detected.',
    'L''attaquant cherche à éviter la détection par les outils de sécurité (antivirus, SIEM).',
    7),

('TA0006', 'Credential Access',
    'The adversary is trying to steal account names and passwords.',
    'L''attaquant cherche à voler des identifiants (mots de passe, tokens, clés).',
    8),

('TA0007', 'Discovery',
    'The adversary is trying to figure out your environment.',
    'L''attaquant explore le réseau interne pour comprendre l''environnement et identifier les cibles.',
    9),

('TA0008', 'Lateral Movement',
    'The adversary is trying to move through your environment.',
    'L''attaquant se déplace d''une machine à l''autre pour atteindre sa cible finale.',
    10),

('TA0009', 'Collection',
    'The adversary is trying to gather data of interest to their goal.',
    'L''attaquant collecte des données d''intérêt (documents, base de données, mots de passe).',
    11),

('TA0011', 'Command and Control',
    'The adversary is trying to communicate with compromised systems to control them.',
    'L''attaquant communique avec les machines compromises pour les piloter à distance.',
    12),

('TA0010', 'Exfiltration',
    'The adversary is trying to steal data.',
    'L''attaquant exfiltre les données volées vers son infrastructure (vol de fichiers, dump BDD).',
    13),

('TA0040', 'Impact',
    'The adversary is trying to manipulate, interrupt, or destroy your systems and data.',
    'L''attaquant cause des dommages : destruction, chiffrement (ransomware), déni de service.',
    14);
