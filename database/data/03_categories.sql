-- ============================================================================
-- SIEM AFRICA - 10 Catégories de signatures
-- ============================================================================

INSERT INTO signature_categories (code, name, name_fr, description, color_hex, icon, display_order) VALUES
('AUTH', 'Authentication',
    'Authentification',
    'Tentatives de connexion, brute force SSH, échecs sudo, login web',
    '#0969DA', '🔑', 1),

('WEB', 'Web Attacks',
    'Attaques Web',
    'SQL injection, XSS, path traversal, file inclusion, web shells',
    '#FB8500', '🌐', 2),

('MALWARE', 'Malware',
    'Logiciels malveillants',
    'Détection de virus, ransomware, backdoors, trojans, rootkits',
    '#CF222E', '🦠', 3),

('NET_RECON', 'Network Reconnaissance',
    'Reconnaissance réseau',
    'Port scans, Nmap, ARP scans, énumération de services',
    '#A371F7', '🔍', 4),

('PRIV_ESC', 'Privilege Escalation',
    'Élévation de privilèges',
    'Abus de sudo, exploits kernel, modification de droits, abus setuid',
    '#D29922', '⬆️', 5),

('DATA_EXFIL', 'Data Exfiltration',
    'Exfiltration de données',
    'Upload anormal, DNS tunneling, transferts vers cloud non autorisés',
    '#8957E5', '📤', 6),

('LATERAL', 'Lateral Movement',
    'Mouvement latéral',
    'PsExec, WMI, abus SMB, propagation entre machines',
    '#1F6FEB', '↔️', 7),

('PERSISTENCE', 'Persistence',
    'Persistance',
    'Cron malveillants, services backdoor, registry keys, web shells',
    '#DA3633', '🔁', 8),

('HONEYPOT', 'Honeypot Trigger',
    'Honeypot déclenché',
    'Connexions sur les pièges SSH (2222), HTTP (8888), MySQL (3307)',
    '#F0B72F', '🍯', 9),

('CUSTOM', 'Custom Rules',
    'Règles personnalisées',
    'Règles ajoutées par l''administrateur du SIEM',
    '#6E7681', '⚙️', 10);
