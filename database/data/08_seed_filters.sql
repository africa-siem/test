-- ============================================================================
-- SIEM AFRICA - Filtres pré-configurés (réduction du bruit)
-- ============================================================================
-- Ces filtres sont activés par défaut pour réduire les faux positifs courants.
-- L'admin peut les désactiver/modifier depuis le dashboard.
-- ============================================================================

INSERT INTO alert_filters (
    filter_uuid, name, description,
    signature_id, src_ip,
    action, downgrade_to,
    filter_type, is_active
) VALUES

-- ============================================================================
-- Filtre 1 : Ignorer les sessions SSH des admins authentifiés (rule 5715 Wazuh)
-- ============================================================================
(lower(hex(randomblob(16))),
    'Login SSH admin réussi',
    'Ignore les ouvertures de session SSH normales pour les admins (réduit le bruit normal)',
    5715,
    NULL,
    'IGNORE', NULL,
    'SYSTEM', 1),

-- ============================================================================
-- Filtre 2 : Réduire la sévérité du scan ARP local (très commun en LAN)
-- ============================================================================
(lower(hex(randomblob(16))),
    'ARP scan en réseau local',
    'Le scan ARP est normal en réseau local : on baisse en INFO au lieu de bloquer',
    110006,
    NULL,
    'DOWNGRADE', 'INFO',
    'SYSTEM', 1),

-- ============================================================================
-- Filtre 3 : Ignorer les pings depuis le réseau interne (gateway, monitoring)
-- ============================================================================
(lower(hex(randomblob(16))),
    'Ping interne',
    'Ignore les ping sweep depuis le réseau interne (monitoring légitime)',
    110007,
    '192.168.0.0/16',
    'IGNORE', NULL,
    'SYSTEM', 1),

-- ============================================================================
-- Filtre 4 : Notifier seulement (sans bloquer) sur les User-Agents suspects
-- ============================================================================
(lower(hex(randomblob(16))),
    'User-Agent suspect en monitoring',
    'Notifier mais ne pas bloquer les UA suspects (peut être légitime : monitoring, tests)',
    31119,
    NULL,
    'NOTIFY_ONLY', NULL,
    'SYSTEM', 1),

-- ============================================================================
-- Filtre 5 : Réduire la sévérité des erreurs 404 fréquentes (scanning normal)
-- ============================================================================
(lower(hex(randomblob(16))),
    'Erreurs 404 fréquentes',
    'Bots et scanners génèrent beaucoup de 404 : on baisse à INFO',
    31127,
    NULL,
    'DOWNGRADE', 'LOW',
    'SYSTEM', 1),

-- ============================================================================
-- Filtre 6 : Premier login d'utilisateur (informatif, pas alerte)
-- ============================================================================
(lower(hex(randomblob(16))),
    'Premier login utilisateur',
    'Les premiers logins sont normaux pour de nouveaux utilisateurs',
    5724,
    NULL,
    'DOWNGRADE', 'INFO',
    'SYSTEM', 1),

-- ============================================================================
-- Filtre 7 : Ignorer les sudo command executed (très bruyant)
-- ============================================================================
-- Quand un admin fait "sudo apt update", "sudo systemctl status", etc.
-- on ne veut PAS d'alerte. Les vraies menaces sudo sont dans 5104, 5105, 5404, 5405.
(lower(hex(randomblob(16))),
    'Sudo command executed (admin normal)',
    'Ignore les commandes sudo normales d''admin. Les vraies menaces (sudoers modifié, ajout au groupe sudo, échec sudo) restent en alerte.',
    5402,
    NULL,
    'IGNORE', NULL,
    'SYSTEM', 1),

-- ============================================================================
-- Filtre 8 : Sudo privileged command - notification seulement
-- ============================================================================
(lower(hex(randomblob(16))),
    'Sudo privileged command',
    'Notifier les commandes sudo privilégiées sans bloquer (pour traçabilité)',
    5401,
    NULL,
    'NOTIFY_ONLY', NULL,
    'SYSTEM', 1);
