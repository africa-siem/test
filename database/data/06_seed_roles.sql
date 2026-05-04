-- ============================================================================
-- SIEM AFRICA - 4 Rôles RBAC
-- ============================================================================
-- Hiérarchie : ADMIN > ANALYST > OPERATOR > VIEWER
-- Les permissions sont stockées en JSON pour flexibilité.
-- ============================================================================

INSERT INTO roles (code, name, description_fr, permissions, is_system) VALUES

-- ============================================================================
-- ADMIN : Tous les droits (gère le SIEM, les utilisateurs, la configuration)
-- ============================================================================
('ADMIN', 'Administrateur',
    'Accès complet : gestion utilisateurs, configuration système, réglages SIEM, IA, et toutes actions sur alertes.',
    '{
        "alerts": ["view","acknowledge","resolve","ignore","mark_fp","assign","export"],
        "filters": ["view","create","edit","delete"],
        "blocked_ips": ["view","block","unblock","permanent_block"],
        "honeypot": ["view","configure","disable"],
        "users": ["view","create","edit","delete","reset_password","unlock"],
        "roles": ["view","assign"],
        "settings": ["view","edit","secrets"],
        "ai": ["view","configure","change_model","clear_cache"],
        "reports": ["view","generate","schedule","delete"],
        "audit": ["view","export"],
        "system": ["restart_services","backup","restore"],
        "countries": ["view","edit"]
    }',
    1),

-- ============================================================================
-- ANALYST : Investigation et résolution d'alertes
-- ============================================================================
('ANALYST', 'Analyste sécurité',
    'Investigation des alertes : peut résoudre, marquer en faux positif, créer des filtres, voir les rapports.',
    '{
        "alerts": ["view","acknowledge","resolve","ignore","mark_fp","assign","export"],
        "filters": ["view","create","edit"],
        "blocked_ips": ["view","block","unblock"],
        "honeypot": ["view"],
        "users": ["view"],
        "settings": ["view"],
        "ai": ["view"],
        "reports": ["view","generate"],
        "audit": ["view"],
        "countries": ["view"]
    }',
    1),

-- ============================================================================
-- OPERATOR : Opérations courantes (réception et traitement des alertes)
-- ============================================================================
('OPERATOR', 'Opérateur SOC',
    'Réception et traitement initial des alertes : peut acquitter, assigner, mais pas résoudre seul.',
    '{
        "alerts": ["view","acknowledge","assign"],
        "filters": ["view"],
        "blocked_ips": ["view"],
        "honeypot": ["view"],
        "users": ["view"],
        "ai": ["view"],
        "reports": ["view"],
        "countries": ["view"]
    }',
    1),

-- ============================================================================
-- VIEWER : Lecture seule (audits, dirigeants, démos)
-- ============================================================================
('VIEWER', 'Lecteur',
    'Lecture seule de toutes les informations sans possibilité de modification. Idéal pour direction, audit ou démos.',
    '{
        "alerts": ["view"],
        "filters": ["view"],
        "blocked_ips": ["view"],
        "honeypot": ["view"],
        "ai": ["view"],
        "reports": ["view"],
        "countries": ["view"]
    }',
    1);
