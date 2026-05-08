-- ============================================================================
-- SIEM AFRICA - Settings dynamiques
-- ============================================================================
-- Tous les paramètres modifiables depuis le dashboard sans redémarrage.
-- Catégories : smtp, ai, ui, correlation, alerting, retention, system
-- ============================================================================

INSERT INTO settings (key, value, value_type, enum_values, category, description_fr, is_sensitive, is_editable) VALUES

-- ============================================================================
-- 📧 SMTP (envoi d'emails sur alertes critiques)
-- ============================================================================
('smtp_enabled', 'true', 'bool', NULL,
    'smtp', 'Activer/désactiver l''envoi d''emails', 0, 1),

('smtp_host', 'smtp.gmail.com', 'text', NULL,
    'smtp', 'Serveur SMTP (ex: smtp.gmail.com, smtp.office365.com)', 0, 1),

('smtp_port', '587', 'int', NULL,
    'smtp', 'Port SMTP (587 pour TLS, 465 pour SSL)', 0, 1),

('smtp_use_tls', 'true', 'bool', NULL,
    'smtp', 'Utiliser TLS (recommandé)', 0, 1),

('smtp_username', '', 'text', NULL,
    'smtp', 'Nom d''utilisateur SMTP (souvent l''email)', 0, 1),

('smtp_password', '', 'secret', NULL,
    'smtp', 'Mot de passe SMTP ou App Password (Gmail)', 1, 1),

('smtp_from_email', '', 'text', NULL,
    'smtp', 'Email expéditeur des notifications', 0, 1),

('smtp_from_name', 'SIEM Africa', 'text', NULL,
    'smtp', 'Nom affiché de l''expéditeur', 0, 1),

('smtp_alert_recipients', '', 'text', NULL,
    'smtp', 'Emails destinataires (séparés par des virgules)', 0, 1),

('smtp_min_severity', 'CRITICAL', 'enum', '["INFO","LOW","MEDIUM","HIGH","CRITICAL"]',
    'smtp', 'Sévérité minimale pour envoyer un email', 0, 1),

-- ============================================================================
-- 🤖 IA Ollama - MULTI-MODÈLES ⭐
-- ============================================================================
('ai_enabled', 'true', 'bool', NULL,
    'ai', 'Activer les explications IA des alertes', 0, 1),

('ai_provider', 'ollama', 'enum', '["ollama","openai","claude","disabled"]',
    'ai', 'Fournisseur IA (ollama = local, gratuit)', 0, 1),

('ai_endpoint', 'http://localhost:11434', 'text', NULL,
    'ai', 'URL du serveur IA (Ollama par défaut)', 0, 1),

-- ⭐ NOUVEAU : Liste des modèles disponibles
('ai_models_available', 'llama3.2:3b,qwen2.5:3b', 'text', NULL,
    'ai', 'Modèles IA disponibles (séparés par virgule). Doivent être pull via "ollama pull <nom>"', 0, 1),

-- ⭐ NOUVEAU : Modèle par défaut (sélectionnable)
('ai_default_model', 'qwen2.5:3b', 'text', NULL,
    'ai', 'Modèle utilisé par défaut pour les explications', 0, 1),

('ai_temperature', '0.3', 'text', NULL,
    'ai', 'Créativité du modèle (0=déterministe, 1=créatif). 0.3 recommandé pour SIEM', 0, 1),

('ai_max_tokens', '300', 'int', NULL,
    'ai', 'Longueur maximale des réponses IA (en tokens)', 0, 1),

('ai_timeout_sec', '60', 'int', NULL,
    'ai', 'Timeout pour les requêtes IA (secondes)', 0, 1),

('ai_min_severity', 'HIGH', 'enum', '["INFO","LOW","MEDIUM","HIGH","CRITICAL"]',
    'ai', 'Sévérité minimale pour générer une explication IA (économie ressources)', 0, 1),

('ai_cache_enabled', 'true', 'bool', NULL,
    'ai', 'Mettre en cache les explications IA (évite de regénérer)', 0, 1),

('ai_cache_ttl_hours', '168', 'int', NULL,
    'ai', 'Durée de vie du cache IA en heures (168 = 7 jours)', 0, 1),

-- ⭐ NOUVEAU : Mode async pour ne pas bloquer l'agent pendant l'appel Ollama
('ai_async_enabled', 'true', 'bool', NULL,
    'ai', 'Mode asynchrone : alerte affichée de suite, IA en background', 0, 1),

-- ⭐ NOUVEAU : Enrichissement des signatures inconnues (la grosse feature)
('ai_enrich_unknown', 'true', 'bool', NULL,
    'ai', 'Envoyer à l''IA les alertes dont la signature n''est pas en BDD', 0, 1),

-- ⭐ NOUVEAU : Auto-promouvoir les analyses IA validées en signatures
('ai_auto_promote_validated', 'false', 'bool', NULL,
    'ai', 'Promouvoir automatiquement les analyses IA validées par admin en vraies signatures', 0, 1),

-- ⭐ NOUVEAU : Healthcheck Ollama au démarrage agent
('ai_healthcheck_on_boot', 'true', 'bool', NULL,
    'ai', 'Vérifier qu''Ollama répond au démarrage de l''agent', 0, 1),

-- ⭐ NOUVEAU : Version du prompt (pour invalider le cache si on change)
('ai_prompt_version', 'v1', 'text', NULL,
    'ai', 'Version actuelle du prompt système (changer = invalider le cache)', 0, 1),

-- ============================================================================
-- 🎨 UI - Interface utilisateur (toggle dark/light ⭐)
-- ============================================================================
-- ⭐ NOUVEAU : Thème par défaut
('theme_default', 'light', 'enum', '["dark","light","auto"]',
    'ui', 'Thème par défaut du dashboard', 0, 1),

-- ⭐ NOUVEAU : Autoriser le toggle utilisateur
('allow_theme_toggle', 'true', 'bool', NULL,
    'ui', 'Autoriser les utilisateurs à changer le thème', 0, 1),

('default_language', 'fr', 'enum', '["fr","en"]',
    'ui', 'Langue par défaut du dashboard', 0, 1),

-- ⭐ NOUVEAU : Autoriser le toggle de langue
('allow_language_toggle', 'true', 'bool', NULL,
    'ui', 'Autoriser les utilisateurs à changer la langue', 0, 1),

('default_timezone', 'Africa/Douala', 'text', NULL,
    'ui', 'Fuseau horaire par défaut', 0, 1),

('items_per_page', '50', 'int', NULL,
    'ui', 'Nombre d''alertes par page', 0, 1),

('refresh_interval_sec', '30', 'int', NULL,
    'ui', 'Intervalle d''actualisation auto du dashboard (secondes)', 0, 1),

('show_welcome_banner', 'true', 'bool', NULL,
    'ui', 'Afficher la bannière de bienvenue', 0, 1),

('organization_name', 'PME Africa', 'text', NULL,
    'ui', 'Nom de l''organisation (affiché en header)', 0, 1),

-- ============================================================================
-- 🔗 Corrélation des alertes
-- ============================================================================
('correlation_enabled', 'true', 'bool', NULL,
    'correlation', 'Activer la corrélation pour réduire le bruit', 0, 1),

('correlation_window_min', '5', 'int', NULL,
    'correlation', 'Fenêtre temporelle de corrélation (minutes)', 0, 1),

('correlation_max_events', '100', 'int', NULL,
    'correlation', 'Nombre max d''events corrélés en une alerte', 0, 1),

-- ============================================================================
-- 🚨 Alerting & Active Response
-- ============================================================================
('auto_block_critical', 'true', 'bool', NULL,
    'alerting', 'Bloquer automatiquement les IPs sur alerte CRITICAL', 0, 1),

('auto_block_duration_min', '60', 'int', NULL,
    'alerting', 'Durée du blocage automatique (minutes). 0=permanent', 0, 1),

('honeypot_auto_block', 'true', 'bool', NULL,
    'alerting', 'Bloquer immédiatement les IPs touchant les honeypots', 0, 1),

('honeypot_block_duration_min', '1440', 'int', NULL,
    'alerting', 'Durée blocage honeypot (1440=24h)', 0, 1),

('brute_force_threshold', '5', 'int', NULL,
    'alerting', 'Nombre de tentatives échouées avant blocage', 0, 1),

('brute_force_window_min', '10', 'int', NULL,
    'alerting', 'Fenêtre de détection brute force (minutes)', 0, 1),

-- ============================================================================
-- 🗄️ Rétention des données (RGPD/conformité)
-- ============================================================================
('retention_alerts_days', '180', 'int', NULL,
    'retention', 'Durée de conservation des alertes (jours)', 0, 1),

('retention_raw_events_days', '7', 'int', NULL,
    'retention', 'Durée des événements bruts (jours, court car volumineux)', 0, 1),

('retention_audit_log_days', '365', 'int', NULL,
    'retention', 'Durée du log d''audit (1 an pour conformité)', 0, 1),

('retention_email_logs_days', '90', 'int', NULL,
    'retention', 'Durée des logs d''emails (jours)', 0, 1),

('retention_honeypot_days', '90', 'int', NULL,
    'retention', 'Durée des hits honeypot (jours)', 0, 1),

-- ============================================================================
-- ⚙️ Système
-- ============================================================================
('system_install_date', datetime('now'), 'text', NULL,
    'system', 'Date d''installation du SIEM', 0, 0),

('system_version', '3.0.0', 'text', NULL,
    'system', 'Version du SIEM Africa', 0, 0),

('system_country_id', '1', 'int', NULL,
    'system', 'Pays principal du déploiement (1=Cameroun par défaut)', 0, 1),

('kpi_snapshot_enabled', 'true', 'bool', NULL,
    'system', 'Activer les snapshots KPI quotidiens', 0, 1),

('kpi_snapshot_hour', '0', 'int', NULL,
    'system', 'Heure du snapshot KPI quotidien (0-23)', 0, 1);
