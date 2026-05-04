-- ============================================================================
-- SIEM AFRICA - Initialisation KPI history
-- ============================================================================
-- On insère les métriques de référence à zéro pour le snapshot J0.
-- L'agent (Module 3) mettra à jour ces valeurs via un cron quotidien.
-- ============================================================================

INSERT INTO kpi_history (snapshot_date, metric_name, metric_value, metric_unit, metric_meta) VALUES
-- Volume d'alertes
(date('now'), 'alerts_total',          0, 'count', '{"description":"Nombre total d''alertes générées"}'),
(date('now'), 'alerts_critical',       0, 'count', '{"description":"Alertes CRITICAL"}'),
(date('now'), 'alerts_high',           0, 'count', '{"description":"Alertes HIGH"}'),
(date('now'), 'alerts_medium',         0, 'count', '{"description":"Alertes MEDIUM"}'),
(date('now'), 'alerts_low',            0, 'count', '{"description":"Alertes LOW"}'),

-- Workflow
(date('now'), 'alerts_resolved',       0, 'count', '{"description":"Alertes résolues"}'),
(date('now'), 'alerts_false_positive', 0, 'count', '{"description":"Faux positifs identifiés"}'),
(date('now'), 'avg_resolution_hours',  0, 'hours', '{"description":"Temps moyen de résolution"}'),

-- Vulnérabilités
(date('now'), 'vulnerabilities_total', 0, 'count', '{"description":"Vulnérabilités CVE détectées"}'),
(date('now'), 'vulnerabilities_critical', 0, 'count', '{"description":"Vulnérabilités critiques"}'),

-- Active Response
(date('now'), 'ips_blocked_total',     0, 'count', '{"description":"IPs bloquées au total"}'),
(date('now'), 'ips_blocked_active',    0, 'count', '{"description":"IPs actuellement bloquées"}'),
(date('now'), 'honeypot_hits',         0, 'count', '{"description":"Tentatives sur honeypots"}'),

-- IA
(date('now'), 'ai_explanations',       0, 'count', '{"description":"Explications IA générées"}'),
(date('now'), 'ai_avg_response_ms',    0, 'ms',    '{"description":"Temps moyen de réponse IA"}'),
(date('now'), 'ai_cache_hits',         0, 'count', '{"description":"Hits du cache IA"}'),

-- Santé du système
(date('now'), 'agent_uptime_pct',      100, '%',   '{"description":"Disponibilité de l''agent"}'),
(date('now'), 'dashboard_uptime_pct',  100, '%',   '{"description":"Disponibilité du dashboard"}'),
(date('now'), 'active_users',          0, 'count', '{"description":"Utilisateurs actifs"}');
