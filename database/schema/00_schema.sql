-- ============================================================================
-- SIEM AFRICA - Module 2 (Base de données)
-- Schéma SQLite - Cible PME africaines (Afrique Centrale)
-- ============================================================================
-- Compatible Ubuntu 22.04 LTS et 24.04 LTS
-- 24 tables, 4 vues, 9 triggers, 88+ index
-- Auteur : Équipe SIEM Africa
-- ============================================================================

-- ----------------------------------------------------------------------------
-- CONFIGURATION SQLITE (cohérence + performance)
-- ----------------------------------------------------------------------------
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA temp_store = MEMORY;
PRAGMA cache_size = -10000;  -- 10 MB de cache

-- ============================================================================
-- DOMAINE 1 : DÉTECTION (référentiel de ce qu'on cherche)
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Table: mitre_tactics (14 tactiques MITRE ATT&CK)
-- ----------------------------------------------------------------------------
CREATE TABLE mitre_tactics (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tactic_id       TEXT    NOT NULL UNIQUE,        -- TA0001, TA0002...
    name            TEXT    NOT NULL,                -- "Initial Access"
    description     TEXT,
    description_fr  TEXT,
    display_order   INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_mitre_tactics_tactic_id ON mitre_tactics(tactic_id);
CREATE INDEX idx_mitre_tactics_order     ON mitre_tactics(display_order);


-- ----------------------------------------------------------------------------
-- Table: mitre_techniques (137 techniques MITRE)
-- ----------------------------------------------------------------------------
CREATE TABLE mitre_techniques (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    technique_id    TEXT    NOT NULL UNIQUE,        -- T1110, T1078...
    name            TEXT    NOT NULL,
    description     TEXT,
    description_fr  TEXT,
    tactic_id       INTEGER NOT NULL,
    is_subtechnique INTEGER NOT NULL DEFAULT 0,
    parent_technique TEXT,                            -- T1110 pour T1110.001
    created_at      TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tactic_id) REFERENCES mitre_tactics(id) ON DELETE RESTRICT
);

CREATE INDEX idx_mitre_techniques_tech_id   ON mitre_techniques(technique_id);
CREATE INDEX idx_mitre_techniques_tactic    ON mitre_techniques(tactic_id);
CREATE INDEX idx_mitre_techniques_parent    ON mitre_techniques(parent_technique);


-- ----------------------------------------------------------------------------
-- Table: signature_categories (10 catégories pour grouper)
-- ----------------------------------------------------------------------------
CREATE TABLE signature_categories (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    code            TEXT    NOT NULL UNIQUE,        -- AUTH, WEB, MALWARE...
    name            TEXT    NOT NULL,
    name_fr         TEXT,
    description     TEXT,
    color_hex       TEXT    NOT NULL DEFAULT '#6e7681',
    icon            TEXT,                            -- emoji ou nom icône
    display_order   INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_categories_code ON signature_categories(code);


-- ----------------------------------------------------------------------------
-- Table: signatures (380 règles de détection)
-- C'est le RÉFÉRENTIEL : ce qu'on cherche dans les events
-- ----------------------------------------------------------------------------
CREATE TABLE signatures (
    id                  INTEGER PRIMARY KEY,        -- = rule_id Wazuh ou SID Snort
    uuid                TEXT    NOT NULL UNIQUE,
    name                TEXT    NOT NULL,
    description         TEXT,
    description_fr      TEXT,
    description_en      TEXT,
    source              TEXT    NOT NULL CHECK(source IN ('wazuh','snort','custom')),
    category_id         INTEGER NOT NULL,
    technique_id        INTEGER,                    -- FK vers mitre_techniques
    severity            TEXT    NOT NULL CHECK(severity IN ('INFO','LOW','MEDIUM','HIGH','CRITICAL')),
    confidence          INTEGER NOT NULL DEFAULT 70 CHECK(confidence BETWEEN 0 AND 100),
    is_active           INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)),
    is_noisy            INTEGER NOT NULL DEFAULT 0 CHECK(is_noisy IN (0,1)),
    is_critical_chain   INTEGER NOT NULL DEFAULT 0 CHECK(is_critical_chain IN (0,1)),
    remediation         TEXT,
    remediation_fr      TEXT,
    references_url      TEXT,                       -- URL doc Wazuh/Snort
    cve_ids             TEXT,                       -- JSON array : ["CVE-2024-1234"]
    metadata            TEXT,                       -- JSON
    created_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (category_id)  REFERENCES signature_categories(id) ON DELETE RESTRICT,
    FOREIGN KEY (technique_id) REFERENCES mitre_techniques(id)     ON DELETE SET NULL
);

CREATE INDEX idx_signatures_uuid        ON signatures(uuid);
CREATE INDEX idx_signatures_source      ON signatures(source);
CREATE INDEX idx_signatures_severity    ON signatures(severity);
CREATE INDEX idx_signatures_category    ON signatures(category_id);
CREATE INDEX idx_signatures_technique   ON signatures(technique_id);
CREATE INDEX idx_signatures_active      ON signatures(is_active);
CREATE INDEX idx_signatures_noisy       ON signatures(is_noisy);


-- ============================================================================
-- DOMAINE 2 : ÉVÉNEMENTS (ce qu'on a détecté)
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Table: raw_events (tampon des événements bruts)
-- Conservés 7 jours pour investigation
-- ----------------------------------------------------------------------------
CREATE TABLE raw_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_uuid      TEXT    NOT NULL UNIQUE,
    source          TEXT    NOT NULL CHECK(source IN ('wazuh','snort','honeypot','custom')),
    signature_id    INTEGER,
    raw_data        TEXT    NOT NULL,                -- JSON brut
    src_ip          TEXT,
    dst_ip          TEXT,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        TEXT,
    received_at     TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    processed       INTEGER NOT NULL DEFAULT 0 CHECK(processed IN (0,1)),
    FOREIGN KEY (signature_id) REFERENCES signatures(id) ON DELETE SET NULL
);

CREATE INDEX idx_raw_events_received   ON raw_events(received_at);
CREATE INDEX idx_raw_events_source     ON raw_events(source);
CREATE INDEX idx_raw_events_processed  ON raw_events(processed);
CREATE INDEX idx_raw_events_src_ip     ON raw_events(src_ip);


-- ----------------------------------------------------------------------------
-- Table: alerts (LE CŒUR DU SYSTÈME)
-- Une alerte structurée = ce que l'admin voit
-- ----------------------------------------------------------------------------
CREATE TABLE alerts (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_uuid          TEXT    NOT NULL UNIQUE,
    signature_id        INTEGER NOT NULL,
    severity            TEXT    NOT NULL CHECK(severity IN ('INFO','LOW','MEDIUM','HIGH','CRITICAL')),
    confidence          INTEGER NOT NULL DEFAULT 70 CHECK(confidence BETWEEN 0 AND 100),
    title               TEXT    NOT NULL,
    description         TEXT,
    src_ip              TEXT,
    dst_ip              TEXT,
    src_port            INTEGER,
    dst_port            INTEGER,
    protocol            TEXT,
    asset_id            INTEGER,                    -- Machine ciblée
    event_count         INTEGER NOT NULL DEFAULT 1,  -- Corrélation
    first_seen          TEXT    NOT NULL,
    last_seen           TEXT    NOT NULL,
    -- Workflow
    status              TEXT    NOT NULL DEFAULT 'NEW'
                                CHECK(status IN ('NEW','ACKNOWLEDGED','INVESTIGATING','RESOLVED','FALSE_POSITIVE','IGNORED')),
    incident_id         INTEGER,
    assigned_to         INTEGER,                    -- user_id
    resolved_at         TEXT,
    resolution_notes    TEXT,
    -- Enrichissement
    enriched_data       TEXT,                       -- JSON : MITRE, geoloc, stats
    tags                TEXT,                       -- JSON array
    metadata            TEXT,                       -- JSON
    -- Enrichissement IA (signatures non répertoriées)
    ai_status           TEXT    NOT NULL DEFAULT 'not_required'
                                CHECK(ai_status IN ('not_required','pending','cached','fresh','failed','disabled')),
    ai_description      TEXT,                       -- Description générée par IA
    ai_remediation      TEXT,                       -- Recommandations IA (JSON array)
    ai_severity         TEXT,                       -- Sévérité estimée par IA
    ai_model_used       TEXT,                       -- 'qwen2.5:3b' ou 'llama3.2:3b'
    ai_processed_at     TEXT,                       -- Quand l'IA a répondu
    ai_cache_id         INTEGER,                    -- FK vers ai_signature_cache
    -- Timestamps
    created_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (signature_id)  REFERENCES signatures(id)  ON DELETE RESTRICT,
    FOREIGN KEY (asset_id)      REFERENCES assets(id)      ON DELETE SET NULL,
    FOREIGN KEY (incident_id)   REFERENCES incidents(id)   ON DELETE SET NULL,
    FOREIGN KEY (assigned_to)   REFERENCES users(id)       ON DELETE SET NULL,
    FOREIGN KEY (ai_cache_id)   REFERENCES ai_signature_cache(id) ON DELETE SET NULL
);

CREATE INDEX idx_alerts_uuid          ON alerts(alert_uuid);
CREATE INDEX idx_alerts_signature     ON alerts(signature_id);
CREATE INDEX idx_alerts_severity      ON alerts(severity);
CREATE INDEX idx_alerts_status        ON alerts(status);
CREATE INDEX idx_alerts_src_ip        ON alerts(src_ip);
CREATE INDEX idx_alerts_dst_ip        ON alerts(dst_ip);
CREATE INDEX idx_alerts_created_at    ON alerts(created_at DESC);
CREATE INDEX idx_alerts_assigned      ON alerts(assigned_to);
CREATE INDEX idx_alerts_incident      ON alerts(incident_id);
CREATE INDEX idx_alerts_event_count   ON alerts(event_count);
CREATE INDEX idx_alerts_ai_status     ON alerts(ai_status);
CREATE INDEX idx_alerts_ai_cache      ON alerts(ai_cache_id);


-- ----------------------------------------------------------------------------
-- Table: incidents (regroupement d'alertes liées)
-- ----------------------------------------------------------------------------
CREATE TABLE incidents (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_uuid   TEXT    NOT NULL UNIQUE,
    title           TEXT    NOT NULL,
    description     TEXT,
    severity        TEXT    NOT NULL CHECK(severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    status          TEXT    NOT NULL DEFAULT 'OPEN'
                            CHECK(status IN ('OPEN','INVESTIGATING','CONTAINED','RESOLVED','CLOSED')),
    assigned_to     INTEGER,
    alert_count     INTEGER NOT NULL DEFAULT 0,
    started_at      TEXT    NOT NULL,
    resolved_at     TEXT,
    resolution      TEXT,
    created_at      TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX idx_incidents_uuid     ON incidents(incident_uuid);
CREATE INDEX idx_incidents_status   ON incidents(status);
CREATE INDEX idx_incidents_assigned ON incidents(assigned_to);


-- ----------------------------------------------------------------------------
-- Table: assets (machines surveillées)
-- ----------------------------------------------------------------------------
CREATE TABLE assets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_uuid      TEXT    NOT NULL UNIQUE,
    hostname        TEXT    NOT NULL,
    ip_address      TEXT,
    os              TEXT,
    asset_type      TEXT    CHECK(asset_type IN ('SERVER','WORKSTATION','NETWORK','IOT','OTHER')),
    criticality     TEXT    NOT NULL DEFAULT 'MEDIUM'
                            CHECK(criticality IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    owner_email     TEXT,
    location        TEXT,
    country_id      INTEGER,                        -- ✅ NOUVEAU : lien pays
    tags            TEXT,                           -- JSON array
    is_active       INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)),
    created_at      TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (country_id) REFERENCES countries(id) ON DELETE SET NULL
);

CREATE INDEX idx_assets_hostname  ON assets(hostname);
CREATE INDEX idx_assets_ip        ON assets(ip_address);
CREATE INDEX idx_assets_country   ON assets(country_id);


-- ============================================================================
-- DOMAINE 3 : RÉPONSE AUX MENACES
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Table: alert_filters (gestion des faux positifs)
-- ----------------------------------------------------------------------------
CREATE TABLE alert_filters (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    filter_uuid         TEXT    NOT NULL UNIQUE,
    name                TEXT    NOT NULL,
    description         TEXT,
    -- Critères
    signature_id        INTEGER,                    -- NULL = toutes signatures
    src_ip              TEXT,                       -- NULL = toutes IPs
    dst_ip              TEXT,
    user_pattern        TEXT,                       -- regex sur usernames
    -- Action
    action              TEXT    NOT NULL DEFAULT 'IGNORE'
                                CHECK(action IN ('IGNORE','DOWNGRADE','NOTIFY_ONLY')),
    downgrade_to        TEXT    CHECK(downgrade_to IN ('INFO','LOW','MEDIUM','HIGH')),
    -- Origine
    filter_type         TEXT    NOT NULL DEFAULT 'MANUAL'
                                CHECK(filter_type IN ('MANUAL','AUTO_NOISE','SYSTEM')),
    created_by          INTEGER,                    -- user_id
    -- Stats
    hit_count           INTEGER NOT NULL DEFAULT 0,
    last_hit_at         TEXT,
    -- État
    is_active           INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)),
    expires_at          TEXT,
    created_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (signature_id) REFERENCES signatures(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by)   REFERENCES users(id)      ON DELETE SET NULL
);

CREATE INDEX idx_filters_active     ON alert_filters(is_active);
CREATE INDEX idx_filters_signature  ON alert_filters(signature_id);
CREATE INDEX idx_filters_src_ip     ON alert_filters(src_ip);
CREATE INDEX idx_filters_type       ON alert_filters(filter_type);


-- ----------------------------------------------------------------------------
-- Table: blocked_ips (IPs bannies)
-- ----------------------------------------------------------------------------
CREATE TABLE blocked_ips (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    block_uuid          TEXT    NOT NULL UNIQUE,
    ip_address          TEXT    NOT NULL,
    reason              TEXT    NOT NULL,
    block_type          TEXT    NOT NULL DEFAULT 'AUTO'
                                CHECK(block_type IN ('AUTO','MANUAL','PERMANENT')),
    blocked_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at          TEXT,                       -- NULL = permanent
    blocked_by          INTEGER,                    -- user_id (NULL si auto)
    alert_id            INTEGER,                    -- alerte déclencheuse
    is_active           INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)),
    unblock_at          TEXT,                       -- date de déblocage effectif
    unblocked_by        INTEGER,
    unblock_reason      TEXT,
    -- Stats
    hit_count           INTEGER NOT NULL DEFAULT 1,
    metadata            TEXT,                       -- JSON
    FOREIGN KEY (blocked_by)   REFERENCES users(id)  ON DELETE SET NULL,
    FOREIGN KEY (unblocked_by) REFERENCES users(id)  ON DELETE SET NULL,
    FOREIGN KEY (alert_id)     REFERENCES alerts(id) ON DELETE SET NULL
);

CREATE INDEX idx_blocked_ip_addr     ON blocked_ips(ip_address);
CREATE INDEX idx_blocked_active      ON blocked_ips(is_active);
CREATE INDEX idx_blocked_expires     ON blocked_ips(expires_at);


-- ----------------------------------------------------------------------------
-- Table: ai_explanations (cache des explications IA Ollama)
-- ----------------------------------------------------------------------------
CREATE TABLE ai_explanations (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    explanation_uuid    TEXT    NOT NULL UNIQUE,
    alert_id            INTEGER,
    signature_id        INTEGER,
    explanation_fr      TEXT,
    explanation_en      TEXT,
    -- Metadata IA
    ai_provider         TEXT    NOT NULL DEFAULT 'ollama',
    ai_model            TEXT    NOT NULL,           -- llama3.2:3b ou qwen2.5:3b
    prompt_used         TEXT,
    tokens_used         INTEGER,
    generation_time_ms  INTEGER,
    -- Cache stats
    is_cached           INTEGER NOT NULL DEFAULT 0 CHECK(is_cached IN (0,1)),
    cache_hits          INTEGER NOT NULL DEFAULT 0,
    last_used_at        TEXT,
    -- Quality
    user_rating         INTEGER CHECK(user_rating IS NULL OR user_rating BETWEEN 1 AND 5),
    user_feedback       TEXT,
    created_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (alert_id)     REFERENCES alerts(id)     ON DELETE CASCADE,
    FOREIGN KEY (signature_id) REFERENCES signatures(id) ON DELETE CASCADE
);

CREATE INDEX idx_ai_alert       ON ai_explanations(alert_id);
CREATE INDEX idx_ai_signature   ON ai_explanations(signature_id);
CREATE INDEX idx_ai_model       ON ai_explanations(ai_model);
CREATE INDEX idx_ai_cached      ON ai_explanations(is_cached);


-- ============================================================================
-- DOMAINE 4 : HONEYPOT & THREAT INTEL
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Table: honeypot_hits (tentatives sur les pièges)
-- ----------------------------------------------------------------------------
CREATE TABLE honeypot_hits (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    hit_uuid            TEXT    NOT NULL UNIQUE,
    honeypot_type       TEXT    NOT NULL CHECK(honeypot_type IN ('SSH','HTTP','MYSQL','FTP','OTHER')),
    honeypot_port       INTEGER NOT NULL,
    src_ip              TEXT    NOT NULL,
    src_port            INTEGER,
    -- Données capturées
    username_attempted  TEXT,
    password_attempted  TEXT,
    http_method         TEXT,
    http_path           TEXT,
    http_user_agent     TEXT,
    http_headers        TEXT,                       -- JSON
    payload             TEXT,
    -- Action prise
    blocked             INTEGER NOT NULL DEFAULT 0 CHECK(blocked IN (0,1)),
    block_id            INTEGER,                    -- FK vers blocked_ips
    alert_id            INTEGER,                    -- alerte créée si applicable
    hit_at              TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    metadata            TEXT,                       -- JSON
    FOREIGN KEY (block_id) REFERENCES blocked_ips(id) ON DELETE SET NULL,
    FOREIGN KEY (alert_id) REFERENCES alerts(id)      ON DELETE SET NULL
);

CREATE INDEX idx_honeypot_type  ON honeypot_hits(honeypot_type);
CREATE INDEX idx_honeypot_src   ON honeypot_hits(src_ip);
CREATE INDEX idx_honeypot_at    ON honeypot_hits(hit_at);


-- ----------------------------------------------------------------------------
-- Table: ip_reputation (réputation des IPs)
-- ----------------------------------------------------------------------------
CREATE TABLE ip_reputation (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address          TEXT    NOT NULL UNIQUE,
    reputation_score    INTEGER NOT NULL DEFAULT 50 CHECK(reputation_score BETWEEN 0 AND 100),
                                                    -- 0=malicieux, 100=trusted
    classification      TEXT    CHECK(classification IN ('MALICIOUS','SUSPICIOUS','UNKNOWN','BENIGN')),
    -- Géolocalisation
    country_code        TEXT,                       -- CM, GA, FR...
    country_name        TEXT,
    city                TEXT,
    asn                 INTEGER,
    asn_owner           TEXT,
    -- Stats locales
    first_seen_at       TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at        TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    total_alerts        INTEGER NOT NULL DEFAULT 0,
    total_honeypot_hits INTEGER NOT NULL DEFAULT 0,
    times_blocked       INTEGER NOT NULL DEFAULT 0,
    -- Threat intel externe (optionnel)
    abuseipdb_score     INTEGER,
    threat_intel_data   TEXT,                       -- JSON
    notes               TEXT,
    updated_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_iprep_addr      ON ip_reputation(ip_address);
CREATE INDEX idx_iprep_classif   ON ip_reputation(classification);
CREATE INDEX idx_iprep_score     ON ip_reputation(reputation_score);
CREATE INDEX idx_iprep_country   ON ip_reputation(country_code);


-- ----------------------------------------------------------------------------
-- Table: threat_intel (renseignement sur les menaces)
-- ----------------------------------------------------------------------------
CREATE TABLE threat_intel (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_uuid         TEXT    NOT NULL UNIQUE,
    title               TEXT    NOT NULL,
    description         TEXT,
    threat_type         TEXT    NOT NULL,           -- malware, apt, vuln...
    severity            TEXT    CHECK(severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    -- IOCs (Indicators Of Compromise)
    ioc_type            TEXT,                       -- ip, domain, hash, url
    ioc_value           TEXT,
    -- Metadata
    source              TEXT,                       -- d'où vient le renseignement
    cve_ids             TEXT,                       -- JSON array
    mitre_techniques    TEXT,                       -- JSON array : ["T1110", "T1078"]
    references_url      TEXT,
    is_active           INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)),
    expires_at          TEXT,
    created_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_threat_type    ON threat_intel(threat_type);
CREATE INDEX idx_threat_ioc     ON threat_intel(ioc_value);
CREATE INDEX idx_threat_active  ON threat_intel(is_active);


-- ============================================================================
-- DOMAINE 5 : WORKFLOW (RBAC, sessions, notifications)
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Table: roles (4 rôles RBAC : ADMIN, ANALYST, OPERATOR, VIEWER)
-- ----------------------------------------------------------------------------
CREATE TABLE roles (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    code            TEXT    NOT NULL UNIQUE,        -- ADMIN, ANALYST...
    name            TEXT    NOT NULL,
    description     TEXT,
    description_fr  TEXT,
    permissions     TEXT    NOT NULL,                -- JSON array de permissions
    is_system       INTEGER NOT NULL DEFAULT 0 CHECK(is_system IN (0,1)),
    created_at      TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_roles_code ON roles(code);


-- ----------------------------------------------------------------------------
-- Table: users (admins du dashboard)
-- ✅ Schéma cohérent avec dashboard (must_change_pwd, is_locked, argon2id)
-- ----------------------------------------------------------------------------
CREATE TABLE users (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    user_uuid           TEXT    NOT NULL UNIQUE,
    email               TEXT    NOT NULL UNIQUE,
    first_name          TEXT,
    last_name           TEXT,
    phone               TEXT,
    -- Auth
    password_hash       TEXT    NOT NULL,            -- argon2id obligatoire
    password_changed_at TEXT,
    must_change_pwd     INTEGER NOT NULL DEFAULT 1 CHECK(must_change_pwd IN (0,1)),
    is_active           INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)),
    is_locked           INTEGER NOT NULL DEFAULT 0 CHECK(is_locked IN (0,1)),
    failed_login_count  INTEGER NOT NULL DEFAULT 0,
    locked_until        TEXT,
    -- Profil
    role_id             INTEGER NOT NULL,
    organization        TEXT,
    department          TEXT,
    country_id          INTEGER,                    -- ✅ NOUVEAU : pays admin
    -- Préférences
    language            TEXT    NOT NULL DEFAULT 'fr' CHECK(language IN ('fr','en')),
    timezone            TEXT    NOT NULL DEFAULT 'Africa/Douala',
    theme_preference    TEXT    NOT NULL DEFAULT 'light' CHECK(theme_preference IN ('dark','light','auto')),
    -- Tracking
    last_login_at       TEXT,
    last_login_ip       TEXT,
    metadata            TEXT,                       -- JSON
    -- Timestamps
    created_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at          TEXT,
    FOREIGN KEY (role_id)    REFERENCES roles(id)     ON DELETE RESTRICT,
    FOREIGN KEY (country_id) REFERENCES countries(id) ON DELETE SET NULL
);

CREATE INDEX idx_users_uuid       ON users(user_uuid);
CREATE INDEX idx_users_email      ON users(email);
CREATE INDEX idx_users_role       ON users(role_id);
CREATE INDEX idx_users_country    ON users(country_id);
CREATE INDEX idx_users_is_active  ON users(is_active);


-- ----------------------------------------------------------------------------
-- Table: user_sessions (sessions actives)
-- ----------------------------------------------------------------------------
CREATE TABLE user_sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_token   TEXT    NOT NULL UNIQUE,
    user_id         INTEGER NOT NULL,
    ip_address      TEXT,
    user_agent      TEXT,
    created_at      TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at      TEXT    NOT NULL,
    last_activity   TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_active       INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_sessions_token   ON user_sessions(session_token);
CREATE INDEX idx_sessions_user    ON user_sessions(user_id);
CREATE INDEX idx_sessions_expires ON user_sessions(expires_at);


-- ----------------------------------------------------------------------------
-- Table: notifications (notifs dashboard)
-- ----------------------------------------------------------------------------
CREATE TABLE notifications (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER,                        -- NULL = broadcast
    notif_type      TEXT    NOT NULL CHECK(notif_type IN ('INFO','SUCCESS','WARNING','ERROR','ALERT')),
    title           TEXT    NOT NULL,
    message         TEXT    NOT NULL,
    link            TEXT,
    is_read         INTEGER NOT NULL DEFAULT 0 CHECK(is_read IN (0,1)),
    read_at         TEXT,
    created_at      TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at      TEXT,
    metadata        TEXT,                           -- JSON
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_notif_user     ON notifications(user_id);
CREATE INDEX idx_notif_read     ON notifications(is_read);
CREATE INDEX idx_notif_created  ON notifications(created_at DESC);


-- ============================================================================
-- DOMAINE 6 : AUDIT & CONFIG
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Table: audit_log (TOUTES les actions importantes)
-- Crucial pour conformité RGPD, ISO 27001, loi cyber Cameroun 2010
-- ----------------------------------------------------------------------------
CREATE TABLE audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER,                        -- NULL pour actions agent
    user_email      TEXT,                           -- copie pour si user supprimé
    action          TEXT    NOT NULL,                -- ALERT_RESOLVED, USER_CREATED...
    action_category TEXT    NOT NULL CHECK(action_category IN
                            ('AUTH','ALERT','USER','FILTER','BLOCK','AI','CONFIG','REPORT','SYSTEM')),
    target_table    TEXT,                           -- table affectée
    target_id       INTEGER,                        -- ID de la ligne affectée
    target_uuid     TEXT,                           -- UUID si applicable
    details         TEXT,                           -- JSON ou texte
    ip_address      TEXT,                           -- IP du client web
    user_agent      TEXT,
    status          TEXT    NOT NULL DEFAULT 'SUCCESS' CHECK(status IN ('SUCCESS','FAILURE')),
    error_message   TEXT,
    performed_at    TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX idx_audit_user      ON audit_log(user_id);
CREATE INDEX idx_audit_action    ON audit_log(action);
CREATE INDEX idx_audit_category  ON audit_log(action_category);
CREATE INDEX idx_audit_target    ON audit_log(target_table, target_id);
CREATE INDEX idx_audit_when      ON audit_log(performed_at DESC);


-- ----------------------------------------------------------------------------
-- Table: email_logs (tracking des emails envoyés)
-- ----------------------------------------------------------------------------
CREATE TABLE email_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email_uuid      TEXT    NOT NULL UNIQUE,
    recipient       TEXT    NOT NULL,
    cc              TEXT,
    subject         TEXT    NOT NULL,
    body_preview    TEXT,                           -- 200 premiers caractères
    template_used   TEXT,                           -- alert, weekly_report...
    -- Tracking
    related_alert_id    INTEGER,
    related_incident_id INTEGER,
    -- Statut
    status          TEXT    NOT NULL DEFAULT 'PENDING'
                            CHECK(status IN ('PENDING','SENT','FAILED','BOUNCED')),
    error_message   TEXT,
    smtp_response   TEXT,
    -- Timestamps
    queued_at       TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    sent_at         TEXT,
    retry_count     INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (related_alert_id)    REFERENCES alerts(id)    ON DELETE SET NULL,
    FOREIGN KEY (related_incident_id) REFERENCES incidents(id) ON DELETE SET NULL
);

CREATE INDEX idx_email_status     ON email_logs(status);
CREATE INDEX idx_email_recipient  ON email_logs(recipient);
CREATE INDEX idx_email_alert      ON email_logs(related_alert_id);


-- ----------------------------------------------------------------------------
-- Table: settings (configuration dynamique)
-- Modifiable depuis le dashboard sans redémarrage
-- ----------------------------------------------------------------------------
CREATE TABLE settings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    key             TEXT    NOT NULL UNIQUE,
    value           TEXT,
    value_type      TEXT    NOT NULL DEFAULT 'text'
                            CHECK(value_type IN ('text','int','bool','secret','json','enum')),
    enum_values     TEXT,                           -- JSON array si value_type=enum
    category        TEXT    NOT NULL,                -- smtp, ai, ui, correlation...
    description     TEXT,
    description_fr  TEXT,
    is_sensitive    INTEGER NOT NULL DEFAULT 0 CHECK(is_sensitive IN (0,1)),
    is_editable     INTEGER NOT NULL DEFAULT 1 CHECK(is_editable IN (0,1)),
    updated_by      INTEGER,
    created_at      TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at      TEXT,
    FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX idx_settings_key       ON settings(key);
CREATE INDEX idx_settings_category  ON settings(category);
CREATE INDEX idx_settings_deleted   ON settings(deleted_at);


-- ----------------------------------------------------------------------------
-- Table: reports (rapports générés)
-- ----------------------------------------------------------------------------
CREATE TABLE reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    report_uuid     TEXT    NOT NULL UNIQUE,
    title           TEXT    NOT NULL,
    report_type     TEXT    NOT NULL CHECK(report_type IN ('DAILY','WEEKLY','MONTHLY','CUSTOM','INCIDENT')),
    format          TEXT    NOT NULL CHECK(format IN ('PDF','CSV','HTML','JSON')),
    -- Plage de données
    period_start    TEXT,
    period_end      TEXT,
    -- Stockage
    file_path       TEXT,
    file_size_bytes INTEGER,
    -- Génération
    generated_by    INTEGER,
    generation_status TEXT  NOT NULL DEFAULT 'PENDING'
                            CHECK(generation_status IN ('PENDING','GENERATING','COMPLETED','FAILED')),
    error_message   TEXT,
    metadata        TEXT,                           -- JSON
    created_at      TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at    TEXT,
    FOREIGN KEY (generated_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX idx_reports_type     ON reports(report_type);
CREATE INDEX idx_reports_status   ON reports(generation_status);
CREATE INDEX idx_reports_created  ON reports(created_at DESC);


-- ============================================================================
-- ✅ DOMAINE 7 (NOUVEAU) : MARCHÉ CIBLE & KPI
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Table: countries (4 pays Afrique Centrale)
-- ✅ NOUVEAU : pour la demande de l'encadreur sur les "4 pays"
-- ----------------------------------------------------------------------------
CREATE TABLE countries (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    code_iso2           TEXT    NOT NULL UNIQUE,    -- CM, GA, CG, CD
    code_iso3           TEXT    UNIQUE,              -- CMR, GAB, COG, COD
    name_fr             TEXT    NOT NULL,            -- "Cameroun"
    name_en             TEXT,                        -- "Cameroon"
    capital             TEXT,                        -- "Yaoundé"
    region              TEXT,                        -- "Afrique Centrale"
    sub_region          TEXT,                        -- "CEMAC", "CEEAC"
    -- Démographie
    population          INTEGER,                     -- 28 millions
    population_year     INTEGER,                     -- 2024
    gdp_usd_billion     REAL,                        -- 47.0
    -- Tech
    internet_penetration_pct REAL,                   -- 35.2
    -- Cyber
    cyber_authority     TEXT,                        -- "ANTIC", "ANINF"
    cyber_law_year      INTEGER,                     -- 2010
    -- Stats
    cyberattack_increase_pct REAL,                   -- 156.0
    cyberattack_loss_million_usd REAL,               -- 45.0
    -- Misc
    timezone            TEXT,                        -- "Africa/Douala"
    flag_emoji          TEXT,                        -- 🇨🇲
    is_active           INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)),
    display_order       INTEGER NOT NULL DEFAULT 0,
    created_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_countries_code     ON countries(code_iso2);
CREATE INDEX idx_countries_active   ON countries(is_active);
CREATE INDEX idx_countries_order    ON countries(display_order);


-- ----------------------------------------------------------------------------
-- Table: kpi_history (snapshots quotidiens des KPI)
-- ✅ NOUVEAU : pour la page KPI demandée par l'encadreur
-- ----------------------------------------------------------------------------
CREATE TABLE kpi_history (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_date       TEXT    NOT NULL,           -- YYYY-MM-DD
    snapshot_hour       INTEGER,                     -- 0-23 (NULL = daily)
    -- KPI principaux
    metric_name         TEXT    NOT NULL,           -- alerts_total, vulnerabilities, etc.
    metric_value        REAL,
    metric_unit         TEXT,                        -- count, ratio, ms, %
    -- Decomposition
    severity_filter     TEXT,                        -- INFO/LOW/MEDIUM/HIGH/CRITICAL ou NULL
    category_filter     TEXT,                        -- AUTH, WEB, MALWARE...
    country_id          INTEGER,                     -- pour stats par pays
    -- Méta
    metric_meta         TEXT,                        -- JSON pour détails
    created_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (country_id) REFERENCES countries(id) ON DELETE SET NULL
);

CREATE INDEX idx_kpi_date       ON kpi_history(snapshot_date);
CREATE INDEX idx_kpi_metric     ON kpi_history(metric_name);
CREATE INDEX idx_kpi_country    ON kpi_history(country_id);
CREATE INDEX idx_kpi_date_metric ON kpi_history(snapshot_date, metric_name);


-- ============================================================================
-- ENRICHISSEMENT IA - Cache des analyses pour signatures non répertoriées
-- ============================================================================
--
-- Quand une alerte arrive avec un rule_id (Wazuh) ou SID (Snort) qui n'est
-- PAS dans la table signatures, l'agent envoie l'alerte à Ollama pour
-- enrichissement (description + remédiation). Le résultat est mis en cache
-- ici pour éviter de re-payer le coût IA pour la même signature.
--
-- Workflow :
--  1. Agent reçoit alerte → cherche dans signatures
--  2. Pas trouvée → calcule signature_hash (SHA256 source+rule_id+raw_message)
--  3. Cherche dans ai_signature_cache via signature_hash
--  4. Trouvée → réutilise (used_count++)
--  5. Pas trouvée → appelle Ollama → sauvegarde ici → utilise
--
-- ============================================================================
CREATE TABLE ai_signature_cache (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    signature_hash      TEXT    NOT NULL UNIQUE,        -- SHA256 unique
    source              TEXT    NOT NULL CHECK(source IN ('wazuh','snort','agent')),
    rule_id             TEXT    NOT NULL,               -- ex: '5710' ou '1000999'
    raw_message         TEXT,                           -- Message brut original
    -- Réponse IA
    ai_description      TEXT    NOT NULL,               -- Description en français
    ai_remediation      TEXT    NOT NULL,               -- JSON array de recommandations
    ai_severity         TEXT    NOT NULL
                                CHECK(ai_severity IN ('INFO','LOW','MEDIUM','HIGH','CRITICAL')),
    ai_mitre_tactic     TEXT,                           -- Si l'IA a déduit un MITRE
    ai_mitre_technique  TEXT,                           -- Idem
    -- Métadonnées du modèle
    model_used          TEXT    NOT NULL,               -- 'qwen2.5:3b' / 'llama3.2:3b'
    prompt_version      TEXT    NOT NULL DEFAULT 'v1',  -- Pour invalider si on change le prompt
    response_time_ms    INTEGER,                        -- Latence Ollama
    -- Validation humaine (apprentissage progressif)
    is_validated        INTEGER NOT NULL DEFAULT 0 CHECK(is_validated IN (0,1)),
    validated_by        INTEGER,                        -- user_id
    validated_at        TEXT,
    -- Statistiques d'usage
    used_count          INTEGER NOT NULL DEFAULT 1,
    last_used_at        TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Timestamps
    created_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (validated_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX idx_aicache_hash      ON ai_signature_cache(signature_hash);
CREATE INDEX idx_aicache_source    ON ai_signature_cache(source);
CREATE INDEX idx_aicache_ruleid    ON ai_signature_cache(rule_id);
CREATE INDEX idx_aicache_model     ON ai_signature_cache(model_used);
CREATE INDEX idx_aicache_validated ON ai_signature_cache(is_validated);
CREATE INDEX idx_aicache_used      ON ai_signature_cache(used_count DESC);
CREATE INDEX idx_aicache_lastused  ON ai_signature_cache(last_used_at DESC);


-- ============================================================================
-- TRIGGERS (logique métier automatique)
-- ============================================================================

-- 1. Mettre à jour updated_at sur alerts
CREATE TRIGGER trg_alerts_updated_at
AFTER UPDATE ON alerts
FOR EACH ROW
BEGIN
    UPDATE alerts SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- 2. Mettre à jour updated_at sur users
CREATE TRIGGER trg_users_updated_at
AFTER UPDATE ON users
FOR EACH ROW
BEGIN
    UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- 3. Mettre à jour updated_at sur signatures
CREATE TRIGGER trg_signatures_updated_at
AFTER UPDATE ON signatures
FOR EACH ROW
BEGIN
    UPDATE signatures SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- 4. Mettre à jour updated_at sur settings
CREATE TRIGGER trg_settings_updated_at
AFTER UPDATE ON settings
FOR EACH ROW
BEGIN
    UPDATE settings SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- Mettre à jour updated_at sur ai_signature_cache
CREATE TRIGGER trg_aicache_updated_at
AFTER UPDATE ON ai_signature_cache
FOR EACH ROW
BEGIN
    UPDATE ai_signature_cache SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- Incrémenter used_count + last_used_at automatiquement quand le cache est lié à une alerte
CREATE TRIGGER trg_aicache_increment_usage
AFTER UPDATE OF ai_cache_id ON alerts
FOR EACH ROW
WHEN NEW.ai_cache_id IS NOT NULL AND (OLD.ai_cache_id IS NULL OR OLD.ai_cache_id != NEW.ai_cache_id)
BEGIN
    UPDATE ai_signature_cache
    SET used_count    = used_count + 1,
        last_used_at  = CURRENT_TIMESTAMP
    WHERE id = NEW.ai_cache_id;
END;

-- 5. APPRENTISSAGE : faux positif → confidence -5 sur la signature
CREATE TRIGGER trg_fp_decrease_confidence
AFTER UPDATE OF status ON alerts
FOR EACH ROW
WHEN NEW.status = 'FALSE_POSITIVE' AND OLD.status != 'FALSE_POSITIVE'
BEGIN
    UPDATE signatures
    SET confidence = MAX(0, confidence - 5)
    WHERE id = NEW.signature_id;
END;

-- 6. APPRENTISSAGE : alerte résolue → confidence +1
CREATE TRIGGER trg_resolved_increase_confidence
AFTER UPDATE OF status ON alerts
FOR EACH ROW
WHEN NEW.status = 'RESOLVED' AND OLD.status != 'RESOLVED'
BEGIN
    UPDATE signatures
    SET confidence = MIN(100, confidence + 1)
    WHERE id = NEW.signature_id;
END;

-- 7. ip_reputation : auto-update au blocage d'IP
CREATE TRIGGER trg_blocked_ip_reputation
AFTER INSERT ON blocked_ips
FOR EACH ROW
BEGIN
    INSERT OR REPLACE INTO ip_reputation (
        ip_address, reputation_score, classification,
        times_blocked, last_seen_at, updated_at
    ) VALUES (
        NEW.ip_address,
        MAX(0, COALESCE((SELECT reputation_score FROM ip_reputation WHERE ip_address = NEW.ip_address), 50) - 20),
        'MALICIOUS',
        COALESCE((SELECT times_blocked FROM ip_reputation WHERE ip_address = NEW.ip_address), 0) + 1,
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP
    );
END;

-- 8. ip_reputation : auto-update sur honeypot hit
CREATE TRIGGER trg_honeypot_ip_reputation
AFTER INSERT ON honeypot_hits
FOR EACH ROW
BEGIN
    INSERT OR REPLACE INTO ip_reputation (
        ip_address, reputation_score, classification,
        total_honeypot_hits, last_seen_at, updated_at
    ) VALUES (
        NEW.src_ip,
        MAX(0, COALESCE((SELECT reputation_score FROM ip_reputation WHERE ip_address = NEW.src_ip), 50) - 30),
        'MALICIOUS',
        COALESCE((SELECT total_honeypot_hits FROM ip_reputation WHERE ip_address = NEW.src_ip), 0) + 1,
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP
    );
END;

-- 9. Compter les alertes liées à un incident
CREATE TRIGGER trg_incident_alert_count
AFTER UPDATE OF incident_id ON alerts
FOR EACH ROW
WHEN NEW.incident_id IS NOT NULL
BEGIN
    UPDATE incidents
    SET alert_count = (SELECT COUNT(*) FROM alerts WHERE incident_id = NEW.incident_id),
        updated_at = CURRENT_TIMESTAMP
    WHERE id = NEW.incident_id;
END;


-- ============================================================================
-- VUES (raccourcis pour le dashboard)
-- ============================================================================

-- Vue 1 : alertes enrichies avec MITRE et catégorie
CREATE VIEW v_alerts_enriched AS
SELECT
    a.id,
    a.alert_uuid,
    a.severity,
    a.confidence,
    a.title,
    a.description,
    a.src_ip,
    a.dst_ip,
    a.event_count,
    a.status,
    a.first_seen,
    a.last_seen,
    a.created_at,
    a.assigned_to,
    -- Signature
    s.name             AS sig_name,
    s.source           AS sig_source,
    s.description_fr   AS sig_desc_fr,
    s.is_noisy         AS sig_is_noisy,
    -- Catégorie
    sc.code            AS category_code,
    sc.name            AS category_name,
    sc.color_hex       AS category_color,
    sc.icon            AS category_icon,
    -- MITRE
    mt.technique_id    AS mitre_technique_id,
    mt.name            AS mitre_technique_name,
    mta.tactic_id      AS mitre_tactic_id,
    mta.name           AS mitre_tactic_name
FROM alerts a
JOIN signatures s ON a.signature_id = s.id
LEFT JOIN signature_categories sc ON s.category_id = sc.id
LEFT JOIN mitre_techniques mt ON s.technique_id = mt.id
LEFT JOIN mitre_tactics mta ON mt.tactic_id = mta.id;


-- Vue 2 : métriques pour le dashboard home
CREATE VIEW v_dashboard_metrics AS
SELECT
    -- Alertes
    (SELECT COUNT(*) FROM alerts WHERE status NOT IN ('RESOLVED','FALSE_POSITIVE','IGNORED')) AS active_alerts,
    (SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL' AND status NOT IN ('RESOLVED','FALSE_POSITIVE','IGNORED')) AS critical_open,
    (SELECT COUNT(*) FROM alerts WHERE created_at >= datetime('now', '-24 hours')) AS alerts_24h,
    (SELECT COUNT(*) FROM alerts WHERE created_at >= datetime('now', '-7 days')) AS alerts_7d,
    -- IPs bloquées
    (SELECT COUNT(*) FROM blocked_ips WHERE is_active = 1) AS blocked_ips,
    -- Honeypot
    (SELECT COUNT(*) FROM honeypot_hits WHERE hit_at >= datetime('now', '-24 hours')) AS honeypot_24h,
    -- Users
    (SELECT COUNT(*) FROM users WHERE is_active = 1 AND deleted_at IS NULL) AS active_users;


-- Vue 3 : top attaquants de la semaine
CREATE VIEW v_top_attackers_week AS
SELECT
    a.src_ip,
    COUNT(*)            AS nb_alerts,
    MAX(a.severity)     AS max_severity,
    MIN(a.first_seen)   AS first_seen,
    MAX(a.last_seen)    AS last_seen,
    SUM(a.event_count)  AS total_events,
    ir.country_code,
    ir.classification,
    ir.reputation_score,
    EXISTS(SELECT 1 FROM blocked_ips bi WHERE bi.ip_address = a.src_ip AND bi.is_active = 1) AS is_blocked
FROM alerts a
LEFT JOIN ip_reputation ir ON a.src_ip = ir.ip_address
WHERE a.created_at >= datetime('now', '-7 days')
  AND a.src_ip IS NOT NULL
GROUP BY a.src_ip
ORDER BY nb_alerts DESC, max_severity DESC
LIMIT 50;


-- Vue 4 : KPI summary (✅ NOUVEAU)
CREATE VIEW v_kpi_summary AS
SELECT
    -- Volume d'alertes
    (SELECT COUNT(*) FROM alerts) AS total_alerts_all_time,
    (SELECT COUNT(*) FROM alerts WHERE created_at >= datetime('now', '-24 hours')) AS alerts_24h,
    (SELECT COUNT(*) FROM alerts WHERE created_at >= datetime('now', '-7 days')) AS alerts_7d,
    (SELECT COUNT(*) FROM alerts WHERE created_at >= datetime('now', '-30 days')) AS alerts_30d,
    -- Sévérité
    (SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL' AND created_at >= datetime('now', '-30 days')) AS critical_30d,
    (SELECT COUNT(*) FROM alerts WHERE severity = 'HIGH' AND created_at >= datetime('now', '-30 days')) AS high_30d,
    -- Vulnérabilités (signatures avec CVE)
    (SELECT COUNT(*) FROM signatures WHERE cve_ids IS NOT NULL AND cve_ids != '[]') AS total_vulnerabilities,
    (SELECT COUNT(DISTINCT a.signature_id) FROM alerts a JOIN signatures s ON a.signature_id = s.id
     WHERE s.cve_ids IS NOT NULL AND s.cve_ids != '[]'
       AND a.created_at >= datetime('now', '-30 days')) AS vulnerabilities_detected_30d,
    -- Performance équipe
    (SELECT COUNT(*) FROM alerts WHERE status = 'RESOLVED' AND resolved_at >= datetime('now', '-30 days')) AS resolved_30d,
    (SELECT AVG(julianday(resolved_at) - julianday(created_at)) * 24
     FROM alerts WHERE resolved_at IS NOT NULL AND resolved_at >= datetime('now', '-30 days')) AS avg_resolution_hours,
    -- Faux positifs
    (SELECT COUNT(*) FROM alerts WHERE status = 'FALSE_POSITIVE' AND created_at >= datetime('now', '-30 days')) AS false_positives_30d,
    -- Active Response
    (SELECT COUNT(*) FROM blocked_ips WHERE blocked_at >= datetime('now', '-30 days')) AS ips_blocked_30d,
    (SELECT COUNT(*) FROM honeypot_hits WHERE hit_at >= datetime('now', '-30 days')) AS honeypot_hits_30d,
    -- IA
    (SELECT COUNT(*) FROM ai_explanations WHERE created_at >= datetime('now', '-30 days')) AS ai_explanations_30d,
    (SELECT AVG(generation_time_ms) FROM ai_explanations WHERE created_at >= datetime('now', '-7 days')) AS avg_ai_response_ms;


-- ============================================================================
-- FIN DU SCHÉMA
-- ============================================================================
-- Total : 24 tables, 4 vues, 9 triggers, 88+ index
-- Compatible Ubuntu 22.04 + 24.04
-- ============================================================================
