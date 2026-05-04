-- ============================================================================
-- SIEM AFRICA - Marché cible : 4 pays d'Afrique Centrale
-- ============================================================================
-- Source des données : Banque Mondiale 2023, ITU 2023, rapports cyber locaux
-- Pays choisis : Cameroun, Gabon, Congo Brazzaville, RDC
-- Cadre régional : CEMAC + CEEAC, programme UE SDBA
-- ============================================================================

INSERT INTO countries (
    code_iso2, code_iso3, name_fr, name_en, capital, region, sub_region,
    population, population_year, gdp_usd_billion, internet_penetration_pct,
    cyber_authority, cyber_law_year,
    cyberattack_increase_pct, cyberattack_loss_million_usd,
    timezone, flag_emoji, display_order
) VALUES
-- 🇨🇲 CAMEROUN (le pays principal de l'équipe)
('CM', 'CMR', 'Cameroun', 'Cameroon', 'Yaoundé',
    'Afrique Centrale', 'CEMAC',
    28000000, 2024, 47.0, 35.2,
    'ANTIC', 2010,
    156.0, 45.0,
    'Africa/Douala', '🇨🇲', 1),

-- 🇬🇦 GABON
('GA', 'GAB', 'Gabon', 'Gabon', 'Libreville',
    'Afrique Centrale', 'CEMAC',
    2400000, 2024, 21.0, 60.0,
    'ANINF', 2023,
    NULL, NULL,
    'Africa/Libreville', '🇬🇦', 2),

-- 🇨🇬 CONGO BRAZZAVILLE
('CG', 'COG', 'Congo (Brazzaville)', 'Republic of the Congo', 'Brazzaville',
    'Afrique Centrale', 'CEMAC',
    6000000, 2024, 14.0, 22.0,
    'ANSSI', 2019,
    NULL, NULL,
    'Africa/Brazzaville', '🇨🇬', 3),

-- 🇨🇩 RÉPUBLIQUE DÉMOCRATIQUE DU CONGO
('CD', 'COD', 'République Démocratique du Congo', 'Democratic Republic of Congo', 'Kinshasa',
    'Afrique Centrale', 'CEEAC',
    102000000, 2024, 65.0, 22.0,
    'ANSI-RDC', 2019,
    NULL, NULL,
    'Africa/Kinshasa', '🇨🇩', 4);
