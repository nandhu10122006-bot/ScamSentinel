-- CyberSentry sample data
-- Use only for development and testing.

INSERT INTO threat_indicators
    (indicator_type, indicator_value, source, is_active)
VALUES
    ('test_domain', 'example.com',
     'Reserved example domain', TRUE),
    ('test_domain', 'example.org',
     'Reserved example domain', TRUE)
ON CONFLICT (indicator_type, indicator_value) DO NOTHING;

INSERT INTO scan_history
    (original_url, normalized_url, classification,
     risk_score, explanation)
VALUES
    ('https://example.com',
     'https://example.com',
     'SAFE_INDICATORS',
     0,
     'Reserved example URL for database testing');