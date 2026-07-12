-- Migration: add whois_cache table
-- Run: sqlite3 /opt/ks/koneksaun-saudavel/db/koneksaun.db < deploy/migrate_add_whois_cache.sql

CREATE TABLE IF NOT EXISTS whois_cache (
    domain TEXT PRIMARY KEY,
    response_json TEXT NOT NULL,
    cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_whois_cache_expires ON whois_cache(expires_at);

-- NOTE: WHOIS API key is stored ENCRYPTED in settings table under key='whois_api_key_enc'
-- (not plaintext). If you used a plaintext key before, re-save it from the admin dashboard
-- after pulling this update. The old 'whois_api_key' entry is no longer read.
