-- =====================================================================
-- Cloudflare D1 Schema — Privacy-Minimal Community VPN Verification
-- Zero credentials, zero raw URIs, zero browsing history, zero GPS/IP storage.
-- =====================================================================

CREATE TABLE IF NOT EXISTS community_reports (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id           TEXT NOT NULL UNIQUE,
    server_id           TEXT NOT NULL,
    config_fingerprint  TEXT NOT NULL,
    protocol            TEXT NOT NULL,
    reporter_id_hash    TEXT NOT NULL,
    bucket_6h           INTEGER NOT NULL,
    tested_at_epoch     INTEGER NOT NULL,
    received_at_epoch   INTEGER NOT NULL,
    success             INTEGER NOT NULL DEFAULT 0,
    handshake_ms        INTEGER NOT NULL DEFAULT 0,
    latency_ms          INTEGER NOT NULL DEFAULT 0,
    download_kbps       REAL NOT NULL DEFAULT 0.0,
    stability_score     REAL NOT NULL DEFAULT 0.0,
    dns_ok              INTEGER NOT NULL DEFAULT 0,
    tcp_ok              INTEGER NOT NULL DEFAULT 0,
    udp_ok              INTEGER NOT NULL DEFAULT 0,
    failure_reason      TEXT NOT NULL DEFAULT '',
    verified_country    TEXT NOT NULL,
    country_confidence  TEXT NOT NULL,
    vpn_interference    INTEGER NOT NULL DEFAULT 0,
    network_transport   TEXT NOT NULL DEFAULT 'UNKNOWN',
    asn_bucket          INTEGER NOT NULL DEFAULT 0,
    UNIQUE(config_fingerprint, reporter_id_hash, bucket_6h)
);

CREATE INDEX IF NOT EXISTS idx_comm_country_time
    ON community_reports(verified_country, received_at_epoch DESC);

CREATE INDEX IF NOT EXISTS idx_comm_export_cursor
    ON community_reports(id ASC);

CREATE TABLE IF NOT EXISTS rate_limits (
    bucket_key   TEXT PRIMARY KEY,
    window_epoch INTEGER NOT NULL,
    hit_count    INTEGER NOT NULL DEFAULT 0
);
