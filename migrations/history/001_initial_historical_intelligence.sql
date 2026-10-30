-- 001_initial_historical_intelligence.sql
-- Historical Server Intelligence Time-Series & Rollup Schema (v1)
-- Privacy & Security Guarantee: NEVER stores plaintext passwords, UUIDs, private keys, or unmasked exit IPs.

CREATE TABLE IF NOT EXISTS servers (
    server_id                TEXT PRIMARY KEY CHECK (length(server_id) >= 6),
    canonical_key_sha256     TEXT NOT NULL UNIQUE,
    protocol                 TEXT NOT NULL,
    masked_endpoint          TEXT NOT NULL,
    port                     INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    subnet_key               TEXT NOT NULL,
    first_seen               TEXT NOT NULL,
    last_seen                TEXT NOT NULL,
    last_verified            TEXT NOT NULL DEFAULT '',
    current_status           TEXT NOT NULL DEFAULT 'DISCOVERED'
                             CHECK (current_status IN ('DISCOVERED', 'OPERATIONAL', 'UNSTABLE', 'FAILED', 'SUPPRESSED', 'QUARANTINED', 'RETIRED')),
    uptime_percentage        REAL,
    uptime_kind              TEXT NOT NULL DEFAULT 'UNKNOWN'
                             CHECK (uptime_kind IN ('OBSERVED', 'ESTIMATED', 'UNKNOWN')),
    total_test_count         INTEGER NOT NULL DEFAULT 0,
    successful_test_count    INTEGER NOT NULL DEFAULT 0,
    failed_test_count        INTEGER NOT NULL DEFAULT 0,
    failure_count            INTEGER NOT NULL DEFAULT 0,
    failure_reasons_json     TEXT NOT NULL DEFAULT '{}',
    average_recovery_time    REAL,
    average_latency          REAL,
    median_latency           REAL,
    p95_latency              REAL,
    jitter                   REAL,
    packet_loss              REAL,
    download_speed           REAL,
    upload_speed             REAL,
    measurement_timestamp    TEXT NOT NULL DEFAULT '',
    source_count             INTEGER NOT NULL DEFAULT 0,
    independent_source_count INTEGER NOT NULL DEFAULT 0,
    first_source_seen        TEXT NOT NULL DEFAULT '',
    last_source_seen         TEXT NOT NULL DEFAULT '',
    detected_country         TEXT NOT NULL DEFAULT 'XX',
    country_confidence       TEXT NOT NULL DEFAULT 'unknown',
    last_failure             TEXT NOT NULL DEFAULT '',
    last_success             TEXT NOT NULL DEFAULT '',
    consecutive_failures     INTEGER NOT NULL DEFAULT 0,
    failed_since_epoch       INTEGER,
    historical_availability  REAL,
    latest_composite_score   REAL NOT NULL DEFAULT 0.0,
    latest_performance_score REAL NOT NULL DEFAULT 0.0,
    latest_reliability_score REAL NOT NULL DEFAULT 0.0,
    security_assessment      TEXT NOT NULL DEFAULT 'Unknown',
    privacy_assessment       TEXT NOT NULL DEFAULT 'Unverified',
    risk_level               TEXT NOT NULL DEFAULT 'UNKNOWN'
);

CREATE INDEX IF NOT EXISTS idx_servers_status ON servers(current_status);
CREATE INDEX IF NOT EXISTS idx_servers_protocol ON servers(protocol);
CREATE INDEX IF NOT EXISTS idx_servers_country ON servers(detected_country);
CREATE INDEX IF NOT EXISTS idx_servers_last_seen ON servers(last_seen);
CREATE INDEX IF NOT EXISTS idx_servers_score ON servers(latest_composite_score DESC);

CREATE TABLE IF NOT EXISTS server_identity_migrations (
    legacy_id    TEXT PRIMARY KEY,
    server_id    TEXT NOT NULL REFERENCES servers(server_id) ON DELETE CASCADE,
    reason       TEXT NOT NULL DEFAULT 'canonical_v2_upgrade',
    migrated_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_identity_migrations_target ON server_identity_migrations(server_id);

CREATE TABLE IF NOT EXISTS server_measurements (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id          TEXT NOT NULL REFERENCES servers(server_id) ON DELETE CASCADE,
    measured_at        TEXT NOT NULL,
    epoch_sec          INTEGER NOT NULL,
    ok                 INTEGER NOT NULL CHECK (ok IN (0, 1)),
    failure_category   TEXT NOT NULL DEFAULT '',
    latency_ms         REAL,
    median_latency_ms  REAL,
    p95_latency_ms     REAL,
    jitter_ms          REAL,
    packet_loss_pct    REAL,
    download_kbps      REAL,
    upload_kbps        REAL,
    exit_country       TEXT NOT NULL DEFAULT 'XX',
    country_source     TEXT NOT NULL DEFAULT 'unknown',
    masked_exit_subnet TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_measurements_server_epoch ON server_measurements(server_id, epoch_sec DESC);
CREATE INDEX IF NOT EXISTS idx_measurements_epoch ON server_measurements(epoch_sec DESC);

CREATE TABLE IF NOT EXISTS server_events (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id        TEXT NOT NULL REFERENCES servers(server_id) ON DELETE CASCADE,
    event_at         TEXT NOT NULL,
    epoch_sec        INTEGER NOT NULL,
    event_type       TEXT NOT NULL,
    previous_status  TEXT NOT NULL DEFAULT '',
    new_status       TEXT NOT NULL DEFAULT '',
    failure_category TEXT NOT NULL DEFAULT '',
    recovery_sec     REAL,
    detail           TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_events_server_epoch ON server_events(server_id, epoch_sec DESC);
CREATE INDEX IF NOT EXISTS idx_events_type_epoch ON server_events(event_type, epoch_sec DESC);

CREATE TABLE IF NOT EXISTS server_sources (
    server_id         TEXT NOT NULL REFERENCES servers(server_id) ON DELETE CASCADE,
    source_id         TEXT NOT NULL,
    operator_id       TEXT NOT NULL,
    first_source_seen TEXT NOT NULL,
    last_source_seen  TEXT NOT NULL,
    sightings_count   INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (server_id, source_id)
);

CREATE INDEX IF NOT EXISTS idx_server_sources_operator ON server_sources(server_id, operator_id);
CREATE INDEX IF NOT EXISTS idx_server_sources_source ON server_sources(source_id);

CREATE TABLE IF NOT EXISTS source_history (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id            TEXT NOT NULL,
    operator_id          TEXT NOT NULL,
    kind                 TEXT NOT NULL,
    recorded_at          TEXT NOT NULL,
    epoch_sec            INTEGER NOT NULL,
    available            INTEGER NOT NULL CHECK (available IN (0, 1)),
    discovered_configs   INTEGER NOT NULL DEFAULT 0,
    unique_valid_servers INTEGER NOT NULL DEFAULT 0,
    alive_servers        INTEGER NOT NULL DEFAULT 0,
    duplicate_rate       REAL NOT NULL DEFAULT 0.0,
    failure_rate         REAL NOT NULL DEFAULT 0.0,
    validity_rate        REAL NOT NULL DEFAULT 0.0,
    confidence_score     REAL NOT NULL DEFAULT 0.0
);

CREATE INDEX IF NOT EXISTS idx_source_history_src_epoch ON source_history(source_id, epoch_sec DESC);
CREATE INDEX IF NOT EXISTS idx_source_history_operator ON source_history(operator_id);

CREATE TABLE IF NOT EXISTS server_country_history (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id          TEXT NOT NULL REFERENCES servers(server_id) ON DELETE CASCADE,
    observed_at        TEXT NOT NULL,
    epoch_sec          INTEGER NOT NULL,
    country_code       TEXT NOT NULL,
    country_source     TEXT NOT NULL,
    confidence         TEXT NOT NULL,
    masked_exit_subnet TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_country_hist_server_epoch ON server_country_history(server_id, epoch_sec DESC);

CREATE TABLE IF NOT EXISTS server_score_history (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id         TEXT NOT NULL REFERENCES servers(server_id) ON DELETE CASCADE,
    scored_at         TEXT NOT NULL,
    epoch_sec         INTEGER NOT NULL,
    composite_score   REAL NOT NULL,
    performance_score REAL NOT NULL,
    reliability_score REAL NOT NULL,
    uptime_pct        REAL,
    uptime_kind       TEXT NOT NULL DEFAULT 'UNKNOWN'
);

CREATE INDEX IF NOT EXISTS idx_score_hist_server_epoch ON server_score_history(server_id, epoch_sec DESC);

CREATE TABLE IF NOT EXISTS server_hourly_aggregates (
    server_id           TEXT NOT NULL REFERENCES servers(server_id) ON DELETE CASCADE,
    hour_bucket         TEXT NOT NULL, -- YYYY-MM-DDTHH:00:00Z
    hour_epoch          INTEGER NOT NULL,
    test_count          INTEGER NOT NULL DEFAULT 0,
    success_count       INTEGER NOT NULL DEFAULT 0,
    avg_latency_ms      REAL,
    median_latency_ms   REAL,
    p95_latency_ms      REAL,
    avg_jitter_ms       REAL,
    avg_packet_loss_pct REAL,
    avg_download_kbps   REAL,
    peak_download_kbps  REAL,
    avg_upload_kbps     REAL,
    observed_uptime_pct REAL,
    PRIMARY KEY (server_id, hour_bucket)
);

CREATE INDEX IF NOT EXISTS idx_hourly_epoch ON server_hourly_aggregates(hour_epoch DESC);

CREATE TABLE IF NOT EXISTS server_daily_aggregates (
    server_id           TEXT NOT NULL REFERENCES servers(server_id) ON DELETE CASCADE,
    day_bucket          TEXT NOT NULL, -- YYYY-MM-DD
    day_epoch           INTEGER NOT NULL,
    test_count          INTEGER NOT NULL DEFAULT 0,
    success_count       INTEGER NOT NULL DEFAULT 0,
    avg_latency_ms      REAL,
    median_latency_ms   REAL,
    p95_latency_ms      REAL,
    avg_jitter_ms       REAL,
    avg_packet_loss_pct REAL,
    avg_download_kbps   REAL,
    peak_download_kbps  REAL,
    avg_upload_kbps     REAL,
    observed_uptime_pct REAL,
    avg_recovery_sec    REAL,
    PRIMARY KEY (server_id, day_bucket)
);

CREATE INDEX IF NOT EXISTS idx_daily_epoch ON server_daily_aggregates(day_epoch DESC);
