-- 002_source_independence_and_suppressions.sql
-- Adds configurable temporary suppression metadata, pipeline run cadence tracking
-- (to distinguish monitoring outages from server downtime), and current source summary table.

ALTER TABLE servers ADD COLUMN suppressed_until_epoch INTEGER NOT NULL DEFAULT 0;
ALTER TABLE servers ADD COLUMN suppression_reason TEXT NOT NULL DEFAULT '';
ALTER TABLE servers ADD COLUMN consecutive_successes INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_servers_suppressed ON servers(suppressed_until_epoch);

CREATE TABLE IF NOT EXISTS pipeline_runs (
    run_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_at          TEXT NOT NULL,
    epoch_sec       INTEGER NOT NULL,
    tested_count    INTEGER NOT NULL DEFAULT 0,
    alive_count     INTEGER NOT NULL DEFAULT 0,
    degraded_mode   INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_pipeline_runs_epoch ON pipeline_runs(epoch_sec DESC);

CREATE TABLE IF NOT EXISTS sources_catalog (
    source_id                TEXT PRIMARY KEY,
    operator_id              TEXT NOT NULL,
    kind                     TEXT NOT NULL,
    state                    TEXT NOT NULL DEFAULT 'active',
    available                INTEGER NOT NULL DEFAULT 1,
    discovered_configs       INTEGER NOT NULL DEFAULT 0,
    unique_valid_servers     INTEGER NOT NULL DEFAULT 0,
    exclusive_servers        INTEGER NOT NULL DEFAULT 0,
    alive_servers            INTEGER NOT NULL DEFAULT 0,
    historical_validity_rate REAL NOT NULL DEFAULT 0.0,
    duplicate_rate           REAL NOT NULL DEFAULT 0.0,
    failure_rate             REAL NOT NULL DEFAULT 0.0,
    confidence_score         REAL NOT NULL DEFAULT 0.0,
    confidence_tier          TEXT NOT NULL DEFAULT 'UNVERIFIED',
    independent_operator     INTEGER NOT NULL DEFAULT 1,
    last_updated             TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_sources_catalog_operator ON sources_catalog(operator_id);
CREATE INDEX IF NOT EXISTS idx_sources_catalog_confidence ON sources_catalog(confidence_score DESC);
