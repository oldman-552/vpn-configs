# Database Schema Reference (`v1`)

Both the GitHub Cloud Intelligence Pipeline and the Android Client use embedded **SQLite in WAL (`Write-Ahead Logging`) mode** with explicit schema migration tracking, `FOREIGN KEY` enforcement, indexed time-range queries, and strict zero-credential storage.

---

## Part A — Cloud Historical Intelligence DB (`state/history.sqlite3`)

Managed by `historical_db.py` with SQL migrations in `migrations/history/` (`001_initial_historical_intelligence.sql`, `002_source_independence_and_suppressions.sql`). Persisted across `@data` branch runs on GitHub Actions with `PRAGMA quick_check` corruption recovery and automatic atomic `.bak` snapshots.

### Tables
1. **`schema_migrations`**
   - `version INTEGER PRIMARY KEY`, `name TEXT NOT NULL`, `applied_at TEXT NOT NULL`
2. **`collection_runs`**
   - `run_id TEXT PRIMARY KEY`, `started_at TEXT`, `finished_at TEXT`, `duration_sec REAL`, `raw_collected INTEGER`, `unique_clean INTEGER`, `tested_count INTEGER`, `alive_count INTEGER`, `quarantined_count INTEGER`, `suppressed_skipped INTEGER`, `degraded_mode INTEGER`
3. **`servers`**
   - `server_id TEXT PRIMARY KEY` (24-hex SHA-256 canonical outbound fingerprint with blinded credential hash)
   - `legacy_id TEXT` (12-hex backward-compatible link to `node_history.json`)
   - `protocol TEXT`, `masked_endpoint TEXT`, `port INTEGER`, `transport TEXT`, `tls_mode TEXT`, `country TEXT`
   - `first_seen_at TEXT`, `last_seen_at TEXT`, `last_tested_at TEXT`, `last_success_at TEXT`
   - `is_active INTEGER`, `consecutive_successes INTEGER`, `consecutive_failures INTEGER`, `total_observations INTEGER`, `total_successes INTEGER`
   - `reliability_score REAL`, `security_assessment TEXT`, `privacy_assessment TEXT`, `risk_level TEXT`, `independent_source_count INTEGER`
   - Indexes: `idx_servers_active_rel(is_active, reliability_score DESC)`, `idx_servers_country(country, is_active)`, `idx_servers_protocol(protocol, is_active)`, `idx_servers_last_seen(last_seen_at DESC)`
4. **`sources`**
   - `source_id TEXT PRIMARY KEY`, `operator_id TEXT NOT NULL`, `source_type TEXT`, `display_name TEXT`, `first_seen_at TEXT`, `last_seen_at TEXT`, `last_success_at TEXT`, `total_runs INTEGER`, `successful_runs INTEGER`, `contributed_total INTEGER`, `alive_contributed INTEGER`, `unique_contributed INTEGER`, `duplicate_count INTEGER`, `suspicious_count INTEGER`, `reliability_score REAL`, `state TEXT`
   - Index: `idx_sources_operator(operator_id)`
5. **`server_sources`**
   - Composite PK `(server_id, source_id)`, `operator_id TEXT`, `first_seen_at TEXT`, `last_seen_at TEXT`, `sightings_count INTEGER`
6. **`server_observations`** (Raw probe series — default retention: **30 days**)
   - `id INTEGER PRIMARY KEY AUTOINCREMENT`, `server_id TEXT`, `run_id TEXT`, `observed_at TEXT`, `observed_epoch INTEGER`, `is_reachable INTEGER`, `tcp_ms REAL`, `tls_ms REAL`, `latency_ms REAL`, `jitter_ms REAL`, `packet_loss_pct REAL`, `download_kbps REAL`, `upload_kbps REAL`, `failure_category TEXT`, `exit_country TEXT`, `consistency_ok INTEGER`
   - Indexes: `idx_obs_server_epoch(server_id, observed_epoch DESC)`, `idx_obs_epoch(observed_epoch DESC)`, `idx_obs_fail_cat(failure_category, observed_epoch DESC)`
7. **`server_hourly_rollups`** (Retention: **90 days**) & **`server_daily_rollups`** (Retention: **365 days**)
   - Composite PK `(server_id, bucket_start_epoch)`: `sample_count`, `success_count`, `avg_latency_ms`, `median_latency_ms`, `p95_latency_ms`, `avg_jitter_ms`, `avg_packet_loss_pct`, `avg_download_kbps`, `avg_upload_kbps`, `dominant_failure`
8. **`server_outages`**
   - Tracks outage intervals (`started_at`, `started_epoch`, `recovered_at`, `recovered_epoch`, `duration_sec`, `failure_count`, `primary_failure_category`) for accurate `mean_recovery_sec` calculation and outage-aware uptime.
9. **`server_suppressions`**
   - `server_id TEXT PRIMARY KEY`, `suppressed_at_epoch INTEGER`, `suppress_until_epoch INTEGER`, `reason TEXT`, `consecutive_failures INTEGER` — suppresses repeatedly dead servers from hot-path probing without deleting their historical identity.

---

## Part B — Android Local SQLite DB (`bahrain_vpn_client.db`, `DB_VERSION = 2`)

Managed by `com.bahrain.vpnconfigs.data.ClientDatabase` (`SQLiteOpenHelper` with `enableWriteAheadLogging()`).

### Tables
1. **`connection_history`**
   - `id INTEGER PRIMARY KEY AUTOINCREMENT`, `server_id TEXT`, `server_label TEXT`, `masked_endpoint TEXT`, `protocol TEXT`, `country TEXT`, `connected_at_ms INTEGER`, `disconnected_at_ms INTEGER`, `duration_sec INTEGER`, `success INTEGER`, `avg_latency_ms INTEGER`, `jitter_ms REAL`, `packet_loss_pct REAL`, `peak_download_bps INTEGER`, `peak_upload_bps INTEGER`, `total_down_bytes INTEGER`, `total_up_bytes INTEGER`, `failure_reason TEXT`, `network_type TEXT`
   - Indexes: `idx_hist_connected_at`, `idx_hist_server_id`, `idx_hist_perf`
2. **`favorite_servers`**
   - `server_id TEXT PRIMARY KEY`, `custom_name TEXT`, `default_label TEXT`, `group_name TEXT`, `protocol TEXT`, `masked_endpoint TEXT`, `country TEXT`, `sort_order INTEGER`, `added_at_ms INTEGER`, `updated_at_ms INTEGER`
3. **`local_server_telemetry`**
   - `server_id TEXT PRIMARY KEY`, `attempts`, `successes`, `consecutive_failures`, `last_failure_at_ms`, `last_failure_category`, `last_success_at_ms`, `avg_establish_ms`, `ewma_latency_ms`, `latency_variance_ms2`, `ewma_jitter_ms`, `ewma_packet_loss_pct`, `best_download_kbps`, `best_upload_kbps`, `wifi_successes`, `cellular_successes`, `recent_trend_delta`
4. **`protection_events`** (Added in `upgradeToV2`)
   - `id INTEGER PRIMARY KEY AUTOINCREMENT`, `event_at_ms INTEGER`, `category TEXT`, `title_ar TEXT`, `detail_ar TEXT` (bounded to latest 200 events).
