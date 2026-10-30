# Android VPN Application & Historical Server Intelligence Upgrade Plan (`v3.3`)

**Repository:** `https://github.com/oldman-552/vpn-configs`  
**Audit Date:** `2026-10-30`  
**Baseline Version Audited:** `v3.2` (`main` @ `35e97ba9414d10faa16b75d9ae1c587696acc2e2`)  
**Target Release:** `v3.3`

---

## 1. Current Architecture

The repository operates as a **100% GitHub-native serverless VPN intelligence and client ecosystem** composed of four integrated subsystems:

1. **Cloud Collection, Validation & Publishing Pipeline (`Python 3.11+` + `.github/workflows/data.yml`):**
   - `collector.py`: Parallel fetcher across 277 Telegram web channels and 26 curated GitHub feeds, guarded by `pipeline_security.py` (DNS-pinned SSRF checks, response byte caps, credential redaction, and SHA-256 verification of `Xray-core` and `sing-box` binaries).
   - `dedupe.py`: 5-layer normalization and deduplication engine (`ParsedIdentity`, `MultiLayerDeduplicator`) producing 24-hex SHA-256 `identity_id` digests over canonicalized `(protocol, host, port, credential, transport_query)` tuples.
   - `security_intelligence.py`: Pre-probe and post-probe static/dynamic configuration evaluator (`QuarantineRegistry`) blocking broken ciphers, `allowInsecure=1`, malformed `REALITY` keys, suspicious ports, and HTTP redirect hijacks.
   - `tester.py`: Multi-round real tunnel probing (`Xray` for `vless/vmess/trojan/ss`, `sing-box` for `hysteria2/tuic`) measuring HTTP 204 RTT, median latency, jitter, Cloudflare `/cdn-cgi/trace` exit country, and bounded download throughput.
   - `scoring.py` & `server/build_data.py`: Longitudinal state carry-over (`state/node_history.json`, `state/source_state.json`), composite/profile ranking, last-known-good fallback protection, and atomic output generation (`alive.txt`, `alive.json`, `best100.txt`, `sub.txt`, `countries.json`, `source_health.json`, `quarantined.json`).
   - `public_api.py`: Static `/api/v1/*` JSON exporter + `ThreadingHTTPServer` read-only API with OpenAPI 3.1 spec, ETag/304 support, pagination, and host/IP masking.

2. **Enterprise Governance Vault & Bundle Publisher (`enterprise/` + `.github/workflows/enterprise.yml`):**
   - Normalized 24-table SQLite enterprise schema (`enterprise/migrations/001..003`) encrypted at rest (`AES-256-GCM`) and exported as an `ECDSA P-256`-signed zero-knowledge client bundle (`@data/enterprise/bundle.json`), including encrypted `VIP` nodes and ABI-aware signed APK update metadata.

3. **Android Native VPN Client (`android/app`, `com.bahrain.vpnconfigs`, `minSdk = 29`, `targetSdk = 34`):**
   - **UI Layer:** Jetpack Compose + Material 3 (`MainActivity.kt`, `Screens.kt`, `EnterpriseScreens.kt`, `AppViewModel.kt`).
   - **VPN Tunnel Engine:** `BahrainVpnService.kt` combining `libbox / sing-box` local SOCKS5 daemon (`127.0.0.1:20808`) with `hev-socks5-tunnel` (`TProxyService`) + `MapDNS` (`198.18.0.2:53`) over Android `VpnService` TUN (`198.18.0.1/32` + `fc00::1/128`).
   - **Resilience & Security Modules:** `KillSwitchController.kt`, `LeakProtectionEngine.kt`, `SmartFailoverEngine.kt`, `ServerRanker.kt`, `SecurityEvaluator.kt`, `ClientDiagnosticsEngine.kt`, `EnterpriseLicenseGuard.kt`, `AppUpdateManager.kt`.
   - **Persistence:** `Prefs.kt` (`SharedPreferences`) + flat JSON files (`data/*`, `enterprise_speed_history.json`).

4. **Admin Applications (`web-admin/` on `gh-pages` + `android/admin`):**
   - 17-page bilingual (`AR/EN`) serverless Web Admin Console (`web-admin/index.html`, `modules/*.js`), public read-only live monitor (`web-admin/monitor.html`), and lightweight Android Admin APK (`com.bahrain.vpnadmin`).

---

## 2. Existing Capabilities (Must Not Be Broken)

1. **Application Identity & Packaging:** `applicationId = "com.bahrain.vpnconfigs"`, R8 minification + resource shrinking, Split-ABI APKs (`arm64-v8a`, `x86_64`, `universal`), JNI `useLegacyPackaging = true`, and `-dontobfuscate` stacktrace safety.
2. **Tunnel Lifecycle Safety:** `TProxyStopService()` invoked strictly *before* closing `tunFd` (`ParcelFileDescriptor`).
3. **Auto-Test & Speed Ranking on Refresh:** Refreshing servers automatically triggers real local tunnel probing and ranks tested servers while preserving active VPN sessions.
4. **Honest Server Card Telemetry & 5-State Badges:** Gray (untested), Green (fast), Orange (medium), Purple (weak), Red (failed/disconnected); never fabricating speeds from ping.
5. **Startup Rotating Promo Popup:** 5-slot banner (`promo/ads.json` + `ad1.png..ad5.png`) with 3-second close countdown.
6. **Source Hiding in `:app`:** Zero raw repository/CDN strings (`oldman-552`, `vpn-configs`, `jsdelivr`, `githubusercontent`) outside `Repo.kt`.
7. **Enterprise Zero-Knowledge Bundle & VIP Nodes:** `ECDSA P-256` verification, `AES-256-GCM` VIP node decryption in memory, 48-hour trial guard, and ABI-aware SHA-256-verified APK auto-updater.
8. **Backward-Compatible `@data` Artifacts:** `alive.txt`, `best100.txt`, `sub.txt`, `alive.json`, `meta.json`, `countries.json`, `source_health.json`, `quarantined.json`, `all.txt.gz`, `protocols/*.txt`, `enterprise/bundle.json`, and `api/v1/*`.

---

## 3. Missing Capabilities & Technical Limitations Identified

### 3.1 Backend & Historical Server Intelligence Gaps
- **Overwritten Flat History (`state/node_history.json`):** Previous measurements are overwritten in place rather than appended as time-series records; there are no hourly (`90d`) or daily (`365d`) rollups, no 24h/7d/30d/90d window analytics, and no `p95` latency or recovery-time calculations.
- **Identity Collision & Migration Gaps:** `parse_identity` produces a 24-hex digest without a secondary collision guard, canonical transport normalization aliases (e.g., `hy2` vs `hysteria2` scheme migrations or default TLS port/SNI normalization), or an identity migration table (`server_identity_migrations`).
- **Naive Uptime Formula:** Current `uptime_pct` blends `ema_reliability` and `runs_alive / runs_seen` without accounting for observation window duration, monitoring outages/cadence gaps, discovery timestamps, or retirement, and does not distinguish `OBSERVED`, `ESTIMATED`, and `UNKNOWN` availability.
- **Unstructured Failure Reasons:** `tester.py` emits low-level strings (`timeout`, `proc_dead`, `http_502`) rather than standardized failure intelligence categories (`CONNECTION_TIMEOUT`, `AUTHENTICATION_FAILURE`, `DNS_FAILURE`, `HANDSHAKE_FAILURE`, `TLS_ERROR`, `ROUTING_FAILURE`, `PACKET_LOSS`, `SERVER_UNAVAILABLE`, `INVALID_CONFIGURATION`, `UNKNOWN_FAILURE`) with recovery-time tracking and temporary suppression policies.
- **Source Operator Independence Blindness:** Multiple feed URLs controlled by the same GitHub repository/operator (e.g., 6 URLs under `Leon406/SubCrawler`, 2 under `mheidari98/.proxy`, 2 under `V2RayRoot/V2RayConfig`, 2 under `igareck/vpn-configs-for-russia`) are currently counted as separate corroborating sources instead of grouping by independent operator identity.
- **Missing Versioned Historical Exports:** `servers-current.json`, `servers-history.json`, `servers-performance.json`, `servers-statistics.json`, `countries-statistics.json`, and `sources-statistics.json` do not yet exist.

### 3.2 Android Client Gaps
- **Smart Server Selection Transparency & Weighting:** `ServerRanker.kt` lacks a configurable 7-factor `SmartServerSelector` (`25%` reliability, `20%` latency, `15%` packet loss, `15%` download speed, `10%` historical uptime, `10%` jitter, `5%` recent stability) with measurement confidence scoring, local establishment-time & latency-variance tracking, geographic preference filtering, network-type compatibility scoring, and human-readable selection explanations.
- **Fixed-Interval Recovery Loop:** `BahrainVpnService.handleAllCandidatesFailed` retries every fixed `15s` infinitely rather than using **exponential backoff with jitter** (`2s -> 5s -> 10s -> 20s -> 40s -> capped 60s`) with max-attempt protection and user notification on repeated failure.
- **Kill Switch Platform Verification & UX:** Needs explicit runtime distinction between Android OS `KILL_SWITCH_ACTIVE` (`VpnService.isLockdownEnabled` confirmed by OS) vs app-level fail-closed TUN hold, direct Android VPN Settings launcher (`Settings.ACTION_VPN_SETTINGS`), warning banner when OS lockdown is off, and persistent `lastProtectionEvent` audit record.
- **Real-Time Connection Monitor & Event Timeline:** Home screen shows basic speed/ping text but lacks a live rolling traffic sparkline chart, connection event timeline, and explicit `measured` vs `estimated` metric badges.
- **Ephemeral History & Raw-URI Favorites:** `Prefs.connectionHistory` caps at 20 `SharedPreferences` rows without disconnect time, duration, packet loss, throughput, failure reason, network type, pagination, or date/server filters; `Prefs.favorites` stores raw URIs in a `StringSet` without stable `server_id` matching across config remark/parameter updates, custom names, or favorite groups.
- **Network Awareness Granularity:** `BahrainVpnService` only hooks `onAvailable` handle changes; it does not track Wi-Fi vs Cellular vs Ethernet, metered status, `NET_CAPABILITY_VALIDATED`, capability transitions, or log structured network transition events.
- **Security Status Classification (Part 3):** Missing the formal 9-state classification engine (`CONNECTED`, `ENCRYPTED_TUNNEL`, `UNKNOWN_SERVER_TRUST`, `DNS_LEAK_DETECTED`, `IPV6_LEAK_DETECTED`, `UNSTABLE_CONNECTION`, `KILL_SWITCH_ACTIVE`, `SECURITY_CHECK_FAILED`, `SECURITY_CHECK_INCOMPLETE`), dedicated `SecurityStatusScreen`, and active IPv4/IPv6 DNS & route leak inspector.
- **Navigation Layout:** Currently 5 tabs (`الاتصال`, `السيرفرات`, `المركز المؤسسي`, `التطبيقات`, `الإعدادات`); needs clean 6-tab navigation (`Home`, `Servers`, `Favorites`, `History`, `Security`, `Settings`) while keeping Split-Tunneling Apps & Enterprise Hub accessible inside `Settings` / `Home`.

---

## 4. Security & Privacy Concerns Addressed

1. **Zero Credential Persistence in Historical Stores:** Neither the backend SQLite database (`history.sqlite3`) nor the Android local SQLite database (`bahrain_vpn_client.db`) may store plaintext passwords, UUIDs, private keys, or raw proxy URIs in measurement/history tables. Stable `server_id` values use cryptographic `SHA-256` over canonicalized parameters, while active connection URIs remain strictly in existing ephemeral/encrypted client config storage.
2. **Epistemic Honesty on Operator Trust & Encryption:** Public community servers must *always* emit `UNKNOWN_SERVER_TRUST` even when `ENCRYPTED_TUNNEL` (`TLS`/`REALITY`) is verified. Only cryptographically attested enterprise VIP nodes may clear `UNKNOWN_SERVER_TRUST`.
3. **Kill Switch Truthfulness:** `KILL_SWITCH_ACTIVE` is emitted **if and only if** `VpnService.isLockdownEnabled == true` is confirmed by Android OS (`API 29+`). App-level fail-closed TUN blocking is labeled explicitly as application-level protection with clear instructions to enable Android's system Always-On + Block Connections Without VPN setting.
4. **Zero Sensitive Network Identifiers:** `NetworkAwarenessMonitor` uses `ConnectivityManager` + `NetworkCapabilities` (`TRANSPORT_WIFI`, `TRANSPORT_CELLULAR`, `TRANSPORT_ETHERNET`, `NET_CAPABILITY_NOT_METERED`, `NET_CAPABILITY_VALIDATED`) and never requests `ACCESS_FINE_LOCATION` or Wi-Fi SSID/BSSID.
5. **Public Export Sanitization:** All new `servers-*.json`, `countries-statistics.json`, and `sources-statistics.json` exports mask endpoint IPs (`/24` IPv4, `/48` IPv6, `*.domain.tld`) and strip all credentials.

---

## 5. Proposed Architecture & Database Migration Strategy

### 5.1 Backend Historical Intelligence SQLite Engine (`historical_db.py` + `migrations/history/`)
In accordance with the repository's 100% GitHub-only architecture and Part 5 (*"Use SQLite for lightweight local persistence... Existing JSON artifacts for public distribution. Do not introduce PostgreSQL simply because it is available"*):
- **Storage Engine:** Python standard-library `sqlite3` in WAL mode (`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA synchronous=NORMAL;`) persisted across GitHub Actions `@data` runs at `state/history.sqlite3` (with automatic integrity check `PRAGMA quick_check` and corruption recovery fallback).
- **Versioned SQL Migrations (`migrations/history/001_initial_historical_intelligence.sql`, `002_source_independence_and_suppressions.sql`):**
  1. `schema_migrations`
  2. `servers` (stable `server_id`, `canonical_key_sha256`, `protocol`, `masked_endpoint`, `subnet_key`, `first_seen`, `last_seen`, `last_verified`, `current_status`, `consecutive_failures`, `suppressed_until`, `total_tests`, `successful_tests`, `failed_tests`, `avg_recovery_sec`, `detected_country`, `country_confidence`, `independent_source_count`, `source_count`, `latest_score`)
  3. `server_identity_migrations` (`legacy_id` -> `server_id`, `migrated_at`, `reason`)
  4. `server_measurements` (`id`, `server_id`, `measured_at`, `epoch_sec`, `ok`, `failure_category`, `latency_ms`, `median_latency_ms`, `p95_latency_ms`, `jitter_ms`, `packet_loss_pct`, `download_kbps`, `upload_kbps`, `exit_country`, `country_source`)
  5. `server_events` (`id`, `server_id`, `event_at`, `event_type`, `previous_status`, `new_status`, `failure_category`, `recovery_sec`, `detail`)
  6. `server_sources` (`server_id`, `source_id`, `operator_id`, `first_source_seen`, `last_source_seen`, `sightings_count`)
  7. `source_history` (`source_id`, `operator_id`, `kind`, `recorded_at`, `available`, `discovered_configs`, `unique_valid_servers`, `alive_servers`, `duplicate_rate`, `failure_rate`, `validity_rate`, `confidence_score`)
  8. `server_country_history` (`id`, `server_id`, `observed_at`, `country_code`, `country_source`, `confidence`)
  9. `server_score_history` (`id`, `server_id`, `scored_at`, `composite_score`, `performance_score`, `reliability_score`, `uptime_pct`, `uptime_kind`)
  10. `server_hourly_aggregates` (`server_id`, `hour_bucket`, `test_count`, `success_count`, `avg_latency_ms`, `median_latency_ms`, `p95_latency_ms`, `avg_jitter_ms`, `avg_packet_loss_pct`, `avg_download_kbps`, `peak_download_kbps`, `avg_upload_kbps`, `observed_uptime_pct`)
  11. `server_daily_aggregates` (`server_id`, `day_bucket`, `test_count`, `success_count`, `avg_latency_ms`, `median_latency_ms`, `p95_latency_ms`, `avg_jitter_ms`, `avg_packet_loss_pct`, `avg_download_kbps`, `peak_download_kbps`, `avg_upload_kbps`, `observed_uptime_pct`, `avg_recovery_sec`)
- **Configurable Retention Policy:** Detailed `server_measurements` (`30` days default), `server_hourly_aggregates` (`90` days default), `server_daily_aggregates` (`365` days default), executed atomically inside each pipeline run.
- **Seamless Bootstrap Migration:** On first run against an existing `@data` branch, `HistoricalServerDB` automatically imports legacy `state/node_history.json` (`24-hex` IDs mapped into `server_identity_migrations` -> `32-hex` collision-hardened `srv_<32hex>` / backward-compatible IDs) so zero prior history is lost.

### 5.2 Android Local SQLite Persistence (`data/ClientDatabase.kt`)
- Implemented via `SQLiteOpenHelper` (`bahrain_vpn_client.db`, schema version `2` with explicit v1 -> v2 migration path):
  1. `connection_history` (session start/end timestamps, duration, `server_id`, masked endpoint, protocol, country, success/failure, avg latency, jitter, packet loss, download/upload bps, failure category, network transport type) with pagination, server/date filtering, performance sorting, configurable retention (`90` days default), and one-tap clear.
  2. `favorite_servers` (stable `server_id`, non-secret display metadata, custom alias name, `group_name`, sort order, encrypted/local reference key without logging credentials, historical success/latency stats, unique index on `server_id`). Automatically migrates legacy `Prefs.favorites` on first launch.
  3. `local_server_telemetry` (per-`server_id` connection attempts, successes, establishment time ms, EWMA latency, latency variance, jitter, packet loss, download/upload kbps, last failure timestamp/category, consecutive failures, network-type affinity).
  4. `protection_events` (persisted Kill Switch, reconnection backoff, network handover, and leak-check events).

---

## 6. Controlled Implementation Phases

| Phase | Scope | Key Files |
|---|---|---|
| **Phase 1** | Repository Audit & Upgrade Plan | `docs/ANDROID_AND_DATA_UPGRADE_PLAN.md` |
| **Phase 2** | Stable Server Identity, Historical SQLite DB & Versioned Migrations | `dedupe.py`, `historical_db.py`, `migrations/history/*.sql` |
| **Phase 3** | Historical Analytics, Windowed Uptime, Failure Intelligence & Source Operator Independence | `historical_analytics.py`, `tester.py`, `scoring.py`, `collector.py` |
| **Phase 4** | Android Smart Server Selection, Exponential-Backoff Auto-Reconnect & Network Awareness | `SmartServerSelector.kt`, `AutoReconnectManager.kt`, `NetworkAwarenessMonitor.kt`, `BahrainVpnService.kt` |
| **Phase 5** | Android Kill Switch OS Lockdown Verification & 9-State Connection Security Diagnostics | `KillSwitchController.kt`, `ConnectionSecurityClassifier.kt`, `LeakDiagnosticsRunner.kt`, `SecurityStatusScreen.kt` |
| **Phase 6** | Android Connection Monitor (Live Sparkline + Timeline), Persistent SQLite History & Favorites | `ClientDatabase.kt`, `ConnectionMonitorCard.kt`, `FavoritesScreen.kt`, `ServerHistoryScreen.kt`, `MainActivity.kt` |
| **Phase 7** | Android Battery & Resource Optimization + Measured Benchmarks | `ResourceAndBatteryMonitor.kt`, `BahrainVpnService.kt`, `docs/ANDROID_BATTERY_OPTIMIZATION.md` |
| **Phase 8** | Web Admin Historical Visualization, Drill-Down Details & Versioned Public Data Exports | `public_api.py`, `server/build_data.py`, `web-admin/monitor.js`, `web-admin/modules/pages_infrastructure.js` |
| **Phase 9** | Comprehensive Backend, Security, Performance & Android Robolectric Test Suites | `tests/test_historical_intelligence.py`, `android/app/src/test/.../SmartVpnUpgradeTest.kt` |
| **Phase 10** | Full Technical Documentation Suite, `README.md`, CI Verification & Release Delivery | `docs/{IMPLEMENTATION_REPORT,SECURITY_MODEL,DATABASE_SCHEMA,ANDROID_ARCHITECTURE,TESTING_REPORT,DEPLOYMENT_GUIDE}.md`, `README.md`, `CHANGELOG.md` |

---

## 7. Testing & Backward Compatibility Strategy

- **Python Automated Suite (`pytest`):** All 42 existing tests must remain green alongside new unit/integration tests covering stable identity invariance & collision handling, SQLite schema migrations, time-series rollups, retention pruning, windowed uptime (`OBSERVED` vs `ESTIMATED` vs `UNKNOWN`), 10-category failure classification, operator-level source independence, secret redaction, query latency benchmarks, and atomic backward-compatible JSON exports.
- **Android Automated Suite (`JUnit4` + `Robolectric` SDK 34 in CI):** All 19 existing `:app` and `:admin` tests must remain green alongside new tests covering `SmartServerSelector` normalization/missing-data honesty/explanations, `AutoReconnectManager` exponential backoff (`2s, 5s, 10s, 20s, 40s, cap`) & jitter, `KillSwitchController` OS lockdown truth table, `ConnectionSecurityClassifier` 9-state transitions, DNS/IPv6 leak diagnostics, `NetworkAwarenessMonitor` transitions, and `ClientDatabase` SQLite migrations, pagination, favorites persistence, and history retention.
- **Explicit Verification Honesty:** Local sandbox verifies Python (`pytest`), Node.js syntax (`node --check`), and static security checks directly; GitHub Actions (`apk.yml`, `ci.yml`, `enterprise.yml`, `data.yml`) executes full Gradle compilation, R8 shrinking, Robolectric unit tests, and live tunnel probing. Physical Android hardware radio handovers (actual cellular tower handoff / OEM battery-saver ROM quirks) are explicitly documented as requiring physical device validation.
