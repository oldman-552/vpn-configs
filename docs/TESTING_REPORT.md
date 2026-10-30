# Testing & Verification Report (`v3.3`)

In accordance with strict engineering honesty rules, this report distinguishes **automated tests executed locally**, **automated Android/Robolectric & R8 checks executed in GitHub Actions CI**, and **scenarios requiring physical mobile hardware**.

---

## 1. Local Python Backend & Historical Intelligence Suite — **PASSED (`48 / 48`)**

Executed locally via `.venv/bin/pytest -v` in **`6.87s`**:
- `tests/test_historical_intelligence.py` (**6 comprehensive end-to-end tests — PASSED**):
  1. `test_canonical_server_id_stability_and_secret_safety`: Verifies canonical `server_id` stability across remark/parameter order changes, sensitivity to real security/endpoint changes, and zero raw password/UUID substrings in fingerprints or JSON exports.
  2. `test_source_operator_independence`: Verifies 6 URLs under `Leon406/SubCrawler` collapse to `1` independent operator (`gh:leon406`), while adding `Mahdi0024` + Telegram `@v2ray_alpha` yields `3` independent operators.
  3. `test_historical_db_migrations_analytics_suppression_and_exports`: Verifies SQLite v1+v2 migrations, `OBSERVED` vs `UNKNOWN` uptime basis, `avg`/`median`/`p95` latency & recovery time calculation, temporary suppression after repeated consecutive failures (`>= 5`) without deleting historical records, retention pruning, and secret-free atomic JSON export of all 6 public files.
  4. `test_corrupted_sqlite_database_auto_recovers`: Corrupts `history.sqlite3` header bytes and verifies automatic quarantine + clean rebuild without crashing `build_data.py`.
  5. `test_bootstrap_from_legacy_node_history_json`: Verifies seamless import of legacy `state/node_history.json` into `servers` with `ESTIMATED` historical continuity.
  6. `test_indexed_query_performance_under_load`: Populates `500` servers and `5,000` observations and verifies full public analytics export completes well within strict sub-second/CI SLA bounds.
- Existing regression suites (**42 tests — ALL PASSED**):
  - `tests/test_audit_fixes.py`, `tests/test_dedupe_and_scoring.py`, `tests/test_enterprise_v3.py`, `tests/test_pipeline_e2e.py`, `tests/test_v31_upgrades.py`.

## 2. Web Admin & Monitor Syntax Audit — **PASSED**
- Executed `node --check web-admin/monitor.js` and `node --check web-admin/modules/pages_infrastructure.js`: **0 syntax errors**.
- Source-hiding static grep audit across `android/app/src/main/`: **0 repository/CDN URLs outside `Repo.kt`**.

## 3. Android Robolectric Unit & Release R8 Verification (`apk.yml` CI)
Because the local sandbox does not bundle a JDK/Android SDK, Gradle compilation, R8 minification, and Robolectric unit suites execute on GitHub Actions (`apk.yml`):
- `SmartVpnUpgradeTest.kt` (5 new multi-assertion Robolectric tests on SDK 34):
  - `canonicalServerIdIsStableAcrossRemarksAndNeverLeaksSecrets`
  - `sqliteFavoritesAndSessionHistoryPersistFilterPaginateAndProtectCredentials`
  - `smartServerSelectorHonorsWeightsRejectsFlakyFastServersAndExplainsConfidence`
  - `autoReconnectBackoffScheduleJitterDisconnectTriggersAndUserCancel`
  - `connectionSecurityClassifierEnforcesAll9StatesAndHonestReporting`
  - `networkAwarenessAndBatteryAdaptiveIntervalsSavePowerInBackground`
- Existing Robolectric regression suites preserved:
  - `AndroidVpnAuditTest.kt` (URI parsing, short-`pbk` handling, sorting, leak plan, failover hysteresis)
  - `EnterpriseAndroidTest.kt` (ECDSA bundle verification, 48h trial, speed test socket loop, ABI-aware updater `versionCode > 11`, AES-256-GCM VIP nodes)

## 4. Physical Device / External Environment Limitations
The following behaviors are architecturally implemented and unit-tested at the decision-engine boundary, but end-to-end kernel validation requires physical Android 10–14 hardware:
- Kernel `tun0` routing table capture during live Wi-Fi -> 5G baseband handovers.
- Android Settings UI toggle for *Always-on VPN + Block connections without VPN* (`VpnService.isLockdownEnabled` OS confirmation).
- Hardware `mAh` battery discharge telemetry under OEM Doze modes.
