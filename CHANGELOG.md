# CHANGELOG.md

## [v3.5] — 2026-10-30 — Google Play Protect Anti-Dropper Hardening, RSA-4096 v2/v3 Release Signing & Unified `v3.5` Tagging

### Added & Hardened
- **Google Play Protect Anti-Dropper Compliance (`AndroidManifest.xml`, `AppUpdateManager.kt`, `Repo.kt`)**:
  - Removed `<uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES" />` from `:app` so the VPN client never matches Play Protect's `PHA:HostileDownloader / Dropper` heuristic.
  - Replaced internal `.apk` archive downloading and `"application/vnd.android.package-archive"` execution with `AppUpdateManager.openVerifiedUpdateInSystemBrowser` (strictly validating `https://` public URLs, copying expected `SHA-256` fingerprint to clipboard, and delegating download/install to the user's trusted system browser while preserving Split-ABI `arm64-v8a` / `x86_64` / `universal` selection).
- **Official Release Signing Pipeline (`.github/workflows/apk.yml`, `android/app/build.gradle.kts`, `android/admin/build.gradle.kts`)**:
  - Wired `KEYSTORE_BASE64` / `ANDROID_KEYSTORE_BASE64`, `KEYSTORE_PASSWORD`, `KEY_ALIAS`, and `KEY_PASSWORD` secrets with `PKCS12 RSA-4096` (`SHA256withRSA`) production certificate generation and full **APK Signature Scheme `v1 + v2 + v3`**, eliminating `CN=Android Debug` signing on release artifacts.
  - Added automated CI security gates (`apksigner verify --verbose --print-certs`, `aapt2 dump permissions`, and DEX bytecode scanning) blocking `REQUEST_INSTALL_PACKAGES`, `application/vnd.android.package-archive`, and `Android Debug` certificates.
- **Unified `v3.5` Tagging Across Android, Admin, Enterprise, Web Dashboards & Documentation**:
  - Bumped User APK (`com.bahrain.vpnconfigs` `versionCode = 13`, `versionName = "3.5"`), Admin APK (`com.bahrain.vpnadmin` `versionCode = 6`, `versionName = "3.5"`), Enterprise `bundle_release = "3.5"`, `web-admin/` (`v3.5`), `README.md`, and architecture/security/deployment documentation.

## [v3.4] — 2026-10-30 — Mandatory Final Architecture: Central GitHub Top 500 + Local Android Personalized Top 50

### Added & Upgraded
- **Central GitHub Server Database & Top-500 Candidate Pool (`central_top500.py`, `server/build_data.py`)**:
  - Enforced strict responsibility separation: GitHub collects, validates, normalizes, deduplicates, assigns stable `server_id` + `config_fingerprint`, runs preliminary tunnel checks, filters unqualified/quarantined servers, and publishes **up to 500** qualified candidates (`top500.json`, `top500.txt`, `top500.manifest.json`, and incremental `top500.delta.json`).
  - Never fabricates configurations or pads unqualified servers to reach 500; explicitly declares `personalized_top50_authority = "ANDROID_LOCAL_ONLY"` and `trust_posture = "UNTRUSTED_PUBLIC_SERVER"`.
  - Publishes monotonic `dataset_version`, SHA-256 payload & canonical `configs_sha256` checksums, and incremental delta diffs.
- **Android Dataset Delivery & Integrity Engine (`Repo.kt`, `Converters.configFingerprint`)**:
  - Implemented `syncTop500Dataset()` with HTTP `ETag` (`304 Not Modified`), raw & canonical SHA-256 checksum verification, optional incremental `top500.delta.json` reconstruction, rollback protection (`datasetVersion` / `generatedAtEpoch` anti-replay), and automatic `top500.last_valid.json` recovery.
- **Android Local Server Intelligence & Sequential VPN Tunnel Scanner (`LocalServerIntelligence.kt`, `SingBox.testRealTunnelSequential`, `ClientDatabase.kt` v3, `versionCode = 12`)**:
  - **Strict Sequential Tunnel Testing (`Mutex` concurrency = 1):** Establishes one real encrypted VPN tunnel at a time, measuring handshake establishment time, median latency, jitter, packet loss, throughput, and stability without opening simultaneous tunnels.
  - **Quick Scan (`startQuickScan`):** Prioritizes recently successful servers, current local Top 50, and Backup Pool, avoids scanning all 500 unnecessarily, optimizes mobile-data/battery budgets, and stops early when sufficient qualified servers are ready.
  - **Full Scan (`startFullScan`):** Sequentially evaluates all configurations in the downloaded Top-500 pool to discover servers outperforming the current local Top 50, re-test stale servers, recalculate Personalized Top 50, and refresh the Backup Pool.
  - **Network-Specific Rankings (`WIFI` vs `MOBILE_DATA`):** Isolated `network_server_stats`, `local_network_rankings`, append-only `server_scan_measurements`, and append-only `local_ranking_history` per network profile — never assuming Wi-Fi performance applies to Mobile Data.

## [v3.3] — 2026-10-30 — Historical Server Intelligence DB, Smart Explainable Selection, Persistent SQLite Client & 9-State Security

### Added & Upgraded
- **Historical Server Intelligence SQLite Engine (`historical_db.py`, `migrations/history/001..002.sql`, `dedupe.py`)**:
  - Secret-safe canonical SHA-256 server identity (`server_id`, zero plaintext credentials in fingerprints or DB), operator-level source independence (`extract_source_operator_id` collapsing multi-file operators like `Leon406/SubCrawler` to `1` operator), 10-category failure intelligence, outage-aware `24h`/`7d`/`30d`/`90d` analytics (`OBSERVED` / `ESTIMATED` / `UNKNOWN` uptime basis), temporary failure suppression without deletion, 30d/90d/365d retention rollups, corruption auto-recovery, and `node_history.json` bootstrap.
  - Published 6 sanitized public JSON exports on `@data`: `servers-current.json`, `servers-history.json`, `servers-performance.json`, `servers-statistics.json`, `countries-statistics.json`, and `sources-statistics.json`.
- **Android Smart Client & Local SQLite Persistence (`v3.3`, `versionCode = 11`)**:
  - Added `ClientDatabase.kt` (`bahrain_vpn_client.db` WAL v2) persisting `connection_history`, `favorite_servers` (custom names, groups, legacy migration), `local_server_telemetry`, and `protection_events` with zero raw credentials.
  - Added `SmartServerSelector.kt` (configurable normalized weights `25/20/15/15/10/10/5`, missing measurements != perfect, confidence level, cooldown exclusion, geo preference, primary + fallback, deterministic Arabic/English reasons).
  - Added `AutoReconnectManager.kt` (`2s, 5s, 10s, 20s, 40s, capped 60s` exponential backoff + `±15%` jitter, 8 disconnect triggers, single-flight guard), `NetworkAwarenessMonitor.kt` (modern `ConnectivityManager`/`NetworkCapabilities`, zero SSID/location collection), and `ResourceAndBatteryMonitor.kt` (zero `WakeLock`s, 45s/60s background adaptive polling).
  - Added `ConnectionSecurityClassifier.kt` + `SecurityStatusScreen.kt` (all 9 mandatory `ConnectionSecurityState` values, DNS/IPv6 leak diagnostics, strict separation of app-level fail-closed TUN hold vs OS `VpnService.isLockdownEnabled`), `ConnectionMonitorCard.kt` (live Canvas traffic chart), `FavoritesScreen.kt`, `ServerHistoryScreen.kt`, and clean 6-tab navigation (`الاتصال`, `السيرفرات`, `المفضّلة`, `السجل`, `الأمان`, `الإعدادات`).
- **Web Historical Intelligence Visualization (`web-admin/monitor.html`, `web-admin/monitor.js`)**:
  - Added `24h`/`7d`/`30d`/`90d` windowed performance selector, 8-criteria historical server explorer, failure category pills, and clickable Historical Server Details modal.
- **QA & Documentation (`48/48` Python tests + `SmartVpnUpgradeTest.kt` + `docs/*.md`)**:
  - Added `tests/test_historical_intelligence.py`, `SmartVpnUpgradeTest.kt`, and `docs/{ANDROID_AND_DATA_UPGRADE_PLAN,ANDROID_BATTERY_OPTIMIZATION,DATABASE_SCHEMA,SECURITY_MODEL,ANDROID_ARCHITECTURE,TESTING_REPORT,DEPLOYMENT_GUIDE,IMPLEMENTATION_REPORT}.md`.

## [v3.2] — 2026-10-30 — Security Intelligence, Zero-Leak Tunnel, Real Kill Switch & Public API v1

### Signed Release Artifacts (`v3.2`)
- `app-arm64-v8a-release.apk` (`27.63 MB` / `28,970,075 B`) — `sha256:13dd72d0182de10f5a5b9d75174d3626aae10759f00e79ae89efa8b0da9dfdee`
- `app-x86_64-release.apk` (`29.44 MB` / `30,870,374 B`) — `sha256:11b8f1828883b1206253ddc619f4c2baa9f85a857591f767e0516a58c7353e5c`
- `app-release.apk` / `app-universal-release.apk` (`54.27 MB` / `56,901,372 B`) — `sha256:ca21059896f59136334e47c42fec34dc1b5105d5db63c03b56062fd57aff9da9`
- `app-admin-release.apk` (`2.19 MB` / `2,292,984 B`) — `sha256:f275b145cd1e82626407fe895d68a8cada44cdaea43ec857759a6d6cb8f10a29`
- `SHA256SUMS.txt` (`443 B`) — `sha256:f17b9fdc7e8a0a7d23ebb763ac22ba96bfef9ecd08b81847b7ada893803df2c3`

### Added
- **Phase 1 Audit Suite**: Added source-verified `ARCHITECTURE_AUDIT.md`, `SECURITY_AUDIT.md`, `PERFORMANCE_AUDIT.md`, and `IMPROVEMENT_ROADMAP.md`.
- **Phase 2 Security & Privacy Intelligence Engine (`security_intelligence.py`, `SecurityEvaluator.kt`)**:
  - Separated Performance (`0–100`) and Reliability (`0–100`) from Security (`Verified / Partial / Unknown / Failed`), Privacy (`Verified / Unverified / Unknown / High Risk`), and Risk (`LOW / MEDIUM / HIGH / CRITICAL / UNKNOWN`).
  - Added pre-probe and post-probe `QuarantineRegistry` (`dist/quarantined.json`) isolating broken ciphers, non-proxy ports, malformed Reality keys, suspicious redirects, and TLS verification failures.
- **Phase 3 Advanced Leak Protection (`LeakProtectionEngine.kt`, `SingBox.kt`, `ClientDiagnosticsEngine.kt`)**:
  - Fixed Android DNS routing so `sing-box` `"tunnel-dns"` detours strictly through `"proxy"` while `"bootstrap"` is isolated to proxy server resolution; sanitized private/LAN DNS inputs.
  - Enforced mandatory `::/0` (`fc00::1/128`) IPv6 capture in `BahrainVpnService` with `ipv4_only` outbound strategy when IPv6 tunneling is disabled, eliminating dual-stack IPv6 bypass.
  - Replaced overclaimed WebRTC boolean with honest split-tunnel and browser STUN advisory diagnostics.
- **Phase 4 Real Fail-Closed Kill Switch (`KillSwitchController.kt`, `BootRestoreReceiver.kt`, `BahrainVpnService.kt`)**:
  - Locks `tun0` *before* daemon probing during `CONNECTING`, holds `tun0` in `PROTECTION_ACTIVE` on unexpected failure with automatic 15s background recovery, restores protection on `BOOT_COMPLETED`, handles seamless Wi-Fi/cellular handovers (`RECONNECTING`), and detects Android OS `isLockdownEnabled`.
- **Phase 5 Multi-Profile Ranking (`scoring.py`, `ServerRanker.kt`)**:
  - Added 5 canonical ranking profiles (`BALANCED`, `LOW_LATENCY`, `HIGH_SPEED`, `HIGH_RELIABILITY`, `PRIVACY_AWARE`) and `dist/privacy_aware.txt` while keeping `FASTEST_DOWNLOAD` auto-test/sort as default.
- **Phase 6 Proactive Auto-Failover (`SmartFailoverEngine.kt`, `VpnState.kt`)**:
  - Added `OFF / SMART / AGGRESSIVE` policies, rolling latency/jitter/packet-loss degradation detection (`CONNECTION_DEGRADED`), 25s hysteresis dwell, non-disruptive background candidate verification on ports `20901..20904`, and rich UI failover telemetry.
- **Phase 7 Source Intelligence (`collector.py`, `scoring.py`)**:
  - Added conditional HTTP (`ETag`/`Last-Modified`), SHA-256 content change tracking, per-source `new/invalid/duplicate/suspicious` counters, rolling availability history, and automated source quarantine.
- **Phase 8 Live Infrastructure Monitor (`web-admin/monitor.html`, `web-admin/monitor.js`)**:
  - Added public read-only responsive AR/EN dark/light monitoring dashboard with 60s caching and SVG historical trend charts.
- **Phase 9 Android Efficiency & 8 Tunnel States**:
  - Implemented all 8 tunnel-verified states (`CONNECTED`, `CONNECTING`, `DISCONNECTED`, `RECONNECTING`, `SWITCHING_SERVER`, `CONNECTION_DEGRADED`, `PROTECTION_ACTIVE`, `CONNECTION_FAILED`), adaptive probe intervals (`3.5s .. 24s`), and notification deduplication.
- **Phase 10 Read-Only Public Statistics API v1 (`public_api.py`)**:
  - Added `/api/v1/{servers,servers/{id},statistics,countries,protocols,sources,health,openapi.json}` static generator + rate-limited/ETag Python HTTP server with strict IP/URI/secret redaction.
- **Phase 11 & 12 QA & Documentation**:
  - Added `tests/test_security_ranking_and_api.py` (42 total passing Python tests) and `LeakKillSwitchAndSecurityTest.kt`, plus `ARCHITECTURE.md`, `SECURITY.md`, `PRIVACY.md`, `API.md`, `DEPLOYMENT.md`, `TESTING.md`, `TROUBLESHOOTING.md`, and `CHANGELOG.md`.

## [v3.1] — 2026-10-30
- Split-ABI R8 APKs (`27.57 MB` ARM64 User APK, `2.19 MB` Admin APK), Encrypted `VIP 💎` nodes, 17-page modular Web Admin, 24-table SQLite vault, and auto-speed test/sort on refresh.
