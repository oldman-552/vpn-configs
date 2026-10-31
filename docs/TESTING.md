# TESTING.md — Automated Verification & QA Guide (`v2`)

## 1. Test Suites Overview

### 1.1 Python Backend, Top-500, Community Ranking, Historical Intelligence, Security, Enterprise & API Suite (`pytest`)
**56 deterministic tests across 6 test modules** (zero live internet dependency during tests):
- **`tests/test_all.py` (29 tests)**: SSRF & redirect validation, SHA-256 verification, safe archive extraction, secret redaction, 5-layer deduplication, `/24` & `/48` diversity, EMA node scoring (`45/30/25`), longitudinal source health, and Last-Known-Good (`LKG`) build fallback.
- **`tests/test_community_and_protocols.py` (5 tests)**: `socks://`/`socks5://`/`http://`/`https://` explicit-port proxy URI parsing, `sing-box` outbound conversion & secret redaction, unified `45/30/25` speed-first scoring (`0.0` unmeasured speed credit + hard `allowInsecure=1` exclusion), strict `IR` multi-device community ranking, and incremental Worker export sync.
- **`tests/test_enterprise_platform.py` (7 tests)**: 24-table SQLite migrations, `Argon2id` + `TOTP 2FA`, brute-force lockout, hash-chained audit log integrity, 48h anti-tamper trial lifecycle, `bundle_release == "2.0"` ECDSA bundle verification, encrypted `VIP 💎` node isolation, encrypted backups, and `Z-Score` anomaly engine.
- **`tests/test_security_ranking_and_api.py` (6 tests)**: Transport security vs. speed separation, `allowInsecure=1` penalty, broken cipher/port quarantine (`QuarantineRegistry`), 5 ranking profiles (`HIGH_SPEED`, `LOW_LATENCY`, `HIGH_RELIABILITY`, `BALANCED`, `PRIVACY_AWARE`), source quarantine, and `/api/v1/*` (`OpenAPI 3.1.0`, `ETag`/`304`, `400`, `429`, zero secret leakage).
- **`tests/test_historical_intelligence.py` (5 tests)**: Persistent `history.sqlite3` migrations (`001..002`), canonical `server_id` stability across remark edits, `24h`/`7d`/`30d`/`90d` availability & latency percentiles, `OBSERVED`/`ESTIMATED`/`UNKNOWN` honesty, source-operator independence, and auto-suppression recovery.
- **`tests/test_top500_architecture.py` (4 tests)**: Central Top-500 cap without padding (`<= 500`), `ANDROID_LOCAL_ONLY` authority boundary, SHA-256 manifest + incremental `top500.delta.json` verification, and deterministic ranking order.

Run locally:
```bash
.venv/bin/pytest -v
```

### 1.2 Web Dashboards Syntax & Secret Audit (`node --check`)
Verifies all JavaScript modules in `web-admin/` (including `app.js`, `monitor.js`, and `modules/*.js`):
```bash
for jsf in web-admin/*.js web-admin/modules/*.js; do node --check "$jsf"; done
```

### 1.3 Android Robolectric & JUnit Test Suites (`34 tests` in `.github/workflows/apk.yml`)
Executed automatically on every Android PR and `main` build via `./gradlew testReleaseUnitTest :admin:testReleaseUnitTest`:
- **`AndroidVpnAuditTest.kt` (6 tests)**: Default `FASTEST_DOWNLOAD` sort, 5 sort modes without inventing speed from ping, staleness decay, active-session preservation, ETag/304 + offline fallback in `Repo`, multi-protocol `SingBox` outbound generation, OpSec redaction, and 5-ad promo rotation.
- **`CommunityAndHotspotTest.kt` (4 tests)**: `SOCKS5`/`HTTP`/`HTTPS` `sing-box` outbound generation & honest TLS security rating; opt-in-only `CommunityTestingManager` (`OFF` default, VPN-interference rejection, privacy-minimal upload with zero URIs/passwords, Hotspot mutual exclusion, instant consent revocation); `VpnHotspotProxyServer` private-IP bind guard, `PAC` auto-config, `HTTP Basic` + `SOCKS5 RFC 1929` auth, remote tunnel DNS forwarding, and 100% Fail-Closed `503` leak block on VPN drop; and `Repo.loadRemote("iran_community")`.
- **`EnterpriseAndroidTest.kt` (6 tests)**: Official `v2` (`versionCode = 2`, `versionName = "2.0"`) Play Protect Zero-Dropper & safe HTTPS browser updater, **Arabic-primary (`RTL`) default + live English (`LTR`) language toggle verification**, ECDSA P-256 signature verification, zero-knowledge PBKDF2+AES-GCM login, 48h monotonic clock trial expiry, daily quota enforcement, encrypted `VIP 💎` lifecycle, and `SmartFailoverEngine`.
- **`LeakKillSwitchAndSecurityTest.kt` (5 tests)**: `SecurityEvaluator` honesty, detoured `"tunnel-dns"` (`"detour": "proxy"`) + mandatory `::/0` IPv6 sinkhole capture, **automatic `.ir` / `.ایران` direct domain bypass (`Prefs.bypassIrDomains = true` default + `direct-dns` + `sniff` + Settings toggle disable)**, fail-closed `KillSwitchController` states, and dwell-guarded proactive failover.
- **`SmartVpnUpgradeTest.kt` (6 tests)**: WAL SQLite `ClientDatabase` migrations, `server_id`-anchored Favorites & custom groups, searchable/paginated session history, 7-factor explainable `SmartServerSelector`, 9-state `ConnectionSecurityClassifier`, and battery-aware adaptive probe intervals.
- **`Top500AndPersonalizedTop50Test.kt` (6 tests)**: Top-500 manifest/delta SHA-256 verification, rollback protection, last-known-valid dataset recovery, strict **Wi-Fi (`WIFI`) vs Mobile Data (`MOBILE_DATA`)** personalized **Top 100** + `BACKUP_POOL` isolation, multi-port batch Stage 1 + Stage 2 speed probing, `DeadConfigPurgePolicy` (auto-purge + Offline Guard + Favorites/VIP protection + per-network ledger), unified `45/30/25` weights + `allowInsecure=1` exclusion, and 3-hour `WorkScheduler` opt-out.
- **`SingBoxConfigExportTest.kt` (4 tests)**: Exports `fragment-vless-ws`, `fragment-trojan-irbypass`, `warp`, `warp-irbypass`, and `batch-multi-outbound` configs validated against `sing-box check -c` in CI.
- **`AdminAppUnitTest.kt` (2 tests)**: Admin APK `v2` (`bundle_release == "2.0"`) crypto, TOTP 2FA, and encrypted vault verification.
