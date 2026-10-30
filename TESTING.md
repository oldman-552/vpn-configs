# TESTING.md — Automated Verification & QA Guide

## 1. Test Suites Overview

### 1.1 Python Backend, Security, Enterprise & API Suite (`pytest`)
42 deterministic tests across 3 test modules (zero live internet dependency during tests):
- **`tests/test_all.py` (29 tests)**: SSRF & redirect validation, SHA-256 verification, safe archive extraction, secret redaction, 5-layer deduplication, `/24` & `/48` diversity, EMA node scoring, longitudinal source health, and Last-Known-Good (`LKG`) build fallback.
- **`tests/test_enterprise_platform.py` (7 tests)**: 24-table SQLite migrations, `Argon2id` + `TOTP 2FA`, brute-force lockout, hash-chained audit log integrity, 48h anti-tamper trial lifecycle, encrypted `VIP 💎` node isolation, encrypted backups, and `Z-Score` anomaly engine.
- **`tests/test_security_ranking_and_api.py` (6 tests)**:
  - Phase 2 security vs speed separation, `allowInsecure=1` penalty, broken cipher/port quarantine (`QuarantineRegistry`).
  - Phase 5 multi-profile ranking (`HIGH_SPEED`, `LOW_LATENCY`, `HIGH_RELIABILITY`, `BALANCED`, `PRIVACY_AWARE`) and freshness decay.
  - Phase 7 source-level quarantine on excessive invalid/suspicious ratio + SHA-256 content change tracking.
  - Phase 10 static `/api/v1/*` export, live HTTP server filtering/pagination, `ETag`/`304`, `400` validation, `429` token-bucket rate limiting, and zero secret/raw-URI leakage.

Run locally:
```bash
.venv/bin/pytest -v
```

### 1.2 Web Dashboards Syntax & Secret Audit (`node --check`)
Verifies all JavaScript modules in `web-admin/` (including `monitor.js` and `modules/*.js`):
```bash
for jsf in web-admin/*.js web-admin/modules/*.js; do node --check "$jsf"; done
```

### 1.3 Android Robolectric & Unit Test Suites (`apk.yml`)
Executed automatically on every Android PR/push/tag via `./gradlew testReleaseUnitTest`:
- **`AndroidVpnAuditTest.kt`**: Default `FASTEST_DOWNLOAD` sort, 5 sort modes without inventing speed from ping, staleness decay, active-session preservation on re-sort, ETag/304 + offline cache fallback in `Repo`, multi-protocol `SingBox` outbound generation, OpSec redaction, and 5-ad promo rotation.
- **`EnterpriseAndroidTest.kt`**: ECDSA P-256 signature verification, zero-knowledge PBKDF2+AES-GCM login, 48h monotonic clock trial expiry, daily quota enforcement, real speed test engine, Split-ABI updater, encrypted `VIP 💎` lifecycle, and `SmartFailoverEngine` ranking/cooldown.
- **`LeakKillSwitchAndSecurityTest.kt`**:
  - Phase 2 `SecurityEvaluator` honesty (`Unverified` public privacy vs `Verified` VIP, `allowInsecure=1` `Failed`/`HIGH`, SSH port quarantine).
  - Phase 3 `SingBox` detoured `"tunnel-dns"` (`"detour": "proxy"`), private-DNS sanitization (`192.168.1.1` → `1.1.1.1`), mandatory `::/0` IPv6 sinkhole capture, and honest WebRTC split-tunnel/browser exposure guidance.
  - Phase 4 `KillSwitchController` fail-closed pre-probe lock, `PROTECTION_ACTIVE` hold on unexpected tunnel drop, and all 8 `VpnPhase` state flags.
  - Phase 5 & 6 `PRIVACY_AWARE` ranking, `OFF`/`SMART`/`AGGRESSIVE` failover modes, 25s dwell hysteresis anti-oscillation, `CRITICAL`-risk candidate exclusion, and adaptive polling intervals.
- **`AdminAppUnitTest.kt`**: Admin APK crypto, TOTP, and vault envelope verification.
