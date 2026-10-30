# CHANGELOG.md

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
