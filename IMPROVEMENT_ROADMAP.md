# Improvement Roadmap — `oldman-552/vpn-configs` (`v3.2` Engineering Transformation)

This roadmap sequences improvements strictly by risk priority (**P0 Security & Privacy → P1 Reliability & Intelligence → P2 Monitoring & UX → P3 Scalability, Public API & Documentation**), ensuring every phase is verified by automated tests before advancing.

---

## Priority Matrix & Execution Phases

### P0 — Security, Privacy & Fail-Closed Tunnel Protection (Phases 2, 3, 4)

1. **Phase 2 — Security & Privacy Intelligence Engine (`security_intelligence.py` + Android `SecurityEvaluator.kt`):**
   - Decouple **Performance Score (`0–100`)** and **Reliability Score (`0–100`)** from **Security Assessment (`Verified` / `Partial` / `Unknown` / `Failed`)** and **Privacy Assessment (`Verified` / `Unverified` / `Unknown` / `High Risk`)**.
   - Implement static + dynamic security checks: `allowInsecure` / `insecure` flags, cleartext transport (`security=none`), weak/deprecated Shadowsocks ciphers (`rc4-md5`, `cfb`, `none`), Reality public-key format validation, SNI/host anomalies, unexpected HTTP redirect interception during probing, and cross-run exit-IP/endpoint drift.
   - Assign explicit risk levels (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `UNKNOWN`) and quarantine `CRITICAL` or tampered configurations into `dist/quarantined.json` (secret-redacted) prior to publishing.
   - Enforce strict honesty: anonymous public servers default to `Privacy: Unverified` (never `Verified`), while operator-controlled encrypted VIP nodes with verified TLS/Reality earn `Security: Verified` without claiming impossible zero-knowledge exit guarantees.

2. **Phase 3 — Advanced DNS, IPv6 & WebRTC Leak Protection (`SingBox.kt`, `BahrainVpnService.kt`, `LeakProtectionEngine.kt`, `ClientDiagnosticsEngine.kt`):**
   - **DNS Leak Fix:** Split `sing-box` DNS into direct `"bootstrap"` (strictly for resolving the proxy outbound host) and `"tunnel-dns"` (`"detour": "proxy"` as `dns.final` and `route.default_domain_resolver`), preventing ISP DNS leakage, with automatic TCP/DoH fallback validation across network transitions.
   - **IPv6 Leak Fix:** Always capture `::/0` (`fc00::1/128` + `::/0`) in `VpnService.Builder`. Route IPv6 through the tunnel when `enableIpv6 == true` and supported; otherwise fail-close IPv6 inside `tun0` with `ipv4_only` outbound resolution so zero packets leak over dual-stack physical interfaces.
   - **WebRTC Exposure Awareness:** Replace binary `webRtcLeakProtected` overclaim with honest `WebRtcExposureLevel` diagnostics and actionable browser guidance.
   - **Automated Leak Testing Framework:** Deterministic JUnit/Robolectric tests verifying `SingBox` DNS detour JSON invariants, IPv4-only / IPv6-only / dual-stack route capture, split-tunnel rules, reconnection transitions, and leak diagnostic reports.

3. **Phase 4 — Real Fail-Closed Kill Switch (`KillSwitchController.kt`, `BahrainVpnService.kt`, `BootRestoreReceiver.kt`):**
   - Establish fail-closed `tun0` capture *before* upstream daemon probing when Kill Switch is enabled (`prefs.killSwitch = true` by default).
   - Maintain `tun0` capture across server switches (`SWITCHING_SERVER`), network handoffs (Wi-Fi ↔ 5G), and unrecovered drops (`PROTECTION_ACTIVE`), releasing `tun0` only on explicit user disconnect.
   - Add `BOOT_COMPLETED` / `MY_PACKAGE_REPLACED` receiver to restore protection when `alwaysOnAutoRestore` + `VpnService.prepare(ctx) == null`, detect Android OS `isLockdownEnabled`, and document OS-level boundaries transparently.

---

### P1 — Intelligent Ranking, Proactive Auto-Failover & Source Intelligence (Phases 5, 6, 7)

4. **Phase 5 — Multi-Profile Intelligent Server Ranking (`scoring.py` + `ServerRanker.kt`):**
   - Evaluate latency, jitter, packet loss, download/upload throughput, connection success rate, historical uptime (`runs_alive / runs_seen` + EMA), recent failures, freshness decay, protocol compatibility, and geographic suitability.
   - Support 5 canonical profiles (`BALANCED`, `LOW_LATENCY`, `HIGH_SPEED`, `HIGH_RELIABILITY`, `PRIVACY_AWARE`) while preserving full backward compatibility with existing UI sort keys (`FASTEST_DOWNLOAD` default).

5. **Phase 6 — Proactive 3-Mode Auto-Failover (`SmartFailoverEngine.kt`, `BahrainVpnService.kt`, `Screens.kt`):**
   - Continuous monitoring of RTT, jitter, rolling packet loss, DNS resolution, and process health with adaptive battery-friendly cadence.
   - Three user-selectable modes: **`OFF`** (manual), **`SMART`** (sustained degradation or tunnel drop), and **`AGGRESSIVE`** (proactive switch when a verified candidate beats degraded/suboptimal active node by a hysteresis margin after minimum dwell time).
   - Fail-closed candidate validation (verify candidate daemon + HTTP + DNS on staging port *before* swapping `20808` while keeping `tun0` locked) plus anti-loop cooldowns and rich UI status telemetry.

6. **Phase 7 — Advanced Server Source Intelligence (`collector.py`, `scoring.py`, `source_stats.py`):**
   - Track per-source `new_configs`, `invalid_configs`, `duplicate_configs`, `suspicious_configs`, `content_sha256` change history, collection availability ring-buffer, and automatic **`quarantined`** state for sources exceeding invalid/malicious thresholds.

---

### P2 & P3 — Live Monitoring Dashboard, Public Statistics API v1, QA & Complete Documentation (Phases 8, 9, 10, 11, 12)

7. **Phase 8 — Live Monitoring Dashboard (`web-admin/monitor.html` + `web-admin/monitor.js` on `gh-pages`):**
   - Public, zero-secret, responsive monitoring dashboard with `ETag`/TTL caching, Overview KPIs (collected, active, healthy, failed, quarantined, sources, last run), Performance/Geographic/Protocol/Source analytics, and historical SVG trend charts.
8. **Phase 9 — Android 8-State UX, Battery Optimization & Security Badges (`VpnState.kt`, `AppViewModel.kt`, `Screens.kt`):**
   - Exact tunnel states (`CONNECTED`, `CONNECTING`, `DISCONNECTED`, `RECONNECTING`, `SWITCHING_SERVER`, `CONNECTION_DEGRADED`, `PROTECTION_ACTIVE`, `CONNECTION_FAILED`), adaptive background polling, notification deduplication, and per-server Security/Privacy/Risk badges.
9. **Phase 10 — Read-Only Public Statistics API v1 (`public_api.py` + static `/api/v1/*` on `@data`/`gh-pages`):**
   - Versioned `/api/v1/{servers,servers/{id},statistics,countries,protocols,sources,health,openapi.json}` with pagination, filtering, per-IP rate limiting, `ETag` caching, input validation, and strict secret redaction.
10. **Phases 11 & 12 — Comprehensive Deterministic Test Suites & Full Documentation Suite:**
    - Backend `pytest` + Android `JUnit/Robolectric` suites covering every security, leak, Kill Switch, ranking, failover, source quarantine, and API edge case.
    - Complete, verified documentation (`README.md`, `ARCHITECTURE.md`, `SECURITY.md`, `PRIVACY.md`, `API.md`, `DEPLOYMENT.md`, `TESTING.md`, `TROUBLESHOOTING.md`, `CHANGELOG.md`).
