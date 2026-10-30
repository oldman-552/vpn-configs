# Architecture Audit — `oldman-552/vpn-configs`

**Audit Date:** 2026-10-30  
**Audited Baseline:** `main` @ `98535bae30023fb31b591edffb3a2c146aa00b30` (`ULTIMATE VPN ENTERPRISE v3.1`)  
**Methodology:** Direct static and dynamic inspection of Python pipeline modules, Enterprise SQLite/cryptography modules, Web Admin JS modules, Android `:app` / `:admin` Kotlin/JNI sources, and GitHub Actions workflows.

---

## 1. Current System Topology & Component Relationships

The repository operates as a **100% Pure-GitHub four-plane platform** without external VPS dependencies:

1. **Cloud Collection, Validation & Publishing Plane (`server/build_data.py`, `.github/workflows/data.yml`):**
   - Runs every 30 minutes on GitHub Actions.
   - `collector.py` fetches 277 Telegram web-preview channels and 26 curated GitHub feeds via `pipeline_security.safe_fetch_text()` with `ETag` / `If-Modified-Since` caching.
   - `dedupe.py` performs 5-layer normalization and identity hashing (`layer1_exact_id`, `identity_id`, `/24` IPv4 & `/48` IPv6 subnet grouping).
   - `tester.py` spawns isolated `Xray-core` (`vless`, `vmess`, `trojan`, `ss`) and `sing-box` (`hysteria2`, `hy2`, `tuic`) child processes to measure HTTP `204` RTT, multi-probe jitter, Cloudflare `/cdn-cgi/trace` exit country, and bounded download throughput.
   - `scoring.py` updates longitudinal `NodeHistoryStore` (`state/node_history.json`) and `SourceHealthRegistry` (`state/source_state.json`), then publishes `alive.json`, `sub.txt`, `best100.txt`, `reliable.txt`, `low_latency.txt`, `high_throughput.txt`, `protocols/*.txt`, `countries.json`, `source_health.json`, and `meta.json` atomically to the orphan `@data` branch with `Last-Known-Good` fallback.

2. **Enterprise Licensing, Audit & Telemetry Plane (`enterprise/`, `.github/workflows/enterprise.yml`):**
   - Normalized 24-table SQLite database (`migrations/001..003`) encrypted at rest inside `enterprise_vault.enc.json` (`AES-256-GCM`) with chained `SHA-256` `admin_audit_logs`.
   - `publisher.py` exports zero-knowledge subscriber license envelopes (`PBKDF2-HMAC-SHA256` 120k + `AES-256-GCM`), encrypted VIP private nodes (`vip_nodes_enc_b64`), remote config, and per-ABI APK update descriptors signed with `ECDSA P-256` into `@data/enterprise/bundle.json`.

3. **Android Subscriber Client (`android/app/`, `com.bahrain.vpnconfigs`):**
   - Uses Android `VpnService` + `hev-socks5-tunnel` (`tun0` + `MapDNS` `198.18.0.2:53`) forwarding into local `libsingbox.so` (`127.0.0.1:20808`).
   - Includes `ServerRanker`, `SmartFailoverEngine`, `EnterpriseLicenseGuard`, `AppUpdateManager`, and `ClientDiagnosticsEngine`.

4. **Governance Clients (`android/admin/` & `web-admin/` on `gh-pages`):**
   - Standalone `com.bahrain.vpnadmin` APK (`TOTP 2FA` + `ECDSA P-256`) and 17-page modular WebCrypto dashboard (`web-admin/modules/*.js`).

---

## 2. Verified Architectural Weaknesses & Gaps

| ID | Subsystem | Finding Verified in Source Code | Impact |
|---|---|---|---|
| **ARCH-01** | `scoring.py` & `ServerRanker.kt` | **Performance and Security are conflated into a single scalar score.** A fast node with `allowInsecure=1` or `security=none` (plaintext VLESS/VMess) can achieve a top composite score (`>90/100`) with zero visibility into transport security or privacy risk. | Users and auto-ranking may select MITM-vulnerable or plaintext proxies over TLS/Reality nodes. |
| **ARCH-02** | `BahrainVpnService.kt` (`handleConnect`) | **Fail-open connection lifecycle & missing Kill Switch.** `startTunLayer()` is invoked *after* `singBox.startDaemon()` and HTTP delay probing (`4–16s`), and `teardownInternal()` closes `tun0` immediately when failover exhausts candidates. | Ordinary app traffic flows over the physical ISP interface during connection startup, error recovery, and drop events. |
| **ARCH-03** | `SingBox.kt` (`buildConfig`) | **Un-detoured DNS resolver configuration.** `dns.final` is bound to `"bootstrap"` (`1.1.1.1` direct without `"detour": "proxy"`). Because `BahrainVpnService` excludes its own package from `tun0`, `sing-box` sends DNS queries directly over the physical network. | ISP/local network observers can see domain queries even while VPN tunnel is `CONNECTED`. |
| **ARCH-04** | `BahrainVpnService.kt` (`startTunLayer`) | **Unprotected IPv6 route when `enableIpv6 == false`.** `addRoute("::", 0)` is omitted when IPv6 tunneling is disabled, leaving dual-stack mobile/Wi-Fi IPv6 routes open outside `tun0`. | Dual-stack apps bypass the VPN completely over native IPv6. |
| **ARCH-05** | `VpnState.kt` (`VpnPhase`) | **Coarse state machine (5 states).** Only `DISCONNECTED`, `CONNECTING`, `CONNECTED`, `SWITCHING`, and `ERROR` exist; there is no distinction between `RECONNECTING`, `SWITCHING_SERVER`, `CONNECTION_DEGRADED`, `PROTECTION_ACTIVE` (Kill Switch engaged), and `CONNECTION_FAILED`. | UI can either under-report degradation or fail to show active fail-closed protection. |
| **ARCH-06** | `SmartFailoverEngine.kt` & `BahrainVpnService.kt` | **Reactive-only failover without policy modes or hysteresis.** Failover triggers only on complete dual-probe failure; sustained latency/jitter/packet-loss degradation is not proactively mitigated, and users cannot select `OFF` / `SMART` / `AGGRESSIVE` policies. | Degraded tunnels (e.g., 1,800 ms RTT or 40% loss) stay pinned indefinitely until total drop. |
| **ARCH-07** | `collector.py` & `scoring.py` (`SourceHealthRegistry`) | **Incomplete per-source anomaly & quarantine tracking.** Tracks `raw_count` and `valid_count`, but does not track per-source `new_configs`, `duplicate_configs`, `invalid_configs`, `suspicious_configs`, content-hash change detection, or automatic quarantine of poisoned feeds. | A compromised upstream source injecting `allowInsecure=1` or malformed payloads stays `"active"`. |
| **ARCH-08** | `Converters.kt` vs `dedupe.py` / `tester.py` | **Duplicated URI security inspection.** Transport/TLS parameter inspection exists separately in Python (`tester.py`/`dedupe.py`) and Kotlin (`Converters.kt`) without a shared canonical security assessment contract in `alive.json`. | Android client lacks server-verified TLS/cipher/redirect risk metadata unless re-derived locally. |
| **ARCH-09** | Public Monitoring & Telemetry Access | **No read-only public monitoring dashboard or versioned REST/JSON API (`/api/v1/*`).** `web-admin/` requires admin credentials to unlock vault views; public read-only health, protocol, country, and historical trend analytics are not exposed via a clean versioned API + public monitor view. | Operators and integrators lack sanitized, rate-limited, paginated observability endpoints. |

---

## 3. Preserved Architectural Strengths (Must Not Regress)

1. **Zero-Secret Client Isolation:** `Repo.kt` encapsulates upstream CDN URLs; User APK contains zero GitHub PATs or private signing keys (enforced in `.github/workflows/apk.yml`).
2. **Atomic `Last-Known-Good` Publishing:** `server/build_data.py` refuses to overwrite `@data` outputs when alive count drops below `MIN_ALIVE`.
3. **Native `hev-socks5-tunnel` + `libsingbox.so` Architecture:** Closing `ParcelFileDescriptor` strictly *after* `TProxyStopService()` prevents native file-descriptor races on Android 10–15 (`minSdk = 29`).
4. **Enterprise Cryptographic Envelopes & VIP Isolation:** `ECDSA P-256` canonical JSON signing and `AES-256-GCM` VIP node encryption remain intact and backward-compatible.
