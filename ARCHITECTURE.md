# ARCHITECTURE.md — VPN Configs Platform (`bahrain-vpn` v3.2)

## 1. Architectural Overview (100% Pure-GitHub)
`bahrain-vpn` is an automated VPN intelligence, security evaluation, encrypted enterprise licensing, and Android client platform operating **100% within GitHub infrastructure** (`GitHub Actions`, `@data` branch via `jsDelivr`, `GitHub Pages` on `gh-pages`, and `GitHub Releases`).

```
[277 Telegram Channels + 26 GitHub Feeds]
            │  (SSRF-guarded HTTPS + ETag/Last-Modified + SHA-256 delta)
            ▼
   collector.py + security_intelligence.py (Pre-Probe Quarantine)
            │
            ▼
   dedupe.py (5-Layer Canonical Protocol & /24-/48 Subnet Deduplication)
            │
            ▼
   tester.py (Multi-stage Xray-core + sing-box SOCKS5h TLS/DNS/HTTP-204 + Throughput)
            │
            ▼
   scoring.py + security_intelligence.py (Post-Probe Redirect/TLS Audit + 5 Ranking Profiles)
            │
            ▼
   server/build_data.py + public_api.py + enterprise/publisher.py
            │
            ├──► @data branch: alive.json, sub.txt, privacy_aware.txt, quarantined.json,
            │                  api/v1/{servers,statistics,countries,protocols,sources,health,openapi}.json,
            │                  enterprise/bundle.json (ECDSA P-256 signed + AES-256-GCM VIP nodes)
            ├──► gh-pages:     web-admin/index.html (17-page Console) + web-admin/monitor.html (Live Monitor)
            └──► Android APKs: User APK (:app, com.bahrain.vpnconfigs) + Admin APK (:admin, com.bahrain.vpnadmin)
```

---

## 2. Core Subsystems

### 2.1 Cloud Collection, Security Intelligence & Ranking Pipeline
- **`pipeline_security.py`**: Public-IP DNS pinning, SSRF/redirect defense, SHA-256 binary verification, Zip/Tar-Slip protection, secret redaction.
- **`security_intelligence.py`**: Multi-dimensional security & privacy assessment (`SecurityReport`, `MultiDimensionalScore`, `QuarantineRegistry`, `ThreatIntelIndicators`), explicitly separating transport security (`Verified / Partial / Unknown / Failed`) and operator privacy (`Verified / Unverified / Unknown / High Risk`) from speed (`Performance 0–100`, `Reliability 0–100`).
- **`collector.py` & `scoring.py`**: Conditional HTTP (`ETag`/`Last-Modified`), SHA-256 source change detection, automated source quarantine (`SourceHealthRegistry`), EMA longitudinal node history (`NodeHistoryStore`), and 5 ranking profiles (`BALANCED`, `LOW_LATENCY`, `HIGH_SPEED`, `HIGH_RELIABILITY`, `PRIVACY_AWARE`).
- **`public_api.py`**: Exports static `/api/v1/*` JSON endpoints + OpenAPI 3.1.0 specification + longitudinal `state/pipeline_history.json`, and provides a rate-limited/ETag Python HTTP server (`python public_api.py --dist dist --port 8080`).

### 2.2 Android User Application (`android/app` — `v3.2`)
- **Tunnel Stack**: `BahrainVpnService` (`VpnService`) → `hev-socks5-tunnel` (`tun0` + MapDNS `198.18.0.2`) → `sing-box` local SOCKS5/Mixed inbound (`127.0.0.1:20808`).
- **Leak Protection (`LeakProtectionEngine.kt` & `SingBox.kt`)**:
  - Splits DNS into direct `"bootstrap"` (strictly for outbound proxy server hostname resolution) and `"tunnel-dns"` (`"detour": "proxy"`, set as `dns.final` and `route.default_domain_resolver`).
  - Always captures `0.0.0.0/0` and `::/0` into `tun0`; when `enableIpv6` is off, `::/0` is sinkholed inside `tun0` and `sing-box` enforces `ipv4_only` domain strategy to prevent dual-stack IPv6 leaks.
- **Fail-Closed Kill Switch (`KillSwitchController.kt` & `BootRestoreReceiver.kt`)**:
  - Locks `tun0` *before* daemon probing on connect, holds `tun0` in `PROTECTION_ACTIVE` on unexpected failure so traffic never falls back to physical Wi-Fi/cellular, handles seamless network handovers via `ConnectivityManager.NetworkCallback` (`RECONNECTING`), and detects Android OS `isLockdownEnabled`.
- **Proactive Failover (`SmartFailoverEngine.kt` & `VpnState.kt`)**:
  - Policies `OFF`, `SMART`, `AGGRESSIVE` with rolling latency/jitter/loss degradation detection, 25s dwell hysteresis, 120s cooldown isolation, background candidate pre-verification on ports `20901..20904`, adaptive battery-friendly polling (`8s → 15s → 24s`), and 8 verified tunnel states.

### 2.3 Enterprise Licensing, Admin APK & Web Dashboards
- **`enterprise/`**: 24-table normalized SQLite vault (`migrations/001..003`), `Argon2id` + `TOTP 2FA`, `AES-256-GCM` VIP node encryption (`AAD = bahrain-vpn-vip-nodes-v31`), `ECDSA P-256` bundle signing, and honest statistical anomaly detection (`Z-Score`).
- **`web-admin/`**: 17-page encrypted Web Admin (`index.html`) + public read-only Live Infrastructure Monitor (`monitor.html` + `monitor.js`) with 60s caching and zero secret exposure.
