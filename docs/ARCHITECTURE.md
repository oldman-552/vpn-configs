# ARCHITECTURE.md — Unified Platform Architecture (`bahrain-vpn` Official `v2`)

## 1. Architectural Overview (100% Pure-GitHub — Release `v2`)
`bahrain-vpn` (`v2`, `versionName = "2.0"`, `versionCode = 2`) is an end-to-end VPN intelligence, security classification, encrypted enterprise licensing, and bilingual Android client platform operating **100% within GitHub infrastructure** (`GitHub Actions`, `@data` branch via `jsDelivr`, `GitHub Pages` on `gh-pages`, and `GitHub Releases` tag **`v2`**).

```
[277 Telegram Channels + 26 Curated GitHub Feeds]
            │  (SSRF-guarded HTTPS + ETag/Last-Modified + SHA-256 delta)
            ▼
   collector.py + security_intelligence.py (Pre-Probe Quarantine)
            │
            ▼
   dedupe.py (5-Layer Canonical Protocol, Server ID & /24-/48 Subnet Deduplication)
            │
            ▼
   tester.py (Multi-stage Xray-core + sing-box SOCKS5h TLS/DNS/HTTP-204 + Throughput)
            │
            ▼
   scoring.py + central_top500.py + community_ranking.py + historical_db.py
            │
            ▼
   server/build_data.py + public_api.py + enterprise/publisher.py
            │
            ├──► @data branch: top500.{manifest,delta,json,txt}, iran-top500.{json,txt}, iran-results.json,
            │                  alive.json, sub.txt, best100.txt, privacy_aware.txt, reliable_sub.txt,
            │                  servers-{current,history,performance,statistics}.json,
            │                  api/v1/{servers,statistics,countries,protocols,sources,health,openapi}.json,
            │                  enterprise/bundle.json (v2 / "2.0" — ECDSA P-256 signed + AES-256-GCM VIP nodes)
            ├──► gh-pages:     web-admin/index.html (17-page Encrypted Console v2) + monitor.html (Live Monitor v2)
            └──► GitHub Releases (v2 ONLY):
                               • User APK (:app, com.bahrain.vpnconfigs, versionCode = 2, Bilingual AR Primary + EN)
                               • Admin APK (:admin, com.bahrain.vpnadmin, versionCode = 2, Bilingual AR Primary + EN)
                               • SHA256SUMS.txt (RSA-4096 APK Signature Scheme v1 + v2 + v3)
```

---

## 2. Core Subsystems (`v2`)

### 2.1 Cloud Candidate Pool (`Top 500`), Historical Intelligence & Security Pipeline
- **`central_top500.py`**: Publishes **up to 500 qualified untrusted candidate servers** (`top500.json`, `top500.txt`, `top500.manifest.json`, `top500.delta.json`) with SHA-256 checksums without padding, explicitly enforcing `"personalized_top50_authority": "ANDROID_LOCAL_ONLY"`.
- **`historical_db.py`**: Persistent SQLite WAL longitudinal intelligence database (`state/history.sqlite3`, `migrations/history/001..002.sql`) computing `24h`, `7d`, `30d`, and `90d` availability and performance percentiles with explicit `OBSERVED / ESTIMATED / UNKNOWN` basis and 10 failure categories.
- **`pipeline_security.py` & `security_intelligence.py`**: Public-IP DNS pinning, SSRF/redirect defense, SHA-256 binary verification, Zip/Tar-Slip protection, secret redaction, and independent transport security vs. operator privacy classification (`QuarantineRegistry`).
- **`collector.py`, `dedupe.py` & `scoring.py`**: Conditional HTTP (`ETag`/`Last-Modified`), source quarantine (`SourceHealthRegistry`), 5-layer canonical deduplication, and 5 ranking profiles (`BALANCED`, `LOW_LATENCY`, `HIGH_SPEED`, `HIGH_RELIABILITY`, `PRIVACY_AWARE`).
- **`public_api.py`**: Exports static anonymized `/api/v1/*` JSON endpoints + `OpenAPI 3.1.0` specification (`api/v1/openapi.json`) + optional local rate-limited HTTP server.

### 2.2 Android User Application (`android/app` — Official `v2`, `versionCode = 2`)
- **Bilingual UI (`AppI18n.kt` + `res/xml/locales_config.xml`)**:
  - **Arabic (`ar`, `LayoutDirection.Rtl`)** is strictly the primary default language on fresh install (`Prefs.appLanguage = "ar"`), with instant one-tap live switching to **English (`en`, `LayoutDirection.Ltr`)** across all screens, foreground notifications, and Quick Settings Tile without restarting.
- **Local Personalized Top-100 Engine, Full-Speed Background Scan & Persistent Lists (`ScanRuntimeCoordinator.kt`, `ServerScanForegroundService.kt`, `LocalServerIntelligence.kt`, `DeadConfigPurgePolicy`, `WorkScheduler.kt` & `ClientDatabase.kt` WAL SQLite)**:
  - Verifies `top500.manifest.json` / `top500.delta.json` (`ETag` + `ECDSA/SHA-256` + rollback protection + last-known-valid recovery), runs ultra-fast multi-port `sing-box` batch scans + `600 KB` download throughput probes (`45%` Download / `30%` Stability / `25%` Ping+Jitter, continuing at full speed when switching apps via `ServerScanForegroundService`, and running automatically every **4 hours** saved directly to lists when idle), persists full per-network results across app restarts (`local_results_WIFI.json` / `local_results_MOBILE_DATA.json`), immediately purges non-working configs (preserving Offline Guard + `⭐ Favorites` + `VIP`), and maintains strictly isolated **Wi-Fi (`WIFI`)** vs **Mobile Data (`MOBILE_DATA`)** **Top 100** + `BACKUP_POOL` rankings.
- **Tunnel Stack & Automatic `.ir` Direct Domain Bypass (`BahrainVpnService.kt` & `SingBox.kt`)**:
  - `BahrainVpnService` (`VpnService`) → `hev-socks5-tunnel` (`tun0` + `MapDNS 198.18.0.2`) → `sing-box 1.14.4` local `mixed` inbound (`127.0.0.1:20808`).
  - **Automatic `.ir` / `.ایران` Direct Routing (`Prefs.bypassIrDomains = true` by default + Settings toggle)**: Configures `sing-box` with protocol sniffing (`{"action": "sniff"}`), `domain_suffix: [".ir", ".xn--mgba3a4f16a"]` routed directly via `"outbound": "direct"` and resolved via `"direct-dns"` (outside the VPN proxy), while keeping 100% of non-`.ir` traffic and DNS detoured inside the encrypted VPN tunnel.
  - **Per-App Split Tunneling (`AppsSplitScreen` & `InstalledApps.kt`)**: Supports both *Bypass VPN for Selected Apps* and *VPN Only for Selected Apps*.
- **Zero-Leak DNS/IPv6, Fail-Closed Kill Switch & 9-State Security (`LeakProtectionEngine.kt`, `KillSwitchController.kt`, `ConnectionSecurityClassifier.kt`)**:
  - Splits DNS into `"bootstrap"` (VPN endpoint resolution), `"tunnel-dns"` (`"detour": "proxy"`, set as `dns.final`), and optional `.ir`-scoped `"direct-dns"`.
  - Always captures `0.0.0.0/0` and `::/0` into `tun0`, locks `tun0` before daemon probing, holds `PROTECTION_ACTIVE` on unexpected drops, and honestly distinguishes App-level TUN block from Android OS `isLockdownEnabled` across 9 explicit security states.
- **Rootless VPN Hotspot & Opt-In Community Verification (`hotspot/VpnHotspotManager.kt`, `community/CommunityTestingManager.kt`, `community_ranking.py`, `community-worker/`)**:
  - **Rootless VPN Hotspot**: Explicitly distinguishes `MODE A: FULL VPN HOTSPOT`, `MODE B: PROXY-BASED SHARING` (private LAN IPv4 listener serving `HTTP/HTTPS CONNECT`, `SOCKS5 TCP/UDP`, and `/proxy.pac` with optional authentication), and `MODE C: UNSUPPORTED`, enforcing fail-closed disconnection whenever the VPN tunnel drops.
  - **Community VPN Verification (Iran `IR` & Global)**: Opt-in (`OFF` by default), local-only sequential probing across `VLESS`, `VMess`, `Trojan`, `Shadowsocks`, `Hysteria2`, `TUIC`, `SOCKS5`, and `HTTP(S)` without ever using phones as proxies/relays; verifies non-VPN origin country (`IR` direct ISP + optional free-tier Cloudflare Worker + D1 edge gatekeeper) and publishes multi-device trust-scored `@data/iran-top500.{json,txt}`, `iran-results.json`, and `{germany,france,turkey,russia}-top500.json`.
- **Google Play Protect Compliance & `RSA-4096` Release Signing (`AppUpdateManager.kt` & `apk.yml`)**:
  - Zero `REQUEST_INSTALL_PACKAGES` permission and zero internal `.apk` installer code; delegates verified `HTTPS` ABI-specific updates (`arm64-v8a`, `x86_64`, `universal`) to the system browser with `SHA-256` clipboard copy, signed with `PKCS12 RSA-4096` (`APK Signature Scheme v1 + v2 + v3`).

### 2.3 Pure-GitHub Enterprise Licensing, Admin APK & Web Dashboards (`v2`)
- **`enterprise/`**: 24-table normalized SQLite vault (`enterprise/migrations/001..003`), `Argon2id` + `TOTP 2FA`, `AES-256-GCM` VIP node encryption, `ECDSA P-256` signed `enterprise/bundle.json` (`bundle_release = "2.0"`), and `Z-Score` anomaly detection.
- **`android/admin/` (`com.bahrain.vpnadmin`, `versionCode = 2`)**: Standalone bilingual (`AR` primary + `EN`) R8-shrunk Admin APK managing subscribers, devices, and encrypted `VIP` nodes over `api.github.com`.
- **`web-admin/`**: 17-page browser-encrypted Web Admin Console (`index.html`) + public read-only Live Infrastructure Monitor (`monitor.html` + `monitor.js`) hosted on `gh-pages`.
