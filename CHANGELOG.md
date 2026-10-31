# Changelog

## [v2] — 2026-10-31 — Official `bahrain-vpn v2` Production Release (`2.0`)

### Ultra-Fast 500 Batch Scanner, Personalized Top 100, Auto-Purge & Unified `45/30/25` Engine
- **Ultra-Fast Multi-Port `sing-box` Batch Scanner (`SingBox.kt`, `Tester.kt`, `LocalServerIntelligence.kt`)**:
  - Replaced single-URI process spawning during scans with ultra-fast multi-stage `sing-box` batch daemons (`180` local SOCKS5h ports per daemon, `120` parallel tunnel probes over `Dispatchers.IO.limitedParallelism(140)`, censorship-safe `600 ms` TCP SYN raw-IP pre-screen, hard-deadline `http://cp.cloudflare.com/generate_204` probes, instant `SIGKILL` daemon teardown, and recursive bisect fallback), followed by parallel time-boxed `600 KB` HTTPS download throughput verification (`Top 30` on Wi-Fi, `Top 18` on Mobile Data, `Top 15` in background, `15` concurrent streams) and a single atomic SQLite batch commit (`recordBatchScanOutcomes`, `<25 ms` for all 500 configs).
- **Personalized `🏆 Top 100` (`أفضل 100`) & Immediate Dead-Config Auto-Purge (`DeadConfigPurgePolicy`, `Repo.kt`, `AppViewModel.kt`)**:
  - Upgraded the per-network personalized pool from `Top 50` to **`Top 100`** (`WIFI` vs `MOBILE_DATA` strictly isolated, `3h` freshness TTL).
  - Non-working configs are immediately purged from UI state and local exports (`all.txt`, `best.txt`, `sub.txt`) while enforcing **Offline Guard** (never wiping Last Known Good when the device is offline or `>= 15` tested return `0` alive), protecting **`⭐ Favorites`** & **`VIP 💎`**, and keeping `top500.last_valid.json` immutable for SHA-256 delta sync.
- **Unified `45%` Download Throughput / `30%` Stability / `25%` Ping+Jitter Formula**:
  - Aligned `scoring.py`, `central_top500.py`, `community_ranking.py`, `tester.py` (`SPEED_TOP = 300`, `socks`/`socks5`/`http`/`https` `sing-box` converters), `SmartServerSelector.kt`, `LocalServerIntelligence.kt`, and `ServerRanker.kt` with `0.0` speed credit for `0 KB/s` and hard pre-filtering of `allowInsecure=1` / `QUARANTINED` configs.
- **Unified 3-Hour Background Scheduler & Settings Transparency (`WorkScheduler.kt`, `RefreshWorker.kt`, `SettingsScreen.kt`)**:
  - Consolidated background refresh onto a single 3-hour `UniquePeriodicWork` (`bahrain_vpn_quality_refresh_3h`), skipping when VPN or VPN Hotspot is active or battery `<25%`, syncing opt-in Zero-PII community telemetry without duplicate probing, and honoring instant opt-out from **Settings** (`الفحص التلقائي لجودة السيرفرات (كل 3 ساعات)` / `Automatic Server Quality Testing (Every 3h)`).

### Anti-censorship & Platform Enhancements (`v2`)
- **Block-type detection** (DNS / SNI / IP / UDP) on the current network; results bias server ranking per protocol.
- **TLS fragmentation** (sing-box `tls.fragment`): Auto (on when SNI filtering is detected) / Always / Off.
- **Free Cloudflare WARP** fallback: one-time registration, used automatically once when every server fails, or manually.
- **CDN-fronted servers** (WebSocket / gRPC / HTTPUpgrade via Cloudflare) are detected, badged, and preferred under IP blocking.

### New features
- Home-screen **widget** with status and one-tap connect/disconnect.
- **Data usage** statistics by server and by network type (Wi-Fi / mobile).
- Shareable **redacted diagnostic report** (credentials, hostnames and IPs masked).

### Security
- `top500.manifest.json` is signed (ECDSA P-256); the app rejects missing/invalid signatures once a public key is configured.
- Admin panel: strict CSP (`script-src 'self'`), no inline handlers, connections limited to GitHub/jsDelivr.
- CodeQL and Dependabot enabled.

### Removed
- Rotating promo/ad popup and its `promo/` assets.
- First-launch public-server notice (the warning remains in the README).

### Engineering
- `targetSdk 35`, `compileSdk 36`; Gradle 8.14.3, AGP 8.13, Kotlin 2.2; updated androidx/Compose.
- UI split into per-screen files.
- CI validates generated sing-box configs with the shipped sing-box version and surfaces Gradle failure causes.

## [v2] — 2026-10-31 — Official `bahrain-vpn v2` Production Release (`2.0`)

### Official Release Highlights
- **Official `v2` Unified Tag & Release (`versionCode = 2`, `versionName = "2.0"`, Tag `v2`)**:
  - Unified User APK (`com.bahrain.vpnconfigs`), Admin APK (`com.bahrain.vpnadmin`), Enterprise License Bundle (`bundle_release = "2.0"`), Web Admin Console (`web-admin/`), `@data/README.md`, and GitHub Releases under the single official **`v2`** release tag (`Latest`), purging stale legacy releases/tags so zero version conflicts exist across the repository.
- **Full Bilingual APK Support — Arabic Primary (`RTL`) + English Secondary (`LTR`)**:
  - Added `AppI18n.kt` (`:app`), `AdminI18n` (`:admin`), `res/xml/locales_config.xml`, and `res/values-en/strings.xml` across both Android modules.
  - **Arabic (`ar`)** is strictly preserved as the primary default language (`LayoutDirection.Rtl`) on fresh installation, with instant one-tap switching to **English (`en`, `LayoutDirection.Ltr`)** from the top bar (`EN / عربي`) or Settings without restarting the app.
  - Localized all screens (`Home`, `Top 50 / Servers`, `Favorites`, `History`, `Security`, `Enterprise Hub`, `Settings`), foreground VPN notifications, Quick Settings Tile, diagnostics, and rotating promo dialogs.
- **Rootless VPN Hotspot Sharing (`VpnHotspotManager.kt` + `VpnHotspotScreen.kt`)**:
  - Dedicated bilingual `VPN Hotspot` screen honestly distinguishing **`MODE A: FULL VPN HOTSPOT`** (verified OS tethering-over-VPN routing), **`MODE B: PROXY-BASED SHARING`** (LAN-only private-IP listener serving `HTTP/HTTPS CONNECT`, `SOCKS5 TCP/UDP`, `/proxy.pac` auto-config, live client traffic counters, and optional `HTTP Basic` / `SOCKS5 RFC 1929` auth), and **`MODE C: UNSUPPORTED`**.
  - Strict **Fail-Closed Leak Protection**: refuses `0.0.0.0`/WAN binding and immediately severs client streams and returns `503` if the VPN tunnel drops (`BahrainVpnService.onDestroy`/`onRevoke`).
- **Opt-In Community-Based VPN Verification & Iran (`IR`) Top 500 (`CommunityTestingManager.kt` + `community_ranking.py` + `community-worker/`)**:
  - Strictly `OFF` by default with explicit opt-in consent and instant revocation; executes local-only sequential non-proxy tests (`127.0.0.1`) across `VLESS`, `VMess`, `Trojan`, `Shadowsocks`, `Hysteria2`, `TUIC`, `SOCKS5`, and `HTTP(S)` while idle (never during active VPN or active VPN Hotspot).
  - Verifies direct non-VPN network origin (`IR` direct ISP + Cloudflare Worker + D1 edge verification without GPS), enforces multi-device anti-manipulation scoring (`>= 2` independent reporters, median latency/speed, recency decay, strict country isolation), and publishes `@data/iran-top500.{json,txt}`, `iran-results.json`, and `{germany,france,turkey,russia}-top500.json`.
- **Automatic `.ir` / `.ایران` Direct Domain Bypass (Enabled by Default + Settings Toggle)**:
  - Enabled by default (`Prefs.bypassIrDomains = true`), routing all `.ir` and `.xn--mgba3a4f16a` (`.ایران`) domains and TLS/HTTP SNI targets directly over the user's physical network (`direct` outbound + `direct-dns` + `sniff` in `SingBox.kt`) without passing through the VPN server, controllable live from both **Settings** and **Split Tunneling**.
- **Central GitHub Top-500 Pool + Local Android Personalized Top-50 Engine**:
  - GitHub (`central_top500.py`) validates, deduplicates (5 layers), evaluates transport security, and publishes up to 500 untrusted candidate configurations (`top500.{manifest,delta,json,txt}`) with SHA-256 checksums without padding.
  - Android (`LocalServerIntelligence.kt` + `ClientDatabase.kt` WAL SQLite) performs sequential real-tunnel verification (`concurrency = 1`), maintaining strictly isolated **Wi-Fi** (`WIFI`) vs **Mobile Data** (`MOBILE_DATA`) rankings (`TOP_50` + `BACKUP_POOL`) and append-only scan history.
- **Google Play Protect Anti-Dropper Hardening & `RSA-4096` `v1/v2/v3` Release Signing**:
  - Zero `REQUEST_INSTALL_PACKAGES` permission and zero internal `.apk` installer code; `AppUpdateManager` delegates verified `HTTPS` ABI-specific updates (`arm64-v8a`, `x86_64`, `universal`) to the system browser while copying the expected `SHA-256` digest to the clipboard.
  - Automated `PKCS12 RSA-4096` release signing (`APK Signature Scheme v1 + v2 + v3`) verified by `apksigner` in `.github/workflows/apk.yml`.
- **Zero-Leak Tunnel, Two-Tier Kill Switch, 9-State Honest Security & Pure-GitHub Enterprise**:
  - Mandatory in-tunnel DNS (`detour = "proxy"`) and fail-closed `::/0` IPv6 capture (`LeakProtectionEngine.kt`), fail-closed `tun0` protection + OS Lockdown detection (`KillSwitchController.kt`), 9 explicit connection security states (`ConnectionSecurityClassifier.kt`), encrypted `VIP 💎` private nodes (`AES-256-GCM` + `ECDSA P-256`), and anonymized public `/api/v1/*` telemetry (`OpenAPI 3.1.0`).
