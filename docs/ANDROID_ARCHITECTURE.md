# Android Client Architecture (`v2` — Bilingual AR/EN + Rootless VPN Hotspot + Community Verification + Central Top 500 + Local Personalized Top 100)

## 0. Mandatory Responsibility Separation
- **GitHub (`central_top500.py` & `community_ranking.py` -> `@data/top500.{manifest,delta,}.json` & `iran-top500.{json,txt}`):** Collect -> Validate -> Hard-Exclude `allowInsecure=1` -> Normalize -> Deduplicate -> Assign `server_id` & `config_fingerprint` -> Preliminary + `600 KB` Speed Check (`45%` Download / `30%` Stability / `25%` Latency+Jitter) -> Publish **up to 500** untrusted candidate configurations with SHA-256 checksums and optional incremental deltas. GitHub **never** selects a user's personalized Top 100.
- **Android (`Repo.kt` + `ScanRuntimeCoordinator.kt` + `ServerScanForegroundService.kt` + `LocalServerIntelligence.kt` + `WorkScheduler.kt` + `ClientDatabase.kt`):** Download & verify Top-500 dataset every **4 hours** (ETag + ECDSA/SHA-256 + rollback protection + last-known-valid recovery) -> Censorship-safe `600 ms` TCP SYN raw-IP pre-screen + probe in ultra-fast multi-port `sing-box` batches (`180` ports/daemon, `120` Stage-1 / `15` Stage-2 concurrency on `Dispatchers.IO.limitedParallelism(140)` + zero-barrier warm-port dispatch + bisect fallback, kept at full unthrottled speed in background via `ScanRuntimeCoordinator` & `ServerScanForegroundService`) + time-boxed `600 KB` real HTTPS download speed + single atomic SQLite batch commit (`recordBatchScanOutcomes`) -> Immediately purge dead configs (with Offline Guard + `⭐ Favorites` / `VIP` protection) -> Persist per-network scan results across app restarts (`local_results_WIFI.json` / `local_results_MOBILE_DATA.json` + SQLite) -> Select Personalized **Top 100** + **Qualified Backup Pool** (`local_network_rankings` + `local_ranking_history`).

## 1. High-Level Module & Package Layout
The Android application (`:app`, `com.bahrain.vpnconfigs`, `versionCode = 2`, `versionName = "2.0"`, `minSdk = 29`, `targetSdk = 35`, `compileSdk = 36`) follows a reactive unidirectional architecture powered by Kotlin Coroutines, `StateFlow`, Jetpack Compose Material 3 with **Arabic (`RTL`) as the primary default language and instant live switching to English (`LTR`) via `AppI18n.kt`**, embedded SQLite (`WAL`), `sing-box`, and `hev-socks5-tunnel`.

```
com.bahrain.vpnconfigs
├── MainActivity.kt                 # 6-destination NavigationBar + Lifecycle foreground observer + VPN permission flow
├── data/
│   ├── Repo.kt                     # Sole network/CDN boundary (ETag/304, Top-500 SHA-256 delta sync, bundle)
│   ├── ManifestSignature.kt        # ECDSA P-256 verification of top500.manifest.json(.sig)
│   ├── Prefs.kt                    # User settings & flags (Arabic primary default "ar", bypassIrDomains = true default)
│   └── ClientDatabase.kt           # WAL SQLite v3 (network rankings, scan history, sessions, favorites, telemetry)
├── engine/
│   ├── Converters.kt               # Multi-protocol URI parser, sing-box config builder, stableServerId(), maskedEndpointLabel()
│   ├── LocalServerIntelligence.kt  # Multi-port sing-box batch scanner, 45/30/25 scorer & Wi-Fi vs Mobile Data Top-100 engine
│   ├── SecurityEvaluator.kt        # Pre-connect TLS/Reality/cipher audit & quarantine gate
│   ├── ServerRanker.kt             # List sorting modes (FASTEST_DOWNLOAD, LOWEST_LATENCY, MOST_STABLE, PRIVACY_AWARE, ...)
│   ├── SmartServerSelector.kt      # Weighted 7-factor explainable selector + cooldown + confidence + fallback
│   ├── SingBox.kt & Socks.kt       # Native daemon lifecycle, .ir/.ایران direct bypass routing, & real HTTP/SOCKS5 probes
│   ├── Tester.kt                   # Bounded-concurrency batch & single-server verifier
│   ├── CensorshipProbe.kt          # DNS/SNI/IP/UDP block-type detection -> per-protocol ranking bonus
│   ├── AntiCensorship.kt           # TlsFragment (sing-box tls.fragment) + CdnDetector (Cloudflare-fronted configs)
│   └── WarpManager.kt              # Free Cloudflare WARP registration + WireGuard endpoint (warp:// fallback)
├── vpn/
│   ├── BahrainVpnService.kt        # Foreground VpnService, TUN builder, parallel failover, session & telemetry recorder
│   ├── VpnState.kt                 # Immutable VpnStatus StateFlow + 30-sample live traffic history ring + event timeline
│   ├── AutoReconnectManager.kt     # 2s->5s->10s->20s->40s->cap exponential backoff + jitter + single-flight guard
│   ├── NetworkAwarenessMonitor.kt  # Modern ConnectivityManager + NetworkCapabilities (Wi-Fi/Cellular/Ethernet/Metered)
│   ├── KillSwitchController.kt     # Fail-closed TUN hold vs OS VpnService.isLockdownEnabled + system settings intent
│   ├── LeakProtectionEngine.kt     # Dual-stack ::/0 capture + MapDNS 198.18.0.2 + DoH sanitization
│   ├── ConnectionSecurityClassifier.kt # 9-state honest security & DNS/IPv6 leak classifier
│   ├── ResourceAndBatteryMonitor.kt    # Real CPU/Heap/PSS telemetry & foreground/background adaptive polling
│   ├── QuickTileService.kt         # Quick Settings tile (also refreshes the home-screen widget)
│   └── VpnWidgetProvider.kt        # Home-screen widget: status + one-tap toggle
├── hotspot/
│   └── VpnHotspotManager.kt        # Rootless LAN-only VPN Hotspot (Mode A/B/C, HTTP/SOCKS5/PAC, Fail-Closed guard)
├── community/
│   └── CommunityTestingManager.kt  # Opt-in non-proxy sequential tester, direct IP origin verifier & secret-free uploader
├── enterprise/                     # ECDSA P-256 license verification, AES-256-GCM VIP nodes, diagnostics, ABI updater
└── ui/
    ├── AppViewModel.kt             # State holder bridging Repo, Tester, ClientDatabase, and SmartServerSelector
    ├── HomeScreen.kt               # ConnectHomeScreen
    ├── ServersScreen.kt            # ServersListScreen, ServerCard
    ├── AppsSplitScreen.kt          # AppsSplitScreen
    ├── SettingsScreen.kt           # SettingsAndExportScreen
    ├── ScreenComponents.kt         # Shared composables (StatusPill, badges, rows)
    ├── ConnectionMonitorCard.kt    # SmartSelectionSummaryCard + RealTimeConnectionMonitorCard (live Canvas chart)
    ├── FavoritesScreen.kt          # Grouped, custom-named, performance-ranked Favorites UI
    ├── ServerHistoryScreen.kt      # Paginated, searchable, date-filtered SQLite Session History UI
    ├── SecurityStatusScreen.kt     # Dedicated 9-state Security, DNS/IPv6 Leak, Kill Switch & Battery UI
    ├── UsageStatsCard.kt           # Data usage by server and network type
    ├── enterprise/                 # Diagnostics (shareable redacted report), BlockingDetectionCard, AntiCensorshipToolsCard
    └── EnterpriseScreens.kt        # Enterprise Hub, Speed Test MandatoryLoginGateDialog
```

## 2. Six Primary Navigation Destinations
1. **الاتصال (`Home`):** One-tap Connect ring, Smart Server Selection explainability card (primary + fallback + confidence + reasons), Real-Time Connection Monitor (live download/upload Canvas chart, duration, verified exit IP/country, RTT/jitter/loss, event log), and active server quick actions.
2. **السيرفرات (`Servers`):** Country filter chips, multi-mode sort bar, search, clipboard import, 5-state latency/speed badges, and per-server favorite star.
3. **المفضّلة (`Favorites`):** Persistent `server_id`-anchored favorites surviving remark updates, custom naming, custom/preset groups (`عام`, `العمل`, `الألعاب`, `البث`), availability dot, local success/speed stats, and 1-tap connect.
4. **السجل (`History`):** Persistent SQLite session log with text search, `24h`/`7d`/`30d` date filters, performance/latency/duration sorting, pagination, configurable retention (`7`/`30`/`90` days), 1-tap reconnect, and individual/full deletion.
5. **الأمان (`Security`):** Live 9-state security classification, transport encryption & operator trust disclosure, DNS/IPv6 leak checks, App vs. OS Kill Switch controls, and live CPU/Memory/Battery polling telemetry.
6. **الإعدادات (`Settings`):** Smart country preference, DNS/DoH, IPv6, Failover mode, batch tester tuning, config exports, plus 1-tap access to **Split Tunneling (`استثناء التطبيقات`)** and **Enterprise Speed & Account Hub (`المركز المؤسسي والسرعة`)**.
