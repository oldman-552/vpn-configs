# Performance Audit — `oldman-552/vpn-configs`

**Audit Date:** 2026-10-30  
**Scope:** Cloud collection/testing pipeline (`collector.py`, `tester.py`, `server/build_data.py`), Android VPN runtime (`BahrainVpnService.kt`, `SingBox.kt`, `Tester.kt`), and Web/API data delivery.

---

## 1. Cloud Pipeline Performance Analysis

| Stage | Current Measured / Configured Behavior | Bottleneck Identified | Optimization Plan |
|---|---|---|---|
| **Upstream Collection (`collector.py`)** | 16 worker threads, `ETag` / `If-Modified-Since` conditional GETs, `SourceHealthRegistry.should_skip_cooldown()` probes disabled feeds every 4th run. | Quarantined or high-invalid feeds still consume deduplication and regex CPU cycles if not filtered early; source content hash (`SHA-256`) is not cached when upstream omits `ETag` (raw GitHub/Telegram HTML). | Track `content_sha256` per source to detect unchanged payloads immediately and skip quarantined sources during cooldown windows. |
| **Candidate Testing (`tester.py` / `build_data.py`)** | `TEST_TOP = 1200`, `SPEED_TOP = 150`, `CONCURRENCY = 40`, 3 stability probes per alive candidate. Baseline run completes in ~100 seconds. | `CRITICAL`-risk or structurally unsafe configs (e.g., broken Reality keys, dead cipher names, quarantined endpoints) consume child-process spawn slots in `select_best` before scoring. | Run pre-tunnel `SecurityIntelligenceEngine.assess_static()` *before* `tester.select_best()` so `CRITICAL` quarantined configs never spawn `Xray`/`sing-box` child processes. |
| **Dataset Serialization (`server/build_data.py`)** | Writes `alive.json` (~400 nodes) as a single payload; dashboards/clients wanting summary statistics or paginated server slices must parse the entire `alive.json` + `meta.json` + `source_health.json`. | Missing lightweight paginated `/api/v1/*` slices and compact `pipeline_history.json` ring-buffer for trend charts. | Emit compact static `/api/v1/` JSON slices (`statistics.json`, `health.json`, paginated `servers/page-*.json`) with bounded history (`<= 96` points = 48h at 30m intervals). |

---

## 2. Android Application Performance, Memory & Battery Analysis

| Area | Current Implementation | Bottleneck Identified | Optimization Plan |
|---|---|---|---|
| **APK Binary Footprint (`build.gradle.kts`)** | R8 shrinking + resource shrinking enabled in `v3.1`: `arm64-v8a` = `27.57 MB`, `Admin APK` = `2.19 MB`. | Keep ProGuard rules strict as new security/failover classes are added so APK size does not regress. | Maintain R8 + resource shrinking and verify DEX class count in CI. |
| **Background Tunnel Polling (`BahrainVpnService.kt`)** | `monitorJob` wakes up every `1000ms` calling JNI `TProxyGetStats()` and updating Notification every `2000ms` even when traffic delta is zero; `probeJob` runs fixed `8000ms` HTTP probes over SOCKS5 regardless of traffic activity or screen/battery state. | Constant 8-second HTTP wakeups drain cellular radio tail energy (`RRC_CONNECTED`) when the tunnel is idle and stable; conversely, when latency spikes (`>900ms`), waiting 8s per sample slows degradation detection. | Implement **adaptive telemetry & probe cadence**: extend probe interval (`15s -> 25s`) during sustained low-jitter stability or idle periods to save battery, and tighten confirmation interval (`3s`) only when RTT/loss crosses degradation thresholds. Skip notification Binder IPC updates when formatted text is unchanged. |
| **Parallel Candidate Testing (`BahrainVpnService` & `Tester.kt`)** | Spawns batches of 4–8 `libsingbox.so` child processes polling `Socket.connect` every `30ms`. | Orphaned temp config files or unclosed process streams if coroutines cancel mid-batch; `metaCache` in `Converters.kt` clears abruptly at 4,096 entries (`metaCache.clear()`). | Ensure `finally` process cleanup on cancellation, bound candidate test batches cleanly, and avoid redundant `Converters.toOutbound` parses via pre-computed security/ranking metadata. |
| **Server List Re-Sorting (`AppViewModel.kt`)** | Auto-test updates re-sort `servers` progressively as speed results arrive. | Recomputing full URI parsing inside comparators on every item comparison (`O(N log N)` per update) allocates unnecessary temporary `JSONObject` instances. | Precompute normalized `RankableServer` metric scores once per server state snapshot before sorting (`Schwartzian transform`), cutting GC churn during progressive speed sorting. |

---

## 3. Web Dashboard & Public API Performance

- **Dashboard Rendering (`web-admin/`):** Currently loads full `bundle.json`; public monitoring views should fetch lightweight `/api/v1/statistics.json`, `/api/v1/countries.json`, `/api/v1/protocols.json`, and `/api/v1/sources.json` concurrently with `ETag` / `sessionStorage` TTL caching (`60s`) to eliminate redundant GitHub/CDN requests and render SVG charts in `<16ms` with zero external charting library bloat.
