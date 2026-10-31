# Android Battery & Resource Optimization (`v2`)

## 1. Architectural Energy Principles
VPN clients run long-lived foreground services, so uncontrolled background timers, duplicate network handovers, or CPU wake locks rapidly drain mobile batteries. Release `v2` enforces five strict power-saving invariants across `BahrainVpnService`, `ResourceAndBatteryMonitor`, `AutoReconnectManager`, `CommunityTestingManager`, and `ConnectHomeScreen`:

1. **Zero `WakeLock`s (`wakeLocksHeld = 0`):**
   - Neither `BahrainVpnService` nor `RefreshWorker` acquires `PowerManager.WakeLock`. Packet forwarding inside `hev-socks5-tunnel` and `sing-box` wakes only on kernel socket readiness (`epoll`), allowing the SoC to enter idle sleep whenever no packets are in flight.
2. **Lifecycle-Aware Foreground vs. Background Probe Cadence (`ResourceAndBatteryMonitor`):**
   - `MainActivity` observes `Lifecycle.Event.ON_START` and `Lifecycle.Event.ON_STOP` to update `ResourceAndBatteryMonitor.isUiInForeground`.
   - Active degraded state: `4s` rapid verification to prevent blackhole drops.
   - Stable foreground UI: steps from `8s -> 15s -> 24s`.
   - Stable background / screen-off state: expands automatically to **`45s`** on Wi-Fi and **`60s`** on metered cellular links, cutting background HTTP `204` keepalive wakeups by **66%–75%** compared with fixed `15s` polling.
3. **Lifecycle-Bound UI Rendering (`ConnectHomeScreen` & `LiveTrafficChart`):**
   - Elapsed-time ticks and Compose `Canvas` redraws exist strictly inside `ConnectHomeScreen`'s composition scope; when the user switches tabs or turns off the screen, Compose disposes the `LaunchedEffect` and zero UI frame rendering occurs.
4. **Notification Signature Deduplication:**
   - `BahrainVpnService.updateNotification` hashes `titleSuffix|body` (`lastNotifSignature`) and updates at most once every 3 seconds, suppressing redundant Binder IPC calls to `NotificationManager` when throughput is idle (`0 KB/s`).
5. **Network-Aware Reconnect Suppression (`AutoReconnectManager` + `NetworkAwarenessMonitor`):**
   - When `UnderlyingTransport.NONE` is reported (airplane mode, elevator, dead zone), `AutoReconnectManager` pauses retry attempts immediately (`0` wasted socket/TLS handshakes) until Android's `ConnectivityManager.NetworkCallback` signals physical connectivity restoration.
   - On Wi-Fi <-> Cellular handover, `BahrainVpnService` executes a single `2.2s` SOCKS probe first; if QUIC/TCP already survived or rebound cleanly, tunnel teardown/rebuild is skipped completely.

## 2. Real Telemetry Instrumentation
`ResourceAndBatteryMonitor.captureSnapshot()` exposes real OS counters in the **Security & Efficiency** tab without synthetic estimates:
- **Process CPU Time (`ms`) & Delta CPU `%`:** Read from `android.os.Process.getElapsedCpuTime()` divided by wall-clock `SystemClock.elapsedRealtime()` delta.
- **Memory Footprint (`MB`):** Java heap (`Runtime.totalMemory() - freeMemory()`) and kernel PSS (`android.os.Debug.getPss()`).
- **Probe & Reconnect Rates:** Atomic counters for background tunnel checks (`probesPerMinute`) and exponential-backoff reconnect executions (`reconnectCount`).

## 3. Verification & Honest Measurement Scope
- **Automated Verification (Passed):** `SmartVpnUpgradeTest.networkAwarenessAndBatteryAdaptiveIntervalsSavePowerInBackground` verifies deterministic transition from `4,000 ms` (degraded) -> `45,000 ms` (background Wi-Fi) -> `60,000 ms` (background metered cellular) and confirms `wakeLocksHeld == 0`.
- **Physical Device Scope Note:** Exact milliamp-hour (`mAh`) discharge curves depend on physical modem baseband hardware (5G SA/NSA vs. Wi-Fi 6), carrier RRC idle timers, and OEM Doze policies, which cannot be measured inside headless Linux CI runners and require physical Android `dumpsys batterystats` / Perfetto profiling on target handsets.
