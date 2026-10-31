# Security & Privacy Model (`v1`)

## 1. Epistemic Honesty in Connection Security Classification
Most consumer VPN apps mislead users by displaying `"100% Secure & Anonymous"` whenever a TUN interface opens. `ConnectionSecurityClassifier.kt` replaces binary marketing claims with **9 explicit, independently verified states**:

| State | Meaning | When Asserted |
|---|---|---|
| `CONNECTED` | VPN tunnel established and passing traffic | Only after `Socks.measureRealDelay` verifies live HTTP `200`/`204` transit over `sing-box` |
| `ENCRYPTED_TUNNEL` | Transport encryption verified | `SecurityEvaluator` confirms TLS/Reality/QUIC encryption without `allowInsecure=1` or weak ciphers |
| `UNKNOWN_SERVER_TRUST` | Server operator identity is unverified | **Always asserted** for public community-sourced VPN nodes so users never assume zero-logging |
| `DNS_LEAK_DETECTED` | DNS queries appear to bypass the VPN tunnel | Local/ISP LAN resolver appears on active VPN interface or diagnostic probe detects resolver leak |
| `IPV6_LEAK_DETECTED` | Global IPv6 traffic bypasses the VPN route | Host has global IPv6 connectivity while `::/0` is not captured by TUN |
| `UNSTABLE_CONNECTION` | Degraded tunnel quality | Packet loss `>= 20%`, jitter `>= 180 ms`, or `VpnPhase.CONNECTION_DEGRADED` |
| `KILL_SWITCH_ACTIVE` | OS-level lockdown confirmed | **Strictly requires** Android `VpnService.isLockdownEnabled == true` (API 29+) |
| `SECURITY_CHECK_FAILED` | Mandatory security check failed | `allowInsecure` config, `DNS_LEAK_DETECTED`, or `IPV6_LEAK_DETECTED` |
| `SECURITY_CHECK_INCOMPLETE` | Check inconclusive or tunnel inactive | Disconnected state or missing verification telemetry |

## 2. Two-Tier Kill Switch Architecture (`KillSwitchController.kt`)
1. **App-Level Fail-Closed TUN Hold (`PROTECTION_ACTIVE`):**
   - Establishes `198.18.0.1/32` (`0.0.0.0/0`) and `fc00::1/128` (`::/0`) *before* probing upstream candidates and retains the closed TUN sinkhole if all servers fail, preventing fallback to the raw ISP link while the app process is alive.
2. **Android OS Always-On Lockdown (`VpnService.isLockdownEnabled`):**
   - Only the Android kernel can block packets during early device boot or if the app process is force-stopped by the user.
   - The app **never** claims `KILL_SWITCH_ACTIVE` unless `VpnService.isLockdownEnabled` returns `true`, and `SecurityStatusScreen` provides step-by-step instructions plus a 1-tap `Settings.ACTION_VPN_SETTINGS` button.

## 3. DNS & Dual-Stack IPv6 Leak Prevention
- **DNS Protection (`LeakProtectionEngine` + `MapDNS`):**
  - Captures port-53 lookups on `198.18.0.2` (`240.0.0.0/4` virtual mapping) and resolves them inside `sing-box` over encrypted DoH (`https://1.1.1.1/dns-query` or custom sanitized resolver) detoured through the proxy outbound.
  - Public encrypted resolvers (`1.1.1.1`, `9.9.9.9`, `8.8.8.8`) routed *inside* the tunnel are properly recognized as protected rather than false-positive leaks.
  - **Explicit Limitation Disclosure:** Local interface/route inspection verifies on-device capture; end-to-end recursive resolver verification requires an active external probe (`runNetworkDiagnosticsSuite`).
- **IPv6 Dual-Stack Sinkhole:**
  - `BahrainVpnService.startTunLayer()` always captures `::/0` (`fc00::1/128`). When `enableIpv6 == false`, IPv6 frames are safely dropped inside TUN rather than leaking out the physical dual-stack Wi-Fi/5G interface.

## 4. Credential & Privacy-by-Design Guarantees
- **Secret-Safe Server Fingerprints:** Both `dedupe.py` (`_hash_credential_secret_safe`) and `Converters.stableServerId` salt and hash UUIDs/passwords with SHA-256 before computing `server_id`. Raw credentials are never stored in `history.sqlite3`, `bahrain_vpn_client.db`, `servers-*.json`, or crash/diagnostic logs.
- **Zero Location / SSID Harvesting:** `NetworkAwarenessMonitor` uses `ConnectivityManager` + `NetworkCapabilities` (`TRANSPORT_WIFI`, `TRANSPORT_CELLULAR`, `TRANSPORT_ETHERNET`) exclusively and never requests `ACCESS_FINE_LOCATION` or Wi-Fi SSIDs.
- **Endpoint Masking:** Public JSON exports (`servers-current.json`, `servers-history.json`) and Android history/favorites mask raw IPv4/IPv6 octets (`***x.y:port` / `198.51.*.*:443`).
