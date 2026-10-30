# Security Audit — `oldman-552/vpn-configs`

**Audit Date:** 2026-10-30  
**Scope:** Threat surface across untrusted public proxy feeds, Python validation pipeline, Android VPN tunnel/routing/DNS/IPv6/Kill-Switch layer, Enterprise licensing, Web Admin, and CI/CD workflows.

---

## 1. Executive Threat Model

Unlike single-operator commercial VPNs, `vpn-configs` aggregates configurations from **untrusted public Telegram channels and GitHub repositories** alongside optional **operator-controlled encrypted VIP nodes**. Consequently:
- **Untrusted Exit Operators:** Technical checks can verify transport encryption (`TLS 1.3`, `Reality`, `AEAD` ciphers), certificate validity, DNS consistency, and absence of HTTP redirect tampering, **but cannot prove that an anonymous exit-node operator does not log or inspect traffic leaving the exit node.**
- **Hostile Config Injection:** Upstream feeds can inject `allowInsecure=1` (MITM-enabling), `security=none` (cleartext proxy), weak legacy ciphers (`rc4-md5`, `aes-128-cfb`, `none`), SSRF private-IP targets, or HTTP redirect traps.
- **Local Network & ISP Leakage:** On Android, any gap in `VpnService` routes (`::/0`), `sing-box` DNS detouring, or startup/reconnect transitions leaks traffic or DNS queries directly to the local ISP.

---

## 2. Verified Security Findings & Severity Classifications

### SEC-01 — High: DNS Queries Sent Outside VPN Tunnel (`SingBox.kt`)
- **Location:** `android/app/src/main/java/com/bahrain/vpnconfigs/engine/SingBox.kt` (`buildConfig`, lines 69–105).
- **Evidence:** `SingBox.buildConfig` defines a single `"bootstrap"` DNS server (`1.1.1.1`, UDP/HTTPS) with **no `"detour": "proxy"`** and assigns it to `"dns": { "final": "bootstrap" }`. Because `BahrainVpnService` calls `builder.addDisallowedApplication(packageName)`, `libsingbox.so` executes outside `tun0` and transmits user domain lookups directly over the physical network.
- **Remediation:** Configure two distinct DNS servers in `sing-box`:
  1. `"bootstrap"` (direct IP resolver, used *only* as `outbound.domain_resolver` to resolve the proxy server's own hostname).
  2. `"tunnel-dns"` (`"detour": "proxy"`, set as `"dns.final"` and `"route.default_domain_resolver"`) so 100% of tunnel DNS resolution traverses the encrypted proxy outbound.

### SEC-02 — High: Native IPv6 Traffic Bypass When `enableIpv6` Is Disabled (`BahrainVpnService.kt`)
- **Location:** `android/app/src/main/java/com/bahrain/vpnconfigs/vpn/BahrainVpnService.kt` (`startTunLayer`, lines 520–523).
- **Evidence:** When `prefs.enableIpv6 == false` (the default!), `Builder` only routes `0.0.0.0/0` and omits `addRoute("::", 0)`. On dual-stack LTE/5G/Wi-Fi networks, Android routes `AAAA` connections over the physical interface outside the VPN.
- **Remediation:** Always capture `::/0` (`addAddress("fc00::1", 128)` + `addRoute("::", 0)`) in `VpnService.Builder`. When IPv6 tunneling is disabled or unsupported by the upstream node, sinkhole IPv6 inside `tun0` (do not enable IPv6 upstream forwarding and set `sing-box` domain strategy to `ipv4_only`), forcing clean, immediate RFC 8305 IPv4 fallback inside the tunnel with zero external IPv6 packets.

### SEC-03 — High: Fail-Open Startup & Drop Behaviour (Missing Kill Switch) (`BahrainVpnService.kt`)
- **Location:** `BahrainVpnService.kt` (`handleConnect`, lines 295–347; `probeJob`, lines 660–695).
- **Evidence:**
  1. During initial connection, `tun0` is not created until *after* `singBox` starts and passes an HTTP probe.
  2. When a connected server drops and failover fails (or is off), `teardownInternal()` closes `tun0`, allowing queued and ongoing app connections to revert silently to the physical network.
- **Remediation:** Implement a fail-closed **Kill Switch** (`prefs.killSwitch`, enabled by default with explicit user toggle):
  - Establish `tun0` (`0.0.0.0/0` + `::/0`) *immediately* upon entering `CONNECTING` before upstream probing. While `sing-box` is not yet verified, `hev-socks5-tunnel` forwards to `127.0.0.1:20808` (closed/guarded), blocking all non-exempt app traffic from escaping.
  - On tunnel failure when Kill Switch is active, keep `tun0` locked in `VpnPhase.PROTECTION_ACTIVE` while attempting controlled recovery, releasing `tun0` only when the user explicitly disconnects.
  - Detect Android OS `VpnService.isLockdownEnabled` (Always-On / Block Connections Without VPN) and document OS-level boundaries honestly (e.g., kernel boot window prior to `VpnService` start unless OS Lockdown is enabled).

### SEC-04 — High: Unclassified Insecure Proxy Configurations (`allowInsecure=1`, `security=none`, Weak Ciphers)
- **Location:** `tester.py` (`to_xray_outbound` / `to_singbox_outbound`), `Converters.kt` (`tlsBlock`), `scoring.py`.
- **Evidence:** Configs specifying `allowInsecure=1` / `insecure=1` disable X.509 certificate verification (permitting trivial active MITM). Configs with `security=none` on VLESS/VMess or `method=none`/`rc4-md5`/`aes-128-cfb` on Shadowsocks lack modern transport/AEAD security, yet receive normal performance scores without risk warnings or quarantine.
- **Remediation:** Build `security_intelligence.py` (and mirror in Kotlin `SecurityEvaluator`) to inspect cipher suites, TLS/Reality settings, SNI-host alignment, port anomalies, endpoint/IP drift across runs, and unexpected HTTP redirects during probing. Classify every config as `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, or `UNKNOWN`, separate `security_assessment` and `privacy_assessment` from performance, quarantine `CRITICAL` configs into `quarantined.json` (redacted), and block `CRITICAL`/`Failed` configs in `PRIVACY_AWARE` mode.

### SEC-05 — Medium: Overstated WebRTC Protection Claim (`ClientDiagnosticsEngine.kt`)
- **Location:** `ClientDiagnosticsEngine.kt` line 489 (`webRtcLeakProtected = viaVpnTunnel`).
- **Evidence:** `VpnService` TUN routing captures standard UDP/TCP STUN traffic for apps inside the tunnel, **but** cannot prevent split-tunneled browsers from bypassing `tun0`, nor can it prevent browser engines with host-candidate enumeration bugs from exposing local link addresses.
- **Remediation:** Replace the binary `webRtcLeakProtected = true` claim with an honest multi-state `webRtcExposureStatus` and user-facing guidance explaining browser WebRTC settings (`disable_non_proxied_udp`).

### SEC-06 — Low: Source-Level Poisoning Resilience (`collector.py` / `scoring.py`)
- **Location:** `scoring.py` (`SourceHealthRecord`).
- **Evidence:** SSRF and size limits in `pipeline_security.py` are strong (blocking RFC1918, loopback, CGNAT `100.64.0.0/10`, link-local `169.254.169.254`, IPv6 zone IDs, hex/octal IP obfuscation, and path traversal). However, a source returning predominantly malformed or `CRITICAL`-risk configs (`allowInsecure=1` floods) is not automatically quarantined.
- **Remediation:** Add per-source suspicious/invalid counters and automatic `quarantined` state transition when a source exceeds safety thresholds.

---

## 3. Existing Controls Verified Sound

- **SSRF & Archive Hardening (`pipeline_security.py`):** Verified DNS resolution checks across all redirect hops (`MAX_REDIRECT_HOPS = 4`), `15 MiB` stream caps, and `SHA-256` binary digest checks for `Xray-core` and `sing-box`.
- **Credential Redaction (`pipeline_security.redact_uri` & `AppDiag.redactSecrets`):** Verified UUIDs, passwords, and query tokens are stripped from logs and public reports.
- **GitHub Actions Supply Chain (`.github/workflows/*.yml`):** All third-party actions are pinned to full 40-character commit SHAs with explicit `permissions:` blocks.
