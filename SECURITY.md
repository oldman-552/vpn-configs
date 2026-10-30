# SECURITY.md — Security Architecture, Threat Model & Honest Limitations (`v3.5`)

## 1. Security Design Principles
1. **Speed ≠ Security**: High throughput or low ping never elevates a server's `security_assessment` or `privacy_assessment`.
2. **Epistemic Honesty**: Unverified public community servers are never labeled `Privacy: Verified`. Only operator-attested encrypted `VIP 💎` nodes with verified transport security achieve `Privacy: Verified`.
3. **Fail-Closed Defaults**: Unsafe configurations are quarantined before publication (`quarantined.json`), and Android Kill Switch defaults to fail-closed `tun0` capture.
4. **Zero Embedded Secrets & Play Protect Compliance (`v3.5`)**: Neither User APK (`:app`), Admin APK (`:admin`), nor `web-admin/` contains embedded GitHub tokens, private keys, plaintext passwords, `REQUEST_INSTALL_PACKAGES`, internal `.apk` dropper code, or `Android Debug` certificates.

---

## 2. Implemented Protections

### 2.1 Configuration & Pipeline Security (`security_intelligence.py` & `pipeline_security.py`)
- **SSRF & Private-Network Blocking**: Rejects RFC1918, loopback, link-local, CGNAT, multicast, cloud metadata (`169.254.169.254`), and DNS rebinding across every redirect hop.
- **Cryptographic & Transport Inspection**:
  - Quarantines broken ciphers (`none`, `plain`, `rc4`, `rc4-md5`, `des-cfb`), cleartext `vless`/`vmess`, invalid Reality public keys, control-character/newline injection, and non-proxy service ports (`22`, `25`, `445`, `3306`, `3389`, `6379`).
  - Flags `allowInsecure=1` (`skip-cert-verify`) as `Security: Failed`, `Privacy: High Risk`, `Risk: HIGH` and excludes it from `PRIVACY_AWARE` and default safe selections.
  - Post-probe verification quarantines nodes exhibiting suspicious HTTP redirects or TLS verification failure.

### 2.2 Android DNS, IPv6 & Kill Switch Security (`LeakProtectionEngine.kt`, `SingBox.kt`, `KillSwitchController.kt`)
- **In-Tunnel DNS Isolation**: Application DNS queries resolve via `198.18.0.2` (MapDNS) → `sing-box` `"tunnel-dns"` (`"detour": "proxy"`). Private/LAN DNS inputs (`192.168.*`, `10.*`, `127.*`) are automatically sanitized to `1.1.1.1`.
- **IPv6 Dual-Stack Sinkhole**: `VpnService.Builder` always captures `::/0` (`fc00::1/128`) regardless of whether upstream IPv6 forwarding is enabled, preventing dual-stack cellular/Wi-Fi IPv6 bypass.
- **Fail-Closed Kill Switch**: Establishes `tun0` prior to proxy probing (`CONNECTING`), maintains `tun0` during `SWITCHING_SERVER` and `RECONNECTING`, and holds `tun0` in `PROTECTION_ACTIVE` if all candidates fail unexpectedly.

---

## 3. Honest Security & OS Limitations
- **Untrusted Public Exit Nodes**: Publicly collected VPN nodes are operated by unknown third parties. Transport encryption (`TLS`/`Reality`/`QUIC`) protects traffic between your device and the VPN server against local ISP/Wi-Fi inspection, **not** against the exit node operator observing destination IPs/SNI or unencrypted `HTTP`. Always use end-to-end `HTTPS/TLS` or private `VIP 💎` nodes for sensitive workloads.
- **Android OS Boot Window vs App Kill Switch**: Android `VpnService` apps cannot intercept kernel packets emitted *before* the Android OS starts the app after a cold reboot, nor if the Android OS force-stops the app process. For kernel-level boot protection, enable **Android Settings → Network & Internet → VPN → bahrain-vpn → Always-on VPN + Block connections without VPN** (`OS Lockdown`, detected and surfaced in the app UI).
- **Browser WebRTC Enumeration**: While `tun0` routes UDP/TCP STUN traffic inside the VPN tunnel (unless a browser is excluded via Split Tunneling), `VpnService` cannot prevent a browser engine from reading local interface addresses via JavaScript APIs. Users requiring strict anonymity should also enable WebRTC UDP restriction in browser privacy settings.

## 4. Reporting Vulnerabilities
Open a security advisory on GitHub Security Advisories for this repository without posting live credentials or private endpoints in public issues.
