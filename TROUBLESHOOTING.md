# TROUBLESHOOTING.md — Operational & Client Troubleshooting Guide

## 1. Android Client (`bahrain-vpn`)

### Status shows `🛡 Kill Switch نشط` (`PROTECTION_ACTIVE`) and internet is paused
- **Cause**: All tested VPN servers failed to respond (e.g., captive Wi-Fi portal or severe ISP blocking), and **Kill Switch** is enabled so `tun0` intentionally blocks unprotected fallback traffic.
- **Resolution**:
  1. Tap **السيرفر التالي** or open the **السيرفرات** tab and tap **فحص وتحديث** while temporarily disconnecting if you need to sign into a hotel/airport captive Wi-Fi portal.
  2. Enable **DNS مشفّر عبر HTTPS (DoH)** and **تمرير UDP عبر TCP** in Settings if your network blocks UDP/QUIC (`hysteria2`/`tuic`).
  3. Tap the main power button (**قطع الاتصال**) to explicitly release Kill Switch and return to direct internet.

### Connection switches to `متّصل (تذبذب)` (`CONNECTION_DEGRADED`)
- **Cause**: Live tunnel monitoring detected RTT ≥ 650 ms, jitter ≥ 180 ms, or packet loss ≥ 25%.
- **Resolution**: Set **Failover Policy** to **ذكي ومتوازن (`SMART`)** or **استباقي فائق (`AGGRESSIVE`)** in the Diagnostics & Health card so `SmartFailoverEngine` pre-verifies a faster server in the background (`20901..20904`) and switches seamlessly without dropping `tun0`.

### Browser WebRTC warning in Network Diagnostics
- **Cause**: Either a browser app is excluded in **Split Tunneling**, or you are using a browser with unrestricted WebRTC interface enumeration.
- **Resolution**: Remove browsers from Split Tunneling exclusions, and in Chrome/Brave/Firefox settings set WebRTC handling to *Disable non-proxied UDP*.

### Boot-time traffic protection before Android starts apps
- **Cause**: Android OS only starts `BootRestoreReceiver` after `BOOT_COMPLETED`.
- **Resolution**: Open **Android Settings → Network & Internet → VPN → ⚙️ bahrain-vpn** and enable **Always-on VPN** + **Block connections without VPN**. The app detects and displays `OS Lockdown: مفعّل`.

---

## 2. Cloud Pipeline & Dashboards

### `meta.json` reports `degraded_mode: true`
- **Cause**: Upstream network outage yielded fewer than `MIN_ALIVE` verified servers during a scheduled run.
- **Behavior**: `server/build_data.py` automatically preserved the Last-Known-Good (`LKG`) `alive.json`, `sub.txt`, `privacy_aware.txt`, and `api/v1/*` artifacts rather than overwriting subscribers' feeds with an empty list.

### Source marked `quarantined` in `source_health.json` or `monitor.html`
- **Cause**: Either ≥ 65% of items from that source failed structural/security checks (`suspicious_count` ≥ 5) or the source returned 0 alive servers across 8 consecutive runs.
- **Resolution**: Inspect `source_health.json` (`quarantine_reason`), remove or replace the upstream URL in `channels.txt` / `github_sources.txt`.
