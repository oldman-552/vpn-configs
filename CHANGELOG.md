# Changelog

## [v1] — 2026-10-31 — Official `bahrain-vpn v1` Production Release (`1.0`)

### Official Release Highlights
- **Official `v1` Clean-Slate Versioning (`versionCode = 1`, `versionName = "1.0"`, Tag `v1`)**:
  - Unified User APK (`com.bahrain.vpnconfigs`), Admin APK (`com.bahrain.vpnadmin`), Enterprise License Bundle (`bundle_release = "1.0"`), Web Admin Console (`web-admin/`), and GitHub Releases under the single official **`v1`** release tag, purging legacy pre-`v1` tags, releases, and obsolete audit artifacts.
- **Full Bilingual APK Support — Arabic Primary (`RTL`) + English Secondary (`LTR`)**:
  - Added `AppI18n.kt` (`:app`), `AdminI18n` (`:admin`), `res/xml/locales_config.xml`, and `res/values-en/strings.xml` across both Android modules.
  - **Arabic (`ar`)** is strictly preserved as the primary default language (`LayoutDirection.Rtl`) on fresh installation, with instant one-tap switching to **English (`en`, `LayoutDirection.Ltr`)** from the top bar (`EN / عربي`) or Settings without restarting the app.
  - Localized all screens (`Home`, `Top 50 / Servers`, `Favorites`, `History`, `Security`, `Enterprise Hub`, `Settings`), foreground VPN notifications, Quick Settings Tile, diagnostics, and rotating promo dialogs.
- **Central GitHub Top-500 Pool + Local Android Personalized Top-50 Engine**:
  - GitHub (`central_top500.py`) validates, deduplicates (5 layers), evaluates transport security, and publishes up to 500 untrusted candidate configurations (`top500.{manifest,delta,json,txt}`) with SHA-256 checksums without padding.
  - Android (`LocalServerIntelligence.kt` + `ClientDatabase.kt` WAL SQLite) performs sequential real-tunnel verification (`concurrency = 1`), maintaining strictly isolated **Wi-Fi** (`WIFI`) vs **Mobile Data** (`MOBILE_DATA`) rankings (`TOP_50` + `BACKUP_POOL`) and append-only scan history.
- **Google Play Protect Anti-Dropper Hardening & `RSA-4096` `v1/v2/v3` Release Signing**:
  - Zero `REQUEST_INSTALL_PACKAGES` permission and zero internal `.apk` installer code; `AppUpdateManager` delegates verified `HTTPS` ABI-specific updates (`arm64-v8a`, `x86_64`, `universal`) to the system browser while copying the expected `SHA-256` digest to the clipboard.
  - Automated `PKCS12 RSA-4096` release signing (`APK Signature Scheme v1 + v2 + v3`) verified by `apksigner` in `.github/workflows/apk.yml`.
- **Zero-Leak Tunnel, Two-Tier Kill Switch, 9-State Honest Security & Pure-GitHub Enterprise**:
  - Mandatory in-tunnel DNS (`detour = "proxy"`) and fail-closed `::/0` IPv6 capture (`LeakProtectionEngine.kt`), fail-closed `tun0` protection + OS Lockdown detection (`KillSwitchController.kt`), 9 explicit connection security states (`ConnectionSecurityClassifier.kt`), encrypted `VIP 💎` private nodes (`AES-256-GCM` + `ECDSA P-256`), and anonymized public `/api/v1/*` telemetry (`OpenAPI 3.1.0`).
