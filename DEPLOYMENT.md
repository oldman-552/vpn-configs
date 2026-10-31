# DEPLOYMENT.md — 100% Pure-GitHub Deployment & Operations Guide (`v1`)

## 1. Zero-External-Server Architecture
Everything runs exclusively on GitHub:
- **`.github/workflows/ci.yml`**: Runs `pytest -v` (51 backend/Top-500/historical/security/API tests) and enforces 40-character commit SHA pinning and explicit `permissions:` across all workflows.
- **`.github/workflows/data.yml`**: Runs every 30 minutes (`*/30 * * * *`) and on `main` pushes, executing collection, pre/post-probe quarantine, 5-layer deduplication, multi-stage `Xray-core` + `sing-box` probing, Central Top-500 export (`top500.{manifest,delta,json,txt}`), SQLite historical analytics (`servers-*.json`), static `/api/v1/*` export, LKG protection, and single-commit force-publish to `@data`.
- **`.github/workflows/enterprise.yml`**: Validates all `web-admin/**/*.js` modules (`node --check` + zero-secret audit) and deploys both the 17-page Encrypted Admin Console (`index.html`) and the public read-only Live Infrastructure Monitor (`monitor.html`) to `gh-pages`.
- **`.github/workflows/apk.yml`**: Fetches SHA-256-verified `sing-box` (`SFA 1.14.4`) and `hev-socks5-tunnel` (`2.19.3`), executes Robolectric unit tests (`testReleaseUnitTest`), signs Split-ABI Bilingual (Arabic Primary + English) User APKs (`v1`, `versionCode = 1`, `versionName = "1.0"`) + Admin APK (`v1`, `versionCode = 1`, `versionName = "1.0"`) with `RSA-4096` APK Signature Scheme `v1/v2/v3` (never `Android Debug`), enforces Play Protect Zero-Dropper & OpSec bytecode audits, and publishes the single official signed GitHub Release **`v1`** (`Latest`).

---

## 2. Required & Optional Repository Secrets
Configure under **GitHub Repository → Settings → Secrets and variables → Actions**:
- `GITHUB_TOKEN` *(automatic)*: Used by `data.yml`, `enterprise.yml`, and `apk.yml` with least-privilege job permissions.
- Android Persistent Release Signing *(recommended for cross-release upgrade continuity & Play Protect whitelisting; otherwise `apk.yml` generates an ephemeral `RSA-4096` production release certificate and wipes it post-build)*:
  - `KEYSTORE_BASE64`: Base64-encoded `.p12` / `.jks` release keystore
  - `KEYSTORE_PASSWORD`: Keystore password
  - `KEY_ALIAS`: Signing key alias
  - `KEY_PASSWORD`: Signing key password

---

## 3. Enabling GitHub Pages (`gh-pages`)
1. Merge changes to `main` so `.github/workflows/enterprise.yml` pushes the built dashboard to `gh-pages`.
2. In **Settings → Pages**, set **Source** = `Deploy from a branch`, **Branch** = `gh-pages` / `/ (root)`.
3. Accessible URLs:
   - **Admin Console (Encrypted)**: `https://<owner>.github.io/<repo>/`
   - **Live Infrastructure Monitor (Public Read-Only)**: `https://<owner>.github.io/<repo>/monitor.html`

---

## 4. Publishing a Signed Official APK Release (`v1`)
```bash
git tag v1
git push origin v1
```
`apk.yml` automatically builds, tests, audits, signs, generates `SHA256SUMS.txt`, and publishes the official GitHub Release (`v1`).
