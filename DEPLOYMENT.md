# DEPLOYMENT.md — 100% Pure-GitHub Deployment & Operations Guide

## 1. Zero-External-Server Architecture
Everything runs exclusively on GitHub:
- **`.github/workflows/ci.yml`**: Runs `pytest -v` (42 backend/security/API tests) and enforces 40-character commit SHA pinning and explicit `permissions:` across all workflows.
- **`.github/workflows/data.yml`**: Runs every 30 minutes (`*/30 * * * *`) and on `main` pushes, executing collection, pre/post-probe quarantine, 5-layer deduplication, multi-stage `Xray-core` + `sing-box` probing, 5-profile ranking, static `/api/v1/*` export, LKG protection, and single-commit force-publish to the `@data` branch.
- **`.github/workflows/enterprise.yml`**: Validates all `web-admin/**/*.js` modules (`node --check` + zero-secret audit) and deploys both the 17-page Encrypted Admin Console (`index.html`) and the public read-only Live Infrastructure Monitor (`monitor.html`) to `gh-pages`.
- **`.github/workflows/apk.yml`**: Fetches SHA-256-verified `sing-box` (`SFA 1.14.4`) and `hev-socks5-tunnel` (`2.19.3`), executes Robolectric unit tests (`testReleaseUnitTest`), compiles R8-shrunk Split-ABI User APKs (`arm64-v8a`, `x86_64`, `universal`) + Admin APK (`:admin`), runs bytecode OpSec audits, and publishes signed GitHub Releases on `v*` tags.

---

## 2. Required & Optional Repository Secrets
Configure under **GitHub Repository → Settings → Secrets and variables → Actions**:
- `GITHUB_TOKEN` *(automatic)*: Used by `data.yml`, `enterprise.yml`, and `apk.yml` with least-privilege job permissions.
- Android Release Signing *(optional; falls back to debug signing only in non-release CI builds)*:
  - `KEYSTORE_BASE64`: Base64-encoded `.jks` / `.keystore` file
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

## 4. Publishing a Signed APK Release (`v3.2`)
```bash
git tag v3.2
git push origin v3.2
```
`apk.yml` automatically builds, tests, audits, signs, generates `SHA256SUMS.txt`, and publishes the GitHub Release.
