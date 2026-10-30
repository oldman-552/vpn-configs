# 100% GitHub-Native Deployment & Operations Guide (`v3.3`)

## 1. Zero-External-Server Architecture
Every component of this platform runs **100% inside GitHub** without external VPS, PostgreSQL, Supabase, or Firebase dependencies:

| Layer | GitHub Mechanism | Artifact / State Location |
|---|---|---|
| Historical Intelligence DB | GitHub Actions (`data.yml`) + `@data` branch | `state/history.sqlite3` (+ atomic `.bak` & `state/node_history.json`) |
| Public Sanitized APIs | `@data` branch via jsDelivr / Raw GitHub | `servers-{current,history,performance,statistics}.json`, `countries-statistics.json`, `sources-statistics.json`, `api/v1/*.json`, `alive.json` |
| Web Admin & Live Monitor | GitHub Pages (`enterprise.yml` -> `gh-pages`) | `web-admin/index.html` & `web-admin/monitor.html` |
| Android Releases (`:app` & `:admin`) | GitHub Actions (`apk.yml`) -> GitHub Releases | Signed `app-arm64-v8a-release.apk`, `app-x86_64-release.apk`, `app-release.apk`, `app-admin-release.apk` |

## 2. Automated Cloud Pipeline (`data.yml`)
1. Runs on schedule (every 6 hours), manual `workflow_dispatch`, or pushes touching `collector.py`, `tester.py`, `dedupe.py`, `scoring.py`, `historical_db.py`, `migrations/**`, or `server/build_data.py`.
2. Restores `prev_dist/state/history.sqlite3` from the `@data` orphan branch.
3. If `history.sqlite3` is running for the first time, bootstraps known nodes from `state/node_history.json` (`ESTIMATED` continuity). If corrupted, quarantines the damaged file and recovers from `.bak` or fresh schema without aborting the pipeline.
4. Defers hot-path probing for servers under active temporary failure suppression (`server_suppressions`) while retaining their historical identity.
5. Records per-server probe observations, updates hourly (`90d`) and daily (`365d`) rollups, prunes raw observations older than `30d`, `VACUUM`s when needed, and atomically publishes all backward-compatible and new v3.3 JSON exports to `@data` (preserving `enterprise/`).

## 3. Building & Publishing Android APKs (`apk.yml`)
1. Pushing to `main` (or dispatching `apk.yml`) fetches pinned `sing-box` (`v1.14.4` SHA-256 verified) and `hev-socks5-tunnel` (`2.19.3` SHA-256 verified).
2. Runs `./gradlew testDebugUnitTest` (executing `AndroidVpnAuditTest`, `EnterpriseAndroidTest`, and `SmartVpnUpgradeTest` under Robolectric SDK 34).
3. Builds R8-minified, resource-shrunk split-ABI release APKs (`versionCode = 11`, `versionName = "3.3"`).

## 4. Deploying Web Admin & Historical Monitor (`enterprise.yml`)
- Automatically deploys `web-admin/` (including `index.html` Admin Console and `monitor.html` Historical Server Intelligence Dashboard) to GitHub Pages (`gh-pages`) on push to `main`.
