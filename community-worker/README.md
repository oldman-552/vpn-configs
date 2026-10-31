# `community-worker/` — Free-Tier Privacy-Minimal Community Verification Gateway (`v1`)

This optional free-tier **Cloudflare Worker + D1** gateway receives **zero-secret, anonymized VPN connectivity observations** from opted-in `bahrain-vpn v1` Android users (`POST /v1/reports`) and exposes an authenticated incremental export (`GET /v1/export`) consumed by `.github/workflows/community_rankings.yml` and `.github/workflows/data.yml`.

## Security & Anti-Abuse Guarantees
- **Zero GitHub Secrets in APK:** Android clients talk only to `POST /v1/reports` (configured via signed `enterprise/bundle.json` -> `remote_config.community_ingest_url`) and hold zero GitHub PATs or tokens. If no Worker URL is configured yet, Android queues reports locally and operates 100% offline-safe.
- **Edge-Verified Origin Country (`request.cf.country`):** Iran (`IR`) and country tags are verified at the Cloudflare edge from the physical non-VPN connection, rejecting reports originating from known datacenter/cloud ASNs or when the client flags `vpn_interference = true`.
- **Strict Privacy & Secret Rejection:** Rejects any payload containing `://` URIs, passwords, UUIDs, Wi-Fi SSIDs, browsing history, or GPS coordinates; hashes edge IP with `RATE_SALT` solely for 1-hour rate limiting (`<= 60` reports/hour/source, 64 KB body limit, 6-hour per-device deduplication).

## Quick Free-Tier Deployment (Zero Cost)
```bash
cd community-worker
npx wrangler d1 create bahrain-vpn-community
# Copy database_id into wrangler.toml, then apply schema:
npx wrangler d1 execute bahrain-vpn-community --remote --file=./schema.sql
npx wrangler secret put EXPORT_BEARER_TOKEN
npx wrangler secret put RATE_SALT
npx wrangler deploy
```

Then add `COMMUNITY_WORKER_URL` and `COMMUNITY_EXPORT_TOKEN` to **GitHub Actions Secrets**, and set `"community_ingest_url"` in `remote_config` when publishing `enterprise/bundle.json`.
