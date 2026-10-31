# API.md — Read-Only Public Statistics API (`v1`)

`bahrain-vpn` provides a versioned, read-only JSON API (`/api/v1/*`) alongside an OpenAPI 3.1.0 specification. It works identically in **two deployment modes**:
1. **Serverless Pure-GitHub Static CDN (`@data` branch)**: Pre-computed every 30 minutes into `dist/api/v1/*.json`.
2. **Live Local/Container HTTP Server (`public_api.py`)**: Serves dynamic pagination, query filtering, `ETag`/`304 Not Modified`, CORS, security headers, and per-IP token-bucket rate limiting (`429 Too Many Requests`).

Zero raw proxy URIs, passwords, UUIDs, tokens, or unmasked server IPs are ever exposed by `/api/v1/*`.

---

## 1. Base URLs
- **GitHub CDN (Static)**: `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/api/v1`
- **Local HTTP Server**: `http://127.0.0.1:8080/api/v1` (`python public_api.py --dist dist --port 8080 --rpm 60`)

---

## 2. Endpoints

| Method | Live HTTP Path | Static CDN Artifact | Description |
|---|---|---|---|
| `GET` | `/api/v1/health` | `/api/v1/health.json` | Pipeline health, freshness age, degraded-mode flag, alive/tested counts |
| `GET` | `/api/v1/statistics` | `/api/v1/statistics.json` | Global summary, latency/speed metrics, security/risk breakdowns, longitudinal history |
| `GET` | `/api/v1/servers` | `/api/v1/servers.json` | Paginated & filterable sanitized server telemetry list |
| `GET` | `/api/v1/servers/{id}` | `/api/v1/servers/{id}.json` | Sanitized multi-dimensional telemetry for a single server ID (`srv_...`) |
| `GET` | `/api/v1/countries` | `/api/v1/countries.json` | Country distribution with average latency, speed, performance, and verified count |
| `GET` | `/api/v1/protocols` | `/api/v1/protocols.json` | Protocol distribution with average latency and throughput |
| `GET` | `/api/v1/sources` | `/api/v1/sources.json` | Sanitized source quality, state (`active`/`probation`/`quarantined`), yield, and availability |
| `GET` | `/api/v1/openapi.json` | `/api/v1/openapi.json` | Full OpenAPI 3.1.0 schema specification |

---

## 3. Query Parameters (`GET /api/v1/servers` on Live HTTP Server)

| Parameter | Type | Default | Allowed Values / Range |
|---|---|---|---|
| `page` | `integer` | `1` | `1 .. 10000` |
| `per_page` | `integer` | `50` | `1 .. 200` |
| `country` | `string` | — | 2-letter ISO code (e.g. `DE`, `NL`, `SG`) |
| `protocol` | `string` | — | `vless`, `trojan`, `vmess`, `ss`, `hysteria2`, `hy2`, `tuic` |
| `security` | `string` | — | `Verified`, `Partial`, `Unknown`, `Failed` |
| `risk` | `string` | — | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `UNKNOWN` |
| `min_performance` | `number` | — | `0.0 .. 100.0` |
| `sort` | `string` | `score` | `score`, `performance`, `reliability`, `latency`, `speed` |

Invalid parameters return `HTTP 400` with `{"error":{"code":400,"message":"..."}}`.

---

## 4. Rate Limiting & Caching
- **Caching**: Every `200 OK` response includes `ETag` and `Cache-Control: public, max-age=60, stale-while-revalidate=300`. Clients sending matching `If-None-Match` receive `304 Not Modified`.
- **Rate Limiting**: Token bucket per client IP (`--rpm`, default `60` requests/minute) with `X-RateLimit-Remaining` and `Retry-After` headers (`HTTP 429` when exhausted).
