/**
 * bahrain-vpn Community Verification Ingest Gateway (Cloudflare Worker + D1 Free Tier)
 *
 * Security & Privacy Guarantees:
 *   1. Zero raw client IP addresses stored (only transient rate-limit hash + CF country/ASN).
 *   2. Authentic Iran (IR) origin verification via Cloudflare network edge (`request.cf.country`),
 *      NEVER trusting client-claimed country or VPN/datacenter ASNs.
 *   3. Rejects any payload containing proxy URIs (`://`), credentials, or oversized fields.
 *   4. Per-IP hourly quota, per-reporter daily quota, and 6-hour `(fingerprint, reporter)` dedup.
 *   5. Read-only export endpoint (`/v1/export`) protected by Bearer token for GitHub Actions ONLY
 *      (zero secrets ever embedded in the Android APK).
 */

const MAX_BODY_BYTES = 65536;
const MAX_REPORTS_PER_BATCH = 30;
const HOURLY_IP_LIMIT = 120;
const DAILY_REPORTER_LIMIT = 250;

const ALLOWED_PROTOCOLS = new Set([
  "vless", "vmess", "trojan", "ss", "hysteria2", "tuic", "socks", "http"
]);

const DATACENTER_ORG_KEYWORDS = [
  "cloudflare", "amazon", "aws", "google cloud", "microsoft", "digitalocean",
  "hetzner", "ovh", "linode", "akamai", "vultr", "choopa", "m247", "datapacket",
  "contabo", "leaseweb", "oracle", "alibaba", "tencent", "scaleway"
];

function jsonResponse(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders,
    },
  });
}

async function sha256Hex(input) {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqualStr(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length || a.length === 0) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function isHexOfLength(str, minLen, maxLen) {
  return typeof str === "string" &&
    str.length >= minLen &&
    str.length <= maxLen &&
    /^[0-9a-f]+$/i.test(str);
}

function isLikelyDatacenterAsnOrg(asOrg) {
  const low = String(asOrg || "").toLowerCase();
  if (!low) return false;
  return DATACENTER_ORG_KEYWORDS.some((kw) => low.includes(kw));
}

async function checkAndIncrementQuota(db, bucketKey, windowEpoch, maxHits) {
  await db.prepare(
    `INSERT INTO rate_limits (bucket_key, window_epoch, hit_count)
     VALUES (?1, ?2, 1)
     ON CONFLICT(bucket_key) DO UPDATE SET
       hit_count = CASE WHEN rate_limits.window_epoch = ?2 THEN rate_limits.hit_count + 1 ELSE 1 END,
       window_epoch = ?2`
  ).bind(bucketKey, windowEpoch).run();

  const row = await db.prepare(
    "SELECT hit_count FROM rate_limits WHERE bucket_key = ?1"
  ).bind(bucketKey).first();
  return row && Number(row.hit_count) <= maxHits;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/v1/health") {
      return jsonResponse({ status: "ok", service: "bahrain-vpn-community-ingest", version: "1.0" });
    }

    if (request.method === "POST" && url.pathname === "/v1/reports") {
      const contentLen = Number(request.headers.get("content-length") || "0");
      if (contentLen > MAX_BODY_BYTES) {
        return jsonResponse({ error: "payload_too_large" }, 413);
      }
      const rawText = await request.text();
      if (rawText.length > MAX_BODY_BYTES) {
        return jsonResponse({ error: "payload_too_large" }, 413);
      }
      // Hard secret/URI guard: reject immediately if any proxy URI or credential key appears
      if (rawText.includes("://") || /password\s*=|uuid\s*=/i.test(rawText)) {
        return jsonResponse({ error: "forbidden_secret_material" }, 400);
      }

      let payload;
      try {
        payload = JSON.parse(rawText);
      } catch {
        return jsonResponse({ error: "invalid_json" }, 400);
      }

      const reporterHash = String(payload?.reporter_id_hash || "").toLowerCase();
      const reports = Array.isArray(payload?.reports) ? payload.reports : null;
      if (!isHexOfLength(reporterHash, 64, 64) || !reports || reports.length === 0 || reports.length > MAX_REPORTS_PER_BATCH) {
        return jsonResponse({ error: "invalid_batch_schema" }, 400);
      }

      const nowEpoch = Math.floor(Date.now() / 1000);
      const hourBucket = Math.floor(nowEpoch / 3600);
      const dayBucket = Math.floor(nowEpoch / 86400);
      const bucket6h = Math.floor(nowEpoch / 21600);

      // Transient hashed IP rate-limit key (raw IP is NEVER persisted)
      const clientIp = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
      const ipSalt = String(env.RATE_LIMIT_SALT || "bahrain-vpn-rl-v1");
      const ipKey = "ip:" + (await sha256Hex(`${ipSalt}|${clientIp}|${hourBucket}`)).slice(0, 32);
      const repKey = `rep:${reporterHash.slice(0, 32)}:${dayBucket}`;

      const ipAllowed = await checkAndIncrementQuota(env.DB, ipKey, hourBucket, HOURLY_IP_LIMIT);
      if (!ipAllowed) {
        return jsonResponse({ error: "rate_limited_ip" }, 429, { "Retry-After": "900" });
      }
      const repAllowed = await checkAndIncrementQuota(env.DB, repKey, dayBucket, DAILY_REPORTER_LIMIT);
      if (!repAllowed) {
        return jsonResponse({ error: "rate_limited_reporter" }, 429, { "Retry-After": "3600" });
      }

      // Network-level origin truth from Cloudflare edge
      const cfCountry = String(request.cf?.country || "").toUpperCase();
      const cfAsn = Number(request.cf?.asn || 0);
      const cfAsOrg = String(request.cf?.asOrganization || "");
      const isDatacenter = isLikelyDatacenterAsnOrg(cfAsOrg);

      let accepted = 0;
      for (const item of reports) {
        const reportId = String(item?.report_id || "").toLowerCase();
        const serverId = String(item?.server_id || "").toLowerCase();
        const cfgFp = String(item?.config_fingerprint || "").toLowerCase();
        const proto = String(item?.protocol || "").toLowerCase();

        if (!isHexOfLength(reportId, 16, 64) ||
            !isHexOfLength(serverId, 24, 32) ||
            !isHexOfLength(cfgFp, 24, 64) ||
            !ALLOWED_PROTOCOLS.has(proto)) {
          continue;
        }

        const clientVpnInterference = Boolean(item?.vpn_interference) || isDatacenter;
        const validEdgeCountry = /^[A-Z]{2}$/.test(cfCountry) && cfCountry !== "XX" && cfCountry !== "T1";

        // Strict IR rule: ONLY assign verified IR when Cloudflare edge confirms IR AND no VPN/DC interference!
        const verifiedCountry = (!clientVpnInterference && validEdgeCountry) ? cfCountry : "";
        const confidence = clientVpnInterference
          ? "VPN_OR_DC_INTERFERENCE"
          : (validEdgeCountry ? "CF_EDGE_VERIFIED" : "UNVERIFIED");

        const success = item?.success === true ? 1 : 0;
        const handshakeMs = Math.max(0, Math.min(30000, Math.round(Number(item?.handshake_ms || 0))));
        const latencyMs = Math.max(0, Math.min(15000, Math.round(Number(item?.latency_ms || 0))));
        const downloadKbps = Math.max(0, Math.min(500000, Number(item?.download_kbps || 0)));
        const stabilityScore = Math.max(0, Math.min(100, Number(item?.stability_score || 0)));
        const dnsOk = item?.dns_ok === true ? 1 : 0;
        const tcpOk = item?.tcp_ok === true ? 1 : 0;
        const udpOk = item?.udp_ok === true ? 1 : 0;
        const failReason = String(item?.failure_reason || "").replace(/[^A-Z0-9_]/gi, "").slice(0, 48);
        const transport = String(item?.network_transport || "UNKNOWN").replace(/[^A-Z_]/gi, "").slice(0, 16);
        const testedEpoch = Math.max(nowEpoch - 86400, Math.min(nowEpoch + 300, Math.floor(Number(item?.tested_at_epoch || nowEpoch))));

        await env.DB.prepare(
          `INSERT OR IGNORE INTO community_reports (
             report_id, server_id, config_fingerprint, protocol, reporter_id_hash,
             bucket_6h, tested_at_epoch, received_at_epoch, success, handshake_ms,
             latency_ms, download_kbps, stability_score, dns_ok, tcp_ok, udp_ok,
             failure_reason, verified_country, country_confidence, vpn_interference,
             network_transport, asn_bucket
           ) VALUES (
             ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
             ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22
           )`
        ).bind(
          reportId, serverId, cfgFp, proto, reporterHash,
          bucket6h, testedEpoch, nowEpoch, success, handshakeMs,
          latencyMs, downloadKbps, stabilityScore, dnsOk, tcpOk, udpOk,
          failReason, verifiedCountry, confidence, clientVpnInterference ? 1 : 0,
          transport, cfAsn
        ).run();
        accepted++;
      }

      // Prune reports older than 14 days to stay comfortably inside D1 5GB Free Tier forever
      if (Math.random() < 0.05) {
        await env.DB.prepare("DELETE FROM community_reports WHERE received_at_epoch < ?1")
          .bind(nowEpoch - 14 * 86400).run();
        await env.DB.prepare("DELETE FROM rate_limits WHERE window_epoch < ?1")
          .bind(dayBucket - 2).run();
      }

      return jsonResponse({ status: "accepted", accepted_count: accepted });
    }

    if (request.method === "GET" && url.pathname === "/v1/export") {
      const expectedToken = String(env.COMMUNITY_EXPORT_TOKEN || "");
      const authHdr = request.headers.get("Authorization") || "";
      const provided = authHdr.startsWith("Bearer ") ? authHdr.slice(7).trim() : "";
      if (!expectedToken || !timingSafeEqualStr(provided, expectedToken)) {
        return jsonResponse({ error: "unauthorized" }, 401);
      }

      const sinceId = Math.max(0, Number(url.searchParams.get("after_id") || "0"));
      const limit = Math.max(1, Math.min(2000, Number(url.searchParams.get("limit") || "1000")));
      const { results } = await env.DB.prepare(
        `SELECT id, report_id, server_id, config_fingerprint, protocol, reporter_id_hash,
                tested_at_epoch, received_at_epoch, success, handshake_ms, latency_ms,
                download_kbps, stability_score, dns_ok, tcp_ok, udp_ok, failure_reason,
                verified_country, country_confidence, vpn_interference, network_transport, asn_bucket
         FROM community_reports
         WHERE id > ?1
         ORDER BY id ASC
         LIMIT ?2`
      ).bind(sinceId, limit).all();

      return jsonResponse({
        schema_version: "1.0",
        exported_at_epoch: Math.floor(Date.now() / 1000),
        count: results.length,
        next_after_id: results.length > 0 ? results[results.length - 1].id : sinceId,
        reports: results,
      });
    }

    return jsonResponse({ error: "not_found" }, 404);
  },
};
