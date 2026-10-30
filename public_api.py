#!/usr/bin/env python3
"""
Phase 10 — Read-Only Public Statistics API v1 (`public_api.py`).

Operates in two complementary modes (100% compatible with Pure-GitHub hosting):
  1. Static Versioned API Tree (`export_static_api_v1`) written to `dist/api/v1/`
     for zero-cost serverless delivery over GitHub Pages / jsDelivr CDN.
  2. Live Read-Only HTTP Server (`PublicStatisticsApiApp` + `ThreadingHTTPServer`)
     exposing:
       GET /api/v1/servers
       GET /api/v1/servers/{id}
       GET /api/v1/statistics
       GET /api/v1/countries
       GET /api/v1/protocols
       GET /api/v1/sources
       GET /api/v1/health
       GET /api/v1/openapi.json
     with pagination, filtering, per-IP token-bucket rate limiting, ETag/304
     caching, strict input validation, and OpenAPI 3.1 documentation.

Security Boundary:
  NEVER exposes raw proxy URIs, UUIDs, passwords, tokens, VIP nodes, or
  unmasked server IP addresses.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

API_VERSION = "1.0.0"
MAX_PER_PAGE = 100
DEFAULT_PER_PAGE = 25
MAX_HISTORY_SNAPSHOTS = 96  # 48 hours @ 30-min cadence

_VALID_SERVER_ID_RE = re.compile(r"^[a-f0-9]{6,24}$")
_VALID_COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
_VALID_PROTO_RE = re.compile(r"^[a-z0-9_+-]{2,16}$")
_ALLOWED_RISKS = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"})
_ALLOWED_SECURITY = frozenset({"Verified", "Partial", "Unknown", "Failed"})
_ALLOWED_PROFILES = frozenset({"BALANCED", "LOW_LATENCY", "HIGH_SPEED", "HIGH_RELIABILITY", "PRIVACY_AWARE"})


def mask_endpoint_host(host: str) -> str:
    """Mask host/IP so public statistics never leak exact residential/private node IPs."""
    h = (host or "").strip().strip("[]").rstrip(".").lower()
    if not h:
        return "masked"
    try:
        ip = ipaddress.ip_address(h)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if isinstance(ip, ipaddress.IPv4Address):
            parts = str(ip).split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        net6 = ipaddress.IPv6Network(f"{ip}/48", strict=False)
        return f"{net6.network_address}/48"
    except ValueError:
        labels = [p for p in h.split(".") if p]
        if len(labels) >= 3:
            return "*." + ".".join(labels[-2:])
        return h


def sanitize_server_for_public_api(raw_srv: dict[str, Any]) -> dict[str, Any]:
    """
    Convert an internal `alive.json` server entry into a strictly secret-free
    public telemetry record (strips `cfg`, `uri`, credentials, and exact IP).
    """
    sid = str(raw_srv.get("id") or "").strip().lower()
    if not sid:
        seed = f"{raw_srv.get('name', '')}:{raw_srv.get('proto', '')}:{raw_srv.get('port', 0)}"
        sid = hashlib.sha256(seed.encode("utf-8", "ignore")).hexdigest()[:12]

    speed_kbps = float(raw_srv.get("speed_kbps", 0.0) or 0.0)
    upload_kbps = float(raw_srv.get("upload_kbps", 0.0) or 0.0)
    perf = float(raw_srv.get("performance_score", raw_srv.get("score", 0.0)) or 0.0)
    rel = float(raw_srv.get("reliability_score", raw_srv.get("score", 0.0)) or 0.0)
    pass_rate = float(raw_srv.get("probe_pass_rate", 1.0) or 1.0)
    loss_pct = float(raw_srv.get("packet_loss_pct", max(0.0, (1.0 - pass_rate) * 100.0)))

    return {
        "id": sid,
        "name": str(raw_srv.get("name", f"bahrain-vpn-{sid[:6]}")),
        "status": "ALIVE",
        "protocol": str(raw_srv.get("canonical_protocol") or raw_srv.get("protocol") or raw_srv.get("proto") or "unknown").lower(),
        "masked_network": mask_endpoint_host(str(raw_srv.get("host", ""))),
        "exit_country": str(raw_srv.get("exit_country", "XX")).upper(),
        "country_source": str(raw_srv.get("country_source", "unknown")),
        "is_cdn": bool(raw_srv.get("is_cdn", False)),
        "performance_score": round(perf, 1),
        "reliability_score": round(rel, 1),
        "composite_score": round(float(raw_srv.get("score", perf) or 0.0), 1),
        "security_assessment": str(raw_srv.get("security_assessment", "Unknown")),
        "privacy_assessment": str(raw_srv.get("privacy_assessment", "Unverified")),
        "risk_level": str(raw_srv.get("risk_level", "UNKNOWN")),
        "latency_ms": round(float(raw_srv.get("median_latency_ms") or raw_srv.get("latency_ms") or 0.0), 1),
        "jitter_ms": round(float(raw_srv.get("jitter_ms", 0.0) or 0.0), 1),
        "download_mbps": round((speed_kbps * 8.0) / 1000.0, 2) if speed_kbps > 0 else 0.0,
        "upload_mbps": round((upload_kbps * 8.0) / 1000.0, 2) if upload_kbps > 0 else 0.0,
        "packet_loss_pct": round(loss_pct, 2),
        "uptime_pct": round(float(raw_srv.get("uptime_pct", 100.0) or 100.0), 2),
        "consecutive_alive": int(raw_srv.get("consecutive_alive", 1) or 1),
        "score_delta": round(float(raw_srv.get("score_delta", 0.0) or 0.0), 1),
        "verified_at": str(raw_srv.get("verified_at", "")),
    }


def build_openapi_spec() -> dict[str, Any]:
    """Return OpenAPI 3.1.0 specification for Public Statistics API v1."""
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "bahrain-vpn Public Infrastructure Intelligence API",
            "version": API_VERSION,
            "description": (
                "Read-only, secret-free telemetry API exposing multi-dimensional VPN server "
                "performance, reliability, security/privacy assessments, protocol analytics, "
                "geographic distributions, and source health."
            ),
        },
        "paths": {
            "/api/v1/servers": {
                "get": {
                    "summary": "List sanitized active servers with pagination and filtering",
                    "parameters": [
                        {"name": "page", "in": "query", "schema": {"type": "integer", "minimum": 1, "default": 1}},
                        {"name": "per_page", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": MAX_PER_PAGE, "default": DEFAULT_PER_PAGE}},
                        {"name": "country", "in": "query", "schema": {"type": "string", "example": "DE"}},
                        {"name": "protocol", "in": "query", "schema": {"type": "string", "example": "vless"}},
                        {"name": "risk", "in": "query", "schema": {"type": "string", "enum": sorted(_ALLOWED_RISKS)}},
                        {"name": "security", "in": "query", "schema": {"type": "string", "enum": sorted(_ALLOWED_SECURITY)}},
                        {"name": "min_performance", "in": "query", "schema": {"type": "number", "minimum": 0, "maximum": 100}},
                        {"name": "profile", "in": "query", "schema": {"type": "string", "enum": sorted(_ALLOWED_PROFILES)}},
                    ],
                    "responses": {"200": {"description": "Paginated server list"}, "400": {"description": "Invalid filter"}, "429": {"description": "Rate limit exceeded"}},
                }
            },
            "/api/v1/servers/{id}": {
                "get": {
                    "summary": "Retrieve sanitized telemetry for a single server ID",
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "Server detail"}, "404": {"description": "Server not found"}},
                }
            },
            "/api/v1/statistics": {"get": {"summary": "Global overview, averages, risk distribution, and historical trend series", "responses": {"200": {"description": "Statistics object"}}}},
            "/api/v1/countries": {"get": {"summary": "Geographic server distribution and country-level reliability/performance", "responses": {"200": {"description": "Countries analytics"}}}},
            "/api/v1/protocols": {"get": {"summary": "Protocol distribution, success rates, and average performance", "responses": {"200": {"description": "Protocols analytics"}}}},
            "/api/v1/sources": {"get": {"summary": "Sanitized Telegram & GitHub source health and quarantine summary", "responses": {"200": {"description": "Sources analytics"}}}},
            "/api/v1/health": {"get": {"summary": "Pipeline liveness, freshness, and operational health", "responses": {"200": {"description": "Health check"}}}},
        },
    }


def _atomic_write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def export_static_api_v1(
    out_dir: Path,
    *,
    prev_dir: Path | None = None,
    meta: dict[str, Any],
    alive_servers_dicts: list[dict[str, Any]],
    tested_by_proto: dict[str, tuple[int, int]] | None = None,
    quarantined_total: int = 0,
    quarantined_reasons: dict[str, int] | None = None,
    source_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Generate the complete `/api/v1/*` JSON tree + bounded longitudinal
    `state/pipeline_history.json` into `out_dir`.
    """
    now_iso = str(meta.get("generated_at") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    sanitized_servers = [sanitize_server_for_public_api(s) for s in alive_servers_dicts]

    active_total = len(sanitized_servers)
    tested_total = int(meta.get("tested", active_total) or active_total)
    failed_total = max(0, tested_total - active_total)
    healthy_total = sum(
        1 for s in sanitized_servers
        if s["reliability_score"] >= 60.0 and s["packet_loss_pct"] < 25.0
    )

    avg_lat = round(sum(s["latency_ms"] for s in sanitized_servers) / active_total, 1) if active_total else 0.0
    avg_jit = round(sum(s["jitter_ms"] for s in sanitized_servers) / active_total, 1) if active_total else 0.0
    measured_dl = [s["download_mbps"] for s in sanitized_servers if s["download_mbps"] > 0]
    avg_dl = round(sum(measured_dl) / len(measured_dl), 2) if measured_dl else 0.0
    avg_loss = round(sum(s["packet_loss_pct"] for s in sanitized_servers) / active_total, 2) if active_total else 0.0
    avg_uptime = round(sum(s["uptime_pct"] for s in sanitized_servers) / active_total, 2) if active_total else 0.0
    avg_perf = round(sum(s["performance_score"] for s in sanitized_servers) / active_total, 1) if active_total else 0.0
    avg_rel = round(sum(s["reliability_score"] for s in sanitized_servers) / active_total, 1) if active_total else 0.0

    sec_counts: dict[str, int] = {}
    risk_counts: dict[str, int] = {}
    for s in sanitized_servers:
        sec_counts[s["security_assessment"]] = sec_counts.get(s["security_assessment"], 0) + 1
        risk_counts[s["risk_level"]] = risk_counts.get(s["risk_level"], 0) + 1

    # Load & append bounded pipeline historical series (for Phase 8 trend charts)
    prior_hist: list[dict[str, Any]] = []
    for base in (prev_dir, out_dir):
        if base and (base / "state" / "pipeline_history.json").is_file():
            try:
                loaded = json.loads((base / "state" / "pipeline_history.json").read_text(encoding="utf-8"))
                if isinstance(loaded, list):
                    prior_hist = loaded
                    break
            except Exception:
                continue

    src_summary = (source_report or {}).get("summary", {}) if isinstance(source_report, dict) else {}
    monitored_sources_total = int(meta.get("channels_total", 0)) + int(meta.get("github_sources", 0))
    active_sources_cnt = int(src_summary.get("active", 0))

    snapshot = {
        "timestamp": now_iso,
        "collected": int(meta.get("raw_collected", 0)),
        "unique_clean": int(meta.get("unique_clean", 0)),
        "tested": tested_total,
        "active": active_total,
        "healthy": healthy_total,
        "failed": failed_total,
        "quarantined": quarantined_total,
        "avg_latency_ms": avg_lat,
        "avg_jitter_ms": avg_jit,
        "avg_download_mbps": avg_dl,
        "avg_packet_loss_pct": avg_loss,
        "avg_performance_score": avg_perf,
        "avg_reliability_score": avg_rel,
        "active_sources": active_sources_cnt,
    }
    history_series = ([h for h in prior_hist if isinstance(h, dict) and h.get("timestamp") != now_iso] + [snapshot])[-MAX_HISTORY_SNAPSHOTS:]
    _atomic_write_json(out_dir / "state" / "pipeline_history.json", history_series)

    # 1. Countries Analytics
    by_cc: dict[str, list[dict[str, Any]]] = {}
    for s in sanitized_servers:
        by_cc.setdefault(s["exit_country"] or "XX", []).append(s)

    countries_list = []
    for cc, items in sorted(by_cc.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        dl_vals = [x["download_mbps"] for x in items if x["download_mbps"] > 0]
        countries_list.append({
            "country": cc,
            "active_servers": len(items),
            "verified_exit_servers": sum(1 for x in items if x["country_source"] == "exit_trace"),
            "avg_latency_ms": round(sum(x["latency_ms"] for x in items) / len(items), 1),
            "best_latency_ms": round(min(x["latency_ms"] for x in items), 1),
            "avg_download_mbps": round(sum(dl_vals) / len(dl_vals), 2) if dl_vals else 0.0,
            "avg_performance_score": round(sum(x["performance_score"] for x in items) / len(items), 1),
            "avg_reliability_score": round(sum(x["reliability_score"] for x in items) / len(items), 1),
            "verified_security_count": sum(1 for x in items if x["security_assessment"] == "Verified"),
        })
    countries_payload = {
        "api_version": API_VERSION,
        "generated_at": now_iso,
        "total_countries": len([c for c in countries_list if c["country"] != "XX"]),
        "best_performing_countries": sorted(
            [c for c in countries_list if c["country"] != "XX"],
            key=lambda c: (-c["avg_performance_score"], c["avg_latency_ms"]),
        )[:10],
        "countries": countries_list,
    }

    # 2. Protocols Analytics
    by_proto: dict[str, list[dict[str, Any]]] = {}
    for s in sanitized_servers:
        by_proto.setdefault(s["protocol"], []).append(s)

    protocols_list = []
    all_protos = sorted(set(by_proto.keys()) | set((tested_by_proto or {}).keys()))
    for proto in all_protos:
        items = by_proto.get(proto, [])
        t_pair = (tested_by_proto or {}).get(proto)
        tested_p = t_pair[0] if t_pair else len(items)
        alive_p = t_pair[1] if t_pair else len(items)
        succ_rate = round(alive_p / max(1, tested_p), 4) if tested_p > 0 else 0.0
        dl_vals = [x["download_mbps"] for x in items if x["download_mbps"] > 0]
        protocols_list.append({
            "protocol": proto,
            "active_servers": len(items),
            "tested_candidates": tested_p,
            "success_rate": succ_rate,
            "avg_latency_ms": round(sum(x["latency_ms"] for x in items) / len(items), 1) if items else 0.0,
            "avg_download_mbps": round(sum(dl_vals) / len(dl_vals), 2) if dl_vals else 0.0,
            "avg_reliability_score": round(sum(x["reliability_score"] for x in items) / len(items), 1) if items else 0.0,
            "verified_security_count": sum(1 for x in items if x["security_assessment"] == "Verified"),
        })
    protocols_list.sort(key=lambda p: (-p["active_servers"], p["protocol"]))
    protocols_payload = {
        "api_version": API_VERSION,
        "generated_at": now_iso,
        "protocols": protocols_list,
    }

    # 3. Sources Analytics (sanitized)
    sources_payload = {
        "api_version": API_VERSION,
        "generated_at": now_iso,
        "monitored_total": monitored_sources_total,
        "summary": src_summary,
        "github_sources": (source_report or {}).get("github_sources", []),
        "telegram_channels_summary": (source_report or {}).get("telegram_channels_summary", {}),
    }

    # 4. Global Statistics Overview + Historical Trend Series
    statistics_payload = {
        "api_version": API_VERSION,
        "generated_at": now_iso,
        "overview": {
            "total_collected_configs": int(meta.get("raw_collected", 0)),
            "unique_clean_configs": int(meta.get("unique_clean", 0)),
            "tested_configs": tested_total,
            "active_servers": active_total,
            "healthy_servers": healthy_total,
            "failed_servers": failed_total,
            "quarantined_servers": quarantined_total,
            "monitored_sources": monitored_sources_total,
            "last_successful_execution": now_iso,
            "pipeline_duration_sec": float(meta.get("duration_sec", 0.0) or 0.0),
            "degraded_mode": bool(meta.get("degraded_mode", False)),
        },
        "performance_analytics": {
            "avg_latency_ms": avg_lat,
            "avg_jitter_ms": avg_jit,
            "avg_download_mbps": avg_dl,
            "avg_packet_loss_pct": avg_loss,
            "historical_availability_pct": avg_uptime,
            "avg_performance_score": avg_perf,
            "avg_reliability_score": avg_rel,
        },
        "security_analytics": {
            "security_assessments": sec_counts,
            "risk_levels": risk_counts,
            "quarantined_reasons": quarantined_reasons or {},
        },
        "history": history_series,
    }

    # 5. Health Check
    health_payload = {
        "api_version": API_VERSION,
        "status": "degraded" if meta.get("degraded_mode") else ("ok" if active_total > 0 else "empty"),
        "generated_at": now_iso,
        "active_servers": active_total,
        "healthy_servers": healthy_total,
        "quarantined_servers": quarantined_total,
        "degraded_mode": bool(meta.get("degraded_mode", False)),
    }

    # 6. Servers Root & Per-Server Static Files
    api_root = out_dir / "api" / "v1"
    total_pages = max(1, math.ceil(len(sanitized_servers) / DEFAULT_PER_PAGE))
    servers_index_payload = {
        "api_version": API_VERSION,
        "generated_at": now_iso,
        "pagination": {
            "page": 1,
            "per_page": DEFAULT_PER_PAGE,
            "total_items": len(sanitized_servers),
            "total_pages": total_pages,
        },
        "items": sanitized_servers[:DEFAULT_PER_PAGE],
        "all_items": sanitized_servers,
    }

    _atomic_write_json(api_root / "servers.json", servers_index_payload)
    _atomic_write_json(api_root / "statistics.json", statistics_payload)
    _atomic_write_json(api_root / "countries.json", countries_payload)
    _atomic_write_json(api_root / "protocols.json", protocols_payload)
    _atomic_write_json(api_root / "sources.json", sources_payload)
    _atomic_write_json(api_root / "health.json", health_payload)
    _atomic_write_json(api_root / "openapi.json", build_openapi_spec())

    srv_dir = api_root / "servers"
    srv_dir.mkdir(parents=True, exist_ok=True)
    for srv in sanitized_servers:
        _atomic_write_json(srv_dir / f"{srv['id']}.json", {"api_version": API_VERSION, "server": srv})

    return statistics_payload


class TokenBucketRateLimiter:
    """Thread-safe per-client-IP token bucket limiter."""

    def __init__(self, rate_per_minute: int = 60, burst: int | None = None) -> None:
        self.rate_per_sec = max(0.05, rate_per_minute / 60.0)
        self.capacity = float(burst if burst is not None else max(1, rate_per_minute))
        self.limit_header = max(1, rate_per_minute)
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, client_ip: str, now_monotonic: float | None = None) -> tuple[bool, int, int]:
        """Return (allowed, remaining_tokens, retry_after_sec)."""
        now = now_monotonic if now_monotonic is not None else time.monotonic()
        key = client_ip or "unknown"
        with self._lock:
            if len(self._buckets) > 4096:
                self._buckets.clear()
            tokens, last_ts = self._buckets.get(key, (self.capacity, now))
            elapsed = max(0.0, now - last_ts)
            tokens = min(self.capacity, tokens + elapsed * self.rate_per_sec)
            if tokens >= 1.0:
                tokens -= 1.0
                self._buckets[key] = (tokens, now)
                return True, int(tokens), 0
            self._buckets[key] = (tokens, now)
            retry_sec = max(1, math.ceil((1.0 - tokens) / self.rate_per_sec))
            return False, 0, retry_sec


class PublicStatisticsApiApp:
    """
    Deterministic, read-only request router over `dist/api/v1/` with ETag caching,
    query validation, filtering, pagination, and rate limiting.
    """

    def __init__(self, dist_dir: Path, *, rate_limit_per_min: int = 60, cache_ttl_sec: int = 15) -> None:
        self.dist_dir = Path(dist_dir)
        self.api_dir = self.dist_dir / "api" / "v1"
        self.limiter = TokenBucketRateLimiter(rate_per_minute=rate_limit_per_min)
        self.cache_ttl_sec = max(1, cache_ttl_sec)
        self._mem_cache: dict[str, tuple[float, Any, str]] = {}
        self._lock = threading.Lock()

    def _load_json_cached(self, filename: str) -> tuple[Any, str] | tuple[None, str]:
        now = time.monotonic()
        with self._lock:
            cached = self._mem_cache.get(filename)
            if cached and (now - cached[0]) < self.cache_ttl_sec:
                return cached[1], cached[2]

        fpath = self.api_dir / filename
        if not fpath.is_file():
            return None, ""
        raw_bytes = fpath.read_bytes()
        etag = '"' + hashlib.sha256(raw_bytes).hexdigest()[:20] + '"'
        obj = json.loads(raw_bytes.decode("utf-8"))
        with self._lock:
            self._mem_cache[filename] = (now, obj, etag)
        return obj, etag

    @staticmethod
    def _error_response(status: int, code: str, message: str, extra_headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
        body = json.dumps(
            {"api_version": API_VERSION, "error": {"code": code, "message": message}},
            ensure_ascii=False,
        ).encode("utf-8")
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        }
        if extra_headers:
            headers.update(extra_headers)
        return status, headers, body

    def handle_get(
        self,
        raw_path_and_query: str,
        *,
        client_ip: str = "127.0.0.1",
        if_none_match: str = "",
    ) -> tuple[int, dict[str, str], bytes]:
        allowed, remaining, retry_after = self.limiter.allow(client_ip)
        rl_headers = {
            "X-RateLimit-Limit": str(self.limiter.limit_header),
            "X-RateLimit-Remaining": str(remaining),
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, OPTIONS",
        }
        if not allowed:
            rl_headers["Retry-After"] = str(retry_after)
            return self._error_response(429, "rate_limit_exceeded", "Rate limit exceeded; retry later.", rl_headers)

        parts = urlsplit(raw_path_and_query)
        path = parts.path.rstrip("/") or "/"
        query = {k: v[-1] for k, v in parse_qs(parts.query, keep_blank_values=False).items() if v}

        if path == "/api/v1/openapi.json" or path == "/api/v1/openapi":
            spec = build_openapi_spec()
            raw = json.dumps(spec, ensure_ascii=False).encode("utf-8")
            etag = '"' + hashlib.sha256(raw).hexdigest()[:20] + '"'
            if if_none_match == etag:
                return 304, {**rl_headers, "ETag": etag}, b""
            return 200, {**rl_headers, "Content-Type": "application/json; charset=utf-8", "ETag": etag, "Cache-Control": "public, max-age=300", "X-Content-Type-Options": "nosniff"}, raw

        simple_map = {
            "/api/v1/statistics": "statistics.json",
            "/api/v1/countries": "countries.json",
            "/api/v1/protocols": "protocols.json",
            "/api/v1/sources": "sources.json",
            "/api/v1/health": "health.json",
        }
        if path in simple_map:
            obj, etag = self._load_json_cached(simple_map[path])
            if obj is None:
                return self._error_response(503, "dataset_unavailable", "Dataset has not been generated yet.", rl_headers)
            if if_none_match and if_none_match == etag:
                return 304, {**rl_headers, "ETag": etag, "Cache-Control": "public, max-age=60"}, b""
            raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            return 200, {
                **rl_headers,
                "Content-Type": "application/json; charset=utf-8",
                "ETag": etag,
                "Cache-Control": "public, max-age=60",
                "X-Content-Type-Options": "nosniff",
            }, raw

        if path == "/api/v1/servers":
            return self._handle_servers_list(query, rl_headers, if_none_match)

        if path.startswith("/api/v1/servers/"):
            srv_id = path.removeprefix("/api/v1/servers/").strip().lower()
            if not _VALID_SERVER_ID_RE.match(srv_id):
                return self._error_response(400, "invalid_server_id", "Server ID must be a 6..24 lowercase hex identifier.", rl_headers)
            obj, etag = self._load_json_cached(f"servers/{srv_id}.json")
            if obj is None:
                return self._error_response(404, "server_not_found", f"Server '{srv_id}' not found.", rl_headers)
            if if_none_match and if_none_match == etag:
                return 304, {**rl_headers, "ETag": etag}, b""
            raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            return 200, {
                **rl_headers,
                "Content-Type": "application/json; charset=utf-8",
                "ETag": etag,
                "Cache-Control": "public, max-age=60",
                "X-Content-Type-Options": "nosniff",
            }, raw

        return self._error_response(404, "route_not_found", f"Unknown API endpoint: {path}", rl_headers)

    def _handle_servers_list(
        self,
        query: dict[str, str],
        rl_headers: dict[str, str],
        if_none_match: str,
    ) -> tuple[int, dict[str, str], bytes]:
        obj, base_etag = self._load_json_cached("servers.json")
        if obj is None:
            return self._error_response(503, "dataset_unavailable", "Servers dataset unavailable.", rl_headers)

        try:
            page = int(query.get("page", "1"))
            per_page = int(query.get("per_page", str(DEFAULT_PER_PAGE)))
        except ValueError:
            return self._error_response(400, "invalid_pagination", "'page' and 'per_page' must be integers.", rl_headers)
        if page < 1 or not (1 <= per_page <= MAX_PER_PAGE):
            return self._error_response(400, "out_of_range_pagination", f"'page' >= 1 and 1 <= 'per_page' <= {MAX_PER_PAGE} required.", rl_headers)

        items: list[dict[str, Any]] = list(obj.get("all_items") or obj.get("items") or [])

        if "country" in query:
            cc = query["country"].strip().upper()
            if not _VALID_COUNTRY_RE.match(cc):
                return self._error_response(400, "invalid_country", "Country filter must be a 2-letter ISO code.", rl_headers)
            items = [s for s in items if s.get("exit_country") == cc]

        if "protocol" in query:
            proto = query["protocol"].strip().lower()
            if not _VALID_PROTO_RE.match(proto):
                return self._error_response(400, "invalid_protocol", "Invalid protocol filter.", rl_headers)
            if proto == "hy2":
                proto = "hysteria2"
            items = [s for s in items if s.get("protocol") == proto]

        if "risk" in query:
            rk = query["risk"].strip().upper()
            if rk not in _ALLOWED_RISKS:
                return self._error_response(400, "invalid_risk", f"Risk must be one of {sorted(_ALLOWED_RISKS)}.", rl_headers)
            items = [s for s in items if s.get("risk_level") == rk]

        if "security" in query:
            sec = query["security"].strip().title()
            if sec not in _ALLOWED_SECURITY:
                return self._error_response(400, "invalid_security", f"Security must be one of {sorted(_ALLOWED_SECURITY)}.", rl_headers)
            items = [s for s in items if s.get("security_assessment") == sec]

        if "min_performance" in query:
            try:
                min_p = float(query["min_performance"])
            except ValueError:
                return self._error_response(400, "invalid_min_performance", "'min_performance' must be numeric.", rl_headers)
            if not (0.0 <= min_p <= 100.0):
                return self._error_response(400, "invalid_min_performance", "'min_performance' must be in 0..100.", rl_headers)
            items = [s for s in items if float(s.get("performance_score", 0.0)) >= min_p]

        if "profile" in query:
            prof = query["profile"].strip().upper()
            if prof not in _ALLOWED_PROFILES:
                return self._error_response(400, "invalid_profile", f"Profile must be one of {sorted(_ALLOWED_PROFILES)}.", rl_headers)
            if prof == "LOW_LATENCY":
                items.sort(key=lambda s: (s.get("latency_ms", 9999.0) or 9999.0, -s.get("reliability_score", 0.0)))
            elif prof == "HIGH_SPEED":
                items.sort(key=lambda s: (-s.get("download_mbps", 0.0), s.get("latency_ms", 9999.0)))
            elif prof == "HIGH_RELIABILITY":
                items.sort(key=lambda s: (-s.get("reliability_score", 0.0), s.get("packet_loss_pct", 100.0)))
            elif prof == "PRIVACY_AWARE":
                items = [
                    s for s in items
                    if s.get("security_assessment") != "Failed"
                    and s.get("risk_level") not in ("HIGH", "CRITICAL")
                    and s.get("privacy_assessment") != "High Risk"
                ]
                sec_rank = {"Verified": 0, "Partial": 1, "Unknown": 2, "Failed": 3}
                items.sort(key=lambda s: (sec_rank.get(s.get("security_assessment", "Unknown"), 2), -s.get("reliability_score", 0.0)))
            else:
                items.sort(key=lambda s: (-s.get("composite_score", 0.0), s.get("latency_ms", 9999.0)))

        total_items = len(items)
        total_pages = max(1, math.ceil(total_items / per_page))
        start = (page - 1) * per_page
        page_slice = items[start : start + per_page]

        resp_payload = {
            "api_version": API_VERSION,
            "generated_at": obj.get("generated_at", ""),
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total_items": total_items,
                "total_pages": total_pages,
            },
            "items": page_slice,
        }
        raw = json.dumps(resp_payload, ensure_ascii=False).encode("utf-8")
        etag = '"' + hashlib.sha256(base_etag.encode("ascii") + raw).hexdigest()[:20] + '"'
        if if_none_match and if_none_match == etag:
            return 304, {**rl_headers, "ETag": etag, "Cache-Control": "public, max-age=60"}, b""
        return 200, {
            **rl_headers,
            "Content-Type": "application/json; charset=utf-8",
            "ETag": etag,
            "Cache-Control": "public, max-age=60",
            "X-Content-Type-Options": "nosniff",
        }, raw


def create_public_api_http_server(
    dist_dir: Path,
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    rate_limit_per_min: int = 60,
) -> ThreadingHTTPServer:
    """Create a thread-pooled read-only HTTP server serving `/api/v1/*`."""
    app = PublicStatisticsApiApp(dist_dir, rate_limit_per_min=rate_limit_per_min)

    class _Handler(BaseHTTPRequestHandler):
        def do_OPTIONS(self) -> None:  # noqa: N802
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            client_ip = self.client_address[0] if self.client_address else "unknown"
            inm = self.headers.get("If-None-Match", "")
            status, headers, body = app.handle_get(self.path, client_ip=client_ip, if_none_match=inm)
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    return ThreadingHTTPServer((host, port), _Handler)
