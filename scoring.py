#!/usr/bin/env python3
"""
Multi-stage validation metadata (L0-L6), longitudinal stability tracking,
honest exit/entry geolocation classification, multi-metric composite scoring,
specialized list builders, and source health lifecycle management.
"""
from __future__ import annotations

import ipaddress
import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import unquote

from dedupe import ConfigProvenance, canonical_protocol, parse_identity, subnet_group_key

MAX_HISTORY_ENTRIES = 5_000

# Cloudflare, Fastly & major Anycast CDN IPv4/IPv6 ranges (entry IP != backend exit IP)
_CDN_IPV4_NETS = tuple(
    ipaddress.IPv4Network(cidr)
    for cidr in (
        "104.16.0.0/12",
        "172.64.0.0/13",
        "162.158.0.0/15",
        "108.162.192.0/18",
        "141.101.64.0/18",
        "188.114.96.0/20",
        "190.93.240.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "131.0.72.0/22",
        "151.101.0.0/16",
    )
)
_CDN_IPV6_NETS = tuple(
    ipaddress.IPv6Network(cidr)
    for cidr in (
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32",
    )
)
_CDN_HOST_SUFFIXES = (
    ".workers.dev",
    ".pages.dev",
    ".cloudflare.com",
    ".trycloudflare.com",
    ".cloudfront.net",
    ".fastly.net",
    ".gcore.lu",
)

# Common genuine geographic ccTLDs (excluding vanity TLDs like .io, .co, .tv, .me, .ai, .gg, .ws, .cc, .tk)
_GEO_CCTLDS = frozenset({
    "ae", "at", "au", "bg", "bh", "br", "ca", "ch", "cz", "de", "dk", "ee",
    "es", "fi", "fr", "gb", "gr", "hk", "hu", "id", "ie", "il", "in", "ir",
    "it", "jp", "kr", "kz", "lt", "lu", "lv", "md", "my", "nl", "no", "OM",
    "pl", "pt", "qa", "ro", "rs", "ru", "sa", "se", "sg", "si", "sk", "th",
    "tr", "tw", "ua", "uk", "us", "vn", "za",
})

_VALID_ISO_COUNTRIES = frozenset({
    "AD", "AE", "AF", "AG", "AL", "AM", "AO", "AR", "AT", "AU", "AZ", "BA", "BD", "BE",
    "BG", "BH", "BN", "BO", "BR", "BS", "BY", "BZ", "CA", "CH", "CL", "CN", "CO", "CR",
    "CY", "CZ", "DE", "DK", "DO", "DZ", "EC", "EE", "EG", "ES", "ET", "FI", "FR", "GB",
    "GE", "GH", "GR", "GT", "HK", "HN", "HR", "HU", "ID", "IE", "IL", "IN", "IQ", "IR",
    "IS", "IT", "JM", "JO", "JP", "KE", "KG", "KH", "KR", "KW", "KZ", "LA", "LB", "LI",
    "LK", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MK", "MM", "MN", "MO", "MT",
    "MU", "MV", "MX", "MY", "MZ", "NA", "NG", "NI", "NL", "NO", "NP", "NZ", "OM", "PA",
    "PE", "PH", "PK", "PL", "PR", "PS", "PT", "PY", "QA", "RO", "RS", "RU", "RW", "SA",
    "SC", "SD", "SE", "SG", "SI", "SK", "SM", "SN", "SY", "TH", "TJ", "TM", "TN", "TR",
    "TT", "TW", "TZ", "UA", "UG", "US", "UY", "UZ", "VA", "VE", "VN", "YE", "ZA",
})


def is_cdn_endpoint(host: str, sni: str = "") -> bool:
    """Detect Anycast CDN entry endpoints where entry IP != exit location."""
    for candidate in (host, sni):
        c = (candidate or "").strip().strip("[]").rstrip(".").lower()
        if not c:
            continue
        if any(c.endswith(sfx) for sfx in _CDN_HOST_SUFFIXES):
            return True
        try:
            ip = ipaddress.ip_address(c)
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                ip = ip.ipv4_mapped
            if isinstance(ip, ipaddress.IPv4Address):
                if any(ip in net for net in _CDN_IPV4_NETS):
                    return True
            else:
                if any(ip in net for net in _CDN_IPV6_NETS):
                    return True
        except ValueError:
            continue
    return False


def _extract_flag_country(text: str) -> str:
    """Extract ISO-3166 alpha-2 code from Unicode Regional Indicator flag emojis."""
    chars = list(text)
    for i in range(len(chars) - 1):
        c1, c2 = ord(chars[i]), ord(chars[i + 1])
        if 0x1F1E6 <= c1 <= 0x1F1FF and 0x1F1E6 <= c2 <= 0x1F1FF:
            cc = chr(c1 - 0x1F1E6 + ord("A")) + chr(c2 - 0x1F1E6 + ord("A"))
            if cc in _VALID_ISO_COUNTRIES:
                return cc
    return ""


def infer_country_hint(uri: str, host: str) -> tuple[str, str]:
    """
    Best-effort non-authoritative country hint from URI remark or ccTLD.
    Explicitly labeled 'remark_hint' or 'tld_hint' — never confused with 'exit_trace'.
    """
    frag = ""
    if "#" in uri:
        frag = unquote(uri.split("#", 1)[1])
    elif uri.lower().startswith("vmess://"):
        ident = parse_identity(uri, reject_private_hosts=False)
        if ident:
            frag = ""
        # Check vmess ps remark
        import base64
        b64 = uri.partition("://")[2].split("?", 1)[0].split("#", 1)[0].strip()
        pad = b64 + "=" * (-len(b64) % 4)
        try:
            d = json.loads(base64.urlsafe_b64decode(pad).decode("utf-8", "ignore"))
            frag = str(d.get("ps", ""))
        except Exception:
            frag = ""

    if frag:
        flag_cc = _extract_flag_country(frag)
        if flag_cc:
            return flag_cc, "remark_hint"
        m = re.search(r"(?:^|[\s\[\(\-_\|])([A-Z]{2})(?:$|[\s\]\)\-_\|0-9])", frag.upper())
        if m and m.group(1) in _VALID_ISO_COUNTRIES and m.group(1) not in ("SS", "WS", "IP", "OK", "TV"):
            return m.group(1), "remark_hint"

    h = (host or "").strip().strip("[]").rstrip(".").lower()
    if "." in h:
        tld = h.rsplit(".", 1)[-1]
        if tld in _GEO_CCTLDS:
            cc = "GB" if tld == "uk" else tld.upper()
            if cc in _VALID_ISO_COUNTRIES:
                return cc, "tld_hint"

    return "XX", "unknown"


def country_flag(country_code: str) -> str:
    """Convert ISO-3166 alpha-2 code to Regional Indicator emoji flag (or 🌐 for XX)."""
    cc = (country_code or "").strip().upper()
    if len(cc) != 2 or cc == "XX" or not cc.isalpha():
        return "🌐"
    return chr(0x1F1E6 + ord(cc[0]) - ord("A")) + chr(0x1F1E6 + ord(cc[1]) - ord("A"))


@dataclass
class ScoringWeights:
    reliability: float = 0.35
    throughput: float = 0.25
    latency: float = 0.20
    stability: float = 0.12
    freshness: float = 0.08

    def normalized(self) -> "ScoringWeights":
        total = self.reliability + self.throughput + self.latency + self.stability + self.freshness
        if total <= 0:
            return ScoringWeights()
        return ScoringWeights(
            reliability=self.reliability / total,
            throughput=self.throughput / total,
            latency=self.latency / total,
            stability=self.stability / total,
            freshness=self.freshness / total,
        )

    def to_dict(self) -> dict[str, float]:
        w = self.normalized()
        return {
            "reliability": round(w.reliability, 4),
            "throughput": round(w.throughput, 4),
            "latency": round(w.latency, 4),
            "stability": round(w.stability, 4),
            "freshness": round(w.freshness, 4),
        }


@dataclass
class NodeHistoryEntry:
    runs_seen: int = 0
    runs_alive: int = 0
    consecutive_alive: int = 0
    consecutive_failures: int = 0
    ema_reliability: float = 0.5
    best_speed_kbps: float = 0.0
    last_latency_ms: float = 0.0
    last_performance_score: float = 0.0
    last_reliability_score: float = 0.0
    last_security_mode: str = ""
    exit_country: str = "XX"
    country_source: str = "unknown"
    last_seen_at: str = ""

    def to_dict(self) -> dict:
        return {
            "runs_seen": self.runs_seen,
            "runs_alive": self.runs_alive,
            "consecutive_alive": self.consecutive_alive,
            "consecutive_failures": self.consecutive_failures,
            "ema_reliability": round(self.ema_reliability, 4),
            "best_speed_kbps": round(self.best_speed_kbps, 1),
            "last_latency_ms": round(self.last_latency_ms, 1),
            "last_performance_score": round(self.last_performance_score, 1),
            "last_reliability_score": round(self.last_reliability_score, 1),
            "last_security_mode": self.last_security_mode,
            "exit_country": self.exit_country,
            "country_source": self.country_source,
            "last_seen_at": self.last_seen_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "NodeHistoryEntry":
        return cls(
            runs_seen=int(d.get("runs_seen", 0)),
            runs_alive=int(d.get("runs_alive", 0)),
            consecutive_alive=int(d.get("consecutive_alive", 0)),
            consecutive_failures=int(d.get("consecutive_failures", 0)),
            ema_reliability=float(d.get("ema_reliability", 0.5)),
            best_speed_kbps=float(d.get("best_speed_kbps", 0.0)),
            last_latency_ms=float(d.get("last_latency_ms", 0.0)),
            last_performance_score=float(d.get("last_performance_score", 0.0)),
            last_reliability_score=float(d.get("last_reliability_score", 0.0)),
            last_security_mode=str(d.get("last_security_mode", "")),
            exit_country=str(d.get("exit_country", "XX")),
            country_source=str(d.get("country_source", "unknown")),
            last_seen_at=str(d.get("last_seen_at", "")),
        )


class NodeHistoryStore:
    """
    Stage-L6 longitudinal stability store carried forward across scheduled runs.
    """

    def __init__(self, entries: dict[str, NodeHistoryEntry] | None = None) -> None:
        self.entries: dict[str, NodeHistoryEntry] = entries or {}

    @classmethod
    def load(cls, path: Path) -> "NodeHistoryStore":
        if not path.is_file():
            return cls()
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                return cls()
            data = raw.get("nodes", raw)
            entries = {
                str(k): NodeHistoryEntry.from_dict(v)
                for k, v in data.items()
                if isinstance(v, dict)
            }
            return cls(entries)
        except Exception:
            return cls()

    def bootstrap_from_alive_json(self, alive_json_path: Path, timestamp: str) -> int:
        """Seed history from an alive.json snapshot (supports both {'servers': [...]} and [...] formats)."""
        if self.entries or not alive_json_path.is_file():
            return 0
        try:
            raw = json.loads(alive_json_path.read_text(encoding="utf-8"))
        except Exception:
            return 0
        items = raw.get("servers", []) if isinstance(raw, dict) else (raw if isinstance(raw, list) else [])
        added = 0
        for item in items:
            if not isinstance(item, dict):
                continue
            uri = item.get("cfg") or item.get("uri") or ""
            ident = parse_identity(uri.split("#", 1)[0], reject_private_hosts=False)
            if not ident:
                continue
            self.entries[ident.identity_id] = NodeHistoryEntry(
                runs_seen=1,
                runs_alive=1,
                consecutive_alive=1,
                ema_reliability=0.72,
                best_speed_kbps=float(item.get("speed_kbps", 0.0)),
                last_latency_ms=float(item.get("latency_ms", 0.0)),
                exit_country=str(item.get("exit_country", "XX")),
                country_source=str(item.get("country_source", "unknown")),
                last_seen_at=timestamp,
            )
            added += 1
        return added

    def record_observation(
        self,
        identity_id: str,
        *,
        ok: bool,
        latency_ms: float = 0.0,
        speed_kbps: float = 0.0,
        exit_country: str = "XX",
        country_source: str = "unknown",
        timestamp: str = "",
    ) -> NodeHistoryEntry:
        ts = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        entry = self.entries.get(identity_id) or NodeHistoryEntry()
        entry.runs_seen += 1
        alpha = 0.35
        if ok:
            entry.runs_alive += 1
            entry.consecutive_alive += 1
            entry.consecutive_failures = 0
            entry.ema_reliability = (1.0 - alpha) * entry.ema_reliability + alpha * 1.0
            if latency_ms > 0:
                entry.last_latency_ms = latency_ms
            if speed_kbps > entry.best_speed_kbps:
                entry.best_speed_kbps = speed_kbps
            if exit_country and exit_country != "XX":
                if country_source == "exit_trace" or entry.country_source != "exit_trace":
                    entry.exit_country = exit_country
                    entry.country_source = country_source
        else:
            entry.consecutive_alive = 0
            entry.consecutive_failures += 1
            entry.ema_reliability = (1.0 - alpha) * entry.ema_reliability

        entry.last_seen_at = ts
        self.entries[identity_id] = entry
        return entry

    def save(self, path: Path) -> None:
        # Keep top MAX_HISTORY_ENTRIES ordered by (consecutive_alive, ema_reliability, last_seen_at)
        ranked = sorted(
            self.entries.items(),
            key=lambda kv: (
                kv[1].consecutive_alive > 0,
                kv[1].ema_reliability,
                kv[1].runs_alive,
                kv[1].last_seen_at,
            ),
            reverse=True,
        )[:MAX_HISTORY_ENTRIES]
        self.entries = dict(ranked)
        payload = {
            "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "count": len(self.entries),
            "nodes": {k: v.to_dict() for k, v in self.entries.items()},
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
        tmp.replace(path)


@dataclass
class ScoredNode:
    uri: str
    identity_id: str
    protocol: str
    canonical_protocol: str
    host: str
    port: int
    subnet_key: str
    latency_ms: float
    median_latency_ms: float
    jitter_ms: float
    probe_pass_rate: float
    speed_kbps: float
    exit_country: str = "XX"
    country_source: str = "unknown"
    is_cdn: bool = False
    is_warp: bool = False
    runs_seen: int = 1
    runs_alive: int = 1
    consecutive_alive: int = 1
    ema_reliability: float = 0.675
    corroboration_count: int = 1
    verified_source_hit: bool = False
    engine: str = ""
    score: float = 0.0
    score_breakdown: dict[str, float] = field(default_factory=dict)
    verified_at: str = ""
    # Phase 2 & Phase 5 multi-dimensional intelligence fields (100% additive & backward-compatible)
    performance_score: float = 0.0
    reliability_score: float = 0.0
    security_assessment: str = "Unknown"
    privacy_assessment: str = "Unverified"
    risk_level: str = "UNKNOWN"
    packet_loss_pct: float = 0.0
    uptime_pct: float = 100.0
    score_delta: float = 0.0
    upload_kbps: float = 0.0
    recent_failures: int = 0

    def to_alive_json_dict(self, *, index: int = 1, labeled_uri: str | None = None) -> dict:
        """
        100% backward-compatible with `bahrain-vpn` Android `Repo.kt` (`name`, `cfg`,
        `latency_ms`, `engine`, `proto`) plus multi-dimensional security & reliability telemetry.
        """
        cfg_out = labeled_uri or self.uri
        return {
            "name": f"bahrain-vpn {index}",
            "cfg": cfg_out,
            "uri": cfg_out,
            "id": self.identity_id[:12],
            "proto": self.protocol,
            "protocol": self.protocol,
            "canonical_protocol": self.canonical_protocol,
            "engine": self.engine,
            "host": self.host,
            "port": self.port,
            "latency_ms": round(self.latency_ms),
            "median_latency_ms": round(self.median_latency_ms),
            "jitter_ms": round(self.jitter_ms, 1),
            "probe_pass_rate": round(self.probe_pass_rate, 3),
            "packet_loss_pct": round(self.packet_loss_pct, 2),
            "speed_kbps": round(self.speed_kbps),
            "upload_kbps": round(self.upload_kbps),
            "score": round(self.score, 1),
            "performance_score": round(self.performance_score or self.score, 1),
            "reliability_score": round(self.reliability_score or self.score, 1),
            "security_assessment": self.security_assessment,
            "privacy_assessment": self.privacy_assessment,
            "risk_level": self.risk_level,
            "uptime_pct": round(self.uptime_pct, 2),
            "score_delta": round(self.score_delta, 1),
            "exit_country": self.exit_country,
            "country_source": self.country_source,
            "is_cdn": self.is_cdn,
            "is_warp": self.is_warp,
            "stability_runs": self.runs_alive,
            "consecutive_alive": self.consecutive_alive,
            "stability_ema": round(self.ema_reliability, 3),
            "corroboration_count": self.corroboration_count,
            "verified_at": self.verified_at,
        }


def compute_composite_score(
    *,
    median_latency_ms: float,
    jitter_ms: float,
    probe_pass_rate: float,
    speed_kbps: float,
    runs_seen: int,
    runs_alive: int,
    consecutive_alive: int,
    ema_reliability: float,
    corroboration_count: int,
    verified_source_hit: bool,
    weights: ScoringWeights | None = None,
) -> tuple[float, dict[str, float]]:
    """
    Compute transparent 0..100 composite score with sample-confidence shrinkage:
    - Reliability (0..100): intra-run probe pass rate + Wilson/Bayesian shrunk longitudinal EMA + streak bonus
    - Throughput (0..100): log-scaled kbps (smooth saturation, neutral confidence prior when speed not measured)
    - Latency (0..100): smooth exponential curve over median RTT
    - Stability (0..100): low relative & absolute jitter + full probe consistency
    - Freshness/Confidence (0..100): multi-source corroboration + verified upstream tier
    """
    w = (weights or ScoringWeights()).normalized()

    # 1. Reliability with Bayesian prior (prior: 1 virtual pass out of 2 virtual runs = 0.55)
    empirical_rate = (runs_alive + 1.1) / (max(1, runs_seen) + 2.0)
    streak_bonus = min(0.18, 0.045 * min(consecutive_alive, 4))
    rel_raw = (
        0.40 * max(0.0, min(1.0, probe_pass_rate))
        + 0.35 * max(0.0, min(1.0, ema_reliability))
        + 0.25 * empirical_rate
        + streak_bonus
    )
    rel_score = max(0.0, min(100.0, rel_raw * 100.0))

    # 2. Throughput (log-scaled: 100 kbps -> ~28, 1 Mbps -> ~60, 5 Mbps -> ~82, 20+ Mbps -> ~98)
    if speed_kbps > 0:
        # log10(speed_kbps) from 1.5 (31 kbps) to 4.4 (25 Mbps)
        tp_norm = (math.log10(max(16.0, speed_kbps)) - 1.2) / 3.2
        tp_score = max(5.0, min(100.0, tp_norm * 100.0))
    else:
        # Unmeasured throughput gets conservative 35.0 so measured fast nodes rank higher,
        # while ultra-low-latency reliable nodes outside speed_top remain fairly represented.
        tp_score = 35.0

    # 3. Latency (<=50ms -> ~96, 150ms -> ~83, 350ms -> ~63, 800ms -> ~35, 2000ms -> ~9)
    eff_lat = max(15.0, median_latency_ms if median_latency_ms > 0 else 2500.0)
    lat_score = 100.0 * math.exp(-(eff_lat - 15.0) / 720.0)
    lat_score = max(0.0, min(100.0, lat_score))

    # 4. Stability (penalizes high jitter and partial probe drops)
    rel_jitter = jitter_ms / max(40.0, eff_lat)
    jitter_penalty = min(70.0, rel_jitter * 65.0 + (jitter_ms / 18.0))
    drop_penalty = (1.0 - max(0.0, min(1.0, probe_pass_rate))) * 45.0
    stab_score = max(0.0, min(100.0, 100.0 - jitter_penalty - drop_penalty))

    # 5. Freshness & source corroboration confidence
    corr_bonus = min(30.0, (max(1, corroboration_count) - 1) * 10.0)
    tier_bonus = 15.0 if verified_source_hit else 0.0
    fresh_score = min(100.0, 55.0 + corr_bonus + tier_bonus)

    composite = (
        w.reliability * rel_score
        + w.throughput * tp_score
        + w.latency * lat_score
        + w.stability * stab_score
        + w.freshness * fresh_score
    )

    # Sample-size confidence factor: brand-new 1-run nodes cap slightly below multi-run proven peers
    confidence = 0.90 + 0.10 * min(1.0, math.log2(max(1, runs_alive) + 1) / 2.5)
    final_score = round(max(0.0, min(100.0, composite * confidence)), 2)

    breakdown = {
        "reliability": round(rel_score, 1),
        "throughput": round(tp_score, 1),
        "latency": round(lat_score, 1),
        "stability": round(stab_score, 1),
        "freshness": round(fresh_score, 1),
    }
    return final_score, breakdown


def diversify_scored_nodes(
    nodes: Iterable[ScoredNode],
    *,
    max_per_host: int = 3,
    max_per_subnet: int = 6,
    limit: int = 0,
) -> list[ScoredNode]:
    """
    Layer-4 & Layer-5 diversified selection over scored nodes.
    Prevents any single host or /24 subnet farm from dominating curated lists.
    """
    seen_ids: set[str] = set()
    host_counts: dict[str, int] = {}
    subnet_counts: dict[str, int] = {}
    out: list[ScoredNode] = []

    for n in nodes:
        if n.identity_id in seen_ids:
            continue
        if max_per_host > 0 and n.host and host_counts.get(n.host, 0) >= max_per_host:
            continue
        if max_per_subnet > 0 and n.subnet_key and subnet_counts.get(n.subnet_key, 0) >= max_per_subnet:
            continue
        seen_ids.add(n.identity_id)
        if n.host:
            host_counts[n.host] = host_counts.get(n.host, 0) + 1
        if n.subnet_key:
            subnet_counts[n.subnet_key] = subnet_counts.get(n.subnet_key, 0) + 1
        out.append(n)
        if limit > 0 and len(out) >= limit:
            break
    return out


def build_specialized_lists(nodes: list[ScoredNode], *, best_n: int = 100) -> dict[str, list[ScoredNode]]:
    """
    Produce specialized ranked lists from verified alive nodes:
    - best100: top N by composite score (host/subnet diversified)
    - reliable: top N prioritized by reliability + longitudinal streak + low jitter
    - low_latency: top N prioritized by median RTT + stability
    - high_throughput: top N with verified download speed prioritized by throughput + score
    """
    by_score = sorted(nodes, key=lambda n: (-n.score, n.median_latency_ms))
    best100 = diversify_scored_nodes(by_score, max_per_host=3, max_per_subnet=6, limit=best_n)

    by_reliable = sorted(
        nodes,
        key=lambda n: (
            -n.consecutive_alive,
            -n.probe_pass_rate,
            -n.ema_reliability,
            -n.score,
            n.median_latency_ms,
        ),
    )
    reliable = diversify_scored_nodes(by_reliable, max_per_host=3, max_per_subnet=6, limit=best_n)

    by_lat = sorted(
        [n for n in nodes if n.median_latency_ms > 0],
        key=lambda n: (n.median_latency_ms + 0.5 * n.jitter_ms, -n.score),
    )
    low_latency = diversify_scored_nodes(by_lat, max_per_host=3, max_per_subnet=6, limit=best_n)

    by_tp = sorted(
        [n for n in nodes if n.speed_kbps > 0],
        key=lambda n: (-n.speed_kbps, -n.score, n.median_latency_ms),
    )
    high_throughput = diversify_scored_nodes(by_tp, max_per_host=3, max_per_subnet=6, limit=best_n)

    return {
        "best100": best100,
        "reliable": reliable,
        "low_latency": low_latency,
        "high_throughput": high_throughput,
    }


# ───────────────── Intelligent Multi-Profile Server Ranking Engine (Phase 5) ─────────────────
RANKING_PROFILES = (
    "BALANCED",
    "LOW_LATENCY",
    "HIGH_SPEED",
    "HIGH_RELIABILITY",
    "PRIVACY_AWARE",
)


@dataclass(frozen=True)
class ProfileWeights:
    latency: float
    jitter: float
    packet_loss: float
    download: float
    upload: float
    uptime: float
    security: float


PROFILE_WEIGHT_PRESETS: dict[str, ProfileWeights] = {
    "BALANCED": ProfileWeights(latency=0.22, jitter=0.10, packet_loss=0.14, download=0.24, upload=0.04, uptime=0.18, security=0.08),
    "LOW_LATENCY": ProfileWeights(latency=0.46, jitter=0.22, packet_loss=0.14, download=0.06, upload=0.02, uptime=0.07, security=0.03),
    "HIGH_SPEED": ProfileWeights(latency=0.14, jitter=0.08, packet_loss=0.12, download=0.46, upload=0.08, uptime=0.08, security=0.04),
    "HIGH_RELIABILITY": ProfileWeights(latency=0.12, jitter=0.14, packet_loss=0.24, download=0.08, upload=0.02, uptime=0.32, security=0.08),
    "PRIVACY_AWARE": ProfileWeights(latency=0.14, jitter=0.08, packet_loss=0.14, download=0.10, upload=0.02, uptime=0.18, security=0.34),
}


def compute_profile_rank_score(
    node: ScoredNode,
    profile: str = "BALANCED",
    *,
    preferred_protocols: set[str] | None = None,
    preferred_country: str = "",
    now_iso: str = "",
    weights_override: ProfileWeights | None = None,
) -> float:
    """
    Evaluate a `ScoredNode` under one of the 5 Phase-5 ranking profiles:
      BALANCED | LOW_LATENCY | HIGH_SPEED | HIGH_RELIABILITY | PRIVACY_AWARE

    Key invariants:
      - Never treats missing throughput (`speed_kbps == 0`) as average throughput.
      - Applies continuous staleness decay for outdated measurements.
      - Uses historical EMA & Bayesian uptime to avoid overreacting to 1-run spikes.
      - `PRIVACY_AWARE` strictly rejects `Failed` security / `HIGH`+`CRITICAL` risk
        nodes (score = 0.0) and never fabricates operator trust for anonymous servers.
    """
    prof = (profile or "BALANCED").strip().upper()
    if prof not in PROFILE_WEIGHT_PRESETS:
        prof = "BALANCED"
    w = weights_override or PROFILE_WEIGHT_PRESETS[prof]

    # Protocol compatibility gate
    if preferred_protocols:
        allowed = {canonical_protocol(p) for p in preferred_protocols}
        if node.canonical_protocol not in allowed and node.protocol.lower() not in allowed:
            return 0.0

    # Strict privacy-aware gate: never select failed/high-risk transport security
    if prof == "PRIVACY_AWARE":
        if node.security_assessment == "Failed" or node.risk_level in ("HIGH", "CRITICAL") or node.privacy_assessment == "High Risk":
            return 0.0

    # 1. Latency (0..100)
    eff_lat = node.median_latency_ms if node.median_latency_ms > 0 else node.latency_ms
    lat_s = 100.0 * math.exp(-max(0.0, eff_lat - 15.0) / 680.0) if eff_lat > 0 else 0.0

    # 2. Jitter (0..100)
    base_lat = max(35.0, eff_lat if eff_lat > 0 else 400.0)
    jit_s = max(0.0, 100.0 - min(90.0, (max(0.0, node.jitter_ms) / base_lat) * 70.0 + max(0.0, node.jitter_ms) / 14.0))

    # 3. Packet loss & connection success rate (0..100)
    pass_rate = max(0.0, min(1.0, node.probe_pass_rate if node.probe_pass_rate > 0 else (1.0 - node.packet_loss_pct / 100.0)))
    loss_s = (pass_rate ** 1.4) * 100.0

    # 4. Download & Upload throughput (0.0 when unmeasured — never fabricated!)
    dl_s = max(5.0, min(100.0, ((math.log10(max(16.0, node.speed_kbps)) - 1.2) / 3.2) * 100.0)) if node.speed_kbps > 0 else 0.0
    ul_s = max(5.0, min(100.0, ((math.log10(max(16.0, node.upload_kbps)) - 1.2) / 3.0) * 100.0)) if node.upload_kbps > 0 else 0.0

    # 5. Historical uptime & dampened EMA (prevents 1-run fluctuations from dominating)
    bayes_up = (max(0, node.runs_alive) + 1.4) / (max(1, node.runs_seen) + 2.5)
    streak_s = min(1.0, math.log2(max(1, node.consecutive_alive) + 1) / 3.2)
    fail_pen = min(45.0, node.recent_failures * 14.0)
    uptime_s = max(0.0, min(100.0, (0.45 * node.ema_reliability + 0.35 * bayes_up + 0.20 * streak_s) * 100.0 - fail_pen))

    # 6. Technical Security & Privacy Assessment score (explicitly distinguishes Verified vs Unverified operator)
    sec_map = {"Verified": 92.0, "Partial": 68.0, "Unknown": 35.0, "Failed": 0.0}
    priv_bonus = 8.0 if node.privacy_assessment == "Verified" else (0.0 if node.privacy_assessment == "Unverified" else -20.0)
    sec_s = max(0.0, min(100.0, sec_map.get(node.security_assessment, 35.0) + priv_bonus))

    total_w = w.latency + w.jitter + w.packet_loss + w.download + w.upload + w.uptime + w.security
    raw = (
        w.latency * lat_s
        + w.jitter * jit_s
        + w.packet_loss * loss_s
        + w.download * dl_s
        + w.upload * ul_s
        + w.uptime * uptime_s
        + w.security * sec_s
    ) / max(0.001, total_w)

    # Freshness decay for stale measurements
    freshness = 1.0
    if node.verified_at:
        try:
            t_ver = datetime.fromisoformat(node.verified_at.replace("Z", "+00:00"))
            t_now = datetime.fromisoformat(now_iso.replace("Z", "+00:00")) if now_iso else datetime.now(timezone.utc)
            age_h = max(0.0, (t_now - t_ver).total_seconds() / 3600.0)
            if age_h > 1.0:
                freshness = max(0.55, min(1.0, math.exp(-(age_h - 1.0) / 85.0)))
        except Exception:
            freshness = 0.85

    # Geographic suitability boost (bounded, never overrides dead/unsafe metrics)
    geo_mult = 1.0
    pref_cc = (preferred_country or "").strip().upper()
    if pref_cc and pref_cc != "ALL" and node.exit_country.upper() == pref_cc:
        geo_mult = 1.08 if node.country_source == "exit_trace" else 1.03

    return round(max(0.0, min(100.0, raw * freshness * geo_mult)), 2)


def rank_nodes_by_profile(
    nodes: Iterable[ScoredNode],
    profile: str = "BALANCED",
    *,
    preferred_protocols: set[str] | None = None,
    preferred_country: str = "",
    now_iso: str = "",
) -> list[ScoredNode]:
    """Return nodes filtered & ordered deterministically by the selected Phase-5 profile."""
    prof = (profile or "BALANCED").strip().upper()
    scored_pairs: list[tuple[float, ScoredNode]] = []
    for n in nodes:
        ps = compute_profile_rank_score(
            n,
            prof,
            preferred_protocols=preferred_protocols,
            preferred_country=preferred_country,
            now_iso=now_iso,
        )
        if prof == "PRIVACY_AWARE" and ps <= 0.0:
            continue
        if preferred_protocols and ps <= 0.0:
            continue
        scored_pairs.append((ps, n))

    scored_pairs.sort(
        key=lambda item: (
            -item[0],
            item[1].median_latency_ms if item[1].median_latency_ms > 0 else 99999.0,
            item[1].identity_id,
        )
    )
    return [n for _, n in scored_pairs]


# ───────────────── Source Health & Quarantine Intelligence (Phase 7) ─────────────────
SOURCE_STATES = (
    "active",
    "degraded",
    "temporarily_failed",
    "disabled",
    "quarantined",
    "retired",
    "pending_validation",
)
DISABLE_FAILURE_THRESHOLD = 6
DEGRADED_FAILURE_THRESHOLD = 3
QUARANTINE_SUSPICIOUS_MIN = 8
QUARANTINE_SUSPICIOUS_RATIO = 0.50


@dataclass
class SourceHealthRecord:
    name: str
    kind: str                       # "github" | "telegram"
    url_or_handle: str
    state: str = "pending_validation"
    consecutive_failures: int = 0
    total_runs: int = 0
    successful_runs: int = 0
    last_status_code: int = 0
    not_modified: bool = False
    etag: str = ""
    last_modified: str = ""
    raw_count: int = 0
    valid_count: int = 0
    new_configs: int = 0
    invalid_configs: int = 0
    duplicate_configs: int = 0
    suspicious_configs: int = 0
    content_sha256: str = ""
    content_changed: bool = False
    quarantine_reason: str = ""
    availability_history: list[int] = field(default_factory=list)
    unique_identities: int = 0
    exclusive_identities: int = 0
    overlap_ratio: float = 0.0
    alive_count: int = 0
    last_error: str = ""
    last_checked_at: str = ""
    last_success_at: str = ""

    @property
    def collection_success_rate(self) -> float:
        if self.total_runs <= 0:
            return 0.0
        return round(self.successful_runs / max(1, self.total_runs), 4)

    def should_skip_cooldown(self) -> bool:
        """
        Disabled/quarantined sources enter cooldown:
          - disabled: re-probed every 4th run (~2h)
          - quarantined: re-probed every 8th run (~4h) for safe recovery check
        """
        if self.state == "retired":
            return True
        if self.state == "quarantined" and (self.total_runs % 8 != 0):
            return True
        if self.state == "disabled" and (self.total_runs % 4 != 0):
            return True
        return False

    def update_from_fetch(
        self,
        *,
        fetch_ok: bool,
        status_code: int = 0,
        not_modified: bool = False,
        etag: str = "",
        last_modified: str = "",
        raw_count: int = 0,
        valid_count: int = 0,
        new_configs: int = 0,
        invalid_configs: int = 0,
        duplicate_configs: int = 0,
        suspicious_configs: int = 0,
        content_sha256: str = "",
        error: str = "",
        timestamp: str = "",
    ) -> None:
        ts = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.total_runs += 1
        self.last_checked_at = ts
        self.last_status_code = status_code
        self.not_modified = not_modified

        if fetch_ok:
            if etag:
                self.etag = etag
            if last_modified:
                self.last_modified = last_modified
            if not_modified:
                self.successful_runs += 1
                self.consecutive_failures = 0
                self.content_changed = False
                self.last_error = ""
                self.availability_history = (self.availability_history + [1])[-24:]
                if self.state in ("pending_validation", "temporarily_failed", "disabled"):
                    self.state = "active"
                return

            if content_sha256:
                self.content_changed = bool(self.content_sha256 and self.content_sha256 != content_sha256)
                self.content_sha256 = content_sha256

            self.raw_count = raw_count
            self.valid_count = valid_count
            self.new_configs = max(0, new_configs)
            self.invalid_configs = max(0, invalid_configs)
            self.duplicate_configs = max(0, duplicate_configs)
            self.suspicious_configs = max(0, suspicious_configs)

            total_inspected = max(1, raw_count + invalid_configs)
            suspicious_ratio = self.suspicious_configs / total_inspected

            # Source-level quarantine check: never trust a popular source injecting hostile/malformed floods
            if (
                self.suspicious_configs >= QUARANTINE_SUSPICIOUS_MIN
                and suspicious_ratio >= QUARANTINE_SUSPICIOUS_RATIO
            ) or (self.invalid_configs >= 20 and valid_count == 0):
                self.consecutive_failures += 1
                self.quarantine_reason = (
                    f"high_suspicious_ratio:{self.suspicious_configs}/{total_inspected}"
                    if self.suspicious_configs >= QUARANTINE_SUSPICIOUS_MIN
                    else f"all_invalid_payload:{self.invalid_configs}"
                )
                self.last_error = self.quarantine_reason
                self.state = "quarantined"
                self.availability_history = (self.availability_history + [0])[-24:]
                return

            if valid_count > 0:
                self.successful_runs += 1
                self.consecutive_failures = 0
                self.last_success_at = ts
                self.last_error = ""
                self.quarantine_reason = ""
                self.state = "active"
                self.availability_history = (self.availability_history + [1])[-24:]
            else:
                self.consecutive_failures += 1
                self.last_error = error or "zero_valid_configs"
                self.availability_history = (self.availability_history + [0])[-24:]
                self.state = (
                    "disabled"
                    if self.consecutive_failures >= DISABLE_FAILURE_THRESHOLD
                    else "degraded"
                )
        else:
            self.consecutive_failures += 1
            self.last_error = (error or "fetch_failed")[:160]
            self.availability_history = (self.availability_history + [0])[-24:]
            if self.consecutive_failures >= DISABLE_FAILURE_THRESHOLD:
                self.state = "disabled"
            elif self.consecutive_failures >= DEGRADED_FAILURE_THRESHOLD:
                self.state = "degraded"
            else:
                self.state = "temporarily_failed"

    def to_public_dict(self) -> dict:
        return {
            "name": self.name,
            "kind": self.kind,
            "state": self.state,
            "consecutive_failures": self.consecutive_failures,
            "total_runs": self.total_runs,
            "successful_runs": self.successful_runs,
            "collection_success_rate": self.collection_success_rate,
            "last_status_code": self.last_status_code,
            "not_modified": self.not_modified,
            "raw_count": self.raw_count,
            "valid_count": self.valid_count,
            "new_configs": self.new_configs,
            "invalid_configs": self.invalid_configs,
            "duplicate_configs": self.duplicate_configs,
            "suspicious_configs": self.suspicious_configs,
            "content_changed": self.content_changed,
            "quarantine_reason": self.quarantine_reason,
            "availability_history": list(self.availability_history[-24:]),
            "unique_identities": self.unique_identities,
            "exclusive_identities": self.exclusive_identities,
            "overlap_ratio": round(self.overlap_ratio, 4),
            "alive_count": self.alive_count,
            "last_error": self.last_error,
            "last_checked_at": self.last_checked_at,
            "last_success_at": self.last_success_at,
        }

    def to_state_dict(self) -> dict:
        d = self.to_public_dict()
        d["url_or_handle"] = self.url_or_handle
        d["etag"] = self.etag
        d["last_modified"] = self.last_modified
        d["content_sha256"] = self.content_sha256
        return d

    @classmethod
    def from_state_dict(cls, d: dict) -> "SourceHealthRecord":
        hist = d.get("availability_history", [])
        clean_hist = [1 if int(x) else 0 for x in hist[-24:]] if isinstance(hist, list) else []
        return cls(
            name=str(d.get("name", "")),
            kind=str(d.get("kind", "github")),
            url_or_handle=str(d.get("url_or_handle", "")),
            state=str(d.get("state", "pending_validation")),
            consecutive_failures=int(d.get("consecutive_failures", 0)),
            total_runs=int(d.get("total_runs", 0)),
            successful_runs=int(d.get("successful_runs", 0)),
            last_status_code=int(d.get("last_status_code", 0)),
            not_modified=bool(d.get("not_modified", False)),
            etag=str(d.get("etag", "")),
            last_modified=str(d.get("last_modified", "")),
            raw_count=int(d.get("raw_count", 0)),
            valid_count=int(d.get("valid_count", 0)),
            new_configs=int(d.get("new_configs", 0)),
            invalid_configs=int(d.get("invalid_configs", 0)),
            duplicate_configs=int(d.get("duplicate_configs", 0)),
            suspicious_configs=int(d.get("suspicious_configs", 0)),
            content_sha256=str(d.get("content_sha256", "")),
            content_changed=bool(d.get("content_changed", False)),
            quarantine_reason=str(d.get("quarantine_reason", "")),
            availability_history=clean_hist,
            unique_identities=int(d.get("unique_identities", 0)),
            exclusive_identities=int(d.get("exclusive_identities", 0)),
            overlap_ratio=float(d.get("overlap_ratio", 0.0)),
            alive_count=int(d.get("alive_count", 0)),
            last_error=str(d.get("last_error", "")),
            last_checked_at=str(d.get("last_checked_at", "")),
            last_success_at=str(d.get("last_success_at", "")),
        )


class SourceHealthRegistry:
    """Persistent registry tracking source lifecycle states, caching headers, and yield."""

    def __init__(self, records: dict[str, SourceHealthRecord] | None = None) -> None:
        self.records: dict[str, SourceHealthRecord] = records or {}

    @classmethod
    def load(cls, path: Path) -> "SourceHealthRegistry":
        if not path.is_file():
            return cls()
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            items = raw.get("sources", {})
            if isinstance(items, list):
                recs = {str(it["name"]): SourceHealthRecord.from_state_dict(it) for it in items if isinstance(it, dict) and "name" in it}
            elif isinstance(items, dict):
                recs = {str(k): SourceHealthRecord.from_state_dict(v) for k, v in items.items() if isinstance(v, dict)}
            else:
                recs = {}
            return cls(recs)
        except Exception:
            return cls()

    def get_or_create(self, name: str, kind: str, url_or_handle: str) -> SourceHealthRecord:
        rec = self.records.get(name)
        if rec is None:
            rec = SourceHealthRecord(name=name, kind=kind, url_or_handle=url_or_handle)
            self.records[name] = rec
        else:
            rec.url_or_handle = url_or_handle
        return rec

    def summary_counts(self) -> dict[str, int]:
        counts = {s: 0 for s in SOURCE_STATES}
        for r in self.records.values():
            counts[r.state] = counts.get(r.state, 0) + 1
        return counts

    def save_state(self, path: Path) -> None:
        payload = {
            "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "summary": self.summary_counts(),
            "sources": {k: v.to_state_dict() for k, v in sorted(self.records.items())},
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)

    def save_public_report(self, path: Path) -> None:
        github_list = [
            r.to_public_dict()
            for r in sorted(self.records.values(), key=lambda x: (x.kind != "github", -x.alive_count, -x.exclusive_identities, x.name))
            if r.kind == "github"
        ]
        tg_records = [r for r in self.records.values() if r.kind == "telegram"]
        tg_summary = {
            "total": len(tg_records),
            "active": sum(1 for r in tg_records if r.state == "active"),
            "degraded": sum(1 for r in tg_records if r.state == "degraded"),
            "temporarily_failed": sum(1 for r in tg_records if r.state == "temporarily_failed"),
            "disabled": sum(1 for r in tg_records if r.state == "disabled"),
            "quarantined": sum(1 for r in tg_records if r.state == "quarantined"),
            "top_alive_channels": [
                r.to_public_dict()
                for r in sorted(tg_records, key=lambda x: (-x.alive_count, -x.exclusive_identities, x.name))[:30]
            ],
        }
        payload = {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "summary": self.summary_counts(),
            "github_sources": github_list,
            "telegram_channels_summary": tg_summary,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)
