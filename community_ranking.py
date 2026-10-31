#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
community_ranking.py — Multi-Device Trust Scoring & Country-Specific VPN Ranking Engine
(Primary Focus: Verified Iran `IR` Direct-ISP Rankings + Optional Country Feeds).

Core Engineering & Anti-Manipulation Guarantees:
  1. Strict Country Isolation:
     - `iran-top500.json`, `iran-top500.txt`, and `iran-results.json` ONLY accept reports
       where `verified_country == "IR"`, `vpn_interference == False`, and
       `country_confidence in {"CF_EDGE_VERIFIED", "VERIFIED_DIRECT_IP"}`.
     - Reports from outside Iran or through active VPN/datacenter ASNs NEVER enter Iran rankings.
  2. Single-Device Manipulation Immunity:
     - Per-device contribution cap: each `reporter_id_hash` contributes AT MOST ONE latest
       observation per `(server_id, country)` within the active scoring window.
     - Minimum independent reporter threshold (`min_distinct_reporters = 2` by default):
       a single device alone CANNOT place or promote any server into `iran-top500.json` / `iran-top500.txt`!
       Single-reporter observations remain transparently visible in `iran-results.json` as
       `status = "PENDING_MULTI_DEVICE_CONFIRMATION"`.
  3. Outlier-Resistant Statistics:
     - Uses MEDIAN latency, MEDIAN handshake time, and MEDIAN download throughput across
       independent reporters — never raw averages that a single spoofed outlier could skew.
  4. Exponential Recency Decay:
     - Observations decay exponentially (`half_life_hours = 24.0`) and configs older than
       `max_age_hours = 72.0` expire from active Top-500 eligibility.
  5. Zero URI Injection & Zero Padding:
     - Only configurations matching the validated central catalog (`server_id` / `config_fingerprint`)
       are emitted as URIs; never fabricates or pads servers to reach 500.
"""
from __future__ import annotations

import hashlib
import json
import statistics
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import collector
from central_top500 import compute_config_fingerprint, strip_uri_fragment
from dedupe import parse_identity

COMMUNITY_SCHEMA_VERSION = "1.0.0"
COMMUNITY_TOP_LIMIT = 500
DEFAULT_MIN_DISTINCT_REPORTERS = 2
DEFAULT_HALF_LIFE_HOURS = 24.0
DEFAULT_MAX_AGE_HOURS = 72.0

TRUSTED_CONFIDENCE_VALUES = frozenset({"CF_EDGE_VERIFIED", "VERIFIED_DIRECT_IP"})

COUNTRY_FEED_SPECS: tuple[tuple[str, str], ...] = (
    ("IR", "iran"),
    ("DE", "germany"),
    ("FR", "france"),
    ("TR", "turkey"),
    ("RU", "russia"),
)


def _write_atomic_text(path: Path, text: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = text.encode("utf-8")
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)
    return hashlib.sha256(data).hexdigest()


def build_catalog_index(catalog_servers: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """
    Index validated public configurations by `server_id` and `config_fingerprint`
    so community reports can never inject unvalidated external URIs.
    """
    by_key: dict[str, dict[str, Any]] = {}
    for item in catalog_servers:
        raw_uri = str(item.get("cfg") or item.get("uri") or "").strip()
        if "://" not in raw_uri:
            continue
        clean_uri = strip_uri_fragment(raw_uri)
        ident = parse_identity(clean_uri, reject_private_hosts=True)
        if ident is None:
            continue
        sid = str(item.get("server_id") or ident.identity_id).strip().lower()
        fp = str(item.get("config_fingerprint") or compute_config_fingerprint(clean_uri)).strip().lower()
        entry = {
            "server_id": sid,
            "config_fingerprint": fp,
            "clean_uri": clean_uri,
            "protocol": ident.canonical_proto,
            "exit_country": str(item.get("exit_country") or item.get("country") or "").upper(),
            "security_assessment": str(item.get("security_assessment") or "Unknown"),
            "privacy_assessment": str(item.get("privacy_assessment") or "Unverified"),
            "risk_level": str(item.get("risk_level") or "UNKNOWN"),
        }
        if sid:
            by_key[f"sid:{sid}"] = entry
        if fp:
            by_key[f"fp:{fp}"] = entry
    return by_key


def compute_country_community_rankings(
    reports: list[dict[str, Any]],
    catalog_index: dict[str, dict[str, Any]],
    *,
    target_country: str = "IR",
    now_epoch: int | None = None,
    min_distinct_reporters: int = DEFAULT_MIN_DISTINCT_REPORTERS,
    half_life_hours: float = DEFAULT_HALF_LIFE_HOURS,
    max_age_hours: float = DEFAULT_MAX_AGE_HOURS,
    limit: int = COMMUNITY_TOP_LIMIT,
) -> dict[str, Any]:
    """
    Aggregate verified reports for `target_country` with per-device deduplication,
    median metrics, Bayesian shrinkage, and exponential recency decay.
    """
    cc = target_country.strip().upper()
    now_s = int(now_epoch if now_epoch is not None else datetime.now(timezone.utc).timestamp())
    cutoff_s = now_s - int(max_age_hours * 3600)

    # Step 1: Filter strictly to authentic non-VPN reports for `cc` and deduplicate per (server_id, reporter_id_hash)
    latest_by_server_reporter: dict[tuple[str, str], dict[str, Any]] = {}
    rejected_vpn_or_unverified = 0
    rejected_other_country = 0

    for r in reports:
        if not isinstance(r, dict):
            continue
        vpn_int = bool(r.get("vpn_interference", False))
        conf = str(r.get("country_confidence") or "").strip().upper()
        rep_cc = str(r.get("verified_country") or "").strip().upper()

        if vpn_int or conf not in TRUSTED_CONFIDENCE_VALUES or len(rep_cc) != 2:
            rejected_vpn_or_unverified += 1
            continue
        if rep_cc != cc:
            rejected_other_country += 1
            continue

        tested_s = int(r.get("tested_at_epoch") or r.get("received_at_epoch") or 0)
        if tested_s < cutoff_s or tested_s > now_s + 600:
            continue

        reporter_hash = str(r.get("reporter_id_hash") or "").strip().lower()
        if len(reporter_hash) < 32:
            continue

        sid = str(r.get("server_id") or "").strip().lower()
        fp = str(r.get("config_fingerprint") or "").strip().lower()
        cat = catalog_index.get(f"fp:{fp}") or catalog_index.get(f"sid:{sid}")
        if cat is None:
            continue

        canonical_sid = cat["server_id"]
        key = (canonical_sid, reporter_hash)
        prev = latest_by_server_reporter.get(key)
        if prev is None or tested_s >= int(prev.get("_tested_s", 0)):
            enriched = dict(r)
            enriched["_tested_s"] = tested_s
            enriched["_cat"] = cat
            latest_by_server_reporter[key] = enriched

    # Step 2: Group deduplicated independent device observations by server_id
    by_server: dict[str, list[dict[str, Any]]] = {}
    for (sid, _), obs in latest_by_server_reporter.items():
        by_server.setdefault(sid, []).append(obs)

    all_results: list[dict[str, Any]] = []
    qualified_top: list[dict[str, Any]] = []

    for sid, obs_list in by_server.items():
        cat = obs_list[0]["_cat"]
        distinct_reporters = len(obs_list)
        distinct_asns = len({int(o.get("asn_bucket") or 0) for o in obs_list if int(o.get("asn_bucket") or 0) > 0})

        weighted_ok = 0.0
        weighted_total = 0.0
        ok_latencies: list[float] = []
        ok_handshakes: list[float] = []
        ok_speeds: list[float] = []
        ok_stabilities: list[float] = []
        failure_reasons: dict[str, int] = {}
        latest_ts = 0

        for o in obs_list:
            ts = int(o["_tested_s"])
            latest_ts = max(latest_ts, ts)
            age_h = max(0.0, (now_s - ts) / 3600.0)
            decay_w = 0.5 ** (age_h / max(1.0, half_life_hours))
            weighted_total += decay_w
            is_ok = bool(o.get("success")) and int(o.get("latency_ms") or 0) > 0
            if is_ok:
                weighted_ok += decay_w
                ok_latencies.append(float(min(15000, max(1, int(o.get("latency_ms") or 0)))))
                hs = int(o.get("handshake_ms") or o.get("latency_ms") or 0)
                if hs > 0:
                    ok_handshakes.append(float(min(30000, hs)))
                spd = float(o.get("download_kbps") or 0.0)
                if spd > 0.0:
                    ok_speeds.append(min(500000.0, spd))
                ok_stabilities.append(float(min(100.0, max(0.0, float(o.get("stability_score") or 75.0)))))
            else:
                fr = str(o.get("failure_reason") or "FAILED").strip()[:48] or "FAILED"
                failure_reasons[fr] = failure_reasons.get(fr, 0) + 1

        raw_success_rate = (weighted_ok / weighted_total) if weighted_total > 0 else 0.0
        # Bayesian prior shrinkage (prior = 1.5 neutral 0.45 observations) prevents 1 lucky ping from scoring 100%
        shrunk_reliability = (weighted_ok + 1.5 * 0.45) / (weighted_total + 1.5)

        median_lat = int(round(statistics.median(ok_latencies))) if ok_latencies else 0
        median_hs = int(round(statistics.median(ok_handshakes))) if ok_handshakes else 0
        median_spd = round(float(statistics.median(ok_speeds)), 1) if ok_speeds else 0.0
        median_stab = round(float(statistics.median(ok_stabilities)), 1) if ok_stabilities else 0.0

        age_latest_h = max(0.0, (now_s - latest_ts) / 3600.0)
        recency_mult = 0.65 + 0.35 * (0.5 ** (age_latest_h / max(1.0, half_life_hours)))

        if ok_latencies:
            lat_score = max(0.0, min(100.0, ((1800.0 - min(1800.0, float(median_lat))) / (1800.0 - 45.0)) * 100.0))
            spd_score = 35.0 if median_spd <= 0.0 else min(100.0, 20.0 + (median_spd / 6000.0) * 80.0)
            rep_conf_bonus = min(15.0, (distinct_reporters - 1) * 4.0 + max(0, distinct_asns - 1) * 3.0)
            base_score = (
                shrunk_reliability * 100.0 * 0.45 +
                lat_score * 0.25 +
                spd_score * 0.15 +
                median_stab * 0.15 +
                rep_conf_bonus
            )
            trust_score = round(min(100.0, base_score * recency_mult), 2)
        else:
            trust_score = 0.0

        meets_multi_device = (
            distinct_reporters >= max(1, int(min_distinct_reporters)) and
            len(ok_latencies) >= max(1, int(min_distinct_reporters)) and
            raw_success_rate >= 0.50 and
            median_lat > 0 and
            str(cat["risk_level"]).upper() != "QUARANTINED"
        )

        status_tag = (
            "VERIFIED_COMMUNITY"
            if meets_multi_device
            else ("PENDING_MULTI_DEVICE_CONFIRMATION" if ok_latencies else "FAILED_IN_COUNTRY")
        )
        last_iso = datetime.fromtimestamp(latest_ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if latest_ts > 0 else ""

        summary_row = {
            "server_id": sid,
            "config_fingerprint": cat["config_fingerprint"],
            "protocol": cat["protocol"],
            "exit_country": cat["exit_country"],
            "verified_from_country": cc,
            "status": status_tag,
            "distinct_reporters": distinct_reporters,
            "distinct_asns": distinct_asns,
            "success_rate": round(raw_success_rate, 3),
            "median_latency_ms": median_lat,
            "median_handshake_ms": median_hs,
            "median_speed_kbps": median_spd,
            "stability_score": median_stab,
            "trust_score": trust_score,
            "failure_breakdown": failure_reasons,
            "security_assessment": cat["security_assessment"],
            "privacy_assessment": cat["privacy_assessment"],
            "risk_level": cat["risk_level"],
            "last_verified_at": last_iso,
        }
        all_results.append(summary_row)

        if meets_multi_device:
            qualified_top.append({**summary_row, "_clean_uri": cat["clean_uri"]})

    all_results.sort(key=lambda x: (-float(x["trust_score"]), -int(x["distinct_reporters"]), int(x["median_latency_ms"] or 999999), x["server_id"]))
    qualified_top.sort(key=lambda x: (-float(x["trust_score"]), -int(x["distinct_reporters"]), int(x["median_latency_ms"]), x["server_id"]))
    qualified_top = qualified_top[: max(0, min(int(limit), COMMUNITY_TOP_LIMIT))]

    ranked_servers: list[dict[str, Any]] = []
    txt_lines: list[str] = []
    for idx, item in enumerate(qualified_top, 1):
        clean_uri = item.pop("_clean_uri")
        remark = f"bahrain-vpn {cc}#{idx} | {item['median_latency_ms']}ms | {item['distinct_reporters']}v"
        labeled_uri = collector.set_uri_remark(clean_uri, remark)
        ranked_row = {
            "rank": idx,
            **item,
            "cfg": labeled_uri,
        }
        ranked_servers.append(ranked_row)
        txt_lines.append(labeled_uri)

    now_iso = datetime.fromtimestamp(now_s, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "schema_version": COMMUNITY_SCHEMA_VERSION,
        "generated_at": now_iso,
        "generated_at_epoch": now_s,
        "country_code": cc,
        "verification_policy": "VERIFIED_NON_VPN_DIRECT_ORIGIN_ONLY",
        "min_distinct_reporters": max(1, int(min_distinct_reporters)),
        "qualified_count": len(ranked_servers),
        "evaluated_servers_count": len(all_results),
        "rejected_vpn_or_unverified_reports": rejected_vpn_or_unverified,
        "isolated_other_country_reports": rejected_other_country,
        "servers": ranked_servers,
        "txt_lines": txt_lines,
        "all_results": all_results,
    }


def export_community_country_datasets(
    out_dir: Path,
    catalog_servers: list[dict[str, Any]],
    reports: list[dict[str, Any]],
    *,
    generated_at_epoch: int | None = None,
    min_distinct_reporters: int = DEFAULT_MIN_DISTINCT_REPORTERS,
) -> dict[str, Any]:
    """
    Generate and write:
      • `iran-top500.json`, `iran-top500.txt`, `iran-results.json`
      • `germany-top500.json`, `france-top500.json`, `turkey-top500.json`, `russia-top500.json`
    Never pads or fabricates configs when fewer than 500 (or 0) qualify.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    catalog_index = build_catalog_index(catalog_servers)
    now_s = int(generated_at_epoch if generated_at_epoch is not None else datetime.now(timezone.utc).timestamp())

    summary_counts: dict[str, int] = {}
    for cc, slug in COUNTRY_FEED_SPECS:
        computed = compute_country_community_rankings(
            reports=reports,
            catalog_index=catalog_index,
            target_country=cc,
            now_epoch=now_s,
            min_distinct_reporters=min_distinct_reporters,
        )
        top_doc = {
            "schema_version": computed["schema_version"],
            "generated_at": computed["generated_at"],
            "generated_at_epoch": computed["generated_at_epoch"],
            "country_code": cc,
            "country_slug": slug,
            "role": "COMMUNITY_VERIFIED_COUNTRY_POOL",
            "personalized_top50_authority": "ANDROID_LOCAL_ONLY",
            "verification_policy": computed["verification_policy"],
            "min_distinct_reporters": computed["min_distinct_reporters"],
            "qualified_count": computed["qualified_count"],
            "servers": computed["servers"],
        }
        _write_atomic_text(out / f"{slug}-top500.json", json.dumps(top_doc, ensure_ascii=False, indent=2) + "\n")
        summary_counts[cc] = int(computed["qualified_count"])

        if cc == "IR":
            txt_body = (
                "\n".join(computed["txt_lines"]) + "\n"
                if computed["txt_lines"]
                else f"# bahrain-vpn iran-top500 ({computed['generated_at']}) — 0 multi-device verified IR configs currently active\n"
            )
            _write_atomic_text(out / "iran-top500.txt", txt_body)

            results_doc = {
                "schema_version": computed["schema_version"],
                "generated_at": computed["generated_at"],
                "generated_at_epoch": computed["generated_at_epoch"],
                "country_code": "IR",
                "verification_policy": computed["verification_policy"],
                "min_distinct_reporters_for_top500": computed["min_distinct_reporters"],
                "qualified_top500_count": computed["qualified_count"],
                "evaluated_servers_count": computed["evaluated_servers_count"],
                "rejected_vpn_or_unverified_reports": computed["rejected_vpn_or_unverified_reports"],
                "isolated_other_country_reports": computed["isolated_other_country_reports"],
                "results": computed["all_results"],
            }
            _write_atomic_text(out / "iran-results.json", json.dumps(results_doc, ensure_ascii=False, indent=2) + "\n")

    return summary_counts
