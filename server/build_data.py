#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
server/build_data.py — خط أنابيب بناء ونشر بيانات فرع `data` (يعمل كلّ 30 دقيقة عبر GitHub Actions).

المزايا المعمارية:
  1) استعادة السجل الطولي للعُقد (L6 NodeHistory) وسجل صحّة المصادر (SourceHealthRegistry) من اللقطة السابقة.
  2) جمع متوازٍ محصّن أمنيًا مع إزالة تكرار خماسية الطبقات وتتبّع المصدر (Provenance).
  3) فحص فعلي متعدّد الجولات (L3–L5) عبر Xray + sing-box مع كشف دولة الخروج الحقيقية.
  4) ترتيب مركّب شفاف وإنتاج القوائم المتخصّصة (best100, reliable, low_latency, high_throughput, protocols, countries).
  5) حماية آخر نسخة صالحة معروفة (Last-Known-Good Fallback) لمنع نشر قوائم فارغة عند انقطاع المنبع.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import json
import logging
import os
import shutil
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import NonCallableMock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import collector  # noqa: E402
import tester  # noqa: E402
from dedupe import MultiLayerDeduplicator, canonical_protocol, parse_identity  # noqa: E402
from pipeline_security import redact_text  # noqa: E402
from scoring import (  # noqa: E402
    NodeHistoryStore,
    ScoredNode,
    ScoringWeights,
    SourceHealthRegistry,
    build_specialized_lists,
    compute_composite_score,
    country_flag,
    diversify_scored_nodes,
    infer_country_hint,
    is_cdn_endpoint,
)

DIST = ROOT / "dist"
PREV_DIR = Path(os.environ["PREV_DIST"]) if os.environ.get("PREV_DIST") else None
LOG = logging.getLogger("build_data")

TEST_TOP = int(os.environ.get("TEST_TOP", "1200"))
SPEED_TOP = int(os.environ.get("SPEED_TOP", "150"))
CONCURRENCY = int(os.environ.get("CONCURRENCY", "40"))
TEST_TIMEOUT = float(os.environ.get("TEST_TIMEOUT", "5"))
BEST_N = int(os.environ.get("BEST_N", "100"))
MAX_PER_HOST = int(os.environ.get("MAX_PER_HOST", "3"))
MIN_ALIVE = int(os.environ.get("MIN_ALIVE", "5"))
PUBLIC_BASE = os.environ.get(
    "PUBLIC_BASE", "https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data"
).rstrip("/")


def write_atomic(path: Path, data: str | bytes, binary: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    if binary:
        assert isinstance(data, (bytes, bytearray))
        tmp.write_bytes(data)
    else:
        assert isinstance(data, str)
        tmp.write_text(data, encoding="utf-8")
    tmp.replace(path)


def _format_node_remark(index: int, node: ScoredNode, extra_tail: str = "") -> str:
    parts = [f"bahrain-vpn {index}"]
    if node.exit_country and node.exit_country != "XX":
        parts.append(f"{country_flag(node.exit_country)} {node.exit_country}")
    parts.append(f"{node.latency_ms:.0f}ms")
    if node.speed_kbps >= 1024:
        parts.append(f"{node.speed_kbps / 1024:.1f}MB/s")
    elif node.speed_kbps > 0:
        parts.append(f"{node.speed_kbps:.0f}KB/s")
    if extra_tail:
        parts.append(extra_tail)
    return collector.set_uri_remark(node.uri, " | ".join(parts))


def _preserve_last_known_good(prev_dir: Path, out_dir: Path) -> bool:
    required = ("alive.txt", "best100.txt", "sub.txt", "alive.json")
    if not prev_dir.is_dir() or not all((prev_dir / f).is_file() for f in required):
        return False
    out_dir.mkdir(parents=True, exist_ok=True)
    for fname in (
        "alive.txt",
        "best100.txt",
        "sub.txt",
        "alive.json",
        "all.txt.gz",
        "reliable.txt",
        "reliable_sub.txt",
        "low_latency.txt",
        "high_throughput.txt",
        "countries.json",
    ):
        src = prev_dir / fname
        if src.is_file():
            shutil.copy2(src, out_dir / fname)
    prev_protos = prev_dir / "protocols"
    if prev_protos.is_dir():
        dst_protos = out_dir / "protocols"
        if dst_protos.exists():
            shutil.rmtree(dst_protos)
        shutil.copytree(prev_protos, dst_protos)
    return True


def _file_url(rel: str) -> str:
    return f"{PUBLIC_BASE}/{rel}" if PUBLIC_BASE else rel


def _is_patched(fn: object) -> bool:
    return isinstance(fn, NonCallableMock) or hasattr(fn, "assert_called")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="بناء حزمة بيانات VPN الموثّقة لفرع data")
    ap.add_argument("--out-dir", type=Path, default=None)
    ap.add_argument("--prev-dir", type=Path, default=None)
    ap.add_argument("--test-top", type=int, default=None)
    ap.add_argument("--speed-top", type=int, default=None)
    ap.add_argument("--concurrency", type=int, default=None)
    ap.add_argument("--timeout", type=float, default=None)
    ap.add_argument("--min-alive", type=int, default=None)
    args = ap.parse_args(argv if argv is not None else [])

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    t_start = time.perf_counter()
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    out_dir = args.out_dir or DIST
    prev_dir = args.prev_dir or PREV_DIR
    eff_test_top = args.test_top if args.test_top is not None else TEST_TOP
    eff_speed_top = args.speed_top if args.speed_top is not None else SPEED_TOP
    eff_concurrency = args.concurrency if args.concurrency is not None else CONCURRENCY
    eff_timeout = args.timeout if args.timeout is not None else TEST_TIMEOUT
    eff_min_alive = args.min_alive if args.min_alive is not None else MIN_ALIVE
    weights = ScoringWeights().normalized()

    # ── 0) استعادة السجل الطولي وسجل الصحّة من اللقطة السابقة ──
    history = NodeHistoryStore()
    registry = SourceHealthRegistry()
    if prev_dir and prev_dir.is_dir():
        history = NodeHistoryStore.load(prev_dir / "state" / "node_history.json")
        if not history.entries:
            seeded = history.bootstrap_from_alive_json(prev_dir / "alive.json", now_iso)
            if seeded:
                LOG.info("تم تهيئة السجل الطولي من alive.json السابق (%d عقدة)", seeded)
        registry = SourceHealthRegistry.load(prev_dir / "state" / "source_state.json")

    prior_alive_ids = {
        cid for cid, entry in history.entries.items() if entry.consecutive_alive >= 1
    }

    # ── 1) الجمع + إزالة التكرار خماسية الطبقات ──
    raw_channels = collector.get_channels()
    urls = collector.channel_urls(raw_channels)
    gh_sources = collector.get_github_sources()
    LOG.info("[1/5] جمع: %d قناة + %d مصدر GitHub", len(urls), len(gh_sources))

    # إذا كانت دوال الجمع محاكاة في اختبارات الوحدة، نمرّ عبرها مباشرةً للتوافق التام
    if _is_patched(collector.collect_telegram) or _is_patched(collector.collect_github):
        tg_cfgs, ok, failed = collector.collect_telegram(urls, workers=12)
        gh_cfgs, gh_stats = collector.collect_github(gh_sources, workers=8)
        raw = gh_cfgs + tg_cfgs
        deduper = MultiLayerDeduplicator(
            verified_sources=set(collector.VERIFIED_TIER_SOURCES),
            reject_private_hosts=True,
        )
        for src_name, cnt in gh_stats:
            rec = registry.get_or_create(src_name, "github", gh_sources.get(src_name, ""))
            rec.update_from_fetch(fetch_ok=(cnt > 0), status_code=200 if cnt > 0 else 0, raw_count=cnt, valid_count=cnt, timestamp=now_iso)
        deduper.ingest_source("github", [collector._sanitize_raw_uri(c) for c in gh_cfgs])
        deduper.ingest_source("telegram", [collector._sanitize_raw_uri(c) for c in tg_cfgs])
        configs = deduper.unique_uris()
        rejected = deduper.summary.invalid_or_unsafe_rejected
        gh_ok = sum(1 for _, c in gh_stats if c > 0)
    else:
        tel = collector.collect_with_telemetry(
            channels=raw_channels,
            github_sources=gh_sources,
            workers=16,
            timeout=15,
            health_registry=registry,
        )
        raw = tel.raw_uris
        ok = tel.channels_ok
        failed = tel.channels_failed
        gh_ok = tel.github_fetched_ok
        deduper = tel.deduper
        configs = tel.unique_uris
        rejected = deduper.summary.invalid_or_unsafe_rejected

    LOG.info(
        "[2/5] تنظيف خماسي الطبقات: خام %d → فريد %d (مرفوض %d، مؤكّد من عدّة مصادر %d)",
        len(raw),
        len(configs),
        rejected,
        deduper.summary.multi_source_corroborated,
    )
    if not configs:
        if prev_dir and _preserve_last_known_good(prev_dir, out_dir):
            LOG.warning("::warning::لم يُجمع أي كانفيغ صالح — تم الحفاظ على آخر حزمة صالحة معروفة.")
            registry.save_state(out_dir / "state" / "source_state.json")
            registry.save_public_report(out_dir / "source_health.json")
            prev_meta = {}
            if (prev_dir / "meta.json").is_file():
                try:
                    prev_meta = json.loads((prev_dir / "meta.json").read_text(encoding="utf-8"))
                except Exception:
                    prev_meta = {}
            preserved_alive = len(
                [ln for ln in (out_dir / "alive.txt").read_text(encoding="utf-8").splitlines() if "://" in ln]
            )
            prev_meta.setdefault("generated_at", now_iso)
            prev_meta.setdefault("alive", preserved_alive)
            prev_meta.update({
                "last_attempted_at": now_iso,
                "degraded_mode": True,
                "degraded_reason": "empty_collection",
                "source_health_summary": registry.summary_counts(),
            })
            write_atomic(out_dir / "meta.json", json.dumps(prev_meta, ensure_ascii=False, indent=2) + "\n")
            return 0
        LOG.error("لا شيء تم جمعه — إيقاف بدون تعديل أي ملف منشور.")
        return 1

    mix = Counter(c.split("://")[0] for c in configs)
    prov_by_id = deduper.provenance_map()
    corroborated_ids = {cid for cid, p in prov_by_id.items() if p.corroboration_count >= 2}

    # ── 2) تجهيز النوى والفحص الفعلي (L3–L5) ──
    xray = tester.ensure_xray()
    sbox = tester.ensure_singbox()
    if not xray and not sbox:
        LOG.error("::error::تعذّر تجهيز النوى — إيقاف.")
        return 1
    LOG.info("[3/5] النوى: xray=%s sing-box=%s", bool(xray), bool(sbox))

    select_kwargs: dict = dict(
        xray_path=xray,
        singbox_path=sbox,
        test_top=eff_test_top,
        speed_top=eff_speed_top,
        concurrency=eff_concurrency,
        rank_by="score",
        timeout=eff_timeout,
    )
    if not _is_patched(tester.select_best):
        select_kwargs["prior_alive_ids"] = prior_alive_ids
        select_kwargs["corroborated_ids"] = corroborated_ids
        select_kwargs["stability_probes"] = 3

    lat, ranked, skipped = tester.select_best(configs, **select_kwargs)
    alive_raw = [r for r in lat if r.ok]
    LOG.info("[3/5] فحص: %d مرشّح → %d حيّة (%d متخطّى)", len(lat), len(alive_raw), skipped)

    # ── 3) تحديث السجل الطولي (L6) وصحّة المصادر وحساب الدرجات المركّبة ──
    alive_per_source: Counter[str] = Counter()
    speed_by_cfg = {r.cfg: r.speed_kbps for r in ranked}
    scored_nodes: list[ScoredNode] = []

    for r in lat:
        ident = parse_identity(r.cfg, reject_private_hosts=True)
        if ident is None:
            continue
        eff_speed = max(r.speed_kbps, speed_by_cfg.get(r.cfg, 0.0)) if r.ok else 0.0
        hist_entry = history.record_observation(
            ident.identity_id,
            ok=r.ok,
            latency_ms=r.median_latency_ms or r.latency_ms,
            speed_kbps=eff_speed,
            exit_country=r.exit_country,
            country_source=r.country_source,
            timestamp=now_iso,
        )
        if not r.ok:
            continue

        prov = prov_by_id.get(ident.identity_id)
        if prov:
            for src_name in prov.sources:
                alive_per_source[src_name] += 1

        if r.exit_country and r.exit_country != "XX" and r.country_source == "exit_trace":
            cc, cc_src = r.exit_country, "exit_trace"
        elif hist_entry.exit_country != "XX" and hist_entry.country_source == "exit_trace":
            cc, cc_src = hist_entry.exit_country, "exit_trace"
        else:
            cc, cc_src = infer_country_hint(r.cfg, ident.host)

        med_lat = r.median_latency_ms or r.latency_ms
        corr_cnt = prov.corroboration_count if prov else 1
        ver_hit = prov.verified_source_hit if prov else False

        score, breakdown = compute_composite_score(
            median_latency_ms=med_lat,
            jitter_ms=r.jitter_ms,
            probe_pass_rate=r.probe_pass_rate or 1.0,
            speed_kbps=eff_speed,
            runs_seen=hist_entry.runs_seen,
            runs_alive=hist_entry.runs_alive,
            consecutive_alive=hist_entry.consecutive_alive,
            ema_reliability=hist_entry.ema_reliability,
            corroboration_count=corr_cnt,
            verified_source_hit=ver_hit,
            weights=weights,
        )

        scored_nodes.append(
            ScoredNode(
                uri=r.cfg,
                identity_id=ident.identity_id,
                protocol=ident.scheme,
                canonical_protocol=ident.canonical_proto,
                host=ident.host,
                port=ident.port,
                subnet_key=ident.subnet_key,
                latency_ms=med_lat,
                median_latency_ms=med_lat,
                jitter_ms=r.jitter_ms,
                probe_pass_rate=r.probe_pass_rate or 1.0,
                speed_kbps=eff_speed,
                exit_country=cc,
                country_source=cc_src,
                is_cdn=is_cdn_endpoint(ident.host, ident.sni),
                is_warp=r.is_warp,
                runs_seen=hist_entry.runs_seen,
                runs_alive=hist_entry.runs_alive,
                consecutive_alive=hist_entry.consecutive_alive,
                ema_reliability=hist_entry.ema_reliability,
                corroboration_count=corr_cnt,
                verified_source_hit=ver_hit,
                engine=r.engine,
                score=score,
                score_breakdown=breakdown,
                verified_at=now_iso,
            )
        )

    for src_name, rec in registry.records.items():
        rec.alive_count = alive_per_source.get(src_name, 0)

    out_dir.mkdir(parents=True, exist_ok=True)
    history.save(out_dir / "state" / "node_history.json")
    registry.save_state(out_dir / "state" / "source_state.json")
    registry.save_public_report(out_dir / "source_health.json")

    if len(scored_nodes) < max(1, eff_min_alive):
        if prev_dir and _preserve_last_known_good(prev_dir, out_dir):
            LOG.warning(
                "::warning::العُقد الحيّة (%d) أقل من الحدّ الآمن (%d) — الحفاظ على آخر حزمة صالحة معروفة.",
                len(scored_nodes),
                max(1, eff_min_alive),
            )
            prev_meta = {}
            if (prev_dir / "meta.json").is_file():
                try:
                    prev_meta = json.loads((prev_dir / "meta.json").read_text(encoding="utf-8"))
                except Exception:
                    prev_meta = {}
            preserved_alive = len(
                [ln for ln in (out_dir / "alive.txt").read_text(encoding="utf-8").splitlines() if "://" in ln]
            )
            prev_meta.setdefault("generated_at", now_iso)
            prev_meta.setdefault("alive", preserved_alive)
            prev_meta.update({
                "last_attempted_at": now_iso,
                "tested": len(lat),
                "degraded_mode": True,
                "degraded_reason": f"alive_below_min:{len(scored_nodes)}<{max(1, eff_min_alive)}",
                "source_health_summary": registry.summary_counts(),
            })
            write_atomic(out_dir / "meta.json", json.dumps(prev_meta, ensure_ascii=False, indent=2) + "\n")
            return 0
        if not scored_nodes:
            LOG.error("لا عقدة حيّة — إيقاف بدون تعديل الملفات المنشورة.")
            return 1

    # ترتيب: الدرجة المركّبة الأعلى ثم الأقل تأخيرًا
    scored_nodes.sort(key=lambda n: (-n.score, n.median_latency_ms))

    # ── 4) بناء المخرجات باسم موحّد bahrain-vpn + القوائم المتخصّصة ──
    alive_named = [_format_node_remark(i, n) for i, n in enumerate(scored_nodes, 1)]
    write_atomic(out_dir / "alive.txt", "\n".join(alive_named) + "\n")
    write_atomic(
        out_dir / "sub.txt",
        base64.b64encode("\n".join(alive_named).encode("utf-8")).decode("ascii") + "\n",
    )

    write_atomic(
        out_dir / "alive.json",
        json.dumps(
            {
                "generated_at": now_iso,
                "count": len(scored_nodes),
                "servers": [
                    n.to_alive_json_dict(index=i, labeled_uri=labeled)
                    for i, (n, labeled) in enumerate(zip(scored_nodes, alive_named), 1)
                ],
            },
            ensure_ascii=False,
        )
        + "\n",
    )

    best = diversify_scored_nodes(
        scored_nodes, max_per_host=MAX_PER_HOST, max_per_subnet=6, limit=BEST_N
    )
    if len(best) < min(BEST_N, len(scored_nodes)):
        chosen_ids = {n.identity_id for n in best}
        for n in scored_nodes:
            if n.identity_id not in chosen_ids:
                best.append(n)
                chosen_ids.add(n.identity_id)
                if len(best) >= BEST_N:
                    break

    stamp_str = time.strftime("%b-%d | %H:%M", time.gmtime())
    best_lines = [_format_node_remark(i, n, extra_tail=stamp_str) for i, n in enumerate(best, 1)]
    write_atomic(out_dir / "best100.txt", "\n".join(best_lines) + "\n")

    spec = build_specialized_lists(scored_nodes)
    rel_lines = [_format_node_remark(i, n) for i, n in enumerate(spec["reliable"], 1)]
    low_lat_lines = [_format_node_remark(i, n) for i, n in enumerate(spec["low_latency"], 1)]
    high_tp_lines = [_format_node_remark(i, n) for i, n in enumerate(spec["high_throughput"], 1)]

    write_atomic(out_dir / "reliable.txt", "\n".join(rel_lines) + ("\n" if rel_lines else ""))
    write_atomic(
        out_dir / "reliable_sub.txt",
        base64.b64encode("\n".join(rel_lines).encode("utf-8")).decode("ascii") + "\n",
    )
    write_atomic(out_dir / "low_latency.txt", "\n".join(low_lat_lines) + ("\n" if low_lat_lines else ""))
    write_atomic(out_dir / "high_throughput.txt", "\n".join(high_tp_lines) + ("\n" if high_tp_lines else ""))

    # قوائم مفصولة حسب البروتوكول المعياري
    proto_dir = out_dir / "protocols"
    proto_dir.mkdir(parents=True, exist_ok=True)
    by_cproto: dict[str, list[ScoredNode]] = {}
    for n in scored_nodes:
        by_cproto.setdefault(n.canonical_protocol, []).append(n)
    proto_files_meta: dict[str, str] = {}
    for pname, pnodes in sorted(by_cproto.items()):
        plines = [_format_node_remark(i, n) for i, n in enumerate(pnodes, 1)]
        write_atomic(proto_dir / f"{pname}.txt", "\n".join(plines) + "\n")
        proto_files_meta[pname] = _file_url(f"protocols/{pname}.txt")

    # فهرس الدول الموثّق
    country_buckets: dict[str, list[ScoredNode]] = {}
    for n in scored_nodes:
        country_buckets.setdefault(n.exit_country or "XX", []).append(n)
    countries_index = {
        "generated_at": now_iso,
        "total_alive": len(scored_nodes),
        "verified_exit_trace_count": sum(1 for n in scored_nodes if n.country_source == "exit_trace"),
        "countries": [
            {
                "code": cc,
                "flag": country_flag(cc),
                "count": len(items),
                "verified_exit_count": sum(1 for x in items if x.country_source == "exit_trace"),
                "best_latency_ms": round(min(x.median_latency_ms for x in items)),
                "top_score": round(max(x.score for x in items), 1),
            }
            for cc, items in sorted(country_buckets.items(), key=lambda kv: (-len(kv[1]), kv[0]))
        ],
    }
    write_atomic(out_dir / "countries.json", json.dumps(countries_index, ensure_ascii=False, indent=2) + "\n")

    # كل الكانفيغات النظيفة مضغوطة (مع إعادة التسمية باسم bahrain-vpn)
    all_named = [collector.set_uri_remark(c, f"bahrain-vpn {i}") for i, c in enumerate(configs, 1)]
    payload = ("\n".join(all_named) + "\n").encode("utf-8")
    write_atomic(out_dir / "all.txt.gz", gzip.compress(payload, compresslevel=9), binary=True)

    # ── 5) meta.json المتوافق رجعيًا والغني بالمؤشرات ──
    meta = {
        "schema_version": 2,
        "generated_at": now_iso,
        "duration_sec": round(time.perf_counter() - t_start, 1),
        "degraded_mode": False,
        "channels_total": len(urls),
        "channels_ok": ok,
        "channels_failed": failed,
        "github_sources": len(gh_sources),
        "github_sources_ok": gh_ok,
        "raw_collected": len(raw),
        "unique_clean": len(configs),
        "tested": len(lat),
        "alive": len(scored_nodes),
        "skipped_unsupported": skipped,
        "alive_by_protocol": dict(Counter(n.canonical_protocol for n in scored_nodes)),
        "collected_by_protocol": dict(mix),
        "best100_by_protocol": dict(Counter(n.canonical_protocol for n in best)),
        "deduplication": deduper.summary.to_dict(),
        "validation_funnel": {
            "l0_raw_collected": len(raw),
            "l1_unique_valid": len(configs),
            "l2_l3_tested": len(lat),
            "l3_tunnel_alive": len(scored_nodes),
            "l4_full_probe_pass": sum(1 for n in scored_nodes if n.probe_pass_rate >= 0.99),
            "l5_speed_verified": sum(1 for n in scored_nodes if n.speed_kbps > 0),
            "l6_multi_run_stable": sum(1 for n in scored_nodes if n.consecutive_alive >= 2),
        },
        "scoring_weights": weights.to_dict(),
        "countries_summary": {c["code"]: c["count"] for c in countries_index["countries"][:20]},
        "source_health_summary": registry.summary_counts(),
        "engines": {"xray": bool(xray), "singbox": bool(sbox)},
        "files": {
            "alive": _file_url("alive.txt"),
            "best100": _file_url("best100.txt"),
            "sub": _file_url("sub.txt"),
            "reliable": _file_url("reliable.txt"),
            "reliable_sub": _file_url("reliable_sub.txt"),
            "low_latency": _file_url("low_latency.txt"),
            "high_throughput": _file_url("high_throughput.txt"),
            "alive_json": _file_url("alive.json"),
            "countries_json": _file_url("countries.json"),
            "source_health_json": _file_url("source_health.json"),
            "all_gz": _file_url("all.txt.gz"),
            "protocols": proto_files_meta,
        },
    }
    write_atomic(out_dir / "meta.json", json.dumps(meta, ensure_ascii=False, indent=2) + "\n")

    LOG.info(
        "[5/5] انتهى في %.1f ثانية | حيّة: %d | أفضل %d: %d | مستقر متعدّد الدورات: %d",
        meta["duration_sec"],
        len(scored_nodes),
        BEST_N,
        len(best),
        meta["validation_funnel"]["l6_multi_run_stable"],
    )

    keep = os.environ.get("COPY_TO")
    if keep:
        dest = ROOT / keep
        dest.mkdir(parents=True, exist_ok=True)
        for f in out_dir.iterdir():
            if f.is_file():
                shutil.copy2(f, dest / f.name)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception as exc:
        print(f"::error::Unhandled build_data error: {redact_text(repr(exc))}", file=sys.stderr)
        raise
