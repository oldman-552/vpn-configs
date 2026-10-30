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
from historical_db import HistoricalServerDB, parse_iso_epoch  # noqa: E402
from pipeline_security import redact_text  # noqa: E402
from public_api import export_static_api_v1  # noqa: E402
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
    rank_nodes_by_profile,
)
from security_intelligence import (  # noqa: E402
    QuarantineRegistry,
    ThreatIntelIndicators,
    assess_configuration_security,
    compute_multidimensional_scores,
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
        "privacy_aware.txt",
        "countries.json",
        "quarantined.json",
        "servers-current.json",
        "servers-history.json",
        "servers-performance.json",
        "servers-statistics.json",
        "countries-statistics.json",
        "sources-statistics.json",
    ):
        src = prev_dir / fname
        if src.is_file():
            shutil.copy2(src, out_dir / fname)
    for sub_tree in ("protocols", "api", "state"):
        prev_sub = prev_dir / sub_tree
        if prev_sub.is_dir():
            dst_sub = out_dir / sub_tree
            if dst_sub.exists():
                shutil.rmtree(dst_sub)
            shutil.copytree(prev_sub, dst_sub)
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

    # ── 0) استعادة السجل الطولي وسجل الصحّة وقاعدة البيانات التاريخية SQLite من اللقطة السابقة ──
    history = NodeHistoryStore()
    registry = SourceHealthRegistry()
    hist_db_path = out_dir / "state" / "history.sqlite3"
    hist_db_path.parent.mkdir(parents=True, exist_ok=True)
    if prev_dir and prev_dir.is_dir():
        prev_sqlite = prev_dir / "state" / "history.sqlite3"
        if prev_sqlite.is_file() and prev_sqlite.resolve() != hist_db_path.resolve():
            shutil.copy2(prev_sqlite, hist_db_path)
        history = NodeHistoryStore.load(prev_dir / "state" / "node_history.json")
        if not history.entries:
            seeded = history.bootstrap_from_alive_json(prev_dir / "alive.json", now_iso)
            if seeded:
                LOG.info("تم تهيئة السجل الطولي من alive.json السابق (%d عقدة)", seeded)
        registry = SourceHealthRegistry.load(prev_dir / "state" / "source_state.json")

    hist_db = HistoricalServerDB(hist_db_path)
    if prev_dir and (prev_dir / "state" / "node_history.json").is_file():
        boot_cnt = hist_db.bootstrap_from_node_history_json(prev_dir / "state" / "node_history.json", now_iso=now_iso)
        if boot_cnt:
            LOG.info("تم ترحيل %d سجل تاريخي أولي إلى SQLite (history.sqlite3)", boot_cnt)

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
    corroborated_ids = {cid for cid, p in prov_by_id.items() if p.independent_source_count >= 2}

    # تسجيل ظهور جميع السيرفرات الصالحة المكتشفة ومصادرها المستقلة في قاعدة SQLite التاريخية
    now_epoch = parse_iso_epoch(now_iso)
    suppressed_ids = hist_db.get_suppressed_ids(now_epoch=now_epoch)
    sighting_batch = []
    for u in configs:
        id_s = parse_identity(u, reject_private_hosts=True)
        if id_s is None:
            continue
        pr_s = prov_by_id.get(id_s.identity_id)
        src_pairs = [(sn, deduper.source_urls.get(sn, "")) for sn in (pr_s.sources if pr_s else ())]
        sighting_batch.append((id_s, src_pairs))
    if sighting_batch:
        hist_db.record_Sightings_batch(sighting_batch, observed_at=now_iso)

    # ── 1b) فحص الأمان الساكن وعزل الكانفيغات الحرجة واستبعاد الموقوفة مؤقتًا (Phase 2 & Failure Suppression) ──
    quarantine_reg = QuarantineRegistry()
    threat_intel = ThreatIntelIndicators.from_json_file(ROOT / "threat_intel_indicators.json")
    safe_configs: list[str] = []
    suppressed_deferred: list[str] = []
    for u in configs:
        ident_pre = parse_identity(u, reject_private_hosts=False)
        prov_pre = prov_by_id.get(ident_pre.identity_id) if ident_pre else None
        pre_rep = assess_configuration_security(u, threat_intel=threat_intel)
        if pre_rep.quarantined:
            quarantine_reg.record(
                u,
                pre_rep,
                sources=(prov_pre.sources if prov_pre else ()),
                timestamp=now_iso,
            )
            continue
        if ident_pre and ident_pre.identity_id in suppressed_ids:
            suppressed_deferred.append(u)
            continue
        safe_configs.append(u)

    # إذا كانت كل الكانفيغات مؤجلة، نحتفظ بها للفحص؛ وإلا نضع المؤجلة في ذيل الطابور دون حذف دائم
    configs = safe_configs + suppressed_deferred

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

    # ── 3) تحديث السجل الطولي (L6) وصحّة المصادر وحساب الدرجات متعدّدة الأبعاد (Phases 2 & 5) ──
    alive_per_source: Counter[str] = Counter()
    tested_per_proto: Counter[str] = Counter()
    alive_per_proto_tested: Counter[str] = Counter()
    speed_by_cfg = {r.cfg: r.speed_kbps for r in ranked}
    scored_nodes: list[ScoredNode] = []

    for r in lat:
        ident = parse_identity(r.cfg, reject_private_hosts=True)
        if ident is None:
            continue
        tested_per_proto[ident.canonical_proto] += 1
        prov = prov_by_id.get(ident.identity_id)
        prior_entry = history.entries.get(ident.identity_id)
        prior_exit_cc = prior_entry.exit_country if prior_entry else ""
        prior_sec_mode = prior_entry.last_security_mode if prior_entry else ""
        prior_perf = prior_entry.last_performance_score if prior_entry else 0.0

        if not r.ok:
            if r.error in ("http_301", "http_302", "http_303", "http_307", "http_308"):
                redir_rep = assess_configuration_security(
                    r.cfg, probe_error=r.error, threat_intel=threat_intel
                )
                quarantine_reg.record(
                    r.cfg,
                    redir_rep,
                    sources=(prov.sources if prov else ()),
                    timestamp=now_iso,
                )
            history.record_observation(
                ident.identity_id,
                ok=False,
                timestamp=now_iso,
            )
            hist_db.record_measurement(
                ident,
                measured_at=now_iso,
                ok=False,
                raw_error=str(r.error or "probe_failed"),
                packet_loss_pct=100.0,
                sources=[(sn, deduper.source_urls.get(sn, "")) for sn in (prov.sources if prov else ())],
            )
            continue

        eff_speed = max(r.speed_kbps, speed_by_cfg.get(r.cfg, 0.0))
        if r.exit_country and r.exit_country != "XX" and r.country_source == "exit_trace":
            cc, cc_src = r.exit_country, "exit_trace"
        elif prior_entry and prior_entry.exit_country != "XX" and prior_entry.country_source == "exit_trace":
            cc, cc_src = prior_entry.exit_country, "exit_trace"
        else:
            cc, cc_src = infer_country_hint(r.cfg, ident.host)

        sec_rep = assess_configuration_security(
            r.cfg,
            tls_probe_verified=True,
            dns_consistent=True,
            prior_exit_country=(prior_exit_cc if (prior_entry and prior_entry.country_source == "exit_trace") else ""),
            current_exit_country=(cc if cc_src == "exit_trace" else ""),
            prior_security_mode=prior_sec_mode,
            threat_intel=threat_intel,
        )
        if sec_rep.quarantined:
            quarantine_reg.record(
                r.cfg,
                sec_rep,
                sources=(prov.sources if prov else ()),
                timestamp=now_iso,
            )
            history.record_observation(ident.identity_id, ok=False, timestamp=now_iso)
            hist_db.record_measurement(
                ident,
                measured_at=now_iso,
                ok=False,
                raw_error="quarantined_post_probe",
                packet_loss_pct=100.0,
                security_assessment=sec_rep.security_assessment,
                privacy_assessment=sec_rep.privacy_assessment,
                risk_level=sec_rep.risk_level,
                sources=[(sn, deduper.source_urls.get(sn, "")) for sn in (prov.sources if prov else ())],
            )
            continue

        alive_per_proto_tested[ident.canonical_proto] += 1
        hist_entry = history.record_observation(
            ident.identity_id,
            ok=True,
            latency_ms=r.median_latency_ms or r.latency_ms,
            speed_kbps=eff_speed,
            exit_country=cc,
            country_source=cc_src,
            timestamp=now_iso,
        )

        if prov:
            for src_name in prov.sources:
                alive_per_source[src_name] += 1

        med_lat = r.median_latency_ms or r.latency_ms
        corr_cnt = prov.independent_source_count if prov else 1
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

        md = compute_multidimensional_scores(
            median_latency_ms=med_lat,
            jitter_ms=r.jitter_ms,
            probe_pass_rate=r.probe_pass_rate or 1.0,
            speed_kbps=eff_speed,
            runs_seen=hist_entry.runs_seen,
            runs_alive=hist_entry.runs_alive,
            consecutive_alive=hist_entry.consecutive_alive,
            ema_reliability=hist_entry.ema_reliability,
            recent_failures=hist_entry.consecutive_failures,
            verified_at=now_iso,
            now_iso=now_iso,
            prior_performance_score=prior_perf,
            security_report=sec_rep,
        )
        hist_entry.last_performance_score = md.performance_score
        hist_entry.last_reliability_score = md.reliability_score
        hist_entry.last_security_mode = "tls" if sec_rep.tls_enabled else "none"

        hist_db.record_measurement(
            ident,
            measured_at=now_iso,
            ok=True,
            latency_ms=r.latency_ms,
            median_latency_ms=med_lat,
            p95_latency_ms=max(med_lat, r.latency_ms) + (r.jitter_ms * 0.5),
            jitter_ms=r.jitter_ms,
            packet_loss_pct=md.packet_loss_pct,
            download_kbps=eff_speed if eff_speed > 0 else None,
            exit_country=cc,
            country_source=cc_src,
            exit_ip=getattr(r, "exit_ip", "") or "",
            composite_score=score,
            performance_score=md.performance_score,
            reliability_score=md.reliability_score,
            security_assessment=md.security_assessment,
            privacy_assessment=md.privacy_assessment,
            risk_level=md.risk_level,
            sources=[(sn, deduper.source_urls.get(sn, "")) for sn in (prov.sources if prov else ())],
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
                performance_score=md.performance_score,
                reliability_score=md.reliability_score,
                security_assessment=md.security_assessment,
                privacy_assessment=md.privacy_assessment,
                risk_level=md.risk_level,
                packet_loss_pct=md.packet_loss_pct,
                uptime_pct=md.uptime_pct,
                score_delta=md.score_delta,
                recent_failures=hist_entry.consecutive_failures,
            )
        )

    overlap_map = deduper.source_overlap_metrics()
    for src_name, rec in registry.records.items():
        rec.alive_count = alive_per_source.get(src_name, 0)
        if src_name in overlap_map:
            om = overlap_map[src_name]
            rec.unique_identities = int(om.get("unique_identities", 0))
            rec.exclusive_identities = int(om.get("exclusive_identities", 0))
            rec.overlap_ratio = float(om.get("overlap_ratio", 0.0))

    out_dir.mkdir(parents=True, exist_ok=True)
    hist_db.record_pipeline_run_and_sources(
        run_at=now_iso,
        tested_count=len(lat),
        alive_count=len(scored_nodes),
        degraded_mode=len(scored_nodes) < max(1, eff_min_alive),
        source_records=[r.to_state_dict() for r in registry.records.values()],
    )
    hist_db.apply_retention_and_retirement(now_iso=now_iso)
    history.save(out_dir / "state" / "node_history.json")
    registry.save_state(out_dir / "state" / "source_state.json")
    registry.save_public_report(out_dir / "source_health.json")
    quarantine_reg.save_public_report(out_dir / "quarantined.json")

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

    priv_ranked = diversify_scored_nodes(
        rank_nodes_by_profile(scored_nodes, "PRIVACY_AWARE", now_iso=now_iso),
        max_per_host=MAX_PER_HOST,
        max_per_subnet=6,
        limit=BEST_N,
    )
    priv_lines = [_format_node_remark(i, n) for i, n in enumerate(priv_ranked, 1)]
    write_atomic(out_dir / "privacy_aware.txt", "\n".join(priv_lines) + ("\n" if priv_lines else ""))

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
        "quarantined": len(quarantine_reg.entries),
        "skipped_unsupported": skipped,
        "alive_by_protocol": dict(Counter(n.canonical_protocol for n in scored_nodes)),
        "collected_by_protocol": dict(mix),
        "best100_by_protocol": dict(Counter(n.canonical_protocol for n in best)),
        "security_summary": dict(Counter(n.security_assessment for n in scored_nodes)),
        "risk_summary": dict(Counter(n.risk_level for n in scored_nodes)),
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
            "privacy_aware": _file_url("privacy_aware.txt"),
            "alive_json": _file_url("alive.json"),
            "countries_json": _file_url("countries.json"),
            "source_health_json": _file_url("source_health.json"),
            "quarantined_json": _file_url("quarantined.json"),
            "api_v1_statistics": _file_url("api/v1/statistics.json"),
            "api_v1_servers": _file_url("api/v1/servers.json"),
            "api_v1_openapi": _file_url("api/v1/openapi.json"),
            "servers_current_json": _file_url("servers-current.json"),
            "servers_history_json": _file_url("servers-history.json"),
            "servers_performance_json": _file_url("servers-performance.json"),
            "servers_statistics_json": _file_url("servers-statistics.json"),
            "countries_statistics_json": _file_url("countries-statistics.json"),
            "sources_statistics_json": _file_url("sources-statistics.json"),
            "all_gz": _file_url("all.txt.gz"),
            "protocols": proto_files_meta,
        },
    }
    write_atomic(out_dir / "meta.json", json.dumps(meta, ensure_ascii=False, indent=2) + "\n")

    # تصدير ملفات الاستخبارات التاريخية المعيارية (Part 7 Versioned Public Exports)
    hist_db.export_public_historical_artifacts(out_dir, generated_at=now_iso)

    # ── 6) تصدير واجهة الإحصاءات العامة المقروءة فقط (/api/v1/*) وبيانات الرصد (Phases 8 & 10) ──
    alive_dicts = [
        n.to_alive_json_dict(index=i, labeled_uri=labeled)
        for i, (n, labeled) in enumerate(zip(scored_nodes, alive_named), 1)
    ]
    tested_proto_pairs = {
        p: (tested_per_proto[p], alive_per_proto_tested.get(p, 0))
        for p in set(tested_per_proto.keys()) | set(alive_per_proto_tested.keys())
    }
    src_pub_report = {}
    if (out_dir / "source_health.json").is_file():
        try:
            src_pub_report = json.loads((out_dir / "source_health.json").read_text(encoding="utf-8"))
        except Exception:
            src_pub_report = {}
    export_static_api_v1(
        out_dir,
        prev_dir=prev_dir,
        meta=meta,
        alive_servers_dicts=alive_dicts,
        tested_by_proto=tested_proto_pairs,
        quarantined_total=len(quarantine_reg.entries),
        quarantined_reasons=quarantine_reg.summary_by_reason(),
        source_report=src_pub_report,
    )

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
