#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
server/build_data.py — يُشغَّل على GitHub Actions كل 30 دقيقة.

المهمة:
  1) جمع كل الكانفيغات (قنوات تلغرام من channels.txt + مستودعات GitHub من github_sources.txt)
  2) تنظيف + إزالة تكرار
  3) فحص اتصال حقيقي بعيّنة متوازنة (Xray + sing-box) لتقليص عشرات الآلاف → ~1,000 حيّة
  4) نشر المخرجات في مجلد dist/ (يرفعها الـ workflow إلى فرع data)

المخرجات في dist/:
  alive.txt        الكانفيغات الحيّة فقط (سطر لكل كانفيغ) ← ينزّلها التطبيق
  alive.json       نفس القائمة + تأخير الخادم + المحرّك (لعرضها في التطبيق)
  sub.txt          نفس القائمة بترميز base64 (اشتراك جاهز لأي عميل)
  best100.txt      أفضل 100 حسب قياس الخادم (مع الـ remark)
  all.txt.gz       كل الكانفيغات النظيفة مضغوطة (نسخة احتياطية كاملة)
  meta.json        وقت التوليد + الأعداد + إصدارات النوى
"""

from __future__ import annotations

import base64
import gzip
import json
import logging
import os
import shutil
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import collector                      # noqa: E402
import tester                         # noqa: E402

DIST = ROOT / "dist"
LOG = logging.getLogger("build_data")

# إعدادات قابلة للتغيير من متغيّرات البيئة (في الـ workflow)
TEST_TOP = int(os.environ.get("TEST_TOP", "1200"))
CONCURRENCY = int(os.environ.get("CONCURRENCY", "40"))
TEST_TIMEOUT = float(os.environ.get("TEST_TIMEOUT", "5"))
BEST_N = int(os.environ.get("BEST_N", "100"))
MAX_PER_HOST = int(os.environ.get("MAX_PER_HOST", "3"))
PUBLIC_BASE = os.environ.get("PUBLIC_BASE", "").rstrip("/")


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


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    t_start = time.perf_counter()

    # ── 1) الجمع (من channels.txt و github_sources.txt إن وُجدا) ──
    raw_channels = collector.get_channels()
    urls = collector.channel_urls(raw_channels)
    gh_sources = collector.get_github_sources()
    LOG.info("[1/5] جمع: %d قناة + %d مصدر GitHub", len(urls), len(gh_sources))

    tg_cfgs, ok, failed = collector.collect_telegram(urls, workers=12)
    gh_cfgs, gh_stats = collector.collect_github(gh_sources, workers=8)
    LOG.info("تلغرام: %d صفحة ناجحة / %d فاشلة → %d كانفيغ | GitHub → %d كانفيغ",
             ok, failed, len(tg_cfgs), len(gh_cfgs))

    raw = tg_cfgs + gh_cfgs
    configs, rejected = collector.clean(raw)
    LOG.info("[2/5] تنظيف: خام %d → فريد %d (مرفوض %d)", len(raw), len(configs), rejected)
    if not configs:
        LOG.error("لا شيء تم جمعه — إيقاف بدون تعديل أي ملف منشور.")
        return 1

    mix = Counter(c.split("://")[0] for c in configs)

    # ── 3) الفحص (تقليص العدد) ──
    xray = tester.ensure_xray()
    sbox = tester.ensure_singbox()
    if not xray and not sbox:
        LOG.error("تعذّر تجهيز النوى — إيقاف.")
        return 1
    LOG.info("[3/5] النوى: xray=%s sing-box=%s", bool(xray), bool(sbox))

    lat, ranked, skipped = tester.select_best(
        configs,
        xray_path=xray,
        singbox_path=sbox,
        test_top=TEST_TOP,
        speed_top=0,                 # لا قياس سرعة على الخادم (التطبيق يقيس على شبكتك)
        concurrency=CONCURRENCY,
        rank_by="latency",
        timeout=TEST_TIMEOUT,
    )
    alive = [r for r in lat if r.ok]
    LOG.info("[3/5] فحص: %d مرشّح → %d حيّة (%d متخطّى)", len(lat), len(alive), skipped)
    if not alive:
        LOG.error("لا عقدة حيّة — إيقاف بدون تعديل الملفات المنشورة.")
        return 1

    # ترتيب: الأقل تأخيرًا أولًا
    alive.sort(key=lambda r: r.latency_ms)

    # ── 4) بناء المخرجات ──
    DIST.mkdir(parents=True, exist_ok=True)

    alive_cfgs = [r.cfg for r in alive]
    write_atomic(DIST / "alive.txt", "\n".join(alive_cfgs) + "\n")

    write_atomic(
        DIST / "sub.txt",
        base64.b64encode("\n".join(alive_cfgs).encode("utf-8")).decode("ascii") + "\n",
    )

    write_atomic(DIST / "alive.json", json.dumps({
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "count": len(alive),
        "servers": [
            {"cfg": r.cfg, "latency_ms": round(r.latency_ms),
             "engine": r.engine, "proto": r.cfg.split("://", 1)[0]}
            for r in alive
        ],
    }, ensure_ascii=False) + "\n")

    # أفضل N حسب قياس الخادم (مع تنويع المضيفين + تكملة القائمة إن لزم)
    diversified = tester.limit_per_host(alive, MAX_PER_HOST)
    best = diversified[:BEST_N]
    if len(best) < min(BEST_N, len(alive)):
        chosen = {id(r) for r in best}
        for r in alive:
            if id(r) not in chosen:
                best.append(r)
                if len(best) >= BEST_N:
                    break

    stamp = time.strftime("%b-%d | %H:%M", time.gmtime())
    lines = [
        f"{r.cfg}#{i} | {r.latency_ms:.0f}ms | {r.engine} | {stamp}"
        for i, r in enumerate(best, 1)
    ]
    write_atomic(DIST / "best100.txt", "\n".join(lines) + "\n")

    # كل الكانفيغات مضغوطة (احتياط كامل)
    payload = ("\n".join(configs) + "\n").encode("utf-8")
    write_atomic(DIST / "all.txt.gz", gzip.compress(payload, compresslevel=9), binary=True)

    # ── 5) meta ──
    meta = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "duration_sec": round(time.perf_counter() - t_start, 1),
        "channels_total": len(urls),
        "channels_ok": ok,
        "channels_failed": failed,
        "github_sources": len(gh_sources),
        "raw_collected": len(raw),
        "unique_clean": len(configs),
        "tested": len(lat),
        "alive": len(alive),
        "skipped_unsupported": skipped,
        "alive_by_protocol": dict(Counter(r.cfg.split("://", 1)[0] for r in alive)),
        "collected_by_protocol": dict(mix),
        "best100_by_protocol": dict(Counter(r.cfg.split("://", 1)[0] for r in best)),
        "engines": {"xray": bool(xray), "singbox": bool(sbox)},
        "files": {
            "alive": f"{PUBLIC_BASE}/alive.txt" if PUBLIC_BASE else "alive.txt",
            "best100": f"{PUBLIC_BASE}/best100.txt" if PUBLIC_BASE else "best100.txt",
            "sub": f"{PUBLIC_BASE}/sub.txt" if PUBLIC_BASE else "sub.txt",
            "alive_json": f"{PUBLIC_BASE}/alive.json" if PUBLIC_BASE else "alive.json",
            "all_gz": f"{PUBLIC_BASE}/all.txt.gz" if PUBLIC_BASE else "all.txt.gz",
        },
    }
    write_atomic(DIST / "meta.json", json.dumps(meta, ensure_ascii=False, indent=2) + "\n")

    LOG.info("[4/5] المخرجات في %s:", DIST)
    for f in sorted(DIST.iterdir()):
        LOG.info("   %-14s %7.1f KB", f.name, f.stat().st_size / 1024)
    LOG.info("[5/5] انتهى في %.1f ثانية | حيّة: %d | أفضل 100: %d",
             time.perf_counter() - t_start, len(alive), len(best))

    keep = os.environ.get("COPY_TO")
    if keep:
        dest = ROOT / keep
        dest.mkdir(parents=True, exist_ok=True)
        for f in DIST.iterdir():
            shutil.copy2(f, dest / f.name)
        LOG.info("نُسخت المخرجات إلى %s", dest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
