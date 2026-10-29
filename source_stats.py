#!/usr/bin/env python3
"""
تقرير إحصائي ومعماري شامل للمصادر (قنوات تيليجرام + مصادر GitHub) + اكتشاف محكوم للمصادر المرشّحة:
- يقيس الخام، الصالح، الهويات الفريدة (Layer-2)، الإضافة الحصرية (Exclusive)، ونسبة التداخل (Overlap).
- يطابق العُقد مع قائمة العُقد الحيّة الفعلية (alive.txt / data branch).
- يدعم `--discover` للبحث المحكوم عبر GitHub API وتقييم المرشّحين كـ `pending_validation` دون تفعيل آلي أعمى.
- يصدر ملخصًا بشريًا واضحًا وملف JSON اختياري (`--json-out`) خاليًا تمامًا من أي بيانات اعتماد.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

import collector
from dedupe import parse_identity
from pipeline_security import MAX_FEED_BYTES, safe_fetch_text

LIVE_ALIVE_URL = "https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/alive.txt"

CANDIDATE_PATHS = (
    "sub.txt",
    "all.txt",
    "configs.txt",
    "v2ray.txt",
    "merged.txt",
    "sub/proxies.txt",
    "subscribe/v2ray.txt",
)


def load_alive_identities(
    alive_file: Path | None, session: requests.Session
) -> tuple[set[str], set[tuple[str, int]], str]:
    text = ""
    src_desc = "غير متاح"
    if alive_file and alive_file.is_file():
        text = alive_file.read_text(encoding="utf-8", errors="ignore")
        src_desc = str(alive_file)
    else:
        res = safe_fetch_text(session, LIVE_ALIVE_URL, timeout=15)
        if res.ok and res.text.strip():
            text = res.text
            src_desc = "فرع data الحيّ"

    ids: set[str] = set()
    hostports: set[tuple[str, int]] = set()
    for line in text.splitlines():
        ident = parse_identity(line.strip(), reject_private_hosts=False)
        if ident:
            ids.add(ident.identity_id)
            hostports.add((ident.host, ident.port))
    return ids, hostports, src_desc


def evaluate_candidate_feed(
    raw_text: str,
    existing_ids: set[str],
    *,
    min_exclusive: int = 20,
    max_overlap_ratio: float = 0.85,
) -> dict[str, int | float | str]:
    """
    تقييم تغذية مرشّحة مقابل مجموعة الهويات الحالية دون كشف أي أسرار:
    يعيد عدد الهويات الفريدة، الحصرية، نسبة التداخل، وقرار الحوكمة الصريح.
    """
    uris = [collector._sanitize_raw_uri(u) for u in collector.parse_subscription(raw_text)]
    cand_ids: set[str] = set()
    for u in uris:
        ident = parse_identity(u, reject_private_hosts=True)
        if ident:
            cand_ids.add(ident.identity_id)

    total = len(cand_ids)
    if total == 0:
        return {
            "unique_identities": 0,
            "exclusive_identities": 0,
            "overlap_ratio": 0.0,
            "decision": "rejected_empty_or_invalid",
        }

    shared = len(cand_ids & existing_ids)
    exclusive = total - shared
    overlap_ratio = round(shared / total, 4)

    if exclusive < min_exclusive:
        decision = "rejected_low_yield"
    elif overlap_ratio > max_overlap_ratio:
        decision = "rejected_high_overlap"
    else:
        decision = "pending_validation"

    return {
        "unique_identities": total,
        "exclusive_identities": exclusive,
        "overlap_ratio": overlap_ratio,
        "decision": decision,
    }


def discover_github_candidates(
    session: requests.Session,
    existing_urls: set[str],
    existing_ids: set[str],
    *,
    max_repos: int = 10,
    freshness_days: int = 30,
    github_token: str | None = None,
) -> list[dict]:
    """
    اكتشاف محكوم لمصادر مرشّحة عبر GitHub Search API مع احترام حدود المعدّل،
    واشتراط الحداثة وعدم الأرشفة وعدم كون المستودع مجرّد Fork، وعدم التفعيل الآلي الأعمى.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=freshness_days)).strftime("%Y-%m-%d")
    query = f"v2ray OR vless OR hysteria2 configs pushed:>={cutoff} fork:false archived:false"
    api_url = (
        f"https://api.github.com/search/repositories"
        f"?q={requests.utils.quote(query)}&sort=updated&order=desc&per_page={min(max_repos, 20)}"
    )
    headers = {"Accept": "application/vnd.github+json"}
    tok = github_token or os.environ.get("GITHUB_TOKEN", "").strip()
    if tok:
        headers["Authorization"] = f"Bearer {tok}"

    try:
        resp = session.get(api_url, headers=headers, timeout=15)
        if resp.status_code != 200:
            return []
        items = resp.json().get("items", [])
    except Exception:
        return []

    existing_repos = {
        "/".join(u.split("/")[3:5]).lower()
        for u in existing_urls
        if "raw.githubusercontent.com/" in u and len(u.split("/")) >= 6
    }

    evaluated: list[dict] = []
    for repo in items[:max_repos]:
        full_name = str(repo.get("full_name", ""))
        if not full_name or full_name.lower() in existing_repos:
            continue
        if repo.get("archived") or repo.get("fork") or repo.get("disabled"):
            evaluated.append({
                "repo": full_name,
                "url": "",
                "license": (repo.get("license") or {}).get("spdx_id") or "UNSPECIFIED",
                "decision": "rejected_stale_or_archived",
                "unique_identities": 0,
                "exclusive_identities": 0,
                "overlap_ratio": 0.0,
            })
            continue

        branch = str(repo.get("default_branch") or "main")
        license_id = (repo.get("license") or {}).get("spdx_id") or "UNSPECIFIED"

        matched = False
        for rel_path in CANDIDATE_PATHS:
            raw_url = f"https://raw.githubusercontent.com/{full_name}/{branch}/{rel_path}"
            if raw_url in existing_urls:
                continue
            fetched = safe_fetch_text(
                session, raw_url, timeout=12, max_bytes=min(MAX_FEED_BYTES, 4 * 1024 * 1024), require_https=True
            )
            if not fetched.ok or not fetched.text.strip():
                continue
            verdict = evaluate_candidate_feed(fetched.text, existing_ids)
            if int(verdict["unique_identities"]) > 0:
                evaluated.append({
                    "repo": full_name,
                    "url": raw_url,
                    "license": license_id,
                    **verdict,
                })
                matched = True
                break

        if not matched:
            evaluated.append({
                "repo": full_name,
                "url": "",
                "license": license_id,
                "decision": "rejected_no_standard_feed",
                "unique_identities": 0,
                "exclusive_identities": 0,
                "overlap_ratio": 0.0,
            })
    return evaluated


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="قياس كفاءة وتفرّد وتداخل المصادر واكتشاف المرشّحين")
    ap.add_argument("--alive-file", type=Path, help="ملف عُقد حيّة محلي للمقارنة")
    ap.add_argument("--top", type=int, default=40, help="عدد القنوات الأعلى المعروضة")
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--no-telegram", action="store_true", help="فحص مصادر GitHub فقط")
    ap.add_argument("--discover", action="store_true", help="تشغيل الاكتشاف المحكوم للمستودعات المرشّحة عبر GitHub API")
    ap.add_argument("--json-out", type=Path, help="حفظ التقرير الكامل بصيغة JSON")
    args = ap.parse_args(argv)

    channels = [] if args.no_telegram else collector.get_channels()
    gh_sources = collector.get_github_sources()

    with collector._build_session(pool_size=max(16, args.workers * 2)) as session:
        alive_ids, alive_hps, alive_origin = load_alive_identities(args.alive_file, session)

        tel = collector.collect_with_telemetry(
            channels=channels,
            github_sources=gh_sources,
            workers=args.workers,
            timeout=args.timeout,
        )
        overlap = tel.deduper.source_overlap_metrics()

        print(f"مرجع العُقد الحيّة: {alive_origin} ({len(alive_ids)} هوية، {len(alive_hps)} مضيف:منفذ)")
        print(f"إجمالي الخام: {len(tel.raw_uris)} | الفريد الصالح: {len(tel.unique_uris)} | المؤكّد من عدّة مصادر: {tel.deduper.summary.multi_source_corroborated}")

        print("\n═══ مصادر GitHub (مرتّبة حسب المطابقة الحيّة ثم الإضافة الحصرية) ═══")
        print(f"{'المصدر':<24} {'الحالة':<10} {'صالح':>7} {'فريد':>7} {'حصري':>7} {'تداخل%':>7} {'حيّ(EP)':>8}")
        print("─" * 76)

        gh_rows = []
        for name in gh_sources:
            rec = tel.health_registry.records.get(name)
            uris = tel.per_source_uris.get(name, [])
            hps = {(ident.host, ident.port) for u in uris if (ident := parse_identity(u))}
            alive_match = len(hps & alive_hps)
            m = overlap.get(name, {"unique_identities": 0, "exclusive_identities": 0, "overlap_ratio": 0.0})
            state = rec.state if rec else "unknown"
            valid_c = rec.valid_count if rec else 0
            gh_rows.append((name, state, valid_c, int(m["unique_identities"]), int(m["exclusive_identities"]), float(m["overlap_ratio"]) * 100.0, alive_match))

        gh_rows.sort(key=lambda r: (-r[6], -r[4], -r[3]))
        for name, state, valid_c, uniq_c, excl_c, ov_pct, alive_m in gh_rows:
            print(f"{name:<24} {state:<10} {valid_c:>7} {uniq_c:>7} {excl_c:>7} {ov_pct:>6.1f}% {alive_m:>8}")

        if channels:
            print(f"\n═══ قنوات تيليجرام (أفضل {args.top} من {len(channels)}) ═══")
            print(f"{'القناة':<28} {'صالح':>7} {'فريد':>7} {'حصري':>7} {'حيّ(EP)':>8}  الحالة")
            print("─" * 76)
            tg_rows = []
            for ch in channels:
                key = f"tg:{ch}"
                rec = tel.health_registry.records.get(key)
                uris = tel.per_source_uris.get(key, [])
                hps = {(ident.host, ident.port) for u in uris if (ident := parse_identity(u))}
                alive_match = len(hps & alive_hps)
                m = overlap.get(key, {"unique_identities": 0, "exclusive_identities": 0})
                tg_rows.append((
                    ch,
                    rec.valid_count if rec else 0,
                    int(m["unique_identities"]),
                    int(m["exclusive_identities"]),
                    alive_match,
                    rec.state if rec else "unknown",
                ))
            tg_rows.sort(key=lambda r: (-r[4], -r[3], -r[2]))
            for ch, vc, uc, ec, am, st in tg_rows[: args.top]:
                print(f"@{ch:<27} {vc:>7} {uc:>7} {ec:>7} {am:>8}  {st}")

        discovered = []
        if args.discover:
            existing_ids = set(tel.deduper.provenance_map().keys())
            discovered = discover_github_candidates(
                session,
                set(gh_sources.values()),
                existing_ids,
            )
            print(f"\n═══ نتائج الاكتشاف المحكوم للمرشّحين ({len(discovered)}) ═══")
            for item in discovered:
                print(
                    f"  {item['repo']:<32} decision={item['decision']:<24} "
                    f"excl={item['exclusive_identities']:>5} overlap={float(item['overlap_ratio'])*100:>5.1f}% "
                    f"license={item['license']}"
                )

    if args.json_out:
        tel.health_registry.save_public_report(args.json_out)
        if discovered:
            data = json.loads(args.json_out.read_text(encoding="utf-8"))
            data["candidate_discovery"] = discovered
            args.json_out.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"\nحُفظ تقرير الصحّة والتداخل في: {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
