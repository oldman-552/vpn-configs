#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
server/sync_community_rankings.py — Pulls anonymized verified community test reports from
the Free-Tier Cloudflare Worker (`COMMUNITY_WORKER_URL` + `COMMUNITY_EXPORT_TOKEN`),
merges them with longitudinal `@data/state/community_reports.json` (retaining 72h window),
and publishes `iran-top500.json`, `iran-top500.txt`, `iran-results.json`, plus country
rankings (`germany/france/turkey/russia-top500.json`).

Works safely even when `COMMUNITY_WORKER_URL` is not yet configured (re-evaluates existing
state cleanly without failing or fabricating servers).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from community_ranking import DEFAULT_MAX_AGE_HOURS, export_community_country_datasets  # noqa: E402


def _load_json_safe(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def fetch_incremental_worker_reports(
    worker_url: str,
    export_token: str,
    after_id: int = 0,
    max_pages: int = 10,
) -> tuple[list[dict[str, Any]], int]:
    base = worker_url.strip().rstrip("/")
    if not base or not export_token.strip():
        return [], after_id
    if not base.startswith("https://") and not base.startswith("http://127.0.0.1:"):
        raise ValueError("Worker URL must use HTTPS")

    collected: list[dict[str, Any]] = []
    cursor = max(0, int(after_id))
    for _ in range(max_pages):
        req_url = f"{base}/v1/export?after_id={cursor}&limit=1000"
        req = urllib.request.Request(
            req_url,
            headers={
                "Authorization": f"Bearer {export_token.strip()}",
                "Accept": "application/json",
                "User-Agent": "bahrain-vpn-aggregator/1.0",
            },
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            if resp.status != 200:
                break
            payload = json.loads(resp.read().decode("utf-8"))
        batch = payload.get("reports") or []
        if not isinstance(batch, list) or not batch:
            break
        collected.extend(r for r in batch if isinstance(r, dict))
        next_cursor = int(payload.get("next_after_id") or cursor)
        if next_cursor <= cursor:
            break
        cursor = next_cursor
        if len(batch) < 1000:
            break
    return collected, cursor


def sync_and_export(
    data_dir: Path,
    *,
    prev_dir: Path | None = None,
    worker_url: str = "",
    export_token: str = "",
    now_epoch: int | None = None,
) -> dict[str, int]:
    now_s = int(now_epoch if now_epoch is not None else datetime.now(timezone.utc).timestamp())
    cutoff_s = now_s - int(DEFAULT_MAX_AGE_HOURS * 3600)

    state_src = (
        prev_dir / "state" / "community_reports.json"
        if prev_dir and (prev_dir / "state" / "community_reports.json").is_file()
        else data_dir / "state" / "community_reports.json"
    )
    prev_state = _load_json_safe(state_src, {"last_worker_id": 0, "reports": []})
    last_id = int(prev_state.get("last_worker_id") or 0)
    existing_reports = prev_state.get("reports") if isinstance(prev_state.get("reports"), list) else []

    fetched: list[dict[str, Any]] = []
    if worker_url.strip() and export_token.strip():
        try:
            fetched, last_id = fetch_incremental_worker_reports(worker_url, export_token, after_id=last_id)
        except Exception as exc:
            print(f"::warning::Community worker fetch skipped ({exc.__class__.__name__}); preserving existing state.")

    deduped_by_id: dict[str, dict[str, Any]] = {}
    for item in [*existing_reports, *fetched]:
        if not isinstance(item, dict):
            continue
        rid = str(item.get("report_id") or "").strip().lower()
        ts = int(item.get("tested_at_epoch") or item.get("received_at_epoch") or 0)
        if not rid or ts < cutoff_s:
            continue
        # Never store raw URIs or credential strings in state
        if "://" in json.dumps(item, ensure_ascii=False):
            continue
        deduped_by_id[rid] = item

    kept_reports = list(deduped_by_id.values())[-25_000:]

    state_out = data_dir / "state" / "community_reports.json"
    state_out.parent.mkdir(parents=True, exist_ok=True)
    state_out.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "updated_at_epoch": now_s,
                "last_worker_id": last_id,
                "reports": kept_reports,
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    # Load validated public server catalog from alive.json + top500.json
    catalog: list[dict[str, Any]] = []
    for candidate_file in (data_dir / "top500.json", data_dir / "alive.json"):
        doc = _load_json_safe(candidate_file, {})
        if isinstance(doc, dict) and isinstance(doc.get("servers"), list):
            catalog.extend(s for s in doc["servers"] if isinstance(s, dict))

    return export_community_country_datasets(
        out_dir=data_dir,
        catalog_servers=catalog,
        reports=kept_reports,
        generated_at_epoch=now_s,
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Aggregate verified community VPN test results into @data country feeds")
    ap.add_argument("--data-dir", type=Path, required=True)
    ap.add_argument("--prev-dir", type=Path, default=None)
    args = ap.parse_args(argv)

    counts = sync_and_export(
        data_dir=args.data_dir,
        prev_dir=args.prev_dir,
        worker_url=os.environ.get("COMMUNITY_WORKER_URL", ""),
        export_token=os.environ.get("COMMUNITY_EXPORT_TOKEN", ""),
    )
    print(f"Community country rankings updated: {counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
