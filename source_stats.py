#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""إحصاء سريع لمصادر الاشتراك: عدد الكانفيغات، العُقد الفريدة، ومزيج البروتوكولات.
لا يقيس السرعة (هذا يحتاج تمرير ترافيك حقيقي عبر العقدة بـ xray/sing-box)."""
from __future__ import annotations

import collections
import sys

import requests

import collector

SOURCES = collector.get_github_sources()


def main() -> int:
    for name, url in SOURCES.items():
        try:
            r = requests.get(url, headers=collector.HEADERS, timeout=40)
            r.raise_for_status()
            cfgs, _ = collector.clean(collector.parse_subscription(r.text))
        except Exception as exc:
            print(f"{name}: فشل — {exc}")
            continue
        mix = collections.Counter(c.split("://", 1)[0] for c in cfgs)
        hosts = {ep for c in cfgs if (ep := collector.endpoint_key(c))}
        print(f"{name:26} cfg={len(cfgs):>6}  unique_ep={len(hosts):>6}  {dict(mix.most_common(6))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
