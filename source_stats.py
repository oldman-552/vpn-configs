#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""إحصاء سريع لمصادر الاشتراك: عدد الكانفيغات، العُقد الفريدة، ومزيج البروتوكولات.
لا يقيس السرعة (هذا يحتاج تمرير ترافيك حقيقي عبر العقدة بـ xray/sing-box)."""
import base64, collections, json, sys
from urllib.parse import urlparse
import requests

SOURCES = {
    "SoliSpirit/v2ray-configs": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
    "MatinGhanbari/v2ray-configs": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
    "ALIILAPRO/v2rayNG-Config": "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
    "ermaozi/get_subscribe": "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "barry-far/V2ray-Config": "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub1.txt",
    "mahdibland/V2RayAggregator": "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity",
    "roosterkid/openproxylist": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "Pawdroid/Free-servers": "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
}

def decode(t):
    ls = [l.strip() for l in t.splitlines() if "://" in l]
    if ls: return ls
    try:
        return [l.strip() for l in base64.b64decode(t + "=" * (-len(t) % 4)).decode("utf-8","ignore").splitlines() if "://" in l]
    except Exception:
        return []

for name, url in SOURCES.items():
    try:
        r = requests.get(url, timeout=40)
        cfgs = decode(r.text)
    except Exception as e:
        print(f"{name}: فشل — {e}"); continue
    mix = collections.Counter(c.split("://")[0] for c in cfgs)
    hosts = set()
    for c in cfgs:
        s, _, rest = c.partition("://")
        if s == "vmess":
            try:
                j = json.loads(base64.b64decode(rest.split("#")[0] + "=" * (-len(rest.split('#')[0]) % 4)))
                hosts.add(f"{j.get('add')}:{j.get('port')}")
            except Exception: pass
        elif "@" in rest:
            hosts.add(rest.split("#")[0].rsplit("@",1)[-1].split("/")[0].split("?")[0])
    print(f"{name:34} cfg={len(cfgs):>6}  unique_ep={len(hosts):>6}  {dict(mix.most_common(6))}")
