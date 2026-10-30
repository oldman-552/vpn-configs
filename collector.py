#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
collector.py — جامع كانفيغات VPN محصّن أمنيًا من قنوات تلغرام ومستودعات GitHub المُدقَّقة.

المزايا المعمارية والأمنية:
  1) حماية SSRF وفحص عناوين IP الخاصة والـ Redirects وحدود حجم الاستجابة (Streaming Bounds).
  2) دعم التخزين المؤقت الشرطي (ETag / If-Modified-Since) وسجل صحّة المصادر ودورة حياتها.
  3) إزالة تكرار خماسية الطبقات (5-Layer Deduplication) مع تتبّع المصدر (Provenance) دون كشف الأسرار.
  4) تنظيف الكيانات النصية (&amp;) والمحارف الخفية (ZWNJ/RLM) وعلامات الترقيم الزائدة.
  5) حجب بيانات الاعتماد (UUIDs / كلمات المرور) بالكامل من السجلات والتقارير.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import collections
import hashlib
import html as html_lib
import json
import logging
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
from zoneinfo import ZoneInfo

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from dedupe import (
    MultiLayerDeduplicator,
    canonical_protocol,
    parse_identity,
)
from pipeline_security import (
    MAX_DECODED_BYTES,
    MAX_FEED_BYTES,
    MAX_FEED_LINES,
    MAX_URI_LENGTH,
    redact_uri,
    safe_fetch_text,
)
from scoring import SourceHealthRecord, SourceHealthRegistry
from security_intelligence import assess_configuration_security

try:
    import jdatetime
except ImportError:
    jdatetime = None

ROOT_DIR = Path(__file__).resolve().parent
DEFAULT_CHANNELS_FILE = ROOT_DIR / "channels.txt"
DEFAULT_SOURCES_FILE = ROOT_DIR / "github_sources.txt"

TZ = ZoneInfo("Asia/Tehran")
LOG = logging.getLogger("collector")
APP_REMARK_PREFIX = "bahrain-vpn"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)
HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept-Language": "en-US,en;q=0.9,fa;q=0.8",
}

# البروتوكولات الأطول أولًا حتى لا تلتقط "ss" جزءًا من "vless" أو "vmess"
SCHEMES = ("hysteria2", "vless", "vmess", "trojan", "hy2", "tuic", "ssr", "ss")
PROTOCOLS = SCHEMES
CONFIG_RE = re.compile(r"(?:%s)://[^\s<>\"'`]+" % "|".join(SCHEMES), re.IGNORECASE)
FRAGMENT_RE = re.compile(r"#.*$")
INVISIBLE_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]+")

VERIFIED_TIER_SOURCES = frozenset({
    "matin-super",
    "4n0nymou3-verified",
    "au1rxx-verified",
    "mahdibland-eternity",
    "ermaozi-reachable",
    "mahdi0024-tested",
    "delta-kronecker",
    "igareck-rus-vless",
    "igareck-rus-all",
    "itsyebekhe-psg",
    "openproxylist",
})

CHANNELS = [
    "IR_Predators", "DailyV2RY", "oneclickvpnkeys", "i10VPN", "Velinamusic", "FNetPro",
    "confegraigan", "zedmodeonvpn", "V2ray_Vpn_Speed", "lightning6", "Parsashonam",
    "XpnTeam", "nexvpn_server", "AzarAndoozVPN", "v2ray_configs_pool", "v2rayNGcloud",
    "ZibaNabz", "FreakConfig", "V_2rey", "V2ray_Alpha", "PROXY_MTM", "SiNABiGO",
    "v2rayng12023", "vlessconfig", "piazshekan", "Free_Internet_Iran", "ARv2ray",
    "VPNCUSTOMIZE", "UnlimitedDev", "MARAMBASHI", "PrivateVPNs", "client_proo",
    "nufilter", "icv2ray", "Vpn_Mikey", "v2rayngvpn", "kingspeedchanel", "VPN_Xpace",
    "SVNTEAM", "WPSNET", "v2rayng_fa2", "Hope_Net", "ServerNett",
]

GITHUB_SOURCES = {
    "matin-super": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/subs/merged/super-sub.txt",
    "4n0nymou3-verified": "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/main/configs/proxy_configs_tested.txt",
    "mahdibland-eternity": "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity",
    "ermaozi-reachable": "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/reachable/v2ray.txt",
    "mahdi0024-tested": "https://raw.githubusercontent.com/Mahdi0024/ProxyCollector/master/sub/proxies.txt",
    "delta-kronecker": "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/all_configs.txt",
    "solispirit-all": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
    "0xradikal-all": "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/configs.txt",
    "barabama-freenodes": "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/merged.txt",
    "matin-all": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
    "leon406-vless": "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/vless",
    "leon406-hysteria2": "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/hysteria2",
    "leon406-mixed": "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/a11",
    "openproxylist": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
}

_local = threading.local()


def _build_session(pool_size: int = 32) -> requests.Session:
    s = requests.Session()
    s.headers.update(HEADERS)
    retry = Retry(
        total=2,
        connect=2,
        read=2,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET", "HEAD"}),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=max(16, pool_size),
        pool_maxsize=max(32, pool_size * 2),
    )
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s


def session() -> requests.Session:
    """إرجاع Session خاص بالـ thread الحالي مع تجميع اتصالات HTTP."""
    if not hasattr(_local, "s"):
        _local.s = _build_session(16)
    return _local.s


# ───────────────────────────── أدوات مساعدة للمصادر ─────────────────────────────
def channel_urls(raw: list[str]) -> list[str]:
    """
    تنقية أسماء القنوات وحذف المكرّر غير الحساس لحالة الأحرف.
    تقبل: "Name" أو "@Name" أو "https://t.me/s/Name" أو "https://t.me/Name".
    """
    seen: dict[str, str] = {}
    for item in raw:
        stripped = item.strip()
        if not stripped or stripped.startswith("#"):
            continue
        cleaned = stripped.split("?", 1)[0].split("#", 1)[0].rstrip("/")
        name = cleaned.split("/")[-1] or stripped
        name = name.removeprefix("@")
        if not re.fullmatch(r"[A-Za-z0-9_]{4,64}", name):
            LOG.warning("اسم مستخدم غير صالح، تم تجاهله: %r", item)
            continue
        seen.setdefault(name.lower(), f"https://t.me/s/{name}")
    return list(seen.values())


def get_channels(path: str | Path | None = None) -> list[str]:
    """قراءة قائمة القنوات من المسار المحدّد، أو من channels.txt إن وُجد، وإلا فالقائمة المدمجة."""
    target = Path(path) if path else (DEFAULT_CHANNELS_FILE if DEFAULT_CHANNELS_FILE.exists() else None)
    if target and target.exists():
        lines = [
            ln.strip()
            for ln in target.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        if lines:
            return lines
    return list(CHANNELS)


def load_sources_file(path: str | Path) -> dict[str, str]:
    """قراءة قائمة مصادر مخصّصة مع منع تكرار نفس الرابط."""
    sources: dict[str, str] = {}
    seen_urls: set[str] = set()
    for i, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[-1].startswith(("https://", "http://")):
            name, url = " ".join(parts[:-1]), parts[-1]
        elif line.startswith(("https://", "http://")):
            name, url = f"custom-{i}", line
        else:
            LOG.warning("سطر غير مفهوم في %s: %r", path, line)
            continue
        norm = url.rstrip("/")
        if norm in seen_urls:
            LOG.warning("تخطّي رابط مكرّر في %s: %s", path, name)
            continue
        seen_urls.add(norm)
        sources[name] = url
    return sources


def get_github_sources(path: str | Path | None = None) -> dict[str, str]:
    """قراءة مصادر GitHub من المسار المحدّد، أو من github_sources.txt إن وُجد، وإلا فالقائمة المدمجة."""
    target = Path(path) if path else (DEFAULT_SOURCES_FILE if DEFAULT_SOURCES_FILE.exists() else None)
    if target and target.exists():
        loaded = load_sources_file(target)
        if loaded:
            return loaded
    return dict(GITHUB_SOURCES)


# ───────────────────────────── الجلب المحصّن وفكّ الترميز ─────────────────────────────
def fetch_text(url: str, retries: int = 2, timeout: tuple[int, int] | float = (5, 25)) -> str | None:
    """
    جلب نص (HTML أو ملف اشتراك) مع حماية SSRF وحدّ أقصى لحجم الاستجابة.
    يُرجع النص أو None عند الفشل.
    """
    eff_timeout = timeout[1] if isinstance(timeout, tuple) else float(timeout)
    for attempt in range(1, max(1, retries) + 1):
        res = safe_fetch_text(
            session(),
            url,
            timeout=eff_timeout,
            max_bytes=MAX_FEED_BYTES,
        )
        if res.ok:
            return res.text
        if res.status_code in (429, 500, 502, 503, 504) and attempt < retries:
            time.sleep(min(10, 1.5 * attempt))
            continue
        if res.error.startswith("ssrf_blocked"):
            LOG.warning("حُجب رابط غير آمن (SSRF): %s", res.error)
            return None
        LOG.debug("%s -> فشل (%s)", url, res.error)
        return None
    return None


def b64_decode(text: str) -> str | None:
    """فكّ base64 القياسي أو URL-safe مع تصحيح الحشو وحدّ الحجم الآمن."""
    if not text or len(text) > MAX_DECODED_BYTES:
        return None
    compact = re.sub(r"\s+", "", text)
    if not compact or len(compact) > MAX_DECODED_BYTES:
        return None
    normalized = compact.replace("-", "+").replace("_", "/")
    padded = normalized + "=" * (-len(normalized) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        try:
            raw = base64.b64decode(padded)
        except (binascii.Error, ValueError):
            return None
    if len(raw) > MAX_DECODED_BYTES:
        return None
    return raw.decode("utf-8", "ignore")


def _extract_bounded(text: str) -> list[str]:
    if not text:
        return []
    if len(text) > MAX_DECODED_BYTES:
        text = text[:MAX_DECODED_BYTES]
    out: list[str] = []
    for m in CONFIG_RE.finditer(text):
        u = m.group(0)
        if len(u) <= MAX_URI_LENGTH:
            out.append(u)
            if len(out) >= MAX_FEED_LINES:
                break
    return out


def parse_subscription(text: str) -> list[str]:
    """
    استخراج الكانفيغات من ملف اشتراك (نص خام، أو Base64 كلّي، أو مقاطع Base64 سطرية)
    مع حدود صارمة لحجم الذاكرة وعدد الأسطر.
    """
    if not text:
        return []
    if len(text) > MAX_DECODED_BYTES:
        text = text[:MAX_DECODED_BYTES]

    unescaped = html_lib.unescape(text)
    found = _extract_bounded(unescaped)
    if found:
        return found

    decoded = b64_decode(text)
    if decoded and "://" in decoded:
        return _extract_bounded(html_lib.unescape(decoded))

    line_results: list[str] = []
    for idx, line in enumerate(text.splitlines()):
        if idx >= MAX_FEED_LINES:
            break
        dec_ln = b64_decode(line)
        if dec_ln and "://" in dec_ln:
            line_results.extend(_extract_bounded(html_lib.unescape(dec_ln)))
            if len(line_results) >= MAX_FEED_LINES:
                break
    return line_results


def extract_configs(html: str) -> list[str]:
    """استخراج كل الكانفيغات من صفحة قناة تلغرام (النص + فواصل الأسطر + الروابط + مقاطع الكود)."""
    if not html:
        return []
    if len(html) > MAX_DECODED_BYTES:
        html = html[:MAX_DECODED_BYTES]
    soup = BeautifulSoup(html, "html.parser")
    blocks = soup.select("div.tgme_widget_message_text")
    if not blocks:
        blocks = [soup]

    found: list[str] = []
    for block in blocks:
        found.extend(_extract_bounded(html_lib.unescape(block.get_text("\n"))))
        for a in block.find_all("a", href=True):
            found.extend(_extract_bounded(html_lib.unescape(a["href"])))
    return found


extract_from_html = extract_configs


# ───────────────────────────── التطبيع وإزالة التكرار خماسية الطبقات ─────────────────────────────
def _strip_trailing_junk(cfg: str) -> str:
    cfg = cfg.rstrip(",.;")
    while cfg.endswith(")") and "(" not in cfg:
        cfg = cfg[:-1]
    while cfg.endswith("]") and "[" not in cfg:
        cfg = cfg[:-1]
    return cfg


def _sanitize_raw_uri(raw: str) -> str:
    unescaped = html_lib.unescape(raw)
    unescaped = INVISIBLE_RE.sub("", unescaped).strip()
    cfg = FRAGMENT_RE.sub("", unescaped).strip()
    cfg = _strip_trailing_junk(cfg)
    if "://" in cfg:
        scheme, _, rest = cfg.partition("://")
        cfg = f"{scheme.lower()}://{rest}"
    return cfg


def validate_config(cfg: str) -> bool:
    """فحص بنيوي وأمني للتأكّد من صلاحية الرابط وخلوّه من عناوين الشبكات الداخلية."""
    if not cfg or len(cfg) > MAX_URI_LENGTH:
        return False
    sanitized = _sanitize_raw_uri(cfg)
    return parse_identity(sanitized, reject_private_hosts=True) is not None


def endpoint_key(cfg: str) -> str | None:
    """مفتاح «host:port» لكانفيغ (متوافق رجعيًا مع --unique-endpoint والاختبارات)."""
    ident = parse_identity(_sanitize_raw_uri(cfg), reject_private_hosts=False)
    if ident is None:
        return None
    if ":" in ident.host:
        return f"[{ident.host}]:{ident.port}"
    return f"{ident.host}:{ident.port}"


def clean(configs: list[str]) -> tuple[list[str], int]:
    """
    تنظيف وتطبيع + حذف المكرّر عبر الطبقات المعيارية (Layer-1 + Layer-2)
    واستبعاد الروابط المشوّهة أو الموجّهة إلى شبكات محلية/خاصة.
    يُرجع (قائمة نظيفة فريدة، عدد المرفوض).
    """
    sanitized_list = [_sanitize_raw_uri(raw) for raw in configs]
    deduper = MultiLayerDeduplicator(reject_private_hosts=True)
    deduper.ingest_source("clean", sanitized_list)
    return deduper.unique_uris(), deduper.summary.invalid_or_unsafe_rejected


def dedupe_by_endpoint(configs: list[str]) -> tuple[list[str], int]:
    """إبقاء أول كانفيغ لكل host:port."""
    out: list[str] = []
    used: set[str] = set()
    for cfg in configs:
        key = endpoint_key(cfg) or cfg
        if key in used:
            continue
        used.add(key)
        out.append(cfg)
    return out, len(configs) - len(out)


# ───────────────────────────── الأختام الزمنية وتسمية bahrain-vpn ─────────────────────────────
def stamp(calendar: str) -> tuple[str, str]:
    """يُرجع (ختم الوقت الكامل، التاريخ فقط) مع بديل ميلادي عند غياب jdatetime."""
    now = datetime.now(TZ)
    if calendar == "jalali":
        if jdatetime is not None:
            j = jdatetime.datetime.fromgregorian(datetime=now)
            return j.strftime("%b-%d | %H:%M"), j.strftime("%b-%d")
        LOG.warning("jdatetime غير مثبّت؛ استخدام التقويم الميلادي بدلًا منه.")
    return now.strftime("%b-%d | %H:%M"), now.strftime("%b-%d")


def set_uri_remark(cfg: str, label: str) -> str:
    """
    تعيين الاسم الظاهر للمستخدم (مثل 'bahrain-vpn 1 | 45ms') بطريقة متوافقة مع كل البروتوكولات:
      • vmess:// → تعديل حقل "ps" داخل JSON المرمّز بـ base64 دون إلحاق #fragment.
      • ssr://   → تعديل معامل remarks داخل حمولة SSR المرمّزة بـ base64url دون إلحاق #fragment.
      • البقية  → إزالة أي #fragment سابق وإلحاق #{label}.
    """
    base = FRAGMENT_RE.sub("", cfg).strip()
    scheme, sep, body = base.partition("://")
    if not sep:
        return cfg
    scheme_l = scheme.lower()

    if scheme_l == "vmess":
        raw = b64_decode(body)
        if raw:
            try:
                j = json.loads(raw)
                if isinstance(j, dict):
                    j["ps"] = label
                    encoded = base64.b64encode(
                        json.dumps(j, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                    ).decode("ascii")
                    return f"vmess://{encoded}"
            except Exception:
                pass
        return base

    if scheme_l == "ssr":
        raw = b64_decode(body)
        if raw and "/?" in raw:
            main_part, q_part = raw.split("/?", 1)
            b64_label = base64.urlsafe_b64encode(label.encode("utf-8")).decode("ascii").rstrip("=")
            params = [p for p in q_part.split("&") if p and not p.startswith("remarks=")]
            params.append(f"remarks={b64_label}")
            rebuilt = f"{main_part}/?{'&'.join(params)}"
            encoded = base64.urlsafe_b64encode(rebuilt.encode("utf-8")).decode("ascii").rstrip("=")
            return f"ssr://{encoded}"
        return base

    return f"{base}#{label}"


def relabel_configs(
    configs: list[str],
    prefix: str = APP_REMARK_PREFIX,
    stats: dict[str, tuple[float, float]] | None = None,
    countries: dict[str, str] | None = None,
) -> list[str]:
    """تسمية قائمة كانفيغات باسم موحّد مع خيار إرفاق الدولة والسرعة والتأخير."""
    out: list[str] = []
    for idx, uri in enumerate(configs, 1):
        parts = [f"{prefix} {idx}"]
        if countries and uri in countries and countries[uri]:
            parts.append(countries[uri])
        if stats and uri in stats:
            lat_ms, spd_kbps = stats[uri]
            if lat_ms > 0:
                parts.append(f"{lat_ms:.0f}ms")
            if spd_kbps >= 1024:
                parts.append(f"{spd_kbps / 1024:.1f}MB/s")
            elif spd_kbps > 0:
                parts.append(f"{spd_kbps:.0f}KB/s")
        label = " | ".join(parts)
        if uri.lower().startswith(("vmess://", "ssr://")):
            out.append(set_uri_remark(uri, label))
        else:
            base = FRAGMENT_RE.sub("", uri).strip()
            out.append(f"{base}#{quote(label, safe=' |.-_:')}")
    return out


def write_outputs(
    configs: list[str],
    out_path: Path,
    calendar: str = "jalali",
    header_note: str = "تحديث كل نصف ساعة",
    tag: str = APP_REMARK_PREFIX,
) -> None:
    """بناء الأسطر باسم موحّد وكتابة الملف بشكل ذرّي."""
    full_ts, date_only = stamp(calendar)
    lines = []
    for i, cfg in enumerate(configs, 1):
        if i == 1:
            label = f"{tag} {i} | {full_ts} | {header_note}"
        else:
            label = f"{tag} {i} | {date_only}"
        lines.append(set_uri_remark(cfg, label))

    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_name(out_path.name + ".tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    tmp.replace(out_path)


def write_best(results, out_path: Path, limit: int, calendar: str, tag: str) -> int:
    """كتابة أفضل N كانفيغ في ملف منفصل باسم موحّد مع السرعة والتأخير."""
    _, date_only = stamp(calendar)
    lines = []
    for i, r in enumerate(results[:limit], 1):
        speed = f"{r.speed_kbps:.0f}KB/s" if r.speed_kbps > 0 else "—"
        label = f"{tag} {i} | {r.latency_ms:.0f}ms | {speed} | {date_only}"
        lines.append(set_uri_remark(r.cfg, label))

    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_name(out_path.name + ".tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    tmp.replace(out_path)
    return len(lines)


# ───────────────────────────── الجلب المتوازي وسجل الصحّة ─────────────────────────────
def fetch_channel(
    sess: requests.Session,
    channel: str,
    timeout: int = 15,
) -> tuple[str, list[str], str | None]:
    handle = channel.strip().lstrip("@").split("/")[-1]
    if not re.fullmatch(r"[A-Za-z0-9_]{4,64}", handle):
        return handle, [], "invalid_channel_handle"
    res = safe_fetch_text(sess, f"https://t.me/s/{handle}", timeout=timeout, max_bytes=MAX_FEED_BYTES, require_https=True)
    if not res.ok:
        return handle, [], res.error or f"http_{res.status_code}"
    return handle, extract_configs(res.text), None


def fetch_github_source(
    sess: requests.Session,
    name: str,
    url: str,
    timeout: int = 25,
) -> tuple[str, list[str], str | None]:
    res = safe_fetch_text(sess, url, timeout=timeout, max_bytes=MAX_FEED_BYTES)
    if not res.ok:
        return name, [], res.error or f"http_{res.status_code}"
    return name, parse_subscription(res.text), None


def collect_telegram(urls: list[str], workers: int) -> tuple[list[str], int, int]:
    """جلب صفحات القنوات بالتوازي. يُرجع (قائمة كانفيغات، نجحت، فشلت)."""
    ordered_pages: dict[str, str] = {}
    ok = failed = 0

    def job(u: str) -> tuple[str, str | None]:
        return u, fetch_text(u, timeout=(5, 15))

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(job, u) for u in urls]
        for fut in as_completed(futures):
            u, html_doc = fut.result()
            if html_doc:
                ordered_pages[u] = html_doc
                ok += 1
            else:
                failed += 1

    cfgs = [c for u in urls if u in ordered_pages for c in extract_configs(ordered_pages[u])]
    return cfgs, ok, failed


def collect_github(
    sources: dict[str, str],
    workers: int,
    max_per_source: int = 0,
) -> tuple[list[str], list[tuple[str, int]]]:
    """جلب ملفات الاشتراك من GitHub بالتوازي مع الحفاظ على ترتيب أولوية المصادر."""
    results: dict[str, list[str]] = {}

    def job(item: tuple[str, str]) -> tuple[str, list[str]]:
        name, url = item
        text = fetch_text(url, timeout=(10, 45))
        if not text:
            return name, []
        cfgs = parse_subscription(text)
        if max_per_source:
            cfgs = cfgs[:max_per_source]
        return name, cfgs

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(job, it) for it in sources.items()]
        for fut in as_completed(futures):
            name, cfgs = fut.result()
            results[name] = cfgs

    ordered = [(name, results.get(name, [])) for name in sources]
    flat = [c for _, cfgs in ordered for c in cfgs]
    return flat, [(name, len(cfgs)) for name, cfgs in ordered]


@dataclass
class CollectionTelemetry:
    raw_uris: list[str]
    unique_uris: list[str]
    channel_stats: dict[str, int]
    deduper: MultiLayerDeduplicator
    health_registry: SourceHealthRegistry
    github_fetched_ok: int = 0
    github_skipped_cooldown: int = 0
    channels_ok: int = 0
    channels_failed: int = 0
    per_source_uris: dict[str, list[str]] = field(default_factory=dict)


def collect_with_telemetry(
    channels: list[str],
    github_sources: dict[str, str],
    workers: int = 12,
    timeout: int = 15,
    health_registry: SourceHealthRegistry | None = None,
) -> CollectionTelemetry:
    """جمع متزامن محصّن مع تتبّع الصحّة وإزالة التكرار خماسية الطبقات وتتبّع المصدر."""
    registry = health_registry or SourceHealthRegistry()
    deduper = MultiLayerDeduplicator(
        verified_sources=set(VERIFIED_TIER_SOURCES),
        reject_private_hosts=True,
    )
    raw_pool: list[str] = []
    ch_stats: dict[str, int] = {}
    per_source_uris: dict[str, list[str]] = {}
    gh_results: dict[str, list[str]] = {}
    ch_results: dict[str, list[str]] = {}
    gh_ok = 0
    gh_skipped = 0
    ch_ok = 0
    ch_failed = 0
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Normalize channel handles preserving order
    clean_handles: list[str] = []
    for u in channel_urls(channels):
        clean_handles.append(u.rsplit("/", 1)[-1])

    with _build_session(pool_size=max(16, workers * 2)) as sess:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            gh_futs = {}
            for name, url in github_sources.items():
                rec = registry.get_or_create(name, "github", url)
                if rec.should_skip_cooldown():
                    rec.total_runs += 1
                    gh_skipped += 1
                    continue
                fut = pool.submit(
                    safe_fetch_text,
                    sess,
                    url,
                    timeout=max(timeout, 25),
                    max_bytes=MAX_FEED_BYTES,
                    require_https=True,
                    etag=rec.etag,
                    last_modified=rec.last_modified,
                )
                gh_futs[fut] = (name, rec)

            ch_futs = {}
            for ch in clean_handles:
                rec = registry.get_or_create(f"tg:{ch}", "telegram", ch)
                if rec.should_skip_cooldown():
                    rec.total_runs += 1
                    ch_stats[ch] = -1
                    ch_failed += 1
                    continue
                fut = pool.submit(fetch_channel, sess, ch, timeout)
                ch_futs[fut] = (ch, rec)

            gh_meta: dict[str, tuple[SourceHealthRecord, object, list[str], str]] = {}
            for fut in as_completed(gh_futs):
                name, rec = gh_futs[fut]
                res = fut.result()
                if not res.ok:
                    rec.update_from_fetch(
                        fetch_ok=False,
                        status_code=res.status_code,
                        error=res.error,
                        timestamp=now_iso,
                    )
                    LOG.warning("[github:%s] فشل: %s (state=%s)", name, res.error, rec.state)
                    gh_results[name] = []
                    continue
                if res.not_modified:
                    rec.update_from_fetch(
                        fetch_ok=True,
                        status_code=res.status_code,
                        not_modified=True,
                        etag=res.etag,
                        last_modified=res.last_modified,
                        timestamp=now_iso,
                    )
                    gh_ok += 1
                    gh_results[name] = []
                    continue
                body_hash = hashlib.sha256(res.text.encode("utf-8", "ignore")).hexdigest()
                uris = [_sanitize_raw_uri(u) for u in parse_subscription(res.text)]
                gh_results[name] = uris
                gh_meta[name] = (rec, res, uris, body_hash)

            ch_meta: dict[str, tuple[SourceHealthRecord, list[str], str]] = {}
            for fut in as_completed(ch_futs):
                ch, rec = ch_futs[fut]
                _h, raw_u, err = fut.result()
                if err:
                    ch_stats[ch] = -1
                    ch_failed += 1
                    rec.update_from_fetch(fetch_ok=False, error=err, timestamp=now_iso)
                    ch_results[ch] = []
                else:
                    uris = [_sanitize_raw_uri(u) for u in raw_u]
                    body_hash = hashlib.sha256("\n".join(uris).encode("utf-8", "ignore")).hexdigest()
                    ch_stats[ch] = len(uris)
                    ch_ok += 1
                    ch_results[ch] = uris
                    ch_meta[ch] = (rec, uris, body_hash)

    def _audit_source_batch(uris: list[str]) -> tuple[int, int]:
        """Count invalid and suspicious/quarantinable URIs in a source batch."""
        invalid_c = 0
        suspicious_c = 0
        for u in uris:
            ident = parse_identity(u, reject_private_hosts=True)
            if ident is None:
                invalid_c += 1
                suspicious_c += 1
                continue
            rep = assess_configuration_security(u)
            if rep.quarantined or rep.risk_level in ("HIGH", "CRITICAL"):
                suspicious_c += 1
        return invalid_c, suspicious_c

    # Ingest in deterministic priority order: Tier-ordered GitHub sources first, then Telegram channels
    for name in github_sources:
        uris = gh_results.get(name, [])
        if name in gh_meta:
            rec, res, _, body_hash = gh_meta[name]
            inv_cnt, susp_cnt = _audit_source_batch(uris)
            valid_est = max(0, len(uris) - inv_cnt)
            rec.update_from_fetch(
                fetch_ok=True,
                status_code=res.status_code,
                etag=res.etag,
                last_modified=res.last_modified,
                raw_count=len(uris),
                valid_count=valid_est,
                invalid_configs=inv_cnt,
                suspicious_configs=susp_cnt,
                content_sha256=body_hash,
                timestamp=now_iso,
            )
            if rec.state == "quarantined":
                LOG.warning("[github:%s] QUARANTINED source skipped (%s)", name, rec.quarantine_reason)
                continue
            valid_cnt, new_cnt = deduper.ingest_source(name, uris)
            rec.valid_count = valid_cnt
            rec.new_configs = new_cnt
            rec.duplicate_configs = max(0, valid_cnt - new_cnt)
            if uris:
                raw_pool.extend(uris)
                per_source_uris[name] = uris
            if valid_cnt > 0:
                gh_ok += 1
        elif uris:
            raw_pool.extend(uris)
            per_source_uris[name] = uris
            deduper.ingest_source(name, uris)

    for ch in clean_handles:
        uris = ch_results.get(ch, [])
        key = f"tg:{ch}"
        if ch in ch_meta:
            rec, _, body_hash = ch_meta[ch]
            inv_cnt, susp_cnt = _audit_source_batch(uris)
            valid_est = max(0, len(uris) - inv_cnt)
            rec.update_from_fetch(
                fetch_ok=True,
                status_code=200,
                raw_count=len(uris),
                valid_count=valid_est,
                invalid_configs=inv_cnt,
                suspicious_configs=susp_cnt,
                content_sha256=body_hash,
                timestamp=now_iso,
            )
            if rec.state == "quarantined":
                LOG.warning("[telegram:%s] QUARANTINED channel skipped (%s)", ch, rec.quarantine_reason)
                continue
            valid_cnt, new_cnt = deduper.ingest_source(key, uris)
            rec.valid_count = valid_cnt
            rec.new_configs = new_cnt
            rec.duplicate_configs = max(0, valid_cnt - new_cnt)
            if uris:
                raw_pool.extend(uris)
                per_source_uris[key] = uris
        elif uris:
            raw_pool.extend(uris)
            per_source_uris[key] = uris
            deduper.ingest_source(key, uris)

    overlap_map = deduper.source_overlap_metrics()
    for src_name, metrics in overlap_map.items():
        if src_name in registry.records:
            r = registry.records[src_name]
            r.unique_identities = int(metrics["unique_identities"])
            r.exclusive_identities = int(metrics["exclusive_identities"])
            r.overlap_ratio = float(metrics["overlap_ratio"])

    return CollectionTelemetry(
        raw_uris=raw_pool,
        unique_uris=deduper.unique_uris(),
        channel_stats=ch_stats,
        deduper=deduper,
        health_registry=registry,
        github_fetched_ok=gh_ok,
        github_skipped_cooldown=gh_skipped,
        channels_ok=ch_ok,
        channels_failed=ch_failed,
        per_source_uris=per_source_uris,
    )


# ───────────────────────────── البرنامج الرئيسي ─────────────────────────────
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="جمع كانفيغات VPN من قنوات تلغرام ومستودعات GitHub في ملف واحد"
    )
    ap.add_argument("-o", "--out", default="config.txt", help="ملف الخروج")
    ap.add_argument("-w", "--workers", type=int, default=12, help="عدد الطلبات المتوازية")
    ap.add_argument("--telegram", dest="telegram", action="store_true", default=True)
    ap.add_argument("--no-telegram", dest="telegram", action="store_false")
    ap.add_argument("--github", dest="github", action="store_true", default=True)
    ap.add_argument("--no-github", dest="github", action="store_false")
    ap.add_argument("--channels", help="ملف نصي: اسم قناة أو رابط في كل سطر")
    ap.add_argument("--sources-file", help="ملف مصادر مخصّص: «اسم URL» في كل سطر")
    ap.add_argument("--max-per-source", type=int, default=0)
    ap.add_argument("--unique-endpoint", action="store_true")
    ap.add_argument("--calendar", choices=("jalali", "gregorian"), default="jalali")
    ap.add_argument("--header-note", default="تحديث كل نصف ساعة")
    ap.add_argument("--tag", default=APP_REMARK_PREFIX)

    ap.add_argument("--test", action="store_true")
    ap.add_argument("--test-top", type=int, default=800)
    ap.add_argument("--speed-top", type=int, default=300)
    ap.add_argument("--best", type=int, default=100)
    ap.add_argument("--best-out", default="best.txt")
    ap.add_argument("--rank-by", choices=("speed", "latency", "score"), default="score")
    ap.add_argument("--max-per-host", type=int, default=3)
    ap.add_argument("--test-report", default="test-report.csv")
    ap.add_argument("--concurrency", type=int, default=16)
    ap.add_argument("--test-timeout", type=float, default=6.0)
    ap.add_argument("--xray")
    ap.add_argument("--singbox")
    ap.add_argument("--no-singbox", action="store_true")
    ap.add_argument("--no-download", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    if not args.telegram and not args.github:
        LOG.error("لا يوجد أي مصدر مفعّل (استخدم --telegram و/أو --github).")
        return 2

    all_configs: list[str] = []
    t0 = time.perf_counter()

    if args.telegram:
        raw = get_channels(args.channels)
        urls = channel_urls(raw)
        LOG.info("[تلغرام] %d قناة فريدة من أصل %d مُدخل", len(urls), len(raw))
        cfgs, ok, failed = collect_telegram(urls, args.workers)
        LOG.info("[تلغرام] الصفحات: %d ناجحة / %d فاشلة | كانفيغ خام: %d", ok, failed, len(cfgs))
        all_configs.extend(cfgs)

    if args.github:
        sources = get_github_sources(args.sources_file)
        LOG.info("[GitHub] %d مصدر", len(sources))
        cfgs, stats = collect_github(sources, args.workers, args.max_per_source)
        for name, n in stats:
            LOG.info("[GitHub] %-24s %d كانفيغ", name, n)
        all_configs.extend(cfgs)

    configs, rejected = clean(all_configs)
    LOG.info("كانفيغ خام: %d | فريد بعد التنظيف: %d | مرفوض: %d", len(all_configs), len(configs), rejected)

    if args.unique_endpoint:
        configs, dropped = dedupe_by_endpoint(configs)
        LOG.info("--unique-endpoint: حُذف %d تكرار بنفس host:port → %d كانفيغ", dropped, len(configs))

    mix = collections.Counter(canonical_protocol(c.split("://")[0]) for c in configs)
    LOG.info("مزيج البروتوكولات: %s", dict(mix.most_common()))

    if not configs:
        LOG.error("لم يتم العثور على أي كانفيغ؛ لم يُعد كتابة الملف.")
        return 1

    out = Path(args.out)
    write_outputs(configs, out, args.calendar, args.header_note, args.tag)
    LOG.info("تمت الكتابة: %s (%d سطر) في %.1f ثانية", out, len(configs), time.perf_counter() - t0)

    if args.test:
        import tester

        xray = args.xray or tester.ensure_xray(allow_download=not args.no_download)
        sbox = None
        if not args.no_singbox:
            sbox = args.singbox or tester.ensure_singbox(allow_download=not args.no_download)

        if not xray and not sbox:
            LOG.error("تعذّر تجهيز أي نواة (Xray/sing-box) → تم تخطّي الفحص.")
            return 1

        lat, best, skipped = tester.select_best(
            configs,
            xray_path=xray,
            singbox_path=sbox,
            test_top=args.test_top,
            speed_top=args.speed_top,
            concurrency=args.concurrency,
            rank_by=args.rank_by,
            timeout=args.test_timeout,
        )
        if args.test_report:
            n_rep = tester.write_report(lat, Path(args.test_report))
            LOG.info("تقرير الفحص المحجوب الأسرار: %s (%d كانفيغ)", args.test_report, n_rep)

        if not best:
            LOG.error("لم تنجح أي عقدة في الفحص؛ لم يُكتب ملف الأفضل.")
            return 1

        best = tester.limit_per_host(best, args.max_per_host)
        best_out = Path(args.best_out)
        n = write_best(best, best_out, args.best, args.calendar, args.tag)
        LOG.info("تمت الكتابة: %s (أفضل %d من %d عقدة حيّة، تخطّي %d)", best_out, n, len(best), skipped)
        # حجب الأسرار بالكامل عند الطباعة في سجلات التشغيل
        for i, r in enumerate(best[:5], 1):
            LOG.info("  #%d %.0fms  %.0fKB/s  %s", i, r.latency_ms, r.speed_kbps, redact_uri(r.cfg))

    return 0


if __name__ == "__main__":
    sys.exit(main())
