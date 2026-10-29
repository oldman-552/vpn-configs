#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
collector.py — جمع كانفيغات VPN من قنوات تلغرام + مستودعات GitHub في ملف واحد.

المصادر المدعومة:
  • قنوات تلغرام العامة (web preview: https://t.me/s/NAME)
  • مستودعات اشتراك على GitHub (روابط raw / jsDelivr) — نص عادي أو base64

المميزات:
  1) استخراج كل كانفيغ على حدة بواسطة regex — حتى لو كانت عدة كانفيغات داخل رسالة واحدة.
  2) يجد الكانفيغات خارج <code> أيضًا (نص عادي داخل الرسالة، أو داخل روابط <a href>).
  3) يفكّ ملفات الاشتراك المُرمّزة بـ base64 القياسي و URL-safe تلقائيًا.
  4) ينظّف الكيانات النصية (&amp;) والمحارف الخفية (ZWNJ/RLM) وعلامات الترقيم الزائدة.
  5) طلبات متوازية + timeout + إعادة محاولة مع backoff (لا تعليق على 429/403).
  6) تنقية الأسماء وحذف التكرار قبل إرسال أي طلب — لا طلب مكرّر.
  7) كتابة ذرّية للملف (tmp ثم replace) وحماية آخر نسخة سليمة عند الفراغ.

أمثلة التشغيل:
    python collector.py                                   # تلغرام + GitHub (الافتراضي)
    python collector.py --no-telegram                     # مستودعات GitHub فقط
    python collector.py --no-github                       # قنوات تلغرام فقط
    python collector.py --max-per-source 500 -o config.txt
    python collector.py --unique-endpoint                 # كانفيغ واحد لكل host:port
    python collector.py --sources-file github_sources.txt  # قائمة مصادر خاصة بك
    python collector.py --calendar gregorian --tag "@my_channel"

    # فحص حقيقي واختيار الأسرع (يُنزّل Xray/sing-box تلقائيًا أول مرة):
    python collector.py --test                       # config.txt + best.txt (أفضل 100)
    python collector.py --test --test-top 1500 --speed-top 400 --concurrency 24
    python collector.py --test --rank-by latency --best 50 --best-out fastest.txt
"""

from __future__ import annotations

import argparse
import base64
import binascii
import collections
import html as html_lib
import json
import logging
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import requests
from bs4 import BeautifulSoup

try:                       # jdatetime اختياري: إذا لم يكن مثبّتًا نستخدم الميلادي
    import jdatetime
except ImportError:
    jdatetime = None

ROOT_DIR = Path(__file__).resolve().parent
DEFAULT_CHANNELS_FILE = ROOT_DIR / "channels.txt"
DEFAULT_SOURCES_FILE = ROOT_DIR / "github_sources.txt"

TZ = ZoneInfo("Asia/Tehran")
LOG = logging.getLogger("collector")

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9,fa;q=0.8",
}

# ترتيب العناصر مهم: البروتوكولات الأطول أولًا، وإلا فإن "ss" ستلتقط جزءًا من "vless"
SCHEMES = ("hysteria2", "vless", "vmess", "trojan", "hy2", "tuic", "ssr", "ss")
CONFIG_RE = re.compile(r"(?:%s)://[^\s<>\"'`]+" % "|".join(SCHEMES))
FRAGMENT_RE = re.compile(r"#.*$")
INVISIBLE_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]+")

# ─────────────────────────────────────────────────────────────────────────────
# 1) قنوات تلغرام الاحتياطية (يُقرأ channels.txt تلقائيًا إن وُجد)
# ─────────────────────────────────────────────────────────────────────────────
CHANNELS = [
    "IR_Predators", "DailyV2RY", "oneclickvpnkeys", "i10VPN", "Velinamusic", "FNetPro",
    "confegraigan", "zedmodeonvpn", "V2ray_Vpn_Speed", "lightning6", "Parsashonam",
    "XpnTeam", "nexvpn_server", "AzarAndoozVPN", "v2ray_configs_pool", "v2rayNGcloud",
    "ZibaNabz", "FreakConfig", "V_2rey", "V2ray_Alpha", "PROXY_MTM", "SiNABiGO",
    "v2rayng12023", "vlessconfig", "piazshekan", "Free_Internet_Iran", "ARv2ray",
    "VPNCUSTOMIZE", "UnlimitedDev", "MARAMBASHI", "PrivateVPNs", "client_proo",
    "nufilter", "icv2ray", "Vpn_Mikey", "v2rayngvpn", "kingspeedchanel", "VPN_Xpace",
    "SVNTEAM", "WPSNET", "v2rayng_fa2", "Hope_Net", "ServerNett", "alfred_config",
    "allv2ray", "alo_v2rayng", "angus_vpn", "antifilterservice", "asak_vpn",
    "asintech", "astrovpn_official", "awlix_ir", "azarbayjab1", "bermudavpn24",
    "bigsmoke_config", "blueberrynetwork", "bored_vpn", "catvpns", "cconfig_v2ray",
    "city_v2rayng", "configforvpn", "configpositive", "configt", "configv2rayforfree",
    "custom_config", "customizev2ray", "cvrnet", "daredevill_404", "deragv2ray",
    "digiv2ray", "directvpn", "donald_vpn", "drvpn_net", "easy_free_vpn", "entrynet",
    "ev2rayy", "expressvpn_420", "external_net", "farahvpn", "fasst_vpn", "fast_2ray",
    "fastkanfig", "fastshadow_vpn", "filterk0sh", "flyv2ray", "freakconfig1",
    "freakconfig2", "free1_vpn", "free_vpn02", "freeconfig01", "freeconfigvpns",
    "freeiranweb", "freenapsternetv", "freev2raym", "freevirgoolnet", "fsv2ray",
    "ghalagyann", "godv2ray_ng", "golestan_vpn", "grizzlyvpn", "hajimamadvpn",
    "hamster_vpnn", "hatunnel_vpn", "hopev2ray", "hormozvpn", "hose_io", "imrv2ray",
    "ios_v2", "ipcloudflaretamiz", "ipv2ray", "iranbaxvpn", "iraniv2ray_config",
    "irv2rey", "isvvpn", "kafing_2", "kingofilter", "ln2ray", "lombo_channel",
    "mahdiserver", "manzariyeh_rasht", "maznet", "meli_proxyy", "mester_v2ray",
    "mgvpnsale", "mikasavpn", "miov2ray", "moftinet", "msv2ray", "msv2raynp", "n2vpn",
    "netmellianti", "new_proxy_channel", "noforcedheaven", "npvv2rayfilter", "ohvpn",
    "orange_vpns", "outline_ir", "outline_vpn", "pars_vpn3",
    "pashmam_vpn", "pishiserver", "pqv2ray", "proprojec", "proxiiraniii", "proxy_n1",
    "proxyfull", "proxystore11", "prroxyng", "puni_shop_v2rayng", "qeshmserver",
    "realvpnmaster", "rnrifci", "satoshivpn", "savagev2ray", "selinc", "shadowproxy66",
    "shokhmiplus", "sinavm", "sobi_vpn", "special_net8", "spikevpn", "srcvpn",
    "summertimeus", "superv2rang", "tehranargo", "tehranargo1", "thexconfig",
    "thunderv2ray", "tv_v2ray", "ultrasurf_12", "v2_city", "v2aryng_vpn", "v2boxvpnn",
    "v2graphy", "v2net_iran", "v2ngfast", "v2pedia", "v2ra2", "v2raand", "v2rang00",
    "v2range", "v2raxx", "v2ray1_ng", "v2ray6388", "v2ray_alpha07", "v2ray_fark",
    "v2ray_ng", "v2ray_one1", "v2ray_raha", "v2ray_rolly", "v2rayargon", "v2raych",
    "v2rayfast", "v2rayfast_7", "v2rayfree_irr", "v2rayiman", "v2raylandd", "v2rayn2g",
    "v2rayng3", "v2rayng_city", "v2rayng_madam", "v2rayng_prime", "v2rayngv",
    "v2rayngvpnn", "v2rayngzendegimamad", "v2rayprotocol", "v2rayyngvpn", "v2rez",
    "v2rray_ng", "v2ry_proxy", "v2ryng01", "v2ryng_vpn", "v2ryngfree", "v2safe",
    "v2safee", "v_2rayngvpn", "vip_vpn_2022", "vipv2rayngnp", "vipv2rey",
    "vipvpn_v2ray", "vistav2ray", "vmesc", "vmess_ir", "vmess_iran", "vmesskhodam",
    "vmesskhodam_vip", "vmessprotocol", "vp22ray", "vpfreen", "vpn_accounti",
    "vpn_free_v2ray5", "vpn_ioss", "vpn_kanfik", "vpn_proxy_custom", "vpn_tehran",
    "vpn_vip_nor", "vpnazadland", "vpnconfignet", "vpnfail_v2ray", "vpnhubmarket",
    "vpnkanfik", "vpnmasi", "vpnowl", "vpnstorefast", "vpnv2rayngv", "vpnxyam_ir",
    "wedbaztel", "wsbvpn", "xvproxy", "zede_filteri", "zohalserver", "vpnaloo",
    "godot404", "prrofile_purple", "vpnsaint", "azadnet", "appsooner",
    "V2SayFreeArchive", "shadoowvpnn", "v2fre", "ConfigsHubPlus", "imtproxy_ir",
    "PASARGAD_V2rayNG", "club_profsor", "Speeds_vpn1", "Airdorap_Free", "VPN_SOLVE",
    "bglvps", "vpnmeliran", "dr_news2", "v2raying", "singbox1", "iProxyem",
    "sabavpn_com", "VpnMaan", "proxy_kafee", "hex_proxy",
]

# ─────────────────────────────────────────────────────────────────────────────
# 2) مستودعات GitHub الاحتياطية (يُقرأ github_sources.txt تلقائيًا إن وُجد)
# ─────────────────────────────────────────────────────────────────────────────
GITHUB_SOURCES = {
    "matin-super": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt",
    "au1rxx-verified": "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/v2ray-base64.txt",
    "mahdibland-eternity": "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity",
    "ermaozi": "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "solispirit-all": "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
    "alilapro": "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
    "matin-all": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
    "matin-hysteria2": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/hysteria2.txt",
    "barryfar-sub1": "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub1.txt",
    "leon406-vless": "https://raw.githubusercontent.com/Leon406/SubCrawler/master/sub/share/vless",
    "leon406-hysteria2": "https://raw.githubusercontent.com/Leon406/SubCrawler/master/sub/share/hysteria2",
    "leon406-mixed": "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/a11",
    "openproxylist": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
}

# requests.Session ليست thread-safe، لذلك نعطي كل thread جلسته الخاصة
_local = threading.local()


def session() -> requests.Session:
    """إرجاع Session خاص بالـ thread الحالي (مع الهيدرز الجاهزة)."""
    if not hasattr(_local, "s"):
        s = requests.Session()
        s.headers.update(HEADERS)
        _local.s = s
    return _local.s


# ───────────────────────────── أدوات مساعدة ─────────────────────────────
def channel_urls(raw: list[str]) -> list[str]:
    """
    تنقية أسماء القنوات وحذف المكرّر.
    تقبل: "Name" أو "@Name" أو "https://t.me/s/Name" أو "https://t.me/Name".
    تلغرام لا يفرّق بين الحروف الكبيرة والصغيرة، لذلك نعمل على lower().
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


def get_github_sources(path: str | Path | None = None) -> dict[str, str]:
    """قراءة مصادر GitHub من المسار المحدّد، أو من github_sources.txt إن وُجد، وإلا فالقائمة المدمجة."""
    target = Path(path) if path else (DEFAULT_SOURCES_FILE if DEFAULT_SOURCES_FILE.exists() else None)
    if target and target.exists():
        loaded = load_sources_file(str(target))
        if loaded:
            return loaded
    return dict(GITHUB_SOURCES)


def fetch_text(url: str, retries: int = 3, timeout: tuple[int, int] = (5, 25)) -> str | None:
    """
    جلب نص (HTML أو ملف اشتراك) مع timeout وإعادة محاولة.
    يُرجع النص أو None عند الفشل (بلا رفع استثناء يكسر الحلقة كلها).
    """
    for attempt in range(1, retries + 1):
        try:
            r = session().get(url, timeout=timeout)
        except requests.RequestException as exc:
            LOG.debug("%s محاولة %d: %s", url, attempt, exc)
            time.sleep(1.5 * attempt)
            continue

        if r.status_code == 200:
            return r.text

        if r.status_code in (429, 500, 502, 503, 504):
            wait = min(30, 2 ** attempt)
            LOG.debug("%s -> %d، انتظار %ss", url, r.status_code, wait)
            time.sleep(wait)
            continue

        LOG.info("%s -> HTTP %d (تخطّي)", url, r.status_code)
        return None

    LOG.warning("فشل الجلب: %s", url)
    return None


def b64_decode(text: str) -> str | None:
    """فكّ base64 القياسي أو URL-safe مع تصحيح الحشو (padding). يُرجع None عند الفشل."""
    compact = re.sub(r"\s+", "", text)
    if not compact:
        return None
    normalized = compact.replace("-", "+").replace("_", "/")
    padded = normalized + "=" * (-len(normalized) % 4)
    try:
        return base64.b64decode(padded, validate=True).decode("utf-8", "ignore")
    except (binascii.Error, ValueError):
        try:
            return base64.b64decode(padded).decode("utf-8", "ignore")
        except (binascii.Error, ValueError):
            return None


def parse_subscription(text: str) -> list[str]:
    """
    استخراج الكانفيغات من ملف اشتراك:
      • نص عادي: سطر لكل كانفيغ
      • base64 لكامل الملف (الشائع في مستودعات GitHub)
    """
    unescaped = html_lib.unescape(text)
    found = CONFIG_RE.findall(unescaped)
    if found:
        return found

    decoded = b64_decode(text)
    if decoded:
        return CONFIG_RE.findall(html_lib.unescape(decoded))
    return []


def extract_configs(html: str) -> list[str]:
    """
    استخراج كل الكانفيغات من صفحة قناة تلغرام.
    نقرأ نص الرسالة كاملًا (وليس <code> فقط) + الروابط، ثم regex.
    """
    soup = BeautifulSoup(html, "html.parser")
    blocks = soup.select("div.tgme_widget_message_text")
    if not blocks:
        blocks = [soup]

    found: list[str] = []
    for block in blocks:
        found.extend(CONFIG_RE.findall(block.get_text("\n")))
        for a in block.find_all("a", href=True):
            found.extend(CONFIG_RE.findall(html_lib.unescape(a["href"])))
    return found


def endpoint_key(cfg: str) -> str | None:
    """
    مفتاح «host:port» لكانفيغ — يُستخدم مع --unique-endpoint
    لإبقاء عقدة واحدة فقط لكل عنوان (حتى لو اختلفت بارامتراتها).
    """
    scheme, _, rest = cfg.partition("://")
    rest = rest.split("#", 1)[0]

    if scheme == "vmess":
        body = rest.split("?", 1)[0]
        dec = b64_decode(body)
        if not dec:
            return None
        try:
            j = json.loads(dec)
            add = str(j.get("add") or "").strip().lower()
            port = str(j.get("port") or "").strip()
            return f"{add}:{port}" if add and port else None
        except Exception:
            return None

    if "@" not in rest:                # ss/ssr بصيغة base64
        dec = b64_decode(rest.split("?", 1)[0].rstrip("/"))
        if not dec or "@" not in dec:
            return None
        rest = dec.rsplit("@", 1)[-1]
        hp = rest.split("/", 1)[0].split("?", 1)[0].strip().lower()
        return hp or None

    host_port = rest.rsplit("@", 1)[-1].split("/", 1)[0].split("?", 1)[0].strip().lower()
    return host_port or None


def _strip_trailing_junk(cfg: str) -> str:
    """إزالة علامات الترقيم الزائدة في نهاية السطر دون إتلاف base64 أو عناوين IPv6."""
    cfg = cfg.rstrip(",.;")
    while cfg.endswith(")") and "(" not in cfg:
        cfg = cfg[:-1]
    while cfg.endswith("]") and "[" not in cfg:
        cfg = cfg[:-1]
    return cfg


def _valid_vmess_body(body: str) -> bool:
    dec = b64_decode(body.split("?", 1)[0])
    if not dec:
        return False
    try:
        j = json.loads(dec)
        if not isinstance(j, dict):
            return False
        add = str(j.get("add") or "").strip()
        uid = str(j.get("id") or "").strip()
        port = int(str(j.get("port") or "0").strip())
        return bool(add and uid and 1 <= port <= 65535)
    except Exception:
        return False


def clean(configs: list[str]) -> tuple[list[str], int]:
    """
    تنظيف + حذف المكرّر مع الحفاظ على الترتيب.
    يُرجع (قائمة نظيفة، عدد المرفوض).
    """
    out: dict[str, None] = {}
    rejected = 0
    for raw in configs:
        unescaped = html_lib.unescape(raw)
        unescaped = INVISIBLE_RE.sub("", unescaped).strip()
        cfg = FRAGMENT_RE.sub("", unescaped).strip()
        cfg = _strip_trailing_junk(cfg)
        scheme, sep, body = cfg.partition("://")
        if not sep:
            rejected += 1
            continue

        needs_at = scheme in ("vless", "trojan", "hysteria2", "hy2", "tuic")
        min_len = 16 if scheme in ("vmess", "ss", "ssr") else 8

        if len(body) < min_len or (needs_at and "@" not in body):
            rejected += 1
            continue

        if scheme == "vmess" and not _valid_vmess_body(body):
            rejected += 1
            continue

        if needs_at:
            after_at = body.rsplit("@", 1)[-1].split("/", 1)[0].split("?", 1)[0]
            if not after_at:
                rejected += 1
                continue

        out.setdefault(cfg, None)
    return list(out), rejected


def dedupe_by_endpoint(configs: list[str]) -> tuple[list[str], int]:
    """إبقاء أول كانفيغ لكل host:port (يقلّل الحجم كثيرًا ويحذف العُقد المكرّرة)."""
    out: list[str] = []
    used: set[str] = set()
    for cfg in configs:
        key = endpoint_key(cfg) or cfg
        if key in used:
            continue
        used.add(key)
        out.append(cfg)
    return out, len(configs) - len(out)


def stamp(calendar: str) -> tuple[str, str]:
    """
    يُرجع (ختم الوقت الكامل، التاريخ فقط).
    إذا اختير التقويم الشمسي ولم يكن jdatetime مثبّتًا نعود تلقائيًا إلى الميلادي.
    """
    now = datetime.now(TZ)
    if calendar == "jalali":
        if jdatetime is not None:
            j = jdatetime.datetime.fromgregorian(datetime=now)
            return j.strftime("%b-%d | %H:%M"), j.strftime("%b-%d")
        LOG.warning("jdatetime غير مثبّت؛ استخدام التقويم الميلادي بدلًا منه.")
    return now.strftime("%b-%d | %H:%M"), now.strftime("%b-%d")


def write_outputs(configs: list[str], out_path: Path, calendar: str,
                  header_note: str, tag: str) -> None:
    """بناء الأسطر (كانفيغ + remark) وكتابة الملف بشكل ذرّي."""
    full_ts, date_only = stamp(calendar)
    lines = []
    for i, cfg in enumerate(configs):
        if i == 0:
            remark = f"#{full_ts} | {header_note}"
        else:
            remark = f"#{tag} {i} | {date_only} | {tag}"
        lines.append(f"{cfg}{remark}")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_name(out_path.name + ".tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    tmp.replace(out_path)


def write_best(results, out_path: Path, limit: int, calendar: str, tag: str) -> int:
    """
    كتابة أفضل N كانفيغ في ملف منفصل، مع سرعة/تأخير كل عقدة في الـ remark.
    يُرجع عدد الأسطر المكتوبة.
    """
    _, date_only = stamp(calendar)
    lines = []
    for i, r in enumerate(results[:limit]):
        speed = f"{r.speed_kbps:.0f}KB/s" if r.speed_kbps > 0 else "—"
        remark = f"#{i + 1} | {r.latency_ms:.0f}ms | {speed} | {date_only} | {tag}"
        lines.append(f"{r.cfg}{remark}")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_name(out_path.name + ".tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    tmp.replace(out_path)
    return len(lines)


def load_sources_file(path: str) -> dict[str, str]:
    """
    قراءة قائمة مصادر مخصّصة. كل سطر:  «اسم  URL»  أو  URL فقط.
    الأسطر الفارغة والتي تبدأ بـ # تُتجاهل.
    """
    sources: dict[str, str] = {}
    for i, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[-1].startswith("http"):
            name, url = " ".join(parts[:-1]), parts[-1]
        elif line.startswith("http"):
            name, url = f"custom-{i}", line
        else:
            LOG.warning("سطر غير مفهوم في %s: %r", path, line)
            continue
        sources[name] = url
    return sources


# ───────────────────────────── الجلب المتوازي ─────────────────────────────
def collect_telegram(urls: list[str], workers: int) -> tuple[list[str], int, int]:
    """جلب صفحات القنوات بالتوازي. يُرجع (قائمة كانفيغات، نجحت، فشلت)."""
    pages: list[str] = []
    ok = failed = 0

    def job(u: str) -> str | None:
        return fetch_text(u, timeout=(5, 15))

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(job, u): u for u in urls}
        for fut in as_completed(futures):
            html = fut.result()
            if html:
                pages.append(html)
                ok += 1
            else:
                failed += 1

    return [c for page in pages for c in extract_configs(page)], ok, failed


def collect_github(sources: dict[str, str], workers: int,
                   max_per_source: int = 0) -> tuple[list[str], list[tuple[str, int]]]:
    """
    جلب ملفات الاشتراك من GitHub بالتوازي.
    يُرجع (قائمة كانفيغات، إحصاء لكل مصدر [(الاسم، العدد)]).
    """
    results: dict[str, list[str]] = {}

    def job(item: tuple[str, str]) -> tuple[str, list[str]]:
        name, url = item
        text = fetch_text(url, timeout=(10, 60))
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

    # ترتيب النتيجة كما في القاموس (مصادر أفضل أولًا) وليس كما انتهت الطلبات
    ordered = [(name, results.get(name, [])) for name in sources]
    flat = [c for _, cfgs in ordered for c in cfgs]
    return flat, [(name, len(cfgs)) for name, cfgs in ordered]


# ───────────────────────────── البرنامج الرئيسي ─────────────────────────────
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="جمع كانفيغات VPN من قنوات تلغرام ومستودعات GitHub في ملف واحد")
    ap.add_argument("-o", "--out", default="config.txt", help="ملف الخروج")
    ap.add_argument("-w", "--workers", type=int, default=8, help="عدد الطلبات المتوازية")
    ap.add_argument("--telegram", dest="telegram", action="store_true", default=True,
                    help="تضمين قنوات تلغرام (افتراضي)")
    ap.add_argument("--no-telegram", dest="telegram", action="store_false",
                    help="تجاهل قنوات تلغرام")
    ap.add_argument("--github", dest="github", action="store_true", default=True,
                    help="تضمين مستودعات GitHub (افتراضي)")
    ap.add_argument("--no-github", dest="github", action="store_false",
                    help="تجاهل مستودعات GitHub")
    ap.add_argument("--channels", help="ملف نصي: اسم قناة أو رابط في كل سطر")
    ap.add_argument("--sources-file", help="ملف مصادر مخصّص: «اسم URL» في كل سطر")
    ap.add_argument("--max-per-source", type=int, default=0,
                    help="أقصى عدد كانفيغ يُؤخذ من كل مصدر GitHub (0 = بلا حد)")
    ap.add_argument("--unique-endpoint", action="store_true",
                    help="إبقاء كانفيغ واحد فقط لكل host:port (ملف أصغر وأنظف)")
    ap.add_argument("--calendar", choices=("jalali", "gregorian"), default="jalali")
    ap.add_argument("--header-note", default="تحديث كل نصف ساعة")
    ap.add_argument("--tag", default="@vpn-bahrain", help="الوسم المستخدم في الـ remark")

    # ── الفحص الحقيقي واختيار الأسرع ──
    ap.add_argument("--test", action="store_true",
                    help="تشغيل فحص اتصال حقيقي واختيار الأسرع (يُنزّل Xray تلقائيًا)")
    ap.add_argument("--test-top", type=int, default=800,
                    help="عدد الكانفيغات التي تُفحص فعليًا (بالترتيب: أفضل المصادر أولًا)")
    ap.add_argument("--speed-top", type=int, default=300,
                    help="عدد العُقد التي تُقاس سرعة تنزيلها")
    ap.add_argument("--best", type=int, default=100, help="عدد الكانفيغات في ملف الأفضل")
    ap.add_argument("--best-out", default="best.txt", help="ملف أفضل N كانفيغ")
    ap.add_argument("--rank-by", choices=("speed", "latency"), default="speed",
                    help="ترتيب الأفضل: السرعة (افتراضي) أو زمن التأخير")
    ap.add_argument("--max-per-host", type=int, default=3,
                    help="أقصى عدد عُقد من نفس المضيف في ملف الأفضل (0 = بلا حد)")
    ap.add_argument("--test-report", default="test-report.csv",
                    help="ملف CSV بنتائج الفحص كاملة")
    ap.add_argument("--concurrency", type=int, default=16,
                    help="عدد عمليات Xray المتوازية أثناء الفحص")
    ap.add_argument("--test-timeout", type=float, default=6.0,
                    help="مهلة محاولة الاتصال بالعقدة بالثواني (افتراضي 6)")
    ap.add_argument("--xray", help="مسار نواة Xray (افتراضي: bin/xray أو تنزيل تلقائي)")
    ap.add_argument("--singbox", help="مسار نواة sing-box (لـ hysteria2/tuic)")
    ap.add_argument("--no-singbox", action="store_true",
                    help="تعطيل فحص hysteria2/tuic عبر sing-box")
    ap.add_argument("--no-download", action="store_true", help="منع تنزيل النوى تلقائيًا")
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

    # 1) تلغرام
    if args.telegram:
        raw = get_channels(args.channels)
        urls = channel_urls(raw)
        LOG.info("[تلغرام] %d قناة فريدة من أصل %d مُدخل", len(urls), len(raw))

        cfgs, ok, failed = collect_telegram(urls, args.workers)
        LOG.info("[تلغرام] الصفحات: %d ناجحة / %d فاشلة | كانفيغ خام: %d",
                 ok, failed, len(cfgs))
        all_configs.extend(cfgs)

    # 2) GitHub
    if args.github:
        sources = get_github_sources(args.sources_file)
        LOG.info("[GitHub] %d مصدر", len(sources))

        cfgs, stats = collect_github(sources, args.workers, args.max_per_source)
        for name, n in stats:
            LOG.info("[GitHub] %-22s %d كانفيغ", name, n)
        LOG.info("[GitHub] الإجمالي الخام: %d", len(cfgs))
        all_configs.extend(cfgs)

    # 3) تنظيف + حذف التكرار (عبر كل المصادر)
    configs, rejected = clean(all_configs)
    LOG.info("كانفيغ خام: %d | فريد بعد التنظيف: %d | مرفوض: %d",
             len(all_configs), len(configs), rejected)

    if args.unique_endpoint:
        configs, dropped = dedupe_by_endpoint(configs)
        LOG.info("--unique-endpoint: حُذف %d تكرار بنفس host:port → %d كانفيغ",
                 dropped, len(configs))

    mix = collections.Counter(c.split("://")[0] for c in configs)
    LOG.info("مزيج البروتوكولات: %s", dict(mix.most_common()))

    # 4) حماية: لا نكتب ملفًا فارغًا فوق نسخة سليمة
    if not configs:
        LOG.error("لم يتم العثور على أي كانفيغ؛ لم يُعد كتابة الملف.")
        return 1

    out = Path(args.out)
    write_outputs(configs, out, args.calendar, args.header_note, args.tag)
    LOG.info("تمت الكتابة: %s (%d سطر) في %.1f ثانية",
             out, len(configs), time.perf_counter() - t0)

    # 5) فحص حقيقي + اختيار الأسرع
    if args.test:
        import tester

        xray = args.xray or tester.ensure_xray(allow_download=not args.no_download)
        sbox = None
        if not args.no_singbox:
            sbox = args.singbox or tester.ensure_singbox(allow_download=not args.no_download)

        if not xray and not sbox:
            LOG.error("تعذّر تجهيز أي نواة (Xray/sing-box) → تم تخطّي الفحص. الملف الكامل مكتوب.")
            return 1
        LOG.info("المحرّكات: Xray=%s | sing-box=%s",
                 Path(xray).name if xray else "غير متاح",
                 Path(sbox).name if sbox else "غير متاح")

        LOG.info("بدء الفحص الحقيقي …")
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
            LOG.info("تقرير الفحص: %s (%d كانفيغ)", args.test_report, n_rep)

        if not best:
            LOG.error("لم تنجح أي عقدة في الفحص؛ لم يُكتب ملف الأفضل.")
            return 1

        diversified = tester.limit_per_host(best, args.max_per_host)
        if args.max_per_host and len(diversified) < len(best):
            LOG.info("تنويع المضيفين: %d → %d عقدة (بحد %d لكل مضيف)",
                     len(best), len(diversified), args.max_per_host)
        best = diversified

        best_out = Path(args.best_out)
        n = write_best(best, best_out, args.best, args.calendar, args.tag)
        LOG.info("تمت الكتابة: %s (أفضل %d من %d عقدة حيّة، تخطّي %d كانفيغ غير مدعوم)",
                 best_out, n, len(best), skipped)
        for i, r in enumerate(best[:5], 1):
            LOG.info("  #%d %.0fms  %.0fKB/s  %s", i, r.latency_ms,
                     r.speed_kbps, r.cfg[:60])

    return 0


if __name__ == "__main__":
    sys.exit(main())
