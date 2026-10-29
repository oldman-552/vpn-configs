#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tester.py — فحص حقيقي للكانفيغات عبر الإنترنت الفعلي لجهازك، واختيار الأسرع.

كيف يعمل؟
  لكل كانفيغ: نشغّل نواة محلية (Xray أو sing-box) كـ outbound + socks محلي، ثم نطلب
  https://www.gstatic.com/generate_204 **عبر البروكسي**. هذا هو الاختبار الوحيد
  الصادق (فحص TCP وحده يعطي نجاحًا كاذبًا). من نجح يُقاس زمن استجابته، ثم
  تُقاس سرعة التنزيل الفعلية، ويُرتَّب الجميع.

المحرّكات:
  • Xray      → vless, vmess, trojan, ss
  • sing-box  → hysteria2, hy2, tuic     (Xray لا يدعمها)
  (ssr غير مدعوم في أي منهما بصيغته القديمة → يُستثنى ويُبلَّغ بعدده)

الاستخدام المباشر:
    python tester.py --input config.txt --best-out best.txt --best 100
"""

from __future__ import annotations

import argparse
import base64
import binascii
import html as html_lib
import json
import logging
import os
import platform
import queue
import re
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

import requests

try:
    import socks           # PySocks: للاتصال عبر socks5h
except ImportError:
    socks = None

LOG = logging.getLogger("tester")

DEFAULT_BIN_DIR = Path(__file__).resolve().parent / "bin"
TEST_URL = "https://www.gstatic.com/generate_204"
SPEED_URL = "https://speed.cloudflare.com/__down?bytes=1000000"
FALLBACK_SINGBOX_VERSION = "1.14.4"

ENGINE_BY_SCHEME = {
    "vless": "xray", "vmess": "xray", "trojan": "xray", "ss": "xray",
    "hysteria2": "singbox", "hy2": "singbox", "tuic": "singbox",
}
XRAY_SCHEMES = ("vless", "vmess", "trojan", "ss")
SINGBOX_SCHEMES = ("hysteria2", "hy2", "tuic")

XRAY_ASSETS = {
    ("linux", "x86_64"): "Xray-linux-64.zip",
    ("linux", "amd64"): "Xray-linux-64.zip",
    ("linux", "aarch64"): "Xray-linux-arm64-v8a.zip",
    ("linux", "arm64"): "Xray-linux-arm64-v8a.zip",
    ("linux", "armv7l"): "Xray-linux-arm32-v7a.zip",
    ("darwin", "x86_64"): "Xray-macos-64.zip",
    ("darwin", "amd64"): "Xray-macos-64.zip",
    ("darwin", "arm64"): "Xray-macos-arm64-v8a.zip",
    ("darwin", "aarch64"): "Xray-macos-arm64-v8a.zip",
    ("windows", "amd64"): "Xray-windows-64.zip",
    ("windows", "x86_64"): "Xray-windows-64.zip",
    ("windows", "x86"): "Xray-windows-32.zip",
}
SINGBOX_ASSETS = {
    ("linux", "x86_64"): "linux-amd64",
    ("linux", "amd64"): "linux-amd64",
    ("linux", "aarch64"): "linux-arm64",
    ("linux", "arm64"): "linux-arm64",
    ("linux", "armv7l"): "linux-armv7",
    ("darwin", "x86_64"): "darwin-amd64",
    ("darwin", "amd64"): "darwin-amd64",
    ("darwin", "arm64"): "darwin-arm64",
    ("darwin", "aarch64"): "darwin-arm64",
    ("windows", "amd64"): "windows-amd64.zip",
    ("windows", "x86_64"): "windows-amd64.zip",
    ("windows", "x86"): "windows-386.zip",
}


# ───────────────────────── تنزيل النوى وتجهيزها ─────────────────────────
def _platform_key() -> tuple[str, str]:
    return platform.system().lower(), platform.machine().lower()


def _gh_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "vpn-configs/1.0"}
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    return headers


def ensure_xray(bin_dir: Path = DEFAULT_BIN_DIR, allow_download: bool = True) -> str | None:
    """إرجاع مسار Xray القابل للتنفيذ؛ وتنزيله تلقائيًا من GitHub إن لم يوجد."""
    exe = bin_dir / ("xray.exe" if os.name == "nt" else "xray")
    if exe.exists() and os.access(exe, os.X_OK):
        return str(exe)
    if not allow_download:
        LOG.warning("لا يوجد Xray في %s (والتنزيل معطّل) → vless/vmess/trojan/ss لن تُفحص.", exe)
        return None

    asset = XRAY_ASSETS.get(_platform_key())
    if not asset:
        LOG.error("لا يوجد إصدار Xray لنظامك (%s/%s).", platform.system(), platform.machine())
        return None

    try:
        bin_dir.mkdir(parents=True, exist_ok=True)
        LOG.info("تنزيل Xray (%s) …", asset)
        url: str | None = None
        try:
            rel_resp = requests.get(
                "https://api.github.com/repos/XTLS/Xray-core/releases/latest",
                headers=_gh_headers(),
                timeout=20,
            )
            if rel_resp.status_code == 200:
                rel = rel_resp.json()
                url = next(
                    (a["browser_download_url"] for a in rel.get("assets", []) if a.get("name") == asset),
                    None,
                )
        except Exception as api_exc:
            LOG.debug("تعذّر استعلام GitHub API لـ Xray (%s)، استخدام الرابط المباشر.", api_exc)

        if not url:
            url = f"https://github.com/XTLS/Xray-core/releases/latest/download/{asset}"

        dl = requests.get(url, timeout=180)
        dl.raise_for_status()
        zpath = bin_dir / "xray.zip"
        zpath.write_bytes(dl.content)
        with zipfile.ZipFile(zpath) as z:
            z.extractall(bin_dir)
        zpath.unlink(missing_ok=True)
        exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
        LOG.info("جاهز: %s", exe)
        return str(exe)
    except Exception as exc:
        LOG.error("فشل تجهيز Xray: %s", exc)
        return None


def _resolve_singbox_version() -> str:
    """معرفة أحدث إصدار sing-box عبر API أو إعادة التوجيه بدون استهلاك حدّ API."""
    try:
        r = requests.get(
            "https://api.github.com/repos/SagerNet/sing-box/releases/latest",
            headers=_gh_headers(),
            timeout=20,
        )
        if r.status_code == 200:
            tag = r.json().get("tag_name", "").lstrip("v")
            if tag:
                return tag
    except Exception:
        pass
    try:
        r = requests.head(
            "https://github.com/SagerNet/sing-box/releases/latest",
            allow_redirects=True,
            timeout=15,
        )
        if "/releases/tag/v" in r.url:
            tag = r.url.rsplit("/releases/tag/v", 1)[-1].split("/", 1)[0].strip()
            if tag:
                return tag
    except Exception:
        pass
    return FALLBACK_SINGBOX_VERSION


def ensure_singbox(bin_dir: Path = DEFAULT_BIN_DIR, allow_download: bool = True) -> str | None:
    """إرجاع مسار sing-box القابل للتنفيذ؛ وتنزيله تلقائيًا (لـ hysteria2/tuic)."""
    exe = bin_dir / ("sing-box.exe" if os.name == "nt" else "sing-box")
    if exe.exists() and os.access(exe, os.X_OK):
        return str(exe)
    if not allow_download:
        LOG.warning("لا يوجد sing-box في %s (والتنزيل معطّل) → hysteria2/tuic لن تُفحص.", exe)
        return None

    suffix = SINGBOX_ASSETS.get(_platform_key())
    if not suffix:
        LOG.error("لا يوجد إصدار sing-box لنظامك (%s/%s).", platform.system(), platform.machine())
        return None

    try:
        bin_dir.mkdir(parents=True, exist_ok=True)
        version = _resolve_singbox_version()
        name = (f"sing-box-{version}-{suffix}" if suffix.endswith(".zip")
                else f"sing-box-{version}-{suffix}.tar.gz")
        url = f"https://github.com/SagerNet/sing-box/releases/download/v{version}/{name}"
        LOG.info("تنزيل sing-box v%s (%s) …", version, suffix)

        dl = requests.get(url, timeout=240)
        dl.raise_for_status()
        archive = bin_dir / name
        archive.write_bytes(dl.content)

        if name.endswith(".zip"):
            with zipfile.ZipFile(archive) as z:
                for m in z.namelist():
                    if m.endswith(("sing-box.exe", "sing-box")):
                        with z.open(m) as src, open(exe, "wb") as dst:
                            dst.write(src.read())
                        break
        else:
            with tarfile.open(archive) as t:
                member = next(m for m in t.getmembers()
                              if m.isfile() and m.name.endswith("/sing-box"))
                extracted = t.extractfile(member)
                if extracted is None:
                    raise RuntimeError("تعذّر استخراج ملف sing-box من الأرشيف")
                with extracted as src, open(exe, "wb") as dst:
                    dst.write(src.read())
        archive.unlink(missing_ok=True)
        exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
        LOG.info("جاهز: %s", exe)
        return str(exe)
    except Exception as exc:
        LOG.error("فشل تجهيز sing-box: %s", exc)
        return None


# ───────────────────────── أدوات تحليل URI و Base64 ─────────────────────────
def _b64_decode_str(s: str) -> str | None:
    compact = re.sub(r"\s+", "", s)
    if not compact:
        return None
    normalized = compact.replace("-", "+").replace("_", "/")
    padded = normalized + "=" * (-len(normalized) % 4)
    try:
        return base64.b64decode(padded).decode("utf-8", "ignore")
    except (binascii.Error, ValueError):
        return None


def _clean_uri(cfg: str) -> str:
    return html_lib.unescape(cfg).strip().split("#", 1)[0].strip()


def _query(cfg: str) -> tuple:
    u = urlsplit(_clean_uri(cfg))
    return u, {k: v[0] for k, v in parse_qs(u.query).items()}


def _valid_port(port: int) -> bool:
    return 1 <= port <= 65535


def _safe_fp(fp: str | None, default: str = "chrome") -> str:
    val = (fp or "").strip()
    if not val or val.lower() == "none":
        return default
    return val


# ───────────────────────── كانفيغ URI → outbound (Xray) ─────────────────────────
def _vless(cfg: str) -> dict | None:
    u, q = _query(cfg)
    if not u.hostname or not u.username:
        return None
    port = int(u.port or 443)
    if not _valid_port(port):
        return None

    net = q.get("type", "tcp")
    if net in ("raw", "tcp"):
        net = "tcp"
    sec = q.get("security", "none")
    stream: dict = {"network": net, "security": sec}

    if net == "ws":
        ws = {"path": unquote(q.get("path", "/"))}
        if q.get("host"):
            ws["host"] = q["host"].split(",")[0]
        stream["wsSettings"] = ws
    elif net == "httpupgrade":
        ws = {"path": unquote(q.get("path", "/"))}
        if q.get("host"):
            ws["host"] = q["host"].split(",")[0]
        stream["httpupgradeSettings"] = ws
    elif net in ("xhttp", "splithttp"):
        stream["xhttpSettings"] = {"path": unquote(q.get("path", "/")),
                                   "host": q.get("host", "")}
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": q.get("serviceName", "")}
    elif net == "tcp" and q.get("headerType") == "http":
        req = {"path": [unquote(q.get("path", "/"))]}
        if q.get("host"):
            req["headers"] = {"Host": [q["host"]]}
        stream["tcpSettings"] = {"header": {"type": "http", "request": req}}

    if sec == "tls":
        tls = {
            "serverName": q.get("sni") or q.get("host") or u.hostname,
            "allowInsecure": q.get("allowInsecure") in ("1", "true") or q.get("insecure") in ("1", "true"),
            "fingerprint": _safe_fp(q.get("fp")),
        }
        if q.get("alpn"):
            tls["alpn"] = [a for a in q["alpn"].split(",") if a]
        stream["tlsSettings"] = tls
    elif sec == "reality":
        stream["realitySettings"] = {
            "serverName": q.get("sni", ""),
            "fingerprint": _safe_fp(q.get("fp")),
            "publicKey": q.get("pbk", ""),
            "shortId": q.get("sid", ""),
            "spiderX": unquote(q.get("spx", "/")) or "/",
        }

    flow = q.get("flow", "")
    if flow and net != "tcp":        # flow صالح فقط مع TCP
        flow = ""
    return {
        "protocol": "vless",
        "settings": {"vnext": [{
            "address": u.hostname, "port": port,
            "users": [{"id": unquote(u.username),
                       "encryption": q.get("encryption", "none") or "none",
                       "flow": flow}],
        }]},
        "streamSettings": stream,
    }


def _vmess(cfg: str) -> dict | None:
    body = _clean_uri(cfg).split("://", 1)[1].split("?", 1)[0]
    dec = _b64_decode_str(body)
    if not dec:
        return None
    try:
        j = json.loads(dec)
        addr = str(j.get("add") or "").strip().strip("[]")
        port = int(str(j.get("port") or "0").strip())
        uid = str(j.get("id") or "").strip()
    except Exception:
        return None
    if not addr or not uid or not _valid_port(port):
        return None

    net = str(j.get("net") or "tcp").strip() or "tcp"
    if net == "raw":
        net = "tcp"
    tls_raw = str(j.get("tls") or "").strip().lower()
    sec = "tls" if (tls_raw in ("tls", "reality", "true", "1") or j.get("tls") is True) else "none"
    stream: dict = {"network": net, "security": sec}

    if net == "ws":
        ws = {"path": str(j.get("path") or "/")}
        if j.get("host"):
            ws["host"] = str(j["host"]).split(",")[0]
        stream["wsSettings"] = ws
    elif net == "httpupgrade":
        ws = {"path": str(j.get("path") or "/")}
        if j.get("host"):
            ws["host"] = str(j["host"]).split(",")[0]
        stream["httpupgradeSettings"] = ws
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": str(j.get("path") or j.get("serviceName") or "")}
    elif net in ("xhttp", "splithttp"):
        stream["xhttpSettings"] = {"path": str(j.get("path") or "/"), "host": str(j.get("host") or "")}
    elif net == "tcp" and j.get("type") == "http":
        req = {"path": [str(j.get("path") or "/")]}
        if j.get("host"):
            req["headers"] = {"Host": [str(j["host"])]}
        stream["tcpSettings"] = {"header": {"type": "http", "request": req}}

    if sec == "tls":
        insecure = (
            str(j.get("allowInsecure") or "").lower() in ("1", "true")
            or j.get("allowInsecure") is True
            or j.get("verify_cert") is False
        )
        tls = {
            "serverName": str(j.get("sni") or j.get("host") or addr),
            "allowInsecure": insecure,
            "fingerprint": _safe_fp(str(j.get("fp") or "")),
        }
        if j.get("alpn"):
            alpn_val = j["alpn"]
            tls["alpn"] = alpn_val if isinstance(alpn_val, list) else [a for a in str(alpn_val).split(",") if a]
        stream["tlsSettings"] = tls

    try:
        aid = int(str(j.get("aid") or 0).strip())
    except ValueError:
        aid = 0

    return {
        "protocol": "vmess",
        "settings": {"vnext": [{
            "address": addr, "port": port,
            "users": [{"id": uid, "alterId": aid,
                       "security": str(j.get("scy") or "auto") or "auto"}],
        }]},
        "streamSettings": stream,
    }


def _trojan(cfg: str) -> dict | None:
    u, q = _query(cfg)
    if not u.hostname or not u.username:
        return None
    port = int(u.port or 443)
    if not _valid_port(port):
        return None

    net = q.get("type", "tcp")
    if net in ("raw", "tcp"):
        net = "tcp"
    sec = q.get("security", "tls") or "tls"
    stream: dict = {"network": net, "security": sec}

    if sec == "tls":
        stream["tlsSettings"] = {
            "serverName": q.get("sni") or q.get("peer") or u.hostname,
            "allowInsecure": q.get("allowInsecure") in ("1", "true") or q.get("insecure") in ("1", "true"),
            "alpn": [a for a in q.get("alpn", "h2,http/1.1").split(",") if a],
            "fingerprint": _safe_fp(q.get("fp")),
        }
    elif sec == "reality":
        stream["realitySettings"] = {
            "serverName": q.get("sni", ""),
            "fingerprint": _safe_fp(q.get("fp")),
            "publicKey": q.get("pbk", ""),
            "shortId": q.get("sid", ""),
            "spiderX": unquote(q.get("spx", "/")) or "/",
        }

    if net == "ws":
        ws = {"path": unquote(q.get("path", "/"))}
        if q.get("host"):
            ws["host"] = q["host"].split(",")[0]
        stream["wsSettings"] = ws
    elif net == "httpupgrade":
        ws = {"path": unquote(q.get("path", "/"))}
        if q.get("host"):
            ws["host"] = q["host"].split(",")[0]
        stream["httpupgradeSettings"] = ws
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": q.get("serviceName", "")}
    elif net in ("xhttp", "splithttp"):
        stream["xhttpSettings"] = {"path": unquote(q.get("path", "/")), "host": q.get("host", "")}

    return {
        "protocol": "trojan",
        "settings": {"servers": [{"address": u.hostname, "port": port,
                                  "password": unquote(u.username)}]},
        "streamSettings": stream,
    }


def _ss(cfg: str) -> dict | None:
    """يدعم ss://base64(method:pass)@host:port و ss://base64(method:pass@host:port) و ss://method:pass@host:port"""
    raw = _clean_uri(cfg).split("://", 1)[1]
    body_part, _, query_part = raw.partition("?")
    if query_part:
        q = parse_qs(query_part)
        if q.get("plugin"):
            return None
    body = body_part.rstrip("/")

    def build(method: str, password: str, host: str, port_str: str) -> dict | None:
        host = host.strip().strip("[]")
        method = method.strip()
        try:
            p = int(port_str.strip())
        except ValueError:
            return None
        if not host or not method or not _valid_port(p):
            return None
        return {
            "protocol": "shadowsocks",
            "settings": {"servers": [{"address": host, "port": p,
                                      "method": method, "password": password}]},
        }

    def split_host_port(hp: str) -> tuple[str, str]:
        hp = hp.rstrip("/")
        host, sep, port = hp.rpartition(":")
        if not sep:
            return "", ""
        return host, port

    def parse_plain(s: str) -> tuple[str, str, str, str] | None:
        if "@" not in s:
            return None
        mp, _, hp = s.rpartition("@")
        if ":" not in mp:
            return None
        host, port = split_host_port(hp)
        method, _, password = mp.partition(":")
        return method, password, host, port

    # 1) صيغة SIP002:  base64(method:pass)@host:port  أو  method:pass@host:port
    if "@" in body:
        left, _, right = body.rpartition("@")
        host, port = split_host_port(right)
        dec = _b64_decode_str(unquote(left))
        if dec and ":" in dec:
            method, _, password = dec.partition(":")
            res = build(method, password, host, port)
            if res:
                return res
        if ":" in left:
            method, _, password = left.partition(":")
            res = build(unquote(method), unquote(password), host, port)
            if res:
                return res

    # 2) كل شيء base64:  method:pass@host:port
    for candidate in (body, unquote(body)):
        dec = _b64_decode_str(candidate)
        if not dec:
            continue
        parsed = parse_plain(dec)
        if parsed:
            res = build(*parsed)
            if res:
                return res

    return None


# ───────────────────────── كانفيغ URI → outbound (sing-box) ─────────────────────────
def _tls_block(q: dict, host: str | None, default_alpn: str) -> dict:
    t: dict = {
        "enabled": True,
        "server_name": q.get("sni") or q.get("peer") or host,
        "insecure": q.get("insecure") in ("1", "true") or q.get("allowInsecure") in ("1", "true"),
        "alpn": [a for a in (q.get("alpn") or default_alpn).split(",") if a],
    }
    return t


def _parse_hy2_ports(port_spec: str, mport: str = "") -> tuple[int, list[str]]:
    """
    تحليل منفذ Hysteria2 المفرد أو نطاق القفز (port hopping).
    تُرجع (server_port المفرد، قائمة server_ports بصيغة start:end إن وُجد قفز منافذ).
    """
    combined = ",".join(p for p in (port_spec.strip(), mport.strip()) if p.strip())
    if not combined:
        return 443, []

    tokens = [t.strip() for t in combined.split(",") if t.strip()]
    has_hopping = len(tokens) > 1 or any("-" in t or ":" in t for t in tokens)
    if not has_hopping:
        p = int(tokens[0])
        return p, []

    ranges: list[str] = []
    first_port = 443
    for tok in tokens:
        sep = "-" if "-" in tok else (":" if ":" in tok else "")
        if sep:
            a_str, _, b_str = tok.partition(sep)
            a, b = int(a_str.strip()), int(b_str.strip())
            if _valid_port(a) and _valid_port(b) and a <= b:
                ranges.append(f"{a}:{b}")
                if first_port == 443:
                    first_port = a
        elif tok.isdigit():
            p = int(tok)
            if _valid_port(p):
                ranges.append(f"{p}:{p}")
                first_port = p
    return first_port, ranges


def _hysteria2(cfg: str) -> dict | None:
    clean = _clean_uri(cfg)
    _, sep, rest = clean.partition("://")
    if not sep:
        return None

    hier, _, query_str = rest.partition("?")
    authority = hier.split("/", 1)[0]
    if "@" in authority:
        userinfo, _, hostport = authority.rpartition("@")
    else:
        userinfo, hostport = "", authority

    if hostport.startswith("["):
        if "]" not in hostport:
            return None
        host, _, after_bracket = hostport[1:].partition("]")
        port_spec = after_bracket.lstrip(":")
    elif ":" in hostport:
        host, _, port_spec = hostport.rpartition(":")
    else:
        host, port_spec = hostport, ""

    host = host.strip()
    if not host:
        return None

    q = {k: v[0] for k, v in parse_qs(query_str).items()}
    try:
        single_port, port_ranges = _parse_hy2_ports(port_spec, q.get("mport", ""))
    except ValueError:
        return None
    if not _valid_port(single_port):
        return None

    # Hysteria2 يستخدم سلسلة المصادقة كاملة (سواء كانت password أو user:pass)
    password = unquote(userinfo)
    ob: dict = {
        "type": "hysteria2",
        "server": host,
        "password": password,
        "tls": _tls_block(q, host, "h3"),
    }
    if port_ranges:
        ob["server_ports"] = port_ranges
    else:
        ob["server_port"] = single_port

    if q.get("obfs") == "salamander" and q.get("obfs-password"):
        ob["obfs"] = {"type": "salamander", "password": q["obfs-password"]}
    if q.get("up"):
        try:
            ob["up_mbps"] = int(float(q["up"]))
        except ValueError:
            pass
    if q.get("down"):
        try:
            ob["down_mbps"] = int(float(q["down"]))
        except ValueError:
            pass
    return ob


def _tuic(cfg: str) -> dict | None:
    u, q = _query(cfg)
    if not u.hostname or not u.username:
        return None
    port = int(u.port or 443)
    if not _valid_port(port):
        return None
    return {
        "type": "tuic",
        "server": u.hostname,
        "server_port": port,
        "uuid": unquote(u.username),
        "password": unquote(u.password or ""),
        "congestion_control": q.get("congestion_control", "bbr"),
        "udp_relay_mode": q.get("udp_relay_mode", "native"),
        "tls": _tls_block(q, u.hostname, "h3"),
    }


XRAY_CONVERTERS = {"vless": _vless, "vmess": _vmess, "trojan": _trojan, "ss": _ss}
SINGBOX_CONVERTERS = {"hysteria2": _hysteria2, "hy2": _hysteria2, "tuic": _tuic}


def engine_for(cfg: str) -> str | None:
    return ENGINE_BY_SCHEME.get(cfg.split("://", 1)[0])


def to_outbound(cfg: str) -> dict | None:
    """تحويل كانفيغ إلى outbound بصيغة Xray (للمحرّك xray فقط)."""
    fn = XRAY_CONVERTERS.get(cfg.split("://", 1)[0])
    if not fn:
        return None
    try:
        return fn(cfg)
    except Exception:
        return None


def to_singbox_outbound(cfg: str) -> dict | None:
    """تحويل كانفيغ إلى outbound بصيغة sing-box (hysteria2 / hy2 / tuic)."""
    fn = SINGBOX_CONVERTERS.get(cfg.split("://", 1)[0])
    if not fn:
        return None
    try:
        return fn(cfg)
    except Exception:
        return None


# ───────────────────────── طلب HTTP عبر socks محلي ─────────────────────────
def http_via_socks(port: int, url: str, timeout: float, max_bytes: int = 0):
    """
    GET عبر socks5h على 127.0.0.1:port.
    يُرجع (status, elapsed_ms, bytes_read)، ويرفع استثناء عند الفشل.
    يضمن إغلاق المقبس في جميع الحالات ولا ينتظر جسمًا لردود 204/304 أو Content-Length: 0.
    """
    if socks is None:
        raise RuntimeError("PySocks غير مثبّت: pip install PySocks")

    u = urlsplit(url)
    host = u.hostname
    if not host:
        raise ValueError(f"Invalid URL: {url}")
    https = u.scheme == "https"
    target_port = u.port or (443 if https else 80)
    path = (u.path or "/") + (("?" + u.query) if u.query else "")

    raw = socks.socksocket()
    sock = None
    f = None
    try:
        raw.set_proxy(socks.SOCKS5, "127.0.0.1", port, rdns=True)
        raw.settimeout(timeout)
        t0 = time.perf_counter()
        raw.connect((host, target_port))

        if https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=host)
            sock.settimeout(timeout)
        else:
            sock = raw

        req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
               "User-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n")
        sock.sendall(req.encode())

        f = sock.makefile("rb")
        status_line = f.readline().decode("latin-1", "ignore")
        status = 0
        if status_line.startswith("HTTP/"):
            parts = status_line.split()
            if len(parts) > 1 and parts[1].isdigit():
                status = int(parts[1])

        content_length: int | None = None
        while True:
            line = f.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            if line.lower().startswith(b"content-length:"):
                try:
                    content_length = int(line.split(b":", 1)[1].strip())
                except ValueError:
                    pass

        no_body = (
            status in (204, 304)
            or 100 <= status < 200
            or content_length == 0
        )
        if no_body:
            return status, (time.perf_counter() - t0) * 1000, 0

        if content_length is not None and content_length > 0:
            limit = min(max_bytes, content_length) if max_bytes > 0 else content_length
        else:
            limit = max_bytes if max_bytes > 0 else 64 * 1024

        read = 0
        while read < limit:
            chunk = f.read(min(16384, limit - read))
            if not chunk:
                break
            read += len(chunk)

        return status, (time.perf_counter() - t0) * 1000, read
    finally:
        if f is not None:
            try:
                f.close()
            except Exception:
                pass
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
        try:
            raw.close()
        except Exception:
            pass


# ───────────────────────── المُختبِر ─────────────────────────
@dataclass
class Result:
    cfg: str
    ok: bool = False
    latency_ms: float = 0.0
    speed_kbps: float = 0.0
    error: str = ""
    engine: str = ""


class Tester:
    """يشغّل عدة نسخ محلية من Xray / sing-box متوازية، كل نسخة على منفذ socks خاص."""

    def __init__(self, xray_path: str | None = None, singbox_path: str | None = None,
                 concurrency: int = 16, base_port: int = 21000,
                 test_url: str = TEST_URL, timeout: float = 6.0,
                 speed_bytes: int = 1_000_000, speed_timeout: float = 8.0):
        self.xray = xray_path
        self.singbox = singbox_path
        self.concurrency = max(1, concurrency)
        self.timeout = timeout
        self.test_url = test_url
        self.speed_bytes = speed_bytes
        self.speed_timeout = speed_timeout
        self._ports: queue.Queue[int] = queue.Queue()
        port = base_port
        allocated = 0
        while allocated < self.concurrency and port < 65000:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex(("127.0.0.1", port)) != 0:
                    self._ports.put(port)
                    allocated += 1
            port += 1
        while allocated < self.concurrency:
            self._ports.put(base_port + allocated)
            allocated += 1

    # ── بناء ملف الإعداد لكل محرّك ──
    def _build(self, engine: str, cfg: str, port: int) -> tuple[list[str], dict] | None:
        if engine == "xray":
            out = to_outbound(cfg)
            if out is None or not self.xray:
                return None
            conf = {
                "log": {"loglevel": "none"},
                "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks",
                              "settings": {"udp": False, "auth": "noauth"}}],
                "outbounds": [out],
            }
            return [self.xray, "-c"], conf

        out = to_singbox_outbound(cfg)
        if out is None or not self.singbox:
            return None
        conf = {
            "log": {"level": "error", "timestamp": False},
            "inbounds": [{"type": "socks", "tag": "in",
                          "listen": "127.0.0.1", "listen_port": port}],
            "outbounds": [dict(out, tag="proxy")],
        }
        return [self.singbox, "run", "-c"], conf

    def _run_one(self, port: int, cfg: str, engine: str, measure_speed: bool) -> Result:
        res = Result(cfg=cfg, engine=engine)
        built = self._build(engine, cfg, port)
        if built is None:
            res.error = "unsupported"
            return res
        cmd_head, conf = built

        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        json.dump(conf, tmp)
        tmp.close()
        proc = subprocess.Popen(cmd_head + [tmp.name],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            wait_until = time.perf_counter() + (2.5 if engine == "singbox" else 1.5)
            opened = False
            while time.perf_counter() < wait_until:
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=0.05).close()
                    opened = True
                    break
                except OSError:
                    if proc.poll() is not None:
                        res.error = "engine-exit"
                        return res
                    time.sleep(0.03)
            if not opened:
                res.error = "no-listen"
                return res

            status, latency, _ = http_via_socks(port, self.test_url, self.timeout, 4096)
            if status not in (200, 204):
                res.error = f"http-{status or '000'}"
                return res

            res.ok = True
            res.latency_ms = latency

            if measure_speed:
                t0 = time.perf_counter()
                st2, _, nbytes = http_via_socks(port, SPEED_URL, self.speed_timeout,
                                                self.speed_bytes)
                dt = max(time.perf_counter() - t0, 1e-3)
                if st2 in (200, 206) and nbytes:
                    res.speed_kbps = (nbytes / 1024) / dt
            return res
        except Exception as exc:
            res.error = type(exc).__name__
            return res
        finally:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                    proc.wait(timeout=1)
                except Exception:
                    pass
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

    def _task(self, cfg: str, measure_speed: bool) -> Result:
        engine = engine_for(cfg)
        if engine is None:
            return Result(cfg=cfg, error="unsupported")
        if (engine == "xray" and not self.xray) or (engine == "singbox" and not self.singbox):
            return Result(cfg=cfg, error="engine-missing", engine=engine)
        port = self._ports.get()
        try:
            return self._run_one(port, cfg, engine, measure_speed)
        finally:
            self._ports.put(port)

    def _map(self, configs: list[str], measure_speed: bool, label: str) -> list[Result]:
        if not configs:
            return []
        results: list[Result] = []
        total = len(configs)
        done = 0
        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futures = {pool.submit(self._task, c, measure_speed): c for c in configs}
            for fut in as_completed(futures):
                results.append(fut.result())
                done += 1
                if done % 50 == 0 or done == total:
                    alive = sum(1 for r in results if r.ok)
                    LOG.info("%s: %d/%d (حيّ: %d)", label, done, total, alive)
        return results

    def latency_stage(self, configs: list[str]) -> list[Result]:
        return self._map(configs, measure_speed=False, label="فحص الاتصال")

    def speed_stage(self, configs: list[str]) -> list[Result]:
        return self._map(configs, measure_speed=True, label="قياس السرعة")


# للتوافق مع الاستيراد القديم
XrayTester = Tester


def pick_candidates(configs: list[str], limit: int) -> tuple[list[str], dict[str, tuple[int, int]]]:
    """
    اختيار عيّنة متوازنة بين البروتوكولات (round-robin) بدل أخذ أول N.
    الترتيب داخل كل بروتوكول محفوظ (أي أن أولوية المصادر تبقى).
    يُرجع (العيّنة، {البروتوكول: (المأخوذ، الإجمالي)}).
    """
    groups: dict[str, list[str]] = {}
    order: list[str] = []
    for c in configs:
        s = c.split("://", 1)[0]
        if s not in groups:
            groups[s] = []
            order.append(s)
        groups[s].append(c)

    idx = {s: 0 for s in order}
    picked: list[str] = []
    while len(picked) < limit:
        progressed = False
        for s in order:
            if idx[s] < len(groups[s]):
                picked.append(groups[s][idx[s]])
                idx[s] += 1
                progressed = True
                if len(picked) >= limit:
                    break
        if not progressed:
            break

    info = {s: (idx[s], len(groups[s])) for s in order}
    return picked, info


def select_best(
    configs: list[str],
    xray_path: str | None = None,
    singbox_path: str | None = None,
    test_top: int = 800,
    speed_top: int = 300,
    concurrency: int = 16,
    rank_by: str = "speed",
    timeout: float = 6.0,
) -> tuple[list[Result], list[Result], int]:
    """
    يشغّل مراحل الفحص ويُرجع (نتائج المرحلة الأولى، المرتّبة، عدد المتخطّى).
    المرحلة 1: فحص اتصال حقيقي (latency) لأول test_top كانفيغ.
    المرحلة 2: قياس سرعة تنزيل لأفضل speed_top منها (إن كان speed_top > 0).
    """
    def supported(c: str) -> bool:
        e = engine_for(c)
        return bool((e == "xray" and xray_path) or (e == "singbox" and singbox_path))

    testable = [c for c in configs if supported(c)]
    skipped = len(configs) - len(testable)
    candidates, info = pick_candidates(testable, test_top)
    LOG.info("فحص فعلي: %d كانفيغ بعيّنة متوازنة (تخطّي %d: ssr أو محرّك غير متاح)",
             len(candidates), skipped)
    LOG.info("توزيع العيّنة: %s",
             " | ".join(f"{s}: {got}/{tot}" for s, (got, tot) in info.items()))

    tester = Tester(xray_path, singbox_path, concurrency=concurrency, timeout=timeout)
    t0 = time.perf_counter()
    lat = tester.latency_stage(candidates)
    alive = sorted([r for r in lat if r.ok], key=lambda r: r.latency_ms)
    LOG.info("نجح %d من %d في %.0f ثانية", len(alive), len(candidates),
             time.perf_counter() - t0)

    if not alive:
        return lat, [], skipped

    speed_candidates = [r.cfg for r in alive if r.latency_ms <= 5000][:max(0, speed_top)]
    sp_by_cfg: dict[str, Result] = {}
    if speed_candidates:
        LOG.info("قياس السرعة لـ %d عقدة …", len(speed_candidates))
        sp = tester.speed_stage(speed_candidates)
        sp_by_cfg = {r.cfg: r for r in sp}

    merged: list[Result] = []
    for r in alive:
        m = sp_by_cfg.get(r.cfg)
        if m:
            r.speed_kbps = m.speed_kbps
        merged.append(r)

    if rank_by == "latency":
        merged.sort(key=lambda r: (r.latency_ms, -r.speed_kbps))
    else:
        with_speed = sorted([r for r in merged if r.speed_kbps > 0],
                            key=lambda r: (-r.speed_kbps, r.latency_ms))
        without = [r for r in merged if r.speed_kbps <= 0]
        merged = with_speed + without

    return lat, merged, skipped


# ───────────────────────── أدوات إضافية ─────────────────────────
def host_of(cfg: str) -> str:
    """استخراج اسم المضيف من أي كانفيغ (لتنويع المصادر)."""
    scheme, _, rest = _clean_uri(cfg).partition("://")
    if scheme == "vmess":
        dec = _b64_decode_str(rest.split("?", 1)[0])
        if not dec:
            return ""
        try:
            j = json.loads(dec)
            return str(j.get("add", "")).strip().strip("[]").lower()
        except Exception:
            return ""

    if "@" not in rest:
        dec = _b64_decode_str(rest.split("?", 1)[0].rstrip("/"))
        if not dec or "@" not in dec:
            return ""
        rest = dec

    hp = rest.rsplit("@", 1)[-1].split("/", 1)[0].split("?", 1)[0].strip()
    if hp.startswith("[") and "]" in hp:
        return hp[1:].partition("]")[0].lower()
    if ":" in hp:
        return hp.rpartition(":")[0].strip("[]").lower()
    return hp.strip("[]").lower()


def limit_per_host(results: list[Result], limit: int) -> list[Result]:
    """
    تنويع النتائج: لا يزيد عدد العُقد المأخوذة من نفس المضيف عن limit.
    يمنع أن يمتلئ ملف «الأفضل» كله بعُقد من مزوّد واحد (تنتهي معًا عادة).
    limit=0 يعني بلا حد.
    """
    if not limit:
        return results
    counts: dict[str, int] = {}
    out: list[Result] = []
    for r in results:
        h = host_of(r.cfg)
        if h and counts.get(h, 0) >= limit:
            continue
        if h:
            counts[h] = counts.get(h, 0) + 1
        out.append(r)
    return out


def write_report(lat_results: list[Result], path: Path) -> int:
    """حفظ نتائج الفحص في CSV لمراجعة ما نجح وما فشل (بلا إعادة فحص)."""
    lines = ["status,engine,latency_ms,speed_kbps,error,config"]
    for r in sorted(lat_results, key=lambda x: (not x.ok, x.latency_ms)):
        cfg = r.cfg.replace('"', "'")
        lines.append(f"{'ok' if r.ok else 'fail'},{r.engine},{r.latency_ms:.0f},"
                     f"{r.speed_kbps:.0f},{r.error},\"{cfg}\"")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    tmp.replace(path)
    return len(lines) - 1


def main(argv: list[str] | None = None) -> int:
    """فحص ملف كانفيغات جاهز (بدون جمع) — مفيد لإعادة الفحص لاحقًا."""
    ap = argparse.ArgumentParser(description="فحص كانفيغات VPN فعليًا واختيار الأسرع")
    ap.add_argument("-i", "--input", default="config.txt")
    ap.add_argument("--best-out", default="best.txt")
    ap.add_argument("--best", type=int, default=100)
    ap.add_argument("--test-top", type=int, default=800)
    ap.add_argument("--speed-top", type=int, default=300)
    ap.add_argument("--concurrency", type=int, default=16)
    ap.add_argument("--rank-by", choices=("speed", "latency"), default="speed")
    ap.add_argument("--max-per-host", type=int, default=3)
    ap.add_argument("--test-timeout", type=float, default=6.0)
    ap.add_argument("--xray")
    ap.add_argument("--singbox")
    ap.add_argument("--report", default="test-report.csv")
    ap.add_argument("--no-download", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(message)s")

    configs = [
        _clean_uri(ln)
        for ln in Path(args.input).read_text(encoding="utf-8").splitlines()
        if "://" in ln
    ]
    LOG.info("قرأت %d كانفيغ من %s", len(configs), args.input)
    if not configs:
        return 1

    xray = args.xray or ensure_xray(allow_download=not args.no_download)
    sbox = args.singbox or ensure_singbox(allow_download=not args.no_download)

    lat, best, skipped = select_best(configs, xray, sbox, test_top=args.test_top,
                                     speed_top=args.speed_top, concurrency=args.concurrency,
                                     rank_by=args.rank_by, timeout=args.test_timeout)
    if args.report:
        LOG.info("تقرير: %s (%d كانفيغ)", args.report, write_report(lat, Path(args.report)))
    if not best:
        LOG.error("لا عقدة ناجحة.")
        return 1

    best = limit_per_host(best, args.max_per_host)
    out = Path(args.best_out)
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for i, r in enumerate(best[:args.best], 1):
        speed = f"{r.speed_kbps:.0f}KB/s" if r.speed_kbps > 0 else "—"
        label = f"bahrain-vpn {i} | {r.latency_ms:.0f}ms | {speed}"
        if r.cfg.startswith("vmess://"):
            try:
                j = json.loads(_b64(r.cfg[8:]).decode("utf-8", "replace"))
                if isinstance(j, dict):
                    j["ps"] = label
                    enc = base64.b64encode(
                        json.dumps(j, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                    ).decode("ascii")
                    lines.append(f"vmess://{enc}")
                    continue
            except Exception:
                pass
        lines.append(f"{r.cfg}#{label}")
    tmp = out.with_name(out.name + ".tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    tmp.replace(out)
    LOG.info("كتبت %s (أفضل %d من %d حيّة، تخطّي %d)",
             out, len(lines), len(best), skipped)
    return 0


if __name__ == "__main__":
    sys.exit(main())
