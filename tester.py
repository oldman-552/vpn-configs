#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tester.py — فحص متعدّد المراحل للكانفيغات عبر أنفاق فعلية (Xray + sing-box).

مراحل التحقّق (L1–L5):
  • L1: فحص بنيوي وأمني (منع العناوين الداخلية/المحلية وبيانات الاعتماد المشوّهة).
  • L2/L3: تشغيل نواة معزولة (بيئة نظيفة بدون متغيرات أسرار) واختبار مرور HTTP فعلي عبر SOCKS5h.
  • L4: فحص استقرار متعدّد الجولات داخل النفق لقياس الوسيط الحقيقي (median RTT)، التذبذب (jitter)،
        ونسبة النجاح، مع استخلاص دولة الخروج الفعلية عبر Cloudflare `/cdn-cgi/trace`.
  • L5: قياس سرعة التنزيل المحدود زمنيًا وحجميًا لأفضل العُقد الحيّة.
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
import shutil
import socket
import ssl
import stat
import statistics
import subprocess
import sys
import tempfile
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

import requests

from dedupe import canonical_protocol, parse_identity
from pipeline_security import (
    MAX_BINARY_BYTES,
    SecurityError,
    is_unsafe_config_host,
    redact_uri,
    safe_extract_tar_binary,
    verify_sha256,
)

try:
    import socks  # PySocks: للاتصال عبر socks5h
except ImportError:
    socks = None

LOG = logging.getLogger("tester")

DEFAULT_BIN_DIR = Path(__file__).resolve().parent / "bin"
TEST_URL = "https://www.gstatic.com/generate_204"
TRACE_URL = "https://cp.cloudflare.com/cdn-cgi/trace"
SPEED_URL = "https://speed.cloudflare.com/__down?bytes=750000"
MAX_SPEED_BYTES = 1_048_576
FALLBACK_SINGBOX_VERSION = "1.14.4"

ENGINE_BY_SCHEME = {
    "vless": "xray",
    "vmess": "xray",
    "trojan": "xray",
    "ss": "xray",
    "hysteria2": "singbox",
    "hy2": "singbox",
    "tuic": "singbox",
    "socks": "singbox",
    "socks5": "singbox",
    "http": "singbox",
    "https": "singbox",
}
XRAY_SCHEMES = ("vless", "vmess", "trojan", "ss")
SINGBOX_SCHEMES = ("hysteria2", "hy2", "tuic", "socks", "socks5", "http", "https")

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


# ───────────────────────── تنزيل النوى وتجهيزها مع فحص SHA-256 ─────────────────────────
def _platform_key() -> tuple[str, str]:
    return platform.system().lower(), platform.machine().lower()


def _gh_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "vpn-configs/2.0"}
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    return headers


def _download_bounded(url: str, dest: Path, timeout: int = 180) -> None:
    with requests.get(url, timeout=timeout, stream=True) as resp:
        resp.raise_for_status()
        total = 0
        with dest.open("wb") as f:
            for chunk in resp.iter_content(chunk_size=131_072):
                if not chunk:
                    continue
                total += len(chunk)
                if total > MAX_BINARY_BYTES:
                    raise SecurityError(f"Binary download exceeded {MAX_BINARY_BYTES} bytes")
                f.write(chunk)


def ensure_xray(
    bin_dir: Path | None = DEFAULT_BIN_DIR,
    allow_download: bool = True,
    *,
    auto_download: bool | None = None,
) -> str | None:
    """إرجاع مسار Xray القابل للتنفيذ؛ وتنزيله والتحقّق من بصمته SHA-256 إن لم يوجد."""
    if auto_download is not None:
        allow_download = auto_download
    target = bin_dir or DEFAULT_BIN_DIR
    if target.is_file() and os.access(target, os.X_OK):
        return str(target)

    exe = target / ("xray.exe" if os.name == "nt" else "xray")
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
        target.mkdir(parents=True, exist_ok=True)
        LOG.info("تنزيل Xray (%s) …", asset)
        url: str | None = None
        expected_digest: str | None = None
        try:
            rel_resp = requests.get(
                "https://api.github.com/repos/XTLS/Xray-core/releases/latest",
                headers=_gh_headers(),
                timeout=20,
            )
            if rel_resp.status_code == 200:
                rel = rel_resp.json()
                for a in rel.get("assets", []):
                    if a.get("name") == asset:
                        url = a.get("browser_download_url")
                        expected_digest = a.get("digest")
                        break
        except Exception as api_exc:
            LOG.debug("تعذّر استعلام GitHub API لـ Xray (%s)، استخدام الرابط المباشر.", api_exc)

        if not url:
            url = f"https://github.com/XTLS/Xray-core/releases/latest/download/{asset}"

        zpath = target / "xray.zip"
        _download_bounded(url, zpath, timeout=180)
        if expected_digest:
            verify_sha256(zpath, expected_digest)
            LOG.info("تم التحقّق من بصمة SHA-256 لأرشيف Xray بنجاح.")

        allowed_files = {"xray", "xray.exe", "geoip.dat", "geosite.dat"}
        with zipfile.ZipFile(zpath) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                mp = Path(info.filename)
                if ".." in mp.parts:
                    raise SecurityError(f"Path traversal in Xray zip: {info.filename}")
                if mp.name in allowed_files and info.file_size <= MAX_BINARY_BYTES:
                    out_file = target / mp.name
                    with zf.open(info) as src, out_file.open("wb") as dst:
                        dst.write(src.read(MAX_BINARY_BYTES + 1))

        zpath.unlink(missing_ok=True)
        exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
        LOG.info("جاهز: %s", exe)
        return str(exe)
    except Exception as exc:
        LOG.error("فشل تجهيز Xray: %s", exc)
        return None


def _resolve_singbox_release(asset_suffix: str) -> tuple[str, str | None, str | None]:
    """إرجاع (version, download_url, sha256_digest) لأحدث إصدار sing-box."""
    try:
        r = requests.get(
            "https://api.github.com/repos/SagerNet/sing-box/releases/latest",
            headers=_gh_headers(),
            timeout=20,
        )
        if r.status_code == 200:
            rel = r.json()
            ver = rel.get("tag_name", "").lstrip("v") or FALLBACK_SINGBOX_VERSION
            expected_name = (
                f"sing-box-{ver}-{asset_suffix}"
                if asset_suffix.endswith(".zip")
                else f"sing-box-{ver}-{asset_suffix}.tar.gz"
            )
            for a in rel.get("assets", []):
                if a.get("name") == expected_name:
                    return ver, a.get("browser_download_url"), a.get("digest")
            return ver, None, None
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
                return tag, None, None
    except Exception:
        pass
    return FALLBACK_SINGBOX_VERSION, None, None


def ensure_singbox(
    bin_dir: Path | None = DEFAULT_BIN_DIR,
    allow_download: bool = True,
    *,
    auto_download: bool | None = None,
) -> str | None:
    """إرجاع مسار sing-box القابل للتنفيذ؛ وتنزيله مع التحقّق من بصمة SHA-256."""
    if auto_download is not None:
        allow_download = auto_download
    target = bin_dir or DEFAULT_BIN_DIR
    if target.is_file() and os.access(target, os.X_OK):
        return str(target)

    exe = target / ("sing-box.exe" if os.name == "nt" else "sing-box")
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
        target.mkdir(parents=True, exist_ok=True)
        version, url, expected_digest = _resolve_singbox_release(suffix)
        name = (
            f"sing-box-{version}-{suffix}"
            if suffix.endswith(".zip")
            else f"sing-box-{version}-{suffix}.tar.gz"
        )
        if not url:
            url = f"https://github.com/SagerNet/sing-box/releases/download/v{version}/{name}"
        LOG.info("تنزيل sing-box v%s (%s) …", version, suffix)

        archive = target / name
        _download_bounded(url, archive, timeout=240)
        if expected_digest:
            verify_sha256(archive, expected_digest)
            LOG.info("تم التحقّق من بصمة SHA-256 لأرشيف sing-box بنجاح.")

        if name.endswith(".zip"):
            from pipeline_security import safe_extract_zip_binary
            safe_extract_zip_binary(archive, {"sing-box", "sing-box.exe"}, exe)
        else:
            safe_extract_tar_binary(archive, {"sing-box", "sing-box.exe"}, exe)

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
    if not u.hostname or not u.username or is_unsafe_config_host(u.hostname):
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
        stream["xhttpSettings"] = {"path": unquote(q.get("path", "/")), "host": q.get("host", "")}
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
    if flow and net != "tcp":
        flow = ""
    return {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": u.hostname,
                "port": port,
                "users": [{
                    "id": unquote(u.username),
                    "encryption": q.get("encryption", "none") or "none",
                    "flow": flow,
                }],
            }]
        },
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
    if not addr or not uid or not _valid_port(port) or is_unsafe_config_host(addr):
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
            tls["alpn"] = (
                alpn_val if isinstance(alpn_val, list) else [a for a in str(alpn_val).split(",") if a]
            )
        stream["tlsSettings"] = tls

    try:
        aid = int(str(j.get("aid") or 0).strip())
    except ValueError:
        aid = 0

    return {
        "protocol": "vmess",
        "settings": {
            "vnext": [{
                "address": addr,
                "port": port,
                "users": [{
                    "id": uid,
                    "alterId": aid,
                    "security": str(j.get("scy") or "auto") or "auto",
                }],
            }]
        },
        "streamSettings": stream,
    }


def _trojan(cfg: str) -> dict | None:
    u, q = _query(cfg)
    if not u.hostname or not u.username or is_unsafe_config_host(u.hostname):
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
        "settings": {"servers": [{"address": u.hostname, "port": port, "password": unquote(u.username)}]},
        "streamSettings": stream,
    }


def _ss(cfg: str) -> dict | None:
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
        if not host or not method or not _valid_port(p) or is_unsafe_config_host(host):
            return None
        return {
            "protocol": "shadowsocks",
            "settings": {"servers": [{"address": host, "port": p, "method": method, "password": password}]},
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
    return {
        "enabled": True,
        "server_name": q.get("sni") or q.get("peer") or host,
        "insecure": q.get("insecure") in ("1", "true") or q.get("allowInsecure") in ("1", "true"),
        "alpn": [a for a in (q.get("alpn") or default_alpn).split(",") if a],
    }


def _parse_hy2_ports(port_spec: str, mport: str = "") -> tuple[int, list[str]]:
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
    if not host or is_unsafe_config_host(host):
        return None

    q = {k: v[0] for k, v in parse_qs(query_str).items()}
    try:
        single_port, port_ranges = _parse_hy2_ports(port_spec, q.get("mport", ""))
    except ValueError:
        return None
    if not _valid_port(single_port):
        return None

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
    if not u.hostname or not u.username or is_unsafe_config_host(u.hostname):
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


def _socks_sb(cfg: str) -> dict | None:
    ident = parse_identity(cfg, reject_private_hosts=True)
    if ident is None or ident.canonical_proto != "socks":
        return None
    u, _ = _query(cfg)
    if not u.hostname or is_unsafe_config_host(u.hostname):
        return None
    port = int(u.port or 1080)
    if not _valid_port(port):
        return None
    ob: dict = {
        "type": "socks",
        "server": u.hostname,
        "server_port": port,
        "version": "5",
    }
    if u.username:
        ob["username"] = unquote(u.username)
        ob["password"] = unquote(u.password or "")
    return ob


def _http_sb(cfg: str) -> dict | None:
    ident = parse_identity(cfg, reject_private_hosts=True)
    if ident is None or ident.canonical_proto != "http":
        return None
    u, q = _query(cfg)
    if not u.hostname or is_unsafe_config_host(u.hostname):
        return None
    is_https = u.scheme.lower() == "https" or q.get("security", "").lower() == "tls"
    port = int(u.port or (443 if is_https else 8080))
    if not _valid_port(port):
        return None
    ob: dict = {
        "type": "http",
        "server": u.hostname,
        "server_port": port,
    }
    if u.username:
        ob["username"] = unquote(u.username)
        ob["password"] = unquote(u.password or "")
    if is_https:
        ob["tls"] = _tls_block(q, u.hostname, "http/1.1")
    return ob


XRAY_CONVERTERS = {"vless": _vless, "vmess": _vmess, "trojan": _trojan, "ss": _ss}
SINGBOX_CONVERTERS = {
    "hysteria2": _hysteria2,
    "hy2": _hysteria2,
    "tuic": _tuic,
    "socks": _socks_sb,
    "socks5": _socks_sb,
    "http": _http_sb,
    "https": _http_sb,
}


def engine_for(cfg: str) -> str | None:
    return ENGINE_BY_SCHEME.get(cfg.split("://", 1)[0].lower())


def to_outbound(cfg: str) -> dict | None:
    """تحويل كانفيغ إلى outbound بصيغة Xray (مع رفض الوجهات المحلية/الخاصة)."""
    fn = XRAY_CONVERTERS.get(cfg.split("://", 1)[0].lower())
    if not fn:
        return None
    try:
        return fn(cfg)
    except Exception:
        return None


def to_singbox_outbound(cfg: str) -> dict | None:
    """تحويل كانفيغ إلى outbound بصيغة sing-box (hysteria2 / hy2 / tuic)."""
    fn = SINGBOX_CONVERTERS.get(cfg.split("://", 1)[0].lower())
    if not fn:
        return None
    try:
        return fn(cfg)
    except Exception:
        return None


# ───────────────────────── طلبات HTTP عبر socks5h المحلي ─────────────────────────
def _open_socks_stream(port: int, host: str, dst_port: int, use_tls: bool, timeout: float):
    if socks is None:
        raise RuntimeError("PySocks غير مثبّت: pip install PySocks")
    raw = socks.socksocket()
    raw.set_proxy(socks.SOCKS5, "127.0.0.1", port, rdns=True)
    raw.settimeout(timeout)
    raw.connect((host, dst_port))
    if use_tls:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(raw, server_hostname=host)
        conn.settimeout(timeout)
        return conn
    return raw


def http_via_socks(port: int, url: str, timeout: float, max_bytes: int = 0) -> tuple[int, float, int]:
    """
    GET عبر socks5h على 127.0.0.1:port مع حدّ صارم للحجم والزمن الكلي.
    يُرجع (status, elapsed_ms, bytes_read).
    """
    u = urlsplit(url)
    use_tls = u.scheme == "https"
    host = u.hostname or ""
    dst_port = u.port or (443 if use_tls else 80)
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")

    t_start = time.perf_counter()
    deadline = t_start + max(timeout, 1.0)
    conn = None
    try:
        conn = _open_socks_stream(port, host, dst_port, use_tls, timeout)
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Connection: close\r\n\r\n"
        )
        t_req = time.perf_counter()
        conn.sendall(req.encode("ascii"))

        buf = bytearray()
        while b"\r\n\r\n" not in buf:
            if time.perf_counter() > deadline:
                raise TimeoutError("header timeout")
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) > 65536:
                break

        head, _, rest = bytes(buf).partition(b"\r\n\r\n")
        status_line = head.split(b"\r\n", 1)[0].decode("latin1", "ignore")
        parts = status_line.split()
        status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0

        if status in (204, 304) or b"content-length: 0" in head.lower():
            return status, max(0.5, (time.perf_counter() - t_req) * 1000.0), 0

        cap = min(max_bytes, MAX_SPEED_BYTES) if max_bytes > 0 else MAX_SPEED_BYTES
        body_len = len(rest)
        while body_len < cap:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                break
            conn.settimeout(min(timeout, max(0.3, remaining)))
            chunk = conn.recv(32768)
            if not chunk:
                break
            body_len += len(chunk)

        elapsed_ms = max(0.5, (time.perf_counter() - t_req) * 1000.0)
        return status, elapsed_ms, body_len
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def trace_via_socks(port: int, timeout: float = 4.0) -> tuple[bool, float, str, bool]:
    """
    طلب Cloudflare `/cdn-cgi/trace` عبر النفق لاستخلاص:
      (ok, elapsed_ms, exit_country_iso2, is_warp)
    يؤدّي وظيفتين في طلب واحد (حوالي 180 بايت فقط):
      1) عيّنة RTT إضافية لفحص الاستقرار (المرحلة L4).
      2) كشف دولة الخروج الحقيقية من خلف النفق (وليس مجرّد IP الدخول أو CDN).
    """
    u = urlsplit(TRACE_URL)
    host = u.hostname or "cp.cloudflare.com"
    use_tls = u.scheme == "https"
    dst_port = u.port or (443 if use_tls else 80)
    path = u.path or "/cdn-cgi/trace"

    conn = None
    try:
        conn = _open_socks_stream(port, host, dst_port, use_tls, timeout)
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: curl/8.5.0\r\n"
            f"Connection: close\r\n\r\n"
        )
        t_req = time.perf_counter()
        conn.sendall(req.encode("ascii"))
        buf = bytearray()
        while len(buf) < 4096:
            chunk = conn.recv(2048)
            if not chunk:
                break
            buf.extend(chunk)
        elapsed_ms = max(0.5, (time.perf_counter() - t_req) * 1000.0)
        head, _, body = bytes(buf).partition(b"\r\n\r\n")
        status_line = head.split(b"\r\n", 1)[0].decode("latin1", "ignore")
        parts = status_line.split()
        status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
        if status != 200 or b"loc=" not in body:
            return False, elapsed_ms, "XX", False

        kv: dict[str, str] = {}
        for line in body.decode("utf-8", "ignore").splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                kv[k.strip()] = v.strip()
        loc = kv.get("loc", "XX").upper()
        if len(loc) != 2 or not loc.isalpha() or loc in ("XX", "T1"):
            loc = "XX"
        is_warp = kv.get("warp", "off").lower() in ("on", "plus")
        return True, elapsed_ms, loc, is_warp
    except Exception:
        return False, 0.0, "XX", False
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


# ───────────────────────── الفاحص المتوازي متعدّد الجولات ─────────────────────────
@dataclass
class Result:
    cfg: str
    ok: bool
    latency_ms: float = 0.0
    speed_kbps: float = 0.0
    error: str = ""
    engine: str = ""
    median_latency_ms: float = 0.0
    jitter_ms: float = 0.0
    probe_pass_rate: float = 0.0
    probes_ok: int = 0
    probes_total: int = 0
    exit_country: str = "XX"
    country_source: str = "unknown"
    is_warp: bool = False
    score: float = 0.0


def _free_ports(n: int) -> list[int]:
    socks_list = []
    ports = []
    for _ in range(n):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        ports.append(s.getsockname()[1])
        socks_list.append(s)
    for s in socks_list:
        s.close()
    return ports


def _wait_port(port: int, proc: subprocess.Popen, deadline: float) -> bool:
    while time.perf_counter() < deadline:
        if proc.poll() is not None:
            return False
        with socket.socket() as s:
            s.settimeout(0.05)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.02)
    return False


def _xray_config(port: int, outbound: dict) -> dict:
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "socks",
            "settings": {"udp": True},
        }],
        "outbounds": [outbound],
    }


def _singbox_config(port: int, outbound: dict) -> dict:
    ob = dict(outbound)
    ob["domain_resolver"] = "bootstrap"
    return {
        "log": {"disabled": True},
        "dns": {
            "servers": [{"type": "udp", "tag": "bootstrap", "server": "1.1.1.1"}],
        },
        "inbounds": [{
            "type": "socks",
            "listen": "127.0.0.1",
            "listen_port": port,
        }],
        "outbounds": [ob],
        "route": {"default_domain_resolver": "bootstrap"},
    }


def _sanitized_subprocess_env(work_dir: str) -> dict[str, str]:
    """بيئة معزولة للنوى الفرعية تمنع تسرّب متغيرات بيئة CI مثل GITHUB_TOKEN."""
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": work_dir,
        "TMPDIR": work_dir,
    }
    for ssl_var in ("SSL_CERT_FILE", "SSL_CERT_DIR", "SYSTEMROOT"):
        if os.environ.get(ssl_var):
            env[ssl_var] = os.environ[ssl_var]
    return env


def _compute_jitter(samples: list[float]) -> float:
    if len(samples) < 2:
        return 0.0
    diffs = [abs(samples[i] - samples[i - 1]) for i in range(1, len(samples))]
    return sum(diffs) / len(diffs)


class Tester:
    """فاحص متوازٍ محصّن أمنيًا يدعم Xray وsing-box مع فحص استقرار متعدّد الجولات."""

    def __init__(
        self,
        xray_path: str | None = None,
        singbox_path: str | None = None,
        concurrency: int = 16,
        timeout: float = 6.0,
        stability_probes: int = 3,
    ):
        if socks is None:
            raise RuntimeError("PySocks مطلوب للفحص: pip install PySocks")
        self.xray = xray_path
        self.singbox = singbox_path
        self.concurrency = max(1, concurrency)
        self.timeout = timeout
        self.stability_probes = max(1, min(5, stability_probes))
        self._ports: queue.Queue[int] = queue.Queue()
        for p in _free_ports(self.concurrency * 2):
            self._ports.put(p)
        self._tmp = Path(tempfile.mkdtemp(prefix="vpntest_"))
        try:
            self._tmp.chmod(0o700)
        except OSError:
            pass

    def close(self) -> None:
        if getattr(self, "_tmp", None) is not None:
            shutil.rmtree(self._tmp, ignore_errors=True)

    def __enter__(self) -> "Tester":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _build_command(self, cfg: str, port: int, cfg_file: Path) -> tuple[list[str], str] | tuple[None, str]:
        eng = engine_for(cfg)
        if eng == "xray":
            if not self.xray:
                return None, "no_xray"
            ob = to_outbound(cfg)
            if not ob:
                return None, "unsupported_or_unsafe"
            cfg_file.write_text(json.dumps(_xray_config(port, ob)), encoding="utf-8")
            return [self.xray, "run", "-c", str(cfg_file)], "xray"

        if eng == "singbox":
            if not self.singbox:
                return None, "no_singbox"
            ob = to_singbox_outbound(cfg)
            if not ob:
                return None, "unsupported_or_unsafe"
            cfg_file.write_text(json.dumps(_singbox_config(port, ob)), encoding="utf-8")
            return [self.singbox, "run", "-c", str(cfg_file)], "singbox"

        return None, "unsupported_scheme"

    def _run(self, cfg: str, port: int, measure_speed: bool) -> Result:
        cfg_file = self._tmp / f"c_{port}_{time.monotonic_ns()}.json"
        cmd, tag = self._build_command(cfg, port, cfg_file)
        if cmd is None:
            return Result(cfg, False, error=tag)

        proc: subprocess.Popen | None = None
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=_sanitized_subprocess_env(str(self._tmp)),
                close_fds=(os.name != "nt"),
            )
            if not _wait_port(port, proc, time.perf_counter() + 2.5):
                return Result(cfg, False, error="core_died", engine=tag)

            # L3: Probe #1 — real end-to-end HTTP 204 over proxy tunnel
            try:
                st, lat1, _ = http_via_socks(port, TEST_URL, self.timeout)
            except Exception as exc:
                return Result(cfg, False, error=type(exc).__name__, engine=tag, probes_ok=0, probes_total=1)
            if st not in (200, 204):
                return Result(cfg, False, error=f"http_{st}", engine=tag, probes_ok=0, probes_total=1)

            samples: list[float] = [lat1]
            probes_ok = 1
            probes_total = 1
            exit_cc = "XX"
            cc_source = "unknown"
            is_warp = False

            # L4: Multi-probe stability + real exit country via Cloudflare trace (on same live tunnel)
            if self.stability_probes >= 2 and not measure_speed:
                probes_total += 1
                tr_ok, tr_lat, loc, warp_flag = trace_via_socks(port, timeout=min(self.timeout, 4.0))
                if tr_ok:
                    probes_ok += 1
                    samples.append(tr_lat)
                    if loc != "XX":
                        exit_cc = loc
                        cc_source = "exit_trace"
                    is_warp = warp_flag

            for _ in range(max(0, self.stability_probes - probes_total) if not measure_speed else 0):
                probes_total += 1
                try:
                    st2, lat_n, _ = http_via_socks(port, TEST_URL, min(self.timeout, 4.5))
                    if st2 in (200, 204):
                        probes_ok += 1
                        samples.append(lat_n)
                except Exception:
                    pass

            med_lat = statistics.median(samples)
            jitter = _compute_jitter(samples)
            pass_rate = probes_ok / max(1, probes_total)

            # L5: Bounded throughput check
            speed = 0.0
            if measure_speed:
                try:
                    st_sp, ms, nbytes = http_via_socks(
                        port, SPEED_URL, self.timeout + 4.0, max_bytes=MAX_SPEED_BYTES
                    )
                    if st_sp == 200 and ms > 0 and nbytes >= 16_384:
                        speed = (nbytes / 1024.0) / (ms / 1000.0)
                except Exception:
                    speed = 0.0

            return Result(
                cfg=cfg,
                ok=True,
                latency_ms=med_lat,
                speed_kbps=speed,
                engine=tag,
                median_latency_ms=med_lat,
                jitter_ms=jitter,
                probe_pass_rate=pass_rate,
                probes_ok=probes_ok,
                probes_total=probes_total,
                exit_country=exit_cc,
                country_source=cc_source,
                is_warp=is_warp,
            )
        finally:
            if proc is not None:
                if proc.poll() is None:
                    proc.terminate()
                try:
                    proc.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    try:
                        proc.wait(timeout=1.0)
                    except Exception:
                        pass
            cfg_file.unlink(missing_ok=True)

    def _task(self, cfg: str, measure_speed: bool) -> Result:
        port = self._ports.get()
        try:
            return self._run(cfg, port, measure_speed)
        finally:
            self._ports.put(port)

    def _map(self, configs: list[str], measure_speed: bool, label: str) -> list[Result]:
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
        return self._map(configs, measure_speed=False, label="فحص الاتصال والاستقرار")

    def speed_stage(self, configs: list[str]) -> list[Result]:
        return self._map(configs, measure_speed=True, label="قياس السرعة")


XrayTester = Tester


def pick_candidates(configs: list[str], limit: int) -> tuple[list[str], dict[str, tuple[int, int]]]:
    """
    اختيار عيّنة متوازنة بين البروتوكولات (round-robin) مع الحفاظ على ترتيب الأولوية.
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


def pick_smart_candidates(
    configs: list[str],
    limit: int,
    *,
    prior_alive_ids: set[str] | None = None,
    corroborated_ids: set[str] | None = None,
    max_per_host_sample: int = 8,
) -> tuple[list[str], dict[str, tuple[int, int]]]:
    """
    اختيار ذكي للعيّنة يجمع بين:
      1) إعادة التحقّق من العُقد الحيّة السابقة (حتى 35% من الميزانية) لبناء استقرار طولي حقيقي (L6).
      2) تفضيل العُقد المؤكّدة من عدّة مصادر مستقلّة.
      3) استكشاف متوازن بين البروتوكولات المعيارية (يوحّد hy2 وhysteria2) مع سقف لكل مضيف.
    """
    prior_ids = prior_alive_ids or set()
    corr_ids = corroborated_ids or set()

    prior_bucket: list[str] = []
    corr_bucket: list[str] = []
    rest_bucket: list[str] = []
    host_seen: dict[str, int] = {}

    for c in configs:
        ident = parse_identity(c, reject_private_hosts=True)
        if ident is None:
            continue
        if max_per_host_sample > 0 and host_seen.get(ident.host, 0) >= max_per_host_sample:
            continue
        host_seen[ident.host] = host_seen.get(ident.host, 0) + 1

        if ident.identity_id in prior_ids:
            prior_bucket.append(c)
        elif ident.identity_id in corr_ids:
            corr_bucket.append(c)
        else:
            rest_bucket.append(c)

    prior_cap = min(len(prior_bucket), int(limit * 0.35))
    seeded = prior_bucket[:prior_cap]
    remaining_pool = prior_bucket[prior_cap:] + corr_bucket + rest_bucket

    # Round-robin across canonical protocols on the remaining budget
    groups: dict[str, list[str]] = {}
    order: list[str] = []
    for c in remaining_pool:
        p = canonical_protocol(c.split("://", 1)[0])
        if p not in groups:
            groups[p] = []
            order.append(p)
        groups[p].append(c)

    idx = {p: 0 for p in order}
    picked = list(seeded)
    while len(picked) < limit:
        progressed = False
        for p in order:
            if idx[p] < len(groups[p]):
                picked.append(groups[p][idx[p]])
                idx[p] += 1
                progressed = True
                if len(picked) >= limit:
                    break
        if not progressed:
            break

    # Tally totals by canonical protocol
    totals: dict[str, int] = {}
    taken: dict[str, int] = {}
    picked_set = set(picked)
    for c in configs:
        p = canonical_protocol(c.split("://", 1)[0])
        totals[p] = totals.get(p, 0) + 1
        if c in picked_set:
            taken[p] = taken.get(p, 0) + 1
    info = {p: (taken.get(p, 0), tot) for p, tot in totals.items()}
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
    prior_alive_ids: set[str] | None = None,
    corroborated_ids: set[str] | None = None,
    stability_probes: int = 3,
) -> tuple[list[Result], list[Result], int]:
    """
    يشغّل مراحل الفحص (الاتصال + الاستقرار + دولة الخروج + السرعة) ويُرجع (نتائج المرحلة الأولى، المرتّبة، المتخطّى).
    """
    def supported(c: str) -> bool:
        e = engine_for(c)
        return bool((e == "xray" and xray_path) or (e == "singbox" and singbox_path))

    testable = [c for c in configs if supported(c)]
    skipped = len(configs) - len(testable)

    if prior_alive_ids is not None or corroborated_ids is not None:
        candidates, info = pick_smart_candidates(
            testable,
            test_top,
            prior_alive_ids=prior_alive_ids,
            corroborated_ids=corroborated_ids,
        )
    else:
        candidates, info = pick_candidates(testable, test_top)

    LOG.info(
        "فحص فعلي: %d كانفيغ بعيّنة متوازنة (تخطّي %d: غير مدعوم أو محرّك غير متاح)",
        len(candidates),
        skipped,
    )
    LOG.info(
        "توزيع العيّنة: %s",
        " | ".join(f"{s}: {got}/{tot}" for s, (got, tot) in info.items()),
    )

    with Tester(
        xray_path,
        singbox_path,
        concurrency=concurrency,
        timeout=timeout,
        stability_probes=stability_probes,
    ) as tester:
        t0 = time.perf_counter()
        lat = tester.latency_stage(candidates)
        alive = sorted([r for r in lat if r.ok], key=lambda r: (r.median_latency_ms or r.latency_ms))
        LOG.info("نجح %d من %d في %.0f ثانية", len(alive), len(candidates), time.perf_counter() - t0)

        if not alive:
            return lat, [], skipped

        speed_candidates = [r.cfg for r in alive if r.latency_ms <= 5000][: max(0, speed_top)]
        sp_by_cfg: dict[str, Result] = {}
        if speed_candidates:
            LOG.info("قياس السرعة لـ %d عقدة …", len(speed_candidates))
            sp = tester.speed_stage(speed_candidates)
            sp_by_cfg = {r.cfg: r for r in sp}

    from scoring import compute_composite_score

    merged: list[Result] = []
    for r in alive:
        m = sp_by_cfg.get(r.cfg)
        if m and m.speed_kbps > 0:
            r.speed_kbps = m.speed_kbps
        sc, _ = compute_composite_score(
            median_latency_ms=r.median_latency_ms or r.latency_ms,
            jitter_ms=r.jitter_ms,
            probe_pass_rate=r.probe_pass_rate or 1.0,
            speed_kbps=r.speed_kbps,
            runs_seen=1,
            runs_alive=1,
            consecutive_alive=1,
            ema_reliability=0.7,
            corroboration_count=1,
            verified_source_hit=False,
        )
        r.score = sc
        merged.append(r)

    if rank_by == "latency":
        merged.sort(key=lambda r: (r.latency_ms, -r.speed_kbps))
    elif rank_by == "score":
        merged.sort(key=lambda r: (-r.score, r.latency_ms))
    else:
        with_speed = sorted(
            [r for r in merged if r.speed_kbps > 0],
            key=lambda r: (-r.speed_kbps, r.latency_ms),
        )
        without = [r for r in merged if r.speed_kbps <= 0]
        merged = with_speed + without

    return lat, merged, skipped


# ───────────────────────── أدوات إضافية وتقارير محجوبة الأسرار ─────────────────────────
def host_of(cfg: str) -> str:
    """استخراج اسم المضيف من أي كانفيغ (لتنويع المصادر)."""
    scheme, _, rest = _clean_uri(cfg).partition("://")
    if scheme.lower() == "vmess":
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
    """تنويع النتائج بحيث لا يزيد عدد العُقد المأخوذة من نفس المضيف عن limit."""
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
    """
    حفظ نتائج الفحص التشخيصي في CSV مع **حجب كامل لبيانات الاعتماد** (UUIDs / كلمات المرور)
    واستبدالها ببصمة SHA-256 قصيرة ومضيف الوجهة فقط.
    """
    lines = ["status,engine,latency_ms,jitter_ms,probe_pass_rate,speed_kbps,exit_country,score,error,redacted_config"]
    for r in sorted(lat_results, key=lambda x: (not x.ok, x.latency_ms)):
        safe_cfg = redact_uri(r.cfg).replace('"', "'")
        lines.append(
            f"{'ok' if r.ok else 'fail'},{r.engine},{r.latency_ms:.0f},"
            f"{r.jitter_ms:.1f},{r.probe_pass_rate:.2f},{r.speed_kbps:.0f},"
            f"{r.exit_country},{r.score:.1f},{r.error},\"{safe_cfg}\""
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    tmp.replace(path)
    return len(lines) - 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="فحص كانفيغات VPN فعليًا واختيار الأفضل")
    ap.add_argument("-i", "--input", default="config.txt")
    ap.add_argument("--best-out", default="best.txt")
    ap.add_argument("--best", type=int, default=100)
    ap.add_argument("--test-top", type=int, default=800)
    ap.add_argument("--speed-top", type=int, default=300)
    ap.add_argument("--concurrency", type=int, default=16)
    ap.add_argument("--rank-by", choices=("speed", "latency", "score"), default="score")
    ap.add_argument("--max-per-host", type=int, default=3)
    ap.add_argument("--test-timeout", type=float, default=6.0)
    ap.add_argument("--xray", type=Path)
    ap.add_argument("--singbox", type=Path)
    ap.add_argument("--report", default="test-report.csv")
    ap.add_argument("--no-download", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    configs = [
        _clean_uri(ln)
        for ln in Path(args.input).read_text(encoding="utf-8").splitlines()
        if "://" in ln
    ]
    LOG.info("قرأت %d كانفيغ من %s", len(configs), args.input)
    if not configs:
        return 1

    xray = ensure_xray(args.xray or DEFAULT_BIN_DIR, allow_download=not args.no_download)
    singbox = ensure_singbox(args.singbox or DEFAULT_BIN_DIR, allow_download=not args.no_download)
    if not xray and not singbox:
        LOG.error("لم يتوفّر لا Xray ولا sing-box — لا يمكن الفحص.")
        return 2

    lat_all, ranked, _ = select_best(
        configs,
        xray_path=xray,
        singbox_path=singbox,
        test_top=args.test_top,
        speed_top=args.speed_top,
        concurrency=args.concurrency,
        rank_by=args.rank_by,
        timeout=args.test_timeout,
    )
    if args.report:
        n = write_report(lat_all, Path(args.report))
        LOG.info("تقرير الفحص المحجوب الأسرار: %s (%d سطر)", args.report, n)

    if not ranked:
        LOG.error("لم ينجح أي كانفيغ.")
        return 3

    best = limit_per_host(ranked, args.max_per_host)[: args.best]
    out_p = Path(args.best_out)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_p.with_name(out_p.name + ".tmp")
    tmp.write_text("\n".join(r.cfg for r in best) + "\n", encoding="utf-8")
    tmp.replace(out_p)
    LOG.info("حفظت أفضل %d عقدة في %s", len(best), out_p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
