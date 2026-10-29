#!/usr/bin/env python3
"""
Security hardening primitives for the VPN configuration pipeline:
- SSRF / private-network / cloud-metadata / redirect validation
- Bounded streaming HTTP fetches with conditional ETag / Last-Modified caching
- Config endpoint target validation (blocking loopback, RFC1918, link-local, metadata)
- Credential redaction & secret-safe SHA-256 fingerprinting for logs and reports
- Cryptographic SHA-256 verification and Zip/Tar path-traversal guards
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import socket
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests

# Strict resource bounds against untrusted upstream feeds
MAX_FEED_BYTES = 15 * 1024 * 1024       # 15 MiB max compressed/raw HTTP body
MAX_DECODED_BYTES = 20 * 1024 * 1024    # 20 MiB max Base64-decoded payload
MAX_FEED_LINES = 120_000                # Max lines processed per feed
MAX_URI_LENGTH = 8_192                  # Max chars per single proxy URI
MAX_REDIRECT_HOPS = 4                   # Controlled redirect limit
MAX_BINARY_BYTES = 120 * 1024 * 1024    # Max binary archive size for Xray/sing-box

ALLOWED_FETCH_SCHEMES = frozenset({"https", "http"})

_BLOCKED_HOST_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".home.arpa",
    ".corp",
    ".lan",
)
_BLOCKED_EXACT_HOSTS = frozenset({
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata",
    "metadata.google.internal",
    "instance-data",
})

_URI_INLINE_RE = re.compile(
    r"(?:vmess|vless|trojan|ss|ssr|hysteria2|hy2|tuic)://[^\s\"'<>`]+",
    re.IGNORECASE,
)


class SecurityError(Exception):
    """Raised when an untrusted input or network target violates security policy."""


def is_forbidden_ip(ip_str: str, *, allow_doc_ipv6: bool = False) -> bool:
    """
    Return True if `ip_str` is loopback, private, link-local, cloud-metadata,
    CGNAT, multicast, unspecified, or reserved.
    """
    clean = ip_str.strip().strip("[]")
    if "%" in clean:
        return True  # IPv6 zone IDs (e.g. fe80::1%eth0) are local-link only
    try:
        ip = ipaddress.ip_address(clean)
    except ValueError:
        return False

    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped

    # Optional exemption for RFC 3849 / RFC 5737 documentation test addresses in unit tests
    if allow_doc_ipv6:
        if isinstance(ip, ipaddress.IPv6Address) and ip in ipaddress.IPv6Network("2001:db8::/32"):
            return False
        if isinstance(ip, ipaddress.IPv4Address) and any(
            ip in ipaddress.IPv4Network(net)
            for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
        ):
            return False

    if (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    ):
        return True

    if isinstance(ip, ipaddress.IPv4Address):
        # Explicit CGNAT 100.64.0.0/10 & AWS/GCP/Azure metadata 169.254.169.254
        if ip in ipaddress.IPv4Network("100.64.0.0/10"):
            return True
        if ip in ipaddress.IPv4Network("0.0.0.0/8"):
            return True
    return False


def is_unsafe_config_host(host: str) -> bool:
    """
    Validate a proxy config's target host/IP before allowing it into outputs or
    local tunnel execution. Prevents configs from pivoting into localhost,
    RFC1918 LANs, or cloud metadata endpoints.
    """
    if not host:
        return True
    h = host.strip().strip("[]").rstrip(".").lower()
    if not h or len(h) > 253:
        return True
    if any(ch in h for ch in (" ", "\t", "\r", "\n", "/", "\\", "@", "?")):
        return True
    if h in _BLOCKED_EXACT_HOSTS or any(h.endswith(sfx) for sfx in _BLOCKED_HOST_SUFFIXES):
        return True

    # Direct IP literal check (allow 2001:db8::/32 documentation range for deterministic tests)
    try:
        ipaddress.ip_address(h)
        return is_forbidden_ip(h, allow_doc_ipv6=True)
    except ValueError:
        pass

    # Reject纯 numeric / octal / hex IPv4 obfuscation such as 0x7f000001 or 2130706433
    if re.fullmatch(r"(?:0x[0-9a-f]+|\d+)", h):
        return True
    return False


def validate_fetch_url(
    url: str,
    *,
    require_https: bool = False,
    resolve_dns: bool = True,
    resolver: Callable[[str, int], list] | None = None,
) -> str:
    """
    Validate an outbound fetch URL against SSRF, scheme abuse, embedded credentials,
    and private/internal DNS resolution. Returns normalized URL or raises SecurityError.
    """
    if not url or not isinstance(url, str) or len(url) > 2048:
        raise SecurityError("Invalid or oversized URL")
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_FETCH_SCHEMES:
        raise SecurityError(f"Disallowed URL scheme: {scheme!r}")
    if require_https and scheme != "https":
        raise SecurityError(f"HTTPS required, got {scheme!r}")
    if parts.username or parts.password:
        raise SecurityError("Embedded URL credentials are not permitted")

    host = (parts.hostname or "").strip().rstrip(".").lower()
    if not host:
        raise SecurityError("URL missing hostname")
    if host in _BLOCKED_EXACT_HOSTS or any(host.endswith(s) for s in _BLOCKED_HOST_SUFFIXES):
        raise SecurityError(f"Blocked internal hostname: {host}")

    try:
        port = parts.port
    except ValueError as exc:
        raise SecurityError("Invalid URL port") from exc
    if port is not None and not (1 <= port <= 65535):
        raise SecurityError(f"Out-of-range URL port: {port}")

    # Literal IP check
    is_ip_literal = False
    try:
        ipaddress.ip_address(host)
        is_ip_literal = True
    except ValueError:
        pass
    if is_ip_literal:
        if is_forbidden_ip(host, allow_doc_ipv6=False):
            raise SecurityError(f"Blocked private/reserved IP literal: {host}")
        return urlunsplit((scheme, parts.netloc, parts.path or "/", parts.query, ""))

    if re.fullmatch(r"(?:0x[0-9a-f]+|\d+)", host):
        raise SecurityError(f"Blocked numeric IP obfuscation: {host}")

    if resolve_dns:
        lookup = resolver or socket.getaddrinfo
        eff_port = port or (443 if scheme == "https" else 80)
        try:
            infos = lookup(host, eff_port)
        except OSError as exc:
            raise SecurityError(f"DNS resolution failed for {host}: {exc}") from exc
        if not infos:
            raise SecurityError(f"DNS returned no addresses for {host}")
        for info in infos:
            sockaddr = info[4]
            if not sockaddr:
                continue
            addr = str(sockaddr[0])
            if is_forbidden_ip(addr, allow_doc_ipv6=False):
                raise SecurityError(f"Host {host} resolved to forbidden IP {addr}")

    return urlunsplit((scheme, parts.netloc, parts.path or "/", parts.query, ""))


@dataclass
class SafeFetchResult:
    ok: bool
    status_code: int = 0
    not_modified: bool = False
    text: str = ""
    bytes_read: int = 0
    etag: str = ""
    last_modified: str = ""
    final_url: str = ""
    error: str = ""


def safe_fetch_text(
    session: requests.Session,
    url: str,
    *,
    timeout: float = 20.0,
    max_bytes: int = MAX_FEED_BYTES,
    require_https: bool = False,
    etag: str = "",
    last_modified: str = "",
    resolve_dns: bool = True,
) -> SafeFetchResult:
    """
    Fetch a text resource with SSRF validation on initial URL + every redirect hop,
    strict byte cap, and optional ETag / If-Modified-Since conditional headers.
    """
    current_url = url
    headers: dict[str, str] = {}
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified

    for hop in range(MAX_REDIRECT_HOPS + 1):
        try:
            current_url = validate_fetch_url(
                current_url, require_https=require_https, resolve_dns=resolve_dns
            )
        except SecurityError as exc:
            return SafeFetchResult(ok=False, error=f"ssrf_blocked:{exc}", final_url=current_url)

        try:
            resp = session.get(
                current_url,
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
                stream=True,
            )
        except requests.RequestException as exc:
            return SafeFetchResult(
                ok=False,
                error=f"request_error:{type(exc).__name__}",
                final_url=current_url,
            )

        try:
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("Location", "").strip()
                if not loc:
                    return SafeFetchResult(
                        ok=False, status_code=resp.status_code, error="empty_redirect", final_url=current_url
                    )
                if hop >= MAX_REDIRECT_HOPS:
                    return SafeFetchResult(
                        ok=False, status_code=resp.status_code, error="too_many_redirects", final_url=current_url
                    )
                current_url = urljoin(current_url, loc)
                continue

            if resp.status_code == 304:
                return SafeFetchResult(
                    ok=True,
                    status_code=304,
                    not_modified=True,
                    etag=resp.headers.get("ETag", etag),
                    last_modified=resp.headers.get("Last-Modified", last_modified),
                    final_url=current_url,
                )

            if resp.status_code != 200:
                return SafeFetchResult(
                    ok=False,
                    status_code=resp.status_code,
                    error=f"http_{resp.status_code}",
                    final_url=current_url,
                )

            cl = resp.headers.get("Content-Length")
            if cl and cl.isdigit() and int(cl) > max_bytes:
                return SafeFetchResult(
                    ok=False,
                    status_code=200,
                    error=f"oversized_content_length:{cl}",
                    final_url=current_url,
                )

            chunks: list[bytes] = []
            total = 0
            for chunk in resp.iter_content(chunk_size=65_536):
                if not chunk:
                    continue
                total += len(chunk)
                if total > max_bytes:
                    return SafeFetchResult(
                        ok=False,
                        status_code=200,
                        bytes_read=total,
                        error=f"max_bytes_exceeded:{max_bytes}",
                        final_url=current_url,
                    )
                chunks.append(chunk)

            raw_bytes = b"".join(chunks)
            enc = resp.encoding or "utf-8"
            try:
                text = raw_bytes.decode(enc, errors="replace")
            except LookupError:
                text = raw_bytes.decode("utf-8", errors="replace")

            return SafeFetchResult(
                ok=True,
                status_code=200,
                text=text,
                bytes_read=total,
                etag=resp.headers.get("ETag", ""),
                last_modified=resp.headers.get("Last-Modified", ""),
                final_url=current_url,
            )
        finally:
            resp.close()

    return SafeFetchResult(ok=False, error="redirect_loop", final_url=current_url)


# ───────────────── Credential Redaction & Secret-Safe Fingerprints ─────────────────
def config_fingerprint(uri: str, length: int = 12) -> str:
    """Deterministic short SHA-256 fingerprint that never exposes credentials."""
    core = uri.split("#", 1)[0].strip()
    return hashlib.sha256(core.encode("utf-8", "ignore")).hexdigest()[:length]


def redact_uri(uri: str) -> str:
    """
    Return a safe, human-diagnosable representation of a proxy URI with all
    UUIDs, passwords, Shadowsocks secrets, and auth tokens redacted.
    Example: `vless://***@example.com:443 [fp:a1b2c3d4e5f6]`
    """
    if not uri or "://" not in uri:
        return "<invalid-uri>"
    fp = config_fingerprint(uri, 12)
    scheme, _, rest = uri.strip().partition("://")
    proto = scheme.lower()

    if proto == "vmess":
        b64 = rest.split("#", 1)[0].split("?", 1)[0].strip()
        pad = b64 + "=" * (-len(b64) % 4)
        try:
            raw = base64.urlsafe_b64decode(pad).decode("utf-8", "ignore")
            data = json.loads(raw)
            host = str(data.get("add", "?")).strip()
            port = str(data.get("port", "?")).strip()
            net = str(data.get("net", "tcp")).strip()
            return f"vmess://***@{host}:{port}?net={net} [fp:{fp}]"
        except Exception:
            return f"vmess://*** [fp:{fp}]"

    if proto == "ssr":
        return f"ssr://*** [fp:{fp}]"

    no_frag = rest.split("#", 1)[0]
    main_part, _, _ = no_frag.partition("?")
    if "@" not in main_part and proto == "ss":
        pad = main_part + "=" * (-len(main_part) % 4)
        try:
            dec = base64.urlsafe_b64decode(pad).decode("utf-8", "ignore")
            if "@" in dec:
                main_part = dec
        except Exception:
            return f"ss://*** [fp:{fp}]"

    if "@" in main_part:
        _, _, hostport = main_part.rpartition("@")
        hostport = hostport.split("/", 1)[0]
        return f"{proto}://***@{hostport} [fp:{fp}]"
    return f"{proto}://*** [fp:{fp}]"


def redact_text(text: str) -> str:
    """Redact any inline proxy URIs embedded inside arbitrary log/error text."""
    if not text or "://" not in text:
        return text
    return _URI_INLINE_RE.sub(lambda m: redact_uri(m.group(0)), text)


# ───────────────── Binary Checksum & Safe Archive Extraction ─────────────────
def verify_sha256(file_path: Path, expected_digest: str) -> bool:
    """
    Verify file SHA-256 against `expected_digest` (accepts 'sha256:<hex>' or '<hex>').
    Raises SecurityError on mismatch.
    """
    exp = expected_digest.strip().lower()
    if exp.startswith("sha256:"):
        exp = exp.split(":", 1)[1].strip()
    if not re.fullmatch(r"[0-9a-f]{64}", exp):
        raise SecurityError(f"Malformed expected SHA-256 digest: {expected_digest!r}")

    h = hashlib.sha256()
    with file_path.open("rb") as f:
        while chunk := f.read(131_072):
            h.update(chunk)
    actual = h.hexdigest().lower()
    if actual != exp:
        raise SecurityError(f"SHA-256 mismatch for {file_path.name}: expected {exp}, got {actual}")
    return True


def safe_extract_zip_binary(zip_path: Path, target_names: set[str], dest_path: Path) -> Path:
    """Extract a single expected binary from a ZIP without trusting member paths."""
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            member_path = Path(info.filename)
            if ".." in member_path.parts:
                raise SecurityError(f"Path traversal in zip member: {info.filename}")
            if member_path.name in target_names:
                if info.file_size > MAX_BINARY_BYTES:
                    raise SecurityError(f"Oversized binary in zip: {info.file_size}")
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, dest_path.open("wb") as dst:
                    dst.write(src.read(MAX_BINARY_BYTES + 1))
                return dest_path
    raise FileNotFoundError(f"None of {target_names} found in {zip_path.name}")


def safe_extract_tar_binary(tar_path: Path, target_names: set[str], dest_path: Path) -> Path:
    """Extract a single expected binary from a tar.gz without trusting member paths or symlinks."""
    with tarfile.open(tar_path, "r:*") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            member_path = Path(member.name)
            if ".." in member_path.parts:
                raise SecurityError(f"Path traversal in tar member: {member.name}")
            if member_path.name in target_names:
                if member.size > MAX_BINARY_BYTES:
                    raise SecurityError(f"Oversized binary in tar: {member.size}")
                src = tf.extractfile(member)
                if src is None:
                    continue
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                with src, dest_path.open("wb") as dst:
                    dst.write(src.read(MAX_BINARY_BYTES + 1))
                return dest_path
    raise FileNotFoundError(f"None of {target_names} found in {tar_path.name}")
