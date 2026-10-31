#!/usr/bin/env python3
"""
5-Layer Proxy Configuration Normalization, Deduplication & Provenance Engine:
- Layer 1: Exact normalized URI deduplication
- Layer 2: Canonical protocol + endpoint + credential + transport identity deduplication
- Layer 3: Secret-safe cross-source provenance & marginal/exclusive contribution metrics
- Layer 4: Infrastructure correlation (/24 IPv4, /48 IPv6, domain root, SNI/endpoint clusters)
- Layer 5: Safe final output deduplication preserving legitimate multi-protocol diversity
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import parse_qsl, unquote

from pipeline_security import MAX_URI_LENGTH, is_unsafe_config_host

COSMETIC_QUERY_KEYS = frozenset({
    "remark",
    "remarks",
    "name",
    "title",
    " tag",
    "tag",
    "ps",
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "source",
    "channel",
    "group",
    "sub",
    "fragment_name",
})
LOWERCASE_QUERY_KEYS = frozenset({
    "type",
    "security",
    "encryption",
    "headerType",
    "headertype",
    "fp",
    "alpn",
    "mode",
    "sni",
    "peer",
    "host",
    "authority",
    "flow",
    "congestion_control",
    "udp_relay_mode",
})


def _hash_credential_secret_safe(cred: str) -> str:
    """Hash raw credential material with domain separation so fingerprints never hold plaintext secrets."""
    return hashlib.sha256(
        b"bahrain-vpn:cred:v2|" + cred.encode("utf-8", "ignore")
    ).hexdigest()


def extract_source_operator_id(source_name: str, kind: str = "", url_or_handle: str = "") -> str:
    """
    Determine the canonical independent operator identity for a source so multiple URLs
    controlled by the same GitHub owner, domain, or Telegram handle count as ONE operator.
    """
    raw = (url_or_handle or "").strip()
    low = raw.lower()
    if "raw.githubusercontent.com/" in low:
        after = low.split("raw.githubusercontent.com/", 1)[1].strip("/")
        owner = after.split("/", 1)[0].strip()
        if owner:
            return f"gh:{owner}"
    if "github.com/" in low:
        after = low.split("github.com/", 1)[1].strip("/")
        owner = after.split("/", 1)[0].strip()
        if owner:
            return f"gh:{owner}"
    if "cdn.jsdelivr.net/gh/" in low:
        after = low.split("cdn.jsdelivr.net/gh/", 1)[1].strip("/")
        owner = after.split("/", 1)[0].split("@", 1)[0].strip()
        if owner:
            return f"gh:{owner}"
    if "t.me/" in low:
        after = low.split("t.me/", 1)[1].strip("/")
        if after.startswith("s/"):
            after = after[2:].strip("/")
        handle = after.split("/", 1)[0].split("?", 1)[0].lstrip("@").strip()
        if handle:
            return f"tg:{handle}"
    if (kind or "").lower() == "telegram" and raw:
        handle = raw.lstrip("@").split("/", 1)[0].split("?", 1)[0].strip().lower()
        if handle:
            return f"tg:{handle}"
    if "://" in low:
        host_part = low.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
        if host_part:
            return f"web:{subnet_group_key(host_part)}"

    # Fallback: normalize well-known multi-feed source name prefixes (e.g. subcrawler-vless -> op:subcrawler)
    sname = (source_name or "").strip().lower()
    if sname.startswith("tg:@"):
        return "tg:" + sname[4:]
    if "-" in sname:
        prefix = sname.split("-", 1)[0]
        if prefix in {"subcrawler", "mheidari", "v2rayroot", "igareck", "barry", "matin", "yebekhe"}:
            return f"op:{prefix}"
    return f"src:{sname or 'unknown'}"


def canonical_protocol(scheme: str) -> str:
    s = scheme.strip().lower()
    if s in ("hy2", "hysteria2"):
        return "hysteria2"
    if s in ("socks", "socks5"):
        return "socks"
    if s in ("http", "https"):
        return "http"
    return s


def _b64_decode(s: str) -> str | None:
    s = s.strip()
    if not s:
        return None
    pad = s + "=" * (-len(s) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return decoder(pad).decode("utf-8", errors="strict")
        except Exception:
            continue
    return None


def _split_host_port(hp: str, default_port: int | None = None) -> tuple[str, int] | None:
    hp = hp.strip()
    if not hp:
        return None
    if hp.startswith("["):
        if "]" not in hp:
            return None
        host, _, rest = hp[1:].partition("]")
        if rest.startswith(":"):
            port_s = rest[1:]
        elif not rest and default_port:
            port_s = str(default_port)
        else:
            return None
    elif ":" in hp:
        host, _, port_s = hp.rpartition(":")
    elif default_port:
        host, port_s = hp, str(default_port)
    else:
        return None

    host = host.strip().strip("[]").rstrip(".").lower()
    # Support Hysteria2 port hopping specs such as "443,20000-30000"
    first_port_tok = port_s.split(",", 1)[0].split("-", 1)[0].strip()
    try:
        port = int(first_port_tok)
    except ValueError:
        return None
    if not host or not (1 <= port <= 65535):
        return None
    return host, port


def subnet_group_key(host: str) -> str:
    """
    Layer-4 infrastructure grouping key:
    - IPv4 -> a.b.c.0/24
    - IPv6 -> /48 network prefix
    - Domain -> registrable 2-label suffix (or 3-label for co.uk/com.au style)
    """
    h = host.strip().strip("[]").rstrip(".").lower()
    try:
        ip = ipaddress.ip_address(h)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if isinstance(ip, ipaddress.IPv4Address):
            net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
            return f"v4:{net.network_address}/24"
        net6 = ipaddress.IPv6Network(f"{ip}/48", strict=False)
        return f"v6:{net6.network_address}/48"
    except ValueError:
        parts = [p for p in h.split(".") if p]
        if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "net", "org", "gov", "edu"):
            return "dom:" + ".".join(parts[-3:])
        if len(parts) >= 2:
            return "dom:" + ".".join(parts[-2:])
        return f"dom:{h}"


@dataclass
class ParsedIdentity:
    uri: str
    canonical_proto: str
    scheme: str
    host: str
    port: int
    sni: str
    subnet_key: str
    layer1_exact_id: str      # 24-hex SHA256 of normalized URI without fragment
    identity_id: str          # 24-hex stable server_id (secret-safe canonical fingerprint)
    canonical_sha256: str = ""  # Full 64-hex SHA256 for collision detection & resolution
    legacy_identity_id: str = ""  # Legacy v1 24-hex ID for seamless historical migration


def parse_identity(uri: str, *, reject_private_hosts: bool = True) -> ParsedIdentity | None:
    """
    Parse, validate, and compute secret-safe Layer-1 & Layer-2 identity keys.
    Returns None if malformed or targeting an unsafe private/loopback address.
    """
    if not uri or len(uri) > MAX_URI_LENGTH or "://" not in uri:
        return None
    u = uri.strip()
    scheme_raw, _, rest = u.partition("://")
    scheme = scheme_raw.lower()
    cproto = canonical_protocol(scheme)
    if cproto not in ("vmess", "vless", "trojan", "ss", "ssr", "hysteria2", "tuic", "socks", "http"):
        return None

    no_frag = rest.split("#", 1)[0].strip()
    if not no_frag:
        return None

    layer1_exact_id = hashlib.sha256(
        f"{scheme}://{no_frag}".encode("utf-8", "ignore")
    ).hexdigest()[:24]

    host = ""
    port = 0
    sni = ""
    legacy_material = ""
    v2_material = ""

    if cproto == "vmess":
        b64 = no_frag.split("?", 1)[0].strip()
        dec = _b64_decode(b64)
        if not dec:
            return None
        try:
            d = json.loads(dec)
        except Exception:
            return None
        if not isinstance(d, dict):
            return None
        host = str(d.get("add", "")).strip().strip("[]").rstrip(".").lower()
        try:
            port = int(str(d.get("port", 0)).strip())
        except (TypeError, ValueError):
            return None
        uid = str(d.get("id", "")).strip().lower()
        if not host or not uid or not (1 <= port <= 65535):
            return None
        net = str(d.get("net") or "tcp").strip().lower()
        tls = str(d.get("tls") or "").strip().lower()
        if tls == "none":
            tls = ""
        sni = str(d.get("sni") or d.get("host") or "").strip().rstrip(".").lower()
        raw_path = str(d.get("path") or "").strip()
        norm_path = "" if (net == "tcp" and raw_path == "/") else raw_path
        scy = str(d.get("scy") or "auto").strip().lower()
        vtype = str(d.get("type") or "none").strip().lower()
        legacy_material = f"vmess|{host}|{port}|{uid}|{net}|{vtype}|{tls}|{sni}|{raw_path}|{scy}"
        cred_h = _hash_credential_secret_safe(uid)
        v2_material = f"v2|vmess|{host}|{port}|{cred_h}|{net}|{vtype}|{tls}|{sni}|{norm_path}|{scy}"

    elif cproto == "ssr":
        dec = _b64_decode(no_frag.split("?", 1)[0].rstrip("/"))
        if not dec:
            return None
        main_ssr = dec.split("/?", 1)[0]
        parts = main_ssr.split(":")
        if len(parts) < 6:
            return None
        host = parts[0].strip().strip("[]").rstrip(".").lower()
        try:
            port = int(parts[1])
        except ValueError:
            return None
        if not host or not (1 <= port <= 65535):
            return None
        legacy_material = f"ssr|{host}|{port}|{':'.join(parts[2:])}"
        cred_h = _hash_credential_secret_safe(":".join(parts[2:]))
        v2_material = f"v2|ssr|{host}|{port}|{cred_h}"

    elif cproto == "ss":
        main_part, _, q_str = no_frag.partition("?")
        main_part = main_part.rstrip("/")
        method_pass = ""
        hp_part = ""
        if "@" in main_part:
            userinfo, _, hp_part = main_part.rpartition("@")
            dec_u = _b64_decode(unquote(userinfo))
            method_pass = dec_u if (dec_u and ":" in dec_u) else unquote(userinfo)
        else:
            dec_all = _b64_decode(unquote(main_part))
            if not dec_all or "@" not in dec_all:
                return None
            method_pass, _, hp_part = dec_all.rpartition("@")
        hp = _split_host_port(hp_part)
        if not hp or ":" not in method_pass:
            return None
        host, port = hp
        method, _, password = method_pass.partition(":")
        method = method.strip().lower()
        if not method or not password:
            return None
        q_pairs = _canonical_query(q_str)
        sni = dict(q_pairs).get("sni", "") or dict(q_pairs).get("host", "")
        legacy_material = f"ss|{host}|{port}|{method}|{password}|{q_pairs}"
        cred_h = _hash_credential_secret_safe(f"{method}:{password}")
        v2_material = f"v2|ss|{host}|{port}|{method}|{cred_h}|{q_pairs}"

    elif cproto in ("socks", "http"):
        main_part, _, q_str = no_frag.partition("?")
        if "/" in main_part:
            authority_part, _, path_part = main_part.partition("/")
            if path_part.strip():
                return None
        else:
            authority_part = main_part
        if "@" in authority_part:
            userinfo, _, hp_str = authority_part.rpartition("@")
            dec_u = _b64_decode(unquote(userinfo))
            cred = dec_u if (dec_u and ":" in dec_u) else unquote(userinfo.strip())
        else:
            cred = ""
            hp_str = authority_part
        # Require explicit port for socks/http so ordinary web URLs are never mistaken for proxies
        if ":" not in hp_str.rsplit("]", 1)[-1]:
            return None
        hp = _split_host_port(hp_str, default_port=None)
        if not hp:
            return None
        host, port = hp
        q_pairs = _canonical_query(q_str)
        q_map = dict(q_pairs)
        sni = q_map.get("sni") or q_map.get("peer") or q_map.get("host") or ""
        tls_flag = "tls" if (scheme == "https" or q_map.get("security", "").lower() == "tls") else "plain"
        legacy_material = f"{cproto}|{host}|{port}|{cred}|{tls_flag}|{q_pairs}"
        cred_h = _hash_credential_secret_safe(cred)
        v2_material = f"v2|{cproto}|{host}|{port}|{cred_h}|{tls_flag}|{q_pairs}"

    else:
        # vless, trojan, hysteria2/hy2, tuic
        main_part, _, q_str = no_frag.partition("?")
        if "@" not in main_part:
            return None
        userinfo, _, hp_str = main_part.rpartition("@")
        hp_str = hp_str.split("/", 1)[0]
        default_port = 443 if cproto in ("hysteria2", "tuic") else None
        hp = _split_host_port(hp_str, default_port=default_port)
        if not hp or not userinfo:
            return None
        host, port = hp
        cred = unquote(userinfo.strip())
        if cproto == "vless":
            cred = cred.lower()
        elif cproto == "tuic" and ":" in cred:
            u_id, _, u_pw = cred.partition(":")
            cred = f"{u_id.lower()}:{u_pw}"
        q_pairs = _canonical_query(q_str)
        q_map = dict(q_pairs)
        sni = q_map.get("sni") or q_map.get("peer") or q_map.get("host") or ""
        legacy_material = f"{cproto}|{host}|{port}|{cred}|{q_pairs}"
        cred_h = _hash_credential_secret_safe(cred)
        v2_material = f"v2|{cproto}|{host}|{port}|{cred_h}|{q_pairs}"

    if reject_private_hosts and is_unsafe_config_host(host):
        return None

    legacy_id = hashlib.sha256(
        legacy_material.encode("utf-8", "ignore")
    ).hexdigest()[:24]
    full_v2_sha = hashlib.sha256(
        v2_material.encode("utf-8", "ignore")
    ).hexdigest()
    identity_id = full_v2_sha[:24]

    return ParsedIdentity(
        uri=u,
        canonical_proto=cproto,
        scheme=scheme,
        host=host,
        port=port,
        sni=sni,
        subnet_key=subnet_group_key(host),
        layer1_exact_id=layer1_exact_id,
        identity_id=identity_id,
        canonical_sha256=full_v2_sha,
        legacy_identity_id=legacy_id,
    )


def _canonical_query(q_str: str) -> list[tuple[str, str]]:
    if not q_str:
        return []
    raw_items: dict[str, str] = {}
    for k, v in parse_qsl(q_str, keep_blank_values=False):
        kl = k.strip().lower()
        if kl in COSMETIC_QUERY_KEYS:
            continue
        val = v.strip()
        if kl in LOWERCASE_QUERY_KEYS:
            val = val.lower()
        if kl in ("sni", "peer", "host", "authority"):
            val = val.rstrip(".")
        if kl == "alpn" and "," in val:
            val = ",".join(sorted(tok.strip() for tok in val.split(",") if tok.strip()))
        # Normalize default TCP/none noise
        if kl == "encryption" and val == "none":
            continue
        if kl == "type" and val == "tcp":
            continue
        if kl == "security" and val == "none":
            continue
        raw_items[kl] = val
    # Canonicalize peer -> sni when sni is omitted (common Trojan/Hysteria2 alias)
    if "peer" in raw_items and "sni" not in raw_items:
        raw_items["sni"] = raw_items.pop("peer")
    elif "peer" in raw_items and raw_items.get("sni") == raw_items.get("peer"):
        raw_items.pop("peer", None)
    return sorted(raw_items.items())


@dataclass
class ConfigProvenance:
    identity_id: str
    canonical_proto: str
    host: str
    port: int
    subnet_key: str
    sni: str
    representative_uri: str
    sources: list[str] = field(default_factory=list)
    operators: list[str] = field(default_factory=list)
    verified_source_hit: bool = False
    canonical_sha256: str = ""
    legacy_identity_id: str = ""

    @property
    def corroboration_count(self) -> int:
        return len(self.sources)

    @property
    def independent_source_count(self) -> int:
        if self.operators:
            return len(set(self.operators))
        return len({extract_source_operator_id(s) for s in self.sources})


@dataclass
class DedupeSummary:
    raw_input: int = 0
    invalid_or_unsafe_rejected: int = 0
    layer1_exact_duplicates: int = 0
    layer2_identity_duplicates: int = 0
    unique_identities: int = 0
    unique_endpoints: int = 0
    unique_subnets: int = 0
    multi_source_corroborated: int = 0

    def to_dict(self) -> dict:
        return {
            "raw_input": self.raw_input,
            "invalid_or_unsafe_rejected": self.invalid_or_unsafe_rejected,
            "layer1_exact_duplicates": self.layer1_exact_duplicates,
            "layer2_identity_duplicates": self.layer2_identity_duplicates,
            "unique_identities": self.unique_identities,
            "unique_endpoints": self.unique_endpoints,
            "unique_subnets": self.unique_subnets,
            "multi_source_corroborated": self.multi_source_corroborated,
        }


class MultiLayerDeduplicator:
    """
    Stateful 5-layer deduplicator across multiple sources.
    Maintains provenance without ever exposing raw credentials in reports.
    """

    def __init__(
        self,
        *,
        verified_sources: set[str] | None = None,
        reject_private_hosts: bool = True,
        source_urls: dict[str, str] | None = None,
    ) -> None:
        self.verified_sources = verified_sources or set()
        self.reject_private_hosts = reject_private_hosts
        self.source_urls: dict[str, str] = dict(source_urls or {})
        self._seen_layer1: set[str] = set()
        self._records: dict[str, ConfigProvenance] = {}
        self._sha_to_id: dict[str, str] = {}
        self._order: list[str] = []
        self._source_ids: dict[str, set[str]] = {}
        self.summary = DedupeSummary()

    def register_source_url(self, source_name: str, url_or_handle: str) -> None:
        if source_name and url_or_handle:
            self.source_urls[source_name] = url_or_handle

    def ingest_source(
        self,
        source_name: str,
        uris: Iterable[str],
        *,
        source_url: str = "",
    ) -> tuple[int, int]:
        """
        Ingest raw candidate URIs from `source_name`.
        Returns (valid_count_in_source, newly_added_unique_count).
        """
        if source_url:
            self.source_urls[source_name] = source_url
        src_url = self.source_urls.get(source_name, "")
        op_id = extract_source_operator_id(source_name, url_or_handle=src_url)
        src_set = self._source_ids.setdefault(source_name, set())
        valid_in_src = 0
        new_unique = 0
        is_verified = source_name in self.verified_sources

        for raw in uris:
            self.summary.raw_input += 1
            ident = parse_identity(raw, reject_private_hosts=self.reject_private_hosts)
            if ident is None:
                self.summary.invalid_or_unsafe_rejected += 1
                continue

            # Resolve collision-safe server_id using full 256-bit canonical_sha256
            eff_id = self._sha_to_id.get(ident.canonical_sha256)
            if eff_id is None:
                existing_rec = self._records.get(ident.identity_id)
                if existing_rec and existing_rec.canonical_sha256 and existing_rec.canonical_sha256 != ident.canonical_sha256:
                    eff_id = ident.canonical_sha256[:32]
                else:
                    eff_id = ident.identity_id
                if ident.canonical_sha256:
                    self._sha_to_id[ident.canonical_sha256] = eff_id

            valid_in_src += 1
            src_set.add(eff_id)

            if ident.layer1_exact_id in self._seen_layer1:
                self.summary.layer1_exact_duplicates += 1
                rec = self._records.get(eff_id)
                if rec:
                    if source_name not in rec.sources:
                        rec.sources.append(source_name)
                    if op_id not in rec.operators:
                        rec.operators.append(op_id)
                    if is_verified:
                        rec.verified_source_hit = True
                continue

            self._seen_layer1.add(ident.layer1_exact_id)

            if eff_id in self._records:
                self.summary.layer2_identity_duplicates += 1
                rec = self._records[eff_id]
                if source_name not in rec.sources:
                    rec.sources.append(source_name)
                if op_id not in rec.operators:
                    rec.operators.append(op_id)
                if is_verified:
                    rec.verified_source_hit = True
                # Prefer canonical hysteria2:// over hy2:// or SIP002 ss:// if cleaner
                if rec.representative_uri.startswith("hy2://") and ident.uri.startswith("hysteria2://"):
                    rec.representative_uri = ident.uri
                continue

            rec = ConfigProvenance(
                identity_id=eff_id,
                canonical_proto=ident.canonical_proto,
                host=ident.host,
                port=ident.port,
                subnet_key=ident.subnet_key,
                sni=ident.sni,
                representative_uri=ident.uri,
                sources=[source_name],
                operators=[op_id],
                verified_source_hit=is_verified,
                canonical_sha256=ident.canonical_sha256,
                legacy_identity_id=ident.legacy_identity_id,
            )
            self._records[eff_id] = rec
            self._order.append(eff_id)
            new_unique += 1

        self._refresh_summary()
        return valid_in_src, new_unique

    def _refresh_summary(self) -> None:
        self.summary.unique_identities = len(self._records)
        self.summary.unique_endpoints = len({(r.host, r.port) for r in self._records.values()})
        self.summary.unique_subnets = len({r.subnet_key for r in self._records.values()})
        self.summary.multi_source_corroborated = sum(
            1 for r in self._records.values() if r.independent_source_count >= 2
        )

    def unique_uris(self) -> list[str]:
        return [self._records[i].representative_uri for i in self._order]

    def provenance_map(self) -> dict[str, ConfigProvenance]:
        return dict(self._records)

    def provenance_by_uri(self) -> dict[str, ConfigProvenance]:
        return {r.representative_uri: r for r in self._records.values()}

    def source_overlap_metrics(self) -> dict[str, dict[str, float | int]]:
        """
        Compute per-source unique count, exclusive contribution, and overlap ratio
        against all other ingested sources.
        """
        out: dict[str, dict[str, float | int]] = {}
        all_sources = list(self._source_ids.keys())
        # Count how many sources contain each identity_id in O(N)
        id_freq: dict[str, int] = {}
        for ids in self._source_ids.values():
            for cid in ids:
                id_freq[cid] = id_freq.get(cid, 0) + 1

        for src in all_sources:
            ids = self._source_ids[src]
            total = len(ids)
            exclusive = sum(1 for cid in ids if id_freq.get(cid, 0) == 1)
            shared = total - exclusive
            overlap_ratio = round(shared / total, 4) if total else 0.0
            out[src] = {
                "unique_identities": total,
                "exclusive_identities": exclusive,
                "shared_identities": shared,
                "overlap_ratio": overlap_ratio,
            }
        return out


def dedupe_output_list(
    uris: Iterable[str],
    *,
    max_per_host: int = 0,
    max_per_subnet: int = 0,
    reject_private_hosts: bool = True,
) -> list[str]:
    """
    Layer-4 & Layer-5 safe output deduplication + host/subnet diversity cap.
    Guarantees zero duplicate identity_id in final published files.
    """
    seen_ids: set[str] = set()
    host_counts: dict[str, int] = {}
    subnet_counts: dict[str, int] = {}
    out: list[str] = []

    for uri in uris:
        ident = parse_identity(uri, reject_private_hosts=reject_private_hosts)
        if ident is None:
            continue
        if ident.identity_id in seen_ids:
            continue
        if max_per_host > 0 and host_counts.get(ident.host, 0) >= max_per_host:
            continue
        if max_per_subnet > 0 and subnet_counts.get(ident.subnet_key, 0) >= max_per_subnet:
            continue

        seen_ids.add(ident.identity_id)
        host_counts[ident.host] = host_counts.get(ident.host, 0) + 1
        subnet_counts[ident.subnet_key] = subnet_counts.get(ident.subnet_key, 0) + 1
        out.append(ident.uri)
    return out
