#!/usr/bin/env python3
"""
Phase 2 — Security & Privacy Intelligence Engine (`security_intelligence.py`).

Strictly separates transport/configuration security and operator privacy risk
from connection speed and reliability:
  - A fast server is NEVER automatically treated as a secure server.
  - Anonymous public servers are NEVER marked `Privacy: Verified`.
  - Distinguishes measured facts (TLS flags, cipher suite, redirect behavior,
    exit-country drift, structural integrity) from unobservable operator trust.
  - Quarantines CRITICAL/malicious/tampered configurations into a secret-safe
    quarantine registry so they never enter published subscription lists.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, unquote

from dedupe import canonical_protocol, parse_identity
from pipeline_security import MAX_URI_LENGTH, is_unsafe_config_host, redact_uri

# Canonical Assessment Taxonomies (Phase 2.1 & 2.2)
SECURITY_ASSESSMENTS = ("Verified", "Partial", "Unknown", "Failed")
PRIVACY_ASSESSMENTS = ("Verified", "Unverified", "Unknown", "High Risk")
RISK_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN")

# Cipher classifications for Shadowsocks / VMess
AEAD_STRONG_CIPHERS = frozenset({
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-256-gcm",
    "aes-128-gcm",
    "aes-192-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
})
DEPRECATED_WEAK_CIPHERS = frozenset({
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "camellia-128-cfb",
    "camellia-256-cfb",
    "bf-cfb",
    "chacha20",
    "salsa20",
})
CRITICAL_BROKEN_CIPHERS = frozenset({
    "none",
    "plain",
    "rc4",
    "rc4-md5",
    "table",
    "des-cfb",
})

# Ports associated with non-proxy infrastructure services (anti-pivoting guard)
SUSPICIOUS_SERVICE_PORTS = frozenset({21, 22, 23, 25, 110, 135, 139, 143, 445, 1433, 3306, 3389, 5432, 6379, 27017})

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_REALITY_PBK_RE = re.compile(r"^[A-Za-z0-9_\-+=/]{42,48}$")


@dataclass(frozen=True)
class ThreatIntelIndicators:
    """
    Optional, deterministic threat-intelligence indicator set (IPs, CIDRs, domains).
    Never fabricates hits when no indicator feed is configured.
    """
    malicious_ips: frozenset[str] = frozenset()
    malicious_domains: frozenset[str] = frozenset()
    malicious_cidrs: tuple[ipaddress._BaseNetwork, ...] = ()

    @classmethod
    def from_json_file(cls, path: Path | None) -> "ThreatIntelIndicators":
        if path is None or not path.is_file():
            return cls()
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                return cls()
            ips = frozenset(str(x).strip().lower() for x in raw.get("ips", []) if x)
            doms = frozenset(str(x).strip().lower().rstrip(".") for x in raw.get("domains", []) if x)
            nets = []
            for cidr in raw.get("cidrs", []):
                try:
                    nets.append(ipaddress.ip_network(str(cidr).strip(), strict=False))
                except ValueError:
                    continue
            return cls(malicious_ips=ips, malicious_domains=doms, malicious_cidrs=tuple(nets))
        except Exception:
            return cls()

    def matches_host(self, host: str) -> bool:
        h = (host or "").strip().strip("[]").rstrip(".").lower()
        if not h:
            return False
        if h in self.malicious_ips or h in self.malicious_domains:
            return True
        for dom in self.malicious_domains:
            if h.endswith("." + dom):
                return True
        try:
            ip = ipaddress.ip_address(h)
            return any(ip in net for net in self.malicious_cidrs)
        except ValueError:
            return False


@dataclass
class SecurityReport:
    config_hash: str
    protocol: str
    host: str
    port: int
    security_assessment: str          # Verified | Partial | Unknown | Failed
    privacy_assessment: str           # Verified | Unverified | Unknown | High Risk
    risk_level: str                   # LOW | MEDIUM | HIGH | CRITICAL | UNKNOWN
    quarantined: bool
    quarantine_reason: str = ""
    tls_enabled: bool = False
    tls_verified: bool = False
    allow_insecure: bool = False
    sni_aligned: bool = False
    aead_cipher: bool = False
    dns_consistent: bool = True
    redirect_anomaly: bool = False
    endpoint_changed: bool = False
    measured_facts: list[str] = field(default_factory=list)
    inferred_risks: list[str] = field(default_factory=list)

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "security_assessment": self.security_assessment,
            "privacy_assessment": self.privacy_assessment,
            "risk_level": self.risk_level,
            "quarantined": self.quarantined,
            "quarantine_reason": self.quarantine_reason,
            "tls_enabled": self.tls_enabled,
            "tls_verified": self.tls_verified,
            "allow_insecure": self.allow_insecure,
            "sni_aligned": self.sni_aligned,
            "aead_cipher": self.aead_cipher,
            "dns_consistent": self.dns_consistent,
            "redirect_anomaly": self.redirect_anomaly,
            "endpoint_changed": self.endpoint_changed,
            "measured_facts": list(self.measured_facts),
            "inferred_risks": list(self.inferred_risks),
        }


@dataclass
class MultiDimensionalScore:
    performance_score: float          # 0..100
    reliability_score: float          # 0..100
    security_assessment: str          # Verified | Partial | Unknown | Failed
    privacy_assessment: str           # Verified | Unverified | Unknown | High Risk
    risk_level: str                   # LOW | MEDIUM | HIGH | CRITICAL | UNKNOWN
    packet_loss_pct: float            # 0..100
    uptime_pct: float                 # 0..100
    freshness_factor: float           # 0..1
    score_delta: float = 0.0          # Change vs prior historical performance score
    factors: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "performance_score": round(self.performance_score, 1),
            "reliability_score": round(self.reliability_score, 1),
            "security_assessment": self.security_assessment,
            "privacy_assessment": self.privacy_assessment,
            "risk_level": self.risk_level,
            "packet_loss_pct": round(self.packet_loss_pct, 2),
            "uptime_pct": round(self.uptime_pct, 2),
            "freshness_factor": round(self.freshness_factor, 3),
            "score_delta": round(self.score_delta, 1),
            "factors": {k: round(v, 1) for k, v in self.factors.items()},
        }


def _safe_b64_json(b64_str: str) -> dict[str, Any] | None:
    s = b64_str.strip()
    if not s:
        return None
    pad = s + "=" * (-len(s) % 4)
    for dec in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            obj = json.loads(dec(pad).decode("utf-8", errors="strict"))
            return obj if isinstance(obj, dict) else None
        except Exception:
            continue
    return None


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip().strip("[]"))
        return True
    except ValueError:
        return False


def _sni_matches_host(host: str, sni: str) -> bool:
    h = (host or "").strip().strip("[]").rstrip(".").lower()
    s = (sni or "").strip().strip("[]").rstrip(".").lower()
    if not h or not s:
        return False
    if h == s:
        return True
    # Subdomain alignment (e.g. edge1.example.com and example.com)
    h_parts = h.split(".")
    s_parts = s.split(".")
    if len(h_parts) >= 2 and len(s_parts) >= 2 and h_parts[-2:] == s_parts[-2:]:
        return True
    return False


def assess_configuration_security(
    uri: str,
    *,
    probe_error: str = "",
    tls_probe_verified: bool = False,
    dns_consistent: bool = True,
    prior_exit_country: str = "",
    current_exit_country: str = "",
    prior_security_mode: str = "",
    operator_attested_vip: bool = False,
    threat_intel: ThreatIntelIndicators | None = None,
) -> SecurityReport:
    """
    Inspect configuration structure, cryptographic transport parameters, certificate
    settings, redirect anomalies, and historical endpoint consistency.

    Note on Epistemic Honesty:
      Technical checks verify wire encryption and endpoint behavior; they NEVER prove
      that an anonymous exit-node operator is trustworthy or non-logging.
    """
    raw_u = (uri or "").strip()
    cfg_hash = hashlib.sha256(raw_u.split("#", 1)[0].encode("utf-8", "ignore")).hexdigest()[:16]

    if not raw_u or len(raw_u) > MAX_URI_LENGTH or _CONTROL_CHARS_RE.search(raw_u):
        return SecurityReport(
            config_hash=cfg_hash,
            protocol="unknown",
            host="",
            port=0,
            security_assessment="Failed",
            privacy_assessment="High Risk",
            risk_level="CRITICAL",
            quarantined=True,
            quarantine_reason="malformed_or_control_chars",
            measured_facts=["malformed_payload"],
        )

    ident_any = parse_identity(raw_u, reject_private_hosts=False)
    if ident_any is None:
        return SecurityReport(
            config_hash=cfg_hash,
            protocol="unknown",
            host="",
            port=0,
            security_assessment="Failed",
            privacy_assessment="High Risk",
            risk_level="CRITICAL",
            quarantined=True,
            quarantine_reason="unparseable_uri_structure",
            measured_facts=["invalid_uri_structure"],
        )

    host = ident_any.host
    port = ident_any.port
    cproto = ident_any.canonical_proto

    if is_unsafe_config_host(host):
        return SecurityReport(
            config_hash=cfg_hash,
            protocol=cproto,
            host=host,
            port=port,
            security_assessment="Failed",
            privacy_assessment="High Risk",
            risk_level="CRITICAL",
            quarantined=True,
            quarantine_reason="unsafe_private_or_reserved_endpoint",
            measured_facts=["private_or_loopback_target"],
        )

    if threat_intel and threat_intel.matches_host(host):
        return SecurityReport(
            config_hash=cfg_hash,
            protocol=cproto,
            host=host,
            port=port,
            security_assessment="Failed",
            privacy_assessment="High Risk",
            risk_level="CRITICAL",
            quarantined=True,
            quarantine_reason="threat_intel_indicator_match",
            measured_facts=["matched_threat_intel_indicator"],
        )

    if port in SUSPICIOUS_SERVICE_PORTS:
        return SecurityReport(
            config_hash=cfg_hash,
            protocol=cproto,
            host=host,
            port=port,
            security_assessment="Failed",
            privacy_assessment="High Risk",
            risk_level="CRITICAL",
            quarantined=True,
            quarantine_reason=f"suspicious_infrastructure_port:{port}",
            measured_facts=[f"non_proxy_service_port:{port}"],
        )

    # Detect unexpected HTTP redirect hijacking on generate_204 (never redirects legitimately)
    redirect_anomaly = probe_error in ("http_301", "http_302", "http_303", "http_307", "http_308")
    if redirect_anomaly:
        return SecurityReport(
            config_hash=cfg_hash,
            protocol=cproto,
            host=host,
            port=port,
            security_assessment="Failed",
            privacy_assessment="High Risk",
            risk_level="CRITICAL",
            quarantined=True,
            quarantine_reason=f"unexpected_http_redirect:{probe_error}",
            redirect_anomaly=True,
            measured_facts=[f"probe_redirected:{probe_error}"],
            inferred_risks=["possible_captive_portal_or_traffic_interception"],
        )

    # Parse protocol-specific security attributes
    no_frag = raw_u.partition("://")[2].split("#", 1)[0]
    q_raw = no_frag.partition("?")[2]
    q: dict[str, str] = {k.lower(): v for k, v in parse_qsl(q_raw, keep_blank_values=True)}

    measured_facts: list[str] = []
    inferred_risks: list[str] = []
    tls_enabled = False
    allow_insecure = False
    sni = ""
    aead_cipher = False
    security_mode = "none"

    if cproto == "vmess":
        vm = _safe_b64_json(no_frag.split("?", 1)[0]) or {}
        tls_val = str(vm.get("tls") or "").strip().lower()
        scy = str(vm.get("scy") or "auto").strip().lower()
        sni = str(vm.get("sni") or vm.get("host") or "").strip()
        allow_insecure = str(vm.get("allowInsecure") or q.get("allowinsecure") or "").lower() in ("1", "true")
        tls_enabled = tls_val in ("tls", "xtls")
        security_mode = "tls" if tls_enabled else "none"
        if scy in CRITICAL_BROKEN_CIPHERS and not tls_enabled:
            return SecurityReport(
                config_hash=cfg_hash,
                protocol=cproto,
                host=host,
                port=port,
                security_assessment="Failed",
                privacy_assessment="High Risk",
                risk_level="CRITICAL",
                quarantined=True,
                quarantine_reason="unencrypted_vmess_none_without_tls",
                measured_facts=["vmess_cipher:none", "tls:disabled"],
            )
        aead_cipher = scy in ("auto", "aes-128-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305")
        measured_facts.append(f"vmess_cipher:{scy}")

    elif cproto == "vless":
        sec = (q.get("security") or "none").strip().lower()
        security_mode = sec
        sni = (q.get("sni") or q.get("peer") or q.get("host") or "").strip()
        allow_insecure = (q.get("allowinsecure") in ("1", "true")) or (q.get("insecure") in ("1", "true"))
        if sec == "reality":
            pbk = (q.get("pbk") or "").strip()
            if not _REALITY_PBK_RE.match(pbk):
                return SecurityReport(
                    config_hash=cfg_hash,
                    protocol=cproto,
                    host=host,
                    port=port,
                    security_assessment="Failed",
                    privacy_assessment="High Risk",
                    risk_level="CRITICAL",
                    quarantined=True,
                    quarantine_reason="invalid_or_missing_reality_public_key",
                    measured_facts=["reality_pbk:invalid"],
                )
            tls_enabled = True
            aead_cipher = True
            measured_facts.append("transport_security:vless_reality_tls13")
        elif sec in ("tls", "xtls"):
            tls_enabled = True
            aead_cipher = True
            measured_facts.append(f"transport_security:vless_{sec}")
        else:
            measured_facts.append("transport_security:cleartext_vless")

    elif cproto in ("trojan", "hysteria2", "tuic"):
        tls_enabled = True
        aead_cipher = True
        security_mode = "tls"
        sni = (q.get("sni") or q.get("peer") or host).strip()
        allow_insecure = (q.get("allowinsecure") in ("1", "true")) or (q.get("insecure") in ("1", "true"))
        measured_facts.append(f"transport_security:{cproto}_tls")

    elif cproto == "ss":
        security_mode = "ss_cipher"
        main_part = no_frag.partition("?")[0].rstrip("/")
        method = ""
        if "@" in main_part:
            uinfo = unquote(main_part.rpartition("@")[0])
            pad = uinfo + "=" * (-len(uinfo) % 4)
            dec_u = None
            for fn in (base64.urlsafe_b64decode, base64.b64decode):
                try:
                    dec_u = fn(pad).decode("utf-8", "strict")
                    break
                except Exception:
                    continue
            mp = dec_u if (dec_u and ":" in dec_u) else uinfo
            method = mp.partition(":")[0].strip().lower()
        else:
            pad = unquote(main_part) + "=" * (-len(unquote(main_part)) % 4)
            for fn in (base64.urlsafe_b64decode, base64.b64decode):
                try:
                    dec_all = fn(pad).decode("utf-8", "strict")
                    method = dec_all.rpartition("@")[0].partition(":")[0].strip().lower()
                    break
                except Exception:
                    continue

        measured_facts.append(f"ss_cipher:{method or 'unknown'}")
        if method in CRITICAL_BROKEN_CIPHERS:
            return SecurityReport(
                config_hash=cfg_hash,
                protocol=cproto,
                host=host,
                port=port,
                security_assessment="Failed",
                privacy_assessment="High Risk",
                risk_level="CRITICAL",
                quarantined=True,
                quarantine_reason=f"broken_ss_cipher:{method}",
                measured_facts=measured_facts,
            )
        aead_cipher = method in AEAD_STRONG_CIPHERS
        if method in DEPRECATED_WEAK_CIPHERS:
            inferred_risks.append(f"deprecated_stream_cipher:{method}")

    elif cproto == "ssr":
        security_mode = "ssr_legacy"
        measured_facts.append("legacy_protocol:ssr")
        inferred_risks.append("legacy_obfuscation_without_modern_aead")

    # Detect unexpected security downgrade or exit-country mutation across runs
    endpoint_changed = False
    if prior_security_mode in ("tls", "reality") and security_mode == "none":
        return SecurityReport(
            config_hash=cfg_hash,
            protocol=cproto,
            host=host,
            port=port,
            security_assessment="Failed",
            privacy_assessment="High Risk",
            risk_level="CRITICAL",
            quarantined=True,
            quarantine_reason="unexpected_tls_downgrade",
            endpoint_changed=True,
            measured_facts=measured_facts + ["tls_downgraded_from_prior_run"],
        )

    if (
        prior_exit_country
        and prior_exit_country != "XX"
        and current_exit_country
        and current_exit_country != "XX"
        and prior_exit_country != current_exit_country
    ):
        endpoint_changed = True
        measured_facts.append(f"exit_country_changed:{prior_exit_country}->{current_exit_country}")
        inferred_risks.append("exit_routing_shifted_between_runs")

    if not dns_consistent:
        inferred_risks.append("dns_resolution_inconsistency")

    sni_aligned = True
    if tls_enabled:
        eff_sni = sni or host
        if security_mode == "reality":
            # VLESS-REALITY intentionally camouflages SNI while authenticating server via Curve25519 pbk
            sni_aligned = True
        elif _is_ip_literal(host) and eff_sni == host:
            sni_aligned = False
            inferred_risks.append("ip_literal_tls_without_domain_sni")
        else:
            sni_aligned = _sni_matches_host(host, eff_sni)
            if not sni_aligned:
                measured_facts.append("sni_differs_from_endpoint_host")

    tls_verified = bool(tls_enabled and not allow_insecure and (tls_probe_verified or security_mode == "reality"))

    # Final independent Security & Privacy classification
    if allow_insecure:
        measured_facts.append("tls_certificate_verification_disabled")
        inferred_risks.append("vulnerable_to_active_mitm")
        sec_assessment = "Failed"
        priv_assessment = "High Risk"
        risk_level = "HIGH"
    elif cproto in ("vless", "vmess") and not tls_enabled:
        inferred_risks.append("outer_transport_not_tls_protected")
        sec_assessment = "Failed"
        priv_assessment = "High Risk"
        risk_level = "HIGH"
    elif cproto == "ssr" or (cproto == "ss" and not aead_cipher):
        sec_assessment = "Failed"
        priv_assessment = "High Risk"
        risk_level = "HIGH"
    elif tls_enabled and not allow_insecure and aead_cipher and dns_consistent and not endpoint_changed:
        if sni_aligned and tls_verified:
            sec_assessment = "Verified"
            risk_level = "LOW"
        else:
            sec_assessment = "Partial"
            risk_level = "MEDIUM" if (not sni_aligned or not tls_probe_verified) else "LOW"
        priv_assessment = "Verified" if operator_attested_vip else "Unverified"
    elif cproto == "ss" and aead_cipher and dns_consistent and not endpoint_changed:
        # Shadowsocks AEAD encrypts payload, though lacks X.509 server certificate identity
        sec_assessment = "Partial"
        risk_level = "MEDIUM"
        priv_assessment = "Verified" if operator_attested_vip else "Unverified"
    else:
        sec_assessment = "Partial" if (tls_enabled or aead_cipher) else "Unknown"
        risk_level = "MEDIUM" if (endpoint_changed or not dns_consistent) else "UNKNOWN"
        priv_assessment = "Unknown"

    if not operator_attested_vip and priv_assessment not in ("High Risk", "Unknown"):
        inferred_risks.append("anonymous_operator_logging_policy_unverifiable")

    return SecurityReport(
        config_hash=cfg_hash,
        protocol=cproto,
        host=host,
        port=port,
        security_assessment=sec_assessment,
        privacy_assessment=priv_assessment,
        risk_level=risk_level,
        quarantined=False,
        tls_enabled=tls_enabled,
        tls_verified=tls_verified,
        allow_insecure=allow_insecure,
        sni_aligned=sni_aligned,
        aead_cipher=aead_cipher,
        dns_consistent=dns_consistent,
        redirect_anomaly=False,
        endpoint_changed=endpoint_changed,
        measured_facts=measured_facts,
        inferred_risks=inferred_risks,
    )


def compute_freshness_decay(verified_at_iso: str, now_iso: str = "") -> float:
    """
    Continuous staleness penalty factor in [0.55, 1.00]:
      - <= 1 hour old  -> 1.00
      - 6 hours old    -> ~0.92
      - 24 hours old   -> ~0.78
      - >= 72 hours    -> 0.55
    """
    if not verified_at_iso:
        return 0.85
    try:
        t_ver = datetime.fromisoformat(verified_at_iso.replace("Z", "+00:00"))
        t_now = (
            datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
            if now_iso
            else datetime.now(timezone.utc)
        )
        age_hours = max(0.0, (t_now - t_ver).total_seconds() / 3600.0)
    except Exception:
        return 0.85

    if age_hours <= 1.0:
        return 1.0
    decay = math.exp(-(age_hours - 1.0) / 85.0)
    return max(0.55, min(1.0, decay))


def compute_multidimensional_scores(
    *,
    median_latency_ms: float,
    jitter_ms: float,
    probe_pass_rate: float,
    speed_kbps: float,
    upload_kbps: float = 0.0,
    runs_seen: int = 1,
    runs_alive: int = 1,
    consecutive_alive: int = 1,
    ema_reliability: float = 0.65,
    recent_failures: int = 0,
    verified_at: str = "",
    now_iso: str = "",
    prior_performance_score: float = 0.0,
    security_report: SecurityReport,
) -> MultiDimensionalScore:
    """
    Compute independent Performance (0..100) and Reliability (0..100) scores
    alongside honest Security & Privacy assessments.
    """
    freshness = compute_freshness_decay(verified_at, now_iso)
    clamped_pass = max(0.0, min(1.0, probe_pass_rate))
    packet_loss_pct = (1.0 - clamped_pass) * 100.0
    uptime_pct = (max(0, runs_alive) / max(1, runs_seen)) * 100.0

    # ── 1) Independent Performance Score (0..100) ──
    # Latency component (0..100)
    if median_latency_ms > 0:
        lat_component = 100.0 * math.exp(-max(0.0, median_latency_ms - 15.0) / 680.0)
    else:
        lat_component = 0.0

    # Jitter stability component (0..100)
    eff_lat = max(35.0, median_latency_ms if median_latency_ms > 0 else 400.0)
    jitter_ratio = max(0.0, jitter_ms) / eff_lat
    jitter_component = max(0.0, 100.0 - min(85.0, jitter_ratio * 70.0 + max(0.0, jitter_ms) / 14.0))

    # Throughput component (never fabricates speed when unmeasured!)
    has_dl = speed_kbps > 0.0
    has_ul = upload_kbps > 0.0
    if has_dl:
        dl_norm = (math.log10(max(16.0, speed_kbps)) - 1.2) / 3.2
        dl_component = max(5.0, min(100.0, dl_norm * 100.0))
        if has_ul:
            ul_norm = (math.log10(max(16.0, upload_kbps)) - 1.2) / 3.0
            ul_component = max(5.0, min(100.0, ul_norm * 100.0))
            tp_component = 0.80 * dl_component + 0.20 * ul_component
        else:
            tp_component = dl_component
        raw_perf = 0.50 * tp_component + 0.35 * lat_component + 0.15 * jitter_component
    else:
        # Unmeasured throughput: score strictly from measured latency & jitter with an
        # explicit incompleteness cap (0.78) so unmeasured servers never outrank proven high-Mbps servers.
        tp_component = 0.0
        raw_perf = (0.68 * lat_component + 0.32 * jitter_component) * 0.78

    # Penalize packet loss inside performance as well (lossy links stall TCP congestion windows)
    loss_multiplier = max(0.35, 1.0 - 0.65 * (packet_loss_pct / 100.0))
    performance_score = max(0.0, min(100.0, raw_perf * loss_multiplier * freshness))

    # ── 2) Independent Reliability Score (0..100) ──
    # Bayesian-shrunk historical uptime so a 1/1 brand-new node gets ~68% empirical base instead of 100%
    bayes_uptime = (max(0, runs_alive) + 1.4) / (max(1, runs_seen) + 2.5)
    streak_factor = min(1.0, math.log2(max(1, consecutive_alive) + 1) / 3.2)
    failure_penalty = min(40.0, recent_failures * 12.0 + packet_loss_pct * 0.45)

    raw_rel = (
        0.38 * (clamped_pass * 100.0)
        + 0.32 * (max(0.0, min(1.0, ema_reliability)) * 100.0)
        + 0.20 * (bayes_uptime * 100.0)
        + 0.10 * (streak_factor * 100.0)
        - failure_penalty
    )
    reliability_score = max(0.0, min(100.0, raw_rel * freshness))

    delta = (performance_score - prior_performance_score) if prior_performance_score > 0 else 0.0

    return MultiDimensionalScore(
        performance_score=round(performance_score, 2),
        reliability_score=round(reliability_score, 2),
        security_assessment=security_report.security_assessment,
        privacy_assessment=security_report.privacy_assessment,
        risk_level=security_report.risk_level,
        packet_loss_pct=round(packet_loss_pct, 2),
        uptime_pct=round(uptime_pct, 2),
        freshness_factor=round(freshness, 3),
        score_delta=round(delta, 2),
        factors={
            "latency_component": lat_component,
            "jitter_component": jitter_component,
            "throughput_component": tp_component,
            "freshness_factor_pct": freshness * 100.0,
            "failure_penalty": failure_penalty,
        },
    )


@dataclass
class QuarantinedEntry:
    config_hash: str
    protocol: str
    redacted_endpoint: str
    reason: str
    risk_level: str
    source_names: list[str]
    detected_at: str

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "config_hash": self.config_hash,
            "protocol": self.protocol,
            "redacted_endpoint": self.redacted_endpoint,
            "reason": self.reason,
            "risk_level": self.risk_level,
            "sources_count": len(self.source_names),
            "detected_at": self.detected_at,
        }


class QuarantineRegistry:
    """
    Secret-safe quarantine store for suspicious, malformed, MITM-prone, or
    redirect-hijacked configurations. Never writes raw URIs or credentials.
    """

    def __init__(self) -> None:
        self.entries: dict[str, QuarantinedEntry] = {}

    def record(
        self,
        uri: str,
        report: SecurityReport,
        *,
        sources: Iterable[str] = (),
        timestamp: str = "",
    ) -> QuarantinedEntry:
        ts = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        redacted_ep = redact_uri(uri)[:96] if uri else f"{report.protocol}://[redacted]"
        entry = QuarantinedEntry(
            config_hash=report.config_hash,
            protocol=report.protocol,
            redacted_endpoint=redacted_ep,
            reason=report.quarantine_reason or f"risk_{report.risk_level.lower()}",
            risk_level=report.risk_level,
            source_names=sorted(set(sources)),
            detected_at=ts,
        )
        self.entries[report.config_hash] = entry
        return entry

    def summary_by_reason(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for e in self.entries.values():
            key = e.reason.split(":", 1)[0]
            counts[key] = counts.get(key, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))

    def save_public_report(self, path: Path) -> None:
        payload = {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "quarantined_total": len(self.entries),
            "reasons_summary": self.summary_by_reason(),
            "entries": [
                e.to_public_dict()
                for e in list(self.entries.values())[:500]
            ],
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        tmp.replace(path)
