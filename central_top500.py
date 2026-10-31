#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
central_top500.py — Central GitHub Server Database & Top-500 Candidate Pool Publisher.

Architectural Contract (Mandatory Responsibility Separation):
  • GitHub collects, validates, normalizes, deduplicates, assigns stable server IDs,
    performs preliminary availability/endpoint checks, filters invalid/unsuitable
    configurations, applies central eligibility rules, and publishes UP TO 500
    qualified candidate configurations (`top500.json`, `top500.txt`,
    `top500.manifest.json`, and optional incremental `top500.delta.json`).
  • GitHub NEVER selects the personalized Top 50 for individual Android users.
  • GitHub NEVER fabricates configurations or pads unqualified servers to reach 500.
  • All public VPN configurations are explicitly marked as UNTRUSTED_PUBLIC_SERVER.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import base64
import os

import collector
from dedupe import parse_identity
from scoring import ScoredNode, country_flag, diversify_scored_nodes

CENTRAL_TOP500_MAX = 500
CENTRAL_TOP500_SCHEMA_VERSION = "1.0.0"
SUPPORTED_CENTRAL_PROTOCOLS = frozenset({"vless", "vmess", "trojan", "hysteria2", "ss", "tuic", "socks", "http"})


def strip_uri_fragment(uri: str) -> str:
    """Return trimmed proxy URI without `#remark` fragment for canonical integrity hashing."""
    return (uri or "").strip().split("#", 1)[0].strip()


def compute_config_fingerprint(uri: str) -> str:
    """
    Compute a deterministic, secret-free 32-hex configuration fingerprint.
    Changes whenever endpoint, protocol, transport, TLS, or hashed credential changes,
    while remaining invariant across `#remark` renames.
    """
    clean_no_frag = strip_uri_fragment(uri)
    ident = parse_identity(clean_no_frag, reject_private_hosts=True)
    if ident is not None:
        material = f"bahrain-vpn:cfg-fp:v1|{ident.canonical_sha256}|{ident.layer1_exact_id}"
    else:
        material = f"bahrain-vpn:cfg-fp:raw|{hashlib.sha256(clean_no_frag.encode('utf-8', 'ignore')).hexdigest()}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def compute_configs_set_sha256(entries: list[dict[str, Any]]) -> str:
    """
    Canonical SHA-256 checksum over the ordered Top-500 candidate set:
    `{server_id}|{config_fingerprint}|{clean_uri_without_fragment}` per line.
    Verifiable identically on Python (GitHub) and Kotlin (Android) after full or delta sync.
    """
    lines = [
        f"{item['server_id']}|{item['config_fingerprint']}|{strip_uri_fragment(str(item.get('cfg', '')))}"
        for item in entries
    ]
    payload = "\n".join(lines).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def is_qualified_for_central_pool(node: ScoredNode) -> bool:
    """
    Central eligibility gate:
      1. Supported protocol & valid non-private canonical identity.
      2. Not quarantined by security intelligence.
      3. Passed preliminary endpoint/tunnel availability check (positive latency <= 8000ms, pass_rate > 0).
      4. Zero active consecutive failure streak (`recent_failures == 0`).
    """
    if not node or not node.uri or "://" not in node.uri:
        return False
    if node.canonical_protocol not in SUPPORTED_CENTRAL_PROTOCOLS:
        return False
    if str(node.risk_level).upper() == "QUARANTINED" or str(node.security_assessment).upper() == "QUARANTINED":
        return False
    if node.median_latency_ms <= 0 or node.median_latency_ms > 8000:
        return False
    if node.probe_pass_rate <= 0.0:
        return False
    if getattr(node, "recent_failures", 0) > 0:
        return False
    ident = parse_identity(node.uri, reject_private_hosts=True)
    return ident is not None and bool(ident.identity_id)


def select_central_top500(
    scored_nodes: list[ScoredNode],
    *,
    limit: int = CENTRAL_TOP500_MAX,
    max_per_host: int = 4,
    max_per_subnet: int = 12,
) -> list[ScoredNode]:
    """
    Filter strictly to qualified configurations and select UP TO `limit` (default 500)
    centrally ranked candidates with host/subnet diversity.
    Never fabricates configurations or pads unqualified nodes to reach 500.
    """
    cap = max(0, min(int(limit), CENTRAL_TOP500_MAX))
    if cap == 0 or not scored_nodes:
        return []

    qualified = [n for n in scored_nodes if is_qualified_for_central_pool(n)]
    if not qualified:
        return []

    qualified.sort(key=lambda n: (-float(n.score), float(n.median_latency_ms), n.identity_id))

    diversified = diversify_scored_nodes(
        qualified,
        max_per_host=max_per_host,
        max_per_subnet=max_per_subnet,
        limit=cap,
    )
    if len(diversified) < min(cap, len(qualified)):
        chosen_ids = {n.identity_id for n in diversified}
        for n in qualified:
            if n.identity_id not in chosen_ids:
                diversified.append(n)
                chosen_ids.add(n.identity_id)
                if len(diversified) >= cap:
                    break
    return diversified[:cap]


def _format_candidate_uri(rank_idx: int, node: ScoredNode) -> str:
    parts = [f"bahrain-vpn {rank_idx}"]
    if node.exit_country and node.exit_country != "XX":
        parts.append(f"{country_flag(node.exit_country)} {node.exit_country}")
    parts.append(f"pool#{rank_idx}")
    return collector.set_uri_remark(strip_uri_fragment(node.uri), " | ".join(parts))


def _iso_to_epoch(iso_str: str) -> int:
    try:
        s = iso_str.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return int(datetime.fromisoformat(s).timestamp())
    except Exception:
        return int(datetime.now(timezone.utc).timestamp())


def _write_atomic_bytes(path: Path, data: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)
    return hashlib.sha256(data).hexdigest()


def export_central_top500_dataset(
    out_dir: Path,
    scored_nodes: list[ScoredNode],
    *,
    prev_dir: Path | None = None,
    generated_at: str = "",
    limit: int = CENTRAL_TOP500_MAX,
) -> dict[str, Any]:
    """
    Publish the Central GitHub Top-500 Candidate Pool and Dataset Delivery suite:
      • `top500.json`          — Up to 500 qualified candidate configs + IDs + fingerprints
      • `top500.txt`           — Plaintext URI list of the same qualified pool
      • `top500.delta.json`    — Optional incremental diff from previous `top500.json`
      • `top500.manifest.json` — Version, timestamp, server IDs, SHA-256 checksums, delta metadata
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    now_iso = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    now_epoch = _iso_to_epoch(now_iso)

    prev_version = 0
    prev_payload: dict[str, Any] | None = None
    for cand_dir in [prev_dir, out]:
        if cand_dir and Path(cand_dir).is_dir():
            mf = Path(cand_dir) / "top500.manifest.json"
            if mf.is_file():
                try:
                    mobj = json.loads(mf.read_text(encoding="utf-8"))
                    prev_version = max(prev_version, int(mobj.get("dataset_version", 0)))
                except Exception:
                    pass
            pj = Path(cand_dir) / "top500.json"
            if prev_payload is None and pj.is_file():
                try:
                    loaded = json.loads(pj.read_text(encoding="utf-8"))
                    if isinstance(loaded.get("servers"), list):
                        prev_payload = loaded
                        prev_version = max(prev_version, int(loaded.get("dataset_version", 0)))
                except Exception:
                    prev_payload = None

    dataset_version = max(prev_version + 1, now_epoch)
    selected = select_central_top500(scored_nodes, limit=limit)

    servers_out: list[dict[str, Any]] = []
    txt_lines: list[str] = []
    seen_server_ids: set[str] = set()

    for idx, node in enumerate(selected, 1):
        ident = parse_identity(node.uri, reject_private_hosts=True)
        sid = ident.identity_id if ident else node.identity_id
        if not sid or sid in seen_server_ids:
            continue
        seen_server_ids.add(sid)
        rank_no = len(servers_out) + 1
        labeled_uri = _format_candidate_uri(rank_no, node)
        cfg_fp = compute_config_fingerprint(labeled_uri)
        txt_lines.append(labeled_uri)
        servers_out.append({
            "central_rank": rank_no,
            "server_id": sid,
            "config_fingerprint": cfg_fp,
            "cfg": labeled_uri,
            "protocol": node.canonical_protocol,
            "country": node.exit_country if node.exit_country and node.exit_country != "XX" else "",
            "country_source": node.country_source or "unknown",
            "preliminary_latency_ms": round(float(node.median_latency_ms), 1),
            "central_quality_score": round(float(node.score), 2),
            "stability_runs": int(node.consecutive_alive),
            "security_assessment": node.security_assessment,
            "privacy_assessment": node.privacy_assessment,
            "risk_level": node.risk_level,
            "trust_posture": "UNTRUSTED_PUBLIC_SERVER",
        })

    configs_sha256 = compute_configs_set_sha256(servers_out)

    top500_doc = {
        "schema_version": CENTRAL_TOP500_SCHEMA_VERSION,
        "dataset_version": dataset_version,
        "generated_at": now_iso,
        "generated_at_epoch": now_epoch,
        "role": "CENTRAL_CANDIDATE_POOL",
        "personalized_top50_authority": "ANDROID_LOCAL_ONLY",
        "personalized_top50_selected_by_github": False,
        "trust_notice": "Public VPN configurations are untrusted candidates. Final Top-50 selection requires local sequential tunnel testing on the user's own Wi-Fi or Mobile Data network.",
        "max_capacity": CENTRAL_TOP500_MAX,
        "qualified_count": len(servers_out),
        "configs_sha256": configs_sha256,
        "servers": servers_out,
    }
    top500_json_bytes = (json.dumps(top500_doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    top500_json_sha256 = _write_atomic_bytes(out / "top500.json", top500_json_bytes)

    top500_txt_bytes = ("\n".join(txt_lines) + ("\n" if txt_lines else "")).encode("utf-8")
    top500_txt_sha256 = _write_atomic_bytes(out / "top500.txt", top500_txt_bytes)

    # Optional incremental delta update against previous valid `top500.json`
    delta_available = False
    delta_sha256 = ""
    base_ver: int | None = None
    base_configs_sha: str | None = None

    if prev_payload is not None and isinstance(prev_payload.get("servers"), list):
        prev_servers = prev_payload["servers"]
        prev_by_id: dict[str, dict[str, Any]] = {
            str(s.get("server_id")): s for s in prev_servers if s.get("server_id")
        }
        base_ver = int(prev_payload.get("dataset_version", 0))
        base_configs_sha = str(prev_payload.get("configs_sha256") or compute_configs_set_sha256(prev_servers))
        if base_ver > 0 and base_ver < dataset_version and base_configs_sha:
            cur_by_id = {s["server_id"]: s for s in servers_out}
            added_or_updated = [
                s for s in servers_out
                if s["server_id"] not in prev_by_id
                or prev_by_id[s["server_id"]].get("config_fingerprint") != s["config_fingerprint"]
                or strip_uri_fragment(str(prev_by_id[s["server_id"]].get("cfg", ""))) != strip_uri_fragment(s["cfg"])
            ]
            removed_ids = sorted(sid for sid in prev_by_id.keys() if sid not in cur_by_id)
            delta_doc = {
                "schema_version": CENTRAL_TOP500_SCHEMA_VERSION,
                "base_dataset_version": base_ver,
                "base_configs_sha256": base_configs_sha,
                "target_dataset_version": dataset_version,
                "target_generated_at": now_iso,
                "target_generated_at_epoch": now_epoch,
                "target_qualified_count": len(servers_out),
                "target_configs_sha256": configs_sha256,
                "added_or_updated": added_or_updated,
                "removed_server_ids": removed_ids,
                "ordered_server_ids": [s["server_id"] for s in servers_out],
            }
            delta_bytes = (json.dumps(delta_doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
            delta_sha256 = _write_atomic_bytes(out / "top500.delta.json", delta_bytes)
            delta_available = True

    manifest_doc = {
        "schema_version": CENTRAL_TOP500_SCHEMA_VERSION,
        "dataset_version": dataset_version,
        "generated_at": now_iso,
        "generated_at_epoch": now_epoch,
        "role": "CENTRAL_CANDIDATE_POOL",
        "personalized_top50_authority": "ANDROID_LOCAL_ONLY",
        "personalized_top50_selected_by_github": False,
        "max_capacity": CENTRAL_TOP500_MAX,
        "qualified_count": len(servers_out),
        "checksums": {
            "top500_json_sha256": top500_json_sha256,
            "top500_txt_sha256": top500_txt_sha256,
            "configs_sha256": configs_sha256,
            "delta_json_sha256": delta_sha256,
        },
        "delta_available": delta_available,
        "delta_base_version": base_ver,
        "delta_base_configs_sha256": base_configs_sha,
        "server_ids": [s["server_id"] for s in servers_out],
        "config_fingerprints": {s["server_id"]: s["config_fingerprint"] for s in servers_out},
    }
    manifest_bytes = (json.dumps(manifest_doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    _write_atomic_bytes(out / "top500.manifest.json", manifest_bytes)
    sign_manifest_file(out / "top500.manifest.json", manifest_bytes)
    return manifest_doc


MANIFEST_SIGNING_KEY_ENV = "TOP500_SIGNING_KEY_B64"


def sign_manifest_file(manifest_path: Path, manifest_bytes: bytes, key_b64: str | None = None) -> str | None:
    """Write `<manifest>.sig` = base64(ECDSA P-256/SHA-256 DER signature over the exact manifest bytes).

    The private key (PKCS#8 DER, base64) comes from the `TOP500_SIGNING_KEY_B64` secret.
    When it is absent the manifest is published unsigned (transition mode) and any stale
    signature file is removed so clients never see a mismatched pair.
    """
    sig_path = manifest_path.with_name(manifest_path.name + ".sig")
    key_b64 = (key_b64 if key_b64 is not None else os.environ.get(MANIFEST_SIGNING_KEY_ENV, "")).strip()
    if not key_b64:
        sig_path.unlink(missing_ok=True)
        return None
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    priv = serialization.load_der_private_key(base64.b64decode(key_b64), password=None)
    if not isinstance(priv, ec.EllipticCurvePrivateKey) or priv.curve.name != "secp256r1":
        raise ValueError("TOP500_SIGNING_KEY_B64 must be an ECDSA P-256 PKCS#8 key")
    sig_b64 = base64.b64encode(priv.sign(manifest_bytes, ec.ECDSA(hashes.SHA256()))).decode("ascii")
    _write_atomic_bytes(sig_path, (sig_b64 + "\n").encode("ascii"))
    return sig_b64
