#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tests/test_top500_architecture.py — Verification of Central GitHub Top-500 Server Database,
anti-padding rules, responsibility separation, SHA-256 checksums, and incremental delta sync.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from central_top500 import (
    CENTRAL_TOP500_MAX,
    compute_config_fingerprint,
    compute_configs_set_sha256,
    export_central_top500_dataset,
    is_qualified_for_central_pool,
    select_central_top500,
    strip_uri_fragment,
)
from dedupe import parse_identity
from scoring import ScoredNode


def _make_scored_node(
    idx: int,
    *,
    latency_ms: float = 95.0,
    score: float = 82.0,
    risk_level: str = "LOW",
    pass_rate: float = 1.0,
    recent_failures: int = 0,
    host_prefix: str = "198.51.100",
    sni: str = "cdn.cloudflare.com",
) -> ScoredNode:
    octet = (idx % 240) + 10
    port = 443 + (idx // 240)
    uuid_str = f"11111111-2222-3333-4444-{idx:012d}"
    uri = f"vless://{uuid_str}@{host_prefix}.{octet}:{port}?encryption=none&security=tls&sni={sni}&type=ws#node-{idx}"
    ident = parse_identity(uri)
    assert ident is not None
    return ScoredNode(
        uri=uri,
        identity_id=ident.identity_id,
        protocol="vless",
        canonical_protocol="vless",
        host=ident.host,
        port=ident.port,
        subnet_key=ident.subnet_key,
        latency_ms=latency_ms,
        median_latency_ms=latency_ms,
        jitter_ms=6.0,
        probe_pass_rate=pass_rate,
        speed_kbps=1800.0,
        exit_country="DE",
        country_source="exit_trace",
        is_cdn=False,
        is_warp=False,
        runs_seen=3,
        runs_alive=3,
        consecutive_alive=3,
        ema_reliability=0.92,
        corroboration_count=2,
        verified_source_hit=True,
        engine="sing-box",
        score=score,
        verified_at="2026-10-30T18:00:00Z",
        performance_score=score,
        reliability_score=88.0,
        security_assessment="TLS_VERIFIED",
        privacy_assessment="STANDARD",
        risk_level=risk_level,
        packet_loss_pct=0.0,
        uptime_pct=99.0,
        recent_failures=recent_failures,
    )


def test_central_top500_never_fabricates_or_pads_unqualified_servers(tmp_path: Path) -> None:
    good = [_make_scored_node(i, score=90.0 - i) for i in range(1, 18)]
    quarantined = _make_scored_node(901, risk_level="QUARANTINED", score=99.0)
    dead = _make_scored_node(902, latency_ms=0.0, pass_rate=0.0, score=95.0)
    failing = _make_scored_node(903, recent_failures=2, score=91.0)
    private_bad = _make_scored_node(904)
    private_bad.uri = "vless://11111111-2222-3333-4444-000000000904@127.0.0.1:443?security=tls"

    assert not is_qualified_for_central_pool(quarantined)
    assert not is_qualified_for_central_pool(dead)
    assert not is_qualified_for_central_pool(failing)
    assert not is_qualified_for_central_pool(private_bad)

    selected = select_central_top500(good + [quarantined, dead, failing, private_bad])
    # Must contain ONLY the 17 qualified servers, NEVER padded to 500 or 50!
    assert len(selected) == 17

    manifest = export_central_top500_dataset(
        tmp_path,
        good + [quarantined, dead, failing, private_bad],
        generated_at="2026-10-30T19:00:00Z",
    )
    assert manifest["qualified_count"] == 17
    assert manifest["max_capacity"] == CENTRAL_TOP500_MAX
    assert manifest["role"] == "CENTRAL_CANDIDATE_POOL"
    assert manifest["personalized_top50_authority"] == "ANDROID_LOCAL_ONLY"
    assert manifest["personalized_top50_selected_by_github"] is False

    # Verify GitHub does NOT emit any personalized Top-50 artifact
    assert not (tmp_path / "top50.json").exists()
    assert not (tmp_path / "personalized-top50.json").exists()


def test_central_top500_caps_strictly_at_500_when_more_qualify() -> None:
    many = [
        _make_scored_node(i, score=100.0 - (i * 0.05), host_prefix=f"198.51.{10 + (i // 200)}")
        for i in range(1, 640)
    ]
    selected = select_central_top500(many)
    assert len(selected) == CENTRAL_TOP500_MAX
    assert len({n.identity_id for n in selected}) == CENTRAL_TOP500_MAX


def test_top500_checksums_monotonic_versions_and_incremental_delta_sync(tmp_path: Path) -> None:
    snap1_dir = tmp_path / "snap1"
    snap2_dir = tmp_path / "snap2"

    pool_v1 = [_make_scored_node(i, score=95.0 - i) for i in range(1, 11)]
    m1 = export_central_top500_dataset(snap1_dir, pool_v1, generated_at="2026-10-30T18:00:00Z")
    assert m1["delta_available"] is False

    raw_json_v1 = (snap1_dir / "top500.json").read_bytes()
    raw_txt_v1 = (snap1_dir / "top500.txt").read_bytes()
    assert hashlib.sha256(raw_json_v1).hexdigest() == m1["checksums"]["top500_json_sha256"]
    assert hashlib.sha256(raw_txt_v1).hexdigest() == m1["checksums"]["top500_txt_sha256"]

    doc_v1 = json.loads(raw_json_v1.decode("utf-8"))
    assert compute_configs_set_sha256(doc_v1["servers"]) == m1["checksums"]["configs_sha256"]
    assert all(s["trust_posture"] == "UNTRUSTED_PUBLIC_SERVER" for s in doc_v1["servers"])

    # Remark-only rename must NOT alter config_fingerprint
    fp_a = compute_config_fingerprint(doc_v1["servers"][0]["cfg"])
    fp_b = compute_config_fingerprint(strip_uri_fragment(doc_v1["servers"][0]["cfg"]) + "#other-remark")
    assert fp_a == fp_b

    # Snapshot 2: drop node #10, modify node #2 SNI, add node #11 & #12; even if clock skewed slightly earlier, version advances monotonically!
    modified_node2 = _make_scored_node(2, score=98.0, sni="edge-new.example.org")
    pool_v2 = [pool_v1[0], modified_node2] + pool_v1[2:9] + [
        _make_scored_node(11, score=80.0),
        _make_scored_node(12, score=79.0),
    ]
    m2 = export_central_top500_dataset(
        snap2_dir,
        pool_v2,
        prev_dir=snap1_dir,
        generated_at="2026-10-30T17:59:55Z",  # simulated slight clock skew
    )
    assert m2["dataset_version"] > m1["dataset_version"]
    assert m2["delta_available"] is True
    assert m2["delta_base_version"] == m1["dataset_version"]
    assert m2["delta_base_configs_sha256"] == m1["checksums"]["configs_sha256"]

    delta_bytes = (snap2_dir / "top500.delta.json").read_bytes()
    assert hashlib.sha256(delta_bytes).hexdigest() == m2["checksums"]["delta_json_sha256"]

    # Simulate Android client incremental reconstruction from v1 + delta -> must match v2 configs_sha256!
    delta_doc = json.loads(delta_bytes.decode("utf-8"))
    client_map = {s["server_id"]: dict(s) for s in doc_v1["servers"]}
    for rem_id in delta_doc["removed_server_ids"]:
        client_map.pop(rem_id, None)
    for up_srv in delta_doc["added_or_updated"]:
        client_map[up_srv["server_id"]] = dict(up_srv)

    # Note: unchanged entries kept from v1 may have updated rank labels in v2, while strip_uri_fragment(cfg) is identical!
    reconstructed = [client_map[sid] for sid in delta_doc["ordered_server_ids"] if sid in client_map]
    assert len(reconstructed) == m2["qualified_count"]
    assert compute_configs_set_sha256(reconstructed) == m2["checksums"]["configs_sha256"]


def test_manifest_signature_roundtrip_and_tamper_detection(tmp_path):
    import base64

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from central_top500 import sign_manifest_file

    key = ec.generate_private_key(ec.SECP256R1())
    key_b64 = base64.b64encode(key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )).decode()
    manifest = tmp_path / "top500.manifest.json"
    body = b'{"dataset_version": 7}\n'
    manifest.write_bytes(body)

    sig_b64 = sign_manifest_file(manifest, body, key_b64=key_b64)
    sig = base64.b64decode((tmp_path / "top500.manifest.json.sig").read_text().strip())
    assert sig == base64.b64decode(sig_b64)
    key.public_key().verify(sig, body, ec.ECDSA(hashes.SHA256()))
    try:
        key.public_key().verify(sig, body.replace(b"7", b"8"), ec.ECDSA(hashes.SHA256()))
        raise AssertionError("tampered manifest must not verify")
    except Exception as exc:  # InvalidSignature
        assert exc.__class__.__name__ == "InvalidSignature"

    # Unsigned (transition) mode removes stale signature files
    assert sign_manifest_file(manifest, body, key_b64="") is None
    assert not (tmp_path / "top500.manifest.json.sig").exists()
