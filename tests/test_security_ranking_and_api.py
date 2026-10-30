from __future__ import annotations

import base64
import json
import threading
from pathlib import Path

import requests

from scoring import ScoredNode, SourceHealthRegistry, compute_profile_rank_score, rank_nodes_by_profile
from security_intelligence import (
    QuarantineRegistry,
    ThreatIntelIndicators,
    assess_configuration_security,
    compute_multidimensional_scores,
)
from public_api import create_public_api_http_server, export_static_api_v1


VALID_REALITY_PBK = "m4U9x_0W9v2N7qLpR3kZ8yH1bC6dF5gJ2sT4uV8wX0Y"


def test_fast_insecure_server_never_classified_as_secure() -> None:
    """Phase 2.1: A fast server with allowInsecure=1 must have high Performance but Failed Security."""
    uri = "trojan://SuperSecretPass99@edge.fast-node.de:443?security=tls&sni=edge.fast-node.de&allowInsecure=1#FastDE"
    sec = assess_configuration_security(uri, tls_probe_verified=True)
    assert sec.security_assessment == "Failed"
    assert sec.privacy_assessment == "High Risk"
    assert sec.risk_level == "HIGH"
    assert not sec.quarantined

    md = compute_multidimensional_scores(
        median_latency_ms=22.0,
        jitter_ms=3.0,
        probe_pass_rate=1.0,
        speed_kbps=15_000.0,
        runs_seen=10,
        runs_alive=10,
        consecutive_alive=10,
        ema_reliability=0.98,
        verified_at="2026-10-30T12:00:00Z",
        now_iso="2026-10-30T12:05:00Z",
        security_report=sec,
    )
    assert md.performance_score >= 85.0
    assert md.reliability_score >= 85.0
    assert md.security_assessment == "Failed"
    assert md.privacy_assessment == "High Risk"


def test_anonymous_public_server_never_gets_verified_privacy_unlike_attested_vip() -> None:
    """Phase 2.1 & 5: Anonymous public nodes with valid TLS/Reality get Security=Verified, Privacy=Unverified."""
    uri = (
        f"vless://11111111-2222-3333-4444-555555555555@nl1.example.net:443"
        f"?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk={VALID_REALITY_PBK}&sid=abcd#NL"
    )
    pub_sec = assess_configuration_security(uri, tls_probe_verified=True, operator_attested_vip=False)
    assert pub_sec.security_assessment == "Verified"
    assert pub_sec.privacy_assessment == "Unverified"
    assert pub_sec.risk_level == "LOW"

    vip_sec = assess_configuration_security(uri, tls_probe_verified=True, operator_attested_vip=True)
    assert vip_sec.security_assessment == "Verified"
    assert vip_sec.privacy_assessment == "Verified"


def test_critical_configs_quarantined_and_secrets_redacted(tmp_path: Path) -> None:
    """Phase 2.2: Broken ciphers, invalid Reality keys, redirects, TLS downgrades, and threat-intel hits quarantine cleanly."""
    qreg = QuarantineRegistry()
    secret_uuid = "99999999-aaaa-bbbb-cccc-dddddddddddd"

    # 1. Broken Shadowsocks cipher
    ss_plain = "ss://" + base64.urlsafe_b64encode(b"rc4-md5:TopSecretPass@198.51.100.12:8388").decode()
    r1 = assess_configuration_security(ss_plain)
    assert r1.quarantined and r1.risk_level == "CRITICAL"
    qreg.record(ss_plain, r1, sources=["feed-a"])

    # 2. Invalid Reality public key
    bad_reality = f"vless://{secret_uuid}@198.51.100.20:443?security=reality&pbk=TOO_SHORT"
    r2 = assess_configuration_security(bad_reality)
    assert r2.quarantined and "reality" in r2.quarantine_reason
    qreg.record(bad_reality, r2, sources=["feed-a"])

    # 3. Unexpected HTTP redirect hijacking during probe
    redir_uri = f"trojan://{secret_uuid}@portal.example.org:443?security=tls&sni=portal.example.org"
    r3 = assess_configuration_security(redir_uri, probe_error="http_302")
    assert r3.quarantined and r3.redirect_anomaly
    qreg.record(redir_uri, r3, sources=["feed-b"])

    # 4. TLS downgrade from prior run
    downgraded = f"vless://{secret_uuid}@edge.example.org:80?security=none&type=ws"
    r4 = assess_configuration_security(downgraded, prior_security_mode="tls")
    assert r4.quarantined and r4.endpoint_changed

    # 5. Threat intel indicator match + suspicious SSH port 22
    ti_file = tmp_path / "ti.json"
    ti_file.write_text(json.dumps({"domains": ["bad-actor.org"], "cidrs": ["203.0.113.128/25"]}), encoding="utf-8")
    ti = ThreatIntelIndicators.from_json_file(ti_file)
    r5 = assess_configuration_security(f"trojan://{secret_uuid}@sub.bad-actor.org:443?sni=sub.bad-actor.org", threat_intel=ti)
    assert r5.quarantined and r5.quarantine_reason == "threat_intel_indicator_match"

    r6 = assess_configuration_security(f"trojan://{secret_uuid}@198.51.100.55:22?sni=example.com")
    assert r6.quarantined and "22" in r6.quarantine_reason

    out_q = tmp_path / "quarantined.json"
    qreg.save_public_report(out_q)
    saved_text = out_q.read_text(encoding="utf-8")
    assert secret_uuid not in saved_text
    assert "TopSecretPass" not in saved_text
    parsed_q = json.loads(saved_text)
    assert parsed_q["quarantined_total"] == 3


def test_phase5_ranking_profiles_staleness_and_incomplete_data() -> None:
    """Phase 5: Verify BALANCED, LOW_LATENCY, HIGH_SPEED, HIGH_RELIABILITY, PRIVACY_AWARE edge cases."""
    fast_insecure = ScoredNode(
        uri="trojan://x@fast-insecure.example.com:443?allowInsecure=1",
        identity_id="id_fast_insec",
        protocol="trojan",
        canonical_protocol="trojan",
        host="fast-insecure.example.com",
        port=443,
        subnet_key="dom:example.com",
        latency_ms=18.0,
        median_latency_ms=18.0,
        jitter_ms=2.0,
        probe_pass_rate=1.0,
        speed_kbps=22_000.0,
        exit_country="DE",
        country_source="exit_trace",
        runs_seen=8,
        runs_alive=8,
        consecutive_alive=8,
        ema_reliability=0.95,
        verified_at="2026-10-30T12:00:00Z",
        security_assessment="Failed",
        privacy_assessment="High Risk",
        risk_level="HIGH",
    )
    verified_reliable = ScoredNode(
        uri="vless://x@safe-rel.example.net:443?security=tls",
        identity_id="id_safe_rel",
        protocol="vless",
        canonical_protocol="vless",
        host="safe-rel.example.net",
        port=443,
        subnet_key="dom:example.net",
        latency_ms=48.0,
        median_latency_ms=48.0,
        jitter_ms=4.0,
        probe_pass_rate=1.0,
        speed_kbps=8_500.0,
        exit_country="NL",
        country_source="exit_trace",
        runs_seen=25,
        runs_alive=25,
        consecutive_alive=25,
        ema_reliability=0.99,
        verified_at="2026-10-30T12:00:00Z",
        security_assessment="Verified",
        privacy_assessment="Unverified",
        risk_level="LOW",
    )
    unmeasured_low_lat = ScoredNode(
        uri="hysteria2://x@ping-only.example.org:443",
        identity_id="id_ping_only",
        protocol="hysteria2",
        canonical_protocol="hysteria2",
        host="ping-only.example.org",
        port=443,
        subnet_key="dom:example.org",
        latency_ms=14.0,
        median_latency_ms=14.0,
        jitter_ms=1.5,
        probe_pass_rate=1.0,
        speed_kbps=0.0,  # Incomplete: speed not measured!
        exit_country="BH",
        country_source="exit_trace",
        runs_seen=3,
        runs_alive=3,
        consecutive_alive=3,
        ema_reliability=0.82,
        verified_at="2026-10-30T12:00:00Z",
        security_assessment="Verified",
        privacy_assessment="Unverified",
        risk_level="LOW",
    )
    stale_clone = ScoredNode(
        **{
            **verified_reliable.__dict__,
            "identity_id": "id_stale",
            "verified_at": "2026-10-25T12:00:00Z",  # 120 hours stale
        }
    )

    pool = [fast_insecure, verified_reliable, unmeasured_low_lat, stale_clone]
    now_iso = "2026-10-30T12:05:00Z"

    # 1. HIGH_SPEED ranks measured 22 Mbps & 8.5 Mbps above unmeasured 0.0 kbps node
    hs = rank_nodes_by_profile(pool, "HIGH_SPEED", now_iso=now_iso)
    assert hs[0].identity_id == "id_fast_insec"
    assert hs[-1].identity_id == "id_ping_only"

    # 2. LOW_LATENCY ranks ultra-low 14ms jitter 1.5ms node at top
    ll = rank_nodes_by_profile(pool, "LOW_LATENCY", now_iso=now_iso)
    assert ll[0].identity_id in ("id_ping_only", "id_fast_insec")

    # 3. PRIVACY_AWARE strictly blocks Failed / High-Risk `fast_insecure`
    pa = rank_nodes_by_profile(pool, "PRIVACY_AWARE", now_iso=now_iso)
    assert all(n.identity_id != "id_fast_insec" for n in pa)
    assert pa[0].identity_id == "id_safe_rel"

    # 4. Staleness decay: fresh node beats identical 5-day-old stale clone
    fresh_s = compute_profile_rank_score(verified_reliable, "HIGH_RELIABILITY", now_iso=now_iso)
    stale_s = compute_profile_rank_score(stale_clone, "HIGH_RELIABILITY", now_iso=now_iso)
    assert fresh_s > stale_s


def test_phase7_source_intelligence_change_detection_and_auto_quarantine() -> None:
    """Phase 7: Poisoned feed auto-quarantines; clean feed tracks SHA-256 content changes and availability."""
    reg = SourceHealthRegistry()
    clean_rec = reg.get_or_create("trusted-gh", "github", "https://example.com/sub.txt")
    clean_rec.update_from_fetch(
        fetch_ok=True,
        status_code=200,
        raw_count=20,
        valid_count=19,
        new_configs=15,
        invalid_configs=1,
        duplicate_configs=4,
        suspicious_configs=1,
        content_sha256="aaa111",
        timestamp="2026-10-30T10:00:00Z",
    )
    assert clean_rec.state == "active"
    assert not clean_rec.content_changed
    assert clean_rec.collection_success_rate == 1.0

    # Second fetch with mutated content hash
    clean_rec.update_from_fetch(
        fetch_ok=True,
        status_code=200,
        raw_count=22,
        valid_count=22,
        new_configs=6,
        invalid_configs=0,
        duplicate_configs=16,
        suspicious_configs=0,
        content_sha256="bbb222",
        timestamp="2026-10-30T10:30:00Z",
    )
    assert clean_rec.content_changed is True
    assert clean_rec.availability_history == [1, 1]

    # Poisoned popular feed injecting predominantly suspicious/CRITICAL configs
    poison_rec = reg.get_or_create("poison-feed", "github", "https://example.com/bad.txt")
    poison_rec.update_from_fetch(
        fetch_ok=True,
        status_code=200,
        raw_count=12,
        valid_count=2,
        invalid_configs=10,
        suspicious_configs=11,
        content_sha256="deadbeef",
        timestamp="2026-10-30T10:30:00Z",
    )
    assert poison_rec.state == "quarantined"
    assert "high_suspicious_ratio" in poison_rec.quarantine_reason
    assert poison_rec.should_skip_cooldown() is True


def test_phase10_public_statistics_api_endpoints_rate_limit_etag_and_redaction(tmp_path: Path) -> None:
    """Phase 10: Test live HTTP endpoints, filtering, pagination, ETag/304, 429 rate limiting, and zero secret leaks."""
    secret_cred = "UltraSecretCredential_DO_NOT_LEAK_7788"
    exact_ip = "198.51.100.77"
    alive_servers = [
        {
            "id": "a1b2c3d4e5f6",
            "name": "bahrain-vpn 1",
            "cfg": f"vless://{secret_cred}@{exact_ip}:443?security=tls&sni=de.example.com#bahrain-vpn 1",
            "uri": f"vless://{secret_cred}@{exact_ip}:443?security=tls&sni=de.example.com#bahrain-vpn 1",
            "protocol": "vless",
            "canonical_protocol": "vless",
            "host": exact_ip,
            "port": 443,
            "latency_ms": 28,
            "median_latency_ms": 28,
            "jitter_ms": 3.2,
            "probe_pass_rate": 1.0,
            "packet_loss_pct": 0.0,
            "speed_kbps": 12_500,
            "score": 89.4,
            "performance_score": 91.0,
            "reliability_score": 94.0,
            "security_assessment": "Verified",
            "privacy_assessment": "Unverified",
            "risk_level": "LOW",
            "uptime_pct": 99.1,
            "exit_country": "DE",
            "country_source": "exit_trace",
            "verified_at": "2026-10-30T12:00:00Z",
        },
        {
            "id": "f6e5d4c3b2a1",
            "name": "bahrain-vpn 2",
            "cfg": f"trojan://{secret_cred}@us.node.example.org:443?allowInsecure=1#bahrain-vpn 2",
            "uri": f"trojan://{secret_cred}@us.node.example.org:443?allowInsecure=1#bahrain-vpn 2",
            "protocol": "trojan",
            "canonical_protocol": "trojan",
            "host": "us.node.example.org",
            "port": 443,
            "latency_ms": 95,
            "median_latency_ms": 95,
            "jitter_ms": 11.0,
            "probe_pass_rate": 0.67,
            "packet_loss_pct": 33.0,
            "speed_kbps": 4_000,
            "score": 61.0,
            "performance_score": 68.0,
            "reliability_score": 58.0,
            "security_assessment": "Failed",
            "privacy_assessment": "High Risk",
            "risk_level": "HIGH",
            "uptime_pct": 80.0,
            "exit_country": "US",
            "country_source": "exit_trace",
            "verified_at": "2026-10-30T12:00:00Z",
        },
    ]
    meta = {
        "generated_at": "2026-10-30T12:00:00Z",
        "duration_sec": 42.5,
        "degraded_mode": False,
        "channels_total": 277,
        "github_sources": 26,
        "raw_collected": 35000,
        "unique_clean": 28000,
        "tested": 1200,
    }
    export_static_api_v1(
        tmp_path,
        meta=meta,
        alive_servers_dicts=alive_servers,
        tested_by_proto={"vless": (600, 210), "trojan": (300, 95)},
        quarantined_total=14,
        quarantined_reasons={"broken_ss_cipher": 9, "unexpected_http_redirect": 5},
        source_report={"summary": {"active": 290, "quarantined": 1}, "github_sources": [], "telegram_channels_summary": {"total": 277}},
    )

    httpd = create_public_api_http_server(tmp_path, host="127.0.0.1", port=0, rate_limit_per_min=8)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{port}"
    try:
        # 1. Statistics & zero-secret check
        r_stat = requests.get(f"{base}/api/v1/statistics", timeout=5)
        assert r_stat.status_code == 200
        assert secret_cred not in r_stat.text
        assert exact_ip not in r_stat.text
        stat_json = r_stat.json()
        assert stat_json["overview"]["active_servers"] == 2
        assert stat_json["overview"]["quarantined_servers"] == 14

        # 2. ETag / 304 conditional caching
        etag = r_stat.headers["ETag"]
        r_304 = requests.get(f"{base}/api/v1/statistics", headers={"If-None-Match": etag}, timeout=5)
        assert r_304.status_code == 304

        # 3. Servers filtering & PRIVACY_AWARE profile
        r_priv = requests.get(f"{base}/api/v1/servers?profile=PRIVACY_AWARE", timeout=5)
        assert r_priv.status_code == 200
        assert secret_cred not in r_priv.text
        assert exact_ip not in r_priv.text  # Masked to 198.51.100.0/24!
        items = r_priv.json()["items"]
        assert len(items) == 1
        assert items[0]["id"] == "a1b2c3d4e5f6"
        assert items[0]["masked_network"] == "198.51.100.0/24"

        # 4. Single server detail & validation error
        r_one = requests.get(f"{base}/api/v1/servers/a1b2c3d4e5f6", timeout=5)
        assert r_one.status_code == 200
        assert r_one.json()["server"]["exit_country"] == "DE"

        r_bad = requests.get(f"{base}/api/v1/servers/INVALID_ID!!", timeout=5)
        assert r_bad.status_code == 400

        # 5. OpenAPI & Health
        assert requests.get(f"{base}/api/v1/health", timeout=5).json()["status"] == "ok"
        assert requests.get(f"{base}/api/v1/openapi.json", timeout=5).json()["openapi"] == "3.1.0"

        # 6. Rate limiter triggers 429 after 8 requests
        codes = [requests.get(f"{base}/api/v1/countries", timeout=5).status_code for _ in range(4)]
        assert 429 in codes
    finally:
        httpd.shutdown()
        httpd.server_close()
