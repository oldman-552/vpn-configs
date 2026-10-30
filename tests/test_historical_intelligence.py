"""
Automated Backend, Security & Performance Tests for Historical Server Intelligence
Database, Stable Identity, Windowed Uptime, Failure Intelligence, Source Independence,
and Versioned Public Data Exports (`tests/test_historical_intelligence.py`).
"""
from __future__ import annotations

import base64
import json
import time
from pathlib import Path

from dedupe import MultiLayerDeduplicator, extract_source_operator_id, parse_identity
from historical_db import (
    FAILURE_CATEGORIES,
    HistoricalServerDB,
    RetentionPolicy,
    SuppressionPolicy,
    classify_failure_reason,
    compute_windowed_uptime,
    epoch_to_iso,
)


def _vmess_uri(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return "vmess://" + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def test_stable_server_identity_invariance_and_no_ip_only_merging() -> None:
    # 1. Query ordering, remark, cosmetic tags, and hy2/hysteria2 scheme normalization produce identical ID
    u1 = "hy2://MySecretPass99@edge.example.com:443?sni=edge.example.com&alpn=h3,h2&utm_source=tg#Node-Alpha"
    u2 = "hysteria2://MySecretPass99@EDGE.EXAMPLE.COM.?alpn=h2,h3&peer=edge.example.com&remarks=Other#bahrain-vpn 1"
    id1 = parse_identity(u1)
    id2 = parse_identity(u2)
    assert id1 is not None and id2 is not None
    assert id1.identity_id == id2.identity_id
    assert id1.canonical_sha256 == id2.canonical_sha256
    assert "MySecretPass99" not in id1.identity_id
    assert "MySecretPass99" not in id1.canonical_sha256

    # 2. VMess JSON key order, string vs int port, and ps remark changes keep stable ID
    vm1 = _vmess_uri({"v": "2", "ps": "OldName", "add": "203.0.113.10", "port": "443", "id": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE", "net": "ws", "tls": "tls", "sni": "cdn.example.com", "path": "/ws"})
    vm2 = _vmess_uri({"path": "/ws", "sni": "CDN.EXAMPLE.COM.", "tls": "tls", "net": "ws", "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "port": 443, "add": "203.0.113.10", "ps": "NewName", "v": "2"})
    assert parse_identity(vm1).identity_id == parse_identity(vm2).identity_id

    # 3. Two distinct servers sharing the exact same IP address or /24 subnet MUST NOT merge
    same_ip_a = "vless://11111111-1111-1111-1111-111111111111@203.0.113.50:443?security=tls&sni=a.example.com#A"
    same_ip_b = "vless://22222222-2222-2222-2222-222222222222@203.0.113.50:443?security=tls&sni=a.example.com#B"
    same_sub_c = "vless://11111111-1111-1111-1111-111111111111@203.0.113.51:443?security=tls&sni=a.example.com#C"
    ia = parse_identity(same_ip_a)
    ib = parse_identity(same_ip_b)
    ic = parse_identity(same_sub_c)
    assert ia.identity_id != ib.identity_id
    assert ia.identity_id != ic.identity_id


def test_identity_collision_disambiguation_and_legacy_migration(tmp_path: Path) -> None:
    db = HistoricalServerDB(tmp_path / "hist.sqlite3")
    u_a = "trojan://SecretA@203.0.113.10:443?security=tls&sni=one.example.com"
    u_b = "trojan://SecretB@203.0.113.11:443?security=tls&sni=two.example.com"
    ident_a = parse_identity(u_a)
    ident_b_raw = parse_identity(u_b)
    assert ident_a and ident_b_raw

    # Force a synthetic 24-hex prefix collision while keeping distinct 256-bit canonical_sha256
    colliding_b = parse_identity(u_b)
    colliding_b.identity_id = ident_a.identity_id

    sid_a = db.resolve_server_id(ident_a, now_iso="2026-10-30T10:00:00Z")
    sid_b = db.resolve_server_id(colliding_b, now_iso="2026-10-30T10:05:00Z")
    assert sid_a != sid_b
    assert len(sid_b) == 32  # Disambiguated cleanly without merging!

    # Legacy alias lookup resolves seamlessly to canonical v2 server_id
    if ident_a.legacy_identity_id != sid_a:
        assert db.resolve_alias(ident_a.legacy_identity_id) == sid_a


def test_failure_classification_temporary_suppression_and_recovery_time(tmp_path: Path) -> None:
    assert classify_failure_reason("connect_timeout after 5s") == "CONNECTION_TIMEOUT"
    assert classify_failure_reason("HTTP 407 Proxy Auth Required") == "AUTHENTICATION_FAILURE"
    assert classify_failure_reason("socket.gaierror: [Errno -2] Name or service not known") == "DNS_FAILURE"
    assert classify_failure_reason("ssl.SSLCertVerificationError: certificate verify failed") == "TLS_ERROR"
    assert classify_failure_reason("quic_handshake reset_by_peer") == "HANDSHAKE_FAILURE"
    assert classify_failure_reason("http_302 captive redirect") == "ROUTING_FAILURE"
    assert classify_failure_reason("", packet_loss_pct=75.0) == "PACKET_LOSS"
    assert classify_failure_reason("Connection refused 503") == "SERVER_UNAVAILABLE"
    assert classify_failure_reason("invalid_uri short_pbk") == "INVALID_CONFIGURATION"
    assert classify_failure_reason("mystery_glitch") == "UNKNOWN_FAILURE"
    assert set(FAILURE_CATEGORIES) >= {
        "CONNECTION_TIMEOUT", "AUTHENTICATION_FAILURE", "DNS_FAILURE", "HANDSHAKE_FAILURE",
        "TLS_ERROR", "ROUTING_FAILURE", "PACKET_LOSS", "SERVER_UNAVAILABLE",
        "INVALID_CONFIGURATION", "UNKNOWN_FAILURE",
    }

    db = HistoricalServerDB(
        tmp_path / "supp.sqlite3",
        suppression=SuppressionPolicy(consecutive_failure_threshold=3, base_suppress_sec=1800, max_suppress_sec=7200),
    )
    uri = "vless://11111111-1111-1111-1111-111111111111@203.0.113.77:443?security=tls&sni=ok.example.com"
    ident = parse_identity(uri)
    assert ident is not None

    t0 = 1_793_300_000
    # Initial success -> single failure MUST NOT delete or suppress the server!
    sid = db.record_measurement(ident, measured_at=epoch_to_iso(t0), ok=True, latency_ms=80.0, median_latency_ms=80.0)
    db.record_measurement(ident, measured_at=epoch_to_iso(t0 + 600), ok=False, raw_error="timeout")
    detail_after_1 = db.get_server_detail(sid, now_iso=epoch_to_iso(t0 + 600))
    assert detail_after_1 is not None
    assert detail_after_1["current_status"] == "UNSTABLE"
    assert not db.is_temporarily_suppressed(sid, now_epoch=t0 + 660)

    # 3 consecutive failures trigger temporary suppression (still preserved in DB)
    db.record_measurement(ident, measured_at=epoch_to_iso(t0 + 1200), ok=False, raw_error="timeout")
    db.record_measurement(ident, measured_at=epoch_to_iso(t0 + 1800), ok=False, raw_error="tls handshake cert")
    assert db.is_temporarily_suppressed(sid, now_epoch=t0 + 1900)
    assert not db.is_temporarily_suppressed(sid, now_epoch=t0 + 4000)  # Suppression expires!

    # Subsequent recovery clears suppression and records exact recovery duration (3600 - 600 = 3000s)
    db.record_measurement(ident, measured_at=epoch_to_iso(t0 + 3600), ok=True, latency_ms=72.0, median_latency_ms=72.0)
    recovered = db.get_server_detail(sid, now_iso=epoch_to_iso(t0 + 3600))
    assert recovered is not None
    assert recovered["current_status"] == "OPERATIONAL"
    assert recovered["average_recovery_time"] == 3000.0
    assert recovered["failure_reasons"]["CONNECTION_TIMEOUT"] == 2
    assert recovered["failure_reasons"]["TLS_ERROR"] == 1


def test_windowed_uptime_handles_discovery_monitoring_outage_and_unknown_honesty() -> None:
    t_end = 1_793_360_000
    t_start = t_end - 86_400

    # 1. Zero observations -> UNKNOWN (None), never fabricated 100% or 0%
    pct_none, kind_none, cov_none = compute_windowed_uptime(
        [],
        window_start_epoch=t_start,
        window_end_epoch=t_end,
        first_seen_epoch=t_start,
    )
    assert pct_none is None
    assert kind_none == "UNKNOWN"
    assert cov_none == 0.0

    # 2. Sparse single test -> ESTIMATED, not OBSERVED
    pct_est, kind_est, _ = compute_windowed_uptime(
        [(t_end - 600, 1)],
        window_start_epoch=t_start,
        window_end_epoch=t_end,
        first_seen_epoch=t_start,
    )
    assert pct_est == 100.0
    assert kind_est == "ESTIMATED"

    # 3. Server discovered 4 hours ago with 6 successful 30-min checks + 2h CI outage gap -> OBSERVED 100%
    first_seen = t_end - 4 * 3600
    runs = [first_seen, first_seen + 1800, first_seen + 9000, first_seen + 10800, first_seen + 12600, t_end]
    obs = [(ts, 1) for ts in runs]
    pct_obs, kind_obs, cov_obs = compute_windowed_uptime(
        obs,
        window_start_epoch=t_start,
        window_end_epoch=t_end,
        first_seen_epoch=first_seen,
        pipeline_run_epochs=runs,
        expected_cadence_sec=1800,
    )
    assert pct_obs == 100.0
    assert kind_obs == "OBSERVED"
    assert cov_obs >= 0.50


def test_source_operator_independence_prevents_same_owner_inflation() -> None:
    # 3 different URLs under Leon406/SubCrawler must resolve to ONE operator ('gh:leon406')
    urls = {
        "subcrawler-vless": "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/vless",
        "subcrawler-tr": "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/tr",
        "subcrawler-ss": "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/ss",
        "barabama": "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/merged.txt",
    }
    assert extract_source_operator_id("subcrawler-vless", url_or_handle=urls["subcrawler-vless"]) == "gh:leon406"
    assert extract_source_operator_id("subcrawler-tr", url_or_handle=urls["subcrawler-tr"]) == "gh:leon406"

    deduper = MultiLayerDeduplicator(source_urls=urls)
    sample = "trojan://SuperSecretCred99@203.0.113.88:443?security=tls&sni=edge.example.com#n1"
    deduper.ingest_source("subcrawler-vless", [sample])
    deduper.ingest_source("subcrawler-tr", [sample])
    deduper.ingest_source("subcrawler-ss", [sample])
    prov = next(iter(deduper.provenance_map().values()))
    assert prov.corroboration_count == 3
    assert prov.independent_source_count == 1  # Same operator!
    assert deduper.summary.multi_source_corroborated == 0

    # Adding an actually independent operator raises independent_source_count to 2
    deduper.ingest_source("barabama", [sample])
    assert prov.independent_source_count == 2
    assert deduper.summary.multi_source_corroborated == 1


def test_multi_window_analytics_retention_corruption_recovery_and_secret_free_exports(tmp_path: Path) -> None:
    db_file = tmp_path / "state" / "history.sqlite3"
    # Write garbage bytes first to verify automatic corruption quarantine & recovery
    db_file.parent.mkdir(parents=True, exist_ok=True)
    db_file.write_bytes(b"NOT_A_VALID_SQLITE_HEADER_CORRUPTED_BYTES")

    db = HistoricalServerDB(
        db_file,
        retention=RetentionPolicy(detailed_days=30, hourly_days=90, daily_days=365, retire_unseen_days=14),
    )
    assert (tmp_path / "state" / "history.corrupt.bak").is_file()
    assert len(db.applied_migrations()) >= 2

    secret_pw = "UltraSensitivePassword_DO_NOT_LEAK_2026"
    raw_exit_ip = "198.51.100.219"
    uri = f"trojan://{secret_pw}@198.51.100.42:443?security=tls&sni=node.example.com#Node1"
    ident = parse_identity(uri)
    assert ident is not None

    now_e = 1_793_400_000
    # Insert an old measurement (45 days ago -> detailed pruned, daily rollup retained!)
    old_e = now_e - 45 * 86_400
    sid = db.record_measurement(
        ident,
        measured_at=epoch_to_iso(old_e),
        ok=True,
        latency_ms=130.0,
        median_latency_ms=130.0,
        jitter_ms=12.0,
        packet_loss_pct=0.0,
        download_kbps=4200.0,
        upload_kbps=1500.0,
        exit_country="DE",
        country_source="exit_trace",
        exit_ip=raw_exit_ip,
        composite_score=81.5,
        performance_score=80.0,
        reliability_score=84.0,
        security_assessment="Verified",
        sources=[("subcrawler-tr", "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/tr")],
    )
    # Insert recent measurements in last 24h
    for step, lat in enumerate((90.0, 95.0, 102.0, 140.0)):
        db.record_measurement(
            ident,
            measured_at=epoch_to_iso(now_e - (4 - step) * 1800),
            ok=True,
            latency_ms=lat,
            median_latency_ms=lat,
            jitter_ms=6.0,
            packet_loss_pct=0.0,
            download_kbps=6400.0 + step * 200.0,
            upload_kbps=2100.0,
            exit_country="DE",
            country_source="exit_trace",
            exit_ip=raw_exit_ip,
            composite_score=88.0,
            performance_score=89.0,
            reliability_score=91.0,
            security_assessment="Verified",
            sources=[
                ("subcrawler-tr", "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/tr"),
                ("barabama", "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/merged.txt"),
            ],
        )

    db.record_pipeline_run_and_sources(
        run_at=epoch_to_iso(now_e),
        tested_count=10,
        alive_count=8,
        degraded_mode=False,
        source_records=[
            {"name": "subcrawler-tr", "kind": "github", "url_or_handle": "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/tr", "state": "active", "raw_count": 50, "valid_count": 48, "unique_identities": 48, "exclusive_identities": 12, "alive_count": 20, "total_runs": 10, "successful_runs": 10},
            {"name": "subcrawler-vless", "kind": "github", "url_or_handle": "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/vless", "state": "active", "raw_count": 100, "valid_count": 96, "unique_identities": 96, "exclusive_identities": 40, "alive_count": 35, "total_runs": 10, "successful_runs": 10},
            {"name": "barabama", "kind": "github", "url_or_handle": "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/merged.txt", "state": "active", "raw_count": 80, "valid_count": 78, "unique_identities": 78, "exclusive_identities": 30, "alive_count": 28, "total_runs": 10, "successful_runs": 10},
        ],
    )

    pruned = db.apply_retention_and_retirement(now_iso=epoch_to_iso(now_e))
    assert pruned["pruned_measurements"] == 1  # 45d detailed row pruned, daily aggregate kept!

    # Benchmark query & multi-window analytics speed (< 50ms)
    t_q0 = time.perf_counter()
    win = db.get_server_window_analytics(sid, now_iso=epoch_to_iso(now_e))
    query_ms = (time.perf_counter() - t_q0) * 1000.0
    assert query_ms < 250.0
    assert set(win.keys()) == {"24h", "7d", "30d", "90d"}
    assert win["24h"]["sample_count"] == 4
    assert win["24h"]["p95_latency_ms"] is not None and win["24h"]["p95_latency_ms"] >= 102.0
    assert win["24h"]["peak_download_kbps"] == 7000.0

    # Verify backup & restore roundtrip
    bak = db.backup_to(tmp_path / "backup.sqlite3")
    restored_db = HistoricalServerDB(tmp_path / "restored.sqlite3")
    restored_db.restore_from(bak)
    assert restored_db.get_server_detail(sid, now_iso=epoch_to_iso(now_e)) is not None

    # Verify atomic public exports & strict secret/IP redaction
    export_dir = tmp_path / "exports"
    written = db.export_public_historical_artifacts(export_dir, generated_at=epoch_to_iso(now_e))
    expected_files = {
        "servers-current.json",
        "servers-history.json",
        "servers-performance.json",
        "servers-statistics.json",
        "countries-statistics.json",
        "sources-statistics.json",
    }
    assert set(written.keys()) == expected_files
    for fname, fpath in written.items():
        text = fpath.read_text(encoding="utf-8")
        parsed = json.loads(text)
        assert parsed["schema_version"] == "1.0.0"
        assert secret_pw not in text, f"Secret leaked in {fname}"
        assert raw_exit_ip not in text, f"Unmasked exit IP leaked in {fname}"
        assert "198.51.100.42" not in text, f"Unmasked server IP leaked in {fname}"

    sources_json = json.loads((export_dir / "sources-statistics.json").read_text(encoding="utf-8"))
    assert sources_json["total_sources"] == 3
    assert sources_json["independent_active_operators"] == 2  # Leon406 + Barabama

    # Also ensure raw SQLite file never contains plaintext secret or unmasked exit IP
    raw_sqlite_bytes = db_file.read_bytes()
    assert secret_pw.encode("utf-8") not in raw_sqlite_bytes
    assert raw_exit_ip.encode("utf-8") not in raw_sqlite_bytes
