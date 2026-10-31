#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit, security, anti-manipulation, and integration tests for:
  1. Extended protocol parsing (`socks://`, `socks5://`, `http://`, `https://`)
  2. Multi-device Community VPN Verification & Iran (`IR`) ranking engine
  3. Incremental Worker export sync (`server/sync_community_rankings.py`)
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from central_top500 import compute_config_fingerprint
from community_ranking import (
    build_catalog_index,
    compute_country_community_rankings,
    export_community_country_datasets,
)
from dedupe import parse_identity
from server.sync_community_rankings import sync_and_export


def test_socks_and_http_proxy_identity_parsing_and_secret_redaction() -> None:
    s1 = "socks5://alice:topSecretPass123@198.51.100.21:1080#NodeSocks"
    s2 = "socks://198.51.100.22:1080#OpenSocks"
    h1 = "http://bob:httpPass99@198.51.100.23:8080#HttpProxy"
    h2 = "https://carol:tlsPass77@edge.example.com:8443?sni=edge.example.com#HttpsProxy"

    id_s1 = parse_identity(s1)
    id_s2 = parse_identity(s2)
    id_h1 = parse_identity(h1)
    id_h2 = parse_identity(h2)

    assert id_s1 is not None and id_s1.canonical_proto == "socks" and id_s1.port == 1080
    assert id_s2 is not None and id_s2.canonical_proto == "socks" and id_s2.port == 1080
    assert id_h1 is not None and id_h1.canonical_proto == "http" and id_h1.port == 8080
    assert id_h2 is not None and id_h2.canonical_proto == "http" and id_h2.port == 8443

    # Credentials must NEVER appear in identity_id or config_fingerprint
    fp_s1 = compute_config_fingerprint(s1)
    assert "topSecretPass123" not in id_s1.identity_id
    assert "topSecretPass123" not in fp_s1
    assert "alice" not in fp_s1

    # Ordinary web URLs and private LAN addresses must be rejected
    assert parse_identity("https://example.com/some/article.html") is None
    assert parse_identity("http://example.com") is None
    assert parse_identity("socks5://192.168.1.1:1080") is None
    assert parse_identity("http://127.0.0.1:8080") is None


def test_iran_community_ranking_anti_manipulation_country_isolation_and_median_scoring(tmp_path: Path) -> None:
    now = 1_793_450_000
    uri_good_ir = "vless://11111111-1111-1111-1111-111111111111@198.51.100.40:443?security=tls&sni=edge.example.com#n1"
    uri_single_spam = "trojan://secretpass@198.51.100.41:443?security=tls&sni=edge2.example.com#n2"
    uri_german_only = "hy2://hypass@198.51.100.42:443?sni=de.example.com#n3"

    catalog = [
        {"cfg": uri_good_ir, "exit_country": "DE", "security_assessment": "Verified", "risk_level": "LOW"},
        {"cfg": uri_single_spam, "exit_country": "NL", "security_assessment": "Verified", "risk_level": "LOW"},
        {"cfg": uri_german_only, "exit_country": "FI", "security_assessment": "Verified", "risk_level": "LOW"},
    ]
    cat_idx = build_catalog_index(catalog)

    fp_good = compute_config_fingerprint(uri_good_ir)
    fp_spam = compute_config_fingerprint(uri_single_spam)
    fp_de = compute_config_fingerprint(uri_german_only)

    rep_ir_1 = "1" * 64
    rep_ir_2 = "2" * 64
    rep_ir_3 = "3" * 64
    rep_spammer = "9" * 64
    rep_de_1 = "a" * 64
    rep_de_2 = "b" * 64

    reports = [
        # Three independent verified Iranian direct-ISP reporters for uri_good_ir (with 1 extreme outlier latency=2ms)
        {
            "report_id": "r01", "config_fingerprint": fp_good, "server_id": "", "protocol": "vless",
            "reporter_id_hash": rep_ir_1, "tested_at_epoch": now - 600, "success": True,
            "handshake_ms": 210, "latency_ms": 2, "download_kbps": 99999.0, "stability_score": 95.0,
            "verified_country": "IR", "country_confidence": "CF_EDGE_VERIFIED", "vpn_interference": False,
            "asn_bucket": 44244,
        },
        {
            "report_id": "r02", "config_fingerprint": fp_good, "server_id": "", "protocol": "vless",
            "reporter_id_hash": rep_ir_2, "tested_at_epoch": now - 500, "success": True,
            "handshake_ms": 240, "latency_ms": 120, "download_kbps": 3400.0, "stability_score": 90.0,
            "verified_country": "IR", "country_confidence": "CF_EDGE_VERIFIED", "vpn_interference": False,
            "asn_bucket": 197207,
        },
        {
            "report_id": "r03", "config_fingerprint": fp_good, "server_id": "", "protocol": "vless",
            "reporter_id_hash": rep_ir_3, "tested_at_epoch": now - 400, "success": True,
            "handshake_ms": 260, "latency_ms": 135, "download_kbps": 3100.0, "stability_score": 88.0,
            "verified_country": "IR", "country_confidence": "VERIFIED_DIRECT_IP", "vpn_interference": False,
            "asn_bucket": 58224,
        },
        # Single malicious device submitting 25 duplicate spam reports for uri_single_spam
        *[
            {
                "report_id": f"spam_{i:02d}", "config_fingerprint": fp_spam, "server_id": "", "protocol": "trojan",
                "reporter_id_hash": rep_spammer, "tested_at_epoch": now - 300 + i, "success": True,
                "handshake_ms": 20, "latency_ms": 10, "download_kbps": 50000.0, "stability_score": 100.0,
                "verified_country": "IR", "country_confidence": "CF_EDGE_VERIFIED", "vpn_interference": False,
                "asn_bucket": 44244,
            }
            for i in range(25)
        ],
        # VPN-interfered report falsely claiming IR must be rejected
        {
            "report_id": "vpn_fake_ir", "config_fingerprint": fp_de, "server_id": "", "protocol": "hysteria2",
            "reporter_id_hash": rep_de_1, "tested_at_epoch": now - 200, "success": True,
            "latency_ms": 40, "download_kbps": 8000.0, "stability_score": 95.0,
            "verified_country": "IR", "country_confidence": "VPN_OR_DC_INTERFERENCE", "vpn_interference": True,
        },
        # Two verified German reporters for uri_german_only -> belongs ONLY in germany-top500.json, NEVER iran-top500!
        {
            "report_id": "de_1", "config_fingerprint": fp_de, "server_id": "", "protocol": "hysteria2",
            "reporter_id_hash": rep_de_1, "tested_at_epoch": now - 150, "success": True,
            "latency_ms": 38, "download_kbps": 12000.0, "stability_score": 96.0,
            "verified_country": "DE", "country_confidence": "CF_EDGE_VERIFIED", "vpn_interference": False,
        },
        {
            "report_id": "de_2", "config_fingerprint": fp_de, "server_id": "", "protocol": "hysteria2",
            "reporter_id_hash": rep_de_2, "tested_at_epoch": now - 120, "success": True,
            "latency_ms": 44, "download_kbps": 11500.0, "stability_score": 94.0,
            "verified_country": "DE", "country_confidence": "CF_EDGE_VERIFIED", "vpn_interference": False,
        },
        # Unknown injected fingerprint not in validated catalog -> must be ignored
        {
            "report_id": "inj_1", "config_fingerprint": "f" * 32, "server_id": "e" * 24, "protocol": "vless",
            "reporter_id_hash": rep_ir_1, "tested_at_epoch": now - 100, "success": True,
            "latency_ms": 15, "verified_country": "IR", "country_confidence": "CF_EDGE_VERIFIED", "vpn_interference": False,
        },
    ]

    ir_res = compute_country_community_rankings(reports, cat_idx, target_country="IR", now_epoch=now)
    # Only uri_good_ir has >=2 independent IR reporters; spammer's 25 reports collapse to 1 reporter!
    assert ir_res["qualified_count"] == 1
    winner = ir_res["servers"][0]
    assert winner["config_fingerprint"] == fp_good
    assert winner["distinct_reporters"] == 3
    assert winner["distinct_asns"] == 3
    # Median of [2, 120, 135] is 120 (immune to the 2ms outlier!)
    assert winner["median_latency_ms"] == 120
    # Median of [99999.0, 3400.0, 3100.0] is 3400.0 (immune to the 99999 outlier!)
    assert winner["median_speed_kbps"] == 3400.0

    # Single-device spammer stays in all_results as PENDING_MULTI_DEVICE_CONFIRMATION with distinct_reporters == 1
    spam_row = next(r for r in ir_res["all_results"] if r["config_fingerprint"] == fp_spam)
    assert spam_row["distinct_reporters"] == 1
    assert spam_row["status"] == "PENDING_MULTI_DEVICE_CONFIRMATION"

    # Export all country files and verify strict isolation + zero padding
    counts = export_community_country_datasets(tmp_path, catalog, reports, generated_at_epoch=now)
    assert counts["IR"] == 1
    assert counts["DE"] == 1
    assert counts["FR"] == 0
    assert counts["TR"] == 0
    assert counts["RU"] == 0

    ir_json = json.loads((tmp_path / "iran-top500.json").read_text(encoding="utf-8"))
    assert ir_json["qualified_count"] == 1
    assert ir_json["personalized_top50_authority"] == "ANDROID_LOCAL_ONLY"
    ir_txt = (tmp_path / "iran-top500.txt").read_text(encoding="utf-8")
    assert "198.51.100.40:443" in ir_txt
    assert "198.51.100.41" not in ir_txt
    assert "198.51.100.42" not in ir_txt

    fr_json = json.loads((tmp_path / "france-top500.json").read_text(encoding="utf-8"))
    assert fr_json["qualified_count"] == 0
    assert fr_json["servers"] == []


def test_worker_incremental_export_sync(tmp_path: Path) -> None:
    now = 1_793_460_000
    uri = "socks5://u1:p1@198.51.100.77:1080#SocksNode"
    fp = compute_config_fingerprint(uri)
    (tmp_path / "alive.json").write_text(
        json.dumps({"servers": [{"cfg": uri, "exit_country": "DE", "security_assessment": "Failed", "risk_level": "HIGH"}]}),
        encoding="utf-8",
    )

    worker_reports = [
        {
            "id": 10, "report_id": "aaaa1111bbbb2222", "server_id": "", "config_fingerprint": fp,
            "protocol": "socks", "reporter_id_hash": "c" * 64, "tested_at_epoch": now - 60,
            "success": True, "handshake_ms": 140, "latency_ms": 95, "download_kbps": 2200.0,
            "stability_score": 85.0, "verified_country": "IR", "country_confidence": "CF_EDGE_VERIFIED",
            "vpn_interference": False, "asn_bucket": 44244,
        },
        {
            "id": 11, "report_id": "cccc3333dddd4444", "server_id": "", "config_fingerprint": fp,
            "protocol": "socks", "reporter_id_hash": "d" * 64, "tested_at_epoch": now - 30,
            "success": True, "handshake_ms": 150, "latency_ms": 105, "download_kbps": 2400.0,
            "stability_score": 87.0, "verified_country": "IR", "country_confidence": "CF_EDGE_VERIFIED",
            "vpn_interference": False, "asn_bucket": 197207,
        },
    ]

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.headers.get("Authorization") != "Bearer test-export-secret":
                self.send_response(401)
                self.end_headers()
                return
            body = json.dumps({
                "schema_version": "1.0",
                "count": len(worker_reports),
                "next_after_id": 11,
                "reports": worker_reports,
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        counts = sync_and_export(
            data_dir=tmp_path,
            worker_url=f"http://127.0.0.1:{port}",
            export_token="test-export-secret",
            now_epoch=now,
        )
        assert counts["IR"] == 1
        st = json.loads((tmp_path / "state" / "community_reports.json").read_text(encoding="utf-8"))
        assert st["last_worker_id"] == 11
        assert len(st["reports"]) == 2
    finally:
        srv.shutdown()
        srv.server_close()
