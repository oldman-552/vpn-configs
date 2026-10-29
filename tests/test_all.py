from __future__ import annotations

import base64
import gzip
import json
import socket
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import collector
import server.build_data as build_data
import tester


def _b64(s: str, urlsafe: bool = False) -> str:
    raw = s.encode("utf-8")
    enc = base64.urlsafe_b64encode(raw) if urlsafe else base64.b64encode(raw)
    return enc.decode("ascii")


# ───────────────────────── اختبارات collector.py ─────────────────────────
def test_channel_urls_dedupe_and_comments():
    raw = [
        "# تعليق",
        "",
        "HopeV2ray",
        "@hopev2ray",
        "https://t.me/s/HopeV2ray/",
        "https://t.me/i10VPN?before=100",
        "ab",  # قصير جدًا -> يُتجاهل
    ]
    urls = collector.channel_urls(raw)
    assert urls == ["https://t.me/s/HopeV2ray", "https://t.me/s/i10VPN"]


def test_default_files_loaded():
    ch = collector.get_channels()
    gh = collector.get_github_sources()
    assert len(ch) >= 270
    assert len(gh) >= 10
    assert "matin-super" in gh


def test_urlsafe_base64_decode_and_subscription():
    # JSON به محارف تنتج - و _ في base64 URL-safe بدون حشو
    vmess_obj = {
        "v": "2",
        "ps": "test>>>???~~~",
        "add": "edge.example.com",
        "port": "443",
        "id": "11111111-2222-3333-4444-555555555555",
        "aid": "0",
        "net": "ws",
        "path": "/?ed=2048",
        "tls": "tls",
    }
    vmess_uri = "vmess://" + _b64(json.dumps(vmess_obj), urlsafe=True).rstrip("=")
    sub_blob = _b64(vmess_uri + "\nvless://uuid-1234@1.2.3.4:443?security=tls&amp;sni=test.com#tag", urlsafe=True).rstrip("=")

    parsed = collector.parse_subscription(sub_blob)
    cleaned, rejected = collector.clean(parsed)
    assert rejected == 0
    assert len(cleaned) == 2
    assert "&amp;" not in cleaned[1]
    assert "security=tls&sni=test.com" in cleaned[1]


def test_extract_configs_html_entities_and_zwnj():
    html = """
    <div class="tgme_widget_message_text">
      <code>vless://11111111-2222-3333-4444-555555555555@1.1.1.1:443?type=ws&amp;security=tls&amp;path=%2Fws\u200c#remark1
      hy2://user:pass@2.2.2.2:443?sni=example.com#remark2</code>
      (trojan://secretpass@3.3.3.3:443?sni=example.org#r3),
      <a href="ss://YWVzLTI1Ni1nY206cGFzcw==@4.4.4.4:8388/?outline=1#out">link</a>
    </div>
    """
    raw = collector.extract_configs(html)
    cleaned, rejected = collector.clean(raw)
    assert rejected == 0
    assert len(cleaned) == 4
    assert cleaned[0] == "vless://11111111-2222-3333-4444-555555555555@1.1.1.1:443?type=ws&security=tls&path=%2Fws"
    assert cleaned[1] == "hy2://user:pass@2.2.2.2:443?sni=example.com"
    assert cleaned[2] == "trojan://secretpass@3.3.3.3:443?sni=example.org"
    assert cleaned[3] == "ss://YWVzLTI1Ni1nY206cGFzcw==@4.4.4.4:8388/?outline=1"


def test_clean_rejects_broken_vmess():
    good_vmess = "vmess://" + _b64(json.dumps({
        "add": "1.2.3.4", "port": 443, "id": "11111111-2222-3333-4444-555555555555"
    }))
    bad_vmess = "vmess://not_valid_json_at_all_1234567890"
    cleaned, rejected = collector.clean([good_vmess, bad_vmess, "vless://broken_no_at_sign"])
    assert cleaned == [good_vmess]
    assert rejected == 2


def test_endpoint_key_and_dedupe():
    ss_full = "ss://" + _b64("aes-256-gcm:secret@5.5.5.5:8388")
    ss_outline = "ss://" + _b64("aes-256-gcm:other") + "@5.5.5.5:8388/?outline=1"
    vless_same = "vless://uuid@5.5.5.5:8388?security=none"
    assert collector.endpoint_key(ss_full) == "5.5.5.5:8388"
    assert collector.endpoint_key(ss_outline) == "5.5.5.5:8388"
    deduped, dropped = collector.dedupe_by_endpoint([ss_full, ss_outline, vless_same])
    assert len(deduped) == 1
    assert dropped == 2


def test_stamp_jalali_fallback_when_jdatetime_missing(monkeypatch):
    monkeypatch.setattr(collector, "jdatetime", None)
    full_ts, date_only = collector.stamp("jalali")
    assert "|" in full_ts
    assert "-" in date_only


def test_write_outputs_creates_parent_dirs(tmp_path: Path):
    out = tmp_path / "nested" / "dir" / "config.txt"
    collector.write_outputs(["vless://u@1.2.3.4:443?security=tls"], out, "gregorian", "note", "@tag")
    assert out.exists()
    lines = out.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert lines[0].startswith("vless://u@1.2.3.4:443?security=tls#")


# ───────────────────────── اختبارات tester.py (المحوّلات) ─────────────────────────
def test_shadowsocks_outline_ipv6_and_plugin():
    # Outline مع /?outline=1
    ss_outline = f"ss://{_b64('chacha20-ietf-poly1305:mypass')}@198.51.100.7:8388/?outline=1#Outline"
    ob = tester.to_outbound(ss_outline)
    assert ob is not None
    srv = ob["settings"]["servers"][0]
    assert srv == {
        "address": "198.51.100.7",
        "port": 8388,
        "method": "chacha20-ietf-poly1305",
        "password": "mypass",
    }

    # IPv6 SIP002
    ss_v6 = f"ss://{_b64('aes-256-gcm:p:a:s:s')}@[2001:db8::1]:443#v6"
    ob_v6 = tester.to_outbound(ss_v6)
    assert ob_v6 is not None
    assert ob_v6["settings"]["servers"][0]["address"] == "2001:db8::1"
    assert ob_v6["settings"]["servers"][0]["port"] == 443
    assert ob_v6["settings"]["servers"][0]["password"] == "p:a:s:s"

    # SIP002 مع plugin غير مدعوم -> يُستثنى
    ss_plugin = f"ss://{_b64('aes-256-gcm:pw')}@1.2.3.4:8388/?plugin=obfs-local%3Bobfs%3Dhttp"
    assert tester.to_outbound(ss_plugin) is None


def test_hysteria2_userpass_and_port_hopping():
    # مصادقة user:pass + منفذ مفرد
    hy_userpass = "hysteria2://alice:sec:ret@hy.example.com:8443/?sni=cdn.example.com&obfs=salamander&obfs-password=obfspw&up=50&down=200"
    ob = tester.to_singbox_outbound(hy_userpass)
    assert ob is not None
    assert ob["password"] == "alice:sec:ret"
    assert ob["server"] == "hy.example.com"
    assert ob["server_port"] == 8443
    assert "server_ports" not in ob
    assert ob["obfs"] == {"type": "salamander", "password": "obfspw"}
    assert ob["up_mbps"] == 50 and ob["down_mbps"] == 200

    # قفز المنافذ (port hopping) بدون تعارض بين server_port و server_ports
    hy_hop = "hy2://token123@192.0.2.10:443,20000-30000?sni=hy.example.com"
    ob_hop = tester.to_singbox_outbound(hy_hop)
    assert ob_hop is not None
    assert "server_port" not in ob_hop
    assert ob_hop["server_ports"] == ["443:443", "20000:30000"]


def test_vless_vmess_trojan_tuic_converters():
    vless_cfg = "vless://11111111-2222-3333-4444-555555555555@[2001:db8::9]:2053?type=ws&security=tls&fp=none&path=%2Fray&host=cdn.test.com"
    ob_vless = tester.to_outbound(vless_cfg)
    assert ob_vless is not None
    assert ob_vless["settings"]["vnext"][0]["address"] == "2001:db8::9"
    assert ob_vless["streamSettings"]["tlsSettings"]["fingerprint"] == "chrome"

    vmess_cfg = "vmess://" + _b64(json.dumps({
        "add": "vm.example.com",
        "port": "2083",
        "id": "11111111-2222-3333-4444-555555555555",
        "aid": "0",
        "net": "grpc",
        "path": "gunService",
        "tls": True,
        "allowInsecure": "1",
    }), urlsafe=True).rstrip("=")
    ob_vmess = tester.to_outbound(vmess_cfg)
    assert ob_vmess is not None
    assert ob_vmess["streamSettings"]["security"] == "tls"
    assert ob_vmess["streamSettings"]["tlsSettings"]["allowInsecure"] is True
    assert ob_vmess["streamSettings"]["grpcSettings"]["serviceName"] == "gunService"

    trojan_cfg = "trojan://pass%40123@tr.example.com:443?security=reality&pbk=PUBKEY&sid=abcd&sni=www.microsoft.com"
    ob_trojan = tester.to_outbound(trojan_cfg)
    assert ob_trojan is not None
    assert ob_trojan["settings"]["servers"][0]["password"] == "pass@123"
    assert ob_trojan["streamSettings"]["realitySettings"]["publicKey"] == "PUBKEY"

    tuic_cfg = "tuic://11111111-2222-3333-4444-555555555555:tuicpass@tuic.example.com:443?congestion_control=bbr&alpn=h3"
    ob_tuic = tester.to_singbox_outbound(tuic_cfg)
    assert ob_tuic is not None
    assert ob_tuic["uuid"] == "11111111-2222-3333-4444-555555555555"
    assert ob_tuic["password"] == "tuicpass"
    assert ob_tuic["tls"]["alpn"] == ["h3"]


def test_host_of_and_pick_candidates():
    ss_b64 = "ss://" + _b64("aes-256-gcm:pw@Example.COM:8388")
    v6_vless = "vless://uuid@[2001:db8::5]:443?security=tls"
    assert tester.host_of(ss_b64) == "example.com"
    assert tester.host_of(v6_vless) == "2001:db8::5"

    cfgs = [
        "vless://u@1.1.1.1:443", "vless://u@1.1.1.2:443", "vless://u@1.1.1.3:443",
        "hy2://p@2.2.2.2:443", "tuic://u:p@3.3.3.3:443",
    ]
    picked, info = tester.pick_candidates(cfgs, 3)
    assert picked == ["vless://u@1.1.1.1:443", "hy2://p@2.2.2.2:443", "tuic://u:p@3.3.3.3:443"]
    assert info["vless"] == (1, 3)


def test_ensure_xray_unsupported_platform_logs_cleanly(monkeypatch):
    monkeypatch.setattr(tester, "_platform_key", lambda: ("plan9", "mips"))
    assert tester.ensure_xray(Path("/tmp/nonexistent-xray-dir"), allow_download=True) is None


# ───────────────────────── اختبار حيّ لـ http_via_socks (204 بدون تعليق) ─────────────────────────
def _start_mock_socks_and_http(response_bytes: bytes, hold_open_sec: float = 0.0) -> tuple[int, int, threading.Event]:
    stop_evt = threading.Event()

    http_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    http_srv.bind(("127.0.0.1", 0))
    http_srv.listen(5)
    http_port = http_srv.getsockname()[1]

    def http_loop():
        http_srv.settimeout(0.2)
        while not stop_evt.is_set():
            try:
                conn, _ = http_srv.accept()
            except OSError:
                continue
            def handle_http(c: socket.socket):
                try:
                    c.recv(1024)
                    c.sendall(response_bytes)
                    if hold_open_sec > 0:
                        stop_evt.wait(hold_open_sec)
                finally:
                    c.close()
            threading.Thread(target=handle_http, args=(conn,), daemon=True).start()
        http_srv.close()

    socks_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks_srv.bind(("127.0.0.1", 0))
    socks_srv.listen(5)
    socks_port = socks_srv.getsockname()[1]

    def socks_loop():
        socks_srv.settimeout(0.2)
        while not stop_evt.is_set():
            try:
                client, _ = socks_srv.accept()
            except OSError:
                continue
            def handle_socks(c: socket.socket):
                upstream = None
                try:
                    ver_nmethods = c.recv(2)
                    if len(ver_nmethods) < 2:
                        return
                    c.recv(ver_nmethods[1])
                    c.sendall(b"\x05\x00")
                    head = c.recv(4)
                    atyp = head[3]
                    if atyp == 3:
                        n = c.recv(1)[0]
                        _ = c.recv(n)
                    elif atyp == 1:
                        _ = c.recv(4)
                    port_bytes = c.recv(2)
                    target_port = int.from_bytes(port_bytes, "big")
                    upstream = socket.create_connection(("127.0.0.1", target_port), timeout=2)
                    c.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")

                    def pipe(src: socket.socket, dst: socket.socket):
                        try:
                            while True:
                                data = src.recv(4096)
                                if not data:
                                    break
                                dst.sendall(data)
                        except OSError:
                            pass
                        finally:
                            try:
                                dst.shutdown(socket.SHUT_WR)
                            except OSError:
                                pass

                    t1 = threading.Thread(target=pipe, args=(c, upstream), daemon=True)
                    t2 = threading.Thread(target=pipe, args=(upstream, c), daemon=True)
                    t1.start()
                    t2.start()
                    t1.join(timeout=3)
                    t2.join(timeout=3)
                finally:
                    if upstream:
                        upstream.close()
                    c.close()
            threading.Thread(target=handle_socks, args=(client,), daemon=True).start()
        socks_srv.close()

    threading.Thread(target=http_loop, daemon=True).start()
    threading.Thread(target=socks_loop, daemon=True).start()
    return socks_port, http_port, stop_evt


def test_http_via_socks_204_returns_immediately_without_waiting_eof():
    resp = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
    socks_port, http_port, stop_evt = _start_mock_socks_and_http(resp, hold_open_sec=2.5)
    try:
        t0 = time.perf_counter()
        status, latency_ms, nbytes = tester.http_via_socks(
            socks_port, f"http://example.com:{http_port}/generate_204", timeout=3.0, max_bytes=4096
        )
        dt = time.perf_counter() - t0
        assert status == 204
        assert nbytes == 0
        assert dt < 0.8, f"http_via_socks علّق بانتظار إغلاق الاتصال: {dt:.2f}s"
        assert latency_ms < 800
    finally:
        stop_evt.set()


def test_http_via_socks_200_reads_exact_body():
    body = b"X" * 2048
    resp = f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body
    socks_port, http_port, stop_evt = _start_mock_socks_and_http(resp, hold_open_sec=2.0)
    try:
        status, _, nbytes = tester.http_via_socks(
            socks_port, f"http://example.com:{http_port}/down", timeout=3.0, max_bytes=4096
        )
        assert status == 200
        assert nbytes == 2048
    finally:
        stop_evt.set()


# ───────────────────────── اختبار دورة الخادم build_data.py ─────────────────────────
def test_build_data_pipeline(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(build_data, "DIST", tmp_path / "dist")
    monkeypatch.setattr(build_data, "PUBLIC_BASE", "https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data")
    monkeypatch.setattr(build_data, "BEST_N", 2)

    sample_cfgs = [
        "vless://11111111-2222-3333-4444-555555555555@1.1.1.1:443?security=tls",
        "hy2://pass@2.2.2.2:443?sni=a.com",
        "trojan://pass@3.3.3.3:443?sni=b.com",
    ]
    fake_results = [
        tester.Result(cfg=sample_cfgs[0], ok=True, latency_ms=120.0, engine="xray"),
        tester.Result(cfg=sample_cfgs[1], ok=True, latency_ms=85.0, engine="singbox"),
        tester.Result(cfg=sample_cfgs[2], ok=False, error="timeout", engine="xray"),
    ]

    with (
        patch.object(collector, "collect_telegram", return_value=(sample_cfgs[:2], 10, 1)),
        patch.object(collector, "collect_github", return_value=(sample_cfgs[2:], [("s1", 1)])),
        patch.object(tester, "ensure_xray", return_value="/usr/bin/true"),
        patch.object(tester, "ensure_singbox", return_value="/usr/bin/true"),
        patch.object(tester, "select_best", return_value=(fake_results, fake_results[:2], 0)),
    ):
        rc = build_data.main()

    assert rc == 0
    dist = tmp_path / "dist"
    assert (dist / "alive.txt").exists()
    assert (dist / "sub.txt").exists()
    assert (dist / "alive.json").exists()
    assert (dist / "best100.txt").exists()
    assert (dist / "all.txt.gz").exists()
    assert (dist / "meta.json").exists()

    meta = json.loads((dist / "meta.json").read_text(encoding="utf-8"))
    assert meta["alive"] == 2
    assert meta["unique_clean"] == 3
    alive_lines = (dist / "alive.txt").read_text(encoding="utf-8").strip().splitlines()
    # الأقل تأخيرًا (85ms) يجب أن يكون الأول
    assert alive_lines[0] == sample_cfgs[1]
    decomp = gzip.decompress((dist / "all.txt.gz").read_bytes()).decode("utf-8").strip().splitlines()
    assert len(decomp) == 3
