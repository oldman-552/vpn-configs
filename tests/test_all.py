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
    # الأقل تأخيرًا (85ms) يجب أن يكون الأول ويحمل الاسم الموحّد bahrain-vpn
    assert alive_lines[0] == f"{sample_cfgs[1]}#bahrain-vpn 1 | 85ms"
    assert alive_lines[1] == f"{sample_cfgs[0]}#bahrain-vpn 2 | 120ms"
    sub_decoded = base64.b64decode((dist / "sub.txt").read_text(encoding="utf-8").strip()).decode("utf-8")
    assert "bahrain-vpn 1" in sub_decoded and "bahrain-vpn 2" in sub_decoded
    decomp = gzip.decompress((dist / "all.txt.gz").read_bytes()).decode("utf-8").strip().splitlines()
    assert len(decomp) == 3


def test_set_uri_remark_bahrain_vpn_across_protocols():
    # VLESS / HY2 / Trojan: يضيف #bahrain-vpn ... بعد حذف أي وسم قديم
    v = collector.set_uri_remark("vless://11111111-2222-3333-4444-555555555555@1.1.1.1:443?security=tls#OLD_CHANNEL", "bahrain-vpn 1")
    assert v.endswith("#bahrain-vpn 1")
    assert "OLD_CHANNEL" not in v

    # VMess: يحدّث حقل ps داخل JSON المرمّز بـ base64 دون إلحاق #fragment خارجي
    raw_vmess = base64.b64encode(json.dumps({
        "v": "2", "ps": "SpamAdChannel", "add": "4.4.4.4", "port": "443",
        "id": "11111111-2222-3333-4444-555555555555", "aid": "0", "net": "ws", "tls": "tls",
    }).encode("utf-8")).decode("ascii")
    m = collector.set_uri_remark(f"vmess://{raw_vmess}#old", "bahrain-vpn 2 | 40ms")
    assert "#" not in m
    decoded_vmess = json.loads(base64.b64decode(m[len("vmess://"):]).decode("utf-8"))
    assert decoded_vmess["ps"] == "bahrain-vpn 2 | 40ms"
    assert tester.to_outbound(m)["settings"]["vnext"][0]["address"] == "4.4.4.4"

    # SSR: يحدّث معامل remarks داخل الحمولة المرمّزة بـ base64url دون إلحاق #fragment
    raw_ssr = base64.urlsafe_b64encode(
        b"5.5.5.5:8388:origin:aes-256-cfb:plain:cGFzcw/?obfsparam=&remarks=T0xE"
    ).decode("ascii").rstrip("=")
    s = collector.set_uri_remark(f"ssr://{raw_ssr}", "bahrain-vpn 3")
    assert "#" not in s
    dec_ssr = collector.b64_decode(s[len("ssr://"):])
    assert dec_ssr is not None and "remarks=" in dec_ssr


def test_write_outputs_and_best_use_bahrain_vpn_tag(tmp_path: Path):
    cfgs = [
        "vless://11111111-2222-3333-4444-555555555555@1.1.1.1:443?security=tls",
        "trojan://pass+word@2.2.2.2:443?sni=example.com",
    ]
    out_cfg = tmp_path / "config.txt"
    collector.write_outputs(cfgs, out_cfg, "gregorian", "تحديث", "bahrain-vpn")
    lines = out_cfg.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert "#bahrain-vpn 1 |" in lines[0]
    assert "#bahrain-vpn 2 |" in lines[1]

    best_cfg = tmp_path / "best.txt"
    results = [
        tester.Result(cfg=cfgs[0], ok=True, latency_ms=42.0, speed_kbps=2500.0),
        tester.Result(cfg=cfgs[1], ok=True, latency_ms=65.0, speed_kbps=1800.0),
    ]
    n = collector.write_best(results, best_cfg, 10, "gregorian", "bahrain-vpn")
    assert n == 2
    blines = best_cfg.read_text(encoding="utf-8").strip().splitlines()
    assert "#bahrain-vpn 1 | 42ms | 2500KB/s" in blines[0]
    assert "#bahrain-vpn 2 | 65ms | 1800KB/s" in blines[1]


# ═════════════════════════════════════════════════════════════════════════════
#  اختبارات الأمان المتقدمة، منع SSRF، تنقيح الأسرار، الـ 5 طبقات لإزالة التكرار،
#  التقييم المركّب L0-L6، دورة حياة المصادر، وحماية آخر نسخة صالحة
# ═════════════════════════════════════════════════════════════════════════════
import io
import re
import tarfile
import zipfile
import pytest
import yaml

import dedupe
import pipeline_security
import scoring


def test_ssrf_and_unsafe_host_blocking():
    blocked_urls = [
        "http://127.0.0.1:8080/sub",
        "https://localhost/sub.txt",
        "http://169.254.169.254/latest/meta-data/",
        "https://10.0.0.5/configs.txt",
        "https://192.168.1.10/sub",
        "https://172.16.10.2/sub",
        "https://[::1]:8443/sub",
        "file:///etc/passwd",
        "ftp://1.1.1.1/sub.txt",
        "https://user:secret@raw.githubusercontent.com/org/repo/main/sub.txt",
    ]
    for u in blocked_urls:
        with pytest.raises(pipeline_security.SecurityError):
            pipeline_security.validate_fetch_url(u, resolve_dns=False)

    # فحص عناوين مضيفي البروكسي الخطرة مقابل العناوين العامة المسموحة
    assert pipeline_security.is_unsafe_config_host("127.0.0.1") is True
    assert pipeline_security.is_unsafe_config_host("169.254.169.254") is True
    assert pipeline_security.is_unsafe_config_host("192.168.0.1") is True
    assert pipeline_security.is_unsafe_config_host("10.1.2.3") is True
    assert pipeline_security.is_unsafe_config_host("router.local") is True
    assert pipeline_security.is_unsafe_config_host("0x7f000001") is True
    assert pipeline_security.is_unsafe_config_host("1.1.1.1") is False
    # RFC 5737 مسموح كعنوان وجهة في اختبارات الكونفيق المقيّدة ولكن محجوب في جلب المصادر
    assert pipeline_security.is_unsafe_config_host("198.51.100.10") is False


def test_safe_fetch_text_blocks_ssrf_redirect_and_caps_size():
    class FakeResp:
        def __init__(self, status_code, headers=None, chunks=b""):
            self.status_code = status_code
            self.headers = headers or {}
            self._chunks = [chunks] if isinstance(chunks, bytes) else list(chunks)
            self.encoding = "utf-8"
            self.closed = False

        def iter_content(self, chunk_size=65536):
            for c in self._chunks:
                yield c

        def close(self):
            self.closed = True

    class RedirectToMetadataSession:
        def get(self, url, **kwargs):
            return FakeResp(302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})

    res = pipeline_security.safe_fetch_text(
        RedirectToMetadataSession(),
        "https://example.com/sub.txt",
        resolve_dns=False,
    )
    assert res.ok is False
    assert "ssrf_blocked" in res.error

    # التحقق من حد الحجم الأقصى ومنع استنزاف الذاكرة
    class OversizedSession:
        def get(self, url, **kwargs):
            return FakeResp(200, chunks=[b"A" * 1024, b"B" * 1024, b"C" * 1024])

    oversized = pipeline_security.safe_fetch_text(
        OversizedSession(),
        "https://example.com/huge.txt",
        max_bytes=1500,
        resolve_dns=False,
    )
    assert oversized.ok is False
    assert "size_cap" in oversized.error or "exceed" in oversized.error.lower()

    # التحقق من الكاش التدريجي عبر ETag / 304 Not Modified
    class EtagSession:
        def __init__(self):
            self.last_headers = {}

        def get(self, url, headers=None, **kwargs):
            self.last_headers = headers or {}
            if self.last_headers.get("If-None-Match") == '"v1"':
                return FakeResp(304, headers={"ETag": '"v1"'})
            return FakeResp(200, headers={"ETag": '"v1"'}, chunks=b"vless://ok")

    sess = EtagSession()
    not_mod = pipeline_security.safe_fetch_text(
        sess, "https://example.com/sub.txt", etag='"v1"', resolve_dns=False
    )
    assert not_mod.ok is True
    assert not_mod.not_modified is True
    assert sess.last_headers.get("If-None-Match") == '"v1"'


def test_credential_redaction_and_archive_path_traversal_guard(tmp_path: Path):
    secret_uuid = "a1b2c3d4-e5f6-4789-abcd-ef0123456789"
    secret_pass = "SuperSecretTrojanPass99!"
    log_msg = (
        f"Failed node vless://{secret_uuid}@1.2.3.4:443?security=tls "
        f"and trojan://{secret_pass}@5.6.7.8:443#tag"
    )
    redacted = pipeline_security.redact_text(log_msg)
    assert secret_uuid not in redacted
    assert secret_pass not in redacted
    assert "***@" in redacted
    assert "[fp:" in redacted
    assert "1.2.3.4:443" in redacted

    # اختبار منع Zip-Slip
    zip_path = tmp_path / "evil.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("../../xray", "echo pwned")
    with pytest.raises(pipeline_security.SecurityError, match="Path traversal"):
        pipeline_security.safe_extract_zip_binary(zip_path, {"xray"}, tmp_path / "out" / "xray")

    # اختبار منع Tar-Slip
    tar_path = tmp_path / "evil.tar.gz"
    with tarfile.open(tar_path, mode="w:gz") as tf:
        info = tarfile.TarInfo(name="../sing-box")
        payload = b"binary"
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    with pytest.raises(pipeline_security.SecurityError, match="Path traversal"):
        pipeline_security.safe_extract_tar_binary(tar_path, {"sing-box"}, tmp_path / "out" / "sing-box")


def test_five_layer_deduplication_and_canonicalization():
    # عقدتان متطابقتان وظيفيًا مع اختلاف الوسم، ترتيب المعاملات، وحالة أحرف UUID
    u1 = "vless://AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE@Example.COM.:443?type=ws&path=%2Fws&security=tls&sni=Example.COM#Channel_A"
    u2 = "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@example.com:443?sni=example.com&security=tls&path=/ws&type=ws#Channel_B"
    # عقدة ثالثة على نفس المضيف والمنفذ ولكن بمعرّف مستخدم مختلف
    u3 = "vless://11111111-2222-3333-4444-555555555555@example.com:443?sni=example.com&security=tls&path=/ws&type=ws#AltUser"
    # التباس hy2 مقابل hysteria2 + قفز المنافذ
    h1 = "hy2://MyPass@198.51.100.77:443,20000-30000/?sni=cdn.example.net&insecure=0#One"
    h2 = "hysteria2://MyPass@198.51.100.77:443?insecure=0&sni=cdn.example.net#Two"
    # عقدة خبيثة تشير إلى شبكة داخلية (يجب رفضها)
    evil_local = "trojan://pw@192.168.1.1:443?sni=test.com#LocalRouter"

    engine = dedupe.MultiLayerDeduplicator(verified_sources={"gh:source1"})
    engine.ingest_source("gh:source1", [u1, h1, evil_local])
    engine.ingest_source("tg:channel2", [u2, u3, h2])

    uris = engine.unique_uris()
    assert len(uris) == 3  # (u1/u2 مدمجة) + u3 + (h1/h2 مدمجة)، وحُجبت evil_local
    assert engine.summary.layer2_identity_duplicates >= 2
    assert engine.summary.invalid_or_unsafe_rejected == 1

    # التأكد من توحيد البروتوكول إلى hysteria2 وعدم تسرب كلمة المرور في البصمة
    hy_rec = [r for r in engine.provenance_map().values() if r.canonical_proto == "hysteria2"][0]
    assert hy_rec.port == 443
    assert "MyPass" not in hy_rec.identity_id
    assert hy_rec.corroboration_count == 2
    assert hy_rec.verified_source_hit is True

    # فحص حساب التداخل بين المصادر بدون أسرار
    overlap = engine.source_overlap_metrics()
    assert overlap["gh:source1"]["unique_identities"] == 2
    assert overlap["gh:source1"]["overlap_ratio"] == 1.0  # كلاهما ظهر أيضًا في tg:channel2
    assert overlap["tg:channel2"]["exclusive_identities"] == 1  # u3 حصرية لـ tg:channel2


def test_scoring_longitudinal_history_and_honest_geolocation(tmp_path: Path):
    hist_path = tmp_path / "node_history.json"
    store = scoring.NodeHistoryStore.load(hist_path)

    u_fast_stable = "vless://11111111-1111-1111-1111-111111111111@1.1.1.1:443?security=tls"
    u_jittery_new = "vless://22222222-2222-2222-2222-222222222222@8.8.8.8:443?security=tls"
    n1 = dedupe.parse_identity(u_fast_stable)
    n2 = dedupe.parse_identity(u_jittery_new)
    assert n1 is not None and n2 is not None

    # محاكاة سجل تاريخي سابق عبر 4 جولات ناجحة للعقدة الأولى
    for _ in range(4):
        store.record_observation(
            n1.identity_id, ok=True, latency_ms=75.0, speed_kbps=2400.0,
            exit_country="DE", country_source="exit_trace"
        )
    store.save(hist_path)

    reloaded = scoring.NodeHistoryStore.load(hist_path)
    obs1 = reloaded.record_observation(
        n1.identity_id, ok=True, latency_ms=80.0, speed_kbps=2600.0,
        exit_country="DE", country_source="exit_trace"
    )
    obs2 = reloaded.record_observation(
        n2.identity_id, ok=True, latency_ms=190.0, speed_kbps=0.0
    )

    score1, brk1 = scoring.compute_composite_score(
        median_latency_ms=80.0, jitter_ms=4.0, probe_pass_rate=1.0, speed_kbps=2600.0,
        runs_seen=obs1.runs_seen, runs_alive=obs1.runs_alive,
        consecutive_alive=obs1.consecutive_alive, ema_reliability=obs1.ema_reliability,
        corroboration_count=2, verified_source_hit=True,
    )
    score2, brk2 = scoring.compute_composite_score(
        median_latency_ms=190.0, jitter_ms=95.0, probe_pass_rate=0.67, speed_kbps=0.0,
        runs_seen=obs2.runs_seen, runs_alive=obs2.runs_alive,
        consecutive_alive=obs2.consecutive_alive, ema_reliability=obs2.ema_reliability,
        corroboration_count=1, verified_source_hit=False,
    )
    assert score1 > score2
    assert brk1["reliability"] > brk2["reliability"]

    # فحص تحديد الدولة الصادق بدون تلفيق
    cc_hint, src_hint = scoring.infer_country_hint(f"{u_jittery_new}#🇳🇱 HintOnly", "8.8.8.8")
    assert cc_hint == "NL"
    assert src_hint == "remark_hint"

    sn1 = scoring.ScoredNode(
        uri=u_fast_stable, identity_id=n1.identity_id, protocol="vless",
        canonical_protocol="vless", host=n1.host, port=n1.port, subnet_key=n1.subnet_key,
        latency_ms=80.0, median_latency_ms=80.0, jitter_ms=4.0, probe_pass_rate=1.0,
        speed_kbps=2600.0, exit_country="DE", country_source="exit_trace",
        runs_seen=obs1.runs_seen, runs_alive=obs1.runs_alive,
        consecutive_alive=obs1.consecutive_alive, ema_reliability=obs1.ema_reliability,
        score=score1, score_breakdown=brk1,
    )
    sn2 = scoring.ScoredNode(
        uri=u_jittery_new, identity_id=n2.identity_id, protocol="vless",
        canonical_protocol="vless", host=n2.host, port=n2.port, subnet_key=n2.subnet_key,
        latency_ms=190.0, median_latency_ms=190.0, jitter_ms=95.0, probe_pass_rate=0.67,
        speed_kbps=0.0, exit_country=cc_hint, country_source=src_hint,
        runs_seen=obs2.runs_seen, runs_alive=obs2.runs_alive,
        consecutive_alive=obs2.consecutive_alive, ema_reliability=obs2.ema_reliability,
        score=score2, score_breakdown=brk2,
    )
    lists = scoring.build_specialized_lists([sn2, sn1], best_n=10)
    assert lists["best100"][0].identity_id == sn1.identity_id
    assert len(lists["reliable"]) >= 1
    assert len(lists["high_throughput"]) == 1


def test_source_lifecycle_transitions(tmp_path: Path):
    reg = scoring.SourceHealthRegistry()
    rec = reg.get_or_create("gh:dead_repo", "github", "https://raw.githubusercontent.com/org/repo/main/sub.txt")
    # مصدر يفشل متكررًا يتحول تلقائيًا من temporarily_failed -> degraded -> disabled
    for _ in range(scoring.DISABLE_FAILURE_THRESHOLD):
        rec.update_from_fetch(fetch_ok=False, status_code=404, error="HTTP 404")
    assert rec.state == "disabled"
    # يدخل في فترة تهدئة ولا يُفحص في كل دورة، ثم يستعيد حالته النشطة تلقائيًا عند عودته للعمل
    rec.update_from_fetch(fetch_ok=True, status_code=200, raw_count=120, valid_count=115)
    assert rec.state == "active"
    assert rec.consecutive_failures == 0

    state_file = tmp_path / "source_state.json"
    reg.save_state(state_file)
    reloaded = scoring.SourceHealthRegistry.load(state_file)
    assert reloaded.records["gh:dead_repo"].state == "active"


def test_build_data_protects_last_known_good_on_zero_alive(tmp_path: Path, monkeypatch):
    dist_dir = tmp_path / "dist"
    prev_dir = tmp_path / "prev_dist"
    prev_dir.mkdir(parents=True)
    # تجهيز نسخة صالحة سابقة (Last-Known-Good)
    prev_uri = "vless://11111111-2222-3333-4444-555555555555@1.1.1.1:443?security=tls#bahrain-vpn 1 | 55ms"
    (prev_dir / "alive.txt").write_text(prev_uri + "\n", encoding="utf-8")
    (prev_dir / "best100.txt").write_text(prev_uri + "\n", encoding="utf-8")
    (prev_dir / "sub.txt").write_text(
        base64.b64encode((prev_uri + "\n").encode("utf-8")).decode("ascii") + "\n",
        encoding="utf-8",
    )
    (prev_dir / "alive.json").write_text(
        json.dumps({"generated_at": "2026-10-29T10:00:00Z", "count": 1, "servers": [{"cfg": prev_uri, "latency_ms": 55}]}),
        encoding="utf-8",
    )

    monkeypatch.setattr(build_data, "DIST", dist_dir)
    monkeypatch.setattr(build_data, "PREV_DIR", prev_dir)

    dead_cfg = "vless://11111111-2222-3333-4444-555555555555@1.1.1.1:443?security=tls"
    dead_res = [tester.Result(cfg=dead_cfg, ok=False, error="timeout", engine="xray")]

    eng = dedupe.MultiLayerDeduplicator()
    eng.ingest_source("gh:test", [dead_cfg])
    reg = scoring.SourceHealthRegistry()
    telemetry = collector.CollectionTelemetry(
        raw_uris=[dead_cfg],
        unique_uris=[dead_cfg],
        channel_stats={"ch1": 1},
        deduper=eng,
        health_registry=reg,
        github_fetched_ok=1,
        channels_ok=1,
        per_source_uris={"gh:test": [dead_cfg]},
    )

    with (
        patch.object(collector, "collect_with_telemetry", return_value=telemetry),
        patch.object(tester, "ensure_xray", return_value="/usr/bin/true"),
        patch.object(tester, "ensure_singbox", return_value="/usr/bin/true"),
        patch.object(tester, "select_best", return_value=(dead_res, [], 0)),
    ):
        rc = build_data.main()

    # يجب حماية ملفات المستخدمين الحية من التصفير وتسجيل degraded_mode=True
    assert rc == 0
    assert (dist_dir / "alive.txt").read_text(encoding="utf-8").strip() == prev_uri
    meta = json.loads((dist_dir / "meta.json").read_text(encoding="utf-8"))
    assert meta["degraded_mode"] is True


def test_curated_sources_and_pinned_github_workflows():
    repo_root = Path(__file__).resolve().parents[1]
    sources = collector.load_sources_file(repo_root / "github_sources.txt")
    assert len(sources) >= 20
    urls = list(sources.values())
    assert len(urls) == len(set(urls)), "Duplicate URLs found in github_sources.txt"
    for name, url in sources.items():
        assert url.startswith("https://"), f"Non-HTTPS source {name}: {url}"

    # التحقق من تثبيت جميع إجراءات GitHub Actions ببصمة SHA من 40 محرفًا
    sha_pin_re = re.compile(r"^[^@]+@[0-9a-f]{40}$")
    wf_dir = repo_root / ".github" / "workflows"
    wf_files = sorted(wf_dir.glob("*.yml"))
    assert len(wf_files) >= 3
    for wf in wf_files:
        doc = yaml.safe_load(wf.read_text(encoding="utf-8"))
        assert "permissions" in doc, f"Top-level permissions missing in {wf.name}"
        for job_name, job in (doc.get("jobs") or {}).items():
            for step in job.get("steps") or []:
                uses = step.get("uses")
                if uses:
                    assert sha_pin_re.match(uses), f"Unpinned uses '{uses}' in {wf.name}:{job_name}"


def test_source_candidate_governance_and_discovery():
    import source_stats

    base_uris = [
        f"vless://11111111-1111-1111-1111-{i:012d}@198.51.100.{(i % 200) + 1}:443?security=tls"
        for i in range(1, 35)
    ]
    existing_ids = {dedupe.parse_identity(u).identity_id for u in base_uris}

    # تغذية مكررة بنسبة 100% يجب رفضها تلقائيًا
    dup_verdict = source_stats.evaluate_candidate_feed("\n".join(base_uris), existing_ids)
    assert dup_verdict["decision"] in ("rejected_low_yield", "rejected_high_overlap")

    # تغذية تضيف 25 عقدة حصرية جديدة تمامًا تُصنّف كـ pending_validation (وليس تفعيلًا أعمى)
    fresh_uris = [
        f"trojan://pass{i}@203.0.113.{(i % 200) + 1}:443?sni=example.org"
        for i in range(1, 26)
    ]
    fresh_verdict = source_stats.evaluate_candidate_feed("\n".join(fresh_uris), existing_ids)
    assert fresh_verdict["exclusive_identities"] == 25
    assert fresh_verdict["decision"] == "pending_validation"


def test_tester_context_manager_cleans_tempdir():
    with tester.Tester(xray_path="/usr/bin/true", singbox_path="/usr/bin/true", concurrency=2) as t:
        tmp_dir = t._tmp
        assert tmp_dir.is_dir()
    assert not tmp_dir.exists()




