"""Automated Unit, Integration, Security & Failure-Mode Tests for ULTIMATE VPN ENTERPRISE."""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from enterprise.ai_intelligence import AIIntelligenceEngine
from enterprise.crypto_security import (
    canonical_json_bytes,
    compute_totp_code,
    compute_user_lookup_id,
    create_encrypted_sqlite_backup,
    der_to_p1363_signature,
    generate_ecdsa_p256_keypair,
    generate_totp_secret,
    open_user_license_envelope,
    restore_encrypted_sqlite_backup,
    verify_ecdsa_b64,
)
from enterprise.database import REQUIRED_TABLES, EnterpriseDB
from enterprise.publisher import run_serverless_cycle


def test_all_21_normalized_tables_and_audit_chain(tmp_path: Path) -> None:
    db = EnterpriseDB(tmp_path / "ent.sqlite3")
    tables = set(db.list_tables())
    for req in REQUIRED_TABLES:
        assert req in tables, f"Missing required table: {req}"

    totp_sec = generate_totp_secret()
    t0 = datetime(2026, 10, 30, 12, 0, 0, tzinfo=timezone.utc)
    adm = db.create_admin("rootadmin", "StrongAdminPass!2026", totp_secret=totp_sec, now=t0)

    # Reject missing/wrong 2FA
    with pytest.raises(PermissionError, match="INVALID_2FA_CODE"):
        db.authenticate_admin("rootadmin", "StrongAdminPass!2026", totp_code="000000", now=t0)

    valid_code = compute_totp_code(totp_sec, unix_time=int(t0.timestamp()))
    session_info = db.authenticate_admin("rootadmin", "StrongAdminPass!2026", totp_code=valid_code, now=t0)
    assert session_info["id"] == adm["id"]
    assert session_info["role_name"] == "SUPER_ADMIN"
    assert db.verify_audit_chain() is True

    # Tamper test: mutating an audit row breaks hash chain verification
    with db.tx() as conn:
        conn.execute("UPDATE admin_audit_logs SET action = 'TAMPERED' WHERE rowid = 1")
    assert db.verify_audit_chain() is False


def test_admin_brute_force_lockout(tmp_path: Path) -> None:
    db = EnterpriseDB(tmp_path / "lockout.sqlite3")
    t0 = datetime(2026, 10, 30, 12, 0, 0, tzinfo=timezone.utc)
    db.create_admin("secops", "CorrectHorseBatteryStaple!9", now=t0)

    for _ in range(5):
        with pytest.raises(PermissionError, match="INVALID_ADMIN_CREDENTIALS"):
            db.authenticate_admin("secops", "WrongPassword", now=t0)

    # Even with correct password, account is locked for 15 minutes
    with pytest.raises(PermissionError, match="ADMIN_ACCOUNT_LOCKED"):
        db.authenticate_admin("secops", "CorrectHorseBatteryStaple!9", now=t0 + timedelta(minutes=5))

    # Unlocks after 15 minutes
    ok = db.authenticate_admin("secops", "CorrectHorseBatteryStaple!9", now=t0 + timedelta(minutes=16))
    assert ok["username"] == "secops"


def test_48h_free_trial_lifecycle_reinstall_and_expiry_disconnect(tmp_path: Path) -> None:
    db = EnterpriseDB(tmp_path / "trial.sqlite3")
    t0 = datetime(2026, 10, 30, 10, 0, 0, tzinfo=timezone.utc)
    user = db.create_user("trial_ali", "SecretPass#123", subscription_type="FREE_TRIAL", now=t0)

    # First login activates 48h server-side trial
    auth = db.authenticate_and_authorize_device(
        "trial_ali", "SecretPass#123", device_install_id="inst_phone_001", model="Pixel 9", now=t0
    )
    assert auth["account_status"] == "FREE_TRIAL"

    # Duplicate trial activation rejected (anti-reinstall / anti-replay)
    with pytest.raises(ValueError, match="TRIAL_ALREADY_USED"):
        db.activate_48h_trial(user["id"], device_install_id="inst_reinstalled_999", now=t0 + timedelta(hours=2))

    # Start VPN session at T+10h
    ses = db.start_vpn_session(user["id"], auth["device_id"], None, "VLESS", now=t0 + timedelta(hours=10))
    mid_state = db.get_trial_or_subscription_state(user["id"], now=t0 + timedelta(hours=12))
    assert mid_state["can_connect"] is True
    assert mid_state["messages"] == ["FREE TRIAL ACTIVE", "36 HOURS REMAINING"]

    # At T+48h + 1s: trial expires automatically & terminates active VPN session
    exp_state = db.get_trial_or_subscription_state(user["id"], now=t0 + timedelta(hours=48, seconds=1))
    assert exp_state["account_status"] == "EXPIRED"
    assert exp_state["can_connect"] is False
    assert exp_state["messages"] == ["YOUR FREE TRIAL HAS EXPIRED", "CONTACT ADMINISTRATOR"]

    hb = db.record_session_heartbeat(ses["session_id"], 1024, 512, now=t0 + timedelta(hours=48, seconds=2))
    assert hb["allow_continue"] is False

    # Admin converts expired trial to MONTHLY paid plan
    upgraded = db.extend_trial_or_subscription(user["id"], extra_hours=0, convert_to_type="MONTHLY", now=t0 + timedelta(hours=49))
    assert upgraded["account_status"] == "ACTIVE"
    assert upgraded["subscription_type"] == "MONTHLY"


def test_device_limit_concurrent_race_and_auto_block_violation(tmp_path: Path) -> None:
    db = EnterpriseDB(tmp_path / "devices.sqlite3")
    t0 = datetime(2026, 10, 30, 8, 0, 0, tzinfo=timezone.utc)
    db.create_user("racer_user", "RacePass!2026", subscription_type="MONTHLY", device_limit=1, auto_block_on_violation=False, now=t0)

    def attempt(idx: int) -> str:
        try:
            res = db.authenticate_and_authorize_device(
                "racer_user", "RacePass!2026", device_install_id=f"concurrent_dev_{idx:03d}", now=t0
            )
            return f"OK:{res['device_id']}"
        except PermissionError as exc:
            return f"DENIED:{exc}"

    with ThreadPoolExecutor(max_workers=4) as pool:
        outcomes = list(pool.map(attempt, range(4)))

    ok_count = sum(1 for o in outcomes if o.startswith("OK:"))
    denied_count = sum(1 for o in outcomes if "DEVICE_LIMIT_REACHED" in o)
    assert ok_count == 1
    assert denied_count == 3

    # Test AUTO BLOCK ON DEVICE VIOLATION
    u2 = db.create_user("strict_user", "StrictPass!99", subscription_type="YEARLY", device_limit=1, auto_block_on_violation=True, now=t0)
    d1 = db.authenticate_and_authorize_device("strict_user", "StrictPass!99", "strict_dev_A", now=t0)
    s1 = db.start_vpn_session(u2["id"], d1["device_id"], None, "HYSTERIA2", now=t0)

    with pytest.raises(PermissionError, match="ACCOUNT_AUTO_BLOCKED_DEVICE_VIOLATION"):
        db.authenticate_and_authorize_device("strict_user", "StrictPass!99", "strict_dev_B_intruder", model="Galaxy S25", now=t0)

    hb = db.record_session_heartbeat(s1["session_id"], 5000, 1000, now=t0 + timedelta(seconds=10))
    assert hb["allow_continue"] is False
    state = db.get_trial_or_subscription_state(u2["id"], now=t0 + timedelta(seconds=10))
    assert state["account_status"] == "BLOCKED"


def test_quota_enforcement_realtime_metrics_and_signed_zero_knowledge_bundle(tmp_path: Path) -> None:
    priv_b64, pub_b64 = generate_ecdsa_p256_keypair()
    db = EnterpriseDB(tmp_path / "bundle.sqlite3")
    t0 = datetime(2026, 10, 30, 14, 0, 0, tzinfo=timezone.utc)

    u = db.create_user(
        "vip_khalid",
        "Khalid#998877",
        subscription_type="SIX_MONTHS",
        max_download_kbps=25000,
        max_daily_mb=10,
        signing_private_key_b64=priv_b64,
        now=t0,
    )
    auth = db.authenticate_and_authorize_device("vip_khalid", "Khalid#998877", "khalid_phone_01", now=t0)
    ses = db.start_vpn_session(u["id"], auth["device_id"], None, "TROJAN", now=t0)

    metrics = db.get_realtime_monitoring_metrics(now=t0)
    assert metrics["registered_accounts"] == 1
    assert metrics["registered_devices"] == 1
    assert metrics["active_devices"] == 1
    assert metrics["active_vpn_sessions"] == 1
    assert metrics["unique_connected_users"] == 1

    # Exceed 10 MB daily quota -> session terminated automatically
    hb = db.record_session_heartbeat(ses["session_id"], 11 * 1024 * 1024, 512 * 1024, now=t0 + timedelta(minutes=1))
    assert hb["allow_continue"] is False
    assert hb["reason"] == "DAILY_QUOTA_EXCEEDED"

    # Export zero-knowledge bundle and verify ECDSA (DER & P1363) + AES-256-GCM decryption
    exported = db.export_public_client_bundle(pub_b64, priv_b64, now=t0)
    raw_bundle_str = str(exported)
    assert "vip_khalid" not in raw_bundle_str  # Zero plaintext username leak!
    assert "Khalid#998877" not in raw_bundle_str

    bundle_body = exported["bundle"]
    sig_der_b64 = exported["signature_b64"]
    assert verify_ecdsa_b64(pub_b64, canonical_json_bytes(bundle_body), sig_der_b64) is True

    sig_p1363_b64 = base64.b64encode(der_to_p1363_signature(base64.b64decode(sig_der_b64))).decode("ascii")
    assert verify_ecdsa_b64(pub_b64, canonical_json_bytes(bundle_body), sig_p1363_b64) is True

    lookup = compute_user_lookup_id("vip_khalid")
    lic_entry = bundle_body["licenses"][lookup]
    opened = open_user_license_envelope("vip_khalid", "Khalid#998877", lic_entry["salt_hex"], lic_entry["envelope_b64"])
    assert opened["certificate"]["username"] == "vip_khalid"
    assert verify_ecdsa_b64(pub_b64, canonical_json_bytes(opened["certificate"]), opened["signature_b64"]) is True

    with pytest.raises(Exception):
        open_user_license_envelope("vip_khalid", "WrongPassword!", lic_entry["salt_hex"], lic_entry["envelope_b64"])


def test_encrypted_backup_restore_serverless_cycle_and_ai_honesty(tmp_path: Path) -> None:
    src_path = tmp_path / "prod.sqlite3"
    db = EnterpriseDB(src_path)
    t0 = datetime(2026, 10, 30, 15, 0, 0, tzinfo=timezone.utc)

    # Empty DB AI report must honestly report INSUFFICIENT_DATA without fake numbers
    empty_ai = AIIntelligenceEngine(db).generate_all_reports(now=t0)
    assert empty_ai["reports"]["SERVER_HEALTH"]["data_sufficiency"] == "INSUFFICIENT_DATA"
    assert empty_ai["reports"]["DAILY_PERFORMANCE"]["median_download_mbps"] is None
    assert empty_ai["auto_destructive_actions_enabled"] is False

    synced = db.sync_servers_from_alive_payload(
        {
            "servers": [
                {"uri": "vless://u1@1.2.3.4:443", "host": "1.2.3.4", "port": 443, "protocol": "vless", "country": "DE", "latency_ms": 85, "speed_kbps": 9200},
                {"uri": "trojan://u2@5.6.7.8:443", "host": "5.6.7.8", "port": 443, "protocol": "trojan", "country": "NL", "latency_ms": 790, "speed_kbps": 150},
            ]
        },
        now=t0,
    )
    assert synced == 2

    populated_ai = AIIntelligenceEngine(db).generate_all_reports(now=t0)
    assert populated_ai["reports"]["SERVER_HEALTH"]["total_servers"] == 2
    assert len(populated_ai["recommendations"]) >= 1
    assert "supporting_data_evidence" in populated_ai["recommendations"][0]

    bk_dir = tmp_path / "backups"
    enc_bk = create_encrypted_sqlite_backup(src_path, bk_dir, "VaultMasterSecret!2026")
    restored_path = tmp_path / "restored.sqlite3"
    restore_encrypted_sqlite_backup(enc_bk, restored_path, "VaultMasterSecret!2026")

    restored_db = EnterpriseDB(restored_path)
    with restored_db.tx() as conn:
        cnt = conn.execute("SELECT COUNT(*) AS c FROM servers").fetchone()["c"]
    assert cnt == 2

    with pytest.raises(Exception):
        restore_encrypted_sqlite_backup(enc_bk, tmp_path / "bad.sqlite3", "WrongPassphrase")

    # Verify full GitHub serverless publisher cycle
    cycle_summary = run_serverless_cycle(
        vault_enc_path=tmp_path / "vault.enc.json",
        alive_json_path=None,
        output_bundle_path=tmp_path / "out_bundle.json",
        backup_dir=tmp_path / "cycle_backups",
        master_passphrase="VaultMasterSecret!2026",
        signing_priv_b64=None,
        signing_pub_b64=None,
    )
    assert (tmp_path / "out_bundle.json").exists()
    assert (tmp_path / "vault.enc.json").exists()
    assert cycle_summary["backup_created"] is not None
