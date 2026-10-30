"""GitHub-Native Serverless Orchestrator & Public Bundle Publisher.

Runs inside GitHub Actions (`.github/workflows/enterprise.yml` and `data.yml`) to:
1. Unlock the AES-256-GCM encrypted SQLite database vault (if present) or initialize it.
2. Synchronize live VPN servers from `alive.json` into `servers` & `server_health`.
3. Expire stale sessions, transition expired 48-hour trials & paid subscriptions,
   and enforce configurable log retention cleanup.
4. Generate AI Performance Intelligence reports (`ai_reports.json` for admins only).
5. Export the ECDSA P-256 signed zero-knowledge public client bundle (`bundle.json`)
   for `@data` branch distribution to User APKs (contains ZERO plaintext usernames,
   passwords, or admin data).
6. Produce an AES-256-GCM encrypted + SHA-256 integrity-verified database backup.
"""
from __future__ import annotations

import argparse
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from enterprise.ai_intelligence import AIIntelligenceEngine
from enterprise.crypto_security import (
    create_encrypted_sqlite_backup,
    decrypt_file_with_passphrase,
    encrypt_file_with_passphrase,
    generate_ecdsa_p256_keypair,
)
from enterprise.database import EnterpriseDB, fmt_iso_utc


def run_serverless_cycle(
    vault_enc_path: Path,
    alive_json_path: Optional[Path],
    output_bundle_path: Path,
    backup_dir: Optional[Path],
    master_passphrase: Optional[str],
    signing_priv_b64: Optional[str],
    signing_pub_b64: Optional[str],
) -> Dict[str, Any]:
    now_dt = datetime.now(timezone.utc)

    if not signing_priv_b64 or not signing_pub_b64:
        signing_priv_b64, signing_pub_b64 = generate_ecdsa_p256_keypair()

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_db_path = Path(tmp_dir) / "enterprise.sqlite3"
        if vault_enc_path.exists() and master_passphrase:
            decrypt_file_with_passphrase(vault_enc_path, tmp_db_path, master_passphrase)

        db = EnterpriseDB(tmp_db_path)

        # Ensure current User & Admin APK version metadata exists in app_versions
        with db.tx() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO app_versions
                   (id, target_app, version_code, version_name, release_notes, release_date,
                    mandatory, min_supported_code, apk_url, apk_sha256, signing_cert_sha256, is_active)
                   VALUES ('ver_user_3_0', 'USER', 8, '3.0',
                           'إصدار ULTIMATE VPN ENTERPRISE v3.0 مع فحص السرعة والتشخيص الذكي ونظام الحسابات',
                           ?, 0, 7,
                           'https://github.com/oldman-552/vpn-configs/releases/latest/download/app-arm64-v8a-release.apk',
                           '', '', 1)""",
                (fmt_iso_utc(now_dt),),
            )
            conn.execute(
                """INSERT OR IGNORE INTO app_versions
                   (id, target_app, version_code, version_name, release_notes, release_date,
                    mandatory, min_supported_code, apk_url, apk_sha256, signing_cert_sha256, is_active)
                   VALUES ('ver_admin_3_0', 'ADMIN', 1, '3.0',
                           'تطبيق إدارة ULTIMATE VPN ENTERPRISE مع المصادقة الثنائية TOTP والتحكم الكامل عبر GitHub',
                           ?, 0, 1,
                           'https://github.com/oldman-552/vpn-configs/releases/latest/download/app-admin-release.apk',
                           '', '', 1)""",
                (fmt_iso_utc(now_dt),),
            )

        synced_servers = 0
        if alive_json_path and alive_json_path.exists():
            alive_obj = json.loads(alive_json_path.read_text(encoding="utf-8"))
            synced_servers = db.sync_servers_from_alive_payload(alive_obj, now=now_dt)

        expired_sessions = db.expire_stale_sessions(stale_after_sec=180, now=now_dt)
        with db.tx() as conn:
            active_uids = [
                r["id"]
                for r in conn.execute(
                    "SELECT id FROM users WHERE account_status IN ('ACTIVE', 'FREE_TRIAL')"
                ).fetchall()
            ]
        for uid in active_uids:
            db.get_trial_or_subscription_state(uid, now=now_dt)

        retention_deleted = db.enforce_retention_policy(retention_days=90, now=now_dt)
        ai_summary = AIIntelligenceEngine(db).generate_all_reports(now=now_dt)

        bundle_payload = db.export_public_client_bundle(signing_pub_b64, signing_priv_b64, now=now_dt)
        output_bundle_path.parent.mkdir(parents=True, exist_ok=True)
        output_bundle_path.write_text(
            json.dumps(bundle_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        backup_created: Optional[str] = None
        if master_passphrase:
            encrypt_file_with_passphrase(tmp_db_path, vault_enc_path, master_passphrase)
            if backup_dir:
                bk = create_encrypted_sqlite_backup(tmp_db_path, backup_dir, master_passphrase, retain_count=14)
                backup_created = str(bk)

        return {
            "synced_servers": synced_servers,
            "expired_sessions": expired_sessions,
            "retention_deleted": retention_deleted,
            "ai_recommendations_count": len(ai_summary.get("recommendations", [])),
            "bundle_path": str(output_bundle_path),
            "backup_created": backup_created,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="ULTIMATE VPN ENTERPRISE GitHub Serverless Engine")
    parser.add_argument("--vault", default="enterprise/vault/enterprise_vault.enc.json")
    parser.add_argument("--alive", default="out/alive.json")
    parser.add_argument("--bundle-out", default="out/enterprise/bundle.json")
    parser.add_argument("--backup-dir", default="out/enterprise/backups")
    args = parser.parse_args()

    summary = run_serverless_cycle(
        vault_enc_path=Path(args.vault),
        alive_json_path=Path(args.alive) if args.alive else None,
        output_bundle_path=Path(args.bundle_out),
        backup_dir=Path(args.backup_dir) if args.backup_dir else None,
        master_passphrase=os.environ.get("ENTERPRISE_MASTER_KEY"),
        signing_priv_b64=os.environ.get("ENTERPRISE_SIGNING_PRIVATE_KEY"),
        signing_pub_b64=os.environ.get("ENTERPRISE_SIGNING_PUBLIC_KEY"),
    )
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
