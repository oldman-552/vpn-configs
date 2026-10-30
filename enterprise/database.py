"""Enterprise Database & Domain Service Layer (21 Normalized SQLite Tables).

Implements:
- Migration runner (`enterprise/migrations/*.sql`) with PRAGMA foreign_keys = ON.
- Admin Users, RBAC Roles, Argon2id + TOTP 2FA + Brute-force lockout.
- Subscriber Accounts, Argon2id + Zero-Knowledge AES-256-GCM License Envelopes.
- 8 Subscription types + strict 48-Hour Free Trial (server-controlled timestamps,
  no duplicate trials, extension & paid conversion).
- Device Registration (`1 Account = 1 Device` default) + `AUTO BLOCK ON DEVICE VIOLATION`.
- VPN Session Lifecycle, Heartbeats, Server-side Expiration & Instant Revocation.
- Per-User Bandwidth & Quota Limits (`bandwidth_limits` + `data_usage`).
- Smart Server Classification (`EXCELLENT`, `VERY_GOOD`, `GOOD`, `AVERAGE`, `POOR`, `OFFLINE`).
- Tamper-Evident Hash-Chained `admin_audit_logs`, Notifications, Remote Config, App Updates,
  and Configurable Data Retention cleanup.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from enterprise.crypto_security import (
    canonical_json_bytes,
    compute_user_lookup_id,
    encrypt_vip_nodes_payload,
    hash_password_argon2id,
    seal_user_license_envelope,
    sign_ecdsa_der_b64,
    verify_password_argon2id,
    verify_totp_code,
)

SUBSCRIPTION_DURATIONS_HOURS: Dict[str, Optional[int]] = {
    "FREE_TRIAL": 48,
    "DAILY": 24,
    "WEEKLY": 24 * 7,
    "MONTHLY": 24 * 30,
    "THREE_MONTHS": 24 * 90,
    "SIX_MONTHS": 24 * 180,
    "YEARLY": 24 * 365,
    "LIFETIME": None,
}

REQUIRED_TABLES = (
    "users",
    "user_subscriptions",
    "user_devices",
    "user_sessions",
    "trial_activations",
    "login_attempts",
    "device_violations",
    "servers",
    "server_health",
    "speed_tests",
    "network_tests",
    "connection_logs",
    "app_versions",
    "app_crashes",
    "notifications",
    "remote_config",
    "admin_users",
    "admin_roles",
    "admin_audit_logs",
    "bandwidth_limits",
    "data_usage",
)


def parse_iso_utc(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    clean = value.strip()
    if clean.endswith("Z"):
        clean = clean[:-1] + "+00:00"
    dt = datetime.fromisoformat(clean)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def fmt_iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def classify_server_quality(
    is_online: bool,
    ping_ms: int,
    download_kbps: float,
    packet_loss_pct: float,
    jitter_ms: float,
    uptime_pct: float,
    server_load_pct: float = 0.0,
) -> Tuple[float, str]:
    """Dynamic quality score [0..100] & tier classification without geographic bias."""
    if not is_online or ping_ms <= 0:
        return 0.0, "OFFLINE"

    lat_score = max(0.0, min(100.0, (900.0 - ping_ms) / 8.6))
    spd_score = min(100.0, (download_kbps / 10240.0) * 100.0) if download_kbps > 0 else 40.0
    loss_score = max(0.0, 100.0 - packet_loss_pct * 8.0)
    jit_score = max(0.0, 100.0 - jitter_ms * 0.8)
    up_score = max(0.0, min(100.0, uptime_pct))
    load_score = max(0.0, 100.0 - server_load_pct)

    score = round(
        0.28 * spd_score
        + 0.24 * lat_score
        + 0.18 * loss_score
        + 0.12 * jit_score
        + 0.12 * up_score
        + 0.06 * load_score,
        2,
    )
    if score >= 85.0:
        tier = "EXCELLENT"
    elif score >= 72.0:
        tier = "VERY_GOOD"
    elif score >= 56.0:
        tier = "GOOD"
    elif score >= 38.0:
        tier = "AVERAGE"
    else:
        tier = "POOR"
    return score, tier


class EnterpriseDB:
    def __init__(self, db_path: Path, migrations_dir: Optional[Path] = None) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.migrations_dir = migrations_dir or (Path(__file__).resolve().parent / "migrations")
        self.apply_migrations()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA busy_timeout = 10000;")
        try:
            conn.execute("BEGIN IMMEDIATE;")
            yield conn
            conn.execute("COMMIT;")
        except Exception:
            conn.execute("ROLLBACK;")
            raise
        finally:
            conn.close()

    def apply_migrations(self) -> List[str]:
        applied_now: List[str] = []
        conn = sqlite3.connect(str(self.db_path))
        try:
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations ("
                "version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)"
            )
            done = {
                int(row[0])
                for row in conn.execute("SELECT version FROM schema_migrations").fetchall()
            }
            for sql_file in sorted(self.migrations_dir.glob("*.sql")):
                ver = int(sql_file.name.split("_", 1)[0])
                if ver in done:
                    continue
                conn.executescript(sql_file.read_text(encoding="utf-8"))
                conn.execute("PRAGMA foreign_keys = ON;")
                conn.execute(
                    "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                    (ver, sql_file.name, fmt_iso_utc(datetime.now(timezone.utc))),
                )
                conn.commit()
                applied_now.append(sql_file.name)
        finally:
            conn.close()
        return applied_now

    def list_tables(self) -> List[str]:
        with self.tx() as conn:
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
            return [r["name"] for r in rows]

    # ------------------------------------------------------------------
    # Tamper-evident Audit Log & Notification Center
    # ------------------------------------------------------------------
    def _append_audit(
        self,
        conn: sqlite3.Connection,
        admin_id: Optional[str],
        action: str,
        target_type: str,
        target_id: str,
        before_obj: Any,
        after_obj: Any,
        now_iso: str,
    ) -> str:
        prev_row = conn.execute(
            "SELECT entry_hash FROM admin_audit_logs ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        prev_hash = prev_row["entry_hash"] if prev_row else "GENESIS"
        before_json = json.dumps(before_obj or {}, sort_keys=True, ensure_ascii=False)
        after_json = json.dumps(after_obj or {}, sort_keys=True, ensure_ascii=False)
        material = f"{now_iso}|{admin_id or ''}|{action}|{target_type}|{target_id}|{before_json}|{after_json}|{prev_hash}"
        entry_hash = hashlib.sha256(material.encode("utf-8")).hexdigest()
        audit_id = f"aud_{uuid.uuid4().hex[:16]}"
        conn.execute(
            """INSERT INTO admin_audit_logs
               (id, logged_at, admin_id, action, target_type, target_id, before_json, after_json, prev_hash, entry_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (audit_id, now_iso, admin_id, action, target_type, target_id, before_json, after_json, prev_hash, entry_hash),
        )
        return audit_id

    def verify_audit_chain(self) -> bool:
        with self.tx() as conn:
            rows = conn.execute("SELECT * FROM admin_audit_logs ORDER BY rowid ASC").fetchall()
            expected_prev = "GENESIS"
            for r in rows:
                if r["prev_hash"] != expected_prev:
                    return False
                material = (
                    f"{r['logged_at']}|{r['admin_id'] or ''}|{r['action']}|"
                    f"{r['target_type']}|{r['target_id']}|{r['before_json']}|"
                    f"{r['after_json']}|{r['prev_hash']}"
                )
                if hashlib.sha256(material.encode("utf-8")).hexdigest() != r["entry_hash"]:
                    return False
                expected_prev = r["entry_hash"]
            return True

    def _emit_notification(
        self,
        conn: sqlite3.Connection,
        category: str,
        severity: str,
        title_ar: str,
        title_en: str,
        body_ar: str,
        body_en: str,
        now_iso: str,
        target_user_id: Optional[str] = None,
    ) -> str:
        nid = f"ntf_{uuid.uuid4().hex[:16]}"
        conn.execute(
            """INSERT INTO notifications
               (id, created_at, event_category, severity, title_ar, title_en, body_ar, body_en, target_user_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (nid, now_iso, category, severity, title_ar, title_en, body_ar, body_en, target_user_id),
        )
        return nid

    def _log_connection_event(
        self,
        conn: sqlite3.Connection,
        event_type: str,
        severity: str = "INFO",
        user_id: Optional[str] = None,
        device_id: Optional[str] = None,
        session_id: Optional[str] = None,
        error_code: str = "",
        error_description: str = "",
        now_iso: Optional[str] = None,
    ) -> None:
        ts = now_iso or fmt_iso_utc(datetime.now(timezone.utc))
        conn.execute(
            """INSERT INTO connection_logs
               (id, logged_at, user_id, device_id, session_id, event_type, error_code, error_description, severity)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                f"log_{uuid.uuid4().hex[:16]}",
                ts,
                user_id,
                device_id,
                session_id,
                event_type,
                error_code,
                error_description,
                severity,
            ),
        )

    # ------------------------------------------------------------------
    # Admin Authentication, Brute-Force Lockout & MFA (TOTP)
    # ------------------------------------------------------------------
    def create_admin(
        self,
        username: str,
        password: str,
        role_id: str = "role_super_admin",
        totp_secret: str = "",
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        ts = fmt_iso_utc(now or datetime.now(timezone.utc))
        aid = f"adm_{uuid.uuid4().hex[:12]}"
        pw_hash = hash_password_argon2id(password)
        clean_user = username.strip().lower()
        with self.tx() as conn:
            conn.execute(
                """INSERT INTO admin_users
                   (id, username, password_hash, totp_secret_enc, totp_enabled, role_id, is_active, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, 1, ?)""",
                (aid, clean_user, pw_hash, totp_secret, 1 if totp_secret else 0, role_id, ts),
            )
            self._append_audit(conn, aid, "ADMIN_CREATE", "admin_users", aid, {}, {"username": clean_user, "role_id": role_id}, ts)
        return {"id": aid, "username": clean_user, "role_id": role_id, "totp_enabled": bool(totp_secret)}

    def authenticate_admin(
        self,
        username: str,
        password: str,
        totp_code: str = "",
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        cur_dt = now or datetime.now(timezone.utc)
        ts = fmt_iso_utc(cur_dt)
        clean_user = username.strip().lower()
        denied_reason: Optional[str] = None
        result_payload: Optional[Dict[str, Any]] = None
        with self.tx() as conn:
            row = conn.execute(
                """SELECT a.*, r.role_name, r.permissions_json
                   FROM admin_users a JOIN admin_roles r ON a.role_id = r.id
                   WHERE a.username = ?""",
                (clean_user,),
            ).fetchone()
            if not row or not row["is_active"]:
                denied_reason = "INVALID_ADMIN_CREDENTIALS"
            elif row["locked_until"] and parse_iso_utc(row["locked_until"]) and cur_dt < parse_iso_utc(row["locked_until"]):
                denied_reason = "ADMIN_ACCOUNT_LOCKED"
            elif not verify_password_argon2id(password, row["password_hash"]):
                fails = int(row["failed_attempts"]) + 1
                lock_iso = fmt_iso_utc(cur_dt + timedelta(minutes=15)) if fails >= 5 else None
                conn.execute(
                    "UPDATE admin_users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                    (fails, lock_iso, row["id"]),
                )
                if fails >= 5:
                    self._emit_notification(
                        conn,
                        "SUSPICIOUS_LOGIN",
                        "CRITICAL",
                        "محاولات دخول مشبوهة لحساب المشرف",
                        "Suspicious Admin Login Attempts",
                        f"تم قفل الحساب {clean_user} مؤقتًا بعد {fails} محاولات فاشلة",
                        f"Admin {clean_user} temporarily locked after {fails} failed attempts",
                        ts,
                    )
                denied_reason = "INVALID_ADMIN_CREDENTIALS"
            elif row["totp_enabled"] and not verify_totp_code(
                row["totp_secret_enc"], totp_code, unix_time=int(cur_dt.timestamp())
            ):
                denied_reason = "INVALID_2FA_CODE"
            else:
                conn.execute(
                    "UPDATE admin_users SET failed_attempts = 0, locked_until = NULL, last_login_at = ? WHERE id = ?",
                    (ts, row["id"]),
                )
                self._append_audit(conn, row["id"], "ADMIN_LOGIN", "admin_users", row["id"], {}, {"login_at": ts}, ts)
                result_payload = {
                    "id": row["id"],
                    "username": row["username"],
                    "role_name": row["role_name"],
                    "permissions": json.loads(row["permissions_json"]),
                }
        if denied_reason:
            raise PermissionError(denied_reason)
        assert result_payload is not None
        return result_payload

    # ------------------------------------------------------------------
    # Subscriber Management, 8 Subscription Types & 48-Hour Free Trial
    # ------------------------------------------------------------------
    def _get_or_init_vip_key_hex(self, conn: sqlite3.Connection, now_iso: str) -> str:
        row = conn.execute("SELECT key_hex FROM vip_key_ring WHERE id = 1").fetchone()
        if row and len(row["key_hex"]) == 64:
            return str(row["key_hex"])
        fresh_hex = os.urandom(32).hex()
        conn.execute(
            "INSERT OR REPLACE INTO vip_key_ring (id, key_hex, rotated_at) VALUES (1, ?, ?)",
            (fresh_hex, now_iso),
        )
        return fresh_hex

    def add_vip_server(
        self,
        label: str,
        config_uri: str,
        country: str = "",
        priority: int = 100,
        admin_id: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        clean_uri = (config_uri or "").strip()
        if "://" not in clean_uri or len(clean_uri) < 12:
            raise ValueError("INVALID_VIP_SERVER_URI")
        proto = clean_uri.split("://", 1)[0].upper()
        clean_label = (label or "VIP Node").strip()
        clean_cc = (country or "").strip().upper()[:2]
        ts = fmt_iso_utc(now or datetime.now(timezone.utc))
        vid = f"vip_{uuid.uuid4().hex[:12]}"
        with self.tx() as conn:
            self._get_or_init_vip_key_hex(conn, ts)
            conn.execute(
                """INSERT INTO vip_servers
                   (id, label, country, protocol, config_uri, priority, enabled, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)""",
                (vid, clean_label, clean_cc, proto, clean_uri, int(priority), ts, ts),
            )
            created = dict(conn.execute("SELECT * FROM vip_servers WHERE id = ?", (vid,)).fetchone())
            self._append_audit(
                conn,
                admin_id,
                "VIP_SERVER_ADD",
                "vip_servers",
                vid,
                {},
                {"label": clean_label, "country": clean_cc, "protocol": proto, "priority": int(priority)},
                ts,
            )
            return created

    def list_vip_servers(self, active_only: bool = False) -> List[Dict[str, Any]]:
        with self.tx() as conn:
            sql = "SELECT * FROM vip_servers"
            if active_only:
                sql += " WHERE enabled = 1"
            sql += " ORDER BY priority DESC, created_at DESC"
            return [dict(r) for r in conn.execute(sql).fetchall()]

    def remove_vip_server(
        self,
        vip_id: str,
        admin_id: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> bool:
        ts = fmt_iso_utc(now or datetime.now(timezone.utc))
        with self.tx() as conn:
            cur = conn.execute("DELETE FROM vip_servers WHERE id = ?", (vip_id,))
            if cur.rowcount > 0:
                self._append_audit(conn, admin_id, "VIP_SERVER_DELETE", "vip_servers", vip_id, {"id": vip_id}, {}, ts)
                return True
            return False

    def _build_signed_user_envelope(
        self,
        conn: sqlite3.Connection,
        user_id: str,
        plaintext_password: str,
        signing_private_key_b64: Optional[str],
    ) -> str:
        u = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        bw = conn.execute("SELECT * FROM bandwidth_limits WHERE user_id = ?", (user_id,)).fetchone()
        devs = conn.execute(
            "SELECT device_install_id FROM user_devices WHERE user_id = ? AND device_status = 'AUTHORIZED'",
            (user_id,),
        ).fetchall()
        vip_key_hex = self._get_or_init_vip_key_hex(conn, u["updated_at"])
        cert: Dict[str, Any] = {
            "user_id": u["id"],
            "username": u["username"],
            "account_status": u["account_status"],
            "subscription_type": u["subscription_type"],
            "subscription_start": u["subscription_start"],
            "subscription_expiration": u["subscription_expiration"],
            "trial_activation_date": u["trial_activation_date"],
            "device_limit": int(u["device_limit"]),
            "authorized_devices": [d["device_install_id"] for d in devs],
            "session_revoked_at": u["session_revoked_at"],
            "vip_access_key_hex": vip_key_hex,
            "bandwidth": {
                "max_download_kbps": int(bw["max_download_kbps"]) if bw else 0,
                "max_upload_kbps": int(bw["max_upload_kbps"]) if bw else 0,
                "max_total_kbps": int(bw["max_total_kbps"]) if bw else 0,
                "max_daily_mb": int(bw["max_daily_mb"]) if bw else 0,
                "max_monthly_mb": int(bw["max_monthly_mb"]) if bw else 0,
                "max_concurrent_connections": int(bw["max_concurrent_connections"]) if bw else 1,
                "auto_block_on_violation": bool(bw["auto_block_on_violation"]) if bw else False,
            },
            "issued_at": u["updated_at"],
        }
        sig = (
            sign_ecdsa_der_b64(signing_private_key_b64, canonical_json_bytes(cert))
            if signing_private_key_b64
            else ""
        )
        envelope_obj = {"certificate": cert, "signature_b64": sig}
        return seal_user_license_envelope(u["username"], plaintext_password, u["envelope_salt_hex"], envelope_obj)

    def create_user(
        self,
        username: str,
        password: str,
        subscription_type: str = "MONTHLY",
        device_limit: int = 1,
        max_download_kbps: int = 0,
        max_upload_kbps: int = 0,
        max_daily_mb: int = 0,
        max_monthly_mb: int = 0,
        auto_block_on_violation: bool = False,
        admin_id: Optional[str] = None,
        signing_private_key_b64: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        if subscription_type not in SUBSCRIPTION_DURATIONS_HOURS:
            raise ValueError(f"Unsupported subscription_type: {subscription_type}")
        cur_dt = now or datetime.now(timezone.utc)
        ts = fmt_iso_utc(cur_dt)
        clean_user = username.strip().lower()
        if len(clean_user) < 3:
            raise ValueError("Username must be at least 3 characters")

        uid = f"usr_{uuid.uuid4().hex[:14]}"
        pw_hash = hash_password_argon2id(password)
        salt_hex = os.urandom(16).hex()

        if subscription_type == "FREE_TRIAL":
            # Trial lasts 48 consecutive hours once activated (or immediately if started now)
            status = "FREE_TRIAL"
            sub_start = None
            sub_exp = None
        else:
            status = "ACTIVE"
            sub_start = ts
            hours = SUBSCRIPTION_DURATIONS_HOURS[subscription_type]
            sub_exp = fmt_iso_utc(cur_dt + timedelta(hours=hours)) if hours is not None else None

        with self.tx() as conn:
            conn.execute(
                """INSERT INTO users
                   (id, username, password_hash, envelope_salt_hex, account_status, subscription_type,
                    subscription_start, subscription_expiration, device_limit, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (uid, clean_user, pw_hash, salt_hex, status, subscription_type, sub_start, sub_exp, device_limit, ts, ts),
            )
            conn.execute(
                """INSERT INTO bandwidth_limits
                   (user_id, auto_block_on_violation, max_download_kbps, max_upload_kbps,
                    max_total_kbps, max_daily_mb, max_monthly_mb, max_concurrent_connections, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)""",
                (
                    uid,
                    1 if auto_block_on_violation else 0,
                    max_download_kbps,
                    max_upload_kbps,
                    max(max_download_kbps + max_upload_kbps, 0) if (max_download_kbps and max_upload_kbps) else 0,
                    max_daily_mb,
                    max_monthly_mb,
                    ts,
                ),
            )
            if subscription_type != "FREE_TRIAL":
                conn.execute(
                    """INSERT INTO user_subscriptions
                       (id, user_id, subscription_type, starts_at, expires_at, is_current, created_by_admin_id, created_at)
                       VALUES (?, ?, ?, ?, ?, 1, ?, ?)""",
                    (f"sub_{uuid.uuid4().hex[:14]}", uid, subscription_type, ts, sub_exp, admin_id, ts),
                )
            env_b64 = self._build_signed_user_envelope(conn, uid, password, signing_private_key_b64)
            conn.execute("UPDATE users SET envelope_ciphertext_b64 = ? WHERE id = ?", (env_b64, uid))
            self._append_audit(
                conn,
                admin_id,
                "USER_CREATE",
                "users",
                uid,
                {},
                {"username": clean_user, "subscription_type": subscription_type, "device_limit": device_limit},
                ts,
            )
            return dict(conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone())

    def activate_48h_trial(
        self,
        user_id: str,
        device_install_id: str = "",
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Backend-controlled 48-hour trial activation. Rejects duplicate trial attempts."""
        cur_dt = now or datetime.now(timezone.utc)
        ts = fmt_iso_utc(cur_dt)
        exp_dt = cur_dt + timedelta(hours=48)
        exp_iso = fmt_iso_utc(exp_dt)

        with self.tx() as conn:
            existing = conn.execute(
                "SELECT * FROM trial_activations WHERE user_id = ?", (user_id,)
            ).fetchone()
            if existing:
                raise ValueError("TRIAL_ALREADY_USED")

            user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if not user:
                raise LookupError("USER_NOT_FOUND")
            if user["account_status"] in ("BLOCKED", "SUSPENDED", "DISABLED"):
                raise PermissionError(f"ACCOUNT_{user['account_status']}")

            tid = f"trl_{uuid.uuid4().hex[:14]}"
            conn.execute(
                """INSERT INTO trial_activations
                   (id, user_id, activated_at, expires_at, extended_hours, converted_to_paid, initial_device_id, status)
                   VALUES (?, ?, ?, ?, 0, 0, ?, 'ACTIVE')""",
                (tid, user_id, ts, exp_iso, device_install_id),
            )
            conn.execute("UPDATE user_subscriptions SET is_current = 0 WHERE user_id = ?", (user_id,))
            conn.execute(
                """INSERT INTO user_subscriptions
                   (id, user_id, subscription_type, starts_at, expires_at, is_current, created_at)
                   VALUES (?, ?, 'FREE_TRIAL', ?, ?, 1, ?)""",
                (f"sub_{uuid.uuid4().hex[:14]}", user_id, ts, exp_iso, ts),
            )
            conn.execute(
                """UPDATE users
                   SET account_status = 'FREE_TRIAL',
                       subscription_type = 'FREE_TRIAL',
                       subscription_start = ?,
                       subscription_expiration = ?,
                       trial_activation_date = ?,
                       updated_at = ?
                   WHERE id = ?""",
                (ts, exp_iso, ts, ts, user_id),
            )
            return {
                "trial_id": tid,
                "user_id": user_id,
                "activated_at": ts,
                "expires_at": exp_iso,
                "remaining_seconds": 48 * 3600,
                "banner": "FREE TRIAL ACTIVE",
                "remaining_label": "48 HOURS REMAINING",
            }

    def get_trial_or_subscription_state(self, user_id: str, now: Optional[datetime] = None) -> Dict[str, Any]:
        cur_dt = now or datetime.now(timezone.utc)
        ts = fmt_iso_utc(cur_dt)
        with self.tx() as conn:
            u = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if not u:
                raise LookupError("USER_NOT_FOUND")

            status = u["account_status"]
            sub_type = u["subscription_type"]
            exp_dt = parse_iso_utc(u["subscription_expiration"])

            if status in ("ACTIVE", "FREE_TRIAL") and exp_dt and cur_dt >= exp_dt:
                status = "EXPIRED"
                conn.execute("UPDATE users SET account_status = 'EXPIRED', updated_at = ? WHERE id = ?", (ts, user_id))
                conn.execute(
                    "UPDATE user_sessions SET session_status = 'EXPIRED', connection_end = ? WHERE user_id = ? AND session_status = 'ACTIVE'",
                    (ts, user_id),
                )
                if sub_type == "FREE_TRIAL":
                    conn.execute("UPDATE trial_activations SET status = 'EXPIRED' WHERE user_id = ?", (user_id,))
                    self._log_connection_event(conn, "TRIAL_EXPIRED", "WARNING", user_id=user_id, now_iso=ts)
                    self._emit_notification(
                        conn,
                        "TRIAL_EXPIRED",
                        "INFO",
                        "انتهاء الفترة التجريبية",
                        "Free Trial Expired",
                        f"انتهت تجربة 48 ساعة للمستخدم {u['username']}",
                        f"48-hour trial expired for {u['username']}",
                        ts,
                        target_user_id=user_id,
                    )
                else:
                    self._log_connection_event(conn, "SUBSCRIPTION_EXPIRED", "WARNING", user_id=user_id, now_iso=ts)

            rem_sec = max(0, int((exp_dt - cur_dt).total_seconds())) if exp_dt else None
            if status == "FREE_TRIAL":
                hours_left = max(0, (rem_sec or 0) // 3600)
                messages = ["FREE TRIAL ACTIVE", f"{hours_left} HOURS REMAINING"]
            elif status == "EXPIRED" and sub_type == "FREE_TRIAL":
                messages = ["YOUR FREE TRIAL HAS EXPIRED", "CONTACT ADMINISTRATOR"]
            elif status in ("BLOCKED", "SUSPENDED", "DISABLED", "EXPIRED"):
                messages = [status, "CONTACT ADMINISTRATOR"]
            else:
                messages = ["ACTIVE"]

            return {
                "user_id": user_id,
                "username": u["username"],
                "account_status": status,
                "subscription_type": sub_type,
                "expires_at": u["subscription_expiration"],
                "remaining_seconds": rem_sec,
                "can_connect": status in ("ACTIVE", "FREE_TRIAL"),
                "messages": messages,
            }

    def extend_trial_or_subscription(
        self,
        user_id: str,
        extra_hours: int,
        convert_to_type: Optional[str] = None,
        admin_id: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        cur_dt = now or datetime.now(timezone.utc)
        ts = fmt_iso_utc(cur_dt)
        with self.tx() as conn:
            u = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if not u:
                raise LookupError("USER_NOT_FOUND")
            before = dict(u)

            if convert_to_type and convert_to_type != "FREE_TRIAL":
                if convert_to_type not in SUBSCRIPTION_DURATIONS_HOURS:
                    raise ValueError(f"Invalid subscription_type: {convert_to_type}")
                dur = SUBSCRIPTION_DURATIONS_HOURS[convert_to_type]
                new_exp = fmt_iso_utc(cur_dt + timedelta(hours=dur)) if dur is not None else None
                new_status = "ACTIVE"
                new_type = convert_to_type
                conn.execute(
                    "UPDATE trial_activations SET converted_to_paid = 1, status = 'CONVERTED' WHERE user_id = ?",
                    (user_id,),
                )
            else:
                base_dt = parse_iso_utc(u["subscription_expiration"])
                if not base_dt or base_dt < cur_dt:
                    base_dt = cur_dt
                new_exp = fmt_iso_utc(base_dt + timedelta(hours=max(1, extra_hours)))
                new_type = u["subscription_type"]
                new_status = "FREE_TRIAL" if new_type == "FREE_TRIAL" else "ACTIVE"
                if new_type == "FREE_TRIAL":
                    conn.execute(
                        "UPDATE trial_activations SET expires_at = ?, extended_hours = extended_hours + ?, status = 'ACTIVE' WHERE user_id = ?",
                        (new_exp, max(1, extra_hours), user_id),
                    )

            conn.execute(
                """UPDATE users
                   SET account_status = ?, subscription_type = ?, subscription_expiration = ?, updated_at = ?
                   WHERE id = ?""",
                (new_status, new_type, new_exp, ts, user_id),
            )
            after = dict(conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone())
            self._append_audit(conn, admin_id, "SUBSCRIPTION_UPDATE", "users", user_id, before, after, ts)
            return after

    def set_user_status(
        self,
        user_id: str,
        new_status: str,
        admin_id: Optional[str] = None,
        revoke_sessions: bool = True,
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        cur_dt = now or datetime.now(timezone.utc)
        ts = fmt_iso_utc(cur_dt)
        with self.tx() as conn:
            u = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if not u:
                raise LookupError("USER_NOT_FOUND")
            before = dict(u)
            revoked_at = ts if revoke_sessions or new_status in ("BLOCKED", "SUSPENDED", "DISABLED") else u["session_revoked_at"]
            conn.execute(
                "UPDATE users SET account_status = ?, session_revoked_at = ?, updated_at = ? WHERE id = ?",
                (new_status, revoked_at, ts, user_id),
            )
            if revoke_sessions or new_status in ("BLOCKED", "SUSPENDED", "DISABLED"):
                conn.execute(
                    "UPDATE user_sessions SET session_status = 'REVOKED', connection_end = ? WHERE user_id = ? AND session_status = 'ACTIVE'",
                    (ts, user_id),
                )
            after = dict(conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone())
            self._append_audit(conn, admin_id, f"USER_STATUS_{new_status}", "users", user_id, before, after, ts)
            return after

    def reset_user_password(
        self,
        user_id: str,
        new_password: str,
        admin_id: Optional[str] = None,
        signing_private_key_b64: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> None:
        ts = fmt_iso_utc(now or datetime.now(timezone.utc))
        pw_hash = hash_password_argon2id(new_password)
        salt_hex = os.urandom(16).hex()
        with self.tx() as conn:
            conn.execute(
                "UPDATE users SET password_hash = ?, envelope_salt_hex = ?, session_revoked_at = ?, updated_at = ? WHERE id = ?",
                (pw_hash, salt_hex, ts, ts, user_id),
            )
            env_b64 = self._build_signed_user_envelope(conn, user_id, new_password, signing_private_key_b64)
            conn.execute("UPDATE users SET envelope_ciphertext_b64 = ? WHERE id = ?", (env_b64, user_id))
            conn.execute(
                "UPDATE user_sessions SET session_status = 'REVOKED', connection_end = ? WHERE user_id = ? AND session_status = 'ACTIVE'",
                (ts, user_id),
            )
            self._append_audit(conn, admin_id, "USER_PASSWORD_RESET", "users", user_id, {}, {"reset_at": ts}, ts)

    # ------------------------------------------------------------------
    # Authentication + Device Limit Enforcement + Violation Auto-Block
    # ------------------------------------------------------------------
    def authenticate_and_authorize_device(
        self,
        username: str,
        password: str,
        device_install_id: str,
        device_name: str = "Android Phone",
        manufacturer: str = "",
        model: str = "",
        android_version: str = "",
        app_version: str = "",
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Atomic transaction preventing concurrent device registration races."""
        cur_dt = now or datetime.now(timezone.utc)
        ts = fmt_iso_utc(cur_dt)
        clean_user = username.strip().lower()
        clean_dev = device_install_id.strip()
        if not clean_dev or len(clean_dev) < 8:
            raise ValueError("INVALID_DEVICE_INSTALL_ID")

        denied_error: Optional[str] = None
        auth_payload: Optional[Dict[str, Any]] = None

        with self.tx() as conn:
            window_start = fmt_iso_utc(cur_dt - timedelta(minutes=10))
            recent_fails = conn.execute(
                "SELECT COUNT(*) AS c FROM login_attempts WHERE username = ? AND succeeded = 0 AND attempted_at >= ?",
                (clean_user, window_start),
            ).fetchone()["c"]
            if recent_fails >= 8:
                self._log_connection_event(conn, "AUTH_RATE_LIMITED", "WARNING", error_code="429", now_iso=ts)
                denied_error = "RATE_LIMITED"
            else:
                u = conn.execute("SELECT * FROM users WHERE username = ?", (clean_user,)).fetchone()
                if not u or not verify_password_argon2id(password, u["password_hash"]):
                    conn.execute(
                        """INSERT INTO login_attempts
                           (id, username, user_id, device_install_id, succeeded, failure_reason, attempted_at)
                           VALUES (?, ?, ?, ?, 0, 'INVALID_CREDENTIALS', ?)""",
                        (f"lgn_{uuid.uuid4().hex[:14]}", clean_user, u["id"] if u else None, clean_dev, ts),
                    )
                    self._log_connection_event(
                        conn, "LOGIN_FAILURE", "WARNING", user_id=u["id"] if u else None, error_code="INVALID_CREDENTIALS", now_iso=ts
                    )
                    denied_error = "INVALID_CREDENTIALS"
                else:
                    uid = u["id"]
                    if u["subscription_type"] == "FREE_TRIAL" and not u["trial_activation_date"]:
                        exp_iso = fmt_iso_utc(cur_dt + timedelta(hours=48))
                        conn.execute(
                            """INSERT INTO trial_activations
                               (id, user_id, activated_at, expires_at, extended_hours, converted_to_paid, initial_device_id, status)
                               VALUES (?, ?, ?, ?, 0, 0, ?, 'ACTIVE')""",
                            (f"trl_{uuid.uuid4().hex[:14]}", uid, ts, exp_iso, clean_dev),
                        )
                        conn.execute(
                            """UPDATE users
                               SET account_status = 'FREE_TRIAL', subscription_start = ?, subscription_expiration = ?,
                                   trial_activation_date = ?, updated_at = ?
                               WHERE id = ?""",
                            (ts, exp_iso, ts, ts, uid),
                        )
                        u = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()

                    exp_dt = parse_iso_utc(u["subscription_expiration"])
                    status = u["account_status"]
                    if status in ("ACTIVE", "FREE_TRIAL") and exp_dt and cur_dt >= exp_dt:
                        status = "EXPIRED"
                        conn.execute("UPDATE users SET account_status = 'EXPIRED', updated_at = ? WHERE id = ?", (ts, uid))

                    if status not in ("ACTIVE", "FREE_TRIAL"):
                        conn.execute(
                            """INSERT INTO login_attempts
                               (id, username, user_id, device_install_id, succeeded, failure_reason, attempted_at)
                               VALUES (?, ?, ?, ?, 0, ?, ?)""",
                            (f"lgn_{uuid.uuid4().hex[:14]}", clean_user, uid, clean_dev, f"STATUS_{status}", ts),
                        )
                        denied_error = f"ACCOUNT_{status}"
                    else:
                        existing_dev = conn.execute(
                            "SELECT * FROM user_devices WHERE user_id = ? AND device_install_id = ?",
                            (uid, clean_dev),
                        ).fetchone()

                        dev_id: Optional[str] = None
                        if existing_dev and existing_dev["device_status"] == "AUTHORIZED":
                            dev_id = existing_dev["id"]
                            conn.execute("UPDATE user_devices SET last_activity = ?, app_version = ? WHERE id = ?", (ts, app_version, dev_id))
                        elif existing_dev and existing_dev["device_status"] in ("BLOCKED", "REVOKED", "REPLACED"):
                            denied_error = f"DEVICE_{existing_dev['device_status']}"
                        else:
                            auth_count = conn.execute(
                                "SELECT COUNT(*) AS c FROM user_devices WHERE user_id = ? AND device_status = 'AUTHORIZED'",
                                (uid,),
                            ).fetchone()["c"]
                            limit = int(u["device_limit"])
                            if auth_count >= limit:
                                bw = conn.execute("SELECT auto_block_on_violation FROM bandwidth_limits WHERE user_id = ?", (uid,)).fetchone()
                                global_cfg = conn.execute(
                                    "SELECT config_value_json FROM remote_config WHERE config_key = 'auto_block_on_device_violation'"
                                ).fetchone()
                                global_auto = global_cfg and json.loads(global_cfg["config_value_json"]) is True
                                auto_block = bool((bw and bw["auto_block_on_violation"]) or global_auto)

                                conn.execute(
                                    """INSERT INTO device_violations
                                       (id, user_id, attempted_install_id, attempted_device_name, attempted_model,
                                        auto_blocked, violation_reason, occurred_at)
                                       VALUES (?, ?, ?, ?, ?, ?, 'DEVICE_LIMIT_EXCEEDED', ?)""",
                                    (f"vio_{uuid.uuid4().hex[:14]}", uid, clean_dev, device_name, model, 1 if auto_block else 0, ts),
                                )
                                self._log_connection_event(
                                    conn, "DEVICE_LIMIT_REACHED", "CRITICAL" if auto_block else "WARNING",
                                    user_id=uid, error_code="DEVICE_LIMIT", error_description=clean_dev, now_iso=ts,
                                )
                                if auto_block:
                                    conn.execute(
                                        "UPDATE users SET account_status = 'BLOCKED', session_revoked_at = ?, updated_at = ? WHERE id = ?",
                                        (ts, ts, uid),
                                    )
                                    conn.execute(
                                        "UPDATE user_sessions SET session_status = 'REVOKED', connection_end = ? WHERE user_id = ? AND session_status = 'ACTIVE'",
                                        (ts, uid),
                                    )
                                    self._emit_notification(
                                        conn,
                                        "DEVICE_VIOLATION_BLOCK",
                                        "CRITICAL",
                                        "حظر تلقائي لمخالفة حد الأجهزة",
                                        "Account Auto-Blocked on Device Violation",
                                        f"تم حظر الحساب {clean_user} لمحاولة تسجيل جهاز إضافي ({model or device_name})",
                                        f"Account {clean_user} auto-blocked after unauthorized device attempt ({model or device_name})",
                                        ts,
                                        target_user_id=uid,
                                    )
                                    denied_error = "ACCOUNT_AUTO_BLOCKED_DEVICE_VIOLATION"
                                else:
                                    self._emit_notification(
                                        conn,
                                        "DEVICE_VIOLATION",
                                        "HIGH",
                                        "رفض جهاز غير مصرح به",
                                        "Unauthorized Device Rejected",
                                        f"تم رفض جهاز إضافي للحساب {clean_user} مع إبقاء الحساب الأصلي نشطًا",
                                        f"Rejected extra device for {clean_user}; primary account kept active",
                                        ts,
                                        target_user_id=uid,
                                    )
                                    denied_error = "DEVICE_LIMIT_REACHED"
                            else:
                                dev_id = f"dev_{uuid.uuid4().hex[:14]}"
                                conn.execute(
                                    """INSERT INTO user_devices
                                       (id, user_id, device_install_id, device_name, manufacturer, model,
                                        android_version, app_version, registration_date, last_activity, device_status)
                                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'AUTHORIZED')""",
                                    (dev_id, uid, clean_dev, device_name, manufacturer, model, android_version, app_version, ts, ts),
                                )

                        if not denied_error and dev_id:
                            conn.execute(
                                """INSERT INTO login_attempts
                                   (id, username, user_id, device_install_id, succeeded, failure_reason, attempted_at)
                                   VALUES (?, ?, ?, ?, 1, '', ?)""",
                                (f"lgn_{uuid.uuid4().hex[:14]}", clean_user, uid, clean_dev, ts),
                            )
                            conn.execute("UPDATE users SET last_login = ?, last_activity = ? WHERE id = ?", (ts, ts, uid))
                            self._log_connection_event(conn, "LOGIN_SUCCESS", "INFO", user_id=uid, device_id=dev_id, now_iso=ts)

                            bw_row = conn.execute("SELECT * FROM bandwidth_limits WHERE user_id = ?", (uid,)).fetchone()
                            auth_payload = {
                                "user_id": uid,
                                "username": clean_user,
                                "device_id": dev_id,
                                "account_status": status,
                                "subscription_type": u["subscription_type"],
                                "subscription_expiration": u["subscription_expiration"],
                                "bandwidth": dict(bw_row) if bw_row else {},
                            }

        if denied_error:
            raise PermissionError(denied_error)
        assert auth_payload is not None
        return auth_payload

    def replace_or_remove_device(
        self,
        device_id: str,
        action: str = "REVOKED",
        replacement_install_id: Optional[str] = None,
        admin_id: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> None:
        if action not in ("REVOKED", "BLOCKED", "REPLACED"):
            raise ValueError("Invalid device action")
        ts = fmt_iso_utc(now or datetime.now(timezone.utc))
        with self.tx() as conn:
            dev = conn.execute("SELECT * FROM user_devices WHERE id = ?", (device_id,)).fetchone()
            if not dev:
                raise LookupError("DEVICE_NOT_FOUND")
            conn.execute("UPDATE user_devices SET device_status = ?, last_activity = ? WHERE id = ?", (action, ts, device_id))
            conn.execute(
                "UPDATE user_sessions SET session_status = 'REVOKED', connection_end = ? WHERE device_id = ? AND session_status = 'ACTIVE'",
                (ts, device_id),
            )
            if action == "REPLACED" and replacement_install_id:
                conn.execute(
                    """INSERT INTO user_devices
                       (id, user_id, device_install_id, device_name, registration_date, last_activity, device_status)
                       VALUES (?, ?, ?, 'Replaced Device', ?, ?, 'AUTHORIZED')""",
                    (f"dev_{uuid.uuid4().hex[:14]}", dev["user_id"], replacement_install_id.strip(), ts, ts),
                )
            self._append_audit(conn, admin_id, f"DEVICE_{action}", "user_devices", device_id, dict(dev), {"status": action}, ts)

    # ------------------------------------------------------------------
    # VPN Session Management, Heartbeats & Real-Time Metrics
    # ------------------------------------------------------------------
    def start_vpn_session(
        self,
        user_id: str,
        device_id: str,
        server_id: Optional[str],
        vpn_protocol: str,
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        cur_dt = now or datetime.now(timezone.utc)
        ts = fmt_iso_utc(cur_dt)
        state = self.get_trial_or_subscription_state(user_id, now=cur_dt)
        if not state["can_connect"]:
            raise PermissionError(f"CANNOT_START_SESSION_{state['account_status']}")

        with self.tx() as conn:
            dev = conn.execute("SELECT * FROM user_devices WHERE id = ? AND user_id = ?", (device_id, user_id)).fetchone()
            if not dev or dev["device_status"] != "AUTHORIZED":
                raise PermissionError("UNAUTHORIZED_DEVICE")

            bw = conn.execute("SELECT * FROM bandwidth_limits WHERE user_id = ?", (user_id,)).fetchone()
            max_conc = int(bw["max_concurrent_connections"]) if bw else 1
            active_cnt = conn.execute(
                "SELECT COUNT(*) AS c FROM user_sessions WHERE user_id = ? AND session_status = 'ACTIVE'",
                (user_id,),
            ).fetchone()["c"]
            if active_cnt >= max_conc:
                conn.execute(
                    "UPDATE user_sessions SET session_status = 'TERMINATED', connection_end = ? WHERE user_id = ? AND session_status = 'ACTIVE'",
                    (ts, user_id),
                )

            sid = f"ses_{uuid.uuid4().hex[:16]}"
            conn.execute(
                """INSERT INTO user_sessions
                   (id, user_id, device_id, server_id, vpn_protocol, connection_start, last_heartbeat, session_status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE')""",
                (sid, user_id, device_id, server_id, vpn_protocol.upper(), ts, ts),
            )
            conn.execute(
                "UPDATE users SET total_sessions = total_sessions + 1, last_activity = ? WHERE id = ?",
                (ts, user_id),
            )
            self._log_connection_event(conn, "VPN_CONNECTED", "INFO", user_id=user_id, device_id=device_id, session_id=sid, now_iso=ts)
            return {"session_id": sid, "started_at": ts}

    def record_session_heartbeat(
        self,
        session_id: str,
        delta_download_bytes: int,
        delta_upload_bytes: int,
        current_down_bps: int = 0,
        current_up_bps: int = 0,
        ping_ms: int = 0,
        jitter_ms: float = 0.0,
        packet_loss_pct: float = 0.0,
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        cur_dt = now or datetime.now(timezone.utc)
        ts = fmt_iso_utc(cur_dt)
        day_key = cur_dt.strftime("%Y-%m-%d")
        month_prefix = cur_dt.strftime("%Y-%m")

        with self.tx() as conn:
            ses = conn.execute("SELECT * FROM user_sessions WHERE id = ?", (session_id,)).fetchone()
            if not ses:
                raise LookupError("SESSION_NOT_FOUND")
            if ses["session_status"] != "ACTIVE":
                return {"allow_continue": False, "reason": f"SESSION_{ses['session_status']}"}

            uid = ses["user_id"]
            u = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
            exp_dt = parse_iso_utc(u["subscription_expiration"])
            if u["account_status"] not in ("ACTIVE", "FREE_TRIAL") or (exp_dt and cur_dt >= exp_dt):
                conn.execute(
                    "UPDATE user_sessions SET session_status = 'REVOKED', connection_end = ? WHERE id = ?",
                    (ts, session_id),
                )
                return {"allow_continue": False, "reason": "ACCOUNT_INACTIVE_OR_EXPIRED"}

            start_dt = parse_iso_utc(ses["connection_start"]) or cur_dt
            dur_sec = max(0, int((cur_dt - start_dt).total_seconds()))
            d_down = max(0, int(delta_download_bytes))
            d_up = max(0, int(delta_upload_bytes))

            conn.execute(
                """UPDATE user_sessions
                   SET session_duration = ?, total_download = total_download + ?, total_upload = total_upload + ?,
                       current_down_bps = ?, current_up_bps = ?, ping_ms = ?, jitter_ms = ?,
                       packet_loss_pct = ?, last_heartbeat = ?
                   WHERE id = ?""",
                (dur_sec, d_down, d_up, current_down_bps, current_up_bps, ping_ms, jitter_ms, packet_loss_pct, ts, session_id),
            )
            conn.execute(
                """UPDATE users
                   SET total_download = total_download + ?, total_upload = total_upload + ?,
                       total_data_usage = total_data_usage + ?, last_activity = ?
                   WHERE id = ?""",
                (d_down, d_up, d_down + d_up, ts, uid),
            )
            conn.execute(
                """INSERT INTO data_usage (id, user_id, usage_date, download_bytes, upload_bytes, sessions_count)
                   VALUES (?, ?, ?, ?, ?, 1)
                   ON CONFLICT(user_id, usage_date) DO UPDATE SET
                       download_bytes = download_bytes + excluded.download_bytes,
                       upload_bytes = upload_bytes + excluded.upload_bytes""",
                (f"du_{uuid.uuid4().hex[:14]}", uid, day_key, d_down, d_up),
            )

            # Enforce Daily & Monthly Data Quotas
            bw = conn.execute("SELECT * FROM bandwidth_limits WHERE user_id = ?", (uid,)).fetchone()
            if bw:
                daily_limit_bytes = int(bw["max_daily_mb"]) * 1024 * 1024
                monthly_limit_bytes = int(bw["max_monthly_mb"]) * 1024 * 1024
                if daily_limit_bytes > 0:
                    day_row = conn.execute(
                        "SELECT download_bytes + upload_bytes AS used FROM data_usage WHERE user_id = ? AND usage_date = ?",
                        (uid, day_key),
                    ).fetchone()
                    if day_row and int(day_row["used"]) >= daily_limit_bytes:
                        conn.execute(
                            "UPDATE user_sessions SET session_status = 'TERMINATED', connection_end = ? WHERE id = ?",
                            (ts, session_id),
                        )
                        return {"allow_continue": False, "reason": "DAILY_QUOTA_EXCEEDED"}

                if monthly_limit_bytes > 0:
                    m_row = conn.execute(
                        "SELECT COALESCE(SUM(download_bytes + upload_bytes), 0) AS used FROM data_usage WHERE user_id = ? AND usage_date LIKE ?",
                        (uid, f"{month_prefix}%"),
                    ).fetchone()
                    if m_row and int(m_row["used"]) >= monthly_limit_bytes:
                        conn.execute(
                            "UPDATE user_sessions SET session_status = 'TERMINATED', connection_end = ? WHERE id = ?",
                            (ts, session_id),
                        )
                        return {"allow_continue": False, "reason": "MONTHLY_QUOTA_EXCEEDED"}

            return {"allow_continue": True, "duration_sec": dur_sec}

    def expire_stale_sessions(self, stale_after_sec: int = 180, now: Optional[datetime] = None) -> int:
        cur_dt = now or datetime.now(timezone.utc)
        cutoff = fmt_iso_utc(cur_dt - timedelta(seconds=stale_after_sec))
        ts = fmt_iso_utc(cur_dt)
        with self.tx() as conn:
            cur = conn.execute(
                """UPDATE user_sessions
                   SET session_status = 'EXPIRED', connection_end = ?
                   WHERE session_status = 'ACTIVE' AND last_heartbeat < ?""",
                (ts, cutoff),
            )
            return cur.rowcount

    def get_realtime_monitoring_metrics(self, stale_after_sec: int = 180, now: Optional[datetime] = None) -> Dict[str, Any]:
        """Distinguishes Registered Accounts, Registered Devices, Active Devices, Active VPN Sessions, and Unique Connected Users."""
        self.expire_stale_sessions(stale_after_sec=stale_after_sec, now=now)
        with self.tx() as conn:
            reg_accounts = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
            reg_devices = conn.execute("SELECT COUNT(*) AS c FROM user_devices WHERE device_status = 'AUTHORIZED'").fetchone()["c"]
            active_sessions = conn.execute("SELECT COUNT(*) AS c FROM user_sessions WHERE session_status = 'ACTIVE'").fetchone()["c"]
            unique_active_devices = conn.execute(
                "SELECT COUNT(DISTINCT device_id) AS c FROM user_sessions WHERE session_status = 'ACTIVE'"
            ).fetchone()["c"]
            unique_connected_users = conn.execute(
                "SELECT COUNT(DISTINCT user_id) AS c FROM user_sessions WHERE session_status = 'ACTIVE'"
            ).fetchone()["c"]
            bw_totals = conn.execute(
                """SELECT COALESCE(SUM(current_down_bps), 0) AS down_bps,
                          COALESCE(SUM(current_up_bps), 0) AS up_bps
                   FROM user_sessions WHERE session_status = 'ACTIVE'"""
            ).fetchone()
            return {
                "registered_accounts": reg_accounts,
                "registered_devices": reg_devices,
                "active_devices": unique_active_devices,
                "active_vpn_sessions": active_sessions,
                "unique_connected_users": unique_connected_users,
                "current_download_bps": int(bw_totals["down_bps"]),
                "current_upload_bps": int(bw_totals["up_bps"]),
            }

    # ------------------------------------------------------------------
    # Server Sync (from alive.json) & Health Classification
    # ------------------------------------------------------------------
    def sync_servers_from_alive_payload(self, alive_obj: Dict[str, Any], now: Optional[datetime] = None) -> int:
        cur_dt = now or datetime.now(timezone.utc)
        ts = fmt_iso_utc(cur_dt)
        servers_list = alive_obj.get("servers", []) if isinstance(alive_obj, dict) else []
        synced = 0
        with self.tx() as conn:
            for idx, srv in enumerate(servers_list[:500]):
                uri = (srv.get("uri") or srv.get("cfg") or "").strip()
                host = (srv.get("host") or srv.get("address") or "").strip()
                port = int(srv.get("port") or 443)
                proto = (srv.get("protocol") or srv.get("proto") or "vless").upper()
                if not uri or not host or not (1 <= port <= 65535):
                    continue
                sid = "srv_" + hashlib.sha256(f"{proto}:{host}:{port}".encode("utf-8")).hexdigest()[:14]
                ping_ms = int(srv.get("latency_ms") or srv.get("ping_ms") or 0)
                jitter = float(srv.get("jitter_ms") or 0.0)
                spd_kbps = float(srv.get("speed_kbps") or 0.0)
                stab_runs = int(srv.get("stability_runs") or 1)
                uptime_pct = min(100.0, max(50.0, stab_runs * 20.0)) if ping_ms > 0 else 0.0
                score, tier = classify_server_quality(
                    is_online=ping_ms > 0,
                    ping_ms=ping_ms,
                    download_kbps=spd_kbps,
                    packet_loss_pct=0.0,
                    jitter_ms=jitter,
                    uptime_pct=uptime_pct,
                )
                status = "ONLINE" if ping_ms > 0 else "OFFLINE"
                conn.execute(
                    """INSERT INTO servers
                       (id, server_name, country, hostname, address, port, protocol, config_uri,
                        status, quality_tier, quality_score, bandwidth_mbps, ping_ms, jitter_ms,
                        uptime_pct, stability_runs, last_health_check, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(id) DO UPDATE SET
                           country = excluded.country,
                           config_uri = excluded.config_uri,
                           status = CASE WHEN servers.enabled = 0 THEN 'DISABLED' ELSE excluded.status END,
                           quality_tier = excluded.quality_tier,
                           quality_score = excluded.quality_score,
                           bandwidth_mbps = excluded.bandwidth_mbps,
                           ping_ms = excluded.ping_ms,
                           jitter_ms = excluded.jitter_ms,
                           uptime_pct = excluded.uptime_pct,
                           stability_runs = excluded.stability_runs,
                           last_health_check = excluded.last_health_check,
                           updated_at = excluded.updated_at""",
                    (
                        sid,
                        f"bahrain-vpn #{idx + 1}",
                        (srv.get("country") or "").upper()[:2],
                        host,
                        host,
                        port,
                        proto,
                        uri,
                        status,
                        tier,
                        score,
                        round((spd_kbps * 8.0) / 1024.0, 2),
                        ping_ms,
                        jitter,
                        uptime_pct,
                        stab_runs,
                        ts,
                        ts,
                        ts,
                    ),
                )
                conn.execute(
                    """INSERT INTO server_health
                       (id, server_id, checked_at, is_online, ping_ms, jitter_ms, download_kbps, quality_score)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (f"sh_{uuid.uuid4().hex[:14]}", sid, ts, 1 if ping_ms > 0 else 0, ping_ms, jitter, spd_kbps, score),
                )
                synced += 1
        return synced

    def update_remote_config(
        self,
        key: str,
        value_obj: Any,
        admin_id: Optional[str] = None,
        confirmed: bool = False,
        now: Optional[datetime] = None,
    ) -> None:
        ts = fmt_iso_utc(now or datetime.now(timezone.utc))
        with self.tx() as conn:
            cur = conn.execute("SELECT * FROM remote_config WHERE config_key = ?", (key,)).fetchone()
            if cur and cur["requires_confirmation"] and not confirmed:
                raise PermissionError("CONFIRMATION_REQUIRED_FOR_SENSITIVE_CONFIG")
            before = json.loads(cur["config_value_json"]) if cur else None
            val_json = json.dumps(value_obj, ensure_ascii=False)
            conn.execute(
                """INSERT INTO remote_config (config_key, config_value_json, requires_confirmation, updated_at, updated_by_admin_id)
                   VALUES (?, ?, 0, ?, ?)
                   ON CONFLICT(config_key) DO UPDATE SET
                       config_value_json = excluded.config_value_json,
                       updated_at = excluded.updated_at,
                       updated_by_admin_id = excluded.updated_by_admin_id""",
                (key, val_json, ts, admin_id),
            )
            self._append_audit(conn, admin_id, "REMOTE_CONFIG_UPDATE", "remote_config", key, {"value": before}, {"value": value_obj}, ts)

    def enforce_retention_policy(self, retention_days: int = 90, now: Optional[datetime] = None) -> Dict[str, int]:
        cur_dt = now or datetime.now(timezone.utc)
        cutoff = fmt_iso_utc(cur_dt - timedelta(days=max(1, retention_days)))
        deleted: Dict[str, int] = {}
        with self.tx() as conn:
            for tbl, col in (
                ("connection_logs", "logged_at"),
                ("server_health", "checked_at"),
                ("login_attempts", "attempted_at"),
                ("speed_tests", "tested_at"),
                ("network_tests", "tested_at"),
                ("app_crashes", "occurred_at"),
            ):
                c = conn.execute(f"DELETE FROM {tbl} WHERE {col} < ?", (cutoff,))
                deleted[tbl] = c.rowcount
        return deleted

    def export_public_client_bundle(
        self,
        public_spki_b64: str,
        private_pkcs8_b64: str,
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Exports signed zero-knowledge public bundle (no plaintext usernames, passwords, or VIP URIs)."""
        ts = fmt_iso_utc(now or datetime.now(timezone.utc))
        with self.tx() as conn:
            users = conn.execute("SELECT * FROM users WHERE envelope_ciphertext_b64 != ''").fetchall()
            rc_rows = conn.execute("SELECT config_key, config_value_json FROM remote_config").fetchall()
            ver_rows = conn.execute("SELECT * FROM app_versions WHERE is_active = 1 ORDER BY version_code DESC").fetchall()
            vip_rows = conn.execute(
                "SELECT id, label, country, protocol, config_uri, priority FROM vip_servers WHERE enabled = 1 ORDER BY priority DESC, created_at DESC"
            ).fetchall()
            vip_key_hex = self._get_or_init_vip_key_hex(conn, ts)

        licenses: Dict[str, Dict[str, Any]] = {}
        for u in users:
            lookup_id = compute_user_lookup_id(u["username"])
            licenses[lookup_id] = {
                "salt_hex": u["envelope_salt_hex"],
                "envelope_b64": u["envelope_ciphertext_b64"],
                "status_code": u["account_status"],
                "revoked_at": u["session_revoked_at"],
                "updated_at": u["updated_at"],
            }

        remote_cfg = {r["config_key"]: json.loads(r["config_value_json"]) for r in rc_rows}
        updates: List[Dict[str, Any]] = []
        for v in ver_rows:
            d = dict(v)
            raw_abi = d.get("abi_assets_json") or "{}"
            try:
                d["abi_assets"] = json.loads(raw_abi) if isinstance(raw_abi, str) else raw_abi
            except Exception:
                d["abi_assets"] = {}
            updates.append(d)

        vip_plain_list = [
            {
                "id": r["id"],
                "label": r["label"],
                "country": r["country"],
                "protocol": r["protocol"],
                "uri": r["config_uri"],
                "priority": int(r["priority"]),
            }
            for r in vip_rows
        ]
        vip_enc_b64 = encrypt_vip_nodes_payload(vip_key_hex, vip_plain_list) if vip_plain_list else ""

        signed_body = {
            "schema_version": 3,
            "bundle_release": "3.1",
            "generated_at": ts,
            "public_key_spki_b64": public_spki_b64,
            "remote_config": remote_cfg,
            "app_updates": updates,
            "vip_nodes_enc_b64": vip_enc_b64,
            "licenses": licenses,
        }
        sig_b64 = sign_ecdsa_der_b64(private_pkcs8_b64, canonical_json_bytes(signed_body))
        return {"bundle": signed_body, "signature_b64": sig_b64}
