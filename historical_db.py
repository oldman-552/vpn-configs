#!/usr/bin/env python3
"""
Historical Server Intelligence Database, Time-Series Analytics, Windowed Uptime,
Failure Classification, Source Independence & Versioned Public Exporter (`historical_db.py`).

Design Principles:
  1. SQLite WAL persistence (`state/history.sqlite3`) integrated directly into the
     existing Pure-GitHub pipeline (`server/build_data.py` + `@data` snapshot carry-over).
  2. Zero credentials in historical storage: NEVER stores plaintext passwords, UUIDs,
     private keys, raw proxy URIs, or unmasked exit IP addresses.
  3. Accurate Uptime Model: accounts for discovery time, retirement, testing cadence,
     and monitoring outages; distinguishes OBSERVED, ESTIMATED, and UNKNOWN availability.
  4. Multi-Window Analytics: 24h, 7d, 30d, and 90d comparisons with p95 latency,
     jitter, packet loss, download/upload speeds, success rate, and recovery time.
  5. Failure Intelligence & Temporary Suppression: 10 structured failure categories;
     never permanently deletes a server for failing a single test.
  6. Source Operator Independence: multiple URLs controlled by the same GitHub owner,
     Telegram channel, or web domain count as ONE independent operator.
"""
from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import json
import logging
import math
import shutil
import sqlite3
import statistics
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Sequence

from dedupe import ParsedIdentity, extract_source_operator_id, parse_identity
from public_api import mask_endpoint_host

LOG = logging.getLogger("historical_db")
MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations" / "history"
EXPORT_SCHEMA_VERSION = "1.0.0"

FAILURE_CATEGORIES = (
    "CONNECTION_TIMEOUT",
    "AUTHENTICATION_FAILURE",
    "DNS_FAILURE",
    "HANDSHAKE_FAILURE",
    "TLS_ERROR",
    "ROUTING_FAILURE",
    "PACKET_LOSS",
    "SERVER_UNAVAILABLE",
    "INVALID_CONFIGURATION",
    "UNKNOWN_FAILURE",
)


@dataclass(frozen=True)
class RetentionPolicy:
    detailed_days: int = 30
    hourly_days: int = 90
    daily_days: int = 365
    retire_unseen_days: int = 14


@dataclass(frozen=True)
class SuppressionPolicy:
    consecutive_failure_threshold: int = 4
    base_suppress_sec: int = 3_600       # 1 hour initial cooldown
    max_suppress_sec: int = 43_200       # Cap at 12 hours (never permanent deletion)


def parse_iso_epoch(ts: str) -> int:
    s = (ts or "").strip()
    if not s:
        return int(datetime.now(timezone.utc).timestamp())
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except Exception:
        return int(datetime.now(timezone.utc).timestamp())


def epoch_to_iso(epoch_sec: int) -> str:
    return datetime.fromtimestamp(int(epoch_sec), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def mask_exit_ip_to_subnet(ip_str: str) -> str:
    """Mask an observed exit IP to /24 (IPv4) or /48 (IPv6) for privacy-safe geo history."""
    raw = (ip_str or "").strip().strip("[]")
    if not raw:
        return ""
    try:
        ip = ipaddress.ip_address(raw)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if isinstance(ip, ipaddress.IPv4Address):
            net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
            return f"{net.network_address}/24"
        net6 = ipaddress.IPv6Network(f"{ip}/48", strict=False)
        return f"{net6.network_address}/48"
    except ValueError:
        return ""


def classify_failure_reason(raw_error: str | None, *, packet_loss_pct: float = 0.0) -> str:
    """
    Map low-level engine/socket/HTTP probe errors into the 10 standardized
    Failure Intelligence categories without leaking sensitive text.
    """
    err = (raw_error or "").strip().lower()
    if not err:
        return "PACKET_LOSS" if packet_loss_pct >= 50.0 else "UNKNOWN_FAILURE"

    if any(tok in err for tok in ("invalid", "unsupported", "bad_uri", "parse", "malformed", "quarantine", "short_pbk")):
        return "INVALID_CONFIGURATION"
    if any(tok in err for tok in ("auth", "401", "403", "407", "bad_password", "uuid", "forbidden", "socks_auth")):
        return "AUTHENTICATION_FAILURE"
    if any(tok in err for tok in ("dns", "nxdomain", "gaierror", "name or service not known", "no address associated", "servfail")):
        return "DNS_FAILURE"
    if any(tok in err for tok in ("tls", "ssl", "x509", "cert", "certificate", "sni", "alpn", "unknown_ca", "reality")):
        return "TLS_ERROR"
    if any(tok in err for tok in ("handshake", "eof_during", "protocol_error", "reset_by_peer", "quic_handshake", "socks_handshake")):
        return "HANDSHAKE_FAILURE"
    if any(tok in err for tok in ("timeout", "timed out", "deadline", "read_timeout", "connect_timeout")):
        return "CONNECTION_TIMEOUT"
    if any(tok in err for tok in ("unreachable", "network is unreachable", "no route", "routing", "http_301", "http_302", "http_307", "loop")):
        return "ROUTING_FAILURE"
    if any(tok in err for tok in ("packet_loss", "degraded_loss", "partial_probe")) or packet_loss_pct >= 60.0:
        return "PACKET_LOSS"
    if any(tok in err for tok in ("refused", "connection refused", "502", "503", "504", "proc_dead", "unavailable", "closed")):
        return "SERVER_UNAVAILABLE"
    return "UNKNOWN_FAILURE"


def compute_percentile(sorted_vals: Sequence[float], pct: float) -> float | None:
    if not sorted_vals:
        return None
    if len(sorted_vals) == 1:
        return round(float(sorted_vals[0]), 2)
    rank = (pct / 100.0) * (len(sorted_vals) - 1)
    low = int(math.floor(rank))
    high = int(math.ceil(rank))
    if low == high:
        return round(float(sorted_vals[low]), 2)
    weight = rank - low
    return round(float(sorted_vals[low] * (1.0 - weight) + sorted_vals[high] * weight), 2)


def compute_windowed_uptime(
    observations: Sequence[tuple[int, int]],
    *,
    window_start_epoch: int,
    window_end_epoch: int,
    first_seen_epoch: int,
    retired_epoch: int | None = None,
    pipeline_run_epochs: Sequence[int] = (),
    expected_cadence_sec: int = 1_800,
) -> tuple[float | None, str, float]:
    """
    Compute honest windowed availability `(uptime_pct, uptime_kind, coverage_ratio)`.

    - Never penalizes pre-discovery time (`t < first_seen_epoch`) or post-retirement time.
    - Discounts monitoring outage intervals (`gap > 2.5 * expected_cadence_sec` in
      `pipeline_run_epochs`) so CI/network outages are not misclassified as server downtime.
    - Distinguishes:
        * 'OBSERVED'  : >= 4 samples and >= 50% active-window observation coverage
        * 'ESTIMATED' : >= 1 sample with lower frequency / partial window coverage
        * 'UNKNOWN'   : 0 samples in window (returns `None` rather than fabricated 0% or 100%)
    """
    eff_start = max(window_start_epoch, first_seen_epoch)
    eff_end = min(window_end_epoch, retired_epoch) if retired_epoch else window_end_epoch
    if eff_end <= eff_start:
        if not observations:
            return None, "UNKNOWN", 0.0
        ok_cnt = sum(1 for _, ok in observations if ok)
        return round((ok_cnt / len(observations)) * 100.0, 2), "ESTIMATED", 0.25

    in_win = sorted(
        [(int(ts), 1 if ok else 0) for ts, ok in observations if eff_start <= int(ts) <= eff_end],
        key=lambda x: x[0],
    )
    if not in_win:
        return None, "UNKNOWN", 0.0

    raw_span = max(1, eff_end - eff_start)
    outage_threshold = int(expected_cadence_sec * 2.5)

    # Subtract monitoring outage gaps observed across global pipeline runs
    outage_sec = 0
    if pipeline_run_epochs:
        runs = sorted(t for t in pipeline_run_epochs if eff_start <= t <= eff_end)
        for idx in range(1, len(runs)):
            gap = runs[idx] - runs[idx - 1]
            if gap > outage_threshold:
                outage_sec += gap - expected_cadence_sec

    monitorable_span = max(1, raw_span - outage_sec)

    # Integrate bounded observation intervals (each sample covers up to 2 * cadence)
    max_hold = max(expected_cadence_sec * 2, 3_600)
    up_sec = 0.0
    observed_sec = 0.0

    for idx, (ts, ok_val) in enumerate(in_win):
        next_ts = in_win[idx + 1][0] if idx + 1 < len(in_win) else eff_end
        dt = max(1, min(next_ts - ts, max_hold))
        # Ensure single-point tail at window end still receives a representative slot
        if idx + 1 == len(in_win) and next_ts == ts:
            dt = min(expected_cadence_sec, monitorable_span)
        observed_sec += dt
        if ok_val == 1:
            up_sec += dt

    coverage = min(1.0, observed_sec / max(1.0, float(monitorable_span)))
    pct = round((up_sec / max(1.0, observed_sec)) * 100.0, 2)
    kind = "OBSERVED" if (len(in_win) >= 4 and coverage >= 0.50) else "ESTIMATED"
    return pct, kind, round(coverage, 4)


class HistoricalServerDB:
    """
    Transactional, WAL-enabled SQLite time-series intelligence database.
    Thread-safe, migration-versioned, and corruption-resilient.
    """

    def __init__(
        self,
        db_path: Path,
        *,
        retention: RetentionPolicy | None = None,
        suppression: SuppressionPolicy | None = None,
    ) -> None:
        self.db_path = Path(db_path)
        self.retention = retention or RetentionPolicy()
        self.suppression = suppression or SuppressionPolicy()
        self._lock = threading.RLock()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_healthy_and_migrated()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        return conn

    def _ensure_healthy_and_migrated(self) -> None:
        with self._lock:
            if self.db_path.is_file() and self.db_path.stat().st_size > 0:
                corrupted = False
                try:
                    conn = self._connect()
                    try:
                        res = conn.execute("PRAGMA quick_check;").fetchone()
                        if not res or str(res[0]).lower() != "ok":
                            corrupted = True
                    finally:
                        conn.close()
                except sqlite3.DatabaseError:
                    corrupted = True

                if corrupted:
                    quarantined = self.db_path.with_suffix(".corrupt.bak")
                    LOG.warning("Detected corrupted SQLite file %s — moving to %s and reinitializing", self.db_path, quarantined)
                    with contextlib.suppress(OSError):
                        shutil.move(str(self.db_path), str(quarantined))
                    for sfx in ("-wal", "-shm"):
                        aux = Path(str(self.db_path) + sfx)
                        with contextlib.suppress(OSError):
                            aux.unlink(missing_ok=True)

            self.apply_migrations()

    @contextlib.contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                yield conn
                conn.execute("COMMIT;")
            except Exception:
                with contextlib.suppress(Exception):
                    conn.execute("ROLLBACK;")
                raise
            finally:
                conn.close()

    def apply_migrations(self) -> list[str]:
        applied_now: list[str] = []
        with self.tx() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version    INTEGER PRIMARY KEY,
                    name       TEXT NOT NULL UNIQUE,
                    applied_at TEXT NOT NULL
                );
                """
            )
            existing = {
                int(row["version"])
                for row in conn.execute("SELECT version FROM schema_migrations;").fetchall()
            }
            if MIGRATIONS_DIR.is_dir():
                for sql_file in sorted(MIGRATIONS_DIR.glob("*.sql")):
                    prefix = sql_file.name.split("_", 1)[0]
                    if not prefix.isdigit():
                        continue
                    ver = int(prefix)
                    if ver in existing:
                        continue
                    sql_script = sql_file.read_text(encoding="utf-8")
                    for stmt in self._split_sql_statements(sql_script):
                        conn.execute(stmt)
                    now_s = epoch_to_iso(int(datetime.now(timezone.utc).timestamp()))
                    conn.execute(
                        "INSERT INTO schema_migrations(version, name, applied_at) VALUES (?, ?, ?);",
                        (ver, sql_file.name, now_s),
                    )
                    applied_now.append(sql_file.name)
        return applied_now

    @staticmethod
    def _split_sql_statements(sql_script: str) -> list[str]:
        statements: list[str] = []
        buf: list[str] = []
        for line in sql_script.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("--"):
                continue
            buf.append(line)
            if stripped.endswith(";"):
                statements.append("\n".join(buf))
                buf.clear()
        if buf:
            statements.append("\n".join(buf))
        return statements

    def applied_migrations(self) -> list[dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute("SELECT version, name, applied_at FROM schema_migrations ORDER BY version ASC;").fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def backup_to(self, dest_path: Path) -> Path:
        dest = Path(dest_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + ".tmp")
        with self._lock:
            src_conn = self._connect()
            try:
                dst_conn = sqlite3.connect(str(tmp))
                try:
                    src_conn.backup(dst_conn)
                finally:
                    dst_conn.close()
            finally:
                src_conn.close()
        tmp.replace(dest)
        return dest

    def restore_from(self, backup_path: Path) -> None:
        src = Path(backup_path)
        if not src.is_file():
            raise FileNotFoundError(f"Backup file not found: {src}")
        with self._lock:
            src_conn = sqlite3.connect(str(src))
            try:
                res = src_conn.execute("PRAGMA quick_check;").fetchone()
                if not res or str(res[0]).lower() != "ok":
                    raise sqlite3.DatabaseError("Backup failed SQLite integrity check")
            finally:
                src_conn.close()
            shutil.copy2(str(src), str(self.db_path))
            for sfx in ("-wal", "-shm"):
                with contextlib.suppress(OSError):
                    Path(str(self.db_path) + sfx).unlink(missing_ok=True)
            self.apply_migrations()

    def _resolve_server_id_in_tx(
        self,
        conn: sqlite3.Connection,
        ident: ParsedIdentity,
        now_iso: str,
    ) -> str:
        full_sha = ident.canonical_sha256 or hashlib.sha256(ident.identity_id.encode("utf-8")).hexdigest()
        by_sha = conn.execute(
            "SELECT server_id FROM servers WHERE canonical_key_sha256 = ?;",
            (full_sha,),
        ).fetchone()
        if by_sha:
            return str(by_sha["server_id"])

        # Check if legacy_identity_id was previously registered and migrate its continuity safely
        if ident.legacy_identity_id:
            mig = conn.execute(
                "SELECT server_id FROM server_identity_migrations WHERE legacy_id = ?;",
                (ident.legacy_identity_id,),
            ).fetchone()
            if mig:
                return str(mig["server_id"])

            legacy_row = conn.execute(
                "SELECT server_id, protocol, port, subnet_key FROM servers WHERE server_id = ?;",
                (ident.legacy_identity_id,),
            ).fetchone()
            if (
                legacy_row
                and str(legacy_row["protocol"]) == ident.canonical_proto
                and int(legacy_row["port"]) == ident.port
                and str(legacy_row["subnet_key"]) == ident.subnet_key
            ):
                # Safe deterministic format upgrade of the exact same endpoint/protocol
                conn.execute(
                    "UPDATE servers SET canonical_key_sha256 = ? WHERE server_id = ?;",
                    (full_sha, ident.legacy_identity_id),
                )
                return str(ident.legacy_identity_id)

        candidate_id = ident.identity_id
        collision = conn.execute(
            "SELECT canonical_key_sha256 FROM servers WHERE server_id = ?;",
            (candidate_id,),
        ).fetchone()
        if collision and str(collision["canonical_key_sha256"]) != full_sha:
            # Handle truncated digest collision deterministically without merging distinct configs
            for width in (32, 40, 64):
                alt_id = full_sha[:width]
                chk = conn.execute("SELECT canonical_key_sha256 FROM servers WHERE server_id = ?;", (alt_id,)).fetchone()
                if not chk or str(chk["canonical_key_sha256"]) == full_sha:
                    candidate_id = alt_id
                    break

        masked_ep = mask_endpoint_host(ident.host)
        conn.execute(
            """
            INSERT INTO servers(
                server_id, canonical_key_sha256, protocol, masked_endpoint, port,
                subnet_key, first_seen, last_seen, current_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'DISCOVERED');
            """,
            (
                candidate_id,
                full_sha,
                ident.canonical_proto,
                masked_ep,
                ident.port,
                ident.subnet_key,
                now_iso,
                now_iso,
            ),
        )
        if ident.legacy_identity_id and ident.legacy_identity_id != candidate_id:
            conn.execute(
                """
                INSERT OR IGNORE INTO server_identity_migrations(legacy_id, server_id, reason, migrated_at)
                VALUES (?, ?, 'canonical_v2_upgrade', ?);
                """,
                (ident.legacy_identity_id, candidate_id, now_iso),
            )
        conn.execute(
            """
            INSERT INTO server_events(server_id, event_at, epoch_sec, event_type, previous_status, new_status, detail)
            VALUES (?, ?, ?, 'DISCOVERED', '', 'DISCOVERED', ?);
            """,
            (candidate_id, now_iso, parse_iso_epoch(now_iso), f"proto={ident.canonical_proto}"),
        )
        return candidate_id

    def resolve_server_id(self, uri_or_ident: str | ParsedIdentity, *, now_iso: str = "") -> str | None:
        ident = (
            uri_or_ident
            if isinstance(uri_or_ident, ParsedIdentity)
            else parse_identity(uri_or_ident, reject_private_hosts=True)
        )
        if ident is None:
            return None
        ts = now_iso or epoch_to_iso(int(datetime.now(timezone.utc).timestamp()))
        with self.tx() as conn:
            return self._resolve_server_id_in_tx(conn, ident, ts)

    def resolve_alias(self, any_server_id: str) -> str | None:
        sid = (any_server_id or "").strip().lower()
        if not sid:
            return None
        with self._lock:
            conn = self._connect()
            try:
                direct = conn.execute("SELECT server_id FROM servers WHERE server_id = ?;", (sid,)).fetchone()
                if direct:
                    return str(direct["server_id"])
                mig = conn.execute("SELECT server_id FROM server_identity_migrations WHERE legacy_id = ?;", (sid,)).fetchone()
                return str(mig["server_id"]) if mig else None
            finally:
                conn.close()

    def is_temporarily_suppressed(self, server_id: str, *, now_epoch: int | None = None) -> bool:
        now_e = now_epoch if now_epoch is not None else int(datetime.now(timezone.utc).timestamp())
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT suppressed_until_epoch FROM servers WHERE server_id = ?;",
                    (server_id,),
                ).fetchone()
                return bool(row and int(row["suppressed_until_epoch"] or 0) > now_e)
            finally:
                conn.close()

    def get_suppressed_ids(self, *, now_epoch: int | None = None) -> set[str]:
        now_e = now_epoch if now_epoch is not None else int(datetime.now(timezone.utc).timestamp())
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT server_id FROM servers WHERE suppressed_until_epoch > ?;",
                    (now_e,),
                ).fetchall()
                return {str(r["server_id"]) for r in rows}
            finally:
                conn.close()

    def bootstrap_from_node_history_json(self, json_path: Path, *, now_iso: str = "") -> int:
        """Import legacy `state/node_history.json` entries if `servers` table is currently empty."""
        if not json_path.is_file():
            return 0
        try:
            raw = json.loads(json_path.read_text(encoding="utf-8"))
        except Exception:
            return 0
        nodes = raw.get("nodes", raw) if isinstance(raw, dict) else {}
        if not isinstance(nodes, dict) or not nodes:
            return 0

        ts = now_iso or epoch_to_iso(int(datetime.now(timezone.utc).timestamp()))
        imported = 0
        with self.tx() as conn:
            cnt = int(conn.execute("SELECT COUNT(*) FROM servers;").fetchone()[0])
            if cnt > 0:
                return 0
            for legacy_id, item in nodes.items():
                if not isinstance(item, dict) or len(str(legacy_id)) < 6:
                    continue
                lid = str(legacy_id).strip().lower()
                runs_seen = max(1, int(item.get("runs_seen", 1)))
                runs_alive = max(0, min(runs_seen, int(item.get("runs_alive", 0))))
                failed = max(0, runs_seen - runs_alive)
                consec_fail = int(item.get("consecutive_failures", 0))
                seen_at = str(item.get("last_seen_at") or ts)
                cc = str(item.get("exit_country") or "XX").upper()
                cc_src = str(item.get("country_source") or "unknown")
                lat = float(item.get("last_latency_ms", 0.0) or 0.0) or None
                spd = float(item.get("best_speed_kbps", 0.0) or 0.0) or None
                perf = float(item.get("last_performance_score", 0.0) or 0.0)
                rel = float(item.get("last_reliability_score", 0.0) or 0.0)
                status = "OPERATIONAL" if runs_alive > 0 and consec_fail == 0 else ("FAILED" if consec_fail > 0 else "DISCOVERED")
                sha_placeholder = hashlib.sha256(f"legacy:{lid}".encode("utf-8")).hexdigest()
                conn.execute(
                    """
                    INSERT OR IGNORE INTO servers(
                        server_id, canonical_key_sha256, protocol, masked_endpoint, port, subnet_key,
                        first_seen, last_seen, last_verified, current_status, uptime_percentage, uptime_kind,
                        total_test_count, successful_test_count, failed_test_count, failure_count,
                        average_latency, median_latency, download_speed, measurement_timestamp,
                        detected_country, country_confidence, consecutive_failures,
                        latest_composite_score, latest_performance_score, latest_reliability_score
                    ) VALUES (?, ?, 'unknown', 'masked', 443, 'legacy', ?, ?, ?, ?, ?, 'ESTIMATED',
                              ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        lid,
                        sha_placeholder,
                        seen_at,
                        seen_at,
                        seen_at if runs_alive > 0 else "",
                        status,
                        round((runs_alive / runs_seen) * 100.0, 2),
                        runs_seen,
                        runs_alive,
                        failed,
                        failed,
                        lat,
                        lat,
                        spd,
                        seen_at,
                        cc,
                        cc_src,
                        consec_fail,
                        perf,
                        perf,
                        rel,
                    ),
                )
                imported += 1
        return imported

    def record_Sightings_batch(
        self,
        sightings: Sequence[tuple[ParsedIdentity, Sequence[tuple[str, str]]]],
        *,
        observed_at: str,
    ) -> dict[str, str]:
        """
        Register discovered servers and their `(source_id, source_url_or_handle)` provenance
        in a single atomic transaction. Returns `{ident.identity_id: resolved_server_id}`.
        """
        resolved_map: dict[str, str] = {}
        with self.tx() as conn:
            for ident, src_pairs in sightings:
                sid = self._resolve_server_id_in_tx(conn, ident, observed_at)
                resolved_map[ident.identity_id] = sid
                for src_name, src_url in src_pairs:
                    op_id = extract_source_operator_id(src_name, url_or_handle=src_url)
                    conn.execute(
                        """
                        INSERT INTO server_sources(server_id, source_id, operator_id, first_source_seen, last_source_seen, sightings_count)
                        VALUES (?, ?, ?, ?, ?, 1)
                        ON CONFLICT(server_id, source_id) DO UPDATE SET
                            operator_id = excluded.operator_id,
                            last_source_seen = excluded.last_source_seen,
                            sightings_count = server_sources.sightings_count + 1;
                        """,
                        (sid, src_name, op_id, observed_at, observed_at),
                    )
                agg = conn.execute(
                    """
                    SELECT COUNT(*) AS src_cnt,
                           COUNT(DISTINCT operator_id) AS indep_cnt,
                           MIN(first_source_seen) AS first_s,
                           MAX(last_source_seen) AS last_s
                    FROM server_sources WHERE server_id = ?;
                    """,
                    (sid,),
                ).fetchone()
                conn.execute(
                    """
                    UPDATE servers
                    SET last_seen = ?,
                        source_count = ?,
                        independent_source_count = ?,
                        first_source_seen = COALESCE(NULLIF(first_source_seen, ''), ?),
                        last_source_seen = ?
                    WHERE server_id = ?;
                    """,
                    (
                        observed_at,
                        int(agg["src_cnt"] or 0),
                        int(agg["indep_cnt"] or 0),
                        str(agg["first_s"] or observed_at),
                        str(agg["last_s"] or observed_at),
                        sid,
                    ),
                )
        return resolved_map

    def record_measurement(
        self,
        ident: ParsedIdentity,
        *,
        measured_at: str,
        ok: bool,
        raw_error: str = "",
        latency_ms: float | None = None,
        median_latency_ms: float | None = None,
        p95_latency_ms: float | None = None,
        jitter_ms: float | None = None,
        packet_loss_pct: float = 0.0,
        download_kbps: float | None = None,
        upload_kbps: float | None = None,
        exit_country: str = "XX",
        country_source: str = "unknown",
        exit_ip: str = "",
        composite_score: float = 0.0,
        performance_score: float = 0.0,
        reliability_score: float = 0.0,
        security_assessment: str = "Unknown",
        privacy_assessment: str = "Unverified",
        risk_level: str = "UNKNOWN",
        sources: Sequence[tuple[str, str]] = (),
    ) -> str:
        """Append one time-series measurement and update aggregates & operational state atomically."""
        epoch_s = parse_iso_epoch(measured_at)
        masked_exit = mask_exit_ip_to_subnet(exit_ip)
        fail_cat = "" if ok else classify_failure_reason(raw_error, packet_loss_pct=packet_loss_pct)

        with self.tx() as conn:
            sid = self._resolve_server_id_in_tx(conn, ident, measured_at)

            if sources:
                for src_name, src_url in sources:
                    op_id = extract_source_operator_id(src_name, url_or_handle=src_url)
                    conn.execute(
                        """
                        INSERT INTO server_sources(server_id, source_id, operator_id, first_source_seen, last_source_seen, sightings_count)
                        VALUES (?, ?, ?, ?, ?, 1)
                        ON CONFLICT(server_id, source_id) DO UPDATE SET
                            operator_id = excluded.operator_id,
                            last_source_seen = excluded.last_source_seen,
                            sightings_count = server_sources.sightings_count + 1;
                        """,
                        (sid, src_name, op_id, measured_at, measured_at),
                    )

            conn.execute(
                """
                INSERT INTO server_measurements(
                    server_id, measured_at, epoch_sec, ok, failure_category,
                    latency_ms, median_latency_ms, p95_latency_ms, jitter_ms,
                    packet_loss_pct, download_kbps, upload_kbps,
                    exit_country, country_source, masked_exit_subnet
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    sid,
                    measured_at,
                    epoch_s,
                    1 if ok else 0,
                    fail_cat,
                    round(latency_ms, 2) if latency_ms and latency_ms > 0 else None,
                    round(median_latency_ms, 2) if median_latency_ms and median_latency_ms > 0 else None,
                    round(p95_latency_ms, 2) if p95_latency_ms and p95_latency_ms > 0 else None,
                    round(jitter_ms, 2) if jitter_ms is not None and jitter_ms >= 0 else None,
                    round(max(0.0, packet_loss_pct), 2),
                    round(download_kbps, 2) if download_kbps and download_kbps > 0 else None,
                    round(upload_kbps, 2) if upload_kbps and upload_kbps > 0 else None,
                    (exit_country or "XX").upper(),
                    country_source or "unknown",
                    masked_exit,
                ),
            )

            self._rollup_server_in_tx(
                conn,
                sid=sid,
                measured_at=measured_at,
                epoch_s=epoch_s,
                ok=ok,
                fail_cat=fail_cat,
                exit_country=(exit_country or "XX").upper(),
                country_source=country_source or "unknown",
                masked_exit=masked_exit,
                composite_score=composite_score,
                performance_score=performance_score,
                reliability_score=reliability_score,
                security_assessment=security_assessment,
                privacy_assessment=privacy_assessment,
                risk_level=risk_level,
            )
            return sid

    def _rollup_server_in_tx(
        self,
        conn: sqlite3.Connection,
        *,
        sid: str,
        measured_at: str,
        epoch_s: int,
        ok: bool,
        fail_cat: str,
        exit_country: str,
        country_source: str,
        masked_exit: str,
        composite_score: float,
        performance_score: float,
        reliability_score: float,
        security_assessment: str,
        privacy_assessment: str,
        risk_level: str,
    ) -> None:
        cur = conn.execute("SELECT * FROM servers WHERE server_id = ?;", (sid,)).fetchone()
        prev_status = str(cur["current_status"])
        total_tests = int(cur["total_test_count"]) + 1
        succ_tests = int(cur["successful_test_count"]) + (1 if ok else 0)
        fail_tests = int(cur["failed_test_count"]) + (0 if ok else 1)
        prev_consec_fail = int(cur["consecutive_failures"])
        prev_consec_succ = int(cur["consecutive_successes"])
        failed_since = cur["failed_since_epoch"]

        reasons: dict[str, int] = {}
        with contextlib.suppress(Exception):
            reasons = json.loads(str(cur["failure_reasons_json"] or "{}"))

        recovery_sec: float | None = None
        suppressed_until = int(cur["suppressed_until_epoch"] or 0)
        suppression_reason = str(cur["suppression_reason"] or "")

        if ok:
            consec_fail = 0
            consec_succ = prev_consec_succ + 1
            suppressed_until = 0
            suppression_reason = ""
            if failed_since is not None and int(failed_since) > 0 and epoch_s >= int(failed_since):
                recovery_sec = float(epoch_s - int(failed_since))
            new_failed_since = None
            new_status = "UNSTABLE" if (reliability_score > 0 and reliability_score < 50.0) else "OPERATIONAL"
        else:
            consec_fail = prev_consec_fail + 1
            consec_succ = 0
            new_failed_since = int(failed_since) if failed_since is not None else epoch_s
            if fail_cat:
                reasons[fail_cat] = int(reasons.get(fail_cat, 0)) + 1
            if consec_fail >= self.suppression.consecutive_failure_threshold:
                exp = consec_fail - self.suppression.consecutive_failure_threshold
                backoff = min(self.suppression.max_suppress_sec, self.suppression.base_suppress_sec * (2 ** min(exp, 5)))
                suppressed_until = epoch_s + int(backoff)
                suppression_reason = f"{fail_cat}:{consec_fail}_consecutive_failures"
                new_status = "SUPPRESSED"
            elif prev_consec_succ > 0 and consec_fail == 1:
                # Never permanently delete or condemn a server on a single transient failure
                new_status = "UNSTABLE"
            else:
                new_status = "FAILED"

        if prev_status != new_status or recovery_sec is not None or not ok:
            ev_type = (
                "RECOVERED" if recovery_sec is not None else
                ("SUPPRESSED" if new_status == "SUPPRESSED" else ("FAILURE" if not ok else "STATUS_CHANGE"))
            )
            conn.execute(
                """
                INSERT INTO server_events(
                    server_id, event_at, epoch_sec, event_type, previous_status, new_status,
                    failure_category, recovery_sec, detail
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    sid,
                    measured_at,
                    epoch_s,
                    ev_type,
                    prev_status,
                    new_status,
                    fail_cat,
                    recovery_sec,
                    suppression_reason if new_status == "SUPPRESSED" else "",
                ),
            )

        # Country history when verified or changed
        if exit_country and exit_country != "XX":
            conf = "HIGH" if country_source == "exit_trace" else ("MEDIUM" if country_source == "tld_hint" else "LOW")
            prev_cc = str(cur["detected_country"] or "XX")
            if prev_cc != exit_country or country_source == "exit_trace":
                conn.execute(
                    """
                    INSERT INTO server_country_history(
                        server_id, observed_at, epoch_sec, country_code, country_source, confidence, masked_exit_subnet
                    ) VALUES (?, ?, ?, ?, ?, ?, ?);
                    """,
                    (sid, measured_at, epoch_s, exit_country, country_source, conf, masked_exit),
                )

        # Recompute recent 30-day window statistics & windowed uptime
        win_start = epoch_s - (30 * 86_400)
        obs_rows = conn.execute(
            """
            SELECT epoch_sec, ok, latency_ms, median_latency_ms, jitter_ms, packet_loss_pct, download_kbps, upload_kbps
            FROM server_measurements
            WHERE server_id = ? AND epoch_sec >= ?
            ORDER BY epoch_sec ASC;
            """,
            (sid, win_start),
        ).fetchall()
        run_epochs = [
            int(r[0])
            for r in conn.execute("SELECT epoch_sec FROM pipeline_runs WHERE epoch_sec >= ? ORDER BY epoch_sec ASC;", (win_start,)).fetchall()
        ]
        first_seen_epoch = parse_iso_epoch(str(cur["first_seen"]))
        uptime_pct, uptime_kind, _ = compute_windowed_uptime(
            [(int(r["epoch_sec"]), int(r["ok"])) for r in obs_rows],
            window_start_epoch=win_start,
            window_end_epoch=epoch_s,
            first_seen_epoch=first_seen_epoch,
            pipeline_run_epochs=run_epochs,
        )

        lats = sorted(
            float(r["median_latency_ms"] or r["latency_ms"])
            for r in obs_rows
            if int(r["ok"]) == 1 and (r["median_latency_ms"] or r["latency_ms"])
        )
        jits = [float(r["jitter_ms"]) for r in obs_rows if int(r["ok"]) == 1 and r["jitter_ms"] is not None]
        losses = [float(r["packet_loss_pct"]) for r in obs_rows if r["packet_loss_pct"] is not None]
        dls = [float(r["download_kbps"]) for r in obs_rows if int(r["ok"]) == 1 and r["download_kbps"]]
        uls = [float(r["upload_kbps"]) for r in obs_rows if int(r["ok"]) == 1 and r["upload_kbps"]]

        avg_lat = round(statistics.mean(lats), 2) if lats else None
        med_lat = round(statistics.median(lats), 2) if lats else None
        p95_lat = compute_percentile(lats, 95.0)
        avg_jit = round(statistics.mean(jits), 2) if jits else None
        avg_loss = round(statistics.mean(losses), 2) if losses else None
        avg_dl = round(statistics.mean(dls), 2) if dls else None
        avg_ul = round(statistics.mean(uls), 2) if uls else None

        rec_rows = conn.execute(
            "SELECT recovery_sec FROM server_events WHERE server_id = ? AND recovery_sec IS NOT NULL;",
            (sid,),
        ).fetchall()
        avg_rec = round(statistics.mean(float(r[0]) for r in rec_rows), 2) if rec_rows else None

        src_agg = conn.execute(
            "SELECT COUNT(*) AS sc, COUNT(DISTINCT operator_id) AS ic FROM server_sources WHERE server_id = ?;",
            (sid,),
        ).fetchone()

        eff_cc = exit_country if exit_country != "XX" else str(cur["detected_country"] or "XX")
        eff_cc_conf = (
            "exit_trace"
            if country_source == "exit_trace"
            else (str(cur["country_confidence"]) if cur["country_confidence"] == "exit_trace" else country_source)
        )

        conn.execute(
            """
            UPDATE servers
            SET last_seen = ?,
                last_verified = CASE WHEN ? = 1 THEN ? ELSE last_verified END,
                current_status = ?,
                uptime_percentage = ?,
                uptime_kind = ?,
                total_test_count = ?,
                successful_test_count = ?,
                failed_test_count = ?,
                failure_count = ?,
                failure_reasons_json = ?,
                average_recovery_time = ?,
                average_latency = ?,
                median_latency = ?,
                p95_latency = ?,
                jitter = ?,
                packet_loss = ?,
                download_speed = COALESCE(?, download_speed),
                upload_speed = COALESCE(?, upload_speed),
                measurement_timestamp = ?,
                source_count = ?,
                independent_source_count = ?,
                detected_country = ?,
                country_confidence = ?,
                last_failure = CASE WHEN ? = 0 THEN ? ELSE last_failure END,
                last_success = CASE WHEN ? = 1 THEN ? ELSE last_success END,
                consecutive_failures = ?,
                consecutive_successes = ?,
                failed_since_epoch = ?,
                suppressed_until_epoch = ?,
                suppression_reason = ?,
                historical_availability = ?,
                latest_composite_score = CASE WHEN ? > 0 THEN ? ELSE latest_composite_score END,
                latest_performance_score = CASE WHEN ? > 0 THEN ? ELSE latest_performance_score END,
                latest_reliability_score = CASE WHEN ? > 0 THEN ? ELSE latest_reliability_score END,
                security_assessment = CASE WHEN ? != 'Unknown' THEN ? ELSE security_assessment END,
                privacy_assessment = ?,
                risk_level = CASE WHEN ? != 'UNKNOWN' THEN ? ELSE risk_level END
            WHERE server_id = ?;
            """,
            (
                measured_at,
                1 if ok else 0,
                measured_at,
                new_status,
                uptime_pct,
                uptime_kind,
                total_tests,
                succ_tests,
                fail_tests,
                fail_tests,
                json.dumps(reasons, ensure_ascii=False, sort_keys=True),
                avg_rec,
                avg_lat,
                med_lat,
                p95_lat,
                avg_jit,
                avg_loss,
                avg_dl,
                avg_ul,
                measured_at,
                int(src_agg["sc"] or 0),
                int(src_agg["ic"] or 0),
                eff_cc,
                eff_cc_conf,
                1 if ok else 0,
                measured_at,
                1 if ok else 0,
                measured_at,
                consec_fail,
                consec_succ,
                new_failed_since,
                suppressed_until,
                suppression_reason,
                uptime_pct,
                composite_score,
                round(composite_score, 2),
                performance_score,
                round(performance_score, 2),
                reliability_score,
                round(reliability_score, 2),
                security_assessment,
                security_assessment,
                privacy_assessment,
                risk_level,
                risk_level,
                sid,
            ),
        )

        if ok or composite_score > 0:
            conn.execute(
                """
                INSERT INTO server_score_history(
                    server_id, scored_at, epoch_sec, composite_score, performance_score,
                    reliability_score, uptime_pct, uptime_kind
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    sid,
                    measured_at,
                    epoch_s,
                    round(composite_score, 2),
                    round(performance_score, 2),
                    round(reliability_score, 2),
                    uptime_pct,
                    uptime_kind,
                ),
            )

        # Update hourly & daily rollups for this bucket
        dt_utc = datetime.fromtimestamp(epoch_s, tz=timezone.utc)
        hour_bucket = dt_utc.strftime("%Y-%m-%dT%H:00:00Z")
        hour_epoch = int(dt_utc.replace(minute=0, second=0, microsecond=0).timestamp())
        day_bucket = dt_utc.strftime("%Y-%m-%d")
        day_epoch = int(dt_utc.replace(hour=0, minute=0, second=0, microsecond=0).timestamp())

        self._recompute_bucket_aggregate_in_tx(
            conn,
            table="server_hourly_aggregates",
            bucket_col="hour_bucket",
            epoch_col="hour_epoch",
            sid=sid,
            bucket_val=hour_bucket,
            bucket_epoch=hour_epoch,
            span_sec=3_600,
            include_recovery=False,
        )
        self._recompute_bucket_aggregate_in_tx(
            conn,
            table="server_daily_aggregates",
            bucket_col="day_bucket",
            epoch_col="day_epoch",
            sid=sid,
            bucket_val=day_bucket,
            bucket_epoch=day_epoch,
            span_sec=86_400,
            include_recovery=True,
        )

    @staticmethod
    def _recompute_bucket_aggregate_in_tx(
        conn: sqlite3.Connection,
        *,
        table: str,
        bucket_col: str,
        epoch_col: str,
        sid: str,
        bucket_val: str,
        bucket_epoch: int,
        span_sec: int,
        include_recovery: bool,
    ) -> None:
        rows = conn.execute(
            """
            SELECT ok, latency_ms, median_latency_ms, jitter_ms, packet_loss_pct, download_kbps, upload_kbps
            FROM server_measurements
            WHERE server_id = ? AND epoch_sec >= ? AND epoch_sec < ?;
            """,
            (sid, bucket_epoch, bucket_epoch + span_sec),
        ).fetchall()
        if not rows:
            return
        t_cnt = len(rows)
        s_cnt = sum(1 for r in rows if int(r["ok"]) == 1)
        lats = sorted(
            float(r["median_latency_ms"] or r["latency_ms"])
            for r in rows
            if int(r["ok"]) == 1 and (r["median_latency_ms"] or r["latency_ms"])
        )
        jits = [float(r["jitter_ms"]) for r in rows if int(r["ok"]) == 1 and r["jitter_ms"] is not None]
        losses = [float(r["packet_loss_pct"]) for r in rows if r["packet_loss_pct"] is not None]
        dls = [float(r["download_kbps"]) for r in rows if int(r["ok"]) == 1 and r["download_kbps"]]
        uls = [float(r["upload_kbps"]) for r in rows if int(r["ok"]) == 1 and r["upload_kbps"]]

        avg_lat = round(statistics.mean(lats), 2) if lats else None
        med_lat = round(statistics.median(lats), 2) if lats else None
        p95_lat = compute_percentile(lats, 95.0)
        avg_jit = round(statistics.mean(jits), 2) if jits else None
        avg_loss = round(statistics.mean(losses), 2) if losses else None
        avg_dl = round(statistics.mean(dls), 2) if dls else None
        peak_dl = round(max(dls), 2) if dls else None
        avg_ul = round(statistics.mean(uls), 2) if uls else None
        obs_up = round((s_cnt / t_cnt) * 100.0, 2)

        if include_recovery:
            rec_rows = conn.execute(
                """
                SELECT recovery_sec FROM server_events
                WHERE server_id = ? AND epoch_sec >= ? AND epoch_sec < ? AND recovery_sec IS NOT NULL;
                """,
                (sid, bucket_epoch, bucket_epoch + span_sec),
            ).fetchall()
            avg_rec = round(statistics.mean(float(r[0]) for r in rec_rows), 2) if rec_rows else None
            conn.execute(
                f"""
                INSERT INTO {table}(
                    server_id, {bucket_col}, {epoch_col}, test_count, success_count,
                    avg_latency_ms, median_latency_ms, p95_latency_ms, avg_jitter_ms,
                    avg_packet_loss_pct, avg_download_kbps, peak_download_kbps, avg_upload_kbps,
                    observed_uptime_pct, avg_recovery_sec
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(server_id, {bucket_col}) DO UPDATE SET
                    test_count = excluded.test_count,
                    success_count = excluded.success_count,
                    avg_latency_ms = excluded.avg_latency_ms,
                    median_latency_ms = excluded.median_latency_ms,
                    p95_latency_ms = excluded.p95_latency_ms,
                    avg_jitter_ms = excluded.avg_jitter_ms,
                    avg_packet_loss_pct = excluded.avg_packet_loss_pct,
                    avg_download_kbps = excluded.avg_download_kbps,
                    peak_download_kbps = excluded.peak_download_kbps,
                    avg_upload_kbps = excluded.avg_upload_kbps,
                    observed_uptime_pct = excluded.observed_uptime_pct,
                    avg_recovery_sec = excluded.avg_recovery_sec;
                """,
                (
                    sid, bucket_val, bucket_epoch, t_cnt, s_cnt,
                    avg_lat, med_lat, p95_lat, avg_jit, avg_loss,
                    avg_dl, peak_dl, avg_ul, obs_up, avg_rec,
                ),
            )
        else:
            conn.execute(
                f"""
                INSERT INTO {table}(
                    server_id, {bucket_col}, {epoch_col}, test_count, success_count,
                    avg_latency_ms, median_latency_ms, p95_latency_ms, avg_jitter_ms,
                    avg_packet_loss_pct, avg_download_kbps, peak_download_kbps, avg_upload_kbps,
                    observed_uptime_pct
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(server_id, {bucket_col}) DO UPDATE SET
                    test_count = excluded.test_count,
                    success_count = excluded.success_count,
                    avg_latency_ms = excluded.avg_latency_ms,
                    median_latency_ms = excluded.median_latency_ms,
                    p95_latency_ms = excluded.p95_latency_ms,
                    avg_jitter_ms = excluded.avg_jitter_ms,
                    avg_packet_loss_pct = excluded.avg_packet_loss_pct,
                    avg_download_kbps = excluded.avg_download_kbps,
                    peak_download_kbps = excluded.peak_download_kbps,
                    avg_upload_kbps = excluded.avg_upload_kbps,
                    observed_uptime_pct = excluded.observed_uptime_pct;
                """,
                (
                    sid, bucket_val, bucket_epoch, t_cnt, s_cnt,
                    avg_lat, med_lat, p95_lat, avg_jit, avg_loss,
                    avg_dl, peak_dl, avg_ul, obs_up,
                ),
            )

    def record_pipeline_run_and_sources(
        self,
        *,
        run_at: str,
        tested_count: int,
        alive_count: int,
        degraded_mode: bool,
        source_records: Sequence[dict[str, Any]],
    ) -> None:
        epoch_s = parse_iso_epoch(run_at)
        with self.tx() as conn:
            conn.execute(
                """
                INSERT INTO pipeline_runs(run_at, epoch_sec, tested_count, alive_count, degraded_mode)
                VALUES (?, ?, ?, ?, ?);
                """,
                (run_at, epoch_s, tested_count, alive_count, 1 if degraded_mode else 0),
            )

            seen_operators: set[str] = set()
            for srec in source_records:
                src_id = str(srec.get("name") or srec.get("source_id") or "").strip()
                if not src_id:
                    continue
                kind = str(srec.get("kind") or "github")
                url_h = str(srec.get("url_or_handle") or "")
                op_id = extract_source_operator_id(src_id, kind=kind, url_or_handle=url_h)
                is_primary_for_op = 1 if op_id not in seen_operators else 0
                seen_operators.add(op_id)

                state = str(srec.get("state") or "active")
                available = 1 if state in ("active", "degraded") and int(srec.get("consecutive_failures", 0)) == 0 else 0
                raw_cnt = max(0, int(srec.get("raw_count", 0)))
                valid_cnt = max(0, int(srec.get("valid_count", 0)))
                uniq_cnt = max(0, int(srec.get("unique_identities", valid_cnt)))
                excl_cnt = max(0, int(srec.get("exclusive_identities", 0)))
                alive_cnt = max(0, int(srec.get("alive_count", 0)))
                invalid_cnt = max(0, int(srec.get("invalid_configs", 0)))
                susp_cnt = max(0, int(srec.get("suspicious_configs", 0)))
                dup_rate = round(float(srec.get("overlap_ratio", 0.0) or 0.0), 4)
                total_runs = max(1, int(srec.get("total_runs", 1)))
                succ_runs = max(0, int(srec.get("successful_runs", 1 if available else 0)))
                fail_rate = round(1.0 - (succ_runs / total_runs), 4)
                validity_rate = round(valid_cnt / max(1, raw_cnt + invalid_cnt), 4) if (raw_cnt + invalid_cnt) > 0 else 0.0

                # Source Confidence Score [0..100]: rewards uptime, validity, alive yield & exclusive configs; penalizes suspicious/duplicates
                avail_comp = (succ_runs / total_runs) * 35.0
                valid_comp = validity_rate * 25.0
                yield_comp = min(25.0, math.log1p(alive_cnt) * 6.5) if alive_cnt > 0 else 0.0
                excl_comp = (1.0 - dup_rate) * 15.0 if uniq_cnt > 0 else 0.0
                susp_pen = min(60.0, susp_cnt * 6.0) + (40.0 if state == "quarantined" else 0.0)
                conf_score = round(max(0.0, min(100.0, avail_comp + valid_comp + yield_comp + excl_comp - susp_pen)), 1)
                conf_tier = (
                    "QUARANTINED" if state == "quarantined" else
                    "HIGH" if conf_score >= 72.0 else
                    "MEDIUM" if conf_score >= 45.0 else
                    "LOW" if total_runs >= 2 else "UNVERIFIED"
                )

                conn.execute(
                    """
                    INSERT INTO source_history(
                        source_id, operator_id, kind, recorded_at, epoch_sec, available,
                        discovered_configs, unique_valid_servers, alive_servers,
                        duplicate_rate, failure_rate, validity_rate, confidence_score
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        src_id, op_id, kind, run_at, epoch_s, available,
                        raw_cnt, uniq_cnt, alive_cnt, dup_rate, fail_rate, validity_rate, conf_score,
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO sources_catalog(
                        source_id, operator_id, kind, state, available, discovered_configs,
                        unique_valid_servers, exclusive_servers, alive_servers,
                        historical_validity_rate, duplicate_rate, failure_rate,
                        confidence_score, confidence_tier, independent_operator, last_updated
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(source_id) DO UPDATE SET
                        operator_id = excluded.operator_id,
                        kind = excluded.kind,
                        state = excluded.state,
                        available = excluded.available,
                        discovered_configs = excluded.discovered_configs,
                        unique_valid_servers = excluded.unique_valid_servers,
                        exclusive_servers = excluded.exclusive_servers,
                        alive_servers = excluded.alive_servers,
                        historical_validity_rate = excluded.historical_validity_rate,
                        duplicate_rate = excluded.duplicate_rate,
                        failure_rate = excluded.failure_rate,
                        confidence_score = excluded.confidence_score,
                        confidence_tier = excluded.confidence_tier,
                        independent_operator = excluded.independent_operator,
                        last_updated = excluded.last_updated;
                    """,
                    (
                        src_id, op_id, kind, state, available, raw_cnt,
                        uniq_cnt, excl_cnt, alive_cnt, validity_rate, dup_rate, fail_rate,
                        conf_score, conf_tier, is_primary_for_op, run_at,
                    ),
                )

    def apply_retention_and_retirement(self, *, now_iso: str = "") -> dict[str, int]:
        """Prune expired time-series rows per configurable RetentionPolicy without losing daily history."""
        now_e = parse_iso_epoch(now_iso) if now_iso else int(datetime.now(timezone.utc).timestamp())
        cut_detailed = now_e - (self.retention.detailed_days * 86_400)
        cut_hourly = now_e - (self.retention.hourly_days * 86_400)
        cut_daily = now_e - (self.retention.daily_days * 86_400)
        cut_retire_iso = epoch_to_iso(now_e - (self.retention.retire_unseen_days * 86_400))

        with self.tx() as conn:
            d_meas = conn.execute("DELETE FROM server_measurements WHERE epoch_sec < ?;", (cut_detailed,)).rowcount
            d_score = conn.execute("DELETE FROM server_score_history WHERE epoch_sec < ?;", (cut_hourly,)).rowcount
            d_src = conn.execute("DELETE FROM source_history WHERE epoch_sec < ?;", (cut_hourly,)).rowcount
            d_hour = conn.execute("DELETE FROM server_hourly_aggregates WHERE hour_epoch < ?;", (cut_hourly,)).rowcount
            d_day = conn.execute("DELETE FROM server_daily_aggregates WHERE day_epoch < ?;", (cut_daily,)).rowcount
            d_ev = conn.execute("DELETE FROM server_events WHERE epoch_sec < ?;", (cut_daily,)).rowcount
            retired = conn.execute(
                """
                UPDATE servers SET current_status = 'RETIRED'
                WHERE last_seen < ? AND current_status NOT IN ('RETIRED', 'QUARANTINED');
                """,
                (cut_retire_iso,),
            ).rowcount
        return {
            "pruned_measurements": d_meas,
            "pruned_scores": d_score,
            "pruned_source_history": d_src,
            "pruned_hourly_aggregates": d_hour,
            "pruned_daily_aggregates": d_day,
            "pruned_events": d_ev,
            "retired_servers": retired,
        }

    def get_server_window_analytics(
        self,
        server_id: str,
        *,
        now_iso: str = "",
        windows: Sequence[tuple[str, int]] = (("24h", 86_400), ("7d", 7 * 86_400), ("30d", 30 * 86_400), ("90d", 90 * 86_400)),
    ) -> dict[str, dict[str, Any]]:
        """Compute reproducible multi-window performance analytics (24h, 7d, 30d, 90d) for a server."""
        now_e = parse_iso_epoch(now_iso) if now_iso else int(datetime.now(timezone.utc).timestamp())
        out: dict[str, dict[str, Any]] = {}
        with self._lock:
            conn = self._connect()
            try:
                srv = conn.execute("SELECT first_seen, current_status, last_seen FROM servers WHERE server_id = ?;", (server_id,)).fetchone()
                if not srv:
                    return {}
                first_seen_e = parse_iso_epoch(str(srv["first_seen"]))
                retired_e = parse_iso_epoch(str(srv["last_seen"])) if str(srv["current_status"]) == "RETIRED" else None

                for label, span_sec in windows:
                    w_start = now_e - span_sec
                    rows = conn.execute(
                        """
                        SELECT epoch_sec, ok, latency_ms, median_latency_ms, jitter_ms,
                               packet_loss_pct, download_kbps, upload_kbps
                        FROM server_measurements
                        WHERE server_id = ? AND epoch_sec >= ? AND epoch_sec <= ?
                        ORDER BY epoch_sec ASC;
                        """,
                        (server_id, w_start, now_e),
                    ).fetchall()

                    if rows:
                        runs = [
                            int(r[0])
                            for r in conn.execute(
                                "SELECT epoch_sec FROM pipeline_runs WHERE epoch_sec >= ? AND epoch_sec <= ? ORDER BY epoch_sec ASC;",
                                (w_start, now_e),
                            ).fetchall()
                        ]
                        up_pct, up_kind, cov = compute_windowed_uptime(
                            [(int(r["epoch_sec"]), int(r["ok"])) for r in rows],
                            window_start_epoch=w_start,
                            window_end_epoch=now_e,
                            first_seen_epoch=first_seen_e,
                            retired_epoch=retired_e,
                            pipeline_run_epochs=runs,
                        )
                        lats = sorted(
                            float(r["median_latency_ms"] or r["latency_ms"])
                            for r in rows
                            if int(r["ok"]) == 1 and (r["median_latency_ms"] or r["latency_ms"])
                        )
                        jits = [float(r["jitter_ms"]) for r in rows if int(r["ok"]) == 1 and r["jitter_ms"] is not None]
                        losses = [float(r["packet_loss_pct"]) for r in rows if r["packet_loss_pct"] is not None]
                        dls = [float(r["download_kbps"]) for r in rows if int(r["ok"]) == 1 and r["download_kbps"]]
                        uls = [float(r["upload_kbps"]) for r in rows if int(r["ok"]) == 1 and r["upload_kbps"]]
                        succ_cnt = sum(1 for r in rows if int(r["ok"]) == 1)
                        rec_rows = conn.execute(
                            "SELECT recovery_sec FROM server_events WHERE server_id = ? AND epoch_sec >= ? AND recovery_sec IS NOT NULL;",
                            (server_id, w_start),
                        ).fetchall()
                        out[label] = {
                            "sample_count": len(rows),
                            "uptime_pct": up_pct,
                            "uptime_kind": up_kind,
                            "coverage_ratio": cov,
                            "connection_success_rate": round(succ_cnt / len(rows), 4),
                            "average_latency_ms": round(statistics.mean(lats), 2) if lats else None,
                            "median_latency_ms": round(statistics.median(lats), 2) if lats else None,
                            "p95_latency_ms": compute_percentile(lats, 95.0),
                            "jitter_ms": round(statistics.mean(jits), 2) if jits else None,
                            "packet_loss_pct": round(statistics.mean(losses), 2) if losses else None,
                            "average_download_kbps": round(statistics.mean(dls), 2) if dls else None,
                            "peak_download_kbps": round(max(dls), 2) if dls else None,
                            "average_upload_kbps": round(statistics.mean(uls), 2) if uls else None,
                            "average_recovery_sec": round(statistics.mean(float(r[0]) for r in rec_rows), 2) if rec_rows else None,
                        }
                    else:
                        # Fallback to hourly/daily rollups for 30d/90d windows after detailed retention pruning
                        agg_rows = conn.execute(
                            """
                            SELECT test_count, success_count, avg_latency_ms, median_latency_ms, p95_latency_ms,
                                   avg_jitter_ms, avg_packet_loss_pct, avg_download_kbps, peak_download_kbps,
                                   avg_upload_kbps, avg_recovery_sec
                            FROM server_daily_aggregates
                            WHERE server_id = ? AND day_epoch >= ?;
                            """,
                            (server_id, w_start),
                        ).fetchall()
                        if not agg_rows:
                            out[label] = {
                                "sample_count": 0,
                                "uptime_pct": None,
                                "uptime_kind": "UNKNOWN",
                                "coverage_ratio": 0.0,
                                "connection_success_rate": None,
                                "average_latency_ms": None,
                                "median_latency_ms": None,
                                "p95_latency_ms": None,
                                "jitter_ms": None,
                                "packet_loss_pct": None,
                                "average_download_kbps": None,
                                "peak_download_kbps": None,
                                "average_upload_kbps": None,
                                "average_recovery_sec": None,
                            }
                        else:
                            tot_t = sum(int(r["test_count"]) for r in agg_rows)
                            tot_s = sum(int(r["success_count"]) for r in agg_rows)
                            lats_a = [float(r["avg_latency_ms"]) for r in agg_rows if r["avg_latency_ms"] is not None]
                            meds_a = [float(r["median_latency_ms"]) for r in agg_rows if r["median_latency_ms"] is not None]
                            p95s_a = [float(r["p95_latency_ms"]) for r in agg_rows if r["p95_latency_ms"] is not None]
                            jits_a = [float(r["avg_jitter_ms"]) for r in agg_rows if r["avg_jitter_ms"] is not None]
                            loss_a = [float(r["avg_packet_loss_pct"]) for r in agg_rows if r["avg_packet_loss_pct"] is not None]
                            dls_a = [float(r["avg_download_kbps"]) for r in agg_rows if r["avg_download_kbps"] is not None]
                            peaks_a = [float(r["peak_download_kbps"]) for r in agg_rows if r["peak_download_kbps"] is not None]
                            uls_a = [float(r["avg_upload_kbps"]) for r in agg_rows if r["avg_upload_kbps"] is not None]
                            recs_a = [float(r["avg_recovery_sec"]) for r in agg_rows if r["avg_recovery_sec"] is not None]
                            out[label] = {
                                "sample_count": tot_t,
                                "uptime_pct": round((tot_s / max(1, tot_t)) * 100.0, 2) if tot_t > 0 else None,
                                "uptime_kind": "ESTIMATED",
                                "coverage_ratio": round(min(1.0, len(agg_rows) / max(1.0, span_sec / 86_400.0)), 4),
                                "connection_success_rate": round(tot_s / max(1, tot_t), 4) if tot_t > 0 else None,
                                "average_latency_ms": round(statistics.mean(lats_a), 2) if lats_a else None,
                                "median_latency_ms": round(statistics.median(meds_a), 2) if meds_a else None,
                                "p95_latency_ms": round(max(p95s_a), 2) if p95s_a else None,
                                "jitter_ms": round(statistics.mean(jits_a), 2) if jits_a else None,
                                "packet_loss_pct": round(statistics.mean(loss_a), 2) if loss_a else None,
                                "average_download_kbps": round(statistics.mean(dls_a), 2) if dls_a else None,
                                "peak_download_kbps": round(max(peaks_a), 2) if peaks_a else None,
                                "average_upload_kbps": round(statistics.mean(uls_a), 2) if uls_a else None,
                                "average_recovery_sec": round(statistics.mean(recs_a), 2) if recs_a else None,
                            }
                return out
            finally:
                conn.close()

    def get_server_detail(self, server_id: str, *, now_iso: str = "") -> dict[str, Any] | None:
        resolved = self.resolve_alias(server_id)
        if not resolved:
            return None
        with self._lock:
            conn = self._connect()
            try:
                srv = conn.execute("SELECT * FROM servers WHERE server_id = ?;", (resolved,)).fetchone()
                if not srv:
                    return None
                sources = [
                    dict(r)
                    for r in conn.execute(
                        "SELECT source_id, operator_id, first_source_seen, last_source_seen, sightings_count FROM server_sources WHERE server_id = ? ORDER BY sightings_count DESC;",
                        (resolved,),
                    ).fetchall()
                ]
                countries = [
                    dict(r)
                    for r in conn.execute(
                        "SELECT observed_at, country_code, country_source, confidence, masked_exit_subnet FROM server_country_history WHERE server_id = ? ORDER BY epoch_sec DESC LIMIT 20;",
                        (resolved,),
                    ).fetchall()
                ]
                scores = [
                    dict(r)
                    for r in conn.execute(
                        "SELECT scored_at, composite_score, performance_score, reliability_score, uptime_pct, uptime_kind FROM server_score_history WHERE server_id = ? ORDER BY epoch_sec DESC LIMIT 48;",
                        (resolved,),
                    ).fetchall()
                ]
                events = [
                    dict(r)
                    for r in conn.execute(
                        "SELECT event_at, event_type, previous_status, new_status, failure_category, recovery_sec, detail FROM server_events WHERE server_id = ? ORDER BY epoch_sec DESC LIMIT 30;",
                        (resolved,),
                    ).fetchall()
                ]
                recent_meas = [
                    dict(r)
                    for r in conn.execute(
                        """
                        SELECT measured_at, ok, failure_category, latency_ms, median_latency_ms,
                               p95_latency_ms, jitter_ms, packet_loss_pct, download_kbps, upload_kbps, exit_country
                        FROM server_measurements
                        WHERE server_id = ?
                        ORDER BY epoch_sec DESC LIMIT 48;
                        """,
                        (resolved,),
                    ).fetchall()
                ]
                d = dict(srv)
                d.pop("canonical_key_sha256", None)
                d["failure_reasons"] = json.loads(str(d.pop("failure_reasons_json", "{}") or "{}"))
                d["sources"] = sources
                d["country_history"] = countries
                d["score_history"] = scores
                d["failure_and_state_events"] = events
                d["recent_measurements"] = recent_meas
                d["windows"] = self.get_server_window_analytics(resolved, now_iso=now_iso)
                return d
            finally:
                conn.close()

    def export_public_historical_artifacts(
        self,
        out_dir: Path,
        *,
        generated_at: str = "",
        max_detailed_servers: int = 300,
    ) -> dict[str, Path]:
        """
        Atomically export Part 7 versioned, cache-friendly, secret-free JSON artifacts:
          - servers-current.json
          - servers-history.json
          - servers-performance.json
          - servers-statistics.json
          - countries-statistics.json
          - sources-statistics.json
        """
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        now_iso = generated_at or epoch_to_iso(int(datetime.now(timezone.utc).timestamp()))
        now_e = parse_iso_epoch(now_iso)

        def _atomic_write(target: Path, payload: dict[str, Any]) -> Path:
            tmp = target.with_name(target.name + ".tmp")
            tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            tmp.replace(target)
            return target

        with self._lock:
            conn = self._connect()
            try:
                status_counts_rows = conn.execute(
                    "SELECT current_status, COUNT(*) AS cnt FROM servers GROUP BY current_status;"
                ).fetchall()
                status_counts = {str(r["current_status"]): int(r["cnt"]) for r in status_counts_rows}
                total_discovered = sum(status_counts.values())
                newly_cutoff = epoch_to_iso(now_e - 86_400)
                newly_discovered = int(
                    conn.execute("SELECT COUNT(*) FROM servers WHERE first_seen >= ?;", (newly_cutoff,)).fetchone()[0]
                )
                removed_rotation = status_counts.get("SUPPRESSED", 0) + status_counts.get("RETIRED", 0) + status_counts.get("QUARANTINED", 0)

                op_rows = conn.execute(
                    """
                    SELECT server_id, protocol, masked_endpoint, port, first_seen, last_seen, last_verified,
                           current_status, uptime_percentage, uptime_kind, total_test_count, successful_test_count,
                           failed_test_count, failure_reasons_json, average_recovery_time, average_latency,
                           median_latency, p95_latency, jitter, packet_loss, download_speed, upload_speed,
                           measurement_timestamp, source_count, independent_source_count, detected_country,
                           country_confidence, consecutive_failures, latest_composite_score,
                           latest_performance_score, latest_reliability_score, security_assessment,
                           privacy_assessment, risk_level
                    FROM servers
                    WHERE current_status IN ('OPERATIONAL', 'UNSTABLE')
                    ORDER BY latest_composite_score DESC, COALESCE(median_latency, 99999) ASC
                    LIMIT 1000;
                    """
                ).fetchall()

                current_servers = []
                for r in op_rows:
                    item = dict(r)
                    item["failure_reasons"] = json.loads(str(item.pop("failure_reasons_json", "{}") or "{}"))
                    current_servers.append(item)

                # Top tracked servers with window analytics & compact sparkline series for Admin/Monitor drill-down
                tracked_rows = conn.execute(
                    """
                    SELECT server_id, protocol, masked_endpoint, first_seen, last_seen, current_status,
                           uptime_percentage, uptime_kind, detected_country, country_confidence,
                           source_count, independent_source_count, latest_composite_score, failure_reasons_json
                    FROM servers
                    ORDER BY CASE WHEN current_status = 'OPERATIONAL' THEN 0 WHEN current_status = 'UNSTABLE' THEN 1 ELSE 2 END,
                             latest_composite_score DESC, total_test_count DESC
                    LIMIT ?;
                    """,
                    (max_detailed_servers,),
                ).fetchall()

                history_items = []
                perf_items = []
                global_failures: dict[str, int] = {}

                for r in tracked_rows:
                    sid = str(r["server_id"])
                    reasons = json.loads(str(r["failure_reasons_json"] or "{}"))
                    for fk, fv in reasons.items():
                        global_failures[fk] = global_failures.get(fk, 0) + int(fv)

                    meas_series = [
                        {
                            "t": str(m["measured_at"]),
                            "ok": int(m["ok"]),
                            "lat": m["median_latency_ms"] or m["latency_ms"],
                            "dl_kbps": m["download_kbps"],
                            "loss": m["packet_loss_pct"],
                        }
                        for m in conn.execute(
                            """
                            SELECT measured_at, ok, latency_ms, median_latency_ms, download_kbps, packet_loss_pct
                            FROM server_measurements
                            WHERE server_id = ?
                            ORDER BY epoch_sec DESC LIMIT 24;
                            """,
                            (sid,),
                        ).fetchall()
                    ][::-1]

                    src_list = [
                        {"source": str(sr["source_id"]), "operator": str(sr["operator_id"]), "sightings": int(sr["sightings_count"])}
                        for sr in conn.execute(
                            "SELECT source_id, operator_id, sightings_count FROM server_sources WHERE server_id = ? ORDER BY sightings_count DESC LIMIT 12;",
                            (sid,),
                        ).fetchall()
                    ]
                    cc_hist = [
                        {"at": str(cr["observed_at"]), "country": str(cr["country_code"]), "confidence": str(cr["confidence"])}
                        for cr in conn.execute(
                            "SELECT observed_at, country_code, confidence FROM server_country_history WHERE server_id = ? ORDER BY epoch_sec DESC LIMIT 8;",
                            (sid,),
                        ).fetchall()
                    ]
                    sc_hist = [
                        {"at": str(sc["scored_at"]), "score": float(sc["composite_score"]), "uptime_pct": sc["uptime_pct"]}
                        for sc in conn.execute(
                            "SELECT scored_at, composite_score, uptime_pct FROM server_score_history WHERE server_id = ? ORDER BY epoch_sec DESC LIMIT 16;",
                            (sid,),
                        ).fetchall()
                    ][::-1]

                    history_items.append({
                        "server_id": sid,
                        "protocol": str(r["protocol"]),
                        "masked_endpoint": str(r["masked_endpoint"]),
                        "first_seen": str(r["first_seen"]),
                        "last_seen": str(r["last_seen"]),
                        "current_status": str(r["current_status"]),
                        "uptime_percentage": r["uptime_percentage"],
                        "uptime_kind": str(r["uptime_kind"]),
                        "detected_country": str(r["detected_country"]),
                        "country_confidence": str(r["country_confidence"]),
                        "source_count": int(r["source_count"]),
                        "independent_source_count": int(r["independent_source_count"]),
                        "failure_reasons": reasons,
                        "sources": src_list,
                        "country_history": cc_hist,
                        "score_history": sc_hist,
                        "series": meas_series,
                    })

                    perf_items.append({
                        "server_id": sid,
                        "protocol": str(r["protocol"]),
                        "detected_country": str(r["detected_country"]),
                        "current_status": str(r["current_status"]),
                        "latest_composite_score": float(r["latest_composite_score"]),
                        "windows": self.get_server_window_analytics(sid, now_iso=now_iso),
                    })

                # Daily fleet trend rollups
                fleet_daily = [
                    dict(dr)
                    for dr in conn.execute(
                        """
                        SELECT day_bucket,
                               COUNT(DISTINCT server_id) AS tracked_servers,
                               ROUND(AVG(avg_latency_ms), 2) AS avg_latency_ms,
                               ROUND(AVG(p95_latency_ms), 2) AS avg_p95_latency_ms,
                               ROUND(AVG(avg_download_kbps), 2) AS avg_download_kbps,
                               ROUND(MAX(peak_download_kbps), 2) AS peak_download_kbps,
                               ROUND(AVG(avg_packet_loss_pct), 2) AS avg_packet_loss_pct,
                               ROUND(AVG(observed_uptime_pct), 2) AS avg_observed_uptime_pct
                        FROM server_daily_aggregates
                        GROUP BY day_bucket
                        ORDER BY day_epoch DESC
                        LIMIT 90;
                        """
                    ).fetchall()
                ][::-1]

                country_stats = [
                    dict(cr)
                    for cr in conn.execute(
                        """
                        SELECT detected_country AS country,
                               COUNT(*) AS total_discovered,
                               SUM(CASE WHEN current_status = 'OPERATIONAL' THEN 1 ELSE 0 END) AS operational_servers,
                               SUM(CASE WHEN country_confidence = 'exit_trace' THEN 1 ELSE 0 END) AS verified_exit_servers,
                               ROUND(AVG(median_latency), 2) AS avg_median_latency_ms,
                               ROUND(AVG(p95_latency), 2) AS avg_p95_latency_ms,
                               ROUND(AVG(download_speed), 2) AS avg_download_kbps,
                               ROUND(AVG(uptime_percentage), 2) AS avg_uptime_pct,
                               ROUND(AVG(latest_composite_score), 2) AS avg_composite_score
                        FROM servers
                        GROUP BY detected_country
                        ORDER BY operational_servers DESC, total_discovered DESC;
                        """
                    ).fetchall()
                ]

                source_stats = [
                    dict(sr)
                    for sr in conn.execute(
                        """
                        SELECT source_id, operator_id, kind, state, available,
                               discovered_configs, unique_valid_servers, exclusive_servers,
                               alive_servers, historical_validity_rate, duplicate_rate,
                               failure_rate, confidence_score, confidence_tier,
                               independent_operator, last_updated
                        FROM sources_catalog
                        ORDER BY confidence_score DESC, alive_servers DESC;
                        """
                    ).fetchall()
                ]
                indep_operators = len({s["operator_id"] for s in source_stats if s.get("available")})
            finally:
                conn.close()

        written: dict[str, Path] = {}
        written["servers-current.json"] = _atomic_write(
            out / "servers-current.json",
            {
                "schema_version": EXPORT_SCHEMA_VERSION,
                "generated_at": now_iso,
                "count": len(current_servers),
                "servers": current_servers,
            },
        )
        written["servers-history.json"] = _atomic_write(
            out / "servers-history.json",
            {
                "schema_version": EXPORT_SCHEMA_VERSION,
                "generated_at": now_iso,
                "count": len(history_items),
                "servers": history_items,
            },
        )
        written["servers-performance.json"] = _atomic_write(
            out / "servers-performance.json",
            {
                "schema_version": EXPORT_SCHEMA_VERSION,
                "generated_at": now_iso,
                "windows_supported": ["24h", "7d", "30d", "90d"],
                "daily_fleet_trends": fleet_daily,
                "servers": perf_items,
            },
        )
        written["servers-statistics.json"] = _atomic_write(
            out / "servers-statistics.json",
            {
                "schema_version": EXPORT_SCHEMA_VERSION,
                "generated_at": now_iso,
                "overview": {
                    "total_discovered_servers": total_discovered,
                    "currently_operational_servers": status_counts.get("OPERATIONAL", 0),
                    "unstable_servers": status_counts.get("UNSTABLE", 0),
                    "failed_servers": status_counts.get("FAILED", 0),
                    "suppressed_servers": status_counts.get("SUPPRESSED", 0),
                    "quarantined_servers": status_counts.get("QUARANTINED", 0),
                    "retired_servers": status_counts.get("RETIRED", 0),
                    "newly_discovered_24h": newly_discovered,
                    "removed_from_active_rotation": removed_rotation,
                },
                "status_breakdown": status_counts,
                "failure_categories": global_failures,
                "daily_trends": fleet_daily,
            },
        )
        written["countries-statistics.json"] = _atomic_write(
            out / "countries-statistics.json",
            {
                "schema_version": EXPORT_SCHEMA_VERSION,
                "generated_at": now_iso,
                "total_countries": sum(1 for c in country_stats if c["country"] != "XX"),
                "countries": country_stats,
            },
        )
        written["sources-statistics.json"] = _atomic_write(
            out / "sources-statistics.json",
            {
                "schema_version": EXPORT_SCHEMA_VERSION,
                "generated_at": now_iso,
                "total_sources": len(source_stats),
                "independent_active_operators": indep_operators,
                "sources": source_stats,
            },
        )
        return written
