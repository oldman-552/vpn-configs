"""AI Performance Intelligence & Evidence-Backed Analytics Engine.

Strictly adheres to Master Specification Section 16:
- Analyzes ONLY real database metrics from the 21 enterprise tables.
- NEVER fabricates percentages or synthetic numbers; explicitly reports
  "INSUFFICIENT_DATA" when sample sizes are zero or below statistical threshold.
- Produces all 6 structured report types:
  1. DAILY_PERFORMANCE
  2. WEEKLY_ANALYTICS
  3. MONTHLY_EXECUTIVE
  4. SERVER_HEALTH
  5. APP_QUALITY
  6. USER_EXPERIENCE
- Every recommendation includes:
  problem_detected, supporting_data_evidence, affected_components,
  severity_level, confidence_level, recommended_technical_solution, priority_order.
- Read-only analytical engine: NEVER executes destructive changes automatically.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from statistics import mean, median
from typing import Any, Dict, List, Optional

from enterprise.database import EnterpriseDB, fmt_iso_utc


def _confidence_from_samples(n: int) -> str:
    if n >= 30:
        return "HIGH"
    if n >= 8:
        return "MEDIUM"
    return "LOW"


class AIIntelligenceEngine:
    def __init__(self, db: EnterpriseDB) -> None:
        self.db = db

    def generate_all_reports(self, now: Optional[datetime] = None) -> Dict[str, Any]:
        cur_dt = now or datetime.now(timezone.utc)
        ts = fmt_iso_utc(cur_dt)

        daily = self._window_metrics(cur_dt - timedelta(days=1), cur_dt, "DAILY_PERFORMANCE")
        weekly = self._window_metrics(cur_dt - timedelta(days=7), cur_dt, "WEEKLY_ANALYTICS")
        monthly = self._window_metrics(cur_dt - timedelta(days=30), cur_dt, "MONTHLY_EXECUTIVE")
        server_health = self._analyze_server_health(cur_dt)
        app_quality = self._analyze_app_quality(cur_dt)
        ux_report = self._analyze_user_experience(cur_dt)
        recommendations = self._build_recommendations(server_health, app_quality, ux_report, weekly)

        return {
            "generated_at": ts,
            "engine_mode": "EVIDENCE_BACKED_STATISTICAL_ANALYZER",
            "auto_destructive_actions_enabled": False,
            "reports": {
                "DAILY_PERFORMANCE": daily,
                "WEEKLY_ANALYTICS": weekly,
                "MONTHLY_EXECUTIVE": monthly,
                "SERVER_HEALTH": server_health,
                "APP_QUALITY": app_quality,
                "USER_EXPERIENCE": ux_report,
            },
            "recommendations": recommendations,
        }

    def _window_metrics(self, start_dt: datetime, end_dt: datetime, report_type: str) -> Dict[str, Any]:
        s_iso = fmt_iso_utc(start_dt)
        e_iso = fmt_iso_utc(end_dt)
        with self.db.tx() as conn:
            sessions = conn.execute(
                "SELECT * FROM user_sessions WHERE connection_start >= ? AND connection_start <= ?",
                (s_iso, e_iso),
            ).fetchall()
            speeds = conn.execute(
                "SELECT * FROM speed_tests WHERE tested_at >= ? AND tested_at <= ?",
                (s_iso, e_iso),
            ).fetchall()
            violations = conn.execute(
                "SELECT * FROM device_violations WHERE occurred_at >= ? AND occurred_at <= ?",
                (s_iso, e_iso),
            ).fetchall()
            trials = conn.execute(
                "SELECT * FROM trial_activations WHERE activated_at >= ? AND activated_at <= ?",
                (s_iso, e_iso),
            ).fetchall()
            logs = conn.execute(
                "SELECT event_type, COUNT(*) AS c FROM connection_logs WHERE logged_at >= ? AND logged_at <= ? GROUP BY event_type",
                (s_iso, e_iso),
            ).fetchall()

        dl_vals = [float(r["download_kbps"]) * 8.0 / 1024.0 for r in speeds if float(r["download_kbps"]) > 0]
        ping_vals = [int(r["ping_ms"]) for r in speeds if int(r["ping_ms"]) > 0]
        loss_vals = [float(r["packet_loss_pct"]) for r in speeds]

        peak_hours: Dict[str, int] = {}
        for s in sessions:
            hr = str(s["connection_start"])[11:13]
            if hr.isdigit():
                peak_hours[f"{hr}:00Z"] = peak_hours.get(f"{hr}:00Z", 0) + 1

        top_peak_hour = max(peak_hours.items(), key=lambda kv: kv[1])[0] if peak_hours else None

        return {
            "report_type": report_type,
            "window_start": s_iso,
            "window_end": e_iso,
            "data_sufficiency": "SUFFICIENT" if (len(sessions) + len(speeds)) > 0 else "INSUFFICIENT_DATA",
            "sessions_total": len(sessions),
            "speed_tests_sample_count": len(speeds),
            "median_download_mbps": round(median(dl_vals), 2) if dl_vals else None,
            "mean_ping_ms": round(mean(ping_vals), 1) if ping_vals else None,
            "mean_packet_loss_pct": round(mean(loss_vals), 2) if loss_vals else None,
            "trial_activations_count": len(trials),
            "trials_converted_count": sum(1 for t in trials if int(t["converted_to_paid"]) == 1),
            "device_violations_count": len(violations),
            "peak_congestion_hour_utc": top_peak_hour,
            "connection_events_breakdown": {r["event_type"]: int(r["c"]) for r in logs},
        }

    def _analyze_server_health(self, cur_dt: datetime) -> Dict[str, Any]:
        with self.db.tx() as conn:
            servers = conn.execute("SELECT * FROM servers").fetchall()

        if not servers:
            return {
                "report_type": "SERVER_HEALTH",
                "data_sufficiency": "INSUFFICIENT_DATA",
                "message": "No servers synchronized in database yet.",
                "total_servers": 0,
                "tier_distribution": {},
                "protocol_efficiency": {},
                "regional_performance": {},
                "degraded_servers": [],
            }

        tiers: Dict[str, int] = {}
        by_proto: Dict[str, List[float]] = {}
        by_country: Dict[str, List[int]] = {}
        degraded: List[Dict[str, Any]] = []

        for s in servers:
            tier = s["quality_tier"]
            tiers[tier] = tiers.get(tier, 0) + 1
            proto = s["protocol"]
            by_proto.setdefault(proto, []).append(float(s["quality_score"]))
            cc = s["country"] or "UN"
            if int(s["ping_ms"]) > 0:
                by_country.setdefault(cc, []).append(int(s["ping_ms"]))

            if tier in ("POOR", "OFFLINE") or float(s["packet_loss_pct"]) >= 10.0 or int(s["ping_ms"]) >= 650:
                degraded.append(
                    {
                        "server_id": s["id"],
                        "server_name": s["server_name"],
                        "protocol": proto,
                        "country": cc,
                        "ping_ms": int(s["ping_ms"]),
                        "packet_loss_pct": float(s["packet_loss_pct"]),
                        "quality_tier": tier,
                        "quality_score": float(s["quality_score"]),
                    }
                )

        proto_summary = {
            p: {"count": len(vals), "avg_quality_score": round(mean(vals), 2)}
            for p, vals in sorted(by_proto.items())
        }
        region_summary = {
            c: {"online_count": len(pings), "median_ping_ms": int(median(pings))}
            for c, pings in sorted(by_country.items())
        }

        return {
            "report_type": "SERVER_HEALTH",
            "data_sufficiency": "SUFFICIENT",
            "total_servers": len(servers),
            "online_servers": sum(1 for s in servers if s["status"] == "ONLINE"),
            "tier_distribution": tiers,
            "protocol_efficiency": proto_summary,
            "regional_performance": region_summary,
            "degraded_servers": degraded[:25],
        }

    def _analyze_app_quality(self, cur_dt: datetime) -> Dict[str, Any]:
        cutoff = fmt_iso_utc(cur_dt - timedelta(days=30))
        with self.db.tx() as conn:
            crashes = conn.execute("SELECT * FROM app_crashes WHERE occurred_at >= ?", (cutoff,)).fetchall()
            drop_logs = conn.execute(
                """SELECT error_code, COUNT(*) AS c
                   FROM connection_logs
                   WHERE logged_at >= ? AND severity IN ('ERROR', 'CRITICAL', 'WARNING')
                   GROUP BY error_code""",
                (cutoff,),
            ).fetchall()

        if not crashes and not drop_logs:
            return {
                "report_type": "APP_QUALITY",
                "data_sufficiency": "INSUFFICIENT_DATA",
                "message": "Zero crash or error logs recorded in the last 30 days.",
                "total_crashes_30d": 0,
                "anr_count_30d": 0,
                "crashes_by_version": {},
                "crashes_by_device_model": {},
                "error_codes": {},
            }

        by_ver: Dict[str, int] = {}
        by_model: Dict[str, int] = {}
        anrs = 0
        for c in crashes:
            v = c["app_version"] or "unknown"
            m = c["device_model"] or "unknown"
            by_ver[v] = by_ver.get(v, 0) + 1
            by_model[m] = by_model.get(m, 0) + 1
            if c["issue_type"] == "ANR":
                anrs += 1

        return {
            "report_type": "APP_QUALITY",
            "data_sufficiency": "SUFFICIENT",
            "total_crashes_30d": len(crashes),
            "anr_count_30d": anrs,
            "crashes_by_version": by_ver,
            "crashes_by_device_model": by_model,
            "error_codes": {(r["error_code"] or "UNSPECIFIED"): int(r["c"]) for r in drop_logs},
        }

    def _analyze_user_experience(self, cur_dt: datetime) -> Dict[str, Any]:
        with self.db.tx() as conn:
            users_by_status = conn.execute(
                "SELECT account_status, COUNT(*) AS c FROM users GROUP BY account_status"
            ).fetchall()
            sub_types = conn.execute(
                "SELECT subscription_type, COUNT(*) AS c FROM users GROUP BY subscription_type"
            ).fetchall()
            net_tests = conn.execute("SELECT * FROM network_tests ORDER BY tested_at DESC LIMIT 200").fetchall()

        dns_leaks = sum(1 for n in net_tests if int(n["dns_leak"]) == 1)
        ip_leaks = sum(1 for n in net_tests if int(n["ip_leak"]) == 1)
        stabilities = [float(n["stability_score"]) for n in net_tests if float(n["stability_score"]) > 0]

        return {
            "report_type": "USER_EXPERIENCE",
            "data_sufficiency": "SUFFICIENT" if (users_by_status or net_tests) else "INSUFFICIENT_DATA",
            "accounts_by_status": {r["account_status"]: int(r["c"]) for r in users_by_status},
            "subscriptions_distribution": {r["subscription_type"]: int(r["c"]) for r in sub_types},
            "network_diagnostics_samples": len(net_tests),
            "dns_leak_incidents": dns_leaks,
            "ip_leak_incidents": ip_leaks,
            "mean_stability_score": round(mean(stabilities), 2) if stabilities else None,
        }

    def _build_recommendations(
        self,
        server_health: Dict[str, Any],
        app_quality: Dict[str, Any],
        ux_report: Dict[str, Any],
        weekly: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        recs: List[Dict[str, Any]] = []

        # 1. Degraded / Offline Servers
        degraded = server_health.get("degraded_servers", [])
        total_srv = int(server_health.get("total_servers", 0))
        if total_srv > 0 and degraded:
            ratio = (len(degraded) / total_srv) * 100.0
            sev = "HIGH" if ratio >= 35.0 else "MEDIUM"
            recs.append(
                {
                    "problem_detected": "Elevated latency, packet loss, or offline state on subset of VPN nodes",
                    "supporting_data_evidence": f"{len(degraded)} of {total_srv} tracked servers ({ratio:.1f}%) classified POOR/OFFLINE or ping >= 650ms",
                    "affected_components": [d["server_id"] for d in degraded[:10]],
                    "severity_level": sev,
                    "confidence_level": _confidence_from_samples(total_srv),
                    "recommended_technical_solution": "Demote POOR/OFFLINE servers in Smart Server Ranker and trigger fresh collector/tester sweep via GitHub Actions.",
                    "priority_order": 1 if sev == "HIGH" else 2,
                }
            )

        # 2. Protocol Efficiency Gap
        protos = server_health.get("protocol_efficiency", {})
        if len(protos) >= 2:
            ranked = sorted(protos.items(), key=lambda kv: kv[1]["avg_quality_score"], reverse=True)
            best_p, best_v = ranked[0]
            worst_p, worst_v = ranked[-1]
            gap = best_v["avg_quality_score"] - worst_v["avg_quality_score"]
            if gap >= 15.0:
                recs.append(
                    {
                        "problem_detected": f"Significant protocol quality divergence between {best_p} and {worst_p}",
                        "supporting_data_evidence": (
                            f"{best_p} avg quality score = {best_v['avg_quality_score']} (n={best_v['count']}) vs "
                            f"{worst_p} = {worst_v['avg_quality_score']} (n={worst_v['count']})"
                        ),
                        "affected_components": [f"protocol:{worst_p}"],
                        "severity_level": "MEDIUM",
                        "confidence_level": _confidence_from_samples(best_v["count"] + worst_v["count"]),
                        "recommended_technical_solution": f"Prefer {best_p} endpoints in Smart Auto-Connect while auditing {worst_p} handshake timeouts.",
                        "priority_order": 3,
                    }
                )

        # 3. App Crashes / ANRs
        crashes_30d = int(app_quality.get("total_crashes_30d", 0))
        anrs_30d = int(app_quality.get("anr_count_30d", 0))
        if crashes_30d > 0 or anrs_30d > 0:
            affected_vers = list(app_quality.get("crashes_by_version", {}).keys())
            recs.append(
                {
                    "problem_detected": "Client runtime crashes or ANR events recorded",
                    "supporting_data_evidence": f"{crashes_30d} crash(es) and {anrs_30d} ANR(s) recorded across versions {affected_vers}",
                    "affected_components": [f"app_version:{v}" for v in affected_vers],
                    "severity_level": "CRITICAL" if anrs_30d > 0 or crashes_30d >= 5 else "HIGH",
                    "confidence_level": _confidence_from_samples(crashes_30d),
                    "recommended_technical_solution": "Inspect stack traces in Crash Reports tab, isolate main-thread I/O, and publish signed patch APK via GitHub Releases.",
                    "priority_order": 1,
                }
            )

        # 4. DNS / IP Leak Incidents
        dns_leaks = int(ux_report.get("dns_leak_incidents", 0))
        ip_leaks = int(ux_report.get("ip_leak_incidents", 0))
        if dns_leaks > 0 or ip_leaks > 0:
            recs.append(
                {
                    "problem_detected": "DNS or IP leak flagged during client Network Diagnostics",
                    "supporting_data_evidence": f"DNS leaks={dns_leaks}, IP leaks={ip_leaks} out of {ux_report.get('network_diagnostics_samples', 0)} diagnostic runs",
                    "affected_components": ["BahrainVpnService:DNS_Routing"],
                    "severity_level": "CRITICAL",
                    "confidence_level": _confidence_from_samples(int(ux_report.get("network_diagnostics_samples", 0))),
                    "recommended_technical_solution": "Verify SingBox remote-dns Hijack-DNS rule and ensure IPv6 unreachable/routed policy inside VpnService.Builder.",
                    "priority_order": 1,
                }
            )

        # 5. Device Sharing Violations
        violations_7d = int(weekly.get("device_violations_count", 0))
        if violations_7d > 0:
            recs.append(
                {
                    "problem_detected": "Unauthorized multi-device credential sharing attempts detected",
                    "supporting_data_evidence": f"{violations_7d} device limit violation event(s) logged in the past 7 days",
                    "affected_components": ["DeviceLicenseGuard"],
                    "severity_level": "MEDIUM",
                    "confidence_level": "HIGH",
                    "recommended_technical_solution": "Review flagged accounts in Device Management and enable AUTO BLOCK ON DEVICE VIOLATION for repeat offenders.",
                    "priority_order": 2,
                }
            )

        if not recs:
            recs.append(
                {
                    "problem_detected": "Insufficient telemetry anomalies or clean baseline",
                    "supporting_data_evidence": (
                        f"Tracked servers={total_srv}, 30d crashes={crashes_30d}, 7d sessions={weekly.get('sessions_total', 0)}"
                    ),
                    "affected_components": ["platform_baseline"],
                    "severity_level": "INFO",
                    "confidence_level": "LOW" if total_srv == 0 else "MEDIUM",
                    "recommended_technical_solution": "Continue scheduled health checks and accumulate speed/diagnostic samples before tuning thresholds.",
                    "priority_order": 5,
                }
            )

        recs.sort(key=lambda r: int(r["priority_order"]))
        for idx, rec in enumerate(recs, start=1):
            rec["priority_order"] = idx
        return recs
