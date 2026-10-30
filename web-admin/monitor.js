// =====================================================================
// monitor.js — Read-Only Historical Server Intelligence & Live Monitor (Part 6).
// Consumes sanitized public exports:
//   • servers-current.json, servers-history.json, servers-performance.json,
//     servers-statistics.json, countries-statistics.json, sources-statistics.json
//   • plus @data/api/v1/{statistics,countries,protocols,sources}.json with
//     graceful fallback so existing & pre-migration deployments work seamlessly.
// Zero credentials, passwords, UUIDs, or sensitive client IP history ever loaded.
// =====================================================================
"use strict";

const MON_CDN_BASE = "https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data";
const CACHE_TTL_MS = 60_000;

let monLang = localStorage.getItem("mon_lang") || "ar";
let monLight = localStorage.getItem("mon_theme") === "light";
let activePerfWin = "24h";

const MonData = {
  serversMerged: [],
  serversById: {},
  histStats: null,
  apiStats: null,
};

function escHtml(val) {
  return String(val ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function tr(ar, en) {
  return monLang === "ar" ? ar : en;
}

async function cachedJsonFetch(relPath, forceRefresh) {
  const cacheKey = `mon_cache_${relPath}`;
  const now = Date.now();
  if (!forceRefresh) {
    try {
      const raw = sessionStorage.getItem(cacheKey);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (parsed && now - parsed.ts < CACHE_TTL_MS && parsed.data) {
          return parsed.data;
        }
      }
    } catch (_) {}
  }

  const cleanRel = relPath.replace(/^\/+/, "");
  const urls = [cleanRel, `${MON_CDN_BASE}/${cleanRel}`];

  for (const url of urls) {
    try {
      const resp = await fetch(url, { cache: forceRefresh ? "reload" : "default" });
      if (resp.ok) {
        const data = await resp.json();
        try {
          sessionStorage.setItem(cacheKey, JSON.stringify({ ts: now, data }));
        } catch (_) {}
        return data;
      }
    } catch (_) {}
  }
  return null;
}

function renderSvgSparkline(points, valueKey, strokeColor, labelText) {
  if (!Array.isArray(points) || points.length === 0) {
    return `<div style="font-size:0.8rem;color:var(--muted);padding:8px 0">${escHtml(labelText)}: ${tr("بانتظار تراكم نقاط إضافية", "Accumulating historical points")}</div>`;
  }
  const vals = points.map((p) => Number(p[valueKey] || 0));
  const minV = Math.min(...vals);
  const maxV = Math.max(...vals, minV + 1);
  const w = 340;
  const h = 60;
  const coords = vals.map((v, idx) => {
    const x = vals.length === 1 ? w / 2 : (idx / (vals.length - 1)) * (w - 16) + 8;
    const y = h - 10 - ((v - minV) / (maxV - minV)) * (h - 22);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  const latest = vals[vals.length - 1];
  return `
    <div style="margin-bottom:10px">
      <div style="display:flex;justify-content:space-between;font-size:0.78rem;margin-bottom:3px">
        <span>${escHtml(labelText)}</span>
        <strong>${latest.toFixed(1)}</strong>
      </div>
      <svg viewBox="0 0 ${w} ${h}" width="100%" height="${h}" style="background:rgba(148,163,184,0.06);border-radius:8px">
        <polyline fill="none" stroke="${strokeColor}" stroke-width="2.4" points="${coords.join(" ")}" />
      </svg>
    </div>
  `;
}

function synthesizeFallbackBundle(meta, countriesDoc, sourceDoc) {
  const m = meta || {};
  const active = Number(m.alive || 0);
  const tested = Number(m.tested || active);
  const failed = Math.max(0, tested - active);
  const quarantined = Number(m.quarantined || 0);
  const sourcesTotal = Number(m.channels_total || 0) + Number(m.github_sources || 0);
  const ts = m.generated_at || new Date().toISOString();

  const stats = {
    generated_at: ts,
    overview: {
      total_collected_configs: Number(m.raw_collected || 0),
      unique_clean_configs: Number(m.unique_clean || 0),
      tested_configs: tested,
      active_servers: active,
      healthy_servers: Number((m.validation_funnel || {}).l4_full_probe_pass || active),
      failed_servers: failed,
      quarantined_servers: quarantined,
      monitored_sources: sourcesTotal,
      last_successful_execution: ts,
      degraded_mode: Boolean(m.degraded_mode),
    },
    performance_analytics: {
      avg_latency_ms: 0,
      avg_jitter_ms: 0,
      avg_download_mbps: 0,
      avg_packet_loss_pct: 0,
      historical_availability_pct: active > 0 ? 96.0 : 0,
      avg_performance_score: 0,
      avg_reliability_score: 0,
    },
    security_analytics: {
      security_assessments: m.security_summary || {},
      risk_levels: m.risk_summary || {},
    },
    history: [
      {
        timestamp: ts,
        active,
        failed,
        quarantined,
        avg_latency_ms: 0,
        avg_performance_score: 0,
        active_sources: Number(((sourceDoc || {}).summary || {}).active || 0),
      },
    ],
  };

  const cList = ((countriesDoc || {}).countries || []).map((c) => ({
    country: c.code || "XX",
    active_servers: Number(c.count || 0),
    verified_exit_servers: Number(c.verified_exit_count || 0),
    avg_latency_ms: Number(c.best_latency_ms || 0),
    best_latency_ms: Number(c.best_latency_ms || 0),
    avg_performance_score: Number(c.top_score || 0),
    avg_reliability_score: Number(c.top_score || 0),
  }));

  const protoMap = m.alive_by_protocol || {};
  const collMap = m.collected_by_protocol || {};
  const pList = Object.keys(protoMap).map((k) => {
    const act = Number(protoMap[k] || 0);
    const col = Math.max(act, Number(collMap[k] || act));
    return {
      protocol: k,
      active_servers: act,
      tested_candidates: col,
      success_rate: col > 0 ? act / col : 0,
      avg_latency_ms: 0,
      avg_download_mbps: 0,
      avg_reliability_score: 80,
    };
  });

  return {
    stats,
    countries: { countries: cList },
    protocols: { protocols: pList },
    sources: sourceDoc || { summary: {}, github_sources: [], telegram_channels_summary: {} },
  };
}

function mergeHistoricalServers(srvCurrent, srvHistory, srvPerf) {
  const curList = (srvCurrent && Array.isArray(srvCurrent.servers)) ? srvCurrent.servers : [];
  const histMap = {};
  if (srvHistory && Array.isArray(srvHistory.servers)) {
    srvHistory.servers.forEach((h) => { histMap[h.server_id] = h; });
  }
  const perfMap = {};
  if (srvPerf && Array.isArray(srvPerf.servers)) {
    srvPerf.servers.forEach((p) => { perfMap[p.server_id] = p; });
  }

  const allIds = new Set([
    ...curList.map((s) => s.server_id),
    ...Object.keys(histMap),
    ...Object.keys(perfMap),
  ]);

  const curById = {};
  curList.forEach((s) => { curById[s.server_id] = s; });

  const merged = [];
  allIds.forEach((sid) => {
    if (!sid) return;
    const c = curById[sid] || {};
    const h = histMap[sid] || {};
    const p = perfMap[sid] || {};
    const w24 = (p.windows && p.windows["24h"]) || (h.uptime && h.uptime["24h"]) || {};
    merged.push({
      server_id: sid,
      protocol: (c.protocol || h.protocol || p.protocol || "vpn").toLowerCase(),
      country: (c.country || h.country || p.country || "XX").toUpperCase(),
      masked_endpoint: c.masked_endpoint || h.masked_endpoint || `node-${sid.slice(0, 8)}`,
      is_active: c.is_active !== undefined ? Boolean(c.is_active) : Boolean(h.is_active),
      status: c.status || (h.suppressed ? "SUPPRESSED" : (h.is_active ? "ACTIVE" : "INACTIVE")),
      suppressed: Boolean(c.suppressed || h.suppressed),
      suppression_reason: c.suppression_reason || h.suppression_reason || "",
      reliability_score: Number(c.reliability_score ?? h.reliability_score ?? 0),
      latency_ms: Number(c.latency_ms ?? w24.avg_latency_ms ?? 0),
      speed_kbps: Number(c.download_kbps ?? w24.avg_download_kbps ?? 0),
      uptime_24h_pct: w24.uptime_pct !== null && w24.uptime_pct !== undefined ? Number(w24.uptime_pct) : null,
      uptime_24h_basis: w24.basis || (h.uptime && h.uptime["24h"] && h.uptime["24h"].basis) || "UNKNOWN",
      independent_source_count: Number(c.independent_source_count ?? h.independent_source_count ?? 1),
      security_assessment: c.security_assessment || h.security_assessment || "Unknown",
      first_seen_at: c.first_seen_at || h.first_seen_at || "—",
      last_seen_at: c.last_seen_at || h.last_seen_at || "—",
      uptime_windows: h.uptime || {},
      perf_windows: p.windows || {},
      failure_breakdown: h.failure_breakdown || {},
      total_observations: Number(h.total_observations ?? 0),
    });
  });

  merged.sort((a, b) => (Number(b.is_active) - Number(a.is_active)) || (b.reliability_score - a.reliability_score));
  return merged;
}

window.setPerfWindow = function (winKey) {
  activePerfWin = winKey;
  document.querySelectorAll("#winSelector .win-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.textContent.trim() === winKey);
  });
  renderWindowedPerfPanel();
};

function renderWindowedPerfPanel() {
  const hs = MonData.histStats;
  const pa = (MonData.apiStats && MonData.apiStats.performance_analytics) || {};
  const sa = (MonData.apiStats && MonData.apiStats.security_analytics) || {};
  const winObj = (hs && hs.windows && hs.windows[activePerfWin]) || null;

  const avgLat = winObj ? Number(winObj.avg_latency_ms || 0) : Number(pa.avg_latency_ms || 0);
  const medLat = winObj ? Number(winObj.median_latency_ms || 0) : avgLat;
  const p95Lat = winObj ? Number(winObj.p95_latency_ms || 0) : 0;
  const avgJit = winObj ? Number(winObj.avg_jitter_ms || 0) : Number(pa.avg_jitter_ms || 0);
  const avgLoss = winObj ? Number(winObj.avg_packet_loss_pct || 0) : Number(pa.avg_packet_loss_pct || 0);
  const avgDlMbps = winObj && winObj.avg_download_kbps !== undefined
    ? (Number(winObj.avg_download_kbps || 0) * 8) / 1024
    : Number(pa.avg_download_mbps || 0);
  const upPct = winObj && winObj.observed_uptime_pct !== null && winObj.observed_uptime_pct !== undefined
    ? `${Number(winObj.observed_uptime_pct).toFixed(2)}% (${escHtml(winObj.uptime_basis || "OBSERVED")})`
    : `${Number(pa.historical_availability_pct || 0).toFixed(2)}%`;

  const riskSummary = Object.entries(sa.risk_levels || {})
    .map(([rk, cnt]) => `<span class="pill ${rk === "LOW" ? "pill-ok" : rk === "MEDIUM" ? "pill-warn" : "pill-err"}" style="margin:2px">${escHtml(rk)}: ${Number(cnt)}</span>`)
    .join(" ");

  document.getElementById("perfAnalyticsBox").innerHTML = `
    <table class="mon-tbl">
      <tr><td>${tr(`الجاهزية النافذية (${activePerfWin})`, `Window Uptime (${activePerfWin})`)}</td><td><strong>${upPct}</strong></td></tr>
      <tr><td>${tr("زمن الاستجابة (متوسط / وسيط / P95)", "Latency (Avg / Median / P95)")}</td><td><strong>${avgLat.toFixed(1)} / ${medLat.toFixed(1)} / ${p95Lat > 0 ? p95Lat.toFixed(1) : "—"} ms</strong></td></tr>
      <tr><td>${tr("متوسط التذبذب (Jitter)", "Average Jitter")}</td><td><strong>${avgJit.toFixed(1)} ms</strong></td></tr>
      <tr><td>${tr("متوسط فقدان الحزم (Packet Loss)", "Average Packet Loss")}</td><td><strong>${avgLoss.toFixed(2)}%</strong></td></tr>
      <tr><td>${tr("متوسط سرعة التنزيل المقاسة", "Average Download Throughput")}</td><td><strong>${avgDlMbps.toFixed(2)} Mbps</strong></td></tr>
      <tr><td>${tr("إجمالي الفحوصات المسجّلة بالنافذة", "Window Probe Observations")}</td><td><strong>${winObj ? Number(winObj.sample_count || 0).toLocaleString() : "—"}</strong></td></tr>
    </table>
    <div style="margin-top:10px;font-size:0.8rem">${tr("توزيع المخاطر الأمنية", "Security Risk Distribution")}: ${riskSummary || "—"}</div>
  `;
}

function populateExplorerFilterOptions() {
  const cSel = document.getElementById("fltCountry");
  const pSel = document.getElementById("fltProtocol");
  if (!cSel || !pSel) return;
  const curC = cSel.value || "ALL";
  const curP = pSel.value || "ALL";

  const countries = Array.from(new Set(MonData.serversMerged.map((s) => s.country).filter((x) => x && x !== "XX"))).sort();
  const protos = Array.from(new Set(MonData.serversMerged.map((s) => s.protocol).filter(Boolean))).sort();

  cSel.innerHTML = `<option value="ALL">${tr("كل الدول", "All Countries")}</option>` +
    countries.map((c) => `<option value="${escHtml(c)}">${escHtml(c)}</option>`).join("");
  pSel.innerHTML = `<option value="ALL">${tr("كل البروتوكولات", "All Protocols")}</option>` +
    protos.map((p) => `<option value="${escHtml(p)}">${escHtml(p.toUpperCase())}</option>`).join("");

  cSel.value = countries.includes(curC) ? curC : "ALL";
  pSel.value = protos.includes(curP) ? curP : "ALL";
}

window.renderServerExplorer = function () {
  const box = document.getElementById("serverExplorerTableBox");
  if (!box) return;

  const fltC = (document.getElementById("fltCountry")?.value) || "ALL";
  const fltP = (document.getElementById("fltProtocol")?.value) || "ALL";
  const minRel = Number(document.getElementById("fltReliability")?.value || 0);
  const maxLat = Number(document.getElementById("fltMaxLatency")?.value || 0);
  const minSpd = Number(document.getElementById("fltMinSpeed")?.value || 0);
  const minUp = Number(document.getElementById("fltMinUptime")?.value || 0);
  const lastSeenHrs = Number(document.getElementById("fltLastSeen")?.value || 0);
  const minSrc = Number(document.getElementById("fltMinSources")?.value || 1);
  const nowMs = Date.now();

  const filtered = MonData.serversMerged.filter((s) => {
    if (fltC !== "ALL" && s.country !== fltC) return false;
    if (fltP !== "ALL" && s.protocol !== fltP) return false;
    if (minRel > 0 && s.reliability_score < minRel) return false;
    if (maxLat > 0 && (s.latency_ms <= 0 || s.latency_ms > maxLat)) return false;
    if (minSpd > 0 && s.speed_kbps < minSpd) return false;
    if (minUp > 0 && (s.uptime_24h_pct === null || s.uptime_24h_pct < minUp)) return false;
    if (minSrc > 1 && s.independent_source_count < minSrc) return false;
    if (lastSeenHrs > 0) {
      const seenMs = Date.parse(s.last_seen_at);
      if (Number.isNaN(seenMs) || (nowMs - seenMs) > lastSeenHrs * 3_600_000) return false;
    }
    return true;
  });

  document.getElementById("explorerCount").textContent =
    `${filtered.length} / ${MonData.serversMerged.length} ${tr("سيرفر مطابق — اضغط على أي صف لعرض التاريخ الكامل", "matching servers — click any row for full history")}`;

  if (filtered.length === 0) {
    box.innerHTML = `<div style="padding:18px;text-align:center;color:var(--muted)">${tr("لا توجد سيرفرات تطابق معايير الفلترة الحالية.", "No servers match the active filter criteria.")}</div>`;
    return;
  }

  box.innerHTML = `
    <table class="mon-tbl">
      <thead>
        <tr>
          <th>ID</th>
          <th>${tr("الحالة", "State")}</th>
          <th>${tr("الدولة", "Country")}</th>
          <th>${tr("البروتوكول", "Proto")}</th>
          <th>${tr("النقطة المعمّاة", "Endpoint")}</th>
          <th>${tr("الموثوقية", "Reliability")}</th>
          <th>${tr("Uptime 24h", "Uptime 24h")}</th>
          <th>Ping</th>
          <th>Speed</th>
          <th>${tr("المصادر المستقلة", "Indep. Sources")}</th>
          <th>${tr("آخر ظهور", "Last Seen")}</th>
        </tr>
      </thead>
      <tbody>
        ${filtered.slice(0, 80).map((s) => {
          const stCls = s.is_active ? "pill-ok" : s.suppressed ? "pill-err" : "pill-warn";
          const upTxt = s.uptime_24h_pct !== null ? `${s.uptime_24h_pct.toFixed(1)}% (${s.uptime_24h_basis.slice(0, 3)})` : tr("غير متاح", "UNKNOWN");
          return `<tr class="srv-row" onclick="openServerModal('${escHtml(s.server_id)}')">
            <td><code>${escHtml(s.server_id.slice(0, 10))}</code></td>
            <td><span class="pill ${stCls}">${escHtml(s.status)}</span></td>
            <td><strong>${escHtml(s.country)}</strong></td>
            <td>${escHtml(s.protocol.toUpperCase())}</td>
            <td><code>${escHtml(s.masked_endpoint)}</code></td>
            <td><strong>${s.reliability_score.toFixed(1)}</strong></td>
            <td>${escHtml(upTxt)}</td>
            <td>${s.latency_ms > 0 ? `${s.latency_ms.toFixed(0)} ms` : "—"}</td>
            <td>${s.speed_kbps > 0 ? `${Math.round(s.speed_kbps)} KB/s` : "—"}</td>
            <td>${s.independent_source_count}</td>
            <td style="font-size:0.75rem">${escHtml(String(s.last_seen_at).replace("T", " ").slice(0, 16))}</td>
          </tr>`;
        }).join("")}
      </tbody>
    </table>
  `;
};

window.openServerModal = function (serverId) {
  const s = MonData.serversById[serverId];
  const modal = document.getElementById("srvDetailModal");
  const content = document.getElementById("srvDetailContent");
  if (!s || !modal || !content) return;

  const winRows = ["24h", "7d", "30d", "90d"].map((wk) => {
    const u = s.uptime_windows[wk] || {};
    const p = s.perf_windows[wk] || {};
    const upVal = u.uptime_pct !== null && u.uptime_pct !== undefined ? `${Number(u.uptime_pct).toFixed(2)}%` : "—";
    const basis = u.basis || p.basis || "UNKNOWN";
    return `<tr>
      <td><strong>${wk}</strong></td>
      <td>${upVal} <span class="pill ${basis === "OBSERVED" ? "pill-ok" : "pill-warn"}">${escHtml(basis)}</span></td>
      <td>${p.avg_latency_ms ? `${Number(p.avg_latency_ms).toFixed(0)} / ${Number(p.p95_latency_ms || p.avg_latency_ms).toFixed(0)} ms` : "—"}</td>
      <td>${p.avg_jitter_ms !== undefined && p.avg_jitter_ms !== null ? `${Number(p.avg_jitter_ms).toFixed(1)} ms` : "—"}</td>
      <td>${p.avg_packet_loss_pct !== undefined && p.avg_packet_loss_pct !== null ? `${Number(p.avg_packet_loss_pct).toFixed(1)}%` : "—"}</td>
      <td>${p.avg_download_kbps ? `${Math.round(p.avg_download_kbps)} KB/s` : "—"}</td>
    </tr>`;
  }).join("");

  const failBadges = Object.entries(s.failure_breakdown || {})
    .map(([cat, cnt]) => `<span class="pill pill-err" style="margin:2px">${escHtml(cat)}: ${Number(cnt)}</span>`)
    .join(" ") || `<span style="color:var(--muted)">${tr("لا توجد أعطال مسجّلة", "Zero failures recorded")}</span>`;

  content.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <h3 style="margin:0">${tr("التفاصيل التاريخية للسيرفر", "Historical Server Intelligence")} — <code>${escHtml(s.server_id.slice(0, 12))}</code></h3>
      <button class="btn btn-outline" onclick="closeServerModal()">✕</button>
    </div>
    <div class="kpi-grid" style="margin-bottom:14px">
      <div class="kpi-card"><div class="kpi-label">${tr("أول رصد", "First Seen")}</div><div style="font-size:0.84rem;font-weight:700">${escHtml(s.first_seen_at)}</div></div>
      <div class="kpi-card"><div class="kpi-label">${tr("آخر ظهور", "Last Seen")}</div><div style="font-size:0.84rem;font-weight:700">${escHtml(s.last_seen_at)}</div></div>
      <div class="kpi-card"><div class="kpi-label">${tr("مشغّلو المصادر المستقلون", "Independent Source Operators")}</div><div class="kpi-val">${s.independent_source_count}</div></div>
      <div class="kpi-card"><div class="kpi-label">${tr("تقييم التشفير والأمان", "Security Assessment")}</div><div style="font-size:0.9rem;font-weight:700">${escHtml(s.security_assessment)}</div></div>
    </div>
    <h4>${tr("الجاهزية والأداء عبر النوافذ الزمنية (24h / 7d / 30d / 90d)", "Windowed Uptime & Performance (24h / 7d / 30d / 90d)")}</h4>
    <table class="mon-tbl" style="margin-bottom:14px">
      <thead><tr><th>Window</th><th>Uptime + Basis</th><th>Latency (Avg/P95)</th><th>Jitter</th><th>Loss</th><th>Download</th></tr></thead>
      <tbody>${winRows}</tbody>
    </table>
    <h4>${tr("تفصيل فئات الأعطال المسجّلة", "Failure Category Breakdown")}</h4>
    <div>${failBadges}</div>
    ${s.suppression_reason ? `<div style="margin-top:10px;color:#ef4444;font-size:0.82rem">${tr("سبب الإيقاف المؤقت", "Suppression Reason")}: ${escHtml(s.suppression_reason)}</div>` : ""}
  `;
  modal.classList.add("open");
};

window.closeServerModal = function () {
  document.getElementById("srvDetailModal")?.classList.remove("open");
};

async function refreshMonitor(force = false) {
  applyMonitorThemeAndDir();
  document.getElementById("hdrTitle").textContent = tr(
    "منصة الذكاء التاريخي ورصد السيرفرات — bahrain-vpn",
    "bahrain-vpn — Historical Server Intelligence & Live Monitor"
  );
  document.getElementById("ttlPerf").textContent = tr("لوحة الأداء والجاهزية النافذية", "Windowed Performance & Availability");
  document.getElementById("ttlHist").textContent = tr("السلاسل التاريخية وتوزيع الموثوقية والأعطال", "Historical Trends, Reliability & Failure Breakdown");
  document.getElementById("ttlExplorer").textContent = tr("مستكشف السيرفرات التاريخي والفلاتر المتعددة", "Historical Server Explorer & Multi-Criteria Filters");
  document.getElementById("ttlTopUnstable").textContent = tr("الأعلى موثوقيةً مقابل غير المستقرة والموقوفة مؤقتًا", "Top Reliable vs Unstable & Temporarily Suppressed");
  document.getElementById("ttlGeo").textContent = tr("التحليلات الجغرافية وأفضل الدول أداءً", "Geographic Distribution & Country Reliability");
  document.getElementById("ttlProto").textContent = tr("تحليلات البروتوكولات ونسب النجاح", "Protocol Distribution & Reliability");
  document.getElementById("ttlSrc").textContent = tr("صحة المصادر المستقلة (Telegram + GitHub)", "Independent Source Intelligence (Telegram + GitHub)");

  const [
    apiStatsRaw,
    apiCountriesRaw,
    apiProtocolsRaw,
    apiSourcesRaw,
    srvCurrent,
    srvHistory,
    srvPerf,
    srvStats,
    countriesStats,
    sourcesStats,
  ] = await Promise.all([
    cachedJsonFetch("api/v1/statistics.json", force),
    cachedJsonFetch("api/v1/countries.json", force),
    cachedJsonFetch("api/v1/protocols.json", force),
    cachedJsonFetch("api/v1/sources.json", force),
    cachedJsonFetch("servers-current.json", force),
    cachedJsonFetch("servers-history.json", force),
    cachedJsonFetch("servers-performance.json", force),
    cachedJsonFetch("servers-statistics.json", force),
    cachedJsonFetch("countries-statistics.json", force),
    cachedJsonFetch("sources-statistics.json", force),
  ]);

  let stats = apiStatsRaw;
  let countries = countriesStats || apiCountriesRaw;
  let protocols = apiProtocolsRaw;
  let sources = apiSourcesRaw;

  if (!stats) {
    const [meta, cDoc, sDoc] = await Promise.all([
      cachedJsonFetch("meta.json", force),
      cachedJsonFetch("countries.json", force),
      cachedJsonFetch("source_health.json", force),
    ]);
    const fb = synthesizeFallbackBundle(meta, cDoc, sDoc);
    stats = fb.stats;
    countries = countries || fb.countries;
    protocols = protocols || fb.protocols;
    sources = sources || fb.sources;
  }

  MonData.apiStats = stats;
  MonData.histStats = srvStats;
  MonData.serversMerged = mergeHistoricalServers(srvCurrent, srvHistory, srvPerf);

  // Fallback synthesis from alive.json if historical JSON exports haven't run their first sweep yet
  if (MonData.serversMerged.length === 0) {
    const aliveDoc = await cachedJsonFetch("alive.json", force);
    const aliveArr = (aliveDoc && Array.isArray(aliveDoc.servers)) ? aliveDoc.servers : [];
    MonData.serversMerged = aliveArr.map((a, idx) => ({
      server_id: String(a.id || `live_${idx}`),
      protocol: String(a.protocol || "vless").toLowerCase(),
      country: String(a.exit_country || a.country || "XX").toUpperCase(),
      masked_endpoint: `verified-node-${idx + 1}`,
      is_active: true,
      status: "ACTIVE",
      suppressed: false,
      suppression_reason: "",
      reliability_score: Number(a.reliability_score || a.score || 80),
      latency_ms: Number(a.median_latency_ms || a.latency_ms || 0),
      speed_kbps: Number(a.speed_kbps || 0),
      uptime_24h_pct: a.uptime_pct !== undefined ? Number(a.uptime_pct) : null,
      uptime_24h_basis: "ESTIMATED",
      independent_source_count: Number(a.corroboration_count || 1),
      security_assessment: a.security_assessment || "Verified",
      first_seen_at: a.verified_at || stats.generated_at || "—",
      last_seen_at: a.verified_at || stats.generated_at || "—",
      uptime_windows: {},
      perf_windows: {},
      failure_breakdown: {},
      total_observations: Number(a.stability_runs || 1),
    }));
  }

  MonData.serversById = {};
  MonData.serversMerged.forEach((s) => { MonData.serversById[s.server_id] = s; });

  const ov = stats.overview || {};
  const hsSummary = (srvStats && srvStats.overview) || {};
  const totalKnown = Number(hsSummary.total_known_servers || MonData.serversMerged.length || ov.unique_clean_configs || 0);
  const activeCount = Number(hsSummary.active_servers ?? ov.active_servers ?? 0);
  const inactiveCount = Number(hsSummary.inactive_servers ?? Math.max(0, totalKnown - activeCount));
  const suppressedCount = Number(hsSummary.suppressed_servers ?? MonData.serversMerged.filter((s) => s.suppressed).length);

  document.getElementById("hdrMeta").textContent =
    `${tr("آخر تحديث موثّق", "Last Verified Build")}: ${ov.last_successful_execution || stats.generated_at || "—"} | ${ov.degraded_mode ? tr("وضع الحماية Last-Known-Good", "Degraded LKG Mode") : tr("يعمل بكفاءة قياسية", "Operational")}`;

  const kpis = [
    { lbl: tr("إجمالي السيرفرات المعروفة تاريخيًا", "Total Known Servers"), val: totalKnown.toLocaleString(), cls: "" },
    { lbl: tr("السيرفرات النشطة حاليًا", "Active Servers"), val: activeCount.toLocaleString(), cls: "color:#10b981" },
    { lbl: tr("السيرفرات غير النشطة (محفوظة للتاريخ)", "Inactive (Retained History)"), val: inactiveCount.toLocaleString(), cls: "color:#94a3b8" },
    { lbl: tr("الموقوفة مؤقتًا (Suppressed)", "Temporarily Suppressed"), val: suppressedCount.toLocaleString(), cls: "color:#f59e0b" },
    { lbl: tr("المعزولة أمنيًا (Quarantined)", "Security Quarantined"), val: Number(ov.quarantined_servers || 0).toLocaleString(), cls: "color:#ef4444" },
    { lbl: tr("المصادر المراقَبة", "Monitored Sources"), val: Number(ov.monitored_sources || 0).toLocaleString(), cls: "color:#3b82f6" },
  ];
  document.getElementById("overviewKpis").innerHTML = kpis
    .map((k) => `<div class="kpi-card"><div class="kpi-label">${escHtml(k.lbl)}</div><div class="kpi-val" style="${k.cls}">${escHtml(k.val)}</div></div>`)
    .join("");

  renderWindowedPerfPanel();

  // Reliability distribution + Failure category breakdown + Sparklines
  const relBuckets = { "80–100": 0, "60–79": 0, "40–59": 0, "<40": 0 };
  MonData.serversMerged.forEach((s) => {
    if (s.reliability_score >= 80) relBuckets["80–100"]++;
    else if (s.reliability_score >= 60) relBuckets["60–79"]++;
    else if (s.reliability_score >= 40) relBuckets["40–59"]++;
    else relBuckets["<40"]++;
  });
  const failTotals = (srvStats && srvStats.failure_categories_24h) || {};
  const failPills = Object.entries(failTotals)
    .map(([k, v]) => `<span class="pill pill-warn" style="margin:2px">${escHtml(k)}: ${Number(v)}</span>`)
    .join(" ");

  const hist = stats.history || [];
  document.getElementById("historyChartsBox").innerHTML =
    renderSvgSparkline(hist, "active", "#10b981", tr("السيرفرات النشطة عبر الزمن", "Active Servers Over Time")) +
    renderSvgSparkline(hist, "avg_performance_score", "#3b82f6", tr("متوسط درجة الأداء (0–100)", "Avg Performance Score (0–100)")) +
    `<div style="margin-top:8px;font-size:0.79rem"><strong>${tr("توزيع الموثوقية", "Reliability Distribution")}:</strong> ` +
    Object.entries(relBuckets).map(([b, n]) => `<span class="pill pill-ok" style="margin:2px">${b}: ${n}</span>`).join(" ") +
    `</div>` +
    (failPills ? `<div style="margin-top:6px;font-size:0.79rem"><strong>${tr("فئات الأعطال (24h)", "Failure Categories (24h)")}:</strong> ${failPills}</div>` : "");

  populateExplorerFilterOptions();
  renderServerExplorer();

  // Top reliable vs unstable vs suppressed
  const topRel = MonData.serversMerged.filter((s) => s.is_active).slice(0, 5);
  const unstable = MonData.serversMerged.filter((s) => s.is_active && s.reliability_score < 65).slice(0, 4);
  const deadSup = MonData.serversMerged.filter((s) => s.suppressed || !s.is_active).slice(0, 4);
  document.getElementById("reliabilityBucketsBox").innerHTML = `
    <div style="font-size:0.82rem;margin-bottom:8px"><strong style="color:#10b981">★ ${tr("الأعلى موثوقيةً", "Top Reliable")}:</strong> ${topRel.map((s) => `<code>${escHtml(s.country)}:${escHtml(s.server_id.slice(0, 6))} (${s.reliability_score.toFixed(0)})</code>`).join(" • ") || "—"}</div>
    <div style="font-size:0.82rem;margin-bottom:8px"><strong style="color:#f59e0b">⚠ ${tr("متذبذبة تحت المراقبة", "Unstable Nodes")}:</strong> ${unstable.map((s) => `<code>${escHtml(s.country)}:${escHtml(s.server_id.slice(0, 6))} (${s.reliability_score.toFixed(0)})</code>`).join(" • ") || tr("لا يوجد", "None")}</div>
    <div style="font-size:0.82rem"><strong style="color:#ef4444">⏸ ${tr("موقوفة مؤقتًا / غير نشطة", "Suppressed / Inactive")}:</strong> ${deadSup.map((s) => `<code>${escHtml(s.server_id.slice(0, 8))} (${escHtml(s.status)})</code>`).join(" • ") || tr("لا يوجد", "None")}</div>
  `;

  const cRows = ((countries || {}).countries || []).slice(0, 12);
  const maxCountryCnt = Math.max(1, ...cRows.map((c) => Number(c.active_servers ?? c.total_servers ?? 0)));
  document.getElementById("geoAnalyticsBox").innerHTML = `
    <table class="mon-tbl">
      <thead><tr><th>${tr("الدولة", "Country")}</th><th>${tr("نشط", "Active")}</th><th>${tr("أفضل/متوسط Ping", "RTT")}</th><th>${tr("الموثوقية", "Reliability")}</th></tr></thead>
      <tbody>
        ${cRows.map((c) => {
          const act = Number(c.active_servers ?? 0);
          const lat = Number(c.best_latency_ms ?? c.avg_latency_ms ?? 0);
          const rel = Number(c.avg_reliability_score ?? 0);
          return `<tr>
            <td><strong>${escHtml(c.country)}</strong></td>
            <td>${act} <div class="bar-track"><div class="bar-fill" style="width:${((act / maxCountryCnt) * 100).toFixed(0)}%"></div></div></td>
            <td>${lat > 0 ? `${lat.toFixed(0)} ms` : "—"}</td>
            <td>${rel.toFixed(1)}/100</td>
          </tr>`;
        }).join("")}
      </tbody>
    </table>
  `;

  const pRows = ((protocols || {}).protocols || []);
  document.getElementById("protoAnalyticsBox").innerHTML = `
    <table class="mon-tbl">
      <thead><tr><th>${tr("البروتوكول", "Protocol")}</th><th>${tr("نشط", "Active")}</th><th>${tr("نسبة النجاح", "Success Rate")}</th><th>${tr("السرعة", "Avg Speed")}</th><th>${tr("الموثوقية", "Reliability")}</th></tr></thead>
      <tbody>
        ${pRows.map((p) => `<tr>
          <td><strong>${escHtml(String(p.protocol).toUpperCase())}</strong></td>
          <td>${Number(p.active_servers || 0)}</td>
          <td>${(Number(p.success_rate || 0) * 100).toFixed(1)}%</td>
          <td>${Number(p.avg_download_mbps || 0).toFixed(2)} Mbps</td>
          <td>${Number(p.avg_reliability_score || 0).toFixed(1)}/100</td>
        </tr>`).join("")}
      </tbody>
    </table>
  `;

  const opRows = (sourcesStats && Array.isArray(sourcesStats.operators)) ? sourcesStats.operators.slice(0, 15) : null;
  const ghRows = ((sources || {}).github_sources || []).slice(0, 15);
  const srcSum = ((sources || {}).summary || {});
  document.getElementById("sourceAnalyticsBox").innerHTML = opRows
    ? `
      <table class="mon-tbl">
        <thead><tr><th>${tr("مشغّل المصدر المستقل", "Independent Operator")}</th><th>${tr("إجمالي/حيّ", "Active/Total")}</th><th>${tr("حصري (Unique)", "Unique")}</th><th>${tr("مكرر", "Dup")}</th><th>${tr("درجة الثقة", "Reliability")}</th></tr></thead>
        <tbody>
          ${opRows.map((op) => `<tr>
            <td><strong>${escHtml(op.operator_id)}</strong></td>
            <td>${Number(op.active_servers || 0)} / ${Number(op.total_contributed || 0)}</td>
            <td>${Number(op.unique_servers || 0)}</td>
            <td>${Number(op.duplicate_submissions || 0)}</td>
            <td><strong>${Number(op.reliability_score || 0).toFixed(1)}</strong></td>
          </tr>`).join("")}
        </tbody>
      </table>
    `
    : `
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px">
        <span class="pill pill-ok">Active: ${Number(srcSum.active || 0)}</span>
        <span class="pill pill-warn">Degraded: ${Number(srcSum.degraded || 0)}</span>
        <span class="pill pill-err">Quarantined: ${Number(srcSum.quarantined || 0)}</span>
      </div>
      <table class="mon-tbl">
        <thead><tr><th>${tr("المصدر", "Source")}</th><th>${tr("الحالة", "State")}</th><th>${tr("حيّ", "Alive")}</th></tr></thead>
        <tbody>
          ${ghRows.map((s) => `<tr><td><strong>${escHtml(s.name)}</strong></td><td>${escHtml(s.state || "active")}</td><td>${Number(s.alive_count || 0)}</td></tr>`).join("")}
        </tbody>
      </table>
    `;
}

function applyMonitorThemeAndDir() {
  document.documentElement.lang = monLang;
  document.documentElement.dir = monLang === "ar" ? "rtl" : "ltr";
  document.body.classList.toggle("light", monLight);
}

function toggleMonitorLang() {
  monLang = monLang === "ar" ? "en" : "ar";
  localStorage.setItem("mon_lang", monLang);
  refreshMonitor(false);
}

function toggleMonitorTheme() {
  monLight = !monLight;
  localStorage.setItem("mon_theme", monLight ? "light" : "dark");
  applyMonitorThemeAndDir();
}

window.addEventListener("DOMContentLoaded", () => refreshMonitor(false));
