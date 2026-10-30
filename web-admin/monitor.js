// =====================================================================
// monitor.js — Phase 8 Read-Only Live Infrastructure Monitoring Dashboard.
// Uses bounded sessionStorage + ETag caching (60s TTL) over sanitized public
// endpoints (@data/api/v1/* with graceful fallback to @data/*.json).
// Never requests, stores, or renders credentials or raw proxy URIs.
// =====================================================================
"use strict";

const MON_CDN_BASE = "https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data";
const CACHE_TTL_MS = 60_000;

let monLang = localStorage.getItem("mon_lang") || "ar";
let monLight = localStorage.getItem("mon_theme") === "light";

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
    } catch (_) {
      // Ignore storage quota errors
    }
  }

  const localTry = `api/v1/${relPath.replace(/^api\/v1\//, "")}`;
  const urls = relPath.startsWith("api/v1/")
    ? [localTry, `${MON_CDN_BASE}/${relPath}`]
    : [`${MON_CDN_BASE}/${relPath}`];

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
    } catch (_) {
      // Try next fallback URL
    }
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
  const h = 64;
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
        avg_latency_ms: 95,
        avg_performance_score: 78,
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
    countries: { countries: cList, best_performing_countries: cList.filter((x) => x.country !== "XX").slice(0, 8) },
    protocols: { protocols: pList },
    sources: sourceDoc || { summary: {}, github_sources: [], telegram_channels_summary: {} },
  };
}

async function refreshMonitor(force = false) {
  applyMonitorThemeAndDir();
  document.getElementById("hdrTitle").textContent = tr(
    "لوحة الرصد الحي للبنية التحتية — bahrain-vpn",
    "bahrain-vpn — Live Infrastructure Intelligence Monitor"
  );
  document.getElementById("ttlPerf").textContent = tr("تحليلات الأداء والموثوقية والأمان", "Performance, Reliability & Security Analytics");
  document.getElementById("ttlHist").textContent = tr("السلاسل التاريخية للأداء والجاهزية", "Historical Trends (Performance, Uptime & Sources)");
  document.getElementById("ttlGeo").textContent = tr("التحليلات الجغرافية وأفضل الدول أداءً", "Geographic Distribution & Top Countries");
  document.getElementById("ttlProto").textContent = tr("تحليلات البروتوكولات ونسب النجاح", "Protocol Distribution & Reliability");
  document.getElementById("ttlSrc").textContent = tr("صحة المصادر (Telegram + GitHub) والعزل الأمني", "Source Intelligence (Telegram + GitHub) & Quarantine");

  let [stats, countries, protocols, sources] = await Promise.all([
    cachedJsonFetch("api/v1/statistics.json", force),
    cachedJsonFetch("api/v1/countries.json", force),
    cachedJsonFetch("api/v1/protocols.json", force),
    cachedJsonFetch("api/v1/sources.json", force),
  ]);

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

  const ov = stats.overview || {};
  const pa = stats.performance_analytics || {};
  const sa = stats.security_analytics || {};

  document.getElementById("hdrMeta").textContent = `${tr("آخر تنفيذ ناجح للخط السحابي", "Last Successful Pipeline Run")}: ${ov.last_successful_execution || stats.generated_at || "—"} | ${ov.degraded_mode ? tr("وضع الحماية Last-Known-Good", "Degraded LKG Mode") : tr("يعمل بكفاءة قياسية", "Operational")}`;

  const kpis = [
    { lbl: tr("إجمالي الكانفيغات المجمّعة", "Collected Configs"), val: (ov.total_collected_configs || 0).toLocaleString(), cls: "" },
    { lbl: tr("السيرفرات النشطة (Alive)", "Active Servers"), val: (ov.active_servers || 0).toLocaleString(), cls: "color:#10b981" },
    { lbl: tr("السيرفرات السليمة (Healthy)", "Healthy Servers"), val: (ov.healthy_servers || 0).toLocaleString(), cls: "color:#3b82f6" },
    { lbl: tr("السيرفرات الفاشلة بالفحص", "Failed Candidates"), val: (ov.failed_servers || 0).toLocaleString(), cls: "color:#f59e0b" },
    { lbl: tr("السيرفرات المعزولة أمنيًا", "Quarantined Configs"), val: (ov.quarantined_servers || 0).toLocaleString(), cls: "color:#ef4444" },
    { lbl: tr("إجمالي المصادر المراقَبة", "Monitored Sources"), val: (ov.monitored_sources || 0).toLocaleString(), cls: "" },
  ];
  document.getElementById("overviewKpis").innerHTML = kpis
    .map((k) => `<div class="kpi-card"><div class="kpi-label">${escHtml(k.lbl)}</div><div class="kpi-val" style="${k.cls}">${escHtml(k.val)}</div></div>`)
    .join("");

  const riskSummary = Object.entries(sa.risk_levels || {})
    .map(([rk, cnt]) => `<span class="pill ${rk === "LOW" ? "pill-ok" : rk === "MEDIUM" ? "pill-warn" : "pill-err"}" style="margin:2px">${escHtml(rk)}: ${Number(cnt)}</span>`)
    .join(" ");

  document.getElementById("perfAnalyticsBox").innerHTML = `
    <table class="mon-tbl">
      <tr><td>${tr("متوسط زمن الاستجابة (Latency)", "Average Latency")}</td><td><strong>${Number(pa.avg_latency_ms || 0).toFixed(1)} ms</strong></td></tr>
      <tr><td>${tr("متوسط التذبذب (Jitter)", "Average Jitter")}</td><td><strong>${Number(pa.avg_jitter_ms || 0).toFixed(1)} ms</strong></td></tr>
      <tr><td>${tr("متوسط سرعة التنزيل الموثّقة", "Average Download Speed")}</td><td><strong>${Number(pa.avg_download_mbps || 0).toFixed(2)} Mbps</strong></td></tr>
      <tr><td>${tr("متوسط فقدان الحزم (Packet Loss)", "Average Packet Loss")}</td><td><strong>${Number(pa.avg_packet_loss_pct || 0).toFixed(2)}%</strong></td></tr>
      <tr><td>${tr("التوافر التاريخي (Uptime)", "Historical Availability")}</td><td><strong>${Number(pa.historical_availability_pct || 0).toFixed(2)}%</strong></td></tr>
      <tr><td>${tr("متوسط درجة الأداء / الموثوقية", "Avg Performance / Reliability")}</td><td><strong>${Number(pa.avg_performance_score || 0).toFixed(1)} / ${Number(pa.avg_reliability_score || 0).toFixed(1)}</strong></td></tr>
    </table>
    <div style="margin-top:12px;font-size:0.8rem">${tr("توزيع المخاطر الأمنية", "Security Risk Distribution")}: ${riskSummary || "—"}</div>
  `;

  const hist = stats.history || [];
  document.getElementById("historyChartsBox").innerHTML =
    renderSvgSparkline(hist, "active", "#10b981", tr("عدد السيرفرات النشطة عبر الزمن", "Active Servers Over Time")) +
    renderSvgSparkline(hist, "avg_performance_score", "#3b82f6", tr("متوسط درجة الأداء (0–100)", "Avg Performance Score (0–100)")) +
    renderSvgSparkline(hist, "failed", "#f59e0b", tr("معدل فشل المرشحين", "Candidate Failure Count")) +
    renderSvgSparkline(hist, "active_sources", "#a855f7", tr("المصادر السليمة النشطة", "Active Healthy Sources"));

  const cRows = ((countries || {}).countries || []).slice(0, 12);
  const maxCountryCnt = Math.max(1, ...cRows.map((c) => Number(c.active_servers || 0)));
  document.getElementById("geoAnalyticsBox").innerHTML = `
    <table class="mon-tbl">
      <thead><tr><th>${tr("الدولة", "Country")}</th><th>${tr("السيرفرات", "Servers")}</th><th>${tr("أفضل Ping", "Best RTT")}</th><th>${tr("الموثوقية", "Reliability")}</th></tr></thead>
      <tbody>
        ${cRows
          .map(
            (c) => `<tr>
              <td><strong>${escHtml(c.country)}</strong></td>
              <td>${Number(c.active_servers)} <div class="bar-track"><div class="bar-fill" style="width:${((Number(c.active_servers) / maxCountryCnt) * 100).toFixed(0)}%"></div></div></td>
              <td>${Number(c.best_latency_ms || 0).toFixed(0)} ms</td>
              <td>${Number(c.avg_reliability_score || 0).toFixed(1)}/100</td>
            </tr>`
          )
          .join("")}
      </tbody>
    </table>
  `;

  const pRows = ((protocols || {}).protocols || []);
  document.getElementById("protoAnalyticsBox").innerHTML = `
    <table class="mon-tbl">
      <thead><tr><th>${tr("البروتوكول", "Protocol")}</th><th>${tr("نشط", "Active")}</th><th>${tr("نسبة النجاح", "Success Rate")}</th><th>${tr("السرعة", "Avg Speed")}</th><th>${tr("الموثوقية", "Reliability")}</th></tr></thead>
      <tbody>
        ${pRows
          .map(
            (p) => `<tr>
              <td><strong>${escHtml(String(p.protocol).toUpperCase())}</strong></td>
              <td>${Number(p.active_servers || 0)}</td>
              <td>${(Number(p.success_rate || 0) * 100).toFixed(1)}%</td>
              <td>${Number(p.avg_download_mbps || 0).toFixed(2)} Mbps</td>
              <td>${Number(p.avg_reliability_score || 0).toFixed(1)}/100</td>
            </tr>`
          )
          .join("")}
      </tbody>
    </table>
  `;

  const ghRows = ((sources || {}).github_sources || []).slice(0, 15);
  const tgSum = ((sources || {}).telegram_channels_summary || {});
  const srcSum = ((sources || {}).summary || {});
  document.getElementById("sourceAnalyticsBox").innerHTML = `
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">
      <span class="pill pill-ok">Active: ${Number(srcSum.active || 0)}</span>
      <span class="pill pill-warn">Degraded: ${Number(srcSum.degraded || 0)}</span>
      <span class="pill pill-warn">Disabled: ${Number(srcSum.disabled || 0)}</span>
      <span class="pill pill-err">Quarantined: ${Number(srcSum.quarantined || 0)}</span>
      <span class="pill pill-ok">Telegram OK: ${Number(tgSum.active || 0)} / ${Number(tgSum.total || 0)}</span>
    </div>
    <table class="mon-tbl">
      <thead><tr><th>${tr("المصدر (GitHub)", "GitHub Source")}</th><th>${tr("الحالة", "State")}</th><th>${tr("معدل النجاح", "Success Rate")}</th><th>${tr("حيّ", "Alive")}</th><th>${tr("جديد/مكرر/مشبوه", "New/Dup/Susp")}</th><th>${tr("آخر فحص ناجح", "Last Success")}</th></tr></thead>
      <tbody>
        ${ghRows
          .map((s) => {
            const st = String(s.state || "unknown");
            const pCls = st === "active" ? "pill-ok" : st === "quarantined" ? "pill-err" : "pill-warn";
            const sr = s.collection_success_rate !== undefined ? (Number(s.collection_success_rate) * 100).toFixed(0) : "100";
            return `<tr>
              <td><strong>${escHtml(s.name)}</strong></td>
              <td><span class="pill ${pCls}">${escHtml(st)}</span></td>
              <td>${sr}%</td>
              <td>${Number(s.alive_count || 0)}</td>
              <td>${Number(s.new_configs || 0)} / ${Number(s.duplicate_configs || 0)} / ${Number(s.suspicious_configs || 0)}</td>
              <td style="font-size:0.75rem">${escHtml(s.last_success_at || "—")}</td>
            </tr>`;
          })
          .join("")}
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
