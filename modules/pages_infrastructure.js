/**
 * modules/pages_infrastructure.js — Pages 6..10 (Servers + Encrypted VIP Private Nodes,
 * Health, Throughput Analytics, Network Diagnostics, Crash & App Health Reports).
 */

const InfrastructureViews = {
  render(pageId, ctx) {
    const { db, q } = ctx;
    switch (pageId) {
      case "servers": {
        const vipRows = db.vip_servers || [];
        const srvRows = AppState.liveServers
          .filter((s) => !q || String(s.cfg || s.uri || "").toLowerCase().includes(q) || String(s.exit_country || "").toLowerCase().includes(q))
          .slice(0, 80);
        return `
          <div class="card no-print">
            <h3>💎 ${t("إدارة سيرفرات VIP الخاصة المشفّرة (تظهر للمشتركين الفعّالين فقط ومحمية من النسخ)", "Encrypted VIP Private Nodes (Active Subscribers Only — Copy-Protected)")}</h3>
            <p style="color:var(--muted);margin-top:4px;font-size:0.85rem">
              ${t("تُشفّر روابط هذه السيرفرات بخوارزمية AES-256-GCM داخل الحزمة الموقّعة ولا يمكن فك تشفيرها إلا بشهادة مشترك نشط.", "VIP URIs are encrypted with AES-256-GCM inside bundle.json and decrypted exclusively in memory by active subscribers.")}
            </p>
            <div class="form-grid" style="margin-top:10px">
              <input id="vipLabel" placeholder="${t("اسم عقدة VIP (مثال: VIP Bahrain #1)", "VIP Label (e.g. VIP Frankfurt #1)")}" />
              <input id="vipCountry" maxlength="2" placeholder="${t("رمز الدولة (BH, DE, NL...)", "Country ISO-2 (BH, DE...)")}" />
              <input id="vipPriority" type="number" value="200" placeholder="${t("الأولوية (أعلى = أولاً)", "Priority (200)")}" />
              <input id="vipUri" placeholder="vless://... | hysteria2://... | trojan://..." />
            </div>
            <div style="margin-top:10px">
              <button class="btn" data-on="click:handleAddVipServer">💎 ${t("إضافة وتشفير ونشر عقدة VIP", "Encrypt & Publish VIP Node")}</button>
            </div>
            ${vipRows.length > 0 ? `
            <table style="margin-top:12px">
              <thead><tr><th>Label</th><th>${t("الدولة", "Country")}</th><th>Protocol</th><th>Priority</th><th>${t("الحالة", "State")}</th><th>${t("إجراء", "Action")}</th></tr></thead>
              <tbody>
                ${vipRows.map((v) => `<tr>
                  <td><strong>💎 ${esc(v.label)}</strong></td>
                  <td>${esc(v.country || "—")}</td>
                  <td><code>${esc(v.protocol || "VLESS")}</code></td>
                  <td>${v.priority || 100}</td>
                  <td><span class="badge ${v.enabled !== false ? "b-ok" : "b-warn"}">${v.enabled !== false ? "ACTIVE" : "PAUSED"}</span></td>
                  <td>
                    <button class="btn btn-outline" data-on="click:toggleVipServer" data-args='["${v.id}"]'>${v.enabled !== false ? t("إيقاف", "Pause") : t("تفعيل", "Enable")}</button>
                    <button class="btn btn-danger" data-on="click:deleteVipServer" data-args='["${v.id}"]'>${t("حذف", "Delete")}</button>
                  </td>
                </tr>`).join("")}
              </tbody>
            </table>` : ""}
          </div>

          <div class="card">
            <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
              <h3>${t("الخوادم العامة الحيّة والتصنيف الذكي (@data)", "Live Public Server Pool & Smart Classification")} (${AppState.liveServers.length})</h3>
              <div style="display:flex;gap:8px;flex-wrap:wrap" class="no-print">
                <a class="btn btn-outline" href="monitor.html" target="_blank" style="text-decoration:none">📊 ${t("فتح منصة الذكاء التاريخي (24h/7d/30d/90d)", "Open Historical Intelligence Dashboard")}</a>
                <button class="btn" data-on="click:triggerPipelineSweep">${t("تشغيل جامع وفاحص السيرفرات الآن (GitHub Actions)", "Trigger Collector & Tester Sweep")}</button>
              </div>
            </div>
            <table>
              <thead><tr><th>#</th><th>${t("الدولة", "Country")}</th><th>Ping</th><th>Speed</th><th>${t("التصنيف", "Tier")}</th><th>${t("النقاط", "Score")}</th></tr></thead>
              <tbody>
                ${srvRows.map((s, i) => {
                  const { score, tier } = classifyServerTier(s);
                  const ping = s.median_latency_ms || s.latency_ms || 0;
                  const spd = s.speed_kbps ? `${Math.round(s.speed_kbps)} KB/s` : "—";
                  return `<tr>
                    <td>bahrain-vpn #${i + 1}</td>
                    <td>${esc(s.exit_country || "—")}</td>
                    <td>${ping} ms</td>
                    <td>${spd}</td>
                    <td><span class="badge ${tier === "EXCELLENT" || tier === "VERY_GOOD" ? "b-ok" : tier === "OFFLINE" || tier === "POOR" ? "b-err" : "b-warn"}">${tier}</span></td>
                    <td>${score}</td>
                  </tr>`;
                }).join("")}
              </tbody>
            </table>
          </div>`;
      }

      case "health": {
        const countries = AppState.liveMeta?.countries_summary || {};
        return `
          <div class="kpi-grid">
            <div class="card"><div class="kpi-label">${t("آخر توليد للقائمة الحيّة", "Last @data Build")}</div><div class="kpi-val" style="font-size:1.1rem">${esc(AppState.liveMeta?.generated_at || "—")}</div></div>
            <div class="card"><div class="kpi-label">${t("قنوات ومصادر ناجحة", "Healthy Sources")}</div><div class="kpi-val">${AppState.liveMeta?.channels_ok || 0} / ${AppState.liveMeta?.channels_total || 0}</div></div>
            <div class="card"><div class="kpi-label">${t("وضع الحماية من التدهور", "Degraded Protection")}</div><div class="kpi-val">${AppState.liveMeta?.degraded_mode ? "ACTIVE" : "NORMAL"}</div></div>
          </div>
          <div class="card">
            <h3>${t("التوزيع الجغرافي الحقيقي لعقد الخروج", "Verified Exit Country Distribution")}</h3>
            <table>
              <thead><tr><th>${t("رمز الدولة", "Country")}</th><th>${t("عدد السيرفرات الحيّة", "Online Nodes")}</th></tr></thead>
              <tbody>
                ${Object.entries(countries).map(([cc, cnt]) => `<tr><td>${esc(cc)}</td><td>${cnt}</td></tr>`).join("")}
              </tbody>
            </table>
          </div>`;
      }

      case "speeds": {
        const measured = AppState.liveServers.filter((s) => Number(s.speed_kbps || 0) > 0);
        const topSpeeds = [...measured].sort((a, b) => (b.speed_kbps || 0) - (a.speed_kbps || 0)).slice(0, 20);
        return `
          <div class="card">
            <h3>${t("تحليلات السرعة المقاسة فعليًا", "Measured Throughput Analytics")} (${measured.length} ${t("عينة مقاسة", "measured samples")})</h3>
            ${topSpeeds.length === 0 ? `<p style="color:var(--muted);margin-top:10px">${t("لا توجد عينات سرعة مسجلة في الحزمة الحالية (بيانات صادقة بدون أرقام افتراضية).", "Zero speed samples recorded yet (no synthetic numbers displayed).")}</p>` : `
            <table>
              <thead><tr><th>#</th><th>${t("الدولة", "Country")}</th><th>KB/s</th><th>Mbps</th><th>Ping</th></tr></thead>
              <tbody>
                ${topSpeeds.map((s, idx) => `<tr>
                  <td>#${idx + 1}</td>
                  <td>${esc(s.exit_country || "—")}</td>
                  <td>${Math.round(s.speed_kbps)} KB/s</td>
                  <td>${((s.speed_kbps * 8) / 1024).toFixed(2)} Mbps</td>
                  <td>${s.median_latency_ms || s.latency_ms || 0} ms</td>
                </tr>`).join("")}
              </tbody>
            </table>`}
          </div>`;
      }

      case "netdiag":
        return `
          <div class="card">
            <h3>${t("تقارير تشخيص الشبكة وكشف تسرب DNS / IP", "Network & Leak Diagnostic Reports")} (${db.network_tests.length})</h3>
            <p style="color:var(--muted);margin-top:6px">${t("يستورد المشرف هنا تقارير التشخيص المعمّاة التي يشاركها المستخدم طوعًا من التطبيق (بدون أي مراقبة خفية للتصفح).", "Displays opt-in redacted diagnostic reports shared by users (zero hidden browsing surveillance).")}</p>
            <div class="no-print" style="margin-top:12px;display:flex;gap:8px">
              <textarea id="diagImportJson" rows="3" placeholder='${t("الصق JSON تقرير التشخيص المصدّر من هاتف المستخدم...", "Paste exported diagnostic JSON from user app...")}'></textarea>
              <button class="btn" data-on="click:importDiagnosticJson">${t("استيراد", "Import")}</button>
            </div>
            <table>
              <thead><tr><th>${t("التاريخ", "Timestamp")}</th><th>Install ID</th><th>↓ Mbps</th><th>↑ Mbps</th><th>Ping</th></tr></thead>
              <tbody>
                ${db.network_tests.map((n) => `<tr>
                  <td>${esc(n.tested_at)}</td>
                  <td><code>${esc(n.device_install_id)}</code></td>
                  <td>${esc(n.last_dl_mbps ?? "—")}</td>
                  <td>${esc(n.last_ul_mbps ?? "—")}</td>
                  <td>${esc(n.last_ping_ms ?? "—")} ms</td>
                </tr>`).join("")}
              </tbody>
            </table>
          </div>`;

      case "crashes":
        return `
          <div class="card">
            <h3>${t("مراقب صحة التطبيق وتقارير الانهيارات (ANR / Crashes)", "App Health & Crash Reports")} (${db.app_crashes.length})</h3>
            ${db.app_crashes.length === 0 ? `<p style="color:var(--muted);margin-top:10px">${t("صفر انهيارات مستوردة حتى الآن.", "Zero crash reports recorded.")}</p>` : `
            <table>
              <thead><tr><th>${t("الوقت", "Time")}</th><th>${t("الإصدار", "Version")}</th><th>${t("الإقلاع", "Startup")}</th><th>${t("الذاكرة", "Memory")}</th><th>${t("الانهيارات", "Crashes")}</th></tr></thead>
              <tbody>
                ${db.app_crashes.map((c) => `<tr>
                  <td>${esc(c.occurred_at)}</td>
                  <td>${esc(c.app_version)}</td>
                  <td>${esc(c.startup_ms)} ms</td>
                  <td>${esc(c.memory_mb)} MB</td>
                  <td>${esc(c.crash_count)}</td>
                </tr>`).join("")}
              </tbody>
            </table>`}
          </div>`;

      default:
        return null;
    }
  },
};

window.handleAddVipServer = async () => {
  const label = (document.getElementById("vipLabel").value || "VIP Edge").trim();
  const country = (document.getElementById("vipCountry").value || "").trim().toUpperCase().slice(0, 2);
  const priority = parseInt(document.getElementById("vipPriority").value || "200", 10) || 200;
  const uri = (document.getElementById("vipUri").value || "").trim();
  if (!uri.includes("://") || uri.length < 14) {
    alert(t("أدخل رابط إعداد VPN صالح (VLESS / Hysteria2 / Trojan / VMess / SS)", "Enter a valid proxy URI (vless://, hysteria2://, trojan://, etc.)"));
    return;
  }
  ensureVaultV31Defaults(AppState.db);
  const proto = uri.split("://")[0].toUpperCase();
  const vid = "vip_" + EnterpriseWebCrypto.randomHex(6);
  AppState.db.vip_servers.unshift({
    id: vid,
    label,
    country,
    protocol: proto,
    uri,
    priority,
    enabled: true,
    created_at: new Date().toISOString(),
  });
  await appendAuditLog("VIP_SERVER_ADD", "vip_servers", vid, { label, country, protocol: proto, priority });
  await saveAndPublishToGitHub(`add VIP node ${label}`);
};

window.toggleVipServer = async (vid) => {
  const v = (AppState.db.vip_servers || []).find((x) => x.id === vid);
  if (!v) return;
  v.enabled = v.enabled === false;
  await appendAuditLog("VIP_SERVER_TOGGLE", "vip_servers", vid, { enabled: v.enabled });
  await saveAndPublishToGitHub(`toggle VIP node ${v.label}`);
};

window.deleteVipServer = async (vid) => {
  if (!confirm(t("حذف عقدة VIP الخاصة؟", "Delete VIP private node?"))) return;
  AppState.db.vip_servers = (AppState.db.vip_servers || []).filter((x) => x.id !== vid);
  await appendAuditLog("VIP_SERVER_DELETE", "vip_servers", vid, {});
  await saveAndPublishToGitHub(`delete VIP node ${vid}`);
};

window.importDiagnosticJson = () => {
  try {
    const o = JSON.parse(document.getElementById("diagImportJson").value);
    const now = new Date().toISOString();
    AppState.db.network_tests.unshift({ tested_at: now, ...o });
    AppState.db.app_crashes.unshift({ occurred_at: now, ...o });
    renderAll();
  } catch (e) {
    alert("Invalid JSON: " + e.message);
  }
};

window.triggerPipelineSweep = async () => {
  try {
    await GitHubServerlessApi.triggerWorkflow(AppState.repoFull, AppState.ghToken, "data.yml", "main");
    alert(t("تم إرسال أمر تحديث وفحص السيرفرات إلى GitHub Actions بنجاح!", "Dispatched data.yml on GitHub Actions!"));
  } catch (e) {
    alert(e.message);
  }
};
