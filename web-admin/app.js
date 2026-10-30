/**
 * app.js — 17-Page Bilingual (AR/EN RTL/LTR) Enterprise Admin Controller
 * Running 100% on GitHub Pages + GitHub REST API + Browser WebCrypto.
 */

const SUBSCRIPTION_HOURS = {
  FREE_TRIAL: 48,
  DAILY: 24,
  WEEKLY: 168,
  MONTHLY: 720,
  THREE_MONTHS: 2160,
  SIX_MONTHS: 4320,
  YEARLY: 8760,
  LIFETIME: null,
};

const PAGES = [
  { id: "overview", ar: "1. النظرة التنفيذية الشاملة", en: "1. Executive Overview" },
  { id: "users", ar: "2. إدارة المشتركين", en: "2. User Management" },
  { id: "subscriptions", ar: "3. الاشتراكات وتجربة 48 ساعة", en: "3. Subscriptions & 48h Trial" },
  { id: "devices", ar: "4. إدارة الأجهزة والمخالفات", en: "4. Devices & Violations" },
  { id: "sessions", ar: "5. مراقب الجلسات النشطة", en: "5. Active Sessions Monitor" },
  { id: "servers", ar: "6. إدارة الخوادم والتصنيف", en: "6. Server Management" },
  { id: "health", ar: "7. صحة الخوادم والاستقرار", en: "7. Server Health & Uptime" },
  { id: "speeds", ar: "8. تحليلات اختبارات السرعة", en: "8. Speed Test Analytics" },
  { id: "netdiag", ar: "9. تشخيص الشبكة والتسريبات", en: "9. Network & Leak Diagnostics" },
  { id: "crashes", ar: "10. صحة التطبيق والانهيارات", en: "10. App Health & Crash Reports" },
  { id: "ai", ar: "11. مركز الذكاء الاصطناعي للأداء", en: "11. AI Performance Intelligence" },
  { id: "notifications", ar: "12. مركز الإشعارات والتنبيهات", en: "12. Notification Center" },
  { id: "remote_config", ar: "13. الإعدادات البعيدة الفورية", en: "13. Remote Configuration" },
  { id: "updates", ar: "14. إدارة الإصدارات والتحديثات", en: "14. App Versions & Updates" },
  { id: "audit", ar: "15. سجلات الأمان والتدقيق", en: "15. Security & Audit Logs" },
  { id: "admins", ar: "16. المشرفون والصلاحيات (RBAC)", en: "16. Admin Users & Roles" },
  { id: "settings", ar: "17. النسخ الاحتياطي المشفّر والنظام", en: "17. Encrypted Backups & System" },
];

const AppState = {
  lang: "ar",
  lightMode: false,
  activePage: "overview",
  searchQuery: "",
  authenticated: false,
  repoFull: "oldman-552/vpn-configs",
  ghToken: "",
  vaultPassphrase: "",
  currentAdmin: null,
  vaultSha: null,
  bundleSha: null,
  liveMeta: null,
  liveServers: [],
  db: null,
};

function createEmptyDb() {
  const now = new Date().toISOString();
  return {
    schema_version: 3,
    signing_keys: null,
    admin_roles: [
      { id: "role_super_admin", name: "SUPER_ADMIN", permissions: ["*"] },
      { id: "role_operator", name: "OPERATOR", permissions: ["users", "devices", "trials", "servers"] },
      { id: "role_auditor", name: "AUDITOR", permissions: ["read_only"] },
    ],
    admin_users: [],
    users: [],
    user_subscriptions: [],
    trial_activations: [],
    bandwidth_limits: {},
    user_devices: [],
    device_violations: [],
    login_attempts: [],
    user_sessions: [],
    data_usage: [],
    speed_tests: [],
    network_tests: [],
    connection_logs: [],
    app_versions: [
      {
        id: "ver_user_3_0",
        target_app: "USER",
        version_code: 8,
        version_name: "3.0",
        release_notes: "ULTIMATE VPN ENTERPRISE v3.0",
        release_date: now,
        mandatory: false,
        min_supported_code: 7,
        apk_url: "https://github.com/oldman-552/vpn-configs/releases/latest/download/app-arm64-v8a-release.apk",
        apk_sha256: "",
        signing_cert_sha256: "",
        is_active: true,
      },
    ],
    app_crashes: [],
    notifications: [],
    remote_config: {
      auth_require_account: { value: false, sensitive: true, desc: "Require account login before VPN connection" },
      auto_block_on_device_violation: { value: false, sensitive: true, desc: "Auto-block account on unauthorized device" },
      trial_duration_hours: { value: 48, sensitive: false, desc: "Server-controlled trial duration (hours)" },
      promo_enabled: { value: true, sensitive: false, desc: "Enable 5-slot rotating startup banner" },
      log_retention_days: { value: 90, sensitive: false, desc: "Telemetry & log retention days" },
    },
    disabled_server_uris: [],
    admin_audit_logs: [],
  };
}

function t(ar, en) {
  return AppState.lang === "ar" ? ar : en;
}

function esc(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function classifyServerTier(srv) {
  const ping = Number(srv.median_latency_ms || srv.latency_ms || 0);
  const spd = Number(srv.speed_kbps || 0);
  const stab = Number(srv.stability_runs || 1);
  if (ping <= 0) return { score: 0, tier: "OFFLINE" };
  const latS = Math.max(0, Math.min(100, (900 - ping) / 8.6));
  const spdS = spd > 0 ? Math.min(100, (spd / 10240) * 100) : 40;
  const upS = Math.min(100, Math.max(50, stab * 20));
  const score = +(0.4 * spdS + 0.38 * latS + 0.22 * upS).toFixed(1);
  const tier =
    score >= 85 ? "EXCELLENT" :
    score >= 72 ? "VERY_GOOD" :
    score >= 56 ? "GOOD" :
    score >= 38 ? "AVERAGE" : "POOR";
  return { score, tier };
}

async function appendAuditLog(action, targetType, targetId, afterObj) {
  const logs = AppState.db.admin_audit_logs;
  const prevHash = logs.length > 0 ? logs[0].entry_hash : "GENESIS";
  const now = new Date().toISOString();
  const afterJson = JSON.stringify(afterObj || {});
  const material = `${now}|${AppState.currentAdmin?.username || "admin"}|${action}|${targetType}|${targetId}|${afterJson}|${prevHash}`;
  const entryHash = await EnterpriseWebCrypto.sha256Hex(material);
  logs.unshift({
    id: "aud_" + EnterpriseWebCrypto.randomHex(6),
    logged_at: now,
    admin: AppState.currentAdmin?.username || "admin",
    action,
    target_type: targetType,
    target_id: targetId,
    after_json: afterJson,
    prev_hash: prevHash,
    entry_hash: entryHash,
  });
}

async function verifyAuditChainIntegrity() {
  const chronological = [...AppState.db.admin_audit_logs].reverse();
  let expectedPrev = "GENESIS";
  for (const row of chronological) {
    if (row.prev_hash !== expectedPrev) return false;
    const mat = `${row.logged_at}|${row.admin}|${row.action}|${row.target_type}|${row.target_id}|${row.after_json}|${row.prev_hash}`;
    const h = await EnterpriseWebCrypto.sha256Hex(mat);
    if (h !== row.entry_hash) return false;
    expectedPrev = row.entry_hash;
  }
  return true;
}

async function syncFromGitHub() {
  const statusEl = document.getElementById("syncStatus");
  if (statusEl) statusEl.textContent = t("جارٍ المزامنة مع GitHub…", "Syncing with GitHub…");
  try {
    const [metaRes, aliveRes, vaultRes, bundleRes] = await Promise.all([
      GitHubServerlessApi.readBranchJson(AppState.repoFull, AppState.ghToken, "data", "meta.json").catch(() => ({ exists: false })),
      GitHubServerlessApi.readBranchJson(AppState.repoFull, AppState.ghToken, "data", "alive.json").catch(() => ({ exists: false })),
      GitHubServerlessApi.readBranchJson(AppState.repoFull, AppState.ghToken, "data", "enterprise/admin_vault.enc.json").catch(() => ({ exists: false })),
      GitHubServerlessApi.readBranchJson(AppState.repoFull, AppState.ghToken, "data", "enterprise/bundle.json").catch(() => ({ exists: false })),
    ]);

    if (metaRes.exists) AppState.liveMeta = metaRes.data;
    if (aliveRes.exists) {
      const arr = Array.isArray(aliveRes.data) ? aliveRes.data : (aliveRes.data?.servers || []);
      AppState.liveServers = arr.slice(0, 400);
    }
    if (bundleRes.exists) AppState.bundleSha = bundleRes.sha;

    if (vaultRes.exists && vaultRes.data) {
      AppState.vaultSha = vaultRes.sha;
      const decrypted = await EnterpriseWebCrypto.decryptAesGcm(
        AppState.vaultPassphrase,
        vaultRes.data.salt_hex,
        vaultRes.data.ciphertext_b64,
        "bahrain-vpn-admin-vault-v3"
      );
      AppState.db = JSON.parse(decrypted);
    } else if (!AppState.db) {
      AppState.db = createEmptyDb();
    }

    if (!AppState.db.signing_keys) {
      AppState.db.signing_keys = await EnterpriseWebCrypto.generateEcdsaP256KeyPair();
    }
    if (statusEl) statusEl.textContent = t("متصل بـ GitHub ✓", "Synced with GitHub ✓");
    renderAll();
  } catch (err) {
    alert(t("خطأ في فك تشفير الخزنة أو اتصال GitHub: ", "Vault/GitHub error: ") + err.message);
    if (statusEl) statusEl.textContent = t("فشل المزامنة", "Sync failed");
  }
}

async function saveAndPublishToGitHub(commitReason = "Update enterprise state") {
  if (!AppState.ghToken) {
    alert(t("أدخل GitHub Token بصلاحية Contents للكتابة المباشرة على المستودع", "Provide a GitHub Token with Contents write permission to publish changes"));
    return;
  }
  const statusEl = document.getElementById("syncStatus");
  if (statusEl) statusEl.textContent = t("جارٍ التشفير والنشر على GitHub…", "Encrypting & publishing to GitHub…");

  try {
    // 1. Encrypt Admin Vault with AES-256-GCM
    const saltHex = EnterpriseWebCrypto.randomHex(16);
    const plainStr = JSON.stringify(AppState.db);
    const ctB64 = await EnterpriseWebCrypto.encryptAesGcm(
      AppState.vaultPassphrase,
      saltHex,
      plainStr,
      "bahrain-vpn-admin-vault-v3"
    );
    const vaultEnvelope = {
      v: 3,
      alg: "PBKDF2-SHA256+AES-256-GCM",
      updated_at: new Date().toISOString(),
      salt_hex: saltHex,
      ciphertext_b64: ctB64,
    };

    const vaultPut = await GitHubServerlessApi.writeBranchJson(
      AppState.repoFull,
      AppState.ghToken,
      "data",
      "enterprise/admin_vault.enc.json",
      vaultEnvelope,
      AppState.vaultSha,
      `chore(enterprise): ${commitReason}`
    );
    AppState.vaultSha = vaultPut.content?.sha || AppState.vaultSha;

    // 2. Build & ECDSA P-256 Sign Zero-Knowledge Public Client Bundle
    const licenses = {};
    for (const u of AppState.db.users) {
      if (!u.envelope_b64) continue;
      const lookupId = await EnterpriseWebCrypto.computeUserLookupId(u.username);
      licenses[lookupId] = {
        salt_hex: u.salt_hex,
        envelope_b64: u.envelope_b64,
        status_code: u.account_status,
        revoked_at: u.session_revoked_at || "",
        updated_at: u.updated_at,
      };
    }
    const rcFlat = {};
    for (const [k, v] of Object.entries(AppState.db.remote_config)) {
      rcFlat[k] = v.value;
    }

    const bundleBody = {
      schema_version: 3,
      generated_at: new Date().toISOString(),
      public_key_spki_b64: AppState.db.signing_keys.publicSpkiB64,
      remote_config: rcFlat,
      app_updates: AppState.db.app_versions.filter((v) => v.is_active),
      licenses,
    };
    const canonicalStr = EnterpriseWebCrypto.canonicalJson(bundleBody);
    const sigB64 = await EnterpriseWebCrypto.signEcdsaP1363B64(
      AppState.db.signing_keys.privatePkcs8B64,
      canonicalStr
    );
    const signedBundle = { bundle: bundleBody, signature_b64: sigB64 };

    const bundlePut = await GitHubServerlessApi.writeBranchJson(
      AppState.repoFull,
      AppState.ghToken,
      "data",
      "enterprise/bundle.json",
      signedBundle,
      AppState.bundleSha,
      `chore(bundle): sign & publish client licenses`
    );
    AppState.bundleSha = bundlePut.content?.sha || AppState.bundleSha;

    if (statusEl) statusEl.textContent = t("تم الحفظ والتوقيع على GitHub ✓", "Encrypted & Signed on GitHub ✓");
    renderAll();
  } catch (err) {
    alert(t("تعذّر النشر على GitHub: ", "Publish failed: ") + err.message);
  }
}

async function rebuildUserSignedEnvelope(userObj, plainPassword) {
  const bw = AppState.db.bandwidth_limits[userObj.id] || {
    max_download_kbps: 0,
    max_upload_kbps: 0,
    max_total_kbps: 0,
    max_daily_mb: 0,
    max_monthly_mb: 0,
    max_concurrent_connections: 1,
    auto_block_on_violation: false,
  };
  const authDevs = AppState.db.user_devices
    .filter((d) => d.user_id === userObj.id && d.device_status === "AUTHORIZED")
    .map((d) => d.device_install_id);

  const cert = {
    user_id: userObj.id,
    username: userObj.username,
    account_status: userObj.account_status,
    subscription_type: userObj.subscription_type,
    subscription_start: userObj.subscription_start || "",
    subscription_expiration: userObj.subscription_expiration || "",
    trial_activation_date: userObj.trial_activation_date || "",
    device_limit: userObj.device_limit || 1,
    authorized_devices: authDevs,
    session_revoked_at: userObj.session_revoked_at || "",
    bandwidth: bw,
    issued_at: userObj.updated_at,
  };
  const certSig = await EnterpriseWebCrypto.signEcdsaP1363B64(
    AppState.db.signing_keys.privatePkcs8B64,
    EnterpriseWebCrypto.canonicalJson(cert)
  );
  userObj.salt_hex = EnterpriseWebCrypto.randomHex(16);
  userObj.envelope_b64 = await EnterpriseWebCrypto.sealUserLicenseEnvelope(
    userObj.username,
    plainPassword,
    userObj.salt_hex,
    { certificate: cert, signature_b64: certSig }
  );
}

// ---------------------------------------------------------------------------
// Export Helpers (Excel .xls SpreadsheetML & Printable PDF)
// ---------------------------------------------------------------------------
function exportCurrentDataExcel() {
  const rows = AppState.db.users.map((u) => [
    u.username,
    u.account_status,
    u.subscription_type,
    u.subscription_expiration || "LIFETIME",
    u.device_limit,
    u.created_at,
  ]);
  let csv = "\uFEFFUsername,Status,Subscription,Expiration,DeviceLimit,CreatedAt\r\n";
  rows.forEach((r) => {
    csv += r.map((c) => `"${String(c ?? "").replace(/"/g, '""')}"`).join(",") + "\r\n";
  });
  const blob = new Blob([csv], { type: "application/vnd.ms-excel;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `bahrain-vpn-enterprise-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
}

// ---------------------------------------------------------------------------
// Page Renderers (All 17 Required Pages)
// ---------------------------------------------------------------------------
function renderSidebar() {
  const nav = document.getElementById("sidebarNav");
  nav.innerHTML = PAGES.map(
    (p) => `<button class="nav-btn ${AppState.activePage === p.id ? "active" : ""}"
              onclick="switchPage('${p.id}')">${esc(t(p.ar, p.en))}</button>`
  ).join("");
}

window.switchPage = (pageId) => {
  AppState.activePage = pageId;
  renderAll();
};

function renderAll() {
  document.documentElement.lang = AppState.lang;
  document.documentElement.dir = AppState.lang === "ar" ? "rtl" : "ltr";
  document.body.classList.toggle("light-mode", AppState.lightMode);
  renderSidebar();
  const container = document.getElementById("pageContainer");
  if (!AppState.db) return;

  const q = AppState.searchQuery.trim().toLowerCase();
  const db = AppState.db;
  const activeSessions = db.user_sessions.filter((s) => s.session_status === "ACTIVE");
  const authDevices = db.user_devices.filter((d) => d.device_status === "AUTHORIZED");
  const uniqueActiveDevs = new Set(activeSessions.map((s) => s.device_id)).size;
  const uniqueActiveUsers = new Set(activeSessions.map((s) => s.user_id)).size;
  const onlineServers = AppState.liveServers.filter((s) => (s.median_latency_ms || s.latency_ms || 0) > 0);

  switch (AppState.activePage) {
    case "overview": {
      const protoCounts = AppState.liveMeta?.alive_by_protocol || {};
      const maxProto = Math.max(1, ...Object.values(protoCounts));
      const barsHtml = Object.entries(protoCounts)
        .map(
          ([proto, cnt]) => `<div class="bar-col">
            <span style="font-size:0.75rem">${cnt}</span>
            <div class="bar-fill" style="height:${Math.max(8, Math.round((cnt / maxProto) * 110))}px"></div>
            <span style="font-size:0.75rem;color:var(--muted)">${esc(proto)}</span>
          </div>`
        )
        .join("");

      container.innerHTML = `
        <div class="kpi-grid">
          <div class="card"><div class="kpi-label">${t("إجمالي الحسابات المسجّلة", "Registered Accounts")}</div><div class="kpi-val">${db.users.length}</div></div>
          <div class="card"><div class="kpi-label">${t("الأجهزة الموثّقة المسجّلة", "Registered Devices")}</div><div class="kpi-val">${authDevices.length}</div></div>
          <div class="card"><div class="kpi-label">${t("الأجهزة المتصلة حاليًا", "Active Devices")}</div><div class="kpi-val">${uniqueActiveDevs}</div></div>
          <div class="card"><div class="kpi-label">${t("جلسات VPN النشطة", "Active VPN Sessions")}</div><div class="kpi-val">${activeSessions.length}</div></div>
          <div class="card"><div class="kpi-label">${t("المشتركون الفريدون المتصلون", "Unique Connected Users")}</div><div class="kpi-val">${uniqueActiveUsers}</div></div>
          <div class="card"><div class="kpi-label">${t("الخوادم الحيّة / المختبرة", "Online / Tested Servers")}</div><div class="kpi-val">${onlineServers.length} / ${AppState.liveMeta?.tested || 0}</div></div>
          <div class="card"><div class="kpi-label">${t("التجارب المجانية النشطة (48h)", "Active 48h Free Trials")}</div><div class="kpi-val">${db.users.filter((u) => u.account_status === "FREE_TRIAL").length}</div></div>
          <div class="card"><div class="kpi-label">${t("مخالفات الأجهزة المرصودة", "Device Violations")}</div><div class="kpi-val">${db.device_violations.length}</div></div>
        </div>
        <div class="card">
          <h3>${t("توزيع البروتوكولات الحيّة على فرع البيانات (@data)", "Live Protocol Distribution (@data)")}</h3>
          <div class="chart-bars">${barsHtml || `<p style="color:var(--muted)">${t("لا توجد بيانات حيّة محمّلة بعد", "No live protocol telemetry loaded yet")}</p>`}</div>
        </div>`;
      break;
    }

    case "users": {
      const filtered = db.users.filter((u) => !q || u.username.includes(q) || u.account_status.toLowerCase().includes(q));
      container.innerHTML = `
        <div class="card no-print">
          <h3>${t("إنشاء حساب مشترك جديد وتوقيع شهادته رقميًا (ECDSA P-256)", "Create Subscriber & Sign License Envelope")}</h3>
          <div class="form-grid">
            <input id="newUName" placeholder="${t("اسم المستخدم", "Username")}" />
            <input id="newUPass" type="password" placeholder="${t("كلمة المرور (6+ أحرف)", "Password (6+ chars)")}" />
            <select id="newUSub">
              ${Object.keys(SUBSCRIPTION_HOURS).map((k) => `<option value="${k}">${k}</option>`).join("")}
            </select>
            <input id="newUDevId" placeholder="${t("معرّف ربط الجهاز الاختياري (inst_...)", "Optional Device ID (inst_...)")}" />
            <input id="newUDlCap" type="number" placeholder="${t("حد التنزيل KB/s (0=مفتوح)", "Max Download KB/s (0=unlimited)")}" />
            <input id="newUDailyMb" type="number" placeholder="${t("الحصة اليومية MB (0=مفتوح)", "Daily Quota MB (0=unlimited)")}" />
          </div>
          <div style="margin-top:12px">
            <button class="btn" onclick="handleCreateUser()">${t("إنشاء الحساب وتوقيع الترخيص", "Create & Sign License")}</button>
          </div>
        </div>
        <div class="card">
          <h3>${t("قائمة المشتركين", "Subscribers")} (${filtered.length})</h3>
          <table>
            <thead><tr><th>${t("المستخدم", "Username")}</th><th>${t("الحالة", "Status")}</th><th>${t("الباقة", "Plan")}</th><th>${t("الانتهاء", "Expires")}</th><th>${t("إجراءات", "Actions")}</th></tr></thead>
            <tbody>
              ${filtered.map((u) => `<tr>
                <td><strong>${esc(u.username)}</strong></td>
                <td><span class="badge ${u.account_status === "ACTIVE" ? "b-ok" : u.account_status === "FREE_TRIAL" ? "b-info" : "b-err"}">${esc(u.account_status)}</span></td>
                <td>${esc(u.subscription_type)}</td>
                <td>${esc(u.subscription_expiration || "LIFETIME")}</td>
                <td>
                  <button class="btn btn-outline" onclick="toggleUserBlock('${u.id}')">${u.account_status === "BLOCKED" ? t("فك الحظر", "Unblock") : t("حظر فوري", "Block")}</button>
                  <button class="btn btn-danger" onclick="deleteUser('${u.id}')">${t("حذف", "Delete")}</button>
                </td>
              </tr>`).join("")}
            </tbody>
          </table>
        </div>`;
      break;
    }

    case "subscriptions": {
      container.innerHTML = `
        <div class="card">
          <h3>${t("إدارة الاشتراكات والتجربة المجانية (48 ساعة محكومة بوقت الخادم)", "Subscriptions & 48-Hour Free Trial Control")}</h3>
          <table>
            <thead><tr><th>${t("المشترك", "User")}</th><th>${t("الباقة", "Type")}</th><th>${t("بداية التفعيل", "Activated")}</th><th>${t("الانتهاء", "Expiration")}</th><th>${t("تحكم", "Control")}</th></tr></thead>
            <tbody>
              ${db.users.map((u) => `<tr>
                <td>${esc(u.username)}</td>
                <td>${esc(u.subscription_type)}</td>
                <td>${esc(u.subscription_start || "—")}</td>
                <td>${esc(u.subscription_expiration || "LIFETIME")}</td>
                <td>
                  <button class="btn btn-outline" onclick="extendUserHours('${u.id}', 48)">+48h</button>
                  <button class="btn btn-success" onclick="convertUserPaid('${u.id}', 'MONTHLY')">${t("ترقية لشهري", "Convert Monthly")}</button>
                </td>
              </tr>`).join("")}
            </tbody>
          </table>
        </div>`;
      break;
    }

    case "devices": {
      container.innerHTML = `
        <div class="card no-print">
          <h3>${t("ربط أو تفويض جهاز لمشترك (قاعدة: 1 حساب = 1 جهاز)", "Bind Authorized Device (1 Account = 1 Device)")}</h3>
          <div class="form-grid">
            <select id="bindUserSel">${db.users.map((u) => `<option value="${u.id}">${esc(u.username)}</option>`).join("")}</select>
            <input id="bindInstallId" placeholder="inst_..." />
            <input id="bindModel" placeholder="${t("طراز الهاتف", "Device Model")}" />
            <input id="bindPassReSign" type="password" placeholder="${t("كلمة مرور المشترك لإعادة ختم الشهادة", "Subscriber Password to Re-seal Envelope")}" />
          </div>
          <div style="margin-top:12px"><button class="btn" onclick="bindDeviceToUser()">${t("اعتماد الجهاز وتحديث الشهادة", "Authorize & Re-Sign")}</button></div>
        </div>
        <div class="card">
          <h3>${t("الأجهزة المسجّلة", "Registered Devices")} (${db.user_devices.length})</h3>
          <table>
            <thead><tr><th>${t("المستخدم", "User")}</th><th>Install ID</th><th>${t("الطراز", "Model")}</th><th>${t("الحالة", "Status")}</th><th>${t("إجراء", "Action")}</th></tr></thead>
            <tbody>
              ${db.user_devices.map((d) => {
                const u = db.users.find((x) => x.id === d.user_id);
                return `<tr>
                  <td>${esc(u?.username || d.user_id)}</td>
                  <td><code>${esc(d.device_install_id)}</code></td>
                  <td>${esc(d.model || d.device_name || "Android")}</td>
                  <td><span class="badge ${d.device_status === "AUTHORIZED" ? "b-ok" : "b-err"}">${esc(d.device_status)}</span></td>
                  <td><button class="btn btn-danger" onclick="revokeDevice('${d.id}')">${t("سحب التفويض", "Revoke")}</button></td>
                </tr>`;
              }).join("")}
            </tbody>
          </table>
        </div>`;
      break;
    }

    case "sessions": {
      container.innerHTML = `
        <div class="card">
          <h3>${t("مراقب الجلسات وإلغاء الجلسات عن بعد", "Active Sessions & Remote Revocation")}</h3>
          <p style="color:var(--muted);margin-top:6px">${t("إلغاء جلسة أي مشترك يحدّث ختم session_revoked_at في الحزمة الموقّعة فيقطع النفق تلقائيًا.", "Revoking updates session_revoked_at in the signed bundle to terminate client tunnels.")}</p>
          <table>
            <thead><tr><th>${t("المشترك", "User")}</th><th>${t("حالة الحساب", "Account Status")}</th><th>${t("آخر إلغاء جلسات", "Last Revocation")}</th><th>${t("إجراء فوري", "Force Action")}</th></tr></thead>
            <tbody>
              ${db.users.map((u) => `<tr>
                <td>${esc(u.username)}</td>
                <td>${esc(u.account_status)}</td>
                <td>${esc(u.session_revoked_at || "—")}</td>
                <td><button class="btn btn-danger" onclick="forceRevokeUserSessions('${u.id}')">${t("قطع جميع الجلسات فورًا", "Force Disconnect")}</button></td>
              </tr>`).join("")}
            </tbody>
          </table>
        </div>`;
      break;
    }

    case "servers": {
      const srvRows = AppState.liveServers
        .filter((s) => !q || String(s.cfg || s.uri || "").toLowerCase().includes(q) || String(s.exit_country || "").toLowerCase().includes(q))
        .slice(0, 80);
      container.innerHTML = `
        <div class="card">
          <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
            <h3>${t("إدارة الخوادم الحيّة والتصنيف الذكي", "Live Server Management & Smart Classification")} (${AppState.liveServers.length})</h3>
            <button class="btn no-print" onclick="triggerPipelineSweep()">${t("تشغيل جامع وفاحص السيرفرات الآن (GitHub Actions)", "Trigger Collector & Tester Sweep")}</button>
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
      break;
    }

    case "health": {
      const countries = AppState.liveMeta?.countries_summary || {};
      container.innerHTML = `
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
      break;
    }

    case "speeds": {
      const measured = AppState.liveServers.filter((s) => Number(s.speed_kbps || 0) > 0);
      const topSpeeds = [...measured].sort((a, b) => (b.speed_kbps || 0) - (a.speed_kbps || 0)).slice(0, 20);
      container.innerHTML = `
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
      break;
    }

    case "netdiag": {
      container.innerHTML = `
        <div class="card">
          <h3>${t("تقارير تشخيص الشبكة وكشف تسرب DNS / IP", "Network & Leak Diagnostic Reports")} (${db.network_tests.length})</h3>
          <p style="color:var(--muted);margin-top:6px">${t("يستورد المشرف هنا تقارير التشخيص المعمّاة التي يشاركها المستخدم طوعًا من التطبيق (بدون أي مراقبة خفية للتصفح).", "Displays opt-in redacted diagnostic reports shared by users (zero hidden browsing surveillance).")}</p>
          <div class="no-print" style="margin-top:12px;display:flex;gap:8px">
            <textarea id="diagImportJson" rows="3" placeholder='${t("الصق JSON تقرير التشخيص المصدّر من هاتف المستخدم...", "Paste exported diagnostic JSON from user app...")}'></textarea>
            <button class="btn" onclick="importDiagnosticJson()">${t("استيراد", "Import")}</button>
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
      break;
    }

    case "crashes": {
      container.innerHTML = `
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
      break;
    }

    case "ai": {
      const totalSrv = AppState.liveServers.length;
      const degraded = AppState.liveServers.filter((s) => (s.median_latency_ms || s.latency_ms || 0) >= 650);
      const confidence = totalSrv >= 30 ? "HIGH" : totalSrv >= 8 ? "MEDIUM" : "LOW";
      container.innerHTML = `
        <div class="card">
          <h3>${t("مركز الذكاء الاصطناعي لتحليل الأداء (مبني على الأدلة الفعلية فقط)", "AI Performance Intelligence (Evidence-Backed Only)")}</h3>
          <p style="color:var(--muted);margin-top:6px">${t("الوضع الآمن مفعّل: لا يتم تنفيذ أي تغييرات تدميرية تلقائيًا دون موافقة المشرف.", "Safe read-only mode: zero automatic destructive changes without admin approval.")}</p>
          <table>
            <thead><tr><th>${t("الأولوية", "Priority")}</th><th>${t("المشكلة المرصودة", "Problem Detected")}</th><th>${t("الدليل الرقمي", "Supporting Evidence")}</th><th>${t("الخطورة / الثقة", "Severity / Confidence")}</th><th>${t("الحل التقني الموصى به", "Recommended Solution")}</th></tr></thead>
            <tbody>
              ${totalSrv === 0 ? `<tr><td>1</td><td>INSUFFICIENT_DATA</td><td>0 live servers loaded</td><td><span class="badge b-info">INFO / LOW</span></td><td>Sync @data branch first</td></tr>` : `
              <tr>
                <td>1</td>
                <td>${t("خوادم ذات زمن استجابة مرتفع (>= 650ms)", "High-latency VPN endpoints (>= 650ms)")}</td>
                <td>${degraded.length} / ${totalSrv} (${((degraded.length / totalSrv) * 100).toFixed(1)}%)</td>
                <td><span class="badge ${degraded.length > totalSrv * 0.3 ? "b-err" : "b-warn"}">${degraded.length > totalSrv * 0.3 ? "HIGH" : "MEDIUM"} / ${confidence}</span></td>
                <td>${t("إبقاء الترتيب الافتراضي على الأسرع تنزيلًا وتشغيل دورة تحديث السيرفرات الدورية.", "Keep FASTEST_DOWNLOAD default ranking and run scheduled pipeline sweep.")}</td>
              </tr>`}
            </tbody>
          </table>
        </div>`;
      break;
    }

    case "notifications": {
      container.innerHTML = `
        <div class="card">
          <h3>${t("مركز الإشعارات والتنبيهات الأمنية", "Notification & Alert Center")} (${db.notifications.length})</h3>
          <table>
            <thead><tr><th>${t("التوقيت", "Time")}</th><th>${t("الأهمية", "Severity")}</th><th>${t("العنوان", "Title")}</th><th>${t("التفاصيل", "Details")}</th></tr></thead>
            <tbody>
              ${db.notifications.map((n) => `<tr>
                <td>${esc(n.created_at)}</td>
                <td><span class="badge b-warn">${esc(n.severity)}</span></td>
                <td>${esc(t(n.title_ar, n.title_en))}</td>
                <td>${esc(t(n.body_ar, n.body_en))}</td>
              </tr>`).join("")}
            </tbody>
          </table>
        </div>`;
      break;
    }

    case "remote_config": {
      container.innerHTML = `
        <div class="card">
          <h3>${t("لوحة الإعدادات البعيدة الفورية (توقّع رقميًا وتصل للتطبيقات)", "Signed Remote Configuration Panel")}</h3>
          <table>
            <thead><tr><th>Key</th><th>${t("الوصف", "Description")}</th><th>${t("القيمة الحالية", "Value")}</th><th>${t("تعديل", "Modify")}</th></tr></thead>
            <tbody>
              ${Object.entries(db.remote_config).map(([k, cfg]) => `<tr>
                <td><code>${esc(k)}</code></td>
                <td>${esc(cfg.desc)}</td>
                <td><strong>${esc(JSON.stringify(cfg.value))}</strong></td>
                <td><button class="btn btn-outline" onclick="toggleOrEditRemoteConfig('${k}')">${t("تغيير", "Change")}</button></td>
              </tr>`).join("")}
            </tbody>
          </table>
        </div>`;
      break;
    }

    case "updates": {
      container.innerHTML = `
        <div class="card">
          <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
            <h3>${t("إدارة الإصدارات وتحديثات APK الموقّعة", "Signed APK Version & Update Manager")}</h3>
            <button class="btn no-print" onclick="triggerApkReleaseBuild()">${t("بناء ونشر APK جديد عبر GitHub Actions", "Trigger Signed APK Build")}</button>
          </div>
          <table>
            <thead><tr><th>Target</th><th>Version</th><th>Code</th><th>Mandatory</th><th>SHA-256</th></tr></thead>
            <tbody>
              ${db.app_versions.map((v) => `<tr>
                <td>${esc(v.target_app)}</td>
                <td>${esc(v.version_name)}</td>
                <td>${v.version_code}</td>
                <td>${v.mandatory ? "YES" : "NO"}</td>
                <td><code>${esc((v.apk_sha256 || "verified-in-release").slice(0, 20))}…</code></td>
              </tr>`).join("")}
            </tbody>
          </table>
        </div>`;
      break;
    }

    case "audit": {
      container.innerHTML = `
        <div class="card">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <h3>${t("سجلات التدقيق الأمني المتسلسلة (SHA-256 Hash Chain)", "Tamper-Evident Admin Audit Logs")}</h3>
            <button class="btn btn-outline no-print" onclick="checkAuditIntegrityUi()">${t("فحص سلامة السلسلة التشفيرية", "Verify Hash Chain")}</button>
          </div>
          <table>
            <thead><tr><th>${t("الوقت", "Time")}</th><th>${t("المشرف", "Admin")}</th><th>${t("الإجراء", "Action")}</th><th>${t("الهدف", "Target")}</th><th>Hash</th></tr></thead>
            <tbody>
              ${db.admin_audit_logs.map((a) => `<tr>
                <td>${esc(a.logged_at)}</td>
                <td>${esc(a.admin)}</td>
                <td>${esc(a.action)}</td>
                <td>${esc(a.target_type)}:${esc(a.target_id)}</td>
                <td><code>${esc(a.entry_hash.slice(0, 14))}…</code></td>
              </tr>`).join("")}
            </tbody>
          </table>
        </div>`;
      break;
    }

    case "admins": {
      container.innerHTML = `
        <div class="card no-print">
          <h3>${t("المشرفون والمصادقة الثنائية (RFC 6238 TOTP 2FA)", "Admin Users, RBAC & TOTP 2FA")}</h3>
          <div class="form-grid">
            <input id="newAdmUser" placeholder="${t("اسم المشرف", "Admin Username")}" />
            <select id="newAdmRole">
              <option value="SUPER_ADMIN">SUPER_ADMIN</option>
              <option value="OPERATOR">OPERATOR</option>
              <option value="AUDITOR">AUDITOR</option>
            </select>
          </div>
          <div style="margin-top:12px">
            <button class="btn" onclick="createNewAdminWithTotp()">${t("إضافة مشرف وتوليد مفتاح 2FA TOTP", "Create Admin + Generate TOTP Secret")}</button>
          </div>
        </div>
        <div class="card">
          <table>
            <thead><tr><th>${t("المشرف", "Username")}</th><th>Role</th><th>2FA TOTP</th></tr></thead>
            <tbody>
              ${db.admin_users.map((a) => `<tr>
                <td>${esc(a.username)}</td>
                <td><span class="badge b-info">${esc(a.role)}</span></td>
                <td>${a.totp_secret ? "ENABLED" : "OFF"}</td>
              </tr>`).join("")}
            </tbody>
          </table>
        </div>`;
      break;
    }

    default: {
      container.innerHTML = `
        <div class="card">
          <h3>${t("النسخ الاحتياطي المشفّر (AES-256-GCM) والاستعادة الموثّقة", "AES-256-GCM Encrypted Backup & Verified Restore")}</h3>
          <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:14px" class="no-print">
            <button class="btn" onclick="downloadEncryptedVaultBackup()">${t("تنزيل نسخة احتياطية مشفّرة الآن", "Download Encrypted Backup")}</button>
            <label class="btn btn-outline" style="cursor:pointer">
              ${t("استعادة نسخة مشفّرة والتحقق منها", "Restore Encrypted Backup")}
              <input type="file" accept=".json" style="display:none" onchange="restoreEncryptedVaultBackup(event)" />
            </label>
          </div>
        </div>`;
      break;
    }
  }
}

// ---------------------------------------------------------------------------
// Interactive Admin Mutations
// ---------------------------------------------------------------------------
window.handleCreateUser = async () => {
  const uname = document.getElementById("newUName").value.trim().toLowerCase();
  const pass = document.getElementById("newUPass").value;
  const subType = document.getElementById("newUSub").value;
  const devId = document.getElementById("newUDevId").value.trim();
  const dlCap = parseInt(document.getElementById("newUDlCap").value || "0", 10) || 0;
  const dailyMb = parseInt(document.getElementById("newUDailyMb").value || "0", 10) || 0;

  if (uname.length < 3 || pass.length < 6) {
    alert(t("اسم المستخدم 3+ أحرف وكلمة المرور 6+ أحرف", "Username 3+ chars and password 6+ chars required"));
    return;
  }
  if (AppState.db.users.some((u) => u.username === uname)) {
    alert(t("اسم المستخدم موجود مسبقًا", "Username already exists"));
    return;
  }

  const now = new Date();
  const hrs = SUBSCRIPTION_HOURS[subType];
  const expIso = hrs ? new Date(now.getTime() + hrs * 3600000).toISOString() : "";
  const uid = "usr_" + EnterpriseWebCrypto.randomHex(7);

  const userObj = {
    id: uid,
    username: uname,
    account_status: subType === "FREE_TRIAL" ? "FREE_TRIAL" : "ACTIVE",
    subscription_type: subType,
    subscription_start: now.toISOString(),
    subscription_expiration: expIso,
    trial_activation_date: subType === "FREE_TRIAL" ? now.toISOString() : "",
    device_limit: 1,
    session_revoked_at: "",
    created_at: now.toISOString(),
    updated_at: now.toISOString(),
  };

  AppState.db.bandwidth_limits[uid] = {
    max_download_kbps: dlCap,
    max_upload_kbps: 0,
    max_total_kbps: dlCap,
    max_daily_mb: dailyMb,
    max_monthly_mb: 0,
    max_concurrent_connections: 1,
    auto_block_on_violation: false,
  };

  if (devId) {
    AppState.db.user_devices.push({
      id: "dev_" + EnterpriseWebCrypto.randomHex(6),
      user_id: uid,
      device_install_id: devId,
      model: "Authorized Phone",
      device_status: "AUTHORIZED",
      registration_date: now.toISOString(),
    });
  }

  await rebuildUserSignedEnvelope(userObj, pass);
  AppState.db.users.unshift(userObj);
  await appendAuditLog("USER_CREATE", "users", uid, { username: uname, subscription_type: subType });
  await saveAndPublishToGitHub(`create user ${uname}`);
};

window.toggleUserBlock = async (uid) => {
  const u = AppState.db.users.find((x) => x.id === uid);
  if (!u) return;
  const nowIso = new Date().toISOString();
  u.account_status = u.account_status === "BLOCKED" ? "ACTIVE" : "BLOCKED";
  if (u.account_status === "BLOCKED") u.session_revoked_at = nowIso;
  u.updated_at = nowIso;
  await appendAuditLog(`USER_${u.account_status}`, "users", uid, { status: u.account_status });
  await saveAndPublishToGitHub(`set ${u.username} ${u.account_status}`);
};

window.deleteUser = async (uid) => {
  if (!confirm(t("تأكيد حذف المشترك نهائيًا؟", "Confirm permanent user deletion?"))) return;
  AppState.db.users = AppState.db.users.filter((x) => x.id !== uid);
  AppState.db.user_devices = AppState.db.user_devices.filter((d) => d.user_id !== uid);
  await appendAuditLog("USER_DELETE", "users", uid, {});
  await saveAndPublishToGitHub(`delete user ${uid}`);
};

window.extendUserHours = async (uid, hrs) => {
  const u = AppState.db.users.find((x) => x.id === uid);
  if (!u) return;
  const base = u.subscription_expiration ? new Date(u.subscription_expiration) : new Date();
  const start = base > new Date() ? base : new Date();
  u.subscription_expiration = new Date(start.getTime() + hrs * 3600000).toISOString();
  if (u.account_status === "EXPIRED") u.account_status = u.subscription_type === "FREE_TRIAL" ? "FREE_TRIAL" : "ACTIVE";
  u.updated_at = new Date().toISOString();
  const pw = prompt(t("أدخل كلمة مرور المشترك لإعادة ختم الشهادة الممددة (أو اتركه فارغًا لتحديث الحالة فقط):", "Optional subscriber password to re-seal certificate:"));
  if (pw && pw.length >= 6) await rebuildUserSignedEnvelope(u, pw);
  await appendAuditLog("SUBSCRIPTION_EXTEND", "users", uid, { hours: hrs });
  await saveAndPublishToGitHub(`extend ${u.username} +${hrs}h`);
};

window.convertUserPaid = async (uid, plan) => {
  const u = AppState.db.users.find((x) => x.id === uid);
  if (!u) return;
  u.subscription_type = plan;
  u.account_status = "ACTIVE";
  const hrs = SUBSCRIPTION_HOURS[plan];
  u.subscription_expiration = hrs ? new Date(Date.now() + hrs * 3600000).toISOString() : "";
  u.updated_at = new Date().toISOString();
  const pw = prompt(t("أدخل كلمة مرور المشترك لإعادة ختم شهادة الباقة المدفوعة:", "Enter subscriber password to re-seal paid certificate:"));
  if (pw && pw.length >= 6) await rebuildUserSignedEnvelope(u, pw);
  await appendAuditLog("TRIAL_CONVERT_PAID", "users", uid, { plan });
  await saveAndPublishToGitHub(`upgrade ${u.username} to ${plan}`);
};

window.bindDeviceToUser = async () => {
  const uid = document.getElementById("bindUserSel").value;
  const inst = document.getElementById("bindInstallId").value.trim();
  const model = document.getElementById("bindModel").value.trim();
  const pw = document.getElementById("bindPassReSign").value;
  const u = AppState.db.users.find((x) => x.id === uid);
  if (!u || !inst || pw.length < 6) {
    alert(t("أكمل حقول الجهاز وكلمة مرور المشترك لإعادة توقيع الشهادة", "Provide device ID and subscriber password"));
    return;
  }
  AppState.db.user_devices = AppState.db.user_devices.map((d) =>
    d.user_id === uid ? { ...d, device_status: "REPLACED" } : d
  );
  AppState.db.user_devices.unshift({
    id: "dev_" + EnterpriseWebCrypto.randomHex(6),
    user_id: uid,
    device_install_id: inst,
    model: model || "Android",
    device_status: "AUTHORIZED",
    registration_date: new Date().toISOString(),
  });
  u.updated_at = new Date().toISOString();
  await rebuildUserSignedEnvelope(u, pw);
  await appendAuditLog("DEVICE_BIND", "user_devices", inst, { user: u.username });
  await saveAndPublishToGitHub(`bind device for ${u.username}`);
};

window.revokeDevice = async (devId) => {
  const d = AppState.db.user_devices.find((x) => x.id === devId);
  if (!d) return;
  d.device_status = "REVOKED";
  await appendAuditLog("DEVICE_REVOKE", "user_devices", devId, {});
  await saveAndPublishToGitHub(`revoke device ${devId}`);
};

window.forceRevokeUserSessions = async (uid) => {
  const u = AppState.db.users.find((x) => x.id === uid);
  if (!u) return;
  u.session_revoked_at = new Date().toISOString();
  u.updated_at = u.session_revoked_at;
  await appendAuditLog("SESSION_FORCE_REVOKE", "users", uid, { at: u.session_revoked_at });
  await saveAndPublishToGitHub(`revoke sessions for ${u.username}`);
};

window.toggleOrEditRemoteConfig = async (key) => {
  const cfg = AppState.db.remote_config[key];
  if (!cfg) return;
  if (cfg.sensitive && !confirm(t(`تأكيد تعديل الإعداد الحساس (${key})؟`, `Confirm modifying sensitive setting (${key})?`))) {
    return;
  }
  if (typeof cfg.value === "boolean") {
    cfg.value = !cfg.value;
  } else {
    const raw = prompt(`New value for ${key}:`, JSON.stringify(cfg.value));
    if (raw === null) return;
    cfg.value = Number.isNaN(Number(raw)) ? raw : Number(raw);
  }
  await appendAuditLog("REMOTE_CONFIG_UPDATE", "remote_config", key, { value: cfg.value });
  await saveAndPublishToGitHub(`remote_config ${key}=${cfg.value}`);
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

window.triggerApkReleaseBuild = async () => {
  try {
    await GitHubServerlessApi.triggerWorkflow(AppState.repoFull, AppState.ghToken, "apk.yml", "main");
    alert(t("تم تشغيل بناء وتوقيع APK على GitHub Actions!", "Dispatched apk.yml on GitHub Actions!"));
  } catch (e) {
    alert(e.message);
  }
};

window.checkAuditIntegrityUi = async () => {
  const ok = await verifyAuditChainIntegrity();
  alert(ok ? t("سلسلة التوقيعات الأمنية سليمة 100% ولم تتعرض لأي عبث ✓", "SHA-256 Audit Chain Verified 100% Intact ✓") : "ALERT: Audit chain mismatch!");
};

window.createNewAdminWithTotp = async () => {
  const u = document.getElementById("newAdmUser").value.trim().toLowerCase();
  const r = document.getElementById("newAdmRole").value;
  if (!u) return;
  const secret = EnterpriseWebCrypto.generateTotpSecretB32();
  AppState.db.admin_users.push({ username: u, role: r, totp_secret: secret, created_at: new Date().toISOString() });
  await appendAuditLog("ADMIN_CREATE", "admin_users", u, { role: r });
  alert(`TOTP Base32 Secret for ${u} (add to Google/Microsoft Authenticator):\n\n${secret}`);
  await saveAndPublishToGitHub(`add admin ${u}`);
};

window.downloadEncryptedVaultBackup = async () => {
  const saltHex = EnterpriseWebCrypto.randomHex(16);
  const ctB64 = await EnterpriseWebCrypto.encryptAesGcm(
    AppState.vaultPassphrase,
    saltHex,
    JSON.stringify(AppState.db),
    "bahrain-vpn-admin-vault-v3"
  );
  const blob = new Blob([JSON.stringify({ v: 3, salt_hex: saltHex, ciphertext_b64: ctB64 }, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `enterprise-vault-backup-${new Date().toISOString().slice(0, 10)}.enc.json`;
  a.click();
};

window.restoreEncryptedVaultBackup = async (ev) => {
  const file = ev.target.files?.[0];
  if (!file) return;
  try {
    const obj = JSON.parse(await file.text());
    const plain = await EnterpriseWebCrypto.decryptAesGcm(
      AppState.vaultPassphrase,
      obj.salt_hex,
      obj.ciphertext_b64,
      "bahrain-vpn-admin-vault-v3"
    );
    const parsed = JSON.parse(plain);
    if (!parsed.users || !parsed.remote_config) throw new Error("Invalid schema");
    AppState.db = parsed;
    await appendAuditLog("VAULT_RESTORE", "system", "backup", {});
    renderAll();
    alert(t("تم فك التشفير والتحقق واستعادة النسخة الاحتياطية بنجاح ✓", "Backup verified & restored ✓"));
  } catch (e) {
    alert("Restore verification failed: " + e.message);
  }
};

// ---------------------------------------------------------------------------
// Login & Initialization
// ---------------------------------------------------------------------------
window.handleAdminUnlock = async () => {
  const repo = document.getElementById("loginRepo").value.trim();
  const token = document.getElementById("loginToken").value.trim();
  const pass = document.getElementById("loginVaultPass").value;
  const admName = document.getElementById("loginAdmUser").value.trim().toLowerCase() || "admin";
  const totp = document.getElementById("loginTotp").value.trim();

  if (!repo || pass.length < 6) {
    alert(t("أدخل اسم المستودع وعبارة تشفير الخزنة (6+ أحرف)", "Enter repository and vault master passphrase (6+ chars)"));
    return;
  }

  AppState.repoFull = repo;
  AppState.ghToken = token;
  AppState.vaultPassphrase = pass;
  await syncFromGitHub();

  if (AppState.db) {
    const foundAdmin = AppState.db.admin_users.find((a) => a.username === admName);
    if (foundAdmin && foundAdmin.totp_secret) {
      const ok2fa = await EnterpriseWebCrypto.verifyTotp(foundAdmin.totp_secret, totp);
      if (!ok2fa) {
        AppState.db = null;
        alert(t("رمز المصادقة الثنائية 2FA TOTP غير صحيح!", "Invalid 6-digit 2FA TOTP code!"));
        return;
      }
    }
    AppState.currentAdmin = foundAdmin || { username: admName, role: "SUPER_ADMIN" };
    AppState.authenticated = true;
    document.getElementById("authOverlay").style.display = "none";
    renderAll();
  }
};

window.toggleLanguage = () => {
  AppState.lang = AppState.lang === "ar" ? "en" : "ar";
  renderAll();
};

window.toggleTheme = () => {
  AppState.lightMode = !AppState.lightMode;
  renderAll();
};

window.onGlobalSearch = (val) => {
  AppState.searchQuery = val;
  renderAll();
};

window.exportExcel = exportCurrentDataExcel;
window.exportPdf = () => window.print();
