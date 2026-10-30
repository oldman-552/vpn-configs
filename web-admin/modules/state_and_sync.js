/**
 * modules/state_and_sync.js — Core State, i18n, Audit Chain, Encrypted Vault Sync,
 * Encrypted VIP Private Nodes Sealing, and ECDSA Bundle Publisher (v3.2).
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
  { id: "servers", ar: "6. الخوادم وعقد VIP المشفّرة", en: "6. Servers & Encrypted VIP Nodes" },
  { id: "health", ar: "7. صحة الخوادم والاستقرار", en: "7. Server Health & Uptime" },
  { id: "speeds", ar: "8. تحليلات اختبارات السرعة", en: "8. Speed Test Analytics" },
  { id: "netdiag", ar: "9. تشخيص الشبكة والتسريبات", en: "9. Network & Leak Diagnostics" },
  { id: "crashes", ar: "10. صحة التطبيق والانهيارات", en: "10. App Health & Crash Reports" },
  { id: "ai", ar: "11. مركز الذكاء الاصطناعي للأداء", en: "11. AI Performance Intelligence" },
  { id: "notifications", ar: "12. مركز الإشعارات والتنبيهات", en: "12. Notification Center" },
  { id: "remote_config", ar: "13. الإعدادات البعيدة الفورية", en: "13. Remote Configuration" },
  { id: "updates", ar: "14. إدارة الإصدارات والتحديثات", en: "14. App Versions & ABI Updates" },
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
    bundle_release: "3.2",
    signing_keys: null,
    vip_key_hex: EnterpriseWebCrypto.randomHex(32),
    vip_servers: [],
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
        id: "ver_user_3_2",
        target_app: "USER",
        version_code: 10,
        version_name: "3.2",
        release_notes: "ULTIMATE VPN ENTERPRISE v3.2 — Zero-Leak DNS/IPv6 + Fail-Closed Kill Switch + Proactive Failover + Security Intelligence",
        release_date: now,
        mandatory: false,
        min_supported_code: 9,
        apk_url: "https://github.com/oldman-552/vpn-configs/releases/download/v3.2/app-arm64-v8a-release.apk",
        apk_sha256: "13dd72d0182de10f5a5b9d75174d3626aae10759f00e79ae89efa8b0da9dfdee",
        signing_cert_sha256: "",
        abi_assets: {
          "arm64-v8a": {
            apk_url: "https://github.com/oldman-552/vpn-configs/releases/download/v3.2/app-arm64-v8a-release.apk",
            apk_sha256: "13dd72d0182de10f5a5b9d75174d3626aae10759f00e79ae89efa8b0da9dfdee",
          },
          x86_64: {
            apk_url: "https://github.com/oldman-552/vpn-configs/releases/download/v3.2/app-x86_64-release.apk",
            apk_sha256: "11b8f1828883b1206253ddc619f4c2baa9f85a857591f767e0516a58c7353e5c",
          },
          universal: {
            apk_url: "https://github.com/oldman-552/vpn-configs/releases/download/v3.2/app-release.apk",
            apk_sha256: "ca21059896f59136334e47c42fec34dc1b5105d5db63c03b56062fd57aff9da9",
          },
        },
        is_active: true,
      },
      {
        id: "ver_admin_3_2",
        target_app: "ADMIN",
        version_code: 3,
        version_name: "3.2",
        release_notes: "ULTIMATE VPN ADMIN v3.2 - Encrypted VIP Private Nodes + Slim R8 Build",
        release_date: now,
        mandatory: false,
        min_supported_code: 2,
        apk_url: "https://github.com/oldman-552/vpn-configs/releases/download/v3.2/app-admin-release.apk",
        apk_sha256: "f275b145cd1e82626407fe895d68a8cada44cdaea43ec857759a6d6cb8f10a29",
        signing_cert_sha256: "",
        abi_assets: {},
        is_active: true,
      },
    ],
    app_crashes: [],
    notifications: [],
    remote_config: {
      auth_require_account: { value: false, sensitive: true, desc: "Require account login before VPN connection" },
      auto_block_on_device_violation: { value: false, sensitive: true, desc: "Auto-block account on unauthorized device" },
      auto_failover_enabled: { value: true, sensitive: false, desc: "Smart 2s Auto-Failover to fastest verified backup server" },
      trial_duration_hours: { value: 48, sensitive: false, desc: "Server-controlled trial duration (hours)" },
      promo_enabled: { value: true, sensitive: false, desc: "Enable 5-slot rotating startup banner" },
      log_retention_days: { value: 90, sensitive: false, desc: "Telemetry & log retention days" },
    },
    disabled_server_uris: [],
    admin_audit_logs: [],
  };
}

function ensureVaultV31Defaults(db) {
  if (!db) return createEmptyDb();
  db.bundle_release = "3.2";
  if (!db.vip_key_hex || db.vip_key_hex.length !== 64) {
    db.vip_key_hex = EnterpriseWebCrypto.randomHex(32);
  }
  if (!Array.isArray(db.vip_servers)) db.vip_servers = [];
  if (!db.remote_config) db.remote_config = {};
  if (!db.remote_config.auto_failover_enabled) {
    db.remote_config.auto_failover_enabled = {
      value: true,
      sensitive: false,
      desc: "Proactive Smart Auto-Failover v3.2 to fastest verified backup server",
    };
  }
  if (Array.isArray(db.app_versions) && !db.app_versions.some((v) => v.version_name === "3.2")) {
    const defaults = createEmptyDb().app_versions;
    db.app_versions.forEach((v) => { v.is_active = false; });
    db.app_versions.unshift(...defaults);
  }
  return db;
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
      AppState.db = ensureVaultV31Defaults(JSON.parse(decrypted));
    } else if (!AppState.db) {
      AppState.db = createEmptyDb();
    }

    if (!AppState.db.signing_keys) {
      AppState.db.signing_keys = await EnterpriseWebCrypto.generateEcdsaP256KeyPair();
    }
    if (statusEl) statusEl.textContent = t("متصل بـ GitHub (v3.2) ✓", "Synced with GitHub (v3.2) ✓");
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
    ensureVaultV31Defaults(AppState.db);
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

    // 2. Encrypt Active VIP Private Nodes with 256-bit AES-GCM (Zero plaintext URIs in bundle.json)
    const activeVip = (AppState.db.vip_servers || [])
      .filter((s) => s.enabled !== false)
      .sort((a, b) => (b.priority || 100) - (a.priority || 100))
      .map((s) => ({
        id: s.id,
        label: s.label,
        country: s.country || "",
        protocol: s.protocol || "VLESS",
        uri: s.uri,
        priority: s.priority || 100,
      }));
    const vipEncB64 = activeVip.length > 0
      ? await EnterpriseWebCrypto.encryptRawKeyAesGcm(
          AppState.db.vip_key_hex,
          EnterpriseWebCrypto.canonicalJson(activeVip),
          EnterpriseWebCrypto.VIP_NODES_AAD
        )
      : "";

    // 3. Build & ECDSA P-256 Sign Zero-Knowledge Public Client Bundle
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
      bundle_release: "3.2",
      generated_at: new Date().toISOString(),
      public_key_spki_b64: AppState.db.signing_keys.publicSpkiB64,
      remote_config: rcFlat,
      app_updates: AppState.db.app_versions.filter((v) => v.is_active),
      vip_nodes_enc_b64: vipEncB64,
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
      `chore(bundle): sign & publish v3.2 client bundle`
    );
    AppState.bundleSha = bundlePut.content?.sha || AppState.bundleSha;

    if (statusEl) statusEl.textContent = t("تم الحفظ والتوقيع على GitHub (v3.2) ✓", "Encrypted & Signed on GitHub (v3.2) ✓");
    renderAll();
  } catch (err) {
    alert(t("تعذّر النشر على GitHub: ", "Publish failed: ") + err.message);
  }
}

async function rebuildUserSignedEnvelope(userObj, plainPassword) {
  ensureVaultV31Defaults(AppState.db);
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
    vip_access_key_hex: AppState.db.vip_key_hex,
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
