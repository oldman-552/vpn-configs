/**
 * app.js — Modular 17-Page Bilingual (AR/EN RTL/LTR) Enterprise Admin Router (v1).
 * Delegates state/sync to `modules/state_and_sync.js` and view rendering to
 * `modules/pages_subscribers.js`, `modules/pages_infrastructure.js`, and `modules/pages_governance.js`.
 */

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

  const viewCtx = {
    db,
    q,
    activeSessions,
    authDevices,
    uniqueActiveDevs,
    uniqueActiveUsers,
    onlineServers,
  };

  container.innerHTML =
    SubscribersViews.render(AppState.activePage, viewCtx) ??
    InfrastructureViews.render(AppState.activePage, viewCtx) ??
    GovernanceViews.render(AppState.activePage, viewCtx);
}

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
