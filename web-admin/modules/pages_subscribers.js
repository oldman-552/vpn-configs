/**
 * modules/pages_subscribers.js — Pages 1..5 (Overview, Users, Subscriptions, Devices, Sessions)
 * and Subscriber/Device Interactive Mutations.
 */

const SubscribersViews = {
  render(pageId, ctx) {
    const { db, q, activeSessions, authDevices, uniqueActiveDevs, uniqueActiveUsers, onlineServers } = ctx;
    switch (pageId) {
      case "overview": {
        const protoCounts = AppState.liveMeta?.alive_by_protocol || {};
        const maxProto = Math.max(1, ...Object.values(protoCounts));
        const vipCount = (db.vip_servers || []).filter((s) => s.enabled !== false).length;
        const barsHtml = Object.entries(protoCounts)
          .map(
            ([proto, cnt]) => `<div class="bar-col">
              <span style="font-size:0.75rem">${cnt}</span>
              <div class="bar-fill" style="height:${Math.max(8, Math.round((cnt / maxProto) * 110))}px"></div>
              <span style="font-size:0.75rem;color:var(--muted)">${esc(proto)}</span>
            </div>`
          )
          .join("");

        return `
          <div class="kpi-grid">
            <div class="card"><div class="kpi-label">${t("إجمالي الحسابات المسجّلة", "Registered Accounts")}</div><div class="kpi-val">${db.users.length}</div></div>
            <div class="card"><div class="kpi-label">${t("الأجهزة الموثّقة المسجّلة", "Registered Devices")}</div><div class="kpi-val">${authDevices.length}</div></div>
            <div class="card"><div class="kpi-label">${t("الأجهزة المتصلة حاليًا", "Active Devices")}</div><div class="kpi-val">${uniqueActiveDevs}</div></div>
            <div class="card"><div class="kpi-label">${t("جلسات VPN النشطة", "Active VPN Sessions")}</div><div class="kpi-val">${activeSessions.length}</div></div>
            <div class="card"><div class="kpi-label">${t("المشتركون الفريدون المتصلون", "Unique Connected Users")}</div><div class="kpi-val">${uniqueActiveUsers}</div></div>
            <div class="card"><div class="kpi-label">${t("الخوادم الحيّة / المختبرة", "Online / Tested Servers")}</div><div class="kpi-val">${onlineServers.length} / ${AppState.liveMeta?.tested || 0}</div></div>
            <div class="card"><div class="kpi-label">${t("سيرفرات VIP المشفّرة الخاصة", "Encrypted VIP Private Nodes")}</div><div class="kpi-val">${vipCount}</div></div>
            <div class="card"><div class="kpi-label">${t("التجارب المجانية النشطة (48h)", "Active 48h Free Trials")}</div><div class="kpi-val">${db.users.filter((u) => u.account_status === "FREE_TRIAL").length}</div></div>
          </div>
          <div class="card">
            <h3>${t("توزيع البروتوكولات الحيّة على فرع البيانات (@data)", "Live Protocol Distribution (@data)")}</h3>
            <div class="chart-bars">${barsHtml || `<p style="color:var(--muted)">${t("لا توجد بيانات حيّة محمّلة بعد", "No live protocol telemetry loaded yet")}</p>`}</div>
          </div>`;
      }

      case "users": {
        const filtered = db.users.filter((u) => !q || u.username.includes(q) || u.account_status.toLowerCase().includes(q));
        return `
          <div class="card no-print">
            <h3>${t("إنشاء حساب مشترك جديد وتوقيع شهادته رقميًا (ECDSA P-256 + مفتاح VIP)", "Create Subscriber & Sign License Envelope (+ VIP Access)")}</h3>
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
      }

      case "subscriptions":
        return `
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

      case "devices":
        return `
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

      case "sessions":
        return `
          <div class="card">
            <h3>${t("مراقب الجلسات وإلغاء الجلسات عن بعد", "Active Sessions & Remote Revocation")}</h3>
            <p style="color:var(--muted);margin-top:6px">${t("إلغاء جلسة أي مشترك يحدّث ختم session_revoked_at في الحزمة الموقّعة فيقطع النفق ويحجب عقد VIP تلقائيًا.", "Revoking updates session_revoked_at in the signed bundle to terminate client tunnels and revoke VIP nodes.")}</p>
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

      default:
        return null;
    }
  },
};

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
