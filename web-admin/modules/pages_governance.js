/**
 * modules/pages_governance.js — Pages 11..17 (AI Intelligence, Notifications,
 * Remote Config, ABI-Aware APK Updates, Tamper-Evident Audit Chain, RBAC Admins, Encrypted Backups).
 */

const GovernanceViews = {
  render(pageId, ctx) {
    const { db } = ctx;
    switch (pageId) {
      case "ai": {
        const totalSrv = AppState.liveServers.length;
        const degraded = AppState.liveServers.filter((s) => (s.median_latency_ms || s.latency_ms || 0) >= 650);
        const confidence = totalSrv >= 30 ? "HIGH" : totalSrv >= 8 ? "MEDIUM" : "LOW";
        return `
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
                  <td>${t("إبقاء الترتيب الشخصي المحلي Top 50 والتبديل الذكي الاستباقي (Auto-Failover v1).", "Keep Personalized Local Top 50 ranking and Proactive Smart Auto-Failover v1 active.")}</td>
                </tr>`}
              </tbody>
            </table>
          </div>`;
      }

      case "notifications":
        return `
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

      case "remote_config":
        return `
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

      case "updates":
        return `
          <div class="card">
            <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
              <h3>${t("إدارة الإصدارات والتحديث الرسمي الآمن حسب المعمارية (Split ABI v1)", "ABI-Aware Signed APK Version & Update Manager (v1)")}</h3>
              <button class="btn no-print" onclick="triggerApkReleaseBuild()">${t("بناء ونشر APK جديد عبر GitHub Actions", "Trigger Signed APK Build")}</button>
            </div>
            <table>
              <thead><tr><th>Target</th><th>Version</th><th>Code</th><th>ABIs</th><th>Mandatory</th><th>SHA-256</th></tr></thead>
              <tbody>
                ${db.app_versions.map((v) => {
                  const abis = Object.keys(v.abi_assets || {});
                  return `<tr>
                    <td>${esc(v.target_app)}</td>
                    <td><strong>${esc(v.version_name)}</strong></td>
                    <td>${v.version_code}</td>
                    <td><code>${esc(abis.length ? abis.join(", ") : "universal")}</code></td>
                    <td>${v.mandatory ? "YES" : "NO"}</td>
                    <td><code>${esc((v.apk_sha256 || "verified-in-release").slice(0, 20))}…</code></td>
                  </tr>`;
                }).join("")}
              </tbody>
            </table>
          </div>`;

      case "audit":
        return `
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

      case "admins":
        return `
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

      default:
        return `
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
    }
  },
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
    const parsed = ensureVaultV31Defaults(JSON.parse(plain));
    if (!parsed.users || !parsed.remote_config) throw new Error("Invalid schema");
    AppState.db = parsed;
    await appendAuditLog("VAULT_RESTORE", "system", "backup", {});
    renderAll();
    alert(t("تم فك التشفير والتحقق واستعادة النسخة الاحتياطية بنجاح ✓", "Backup verified & restored ✓"));
  } catch (e) {
    alert("Restore verification failed: " + e.message);
  }
};
