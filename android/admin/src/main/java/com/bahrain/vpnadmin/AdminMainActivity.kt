// =====================================================================
// AdminMainActivity.kt — تطبيق الإدارة المستقل (bahrain-vpn Admin APK)
// يوفر تحكمًا فوريًا بمشتركي المنصة، التجارب المجانية 48 ساعة، الأجهزة،
// الخوادم، الإعدادات البعيدة، وتقارير الذكاء الاصطناعي عبر GitHub حصريًا.
// =====================================================================
package com.bahrain.vpnadmin

import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material.icons.filled.Devices
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.People
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant

class AdminMainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val vaultMgr = AdminGitHubVaultManager(applicationContext)
        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
                    AdminRootApp(vaultMgr)
                }
            }
        }
    }
}

private val SUB_HOURS = mapOf(
    "FREE_TRIAL" to 48L,
    "DAILY" to 24L,
    "WEEKLY" to 168L,
    "MONTHLY" to 720L,
    "THREE_MONTHS" to 2160L,
    "SIX_MONTHS" to 4320L,
    "YEARLY" to 8760L,
    "LIFETIME" to null,
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AdminRootApp(vaultMgr: AdminGitHubVaultManager) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val savedCreds = remember { vaultMgr.loadEncryptedCredentials() }

    var unlocked by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var repoFull by remember { mutableStateOf(savedCreds?.first ?: "oldman-552/vpn-configs") }
    var ghToken by remember { mutableStateOf(savedCreds?.second ?: "") }
    var adminUser by remember { mutableStateOf(savedCreds?.third ?: "admin") }
    var vaultPass by remember { mutableStateOf("") }
    var totpCode by remember { mutableStateOf("") }

    var vaultSha by remember { mutableStateOf<String?>(null) }
    var bundleSha by remember { mutableStateOf<String?>(null) }
    var dbState by remember { mutableStateOf(vaultMgr.createEmptyVaultDb()) }
    var liveMeta by remember { mutableStateOf<JSONObject?>(null) }
    var liveServersCount by remember { mutableIntStateOf(0) }
    var uiTick by remember { mutableIntStateOf(0) }
    var tab by remember { mutableIntStateOf(0) }

    fun toast(msg: String) = Toast.makeText(ctx, msg, Toast.LENGTH_SHORT).show()

    fun syncAndUnlock() {
        if (repoFull.isBlank() || vaultPass.length < 6) {
            toast("أدخل المستودع وعبارة تشفير الخزنة (6+ أحرف)")
            return
        }
        busy = true
        scope.launch {
            runCatching {
                val (_, metaObj) = vaultMgr.readGitHubJson(repoFull, ghToken, "data", "meta.json")
                val (_, aliveObj) = vaultMgr.readGitHubJson(repoFull, ghToken, "data", "alive.json")
                val (vSha, vEnc) = vaultMgr.readGitHubJson(repoFull, ghToken, "data", "enterprise/admin_vault.enc.json")
                val (bSha, _) = vaultMgr.readGitHubJson(repoFull, ghToken, "data", "enterprise/bundle.json")

                val loadedDb = if (vEnc != null) {
                    val plain = AdminCrypto.decryptAesGcm(
                        vaultPass,
                        vEnc.getString("salt_hex"),
                        vEnc.getString("ciphertext_b64"),
                        "bahrain-vpn-admin-vault-v3",
                    )
                    JSONObject(plain)
                } else {
                    vaultMgr.createEmptyVaultDb()
                }

                // Enforce RFC 6238 TOTP 2FA if configured on admin record
                val admins = loadedDb.optJSONArray("admin_users") ?: JSONArray()
                for (i in 0 until admins.length()) {
                    val a = admins.getJSONObject(i)
                    if (a.optString("username").equals(adminUser.trim(), ignoreCase = true)) {
                        val sec = a.optString("totp_secret", "")
                        if (sec.isNotBlank() && !AdminCrypto.verifyTotpCode(sec, totpCode)) {
                            throw SecurityException("رمز المصادقة الثنائية TOTP 2FA غير صحيح")
                        }
                    }
                }

                vaultSha = vSha
                bundleSha = bSha
                liveMeta = metaObj
                liveServersCount = aliveObj?.optJSONArray("servers")?.length() ?: (metaObj?.optInt("alive") ?: 0)
                dbState = loadedDb
                vaultMgr.saveEncryptedCredentials(repoFull, ghToken, adminUser)
                unlocked = true
                uiTick++
            }.onFailure { err ->
                toast("تعذّر الفتح: ${err.message}")
            }
            busy = false
        }
    }

    fun publishChanges(reason: String) {
        if (ghToken.isBlank()) {
            toast("أدخل GitHub Token للكتابة المباشرة على المستودع")
            return
        }
        busy = true
        scope.launch {
            runCatching {
                val saltHex = AdminCrypto.randomHex(16)
                val ctB64 = AdminCrypto.encryptAesGcm(vaultPass, saltHex, dbState.toString(), "bahrain-vpn-admin-vault-v3")
                val encVault = JSONObject()
                    .put("v", 3)
                    .put("alg", "PBKDF2-SHA256+AES-256-GCM")
                    .put("updated_at", Instant.now().toString())
                    .put("salt_hex", saltHex)
                    .put("ciphertext_b64", ctB64)

                vaultSha = vaultMgr.writeGitHubJson(
                    repoFull,
                    ghToken,
                    "data",
                    "enterprise/admin_vault.enc.json",
                    encVault,
                    vaultSha,
                    "chore(admin-apk): $reason",
                ) ?: vaultSha

                val pubBundle = vaultMgr.buildSignedPublicBundle(dbState)
                bundleSha = vaultMgr.writeGitHubJson(
                    repoFull,
                    ghToken,
                    "data",
                    "enterprise/bundle.json",
                    pubBundle,
                    bundleSha,
                    "chore(bundle): sign & publish from Admin APK",
                ) ?: bundleSha

                uiTick++
                toast("تم التشفير والتوقيع والنشر على GitHub ✓")
            }.onFailure { err ->
                toast("خطأ أثناء النشر: ${err.message}")
            }
            busy = false
        }
    }

    if (!unlocked) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Spacer(Modifier.height(28.dp))
            Text("ULTIMATE VPN ADMIN", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.ExtraBold)
            Text("مركز الإدارة المشفّر عبر GitHub + مصادقة ثنائية TOTP 2FA", style = MaterialTheme.typography.bodySmall)
            OutlinedTextField(value = repoFull, onValueChange = { repoFull = it }, label = { Text("مستودع GitHub") }, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(
                value = ghToken,
                onValueChange = { ghToken = it },
                label = { Text("GitHub Token (يُحفظ مشفّرًا في Keystore فقط)") },
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = vaultPass,
                onValueChange = { vaultPass = it },
                label = { Text("عبارة التشفير الرئيسية للخزنة (AES-256-GCM)") },
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(value = adminUser, onValueChange = { adminUser = it }, label = { Text("اسم المشرف") }, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(value = totpCode, onValueChange = { totpCode = it }, label = { Text("رمز 2FA TOTP (6 أرقام إن فُعّل)") }, modifier = Modifier.fillMaxWidth())
            Button(onClick = { syncAndUnlock() }, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
                Text(if (busy) "جارٍ فك التشفير والمزامنة…" else "الدخول إلى لوحة المشرف")
            }
        }
        return
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("ULTIMATE VPN ADMIN", fontWeight = FontWeight.Bold) },
                actions = {
                    OutlinedButton(onClick = { syncAndUnlock() }, enabled = !busy) { Text("مزامنة") }
                },
            )
        },
        bottomBar = {
            NavigationBar {
                NavigationBarItem(selected = tab == 0, onClick = { tab = 0 }, icon = { Icon(Icons.Filled.Dashboard, null) }, label = { Text("الرئيسية") })
                NavigationBarItem(selected = tab == 1, onClick = { tab = 1 }, icon = { Icon(Icons.Filled.People, null) }, label = { Text("المشتركون") })
                NavigationBarItem(selected = tab == 2, onClick = { tab = 2 }, icon = { Icon(Icons.Filled.Devices, null) }, label = { Text("الأجهزة") })
                NavigationBarItem(selected = tab == 3, onClick = { tab = 3 }, icon = { Icon(Icons.Filled.Dns, null) }, label = { Text("الخوادم") })
                NavigationBarItem(selected = tab == 4, onClick = { tab = 4 }, icon = { Icon(Icons.Filled.Tune, null) }, label = { Text("الإعدادات") })
            }
        },
    ) { pad ->
        // Reference uiTick so Compose recomposes after JSONObject mutations
        val _tick = uiTick
        val usersArr = dbState.optJSONArray("users") ?: JSONArray()
        val devsArr = dbState.optJSONArray("user_devices") ?: JSONArray()

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(pad)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            when (tab) {
                0 -> {
                    Card(shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            Text("المؤشرات الفورية للمنصة ($_tick)", fontWeight = FontWeight.Bold)
                            Text("• إجمالي الحسابات المسجّلة: ${usersArr.length()}")
                            Text("• الأجهزة المسجّلة: ${devsArr.length()}")
                            Text("• الخوادم الحيّة (@data): $liveServersCount (المختبرة: ${liveMeta?.optInt("tested") ?: 0})")
                            Text("• سلامة سلسلة التدقيق SHA-256: ${if (vaultMgr.verifyAuditChain(dbState)) "سليمة ✓" else "تحذير!"}")
                        }
                    }
                    Card(shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text("مركز الذكاء الاصطناعي والأوامر السحابية", fontWeight = FontWeight.Bold)
                            Text(
                                if (liveServersCount > 0) "الدليل الفعلي: $liveServersCount عقدة متاحة حاليًا. يوصى بإبقاء الفرز التلقائي على الأسرع تنزيلًا."
                                else "لا تتوفر عينات كافية بعد (INSUFFICIENT_DATA) — شغّل فحص السيرفرات.",
                                style = MaterialTheme.typography.bodySmall,
                            )
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Button(onClick = {
                                    scope.launch {
                                        val ok = runCatching { vaultMgr.triggerGitHubWorkflow(repoFull, ghToken, "data.yml") }.getOrDefault(false)
                                        toast(if (ok) "تم تشغيل تحديث السيرفرات" else "تعذّر تشغيل سير العمل")
                                    }
                                }) { Text("تحديث السيرفرات") }
                                OutlinedButton(onClick = {
                                    scope.launch {
                                        val ok = runCatching { vaultMgr.triggerGitHubWorkflow(repoFull, ghToken, "apk.yml") }.getOrDefault(false)
                                        toast(if (ok) "تم تشغيل بناء APK" else "تعذّر تشغيل البناء")
                                    }
                                }) { Text("بناء APK") }
                            }
                        }
                    }
                }

                1 -> {
                    var newU by remember { mutableStateOf("") }
                    var newP by remember { mutableStateOf("") }
                    var selPlan by remember { mutableStateOf("FREE_TRIAL") }
                    var newDev by remember { mutableStateOf("") }

                    Card(shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text("إنشاء مشترك أو تفعيل تجربة 48 ساعة", fontWeight = FontWeight.Bold)
                            OutlinedTextField(value = newU, onValueChange = { newU = it }, label = { Text("اسم المستخدم") }, modifier = Modifier.fillMaxWidth())
                            OutlinedTextField(value = newP, onValueChange = { newP = it }, label = { Text("كلمة المرور (6+)") }, modifier = Modifier.fillMaxWidth())
                            OutlinedTextField(value = newDev, onValueChange = { newDev = it }, label = { Text("رمز جهاز اختياري (inst_...)") }, modifier = Modifier.fillMaxWidth())
                            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                listOf("FREE_TRIAL", "MONTHLY", "YEARLY", "LIFETIME").forEach { plan ->
                                    FilterChip(selected = selPlan == plan, onClick = { selPlan = plan }, label = { Text(plan) })
                                }
                            }
                            Button(
                                onClick = {
                                    val clean = newU.trim().lowercase()
                                    if (clean.length < 3 || newP.length < 6) {
                                        toast("تحقق من اسم المستخدم وكلمة المرور")
                                        return@Button
                                    }
                                    val now = Instant.now()
                                    val hrs = SUB_HOURS[selPlan]
                                    val exp = if (hrs != null) now.plusSeconds(hrs * 3600L).toString() else ""
                                    val uid = "usr_${AdminCrypto.randomHex(6)}"
                                    val uObj = JSONObject()
                                        .put("id", uid)
                                        .put("username", clean)
                                        .put("account_status", if (selPlan == "FREE_TRIAL") "FREE_TRIAL" else "ACTIVE")
                                        .put("subscription_type", selPlan)
                                        .put("subscription_start", now.toString())
                                        .put("subscription_expiration", exp)
                                        .put("device_limit", 1)
                                        .put("updated_at", now.toString())
                                    if (newDev.isNotBlank()) {
                                        devsArr.put(
                                            JSONObject()
                                                .put("id", "dev_${AdminCrypto.randomHex(5)}")
                                                .put("user_id", uid)
                                                .put("device_install_id", newDev.trim())
                                                .put("device_status", "AUTHORIZED")
                                        )
                                    }
                                    vaultMgr.sealUserEnvelope(dbState, uObj, newP)
                                    usersArr.put(uObj)
                                    vaultMgr.appendAuditLog(dbState, adminUser, "USER_CREATE", "users", uid, JSONObject().put("u", clean))
                                    publishChanges("create user $clean")
                                },
                                modifier = Modifier.fillMaxWidth(),
                            ) { Text("إنشاء وتوقيع الشهادة ونشرها") }
                        }
                    }

                    for (i in 0 until usersArr.length()) {
                        val u = usersArr.getJSONObject(i)
                        Card(shape = RoundedCornerShape(14.dp), modifier = Modifier.fillMaxWidth()) {
                            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text("${u.optString("username")} • ${u.optString("account_status")}", fontWeight = FontWeight.Bold)
                                Text("الباقة: ${u.optString("subscription_type")} • الانتهاء: ${u.optString("subscription_expiration").ifBlank { "مدى الحياة" }}", style = MaterialTheme.typography.bodySmall)
                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    OutlinedButton(onClick = {
                                        val nextSt = if (u.optString("account_status") == "BLOCKED") "ACTIVE" else "BLOCKED"
                                        u.put("account_status", nextSt)
                                        if (nextSt == "BLOCKED") u.put("session_revoked_at", Instant.now().toString())
                                        u.put("updated_at", Instant.now().toString())
                                        vaultMgr.appendAuditLog(dbState, adminUser, "USER_$nextSt", "users", u.optString("id"), JSONObject())
                                        publishChanges("status $nextSt")
                                    }) { Text(if (u.optString("account_status") == "BLOCKED") "فك الحظر" else "حظر فوري") }

                                    OutlinedButton(onClick = {
                                        u.put("session_revoked_at", Instant.now().toString())
                                        vaultMgr.appendAuditLog(dbState, adminUser, "REVOKE_SESSION", "users", u.optString("id"), JSONObject())
                                        publishChanges("revoke session")
                                    }) { Text("قطع الجلسة") }
                                }
                            }
                        }
                    }
                }

                2 -> {
                    Card(shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text("الأجهزة الموثّقة (${devsArr.length()})", fontWeight = FontWeight.Bold)
                            for (i in 0 until devsArr.length()) {
                                val d = devsArr.getJSONObject(i)
                                HorizontalDivider()
                                Row(
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically,
                                    modifier = Modifier.fillMaxWidth(),
                                ) {
                                    Column(Modifier.weight(1f)) {
                                        Text(d.optString("device_install_id"), style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
                                        Text("الحالة: ${d.optString("device_status")}", style = MaterialTheme.typography.labelSmall)
                                    }
                                    OutlinedButton(onClick = {
                                        d.put("device_status", "REVOKED")
                                        vaultMgr.appendAuditLog(dbState, adminUser, "DEVICE_REVOKE", "user_devices", d.optString("id"), JSONObject())
                                        publishChanges("revoke device")
                                    }) { Text("إلغاء") }
                                }
                            }
                        }
                    }
                }

                3 -> {
                    val audits = dbState.optJSONArray("admin_audit_logs") ?: JSONArray()
                    Card(shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            Text("ملخص الخوادم الحيّة (@data)", fontWeight = FontWeight.Bold)
                            Text("الخوادم النشطة: $liveServersCount • آخر تحديث: ${liveMeta?.optString("generated_at") ?: "—"}")
                        }
                    }
                    Card(shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            Text("سجل التدقيق الأمني المتسلسل (${audits.length()})", fontWeight = FontWeight.Bold)
                            for (i in 0 until minOf(audits.length(), 15)) {
                                val a = audits.getJSONObject(i)
                                Text("• ${a.optString("action")} (${a.optString("admin")}) — ${a.optString("entry_hash").take(10)}…", style = MaterialTheme.typography.labelSmall)
                            }
                        }
                    }
                }

                else -> {
                    val rc = dbState.optJSONObject("remote_config") ?: JSONObject()
                    Card(shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                            Text("الإعدادات البعيدة الموقّعة (Remote Config)", fontWeight = FontWeight.Bold)
                            rc.keys().forEach { key ->
                                val item = rc.getJSONObject(key)
                                val curVal = item.opt("value")
                                Row(
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically,
                                    modifier = Modifier.fillMaxWidth(),
                                ) {
                                    Column(Modifier.weight(1f)) {
                                        Text(key, fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.bodySmall)
                                        Text("${item.optString("desc")} = $curVal", style = MaterialTheme.typography.labelSmall)
                                    }
                                    if (curVal is Boolean) {
                                        OutlinedButton(onClick = {
                                            item.put("value", !curVal)
                                            vaultMgr.appendAuditLog(dbState, adminUser, "REMOTE_CONFIG", key, key, JSONObject().put("v", !curVal))
                                            publishChanges("toggle $key")
                                        }) { Text("تبديل") }
                                    }
                                }
                            }
                            HorizontalDivider()
                            Button(
                                onClick = {
                                    val sec = AdminCrypto.generateTotpSecretB32()
                                    val admins = dbState.optJSONArray("admin_users") ?: JSONArray().also { dbState.put("admin_users", it) }
                                    admins.put(JSONObject().put("username", adminUser.trim().lowercase()).put("role", "SUPER_ADMIN").put("totp_secret", sec))
                                    vaultMgr.appendAuditLog(dbState, adminUser, "ENABLE_2FA", "admin_users", adminUser, JSONObject())
                                    toast("مفتاح TOTP 2FA: $sec")
                                    publishChanges("enable admin 2fa")
                                },
                                modifier = Modifier.fillMaxWidth(),
                            ) { Text("توليد وتفعيل مفتاح مصادقة ثنائية TOTP 2FA") }
                        }
                    }
                }
            }
        }
    }
}
