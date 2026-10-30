// =====================================================================
// EnterpriseScreens.kt — واجهة حساب المشترك، العدّاد التنازلي لتجربة 48 ساعة،
// استوديو قياس السرعة الحقيقي عبر النفق، تشخيص التسريبات، وصحة وتحديثات التطبيق.
// =====================================================================
package com.bahrain.vpnconfigs.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountCircle
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.HealthAndSafety
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.NetworkCheck
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.SystemUpdate
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.bahrain.vpnconfigs.vpn.VpnPhase
import com.bahrain.vpnconfigs.vpn.VpnStatus
import kotlinx.coroutines.delay
import java.util.Locale

@Composable
fun MandatoryLoginGateDialog(
    vm: AppViewModel,
    state: UiState,
    onCopyDeviceId: (String) -> Unit,
) {
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var rememberMe by remember { mutableStateOf(true) }
    var showResetHelp by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = { /* إلزامي عند تفعيل اشتراط الحساب من المشرف */ },
        icon = { Icon(Icons.Filled.Lock, contentDescription = null) },
        title = { Text("تسجيل الدخول الإلزامي", fontWeight = FontWeight.Bold) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "يلزم تسجيل الدخول بحساب فعّال أو فترة تجريبية (48 ساعة) للوصول إلى خوادم الـ VPN.",
                    style = MaterialTheme.typography.bodySmall,
                )
                OutlinedTextField(
                    value = username,
                    onValueChange = { username = it },
                    label = { Text("اسم المستخدم") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text("كلمة المرور") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier.fillMaxWidth(),
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = rememberMe, onCheckedChange = { rememberMe = it })
                    Text("تذكّرني بأمان (تشفير Android Keystore)", style = MaterialTheme.typography.bodySmall)
                }
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        "رمز الجهاز: ${state.accountState.deviceInstallId.take(16)}…",
                        style = MaterialTheme.typography.labelSmall,
                    )
                    TextButton(onClick = { onCopyDeviceId(state.accountState.deviceInstallId) }) {
                        Text("نسخ الرمز")
                    }
                }
                if (showResetHelp) {
                    Text(
                        "لإعادة تعيين كلمة المرور أو تفعيل جهاز جديد، أرسل اسم المستخدم ورمز جهازك للمشرف لإصدار شهادة محدّثة.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary,
                    )
                } else {
                    TextButton(onClick = { showResetHelp = true }) {
                        Text("نسيت كلمة المرور؟")
                    }
                }
                state.authError?.let { err ->
                    Text(err, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
            }
        },
        confirmButton = {
            Button(
                onClick = { vm.loginEnterpriseAccount(username, password, rememberMe) },
                enabled = !state.authLoading,
            ) {
                Text(if (state.authLoading) "جارٍ التحقق…" else "تسجيل الدخول")
            }
        },
        dismissButton = {
            OutlinedButton(onClick = { vm.syncEnterpriseBundle() }) {
                Text("تحديث التراخيص")
            }
        },
    )
}

@Composable
fun EnterpriseHubScreen(
    state: UiState,
    vpnStatus: VpnStatus,
    vm: AppViewModel,
    modifier: Modifier = Modifier,
    onCopy: (String, String) -> Unit,
) {
    val scroll = rememberScrollState()
    val acct = state.accountState
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var rememberMe by remember { mutableStateOf(true) }
    var testUrlInput by remember { mutableStateOf("https://1.1.1.1") }

    // عدّاد حيّ بالثواني للفترة التجريبية 48 ساعة والاشتراك
    var liveRemainingSec by remember(acct.remainingSeconds) {
        mutableLongStateOf(acct.remainingSeconds ?: -1L)
    }
    LaunchedEffect(acct.remainingSeconds, acct.isLoggedIn) {
        liveRemainingSec = acct.remainingSeconds ?: -1L
        while (acct.isLoggedIn && liveRemainingSec > 0L) {
            delay(1000L)
            liveRemainingSec = (liveRemainingSec - 1L).coerceAtLeast(0L)
            if (liveRemainingSec == 0L) {
                vm.refreshEnterpriseState()
            }
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(scroll)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        // 1. بطاقة التحديثات الرسمية الموقّعة (إن توفّر إصدار أحدث)
        state.availableUpdate?.let { upd ->
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = if (upd.mandatory) MaterialTheme.colorScheme.errorContainer
                    else MaterialTheme.colorScheme.primaryContainer
                ),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Filled.SystemUpdate, contentDescription = null)
                        Spacer(Modifier.width(8.dp))
                        Text(
                            text = if (upd.mandatory) "تحديث أمني إلزامي (${upd.versionName})" else "تحديث جديد متاح (${upd.versionName})",
                            fontWeight = FontWeight.Bold,
                        )
                    }
                    if (upd.releaseNotes.isNotBlank()) {
                        Text(upd.releaseNotes, style = MaterialTheme.typography.bodySmall)
                    }
                    Button(
                        onClick = { vm.downloadAndInstallSignedUpdate() },
                        enabled = !state.updatingApk,
                    ) {
                        Text(if (state.updatingApk) "جارٍ التحقق من بصمة SHA-256 والتنزيل…" else "تنزيل وتثبيت رسمي آمن")
                    }
                }
            }
        }

        // 2. بطاقة الحساب، التجربة المجانية 48 ساعة، وترخيص الجهاز الواحد
        Card(
            shape = RoundedCornerShape(18.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Filled.AccountCircle, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                        Spacer(Modifier.width(8.dp))
                        Text("الحساب والترخيص المؤسسي", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                    }
                    TextButton(onClick = { vm.syncEnterpriseBundle() }) {
                        Text("مزامنة")
                    }
                }

                // رمز تثبيت الجهاز العشوائي الفريد (1 Account = 1 Device)
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(10.dp))
                        .padding(horizontal = 12.dp, vertical = 6.dp),
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("معرّف ربط الجهاز (1 حساب = ${acct.deviceLimit} جهاز)", style = MaterialTheme.typography.labelSmall)
                        Text(acct.deviceInstallId, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Medium)
                    }
                    IconButton(onClick = { onCopy(acct.deviceInstallId, "تم نسخ رمز الجهاز") }) {
                        Icon(Icons.Filled.ContentCopy, contentDescription = "نسخ رمز الجهاز")
                    }
                }

                if (acct.isLoggedIn) {
                    val statusColor = when (acct.accountStatus) {
                        "ACTIVE" -> Color(0xFF2E7D32)
                        "FREE_TRIAL" -> Color(0xFF1565C0)
                        else -> Color(0xFFC62828)
                    }
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(statusColor.copy(alpha = 0.14f), RoundedCornerShape(12.dp))
                            .padding(12.dp),
                    ) {
                        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text(acct.statusHeadlineEn, fontWeight = FontWeight.Bold, color = statusColor)
                            Text(acct.statusDetailAr, style = MaterialTheme.typography.bodySmall)
                            Text("المشترك: ${acct.username} • الباقة: ${acct.subscriptionType}", style = MaterialTheme.typography.labelMedium)
                            if (liveRemainingSec >= 0L) {
                                val hrs = liveRemainingSec / 3600L
                                val mins = (liveRemainingSec % 3600L) / 60L
                                val secs = liveRemainingSec % 60L
                                Text(
                                    String.format(Locale.US, "العدّاد الزمني المتبقّي: %02dh : %02dm : %02ds", hrs, mins, secs),
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = FontWeight.SemiBold,
                                    color = statusColor,
                                )
                            }
                        }
                    }

                    // حدود السرعة وحصة الاستهلاك اليومية/الشهرية
                    val dayMb = acct.dailyUsedBytes / (1024.0 * 1024.0)
                    val monthMb = acct.monthlyUsedBytes / (1024.0 * 1024.0)
                    Text(
                        String.format(
                            Locale.US,
                            "استهلاك اليوم: %.1f MB%s  •  الشهر: %.1f MB%s",
                            dayMb,
                            if (acct.bandwidth.maxDailyMb > 0) " / ${acct.bandwidth.maxDailyMb} MB" else "",
                            monthMb,
                            if (acct.bandwidth.maxMonthlyMb > 0) " / ${acct.bandwidth.maxMonthlyMb} MB" else "",
                        ),
                        style = MaterialTheme.typography.bodySmall,
                    )
                    if (acct.bandwidth.maxDailyMb > 0) {
                        LinearProgressIndicator(
                            progress = { (dayMb.toFloat() / acct.bandwidth.maxDailyMb.toFloat()).coerceIn(0f, 1f) },
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                    if (acct.bandwidth.maxDownloadKbps > 0 || acct.bandwidth.maxUploadKbps > 0) {
                        Text(
                            "سقف السرعة المخصّص: ↓ ${acct.bandwidth.maxDownloadKbps} KB/s • ↑ ${acct.bandwidth.maxUploadKbps} KB/s",
                            style = MaterialTheme.typography.labelSmall,
                        )
                    }

                    OutlinedButton(onClick = { vm.logoutEnterpriseAccount() }, modifier = Modifier.fillMaxWidth()) {
                        Text("تسجيل الخروج وإلغاء الجلسة المحلية")
                    }
                } else {
                    Text(acct.statusDetailAr, style = MaterialTheme.typography.bodySmall)
                    OutlinedTextField(
                        value = username,
                        onValueChange = { username = it },
                        label = { Text("اسم المستخدم") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    OutlinedTextField(
                        value = password,
                        onValueChange = { password = it },
                        label = { Text("كلمة المرور") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = rememberMe, onCheckedChange = { rememberMe = it })
                        Text("تذكّر الجلسة بأمان", style = MaterialTheme.typography.bodySmall)
                    }
                    state.authError?.let { err ->
                        Text(err, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                    }
                    Button(
                        onClick = { vm.loginEnterpriseAccount(username, password, rememberMe) },
                        enabled = !state.authLoading,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(if (state.authLoading) "جارٍ التحقق التشفيري…" else "تسجيل الدخول وتفعيل الجهاز")
                    }
                }

                if (acct.loginHistory.isNotEmpty()) {
                    HorizontalDivider()
                    Text("آخر عمليات المصادقة:", style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold)
                    acct.loginHistory.take(3).forEach { item ->
                        Text(item, style = MaterialTheme.typography.labelSmall)
                    }
                }
            }
        }

        // 3. استوديو اختبار السرعة الفعلي عبر نفق الـ VPN (Download / Upload / Ping / Jitter / Loss)
        Card(
            shape = RoundedCornerShape(18.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Filled.Speed, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                    Spacer(Modifier.width(8.dp))
                    Column {
                        Text("اختبار السرعة الحقيقي عبر النفق", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                        Text(
                            if (vpnStatus.phase == VpnPhase.CONNECTED) "يمر الفحص فعليًا داخل نفق ${vpnStatus.activeLabel}"
                            else "الـ VPN غير متّصل — سيقيس سرعة الشبكة المباشرة للمقارنة",
                            style = MaterialTheme.typography.labelSmall,
                        )
                    }
                }

                val latest = state.latestSpeedRecord
                val displayMbps = if (state.speedTestRunning) state.liveSpeedGaugeMbps else (latest?.downloadMbps ?: 0.0)
                SpeedGaugeAndCurve(
                    mbps = displayMbps,
                    curve = if (state.speedTestRunning) state.liveSpeedCurve else (latest?.curveSamplesMbps ?: emptyList()),
                )

                if (state.speedTestRunning) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                        Text(state.speedTestStage, style = MaterialTheme.typography.bodySmall)
                    }
                }

                latest?.let { r ->
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        MetricTile("التنزيل", String.format(Locale.US, "%.2f Mbps", r.downloadMbps))
                        MetricTile("الرفع", String.format(Locale.US, "%.2f Mbps", r.uploadMbps))
                        MetricTile("Ping", "${r.pingMs} ms")
                    }
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        MetricTile("Jitter", "${r.jitterMs} ms")
                        MetricTile("فقدان الحزم", String.format(Locale.US, "%.0f%%", r.packetLossPct))
                        MetricTile("الذروة", String.format(Locale.US, "%.2f Mbps", r.maxMbps))
                    }
                }

                Button(
                    onClick = { vm.runFullClientSpeedTest() },
                    enabled = !state.speedTestRunning,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(if (state.speedTestRunning) "جارٍ القياس الفعلي…" else "بدء اختبار السرعة الشامل الآن")
                }

                if (state.speedHistory.size >= 2) {
                    HorizontalDivider()
                    Text("مقارنة سجل اختبارات السرعة الأخيرة:", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
                    state.speedHistory.take(4).forEach { h ->
                        Text(
                            String.format(
                                Locale.US,
                                "• %s: ↓ %.2f Mbps | ↑ %.2f Mbps | %d ms | Loss %.0f%%",
                                h.serverLabel,
                                h.downloadMbps,
                                h.uploadMbps,
                                h.pingMs,
                                h.packetLossPct,
                            ),
                            style = MaterialTheme.typography.labelSmall,
                        )
                    }
                }
            }
        }

        // 4. أداة تشخيص الشبكة وكشف تسرب IP/DNS وفحص الرابط الاختباري الصريح
        Card(
            shape = RoundedCornerShape(18.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Filled.NetworkCheck, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                    Spacer(Modifier.width(8.dp))
                    Text("تشخيص الشبكة وكشف التسرب (DNS / IP / TLS)", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                }

                FilledTonalButton(
                    onClick = { vm.runNetworkDiagnosticsSuite() },
                    enabled = !state.netDiagRunning,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(if (state.netDiagRunning) "جارٍ فحص المسارات والتسريبات…" else "تشغيل الفحص الأمني للشبكة")
                }

                state.netDiagReport?.let { rep ->
                    val safeNoLeak = !rep.ipLeakDetected && !rep.dnsLeakDetected
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = if (safeNoLeak) Icons.Filled.CheckCircle else Icons.Filled.Warning,
                            contentDescription = null,
                            tint = if (safeNoLeak) Color(0xFF2E7D32) else Color(0xFFC62828),
                        )
                        Spacer(Modifier.width(6.dp))
                        Text(
                            text = if (safeNoLeak) "الحماية سليمة • مؤشر الاستقرار ${rep.stabilityScore}/100"
                            else "تنبيه: تحقّق من مسار النفق أو إعداد DNS • الاستقرار ${rep.stabilityScore}/100",
                            fontWeight = FontWeight.SemiBold,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    Text(
                        "حالة النفق: ${rep.tunnelStatus} • DNS: ${rep.dnsResolutionMs} ms • TLS صالح: ${if (rep.tlsValid) "نعم" else "لا"} • MTU: ${rep.mtuBytes}",
                        style = MaterialTheme.typography.labelSmall,
                    )
                    Text(
                        "تسرب IP: ${if (rep.ipLeakDetected) "مكتشف!" else "محمي"} • تسرب DNS: ${if (rep.dnsLeakDetected) "مكتشف!" else "محمي"} • الخروج: ${rep.exitCountry.ifBlank { "—" }}",
                        style = MaterialTheme.typography.labelSmall,
                    )
                }

                HorizontalDivider()
                Text("فحص استجابة رابط اختباري صريح (بدون أي تتبع للتصفح):", style = MaterialTheme.typography.labelMedium)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(
                        value = testUrlInput,
                        onValueChange = { testUrlInput = it },
                        singleLine = true,
                        modifier = Modifier.weight(1f),
                        label = { Text("رابط الاختبار (HTTPS)") },
                    )
                    Button(onClick = { vm.probeExplicitTestUrl(testUrlInput) }) {
                        Text("افحص")
                    }
                }
                state.urlProbeResult?.let { pr ->
                    Text(
                        text = if (pr.reachable) "متاح (HTTP ${pr.httpStatus}) خلال ${pr.responseTimeMs} ms • شهادة TLS: ${if (pr.tlsVerified) "موثوقة" else "غير متحققة"}"
                        else "تعذّر الوصول للرابط المحدد من المسار الحالي",
                        style = MaterialTheme.typography.labelSmall,
                    )
                }
            }
        }

        // 5. مراقب صحة التطبيق والموافقة الشفافة على تصدير التشخيصات
        Card(
            shape = RoundedCornerShape(18.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            val health = state.appHealth
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Filled.HealthAndSafety, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                    Spacer(Modifier.width(8.dp))
                    Text("مراقب صحة التطبيق والخصوصية", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                }
                Text(
                    "زمن الإقلاع: ${health.startupTimeMs} ms • الذاكرة: ${health.memoryUsedMb} MB • الانهيارات: ${health.crashCount} • أخطاء DNS/النفق: ${health.dnsErrorCount + health.tunnelErrorCount}",
                    style = MaterialTheme.typography.labelSmall,
                )
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        "الموافقة على تصدير تقرير التشخيص الخالي من البيانات الشخصية",
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.weight(1f),
                    )
                    Switch(
                        checked = health.diagnosticConsent,
                        onCheckedChange = { vm.setDiagnosticConsent(it) },
                    )
                }
                if (health.diagnosticConsent) {
                    OutlinedButton(
                        onClick = {
                            val reportJson = vm.buildRedactedDiagnosticReportJson()
                            onCopy(reportJson, "تم نسخ تقرير التشخيص المعمّى للحافظة")
                        },
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text("نسخ تقرير التشخيص التقني الآمن")
                    }
                }
            }
        }
    }
}

@Composable
private fun MetricTile(label: String, value: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Bold)
    }
}

@Composable
private fun SpeedGaugeAndCurve(mbps: Double, curve: List<Double>) {
    val primary = MaterialTheme.colorScheme.primary
    val track = MaterialTheme.colorScheme.surfaceVariant
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Box(contentAlignment = Alignment.Center, modifier = Modifier.size(136.dp)) {
            Canvas(modifier = Modifier.fillMaxSize()) {
                val stroke = Stroke(width = 12.dp.toPx(), cap = StrokeCap.Round)
                drawArc(
                    color = track,
                    startAngle = 135f,
                    sweepAngle = 270f,
                    useCenter = false,
                    style = stroke,
                )
                val sweep = ((mbps / 100.0).coerceIn(0.0, 1.0) * 270.0).toFloat()
                drawArc(
                    color = primary,
                    startAngle = 135f,
                    sweepAngle = sweep,
                    useCenter = false,
                    style = stroke,
                )
            }
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    String.format(Locale.US, "%.2f", mbps),
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.ExtraBold,
                )
                Text("Mbps", style = MaterialTheme.typography.labelSmall)
            }
        }

        if (curve.size >= 2) {
            Canvas(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp)
                    .padding(horizontal = 8.dp),
            ) {
                val maxVal = (curve.maxOrNull() ?: 1.0).coerceAtLeast(1.0)
                val stepX = size.width / (curve.size - 1).coerceAtLeast(1)
                val path = Path()
                curve.forEachIndexed { idx, v ->
                    val x = idx * stepX
                    val y = size.height - ((v / maxVal).toFloat() * size.height * 0.88f)
                    if (idx == 0) path.moveTo(x, y) else path.lineTo(x, y)
                }
                drawPath(path = path, color = primary, style = Stroke(width = 3.dp.toPx(), cap = StrokeCap.Round))
                val lastY = size.height - ((curve.last() / maxVal).toFloat() * size.height * 0.88f)
                drawCircle(color = primary, radius = 4.dp.toPx(), center = Offset(size.width, lastY))
            }
        }
    }
}
