// =====================================================================
// DiagnosticsAndHealthSection.kt — تشخيص التسرب (DNS/IP/TLS/MTU)،
// التبديل التلقائي السريع (~ثانيتين)، ومراقب صحة التطبيق والخصوصية (v1).
// =====================================================================
package com.bahrain.vpnconfigs.ui.enterprise

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.HealthAndSafety
import androidx.compose.material.icons.filled.NetworkCheck
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.bahrain.vpnconfigs.ui.AppViewModel
import com.bahrain.vpnconfigs.ui.UiState
import com.bahrain.vpnconfigs.util.tr
import com.bahrain.vpnconfigs.vpn.FailoverMode
import com.bahrain.vpnconfigs.vpn.KillSwitchController
import com.bahrain.vpnconfigs.vpn.VpnStateManager

@Composable
fun NetworkDiagnosticsCard(
    state: UiState,
    vm: AppViewModel,
) {
    var testUrlInput by remember { mutableStateOf("https://1.1.1.1") }

    Card(
        shape = RoundedCornerShape(18.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Filled.NetworkCheck, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                Spacer(Modifier.width(8.dp))
                Text(
                    tr("تشخيص الشبكة وكشف التسرب (DNS / IP / TLS)", "Network Diagnostics & Leak Check (DNS / IP / TLS)"),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                )
            }

            FilledTonalButton(
                onClick = { vm.runNetworkDiagnosticsSuite() },
                enabled = !state.netDiagRunning,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    if (state.netDiagRunning) tr("جارٍ فحص المسارات والتسريبات…", "Checking routes & leaks…")
                    else tr("تشغيل الفحص الأمني للشبكة", "Run Network Security Check")
                )
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
                        text = if (safeNoLeak) {
                            tr("الحماية سليمة • مؤشر الاستقرار ${rep.stabilityScore}/100", "Protection verified • Stability ${rep.stabilityScore}/100")
                        } else {
                            tr("تنبيه: تحقّق من مسار النفق أو إعداد DNS • الاستقرار ${rep.stabilityScore}/100", "Alert: Check tunnel route or DNS • Stability ${rep.stabilityScore}/100")
                        },
                        fontWeight = FontWeight.SemiBold,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                Text(
                    tr(
                        "حالة النفق: ${rep.tunnelStatus} • DNS: ${rep.dnsResolutionMs} ms • TLS صالح: ${if (rep.tlsValid) "نعم" else "لا"} • MTU: ${rep.mtuBytes}",
                        "Tunnel: ${rep.tunnelStatus} • DNS: ${rep.dnsResolutionMs} ms • TLS Valid: ${if (rep.tlsValid) "Yes" else "No"} • MTU: ${rep.mtuBytes}",
                    ),
                    style = MaterialTheme.typography.labelSmall,
                )
                Text(
                    tr(
                        "تسرب IP: ${if (rep.ipLeakDetected) "مكتشف!" else "محمي"} • تسرب DNS: ${if (rep.dnsLeakDetected) "مكتشف!" else "محمي"} • حماية IPv6: ${if (rep.ipv6LeakProtected) "محكم (::/0)" else "غير نشط"} • الخروج: ${rep.exitCountry.ifBlank { "—" }}",
                        "IP Leak: ${if (rep.ipLeakDetected) "Detected!" else "Protected"} • DNS Leak: ${if (rep.dnsLeakDetected) "Detected!" else "Protected"} • IPv6: ${if (rep.ipv6LeakProtected) "Captured (::/0)" else "Off"} • Exit: ${rep.exitCountry.ifBlank { "—" }}",
                    ),
                    style = MaterialTheme.typography.labelSmall,
                )
                if (rep.webRtcSummaryAr.isNotBlank()) {
                    Text(
                        tr("حالة WebRTC: ${rep.webRtcSummaryAr}", "WebRTC: ${rep.webRtcSummaryAr}"),
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Medium,
                    )
                }
                Text(
                    tr(
                        "مفتاح الإيقاف: ${if (rep.killSwitchEnabled) "مفعّل بالتطبيق" else "معطّل"} • قفل أندرويد الدائم (OS Lockdown): ${if (rep.osLockdownActive) "مفعّل" else "غير مفعّل"}",
                        "Kill Switch: ${if (rep.killSwitchEnabled) "App Enabled" else "Off"} • Android OS Lockdown: ${if (rep.osLockdownActive) "Active" else "Not Enabled"}",
                    ),
                    style = MaterialTheme.typography.labelSmall,
                )
            }

            HorizontalDivider()
            Text(
                tr("فحص استجابة رابط اختباري صريح (بدون أي تتبع للتصفح):", "Explicit HTTPS Test URL Probe (zero browsing tracking):"),
                style = MaterialTheme.typography.labelMedium,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = testUrlInput,
                    onValueChange = { testUrlInput = it },
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                    label = { Text(tr("رابط الاختبار (HTTPS)", "Test URL (HTTPS)")) },
                )
                Button(onClick = { vm.probeExplicitTestUrl(testUrlInput) }) {
                    Text(tr("افحص", "Probe"))
                }
            }
            state.urlProbeResult?.let { pr ->
                Text(
                    text = if (pr.reachable) {
                        tr(
                            "متاح (HTTP ${pr.httpStatus}) خلال ${pr.responseTimeMs} ms • شهادة TLS: ${if (pr.tlsVerified) "موثوقة" else "غير متحققة"}",
                            "Reachable (HTTP ${pr.httpStatus}) in ${pr.responseTimeMs} ms • TLS: ${if (pr.tlsVerified) "Verified" else "Unverified"}",
                        )
                    } else {
                        tr("تعذّر الوصول للرابط المحدد من المسار الحالي", "Could not reach URL through current route")
                    },
                    style = MaterialTheme.typography.labelSmall,
                )
            }
        }
    }
}

@Composable
fun AppHealthAndFailoverCard(
    state: UiState,
    vm: AppViewModel,
    onCopy: (String, String) -> Unit,
) {
    val health = state.appHealth
    val vpnSt by VpnStateManager.status.collectAsState()
    Card(
        shape = RoundedCornerShape(18.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Filled.HealthAndSafety, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                Spacer(Modifier.width(8.dp))
                Text(
                    tr("مفتاح الإيقاف والتبديل الذكي وصحة النفق (v1)", "Kill Switch, Smart Failover & Tunnel Health (v1)"),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                )
            }

            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        tr("مفتاح الإيقاف الصارم (Fail-Closed Kill Switch)", "Fail-Closed Kill Switch"),
                        style = MaterialTheme.typography.bodySmall,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Text(
                        tr(
                            "يقفل واجهة TUN قبل الربط ويمنع تسرب البيانات عند سقوط جميع السيرفرات",
                            "Locks TUN interface before probing and prevents traffic leaks if all servers drop",
                        ),
                        style = MaterialTheme.typography.labelSmall,
                    )
                }
                Switch(
                    checked = state.killSwitch,
                    onCheckedChange = { vm.setKillSwitch(it) },
                )
            }
            Text(
                tr(
                    KillSwitchController.OS_LIMITATION_NOTE_AR,
                    "In-app Kill Switch blocks app leaks during connection, switching, and drops; to block pre-boot system packets on device restart, also enable 'Always-on VPN + Block connections without VPN' in Android settings.",
                ),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.secondary,
            )

            HorizontalDivider()
            Text(
                tr("سياسة التبديل التلقائي ومقاومة التدهور (Failover Policy):", "Smart Failover Policy:"),
                style = MaterialTheme.typography.bodySmall,
                fontWeight = FontWeight.SemiBold,
            )
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                FailoverMode.entries.forEach { mode ->
                    FilterChip(
                        selected = FailoverMode.fromKey(state.failoverMode) == mode,
                        onClick = { vm.setFailoverMode(mode.key) },
                        label = { Text(mode.displayTitle) },
                    )
                }
            }

            // ── لوحة مؤشرات التبديل الحيّة (Phase 6.5 Failover Telemetry) ──
            val lastSwitchLbl = if (vpnSt.lastSuccessfulSwitchAtMs > 0L) {
                val secAgo = ((System.currentTimeMillis() - vpnSt.lastSuccessfulSwitchAtMs) / 1000L).coerceAtLeast(0L)
                if (secAgo < 60L) tr("منذ ${secAgo} ث", "${secAgo}s ago") else tr("منذ ${secAgo / 60L} د", "${secAgo / 60L}m ago")
            } else "—"
            Text(
                tr(
                    "السيرفر الحالي: ${vpnSt.activeLabel} • السابق: ${vpnSt.previousServerLabel.ifBlank { "—" }} • البديل المرشّح: ${vpnSt.targetServerLabel.ifBlank { "—" }}",
                    "Current: ${vpnSt.activeLabel} • Previous: ${vpnSt.previousServerLabel.ifBlank { "—" }} • Backup: ${vpnSt.targetServerLabel.ifBlank { "—" }}",
                ),
                style = MaterialTheme.typography.labelSmall,
            )
            Text(
                tr(
                    "جودة الاتصال: ${vpnSt.displayConnectionQuality} • التأخير: ${if (vpnSt.livePingMs > 0L) "${vpnSt.livePingMs} ms" else "—"} • فقدان الحزم: ${vpnSt.packetLossPct}% • الحالة: ${vpnSt.displaySwitchingStatus} • آخر تبديل ناجح: $lastSwitchLbl",
                    "Quality: ${vpnSt.displayConnectionQuality} • Ping: ${if (vpnSt.livePingMs > 0L) "${vpnSt.livePingMs} ms" else "—"} • Loss: ${vpnSt.packetLossPct}% • State: ${vpnSt.displaySwitchingStatus} • Last switch: $lastSwitchLbl",
                ),
                style = MaterialTheme.typography.labelSmall,
            )

            HorizontalDivider()
            Text(
                tr(
                    "زمن الإقلاع: ${health.startupTimeMs} ms • الذاكرة: ${health.memoryUsedMb} MB • الانهيارات: ${health.crashCount} • أحداث النفق/DNS: ${health.dnsErrorCount + health.tunnelErrorCount}",
                    "Startup: ${health.startupTimeMs} ms • Memory: ${health.memoryUsedMb} MB • Crashes: ${health.crashCount} • Tunnel/DNS events: ${health.dnsErrorCount + health.tunnelErrorCount}",
                ),
                style = MaterialTheme.typography.labelSmall,
            )
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    tr(
                        "الموافقة على تصدير تقرير التشخيص الخالي من البيانات الشخصية",
                        "Consent to export redacted zero-PII diagnostic report",
                    ),
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
                        onCopy(reportJson, tr("تم نسخ تقرير التشخيص المعمّى للحافظة", "Redacted diagnostic report copied"))
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(tr("نسخ تقرير التشخيص التقني الآمن", "Copy Redacted Technical Report"))
                }
            }
        }
    }
}
