// =====================================================================
// DiagnosticsAndHealthSection.kt — تشخيص التسرب (DNS/IP/TLS/MTU)،
// التبديل التلقائي السريع (~ثانيتين)، ومراقب صحة التطبيق والخصوصية (v3.1).
// =====================================================================
package com.bahrain.vpnconfigs.ui.enterprise

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.HealthAndSafety
import androidx.compose.material.icons.filled.NetworkCheck
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
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
}

@Composable
fun AppHealthAndFailoverCard(
    state: UiState,
    vm: AppViewModel,
    onCopy: (String, String) -> Unit,
) {
    val health = state.appHealth
    Card(
        shape = RoundedCornerShape(18.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Filled.HealthAndSafety, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                Spacer(Modifier.width(8.dp))
                Text("الاستمرارية الذكية وصحة التطبيق (v3.1)", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            }

            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("التبديل التلقائي السريع عند الانقطاع (Auto-Failover ~2s)", style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
                    Text("ينتقل تلقائيًا إلى ثاني أسرع سيرفر شغّال دون هدم واجهة TUN", style = MaterialTheme.typography.labelSmall)
                }
                Switch(
                    checked = state.autoFailover,
                    onCheckedChange = { vm.setAutoFailover(it) },
                )
            }

            HorizontalDivider()
            Text(
                "زمن الإقلاع: ${health.startupTimeMs} ms • الذاكرة: ${health.memoryUsedMb} MB • الانهيارات: ${health.crashCount} • أحداث النفق/DNS: ${health.dnsErrorCount + health.tunnelErrorCount}",
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
