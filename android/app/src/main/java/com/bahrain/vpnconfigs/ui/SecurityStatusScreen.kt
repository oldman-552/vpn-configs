// =====================================================================
// SecurityStatusScreen.kt — شاشة حالة الأمان والتسرب الصريحة (Part 3 & Part 2.3/2.8).
//
// المبدأ الهندسي:
//   • تعرض الحالات الـ 9 المعتمدة بصدق كامل دون ادعاء أن أي اتصال عام «موثوق 100%».
//   • تفصل بوضوح بين تشفير النفق، هوية مشغّل السيرفر، فحص تسرب DNS و IPv6،
//     وحالة Kill Switch على مستوى التطبيق مقابل القفل الرسمي من نظام أندرويد (OS Lockdown).
// =====================================================================
package com.bahrain.vpnconfigs.ui

import android.content.Context
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
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
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BatterySaver
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.bahrain.vpnconfigs.data.ProtectionEventRecord
import com.bahrain.vpnconfigs.vpn.DiagnosticOutcome
import com.bahrain.vpnconfigs.vpn.KillSwitchController
import com.bahrain.vpnconfigs.vpn.ResourceTelemetrySnapshot
import com.bahrain.vpnconfigs.vpn.SecurityStatusReport
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun SecurityStatusScreen(
    report: SecurityStatusReport,
    appKillSwitchEnabled: Boolean,
    lastProtectionEvent: String,
    protectionEvents: List<ProtectionEventRecord>,
    resourceSnapshot: ResourceTelemetrySnapshot,
    runningDiagnostics: Boolean,
    onToggleAppKillSwitch: (Boolean) -> Unit,
    onRunLiveSecurityCheck: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val ctx = LocalContext.current
    val timeFmt = remember { SimpleDateFormat("HH:mm:ss", Locale.US) }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 14.dp, vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "تصنيف الأمان وفحص التسرب",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    text = "آخر تقييم: ${timeFmt.format(Date(report.checkedAtMs))}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Button(
                onClick = onRunLiveSecurityCheck,
                enabled = !runningDiagnostics,
            ) {
                Icon(Icons.Default.Refresh, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(6.dp))
                Text(if (runningDiagnostics) "جارٍ الفحص…" else "فحص الآن")
            }
        }

        // Plain-language honest headline card
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f),
            ),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.35f)),
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Text(
                    text = report.headlineAr,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Bold,
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    text = report.headlineEn,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(10.dp))

                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    report.primaryStates.forEach { st ->
                        val chipColor = if (st.isWarningOrFailure) {
                            Color(0xFFF59E0B)
                        } else {
                            Color(0xFF10B981)
                        }
                        AssistChip(
                            onClick = {},
                            label = { Text("${st.name} • ${st.titleAr}") },
                            colors = AssistChipDefaults.assistChipColors(
                                labelColor = chipColor,
                            ),
                        )
                    }
                }

                if (report.failureExplanationsAr.isNotEmpty()) {
                    Spacer(Modifier.height(8.dp))
                    HorizontalDivider()
                    Spacer(Modifier.height(8.dp))
                    report.failureExplanationsAr.forEach { warn ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                Icons.Default.Warning,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.error,
                                modifier = Modifier.size(16.dp),
                            )
                            Spacer(Modifier.width(6.dp))
                            Text(
                                text = warn,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error,
                            )
                        }
                    }
                }
            }
        }

        // 1) Tunnel & Encryption + Operator Trust Card
        SecurityDetailSection(
            title = "١. حالة النفق، التشفير، وهوية المشغّل",
            icon = Icons.Default.Lock,
        ) {
            KeyValRow("حالة نفق الـ VPN", if (report.tunnelEstablished) "متّصل ومُتحقّق من مرور البيانات" else "غير متّصل")
            KeyValRow("التحقق من تشفير النقل", if (report.encryptionVerified) "موثّق (${report.encryptionDetailAr})" else report.encryptionDetailAr)
            KeyValRow("ثقة مشغّل السيرفر", report.serverTrustLabelAr)
            Text(
                text = "ملاحظة شفافية: تشفير النفق يحمي بياناتك من مزوّد الإنترنت المحلي والشبكات العامة، لكن السيرفرات العامة المجانية يديرها أطراف غير موثّقين؛ لا تفترض عدم احتفاظ المشغّل بالسجلات.",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        // 2) DNS & IPv6 Leak Protection Card
        SecurityDetailSection(
            title = "٢. حماية تسرب DNS ومسار IPv6",
            icon = Icons.Default.Dns,
        ) {
            KeyValRow("نتيجة فحص DNS", report.dnsCheck.outcome.labelAr)
            KeyValRow("محلّل DNS المُعدّ", "${report.dnsCheck.configuredResolver} (${if (report.dnsCheck.usesEncryptedDoh) "DoH مشفّر" else "داخل النفق"})")
            Text(text = report.dnsCheck.explanationAr, style = MaterialTheme.typography.bodySmall)
            Text(
                text = report.dnsCheck.limitationNoteAr,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Spacer(Modifier.height(8.dp))
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f))
            Spacer(Modifier.height(8.dp))

            KeyValRow(
                "نتيجة فحص IPv6",
                when (report.ipv6Check.outcome) {
                    DiagnosticOutcome.PROTECTED -> "محمي داخل النفق"
                    DiagnosticOutcome.UNAVAILABLE_SAFE -> "غير متوفّر على الشبكة (آمن)"
                    DiagnosticOutcome.LEAK_DETECTED -> "رُصد احتمال تسرب!"
                    DiagnosticOutcome.INCONCLUSIVE -> "غير حاسم (النفق متوقف)"
                }
            )
            Text(text = report.ipv6Check.explanationAr, style = MaterialTheme.typography.bodySmall)
        }

        // 3) Kill Switch (App-level Fail-Closed vs Android OS Always-On Lockdown)
        SecurityDetailSection(
            title = "٣. مفتاح الإيقاف الصارم (Kill Switch)",
            icon = Icons.Default.Security,
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("مفتاح الإيقاف الوقائي داخل التطبيق", fontWeight = FontWeight.SemiBold)
                    Text(
                        text = if (appKillSwitchEnabled) "نشط: يحتجز واجهة TUN ويمنع الارتداد للشبكة العادية عند سقوط النفق"
                        else "متوقف: يسمح بعودة الإنترنت المباشر عند فشل جميع السيرفرات",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Switch(checked = appKillSwitchEnabled, onCheckedChange = onToggleAppKillSwitch)
            }

            Spacer(Modifier.height(8.dp))
            KeyValRow(
                "القفل الصارم من نظام أندرويد (OS Lockdown)",
                if (report.killSwitchOsConfirmed) "مؤكّد ونشط من النظام ✓" else "غير مفعّل في إعدادات أندرويد",
            )
            if (lastProtectionEvent.isNotBlank()) {
                KeyValRow("آخر حدث حماية مسجّل", lastProtectionEvent)
            }

            Spacer(Modifier.height(6.dp))
            KillSwitchController.ALWAYS_ON_STEPS_AR.forEach { step ->
                Text(text = step, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }

            Spacer(Modifier.height(8.dp))
            OutlinedButton(
                onClick = { openVpnSettingsSafely(ctx) },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Icon(Icons.Default.Settings, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(6.dp))
                Text("فتح إعدادات VPN في أندرويد لتفعيل القفل الدائم")
            }

            if (protectionEvents.isNotEmpty()) {
                Spacer(Modifier.height(8.dp))
                Text("سجل أحداث الحماية الأخيرة:", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
                protectionEvents.take(4).forEach { ev ->
                    Text(
                        text = "• [${timeFmt.format(Date(ev.eventAtMs))}] ${ev.titleAr}",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }

        // 4) Battery & Resource Efficiency Telemetry (Part 2.8)
        SecurityDetailSection(
            title = "٤. كفاءة استهلاك البطارية والموارد",
            icon = Icons.Default.BatterySaver,
        ) {
            KeyValRow("وقت المعالج التراكمي / النسبة", "${resourceSnapshot.cpuTimeMs} ms (${resourceSnapshot.estimatedCpuPct}%)")
            KeyValRow("الذاكرة المستخدمة (Heap / PSS)", "${resourceSnapshot.javaHeapMb} MB / ${resourceSnapshot.nativePssMb} MB")
            KeyValRow("فترة الفحص التكيّفية الحالية", "${resourceSnapshot.activePollingIntervalMs / 1000} ثانية")
            KeyValRow("الفحوصات الخلفية / الإعادات", "${resourceSnapshot.backgroundProbesCount} (${resourceSnapshot.probesPerMinute}/د) • ${resourceSnapshot.reconnectCount} إعادة")
            KeyValRow("أقفال الإيقاظ الممسوكة (WakeLocks)", "${resourceSnapshot.wakeLocksHeld} (صفر أقفال لتوفير الطاقة)")
        }

        Spacer(Modifier.height(16.dp))
    }
}

@Composable
private fun SecurityDetailSection(
    title: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    content: @Composable () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.45f)),
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(20.dp))
                Spacer(Modifier.width(8.dp))
                Text(text = title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
            }
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.35f))
            content()
        }
    }
}

@Composable
private fun KeyValRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(0.95f),
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.weight(1.05f),
        )
    }
}

private fun openVpnSettingsSafely(ctx: Context) {
    runCatching {
        ctx.startActivity(KillSwitchController.createSystemVpnSettingsIntent())
    }
}
