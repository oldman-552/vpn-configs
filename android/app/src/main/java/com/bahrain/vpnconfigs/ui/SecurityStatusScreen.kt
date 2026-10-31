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
import com.bahrain.vpnconfigs.util.AppI18n
import com.bahrain.vpnconfigs.util.tr
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
                    text = tr("تصنيف الأمان وفحص التسرب", "Security & Leak Verification"),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    text = tr("آخر تقييم: ${timeFmt.format(Date(report.checkedAtMs))}", "Last checked: ${timeFmt.format(Date(report.checkedAtMs))}"),
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
                Text(if (runningDiagnostics) tr("جارٍ الفحص…", "Checking…") else tr("فحص الآن", "Run Check"))
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
                    text = tr(report.headlineAr, report.headlineEn),
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Bold,
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    text = tr(report.headlineEn, report.headlineAr),
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
                            label = { Text("${st.name} • ${tr(st.titleAr, st.titleEn)}") },
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
            title = tr("١. حالة النفق، التشفير، وهوية المشغّل", "1. Tunnel, Encryption & Operator Trust"),
            icon = Icons.Default.Lock,
        ) {
            KeyValRow(
                tr("حالة نفق الـ VPN", "VPN Tunnel State"),
                if (report.tunnelEstablished) tr("متّصل ومُتحقّق من مرور البيانات", "Established & Verified")
                else tr("غير متّصل", "Disconnected"),
            )
            KeyValRow(
                tr("التحقق من تشفير النقل", "Transport Encryption"),
                if (report.encryptionVerified) tr("موثّق (${report.encryptionDetailAr})", "Verified (${report.encryptionDetailAr})")
                else report.encryptionDetailAr,
            )
            KeyValRow(
                tr("ثقة مشغّل السيرفر", "Operator Trust"),
                if (AppI18n.isEnglish && !report.serverTrustVerified) "Unverified Public Operator (UNKNOWN_SERVER_TRUST)"
                else if (AppI18n.isEnglish) "Managed VIP Node"
                else report.serverTrustLabelAr,
            )
            Text(
                text = tr(
                    "ملاحظة شفافية: تشفير النفق يحمي بياناتك من مزوّد الإنترنت المحلي والشبكات العامة، لكن السيرفرات العامة المجانية يديرها أطراف غير موثّقين؛ لا تفترض عدم احتفاظ المشغّل بالسجلات.",
                    "Transparency note: Tunnel encryption protects traffic from your local ISP and public Wi-Fi, but public community nodes are operated by unverified third parties — never assume zero-logging.",
                ),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        // 2) DNS & IPv6 Leak Protection Card
        SecurityDetailSection(
            title = tr("٢. حماية تسرب DNS ومسار IPv6", "2. DNS & IPv6 Leak Protection"),
            icon = Icons.Default.Dns,
        ) {
            KeyValRow(tr("نتيجة فحص DNS", "DNS Check"), tr(report.dnsCheck.outcome.labelAr, report.dnsCheck.outcome.labelEn))
            KeyValRow(
                tr("محلّل DNS المُعدّ", "Configured DNS"),
                "${report.dnsCheck.configuredResolver} (${if (report.dnsCheck.usesEncryptedDoh) tr("DoH مشفّر", "Encrypted DoH") else tr("داخل النفق", "In-Tunnel")})",
            )
            Text(text = tr(report.dnsCheck.explanationAr, report.dnsCheck.explanationEn), style = MaterialTheme.typography.bodySmall)
            Text(
                text = tr(
                    report.dnsCheck.limitationNoteAr,
                    "This check inspects active local routing and TUN DNS capture; full end-to-end recursive DNS verification requires live external probing.",
                ),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Spacer(Modifier.height(8.dp))
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f))
            Spacer(Modifier.height(8.dp))

            KeyValRow(
                tr("نتيجة فحص IPv6", "IPv6 Check"),
                tr(report.ipv6Check.outcome.labelAr, report.ipv6Check.outcome.labelEn),
            )
            Text(text = tr(report.ipv6Check.explanationAr, report.ipv6Check.explanationEn), style = MaterialTheme.typography.bodySmall)
        }

        // 3) Kill Switch (App-level Fail-Closed vs Android OS Always-On Lockdown)
        SecurityDetailSection(
            title = tr("٣. مفتاح الإيقاف الصارم (Kill Switch)", "3. Strict Fail-Closed Kill Switch"),
            icon = Icons.Default.Security,
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(tr("مفتاح الإيقاف الوقائي داخل التطبيق", "In-App Fail-Closed Kill Switch"), fontWeight = FontWeight.SemiBold)
                    Text(
                        text = if (appKillSwitchEnabled) {
                            tr(
                                "نشط: يحتجز واجهة TUN ويمنع الارتداد للشبكة العادية عند سقوط النفق",
                                "Active: Holds TUN interface to prevent fallback to unprotected network if tunnel drops",
                            )
                        } else {
                            tr(
                                "متوقف: يسمح بعودة الإنترنت المباشر عند فشل جميع السيرفرات",
                                "Off: Allows direct internet fallback if all VPN servers fail",
                            )
                        },
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Switch(checked = appKillSwitchEnabled, onCheckedChange = onToggleAppKillSwitch)
            }

            Spacer(Modifier.height(8.dp))
            KeyValRow(
                tr("القفل الصارم من نظام أندرويد (OS Lockdown)", "Android OS VPN Lockdown"),
                if (report.killSwitchOsConfirmed) tr("مؤكّد ونشط من النظام ✓", "Confirmed Active by OS ✓")
                else tr("غير مفعّل في إعدادات أندرويد", "Not enabled in Android settings"),
            )
            if (lastProtectionEvent.isNotBlank()) {
                KeyValRow(tr("آخر حدث حماية مسجّل", "Last Protection Event"), lastProtectionEvent)
            }

            Spacer(Modifier.height(6.dp))
            KillSwitchController.alwaysOnSteps().forEach { step ->
                Text(text = step, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }

            Spacer(Modifier.height(8.dp))
            OutlinedButton(
                onClick = { openVpnSettingsSafely(ctx) },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Icon(Icons.Default.Settings, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(6.dp))
                Text(tr("فتح إعدادات VPN في أندرويد لتفعيل القفل الدائم", "Open Android VPN Settings (Always-on Lockdown)"))
            }

            if (protectionEvents.isNotEmpty()) {
                Spacer(Modifier.height(8.dp))
                Text(
                    tr("سجل أحداث الحماية الأخيرة:", "Recent Protection Events:"),
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                )
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
            title = tr("٤. كفاءة استهلاك البطارية والموارد", "4. Battery & Resource Efficiency"),
            icon = Icons.Default.BatterySaver,
        ) {
            KeyValRow(tr("وقت المعالج التراكمي / النسبة", "Cumulative CPU / Load"), "${resourceSnapshot.cpuTimeMs} ms (${resourceSnapshot.estimatedCpuPct}%)")
            KeyValRow(tr("الذاكرة المستخدمة (Heap / PSS)", "Memory Usage (Heap / PSS)"), "${resourceSnapshot.javaHeapMb} MB / ${resourceSnapshot.nativePssMb} MB")
            KeyValRow(tr("فترة الفحص التكيّفية الحالية", "Adaptive Probe Interval"), tr("${resourceSnapshot.activePollingIntervalMs / 1000} ثانية", "${resourceSnapshot.activePollingIntervalMs / 1000} sec"))
            KeyValRow(tr("الفحوصات الخلفية / الإعادات", "Background Probes / Reconnects"), tr("${resourceSnapshot.backgroundProbesCount} (${resourceSnapshot.probesPerMinute}/د) • ${resourceSnapshot.reconnectCount} إعادة", "${resourceSnapshot.backgroundProbesCount} (${resourceSnapshot.probesPerMinute}/min) • ${resourceSnapshot.reconnectCount} reconnects"))
            KeyValRow(tr("أقفال الإيقاظ الممسوكة (WakeLocks)", "Held WakeLocks"), tr("${resourceSnapshot.wakeLocksHeld} (صفر أقفال لتوفير الطاقة)", "${resourceSnapshot.wakeLocksHeld} (zero wake-locks for battery saving)"))
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
