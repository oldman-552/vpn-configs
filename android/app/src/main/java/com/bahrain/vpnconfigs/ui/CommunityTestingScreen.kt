// =====================================================================
// CommunityTestingScreen.kt — واجهة الفحص المجتمعي الطوعي وترتيب سيرفرات
// إيران الموثّقة (Community VPN Verification — العربية أساسية RTL + الإنجليزية LTR).
// =====================================================================
package com.bahrain.vpnconfigs.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.DeleteForever
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.bahrain.vpnconfigs.community.CommunityTestingManager
import com.bahrain.vpnconfigs.util.tr
import com.bahrain.vpnconfigs.vpn.VpnStateManager
import kotlinx.coroutines.launch

@Composable
fun CommunityTestingScreen(
    state: UiState,
    vm: AppViewModel,
    onBack: () -> Unit,
    onLoadIranCommunityPool: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val commState by CommunityTestingManager.state.collectAsState()

    var maxPerRunTxt by remember(commState.maxConfigsPerRun) {
        mutableStateOf(commState.maxConfigsPerRun.toString())
    }
    var dailyLimitTxt by remember(commState.dailyLimit) {
        mutableStateOf(commState.dailyLimit.toString())
    }

    LaunchedEffect(Unit) {
        CommunityTestingManager.refreshSnapshot(ctx)
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        // ── الشريط العلوي ──
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = onBack) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = tr("رجوع", "Back"))
            }
            Icon(
                Icons.Filled.Public,
                contentDescription = null,
                tint = if (commState.optInEnabled) VpnConnectedGreen else MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(26.dp),
            )
            Spacer(Modifier.width(8.dp))
            Column {
                Text(
                    tr("الفحص المجتمعي الموثّق (إيران IR والدول)", "Community VPN Verification (Iran & Global)"),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.ExtraBold,
                )
                Text(
                    tr("اختبار محلي طوعي بدون بروكسي وخصوصية صارمة 100%", "Opt-in local-only config verification with strict privacy"),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
            }
        }

        commState.displayError?.let { err ->
            Surface(
                color = MaterialTheme.colorScheme.errorContainer,
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    text = err,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(12.dp),
                )
            }
        }

        // ── ميثاق الخصوصية والأمان الصريح ──
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Filled.VerifiedUser, contentDescription = null, tint = VpnConnectedGreen)
                    Spacer(Modifier.width(8.dp))
                    Text(
                        tr("ضمانات الأمان والخصوصية الصارمة", "Strict Privacy & Safety Guarantees"),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                    )
                }
                Text(
                    tr(
                        "• معطّل افتراضيًا ولا يعمل إلا بموافقتك الصريحة مع إمكانية الإلغاء الفوري في أي لحظة.\n" +
                            "• هاتفك يُجري فحصًا محليًا فقط ولا يعمل أبدًا كبروكسي عام أو نقطة عبور لأي مستخدم آخر.\n" +
                            "• لا يقطع اتصال الـ VPN النشط لديك، ويتوقف تلقائيًا فور تشغيل نقطة اتصال الـ VPN (Hotspot).\n" +
                            "• لا يجمع أي كلمات مرور أو روابط خاصة أو سجل تصفح أو موقع GPS أو اسم شبكة Wi‑Fi.",
                        "• Disabled by default (OFF); runs only with explicit opt-in and can be revoked instantly.\n" +
                            "• Your phone runs local connectivity probes ONLY and NEVER acts as a public proxy or relay.\n" +
                            "• Never interrupts active VPN sessions and automatically pauses whenever VPN Hotspot is active.\n" +
                            "• Zero credentials, zero browsing history, zero Wi-Fi SSIDs, and zero GPS data collected.",
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
            }
        }

        // ── بطاقة الموافقة والتحكم الفوري + جلب قائمة إيران ──
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text(
                    commState.displayStatus,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold,
                )

                if (commState.isRunning && commState.totalInCurrentRun > 0) {
                    val frac = (commState.testedInCurrentRun.toFloat() / commState.totalInCurrentRun.toFloat())
                        .coerceIn(0f, 1f)
                    LinearProgressIndicator(progress = { frac }, modifier = Modifier.fillMaxWidth())
                    Text(
                        tr(
                            "جارٍ الفحص التسلسلي الآمن: ${commState.testedInCurrentRun} / ${commState.totalInCurrentRun} (${commState.currentProtocol})",
                            "Sequential local probe: ${commState.testedInCurrentRun} / ${commState.totalInCurrentRun} (${commState.currentProtocol})",
                        ),
                        style = MaterialTheme.typography.labelSmall,
                        fontFamily = FontFamily.Monospace,
                    )
                }

                if (!commState.optInEnabled) {
                    Button(
                        onClick = { CommunityTestingManager.grantConsent(ctx) },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = VpnConnectedGreen),
                    ) {
                        Text(
                            tr("أوافق وأفعّل الفحص المجتمعي الطوعي", "Grant Consent & Enable Community Testing"),
                            fontWeight = FontWeight.Bold,
                        )
                    }
                } else {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        if (!commState.isRunning) {
                            Button(
                                onClick = {
                                    CommunityTestingManager.startManualOrScheduledRun(
                                        ctx = ctx,
                                        candidateConfigs = state.configs,
                                        isBackgroundRun = false,
                                    )
                                },
                                modifier = Modifier.weight(1f),
                            ) {
                                Icon(Icons.Filled.PlayArrow, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(Modifier.width(4.dp))
                                Text(tr("بدء جولة فحص الآن", "Run Verification Now"))
                            }
                        } else {
                            Button(
                                onClick = { CommunityTestingManager.stopCurrentRun() },
                                modifier = Modifier.weight(1f),
                                colors = ButtonDefaults.buttonColors(containerColor = VpnDangerRed),
                            ) {
                                Icon(Icons.Filled.Stop, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(Modifier.width(4.dp))
                                Text(tr("إيقاف الجولة", "Stop Run"))
                            }
                        }

                        OutlinedButton(
                            onClick = {
                                scope.launch { CommunityTestingManager.submitPendingReports(ctx) }
                            },
                            modifier = Modifier.weight(1f),
                        ) {
                            Icon(Icons.Filled.CloudUpload, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(4.dp))
                            Text(tr("رفع المعلّق", "Sync Pending"))
                        }
                    }

                    OutlinedButton(
                        onClick = { CommunityTestingManager.revokeConsent(ctx, clearLocalPending = true) },
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Icon(Icons.Filled.DeleteForever, contentDescription = null, tint = VpnDangerRed, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        Text(
                            tr("إلغاء الموافقة فورًا ومسح السجل المحلي", "Revoke Consent Immediately & Clear Local Reports"),
                            color = VpnDangerRed,
                        )
                    }
                }

                HorizontalDivider()

                OutlinedButton(
                    onClick = onLoadIranCommunityPool,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        tr(
                            "🇮🇷 التبديل لقائمة سيرفرات إيران الموثّقة مجتمعيًا (Iran Top 500)",
                            "🇮🇷 Switch to Community-Verified Iran Top 500 Pool",
                        ),
                        fontWeight = FontWeight.SemiBold,
                    )
                }
            }
        }

        // ── بطاقة التحقق من دولة المصدر وإحصاءات المساهمة ──
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    tr("حالة التحقق من الشبكة والإحصاءات المحلية", "Origin Verification & Local Contribution Metrics"),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                )
                val cc = commState.lastVerifiedCountry
                val originLabel = when {
                    commState.vpnInterferenceDetected ->
                        tr("تحذير: رُصد VPN نشط (تُرفض نسبة الفحص للشبكة المحلية)", "VPN Interference Detected (Not counted as direct ISP)")
                    cc.length == 2 ->
                        "${VpnStateManager.countryFlag(cc)} $cc (${tr("تحقق مباشر موثّق", "Verified Direct Public IP")})"
                    else ->
                        tr("سيتم التحقق عند بدء أول جولة فحص بدون VPN", "Verified automatically on first non-VPN run")
                }

                CommunityStatRow(tr("دولة الشبكة المباشرة الموثّقة", "Verified Direct Network Country"), originLabel)
                CommunityStatRow(tr("إجمالي الفحوصات المنفّذة محليًا", "Total Configs Verified Locally"), "${commState.summary.totalTested}")
                CommunityStatRow(tr("السيرفرات الناجحة فعليًا", "Verified Working Configs"), "${commState.summary.totalSuccess}")
                CommunityStatRow(tr("تقارير موثّقة من داخل إيران (IR)", "Verified Iran (IR) Direct Reports"), "${commState.summary.verifiedIranCount}")
                CommunityStatRow(
                    tr("بانتظار الرفع / تم رفعها", "Queued / Uploaded Reports"),
                    "${commState.summary.pendingUploadCount} / ${commState.summary.submittedCount}",
                )
                if (commState.displayLastSync.isNotBlank()) {
                    Text(
                        commState.displayLastSync,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.secondary,
                    )
                }
            }
        }

        // ── قيود الشبكة والجدولة واستهلاك البيانات ──
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text(
                    tr("ضوابط الشبكة والبيانات والجدولة", "Network, Data & Schedule Limits"),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f).padding(end = 8.dp)) {
                        Text(tr("الفحص عبر شبكة Wi‑Fi فقط", "Test on Wi‑Fi Only"), fontWeight = FontWeight.Medium)
                        Text(
                            tr("يمنع استهلاك باقة بيانات الجوال أثناء الفحص المجتمعي", "Prevents mobile data usage during community checks"),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.secondary,
                        )
                    }
                    Switch(
                        checked = commState.wifiOnly,
                        onCheckedChange = { CommunityTestingManager.updateSettings(ctx, wifiOnly = it) },
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f).padding(end = 8.dp)) {
                        Text(tr("الفحص التلقائي الهادئ عند خمول الجهاز", "Idle Background Verification"), fontWeight = FontWeight.Medium)
                        Text(
                            tr("يعمل فقط عند عدم اتصال الـ VPN وعدم تشغيل الهوتسبوت وفوق 25% بطارية", "Runs only when VPN & Hotspot are idle and battery >= 25%"),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.secondary,
                        )
                    }
                    Switch(
                        checked = commState.backgroundScheduleEnabled,
                        enabled = commState.optInEnabled,
                        onCheckedChange = { CommunityTestingManager.updateSettings(ctx, backgroundSchedule = it) },
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    OutlinedTextField(
                        value = maxPerRunTxt,
                        onValueChange = {
                            maxPerRunTxt = it.filter(Char::isDigit).take(2)
                            maxPerRunTxt.toIntOrNull()?.let { v ->
                                CommunityTestingManager.updateSettings(ctx, maxPerRun = v)
                            }
                        },
                        label = { Text(tr("لكل جولة (5–50)", "Per Run (5–50)")) },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.weight(1f),
                    )
                    OutlinedTextField(
                        value = dailyLimitTxt,
                        onValueChange = {
                            dailyLimitTxt = it.filter(Char::isDigit).take(3)
                            dailyLimitTxt.toIntOrNull()?.let { v ->
                                CommunityTestingManager.updateSettings(ctx, dailyLimit = v)
                            }
                        },
                        label = { Text(tr("الحد اليومي (10–250)", "Daily Cap (10–250)")) },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.weight(1f),
                    )
                }
            }
        }

        // ── أحدث الفحوصات المحلية المعمّاة ──
        if (commState.recentReports.isNotEmpty()) {
            ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        tr("آخر القياسات المجهولة الهوية على جهازك", "Recent Anonymized Local Measurements"),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                    )
                    commState.recentReports.take(10).forEach { r ->
                        HorizontalDivider()
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    "${r.protocol.uppercase()} • #${r.configFingerprint.take(10)}",
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.SemiBold,
                                    style = MaterialTheme.typography.bodySmall,
                                )
                                val sub = if (r.success) {
                                    "⚡ ${r.latencyMs}ms • ${(r.downloadKbps).toInt()} KB/s • ${r.verifiedCountry.ifBlank { "—" }}"
                                } else {
                                    "${r.failureReason} • ${r.verifiedCountry.ifBlank { "—" }}"
                                }
                                Text(
                                    sub,
                                    style = MaterialTheme.typography.labelSmall,
                                    color = if (r.success) VpnConnectedGreen else VpnDangerRed,
                                    fontFamily = FontFamily.Monospace,
                                )
                            }
                            Text(
                                if (r.submitted) tr("مرفوع ✓", "Synced ✓") else tr("محفوظ", "Local"),
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.secondary,
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun CommunityStatRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.secondary,
            modifier = Modifier.weight(0.52f),
        )
        Text(
            value,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.weight(0.48f),
        )
    }
}
