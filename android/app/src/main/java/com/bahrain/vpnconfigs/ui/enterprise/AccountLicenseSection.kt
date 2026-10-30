// =====================================================================
// AccountLicenseSection.kt — بطاقة التحديث الذكي حسب المعالج (Split ABI)
// وبطاقة حساب المشترك، عدّاد تجربة 48 ساعة، ربط الجهاز، وحالة عقد VIP (v3.1).
// =====================================================================
package com.bahrain.vpnconfigs.ui.enterprise

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountCircle
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.SystemUpdate
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.bahrain.vpnconfigs.ui.AppViewModel
import com.bahrain.vpnconfigs.ui.UiState
import java.util.Locale

@Composable
fun SignedAppUpdateBanner(
    state: UiState,
    vm: AppViewModel,
) {
    val upd = state.availableUpdate ?: return
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
                    text = if (upd.mandatory) "تحديث أمني إلزامي (${upd.versionName} • ${upd.selectedAbi})"
                    else "تحديث ذكي متاح (${upd.versionName} • حزمة ${upd.selectedAbi})",
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
                Text(
                    if (state.updatingApk) "جارٍ التحقق من بصمة SHA-256 والتنزيل…"
                    else "تنزيل حزمة ${upd.selectedAbi} وتثبيتها رسميًا"
                )
            }
        }
    }
}

@Composable
fun AccountLicenseCard(
    state: UiState,
    liveRemainingSec: Long,
    vm: AppViewModel,
    onCopy: (String, String) -> Unit,
) {
    val acct = state.accountState
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var rememberMe by remember { mutableStateOf(true) }

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
                        if (acct.vipNodesUnlocked > 0) {
                            Text(
                                "💎 عقد VIP المشفّرة المفتوحة لحسابك: ${acct.vipNodesUnlocked} عقدة خاصة",
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFFFFA000),
                            )
                        }
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
                    Text(if (state.authLoading) "جارٍ التحقق التشفيري…" else "تسجيل الدخول وتفعيل الجهاز وعقد VIP")
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
}
