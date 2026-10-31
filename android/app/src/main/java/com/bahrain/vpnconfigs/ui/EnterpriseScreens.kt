// =====================================================================
// EnterpriseScreens.kt — المنسّق المعياري لشاشة المركز المؤسسي وبوابة الدخول (v2).
// تم تفكيك المكوّنات الفرعية إلى حزمة `com.bahrain.vpnconfigs.ui.enterprise`
// لسهولة الصيانة والتوسع المستقبلي.
// =====================================================================
package com.bahrain.vpnconfigs.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.bahrain.vpnconfigs.ui.enterprise.AccountLicenseCard
import com.bahrain.vpnconfigs.ui.enterprise.AppHealthAndFailoverCard
import com.bahrain.vpnconfigs.ui.enterprise.AntiCensorshipToolsCard
import com.bahrain.vpnconfigs.ui.enterprise.BlockingDetectionCard
import com.bahrain.vpnconfigs.ui.enterprise.NetworkDiagnosticsCard
import com.bahrain.vpnconfigs.ui.enterprise.SignedAppUpdateBanner
import com.bahrain.vpnconfigs.ui.enterprise.TunnelSpeedStudioCard
import com.bahrain.vpnconfigs.util.tr
import com.bahrain.vpnconfigs.vpn.VpnStatus
import kotlinx.coroutines.delay

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
        title = { Text(tr("تسجيل الدخول الإلزامي", "Account Login Required"), fontWeight = FontWeight.Bold) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    tr(
                        "يلزم تسجيل الدخول بحساب فعّال أو فترة تجريبية (48 ساعة) للوصول إلى خوادم الـ VPN وعقد VIP الخاصة.",
                        "Please sign in with an active account or 48-hour trial to access VPN servers and private VIP nodes.",
                    ),
                    style = MaterialTheme.typography.bodySmall,
                )
                OutlinedTextField(
                    value = username,
                    onValueChange = { username = it },
                    label = { Text(tr("اسم المستخدم", "Username")) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text(tr("كلمة المرور", "Password")) },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier.fillMaxWidth(),
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = rememberMe, onCheckedChange = { rememberMe = it })
                    Text(
                        tr("تذكّرني بأمان (تشفير Android Keystore)", "Remember me securely (Android Keystore)"),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        tr("رمز الجهاز: ${state.accountState.deviceInstallId.take(16)}…", "Device ID: ${state.accountState.deviceInstallId.take(16)}…"),
                        style = MaterialTheme.typography.labelSmall,
                    )
                    TextButton(onClick = { onCopyDeviceId(state.accountState.deviceInstallId) }) {
                        Text(tr("نسخ الرمز", "Copy ID"))
                    }
                }
                if (showResetHelp) {
                    Text(
                        tr(
                            "لإعادة تعيين كلمة المرور أو تفعيل جهاز جديد، أرسل اسم المستخدم ورمز جهازك للمشرف لإصدار شهادة محدّثة.",
                            "To reset your password or authorize a new device, send your username and Device ID to the administrator.",
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary,
                    )
                } else {
                    TextButton(onClick = { showResetHelp = true }) {
                        Text(tr("نسيت كلمة المرور؟", "Forgot password?"))
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
                Text(if (state.authLoading) tr("جارٍ التحقق…", "Verifying…") else tr("تسجيل الدخول", "Sign In"))
            }
        },
        dismissButton = {
            OutlinedButton(onClick = { vm.syncEnterpriseBundle() }) {
                Text(tr("تحديث التراخيص", "Sync Licenses"))
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
        SignedAppUpdateBanner(state = state, vm = vm)
        AccountLicenseCard(state = state, liveRemainingSec = liveRemainingSec, vm = vm, onCopy = onCopy)
        TunnelSpeedStudioCard(state = state, vpnStatus = vpnStatus, vm = vm)
        NetworkDiagnosticsCard(state = state, vm = vm)
        BlockingDetectionCard(vm = vm)
        AntiCensorshipToolsCard(vm = vm)
        AppHealthAndFailoverCard(state = state, vm = vm, onCopy = onCopy)
    }
}
