// =====================================================================
// MainActivity.kt — نقطة الدخول لتطبيق bahrain-vpn: Material 3 + RTL + 4 تبويبات.
// =====================================================================
package com.bahrain.vpnconfigs

import android.Manifest
import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.LayoutDirection
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.bahrain.vpnconfigs.data.Prefs
import com.bahrain.vpnconfigs.ui.AppTheme
import com.bahrain.vpnconfigs.ui.AppViewModel
import com.bahrain.vpnconfigs.ui.AppsSplitScreen
import com.bahrain.vpnconfigs.ui.ConnectHomeScreen
import com.bahrain.vpnconfigs.ui.PromoPopupDialog
import com.bahrain.vpnconfigs.ui.ServerItem
import com.bahrain.vpnconfigs.ui.ServersListScreen
import com.bahrain.vpnconfigs.ui.SettingsAndExportScreen
import com.bahrain.vpnconfigs.vpn.BahrainVpnService
import com.bahrain.vpnconfigs.vpn.VpnStateManager
import com.bahrain.vpnconfigs.work.RefreshWorker
import java.io.File
import java.util.concurrent.TimeUnit

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        scheduleRefreshIfEnabled()

        setContent {
            AppTheme {
                CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
                    AppRoot()
                }
            }
        }
    }

    private fun scheduleRefreshIfEnabled() {
        val wm = WorkManager.getInstance(this)
        if (Prefs(this).autoRefresh) {
            val req = PeriodicWorkRequestBuilder<RefreshWorker>(1, TimeUnit.HOURS).build()
            wm.enqueueUniquePeriodicWork("refresh", ExistingPeriodicWorkPolicy.KEEP, req)
        } else {
            wm.cancelUniqueWork("refresh")
        }
    }
}

@Composable
private fun AppRoot(vm: AppViewModel = viewModel()) {
    var tab by remember { mutableIntStateOf(0) }
    val ctx = LocalContext.current
    val state = vm.state
    val vpnStatus by VpnStateManager.status.collectAsState()

    var pendingTarget by remember { mutableStateOf<Pair<String, String>?>(null) }
    var backgroundedAtMs by remember { mutableLongStateOf(0L) }
    var skipNextReopenPromo by remember { mutableStateOf(false) }
    val lifecycleOwner = LocalLifecycleOwner.current

    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_STOP -> {
                    val changingCfg = (ctx as? Activity)?.isChangingConfigurations == true
                    if (!changingCfg) {
                        backgroundedAtMs = System.currentTimeMillis()
                    }
                }
                Lifecycle.Event.ON_START -> {
                    val bgAt = backgroundedAtMs
                    backgroundedAtMs = 0L
                    if (skipNextReopenPromo) {
                        skipNextReopenPromo = false
                    } else if (bgAt > 0L && pendingTarget == null && System.currentTimeMillis() - bgAt >= 15_000L) {
                        vm.triggerNextPromoBanner()
                    }
                }
                else -> Unit
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    val notifLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission(),
    ) { /* اختياري لإظهار إشعار السرعة في أندرويد 13+ */ }

    LaunchedEffect(Unit) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                ctx,
                Manifest.permission.POST_NOTIFICATIONS,
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                notifLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult(),
    ) { res ->
        val target = pendingTarget
        pendingTarget = null
        if (res.resultCode == Activity.RESULT_OK && target != null) {
            BahrainVpnService.startConnect(ctx, target.first, target.second)
        } else if (res.resultCode != Activity.RESULT_OK) {
            Toast.makeText(ctx, "يجب الموافقة على صلاحية الـ VPN لبدء الاتصال", Toast.LENGTH_SHORT).show()
        }
    }

    fun requestConnect(server: ServerItem?) {
        if (server == null) {
            Toast.makeText(ctx, "لا توجد سيرفرات متاحة حاليًا — جارٍ تحديث القائمة", Toast.LENGTH_SHORT).show()
            vm.refresh()
            return
        }
        vm.selectServer(server)
        val prep = VpnService.prepare(ctx)
        if (prep != null) {
            pendingTarget = server.cfg to server.name
            vpnPermissionLauncher.launch(prep)
        } else {
            BahrainVpnService.startConnect(ctx, server.cfg, server.name)
        }
    }

    Scaffold(
        bottomBar = {
            NavigationBar {
                NavigationBarItem(
                    selected = tab == 0,
                    onClick = { tab = 0 },
                    icon = { Icon(Icons.Filled.Shield, contentDescription = null) },
                    label = { Text("الاتصال") },
                )
                NavigationBarItem(
                    selected = tab == 1,
                    onClick = { tab = 1 },
                    icon = {
                        BadgedBox(
                            badge = {
                                if (state.servers.isNotEmpty()) {
                                    Badge { Text("${state.servers.size}") }
                                }
                            }
                        ) {
                            Icon(Icons.Filled.Dns, contentDescription = null)
                        }
                    },
                    label = { Text("السيرفرات") },
                )
                NavigationBarItem(
                    selected = tab == 2,
                    onClick = {
                        tab = 2
                        vm.ensureAppsLoaded()
                    },
                    icon = {
                        BadgedBox(
                            badge = {
                                if (state.splitApps.isNotEmpty()) {
                                    Badge { Text("${state.splitApps.size}") }
                                }
                            }
                        ) {
                            Icon(Icons.Filled.Apps, contentDescription = null)
                        }
                    },
                    label = { Text("التطبيقات") },
                )
                NavigationBarItem(
                    selected = tab == 3,
                    onClick = { tab = 3 },
                    icon = { Icon(Icons.Filled.Settings, contentDescription = null) },
                    label = { Text("الإعدادات") },
                )
            }
        },
    ) { pad ->
        val m = Modifier.padding(pad)
        when (tab) {
            0 -> ConnectHomeScreen(
                state = state,
                vpnStatus = vpnStatus,
                vm = vm,
                modifier = m,
                onToggleConnect = {
                    if (vpnStatus.isActive) {
                        BahrainVpnService.stopVpn(ctx)
                    } else {
                        requestConnect(state.selectedServer)
                    }
                },
                onNextServer = { BahrainVpnService.switchNextServer(ctx) },
                onOpenServersTab = { tab = 1 },
                onCopy = { txt, msg -> copyToClipboard(ctx, txt, msg) },
            )
            1 -> ServersListScreen(
                state = state,
                vpnStatus = vpnStatus,
                vm = vm,
                modifier = m,
                onConnectServer = { srv -> requestConnect(srv) },
                onReadClipboard = { readClipboardText(ctx) },
                onCopy = { txt, msg -> copyToClipboard(ctx, txt, msg) },
            )
            2 -> AppsSplitScreen(
                state = state,
                vm = vm,
                modifier = m,
            )
            else -> SettingsAndExportScreen(
                vm = vm,
                state = state,
                modifier = m,
                onCopy = { txt, msg -> copyToClipboard(ctx, txt, msg) },
                onCopyFile = { file -> copyFileContent(ctx, file) },
                onShareFile = { file -> shareFile(ctx, file) },
            )
        }
    }

    state.activePromo?.let { promo ->
        PromoPopupDialog(
            banner = promo,
            onDismiss = { vm.dismissPromo() },
            onLinkOpened = { skipNextReopenPromo = true },
        )
    }
}

private fun readClipboardText(ctx: Context): String {
    val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    val item = cm.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)
    return item?.coerceToText(ctx)?.toString() ?: ""
}

private fun copyToClipboard(ctx: Context, text: String, toastMsg: String = "تم النسخ للحافظة") {
    val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    cm.setPrimaryClip(ClipData.newPlainText("bahrain-vpn", text))
    Toast.makeText(ctx, toastMsg, Toast.LENGTH_SHORT).show()
}

private fun copyFileContent(ctx: Context, file: File) {
    runCatching {
        val content = file.readText(Charsets.UTF_8)
        copyToClipboard(ctx, content, "تم نسخ القائمة إلى الحافظة")
    }.onFailure {
        Toast.makeText(ctx, "تعذّرت قراءة البيانات المطلوبة", Toast.LENGTH_SHORT).show()
    }
}

private fun shareFile(ctx: Context, file: File) {
    runCatching {
        val uri = FileProvider.getUriForFile(ctx, "${ctx.packageName}.files", file)
        val i = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        ctx.startActivity(Intent.createChooser(i, "مشاركة قائمة السيرفرات"))
    }.onFailure {
        Toast.makeText(ctx, "تعذّرت مشاركة القائمة", Toast.LENGTH_SHORT).show()
    }
}
