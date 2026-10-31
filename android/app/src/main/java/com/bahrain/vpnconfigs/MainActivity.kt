// =====================================================================
// MainActivity.kt — نقطة الدخول لتطبيق bahrain-vpn (v2): Material 3 + دعم ثنائي اللغة (العربية أساسية RTL + الإنجليزية LTR).
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
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Star
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
import com.bahrain.vpnconfigs.ui.CommunityTestingScreen
import com.bahrain.vpnconfigs.ui.ConnectHomeScreen
import com.bahrain.vpnconfigs.ui.EnterpriseHubScreen
import com.bahrain.vpnconfigs.ui.FavoritesScreen
import com.bahrain.vpnconfigs.ui.MandatoryLoginGateDialog
import com.bahrain.vpnconfigs.ui.SecurityStatusScreen
import com.bahrain.vpnconfigs.ui.ServerHistoryScreen
import com.bahrain.vpnconfigs.ui.ServerItem
import com.bahrain.vpnconfigs.ui.ServersListScreen
import com.bahrain.vpnconfigs.ui.SettingsAndExportScreen
import com.bahrain.vpnconfigs.ui.VpnHotspotScreen
import com.bahrain.vpnconfigs.engine.Converters
import com.bahrain.vpnconfigs.util.AppI18n
import com.bahrain.vpnconfigs.util.tr
import com.bahrain.vpnconfigs.vpn.BahrainVpnService
import com.bahrain.vpnconfigs.vpn.ResourceAndBatteryMonitor
import com.bahrain.vpnconfigs.vpn.VpnStateManager
import com.bahrain.vpnconfigs.work.RefreshWorker
import java.io.File
import java.util.concurrent.TimeUnit

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        AppI18n.initFromPrefs(this)
        enableEdgeToEdge()
        scheduleRefreshIfEnabled()

        setContent {
            val activeLang = AppI18n.current
            AppTheme {
                CompositionLocalProvider(LocalLayoutDirection provides activeLang.layoutDirection) {
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
    val lifecycleOwner = LocalLifecycleOwner.current

    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_STOP -> {
                    ResourceAndBatteryMonitor.isUiInForeground = false
                }
                Lifecycle.Event.ON_START -> {
                    ResourceAndBatteryMonitor.isUiInForeground = true
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
            Toast.makeText(
                ctx,
                tr("يجب الموافقة على صلاحية الـ VPN لبدء الاتصال", "VPN permission is required to connect"),
                Toast.LENGTH_SHORT,
            ).show()
        }
    }

    fun requestConnect(server: ServerItem?) {
        vm.refreshEnterpriseState()
        val acct = vm.state.accountState
        if (!acct.canConnectVpn) {
            Toast.makeText(
                ctx,
                acct.displayStatusDetail.ifBlank {
                    tr("يلزم حساب فعّال لبدء الاتصال", "An active account is required to connect")
                },
                Toast.LENGTH_LONG,
            ).show()
            tab = 7
            return
        }
        if (server == null) {
            Toast.makeText(
                ctx,
                tr("لا توجد سيرفرات متاحة حاليًا — جارٍ تحديث القائمة", "No servers available — refreshing list…"),
                Toast.LENGTH_SHORT,
            ).show()
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

    val serversById = remember(state.servers) {
        state.servers.associateBy { it.serverId }
    }

    Scaffold(
        bottomBar = {
            NavigationBar {
                NavigationBarItem(
                    selected = tab == 0,
                    onClick = { tab = 0 },
                    icon = { Icon(Icons.Filled.Shield, contentDescription = null) },
                    label = { Text(tr("الاتصال", "Connect"), maxLines = 1) },
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
                    label = { Text(tr("السيرفرات", "Servers"), maxLines = 1) },
                )
                NavigationBarItem(
                    selected = tab == 2,
                    onClick = {
                        tab = 2
                        vm.refreshPersistenceSnapshotAsync()
                    },
                    icon = {
                        BadgedBox(
                            badge = {
                                if (state.favoritesList.isNotEmpty()) {
                                    Badge { Text("${state.favoritesList.size}") }
                                }
                            }
                        ) {
                            Icon(Icons.Filled.Star, contentDescription = null)
                        }
                    },
                    label = { Text(tr("المفضّلة", "Favorites"), maxLines = 1) },
                )
                NavigationBarItem(
                    selected = tab == 3,
                    onClick = {
                        tab = 3
                        vm.refreshPersistenceSnapshotAsync()
                    },
                    icon = { Icon(Icons.Filled.History, contentDescription = null) },
                    label = { Text(tr("السجل", "History"), maxLines = 1) },
                )
                NavigationBarItem(
                    selected = tab == 4,
                    onClick = {
                        tab = 4
                        vm.refreshPersistenceSnapshotAsync()
                    },
                    icon = { Icon(Icons.Filled.Security, contentDescription = null) },
                    label = { Text(tr("الأمان", "Security"), maxLines = 1) },
                )
                NavigationBarItem(
                    selected = tab in setOf(5, 6, 7, 8, 9),
                    onClick = { tab = 5 },
                    icon = { Icon(Icons.Filled.Settings, contentDescription = null) },
                    label = { Text(tr("الإعدادات", "Settings"), maxLines = 1) },
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
                        val smartPick = if (state.smartAutoSelect) {
                            state.smartDecision.primary?.let { p ->
                                state.servers.firstOrNull { it.cfg == p.cfg }
                            }
                        } else null
                        requestConnect(smartPick ?: state.selectedServer)
                    }
                },
                onConnectBestSmart = {
                    val smartPick = state.smartDecision.primary?.let { p ->
                        state.servers.firstOrNull { it.cfg == p.cfg }
                    } ?: state.selectedServer
                    requestConnect(smartPick)
                },
                onNextServer = { BahrainVpnService.switchNextServer(ctx) },
                onOpenServersTab = { tab = 1 },
                onOpenHotspot = { tab = 8 },
                onOpenCommunityTesting = { tab = 9 },
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
            2 -> FavoritesScreen(
                favorites = state.favoritesList,
                groups = state.favoriteGroups,
                selectedGroup = state.favoriteGroupFilter,
                sortOrder = state.favoriteSortOrder,
                serversById = serversById,
                telemetryById = state.telemetryById,
                activeServerId = vpnStatus.activeCfg?.let { Converters.stableServerId(it) }.orEmpty(),
                onSelectGroup = { vm.setFavoriteGroupFilter(it) },
                onSelectSort = { vm.setFavoriteSortOrder(it) },
                onConnectFavorite = { srv -> requestConnect(srv) },
                onEditFavorite = { sid, name, grp -> vm.updateFavoriteDetails(sid, name, grp) },
                onRemoveFavorite = { sid -> vm.removeFavoriteById(sid) },
                modifier = m,
            )
            3 -> ServerHistoryScreen(
                records = state.sqliteHistory,
                totalMatchingCount = state.sqliteHistoryTotal,
                searchQuery = state.historySearchQuery,
                dateRangeDays = state.historyDateDays,
                sortOrder = state.historySortOrder,
                retentionDays = state.historyRetentionDays,
                serversById = serversById,
                onSearchChange = { vm.setHistorySearchQuery(it) },
                onDateRangeChange = { vm.setHistoryDateDays(it) },
                onSortChange = { vm.setHistorySortOrder(it) },
                onRetentionChange = { vm.setHistoryRetentionDays(it) },
                onLoadMore = { vm.loadMoreHistory() },
                onDeleteEntry = { vm.deleteHistoryRecord(it) },
                onClearAll = { vm.clearConnectionHistory() },
                onReconnectServer = { srv -> requestConnect(srv) },
                modifier = m,
            )
            4 -> {
                val secReport = remember(vpnStatus, state.netDiagReport, state.killSwitch) {
                    vm.evaluateSecurityReport(vpnStatus)
                }
                val resSnap = remember(vpnStatus) {
                    ResourceAndBatteryMonitor.captureSnapshot()
                }
                SecurityStatusScreen(
                    report = secReport,
                    appKillSwitchEnabled = state.killSwitch,
                    lastProtectionEvent = vpnStatus.lastProtectionEvent,
                    protectionEvents = state.protectionEvents,
                    resourceSnapshot = resSnap,
                    runningDiagnostics = state.netDiagRunning,
                    onToggleAppKillSwitch = { vm.setKillSwitch(it) },
                    onRunLiveSecurityCheck = { vm.runNetworkDiagnosticsSuite() },
                    modifier = m,
                )
            }
            6 -> AppsSplitScreen(
                state = state,
                vm = vm,
                modifier = m,
            )
            7 -> EnterpriseHubScreen(
                state = state,
                vpnStatus = vpnStatus,
                vm = vm,
                modifier = m,
                onCopy = { txt, msg -> copyToClipboard(ctx, txt, msg) },
            )
            8 -> VpnHotspotScreen(
                vpnStatus = vpnStatus,
                onBack = { tab = 0 },
                onCopy = { txt, msg -> copyToClipboard(ctx, txt, msg) },
                modifier = m,
            )
            9 -> CommunityTestingScreen(
                state = state,
                vm = vm,
                onBack = { tab = 0 },
                onLoadIranCommunityPool = {
                    vm.setFeedProfile("iran_community")
                    tab = 1
                },
                modifier = m,
            )
            else -> SettingsAndExportScreen(
                vm = vm,
                state = state,
                modifier = m,
                onCopy = { txt, msg -> copyToClipboard(ctx, txt, msg) },
                onCopyFile = { file -> copyFileContent(ctx, file) },
                onShareFile = { file -> shareFile(ctx, file) },
                onOpenSplitApps = {
                    vm.ensureAppsLoaded()
                    tab = 6
                },
                onOpenEnterpriseHub = {
                    vm.refreshEnterpriseState()
                    tab = 7
                },
                onOpenHotspot = { tab = 8 },
                onOpenCommunityTesting = { tab = 9 },
            )
        }
    }

    if (state.accountState.authRequired && !state.accountState.isLoggedIn) {
        MandatoryLoginGateDialog(
            vm = vm,
            state = state,
            onCopyDeviceId = { id -> copyToClipboard(ctx, id, tr("تم نسخ رمز الجهاز", "Device ID copied")) },
        )
    }
}

private fun readClipboardText(ctx: Context): String {
    val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    val item = cm.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)
    return item?.coerceToText(ctx)?.toString() ?: ""
}

private fun copyToClipboard(
    ctx: Context,
    text: String,
    toastMsg: String = tr("تم النسخ للحافظة", "Copied to clipboard"),
) {
    if (text.isNotBlank()) {
        val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("bahrain-vpn", text))
    }
    Toast.makeText(ctx, toastMsg, Toast.LENGTH_SHORT).show()
}

private fun copyFileContent(ctx: Context, file: File) {
    runCatching {
        val content = file.readText(Charsets.UTF_8)
        copyToClipboard(ctx, content, tr("تم نسخ القائمة إلى الحافظة", "Server list copied to clipboard"))
    }.onFailure {
        Toast.makeText(ctx, tr("تعذّرت قراءة البيانات المطلوبة", "Could not read requested data"), Toast.LENGTH_SHORT).show()
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
        ctx.startActivity(Intent.createChooser(i, tr("مشاركة قائمة السيرفرات", "Share server list")))
    }.onFailure {
        Toast.makeText(ctx, tr("تعذّرت مشاركة القائمة", "Could not share server list"), Toast.LENGTH_SHORT).show()
    }
}
