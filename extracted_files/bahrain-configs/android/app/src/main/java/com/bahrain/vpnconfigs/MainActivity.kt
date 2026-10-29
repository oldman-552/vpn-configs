// =====================================================================
// MainActivity.kt — نقطة الدخول: Material 3 + RTL + 4 تبويبات.
// =====================================================================
package com.bahrain.vpnconfigs

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.LayoutDirection
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.bahrain.vpnconfigs.ui.AppViewModel
import com.bahrain.vpnconfigs.ui.FilesScreen
import com.bahrain.vpnconfigs.ui.HomeScreen
import com.bahrain.vpnconfigs.ui.ResultsScreen
import com.bahrain.vpnconfigs.ui.SettingsScreen
import com.bahrain.vpnconfigs.ui.AppTheme
import com.bahrain.vpnconfigs.work.RefreshWorker
import java.util.concurrent.TimeUnit

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        scheduleRefresh()

        setContent {
            AppTheme {
                CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
                    AppRoot()
                }
            }
        }
    }

    private fun scheduleRefresh() {
        val req = PeriodicWorkRequestBuilder<RefreshWorker>(1, TimeUnit.HOURS).build()
        WorkManager.getInstance(this)
            .enqueueUniquePeriodicWork("refresh", ExistingPeriodicWorkPolicy.KEEP, req)
    }
}

@Composable
private fun AppRoot(vm: AppViewModel = viewModel()) {
    var tab by remember { mutableIntStateOf(0) }
    val ctx = LocalContext.current
    val state = vm.state

    Scaffold(
        bottomBar = {
            NavigationBar {
                NavigationBarItem(
                    selected = tab == 0,
                    onClick = { tab = 0 },
                    icon = { Icon(Icons.Filled.PlayArrow, contentDescription = null) },
                    label = { Text("الرئيسية") },
                )
                NavigationBarItem(
                    selected = tab == 1,
                    onClick = { tab = 1 },
                    icon = { Icon(Icons.Filled.CheckCircle, contentDescription = null) },
                    label = { Text("النتائج") },
                )
                NavigationBarItem(
                    selected = tab == 2,
                    onClick = { tab = 2 },
                    icon = { Icon(Icons.Filled.Description, contentDescription = null) },
                    label = { Text("الملفات") },
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
            0 -> HomeScreen(state, vm, m)
            1 -> ResultsScreen(state, m, onCopy = { cfg -> copyToClipboard(ctx, cfg) })
            2 -> FilesScreen(state, m, onShare = { file -> shareFile(ctx, file) })
            else -> SettingsScreen(vm, m)
        }
    }
}

private fun copyToClipboard(ctx: Context, text: String) {
    val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    cm.setPrimaryClip(ClipData.newPlainText("config", text))
    Toast.makeText(ctx, "نُسخ الكانفيغ", Toast.LENGTH_SHORT).show()
}

private fun shareFile(ctx: Context, file: java.io.File) {
    val uri = androidx.core.content.FileProvider.getUriForFile(
        ctx, "${ctx.packageName}.files", file,
    )
    val i = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_STREAM, uri)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    ctx.startActivity(Intent.createChooser(i, "مشاركة الملف"))
}
