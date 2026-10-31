package com.bahrain.vpnconfigs.ui

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.NetworkCheck
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.SkipNext
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.StarBorder
import androidx.compose.material.icons.filled.SwapHoriz
import androidx.compose.material.icons.filled.WifiTethering
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilterChip
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.bahrain.vpnconfigs.data.LocalPoolTier
import com.bahrain.vpnconfigs.engine.ServerSortMode
import com.bahrain.vpnconfigs.util.AppI18n
import com.bahrain.vpnconfigs.util.AppLang
import com.bahrain.vpnconfigs.util.UiMessages
import com.bahrain.vpnconfigs.util.tr
import com.bahrain.vpnconfigs.vpn.VpnPhase
import com.bahrain.vpnconfigs.vpn.VpnStateManager
import com.bahrain.vpnconfigs.vpn.VpnStatus
import kotlinx.coroutines.delay
import java.io.File

// ═══════════════════════════════════════════════════════════════════════════
//  3) شاشة استثناء التطبيقات (التطبيقات — Split Tunneling)
// ═══════════════════════════════════════════════════════════════════════════
@Composable
fun AppsSplitScreen(
    state: UiState,
    vm: AppViewModel,
    modifier: Modifier = Modifier,
) {
    var search by remember { mutableStateOf("") }
    var showSystem by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        vm.ensureAppsLoaded()
    }

    val visibleApps = remember(state.installedApps, search, showSystem, state.splitApps) {
        state.installedApps.filter { app ->
            val passSys = showSystem || !app.isSystem || app.packageName in state.splitApps
            val q = search.trim()
            val passSearch = q.isEmpty() ||
                app.label.contains(q, ignoreCase = true) ||
                app.packageName.contains(q, ignoreCase = true)
            passSys && passSearch
        }.sortedWith(
            compareByDescending<com.bahrain.vpnconfigs.vpn.AppEntry> { it.packageName in state.splitApps }
                .thenBy { it.label.lowercase() }
        )
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 14.dp, vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(tr("التحكم بالتطبيقات (Split Tunneling)", "Per-App Split Tunneling"), style = MaterialTheme.typography.titleLarge)
        Text(
            tr(
                "استثنِ تطبيقات البنوك والخدمات المحلية لتعمل على شبكتك العادية بينما يعمل الـ VPN لبقية التطبيقات.",
                "Exclude banking and local apps so they use your direct network while VPN protects all other apps.",
            ),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.secondary,
        )

        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(12.dp)) {
                SettingToggleRow(
                    title = tr(
                        "استثناء نطاقات .ir من الـ VPN تلقائياً",
                        "Bypass .ir Domains Directly (No VPN)",
                    ),
                    subtitle = tr(
                        "مفعّل افتراضياً — أي اتصال لدومين أو سيرفر ينتهي بـ .ir أو .ایران يمرّ مباشرة بدون سيرفر الـ VPN",
                        "Enabled by default — routes all .ir and .ایران domains/servers directly without passing through the VPN server",
                    ),
                    checked = state.bypassIrDomains,
                    onCheckedChange = { vm.setBypassIrDomains(it) },
                )
            }
        }

        if (state.tunnelNeedsReload) {
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(10.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        tr("تغيّرت قائمة التطبيقات أثناء الاتصال", "Split-tunnel app list changed while connected"),
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.weight(1f),
                    )
                    Button(onClick = { vm.applyTunnelReload() }) {
                        Icon(Icons.Filled.Check, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp))
                        Text(tr("تطبيق الآن", "Apply Now"))
                    }
                }
            }
        }

        // وضع التمرير
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            FilterChip(
                selected = !state.splitIncludeOnly,
                onClick = { vm.setSplitIncludeOnly(false) },
                label = { Text(tr("استثناء المحدد من VPN", "Bypass VPN for Selected")) },
            )
            FilterChip(
                selected = state.splitIncludeOnly,
                onClick = { vm.setSplitIncludeOnly(true) },
                label = { Text(tr("تشغيل VPN للمحدد فقط", "VPN Only for Selected")) },
            )
        }

        OutlinedTextField(
            value = search,
            onValueChange = { search = it },
            placeholder = { Text(tr("ابحث عن تطبيق (واتساب، يوتيوب، البنك…)…", "Search installed apps (WhatsApp, YouTube, Banking…)…")) },
            leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = showSystem, onCheckedChange = { showSystem = it })
                Text(tr("إظهار تطبيقات النظام", "Show System Apps"), style = MaterialTheme.typography.bodyMedium)
            }
            if (state.splitApps.isNotEmpty()) {
                TextButton(onClick = { vm.clearAppSplit() }) {
                    Text(tr("إلغاء تحديد الكل (${state.splitApps.size})", "Clear Selection (${state.splitApps.size})"))
                }
            }
        }

        if (state.appsLoading) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    CircularProgressIndicator()
                    Spacer(Modifier.height(8.dp))
                    Text(tr("جارٍ قراءة التطبيقات المثبّتة…", "Loading installed apps…"))
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(6.dp),
                contentPadding = PaddingValues(bottom = 16.dp),
            ) {
                items(visibleApps, key = { it.packageName }) { app ->
                    val checked = app.packageName in state.splitApps
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { vm.toggleAppSplit(app.packageName) },
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 12.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(10.dp),
                        ) {
                            if (app.icon != null) {
                                Image(
                                    bitmap = app.icon,
                                    contentDescription = null,
                                    modifier = Modifier
                                        .size(38.dp)
                                        .clip(RoundedCornerShape(8.dp)),
                                )
                            } else {
                                Icon(
                                    Icons.Filled.Shield,
                                    contentDescription = null,
                                    modifier = Modifier.size(38.dp),
                                )
                            }
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    app.label,
                                    style = MaterialTheme.typography.titleMedium,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                                Text(
                                    app.packageName,
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.secondary,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            }
                            Checkbox(
                                checked = checked,
                                onCheckedChange = { vm.toggleAppSplit(app.packageName) },
                            )
                        }
                    }
                }
            }
        }
    }
}
