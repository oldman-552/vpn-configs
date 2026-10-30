// =====================================================================
// Screens.kt — الواجهات الأربع لتطبيق bahrain-vpn بتصميم Material 3 و RTL:
//   1) ConnectHomeScreen      — زر الاتصال الدائري، العداد، السرعة الحية، السيرفر النشط
//   2) ServersListScreen      — قائمة سيرفرات bahrain-vpn كاملة مع الفلاتر والفحص والمفضلة
//   3) AppsSplitScreen        — استثناء التطبيقات من النفق (Split Tunneling)
//   4) SettingsAndExportScreen — إعدادات DNS والنفق والفحص وتصدير الملفات
// =====================================================================
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
import androidx.compose.material.icons.filled.NetworkCheck
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.SkipNext
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.StarBorder
import androidx.compose.material.icons.filled.SwapHoriz
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.bahrain.vpnconfigs.engine.ServerSortMode
import com.bahrain.vpnconfigs.util.UiMessages
import com.bahrain.vpnconfigs.vpn.VpnPhase
import com.bahrain.vpnconfigs.vpn.VpnStateManager
import com.bahrain.vpnconfigs.vpn.VpnStatus
import kotlinx.coroutines.delay
import java.io.File

// ═══════════════════════════════════════════════════════════════════════════
//  1) شاشة الاتصال الرئيسية (الاتصال)
// ═══════════════════════════════════════════════════════════════════════════
@Composable
fun ConnectHomeScreen(
    state: UiState,
    vpnStatus: VpnStatus,
    vm: AppViewModel,
    modifier: Modifier = Modifier,
    onToggleConnect: () -> Unit,
    onNextServer: () -> Unit,
    onOpenServersTab: () -> Unit,
    onCopy: (String, String) -> Unit,
) {
    var elapsedSec by remember { mutableLongStateOf(0L) }

    LaunchedEffect(vpnStatus.phase, vpnStatus.connectedSinceMs) {
        if (vpnStatus.isTunnelVerified && vpnStatus.connectedSinceMs > 0L) {
            while (true) {
                elapsedSec = ((System.currentTimeMillis() - vpnStatus.connectedSinceMs) / 1000L)
                    .coerceAtLeast(0L)
                delay(1000L)
            }
        } else {
            elapsedSec = 0L
        }
    }

    val isConnected = vpnStatus.isTunnelVerified
    val isBusy = vpnStatus.isTransitioning
    val isProtectedLock = vpnStatus.phase == VpnPhase.PROTECTION_ACTIVE

    val ringColor by animateColorAsState(
        targetValue = when {
            vpnStatus.phase == VpnPhase.CONNECTED -> VpnConnectedGreen
            vpnStatus.phase == VpnPhase.CONNECTION_DEGRADED -> VpnConnectingAmber
            isBusy -> VpnConnectingAmber
            isProtectedLock -> VpnConnectingAmber
            vpnStatus.phase == VpnPhase.CONNECTION_FAILED -> VpnDangerRed
            else -> MaterialTheme.colorScheme.primary
        },
        label = "vpnRingColor",
    )

    val pulse = rememberInfiniteTransition(label = "pulse")
    val pulseScale by pulse.animateFloat(
        initialValue = 1.0f,
        targetValue = if (isBusy) 1.09f else if (isConnected) 1.03f else 1.0f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1100, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "pulseScale",
    )

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 14.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        // ── الشريط العلوي وحالة الحماية ──
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Icon(
                    Icons.Filled.Shield,
                    contentDescription = null,
                    tint = ringColor,
                    modifier = Modifier.size(28.dp),
                )
                Column {
                    Text(
                        "bahrain-vpn",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.ExtraBold,
                    )
                    val homeSub = buildString {
                        append("${state.servers.size} سيرفر متاح")
                        if (state.lastUpdatedLabel.isNotBlank()) {
                            append(" • ").append(state.lastUpdatedLabel)
                        }
                    }
                    Text(
                        homeSub,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.secondary,
                    )
                }
            }

            StatusPill(phase = vpnStatus.phase)
        }

        // ── رسائل التنبيه أو الحالة ──
        val bannerError = vpnStatus.error ?: state.error
        val bannerInfo = state.info ?: vpnStatus.statusMessage
        if (bannerError != null) {
            BannerCard(text = bannerError, isError = true)
        } else if (bannerInfo != null) {
            BannerCard(text = bannerInfo, isError = false)
        }

        Spacer(Modifier.height(4.dp))

        // ── زر الاتصال الدائري الكبير + العداد ──
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier.size(196.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(190.dp)
                    .scale(pulseScale)
                    .clip(CircleShape)
                    .background(ringColor.copy(alpha = if (isConnected || isBusy) 0.16f else 0.08f))
            )
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .size(158.dp)
                    .clip(CircleShape)
                    .background(
                        Brush.radialGradient(
                            colors = listOf(
                                ringColor.copy(alpha = if (isConnected) 0.95f else 0.22f),
                                ringColor.copy(alpha = if (isConnected) 0.72f else 0.10f),
                            )
                        )
                    )
                    .border(3.dp, ringColor, CircleShape)
                    .clickable(onClick = onToggleConnect),
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    if (isBusy) {
                        CircularProgressIndicator(
                            color = ringColor,
                            strokeWidth = 3.dp,
                            modifier = Modifier.size(40.dp),
                        )
                    } else {
                        Icon(
                            Icons.Filled.PowerSettingsNew,
                            contentDescription = "اتصال / إيقاف",
                            tint = if (isConnected) Color.White else ringColor,
                            modifier = Modifier.size(48.dp),
                        )
                    }
                    Spacer(Modifier.height(6.dp))
                    Text(
                        text = when {
                            vpnStatus.phase == VpnPhase.CONNECTION_DEGRADED -> "متّصل (بطيء)"
                            isConnected -> "متّصل"
                            isProtectedLock -> "حجب التسرب نشط"
                            isBusy -> "جارٍ الربط…"
                            else -> "اضغط للاتصال"
                        },
                        style = MaterialTheme.typography.titleMedium,
                        color = if (isConnected) Color.White else MaterialTheme.colorScheme.onSurface,
                        fontWeight = FontWeight.Bold,
                    )
                    if (isConnected) {
                        Text(
                            text = VpnStateManager.formatDuration(elapsedSec),
                            fontFamily = FontFamily.Monospace,
                            fontSize = 14.sp,
                            color = Color.White.copy(alpha = 0.92f),
                        )
                    }
                }
            }
        }

        // ── شارة عنوان الخروج المحمي (Exit IP & Country) عند الاتصال ──
        if (isConnected && (vpnStatus.exitCountry.isNotBlank() || vpnStatus.exitIp.isNotBlank())) {
            val flag = VpnStateManager.countryFlag(vpnStatus.exitCountry)
            val txt = buildString {
                append(flag)
                if (vpnStatus.exitCountry.isNotBlank()) append(" ").append(vpnStatus.exitCountry)
                if (vpnStatus.exitIp.isNotBlank()) append("  •  ").append(vpnStatus.exitIp)
            }
            Surface(
                color = VpnConnectedGreen.copy(alpha = 0.14f),
                shape = RoundedCornerShape(50),
            ) {
                Text(
                    text = txt,
                    color = VpnConnectedGreen,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                    fontSize = 13.sp,
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 6.dp),
                )
            }
        }

        // ── بطاقتا السرعة الحيّة والبيانات ──
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            TelemetryCard(
                modifier = Modifier.weight(1f),
                title = "سرعة التنزيل",
                mainValue = VpnStateManager.formatSpeed(vpnStatus.downSpeedBps),
                subValue = "الإجمالي: ${VpnStateManager.formatBytes(vpnStatus.totalDownBytes)}",
                icon = Icons.Filled.ArrowDownward,
                accent = VpnConnectedGreen,
            )
            TelemetryCard(
                modifier = Modifier.weight(1f),
                title = "سرعة الرفع",
                mainValue = VpnStateManager.formatSpeed(vpnStatus.upSpeedBps),
                subValue = if (vpnStatus.livePingMs > 0) {
                    "البينغ الحيّ: ${vpnStatus.livePingMs} ms"
                } else {
                    "الإجمالي: ${VpnStateManager.formatBytes(vpnStatus.totalUpBytes)}"
                },
                icon = Icons.Filled.ArrowUpward,
                accent = MaterialTheme.colorScheme.primary,
            )
        }

        // ── بطاقة السيرفر الحالي ──
        val currentServer = if (vpnStatus.isActive && vpnStatus.activeCfg != null) {
            state.servers.firstOrNull { it.cfg == vpnStatus.activeCfg } ?: ServerItem(
                cfg = vpnStatus.activeCfg,
                name = vpnStatus.activeLabel,
                proto = vpnStatus.activeProto.ifBlank { "VPN" },
                endpoint = vpnStatus.activeEndpoint,
                latencyMs = vpnStatus.livePingMs,
            )
        } else {
            state.selectedServer
        }

        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = if (vpnStatus.isActive) "السيرفر المتّصل حاليًا" else "السيرفر المختار للاتصال",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.secondary,
                    )
                    if (currentServer != null) {
                        ProtoChip(currentServer.proto)
                    }
                }

                if (currentServer != null) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = currentServer.name,
                                style = MaterialTheme.typography.titleLarge,
                                fontWeight = FontWeight.Bold,
                            )
                            Text(
                                text = currentServer.endpoint,
                                style = MaterialTheme.typography.bodyMedium,
                                fontFamily = FontFamily.Monospace,
                                color = MaterialTheme.colorScheme.secondary,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            if (currentServer.locallyTested && currentServer.speedKbps > 0.0) {
                                Text(
                                    text = formatPhoneSpeedLabel(currentServer.speedKbps),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = phoneSpeedColor(currentServer.speedKbps),
                                    fontWeight = FontWeight.Medium,
                                )
                            }
                        }

                        if (vpnStatus.isActive && vpnStatus.livePingMs > 0L) {
                            LatencyBadge(
                                ms = vpnStatus.livePingMs,
                                locallyTested = true,
                                localFailed = false,
                            )
                        } else {
                            LatencyBadge(
                                ms = currentServer.latencyMs,
                                locallyTested = currentServer.locallyTested,
                                localFailed = currentServer.localFailed,
                            )
                        }
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        Button(
                            onClick = onOpenServersTab,
                            modifier = Modifier.weight(1f),
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp),
                        ) {
                            Icon(Icons.Filled.SwapHoriz, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(4.dp))
                            Text("القائمة")
                        }
                        if (vpnStatus.isActive) {
                            OutlinedButton(
                                onClick = onNextServer,
                                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp),
                            ) {
                                Icon(Icons.Filled.SkipNext, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(Modifier.width(4.dp))
                                Text("التالي")
                            }
                        }
                        OutlinedButton(
                            onClick = { vm.pingSingleServer(currentServer) },
                            enabled = state.pingingSingleCfg == null,
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp),
                        ) {
                            if (state.pingingSingleCfg == currentServer.cfg) {
                                CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                            } else {
                                Icon(Icons.Filled.NetworkCheck, contentDescription = null, modifier = Modifier.size(18.dp))
                            }
                            Spacer(Modifier.width(4.dp))
                            Text("فحص السرعة")
                        }
                        IconButton(
                            onClick = {
                                onCopy(currentServer.exportUri, "نُسخ ${currentServer.name} للحافظة")
                            }
                        ) {
                            Icon(Icons.Filled.ContentCopy, contentDescription = "نسخ")
                        }
                    }
                } else {
                    Text(
                        "${UiMessages.MSG_NO_SERVERS}. اضغط «تحديث القائمة» بالأسفل.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
        }

        // ── أدوات الفحص السريع والتبديل الذكي ──
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("التبديل التلقائي عند الانقطاع", style = MaterialTheme.typography.titleMedium)
                        Text(
                            "ينتقل تلقائيًا إلى السيرفر التالي إن توقّف السيرفر الحالي",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.secondary,
                        )
                    }
                    Switch(
                        checked = state.autoFailover,
                        onCheckedChange = { vm.setAutoFailover(it) },
                    )
                }

                HorizontalDivider()

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    OutlinedButton(
                        onClick = { vm.refresh() },
                        enabled = !state.loading && !state.testing,
                        modifier = Modifier.weight(1f),
                    ) {
                        Icon(Icons.Filled.Refresh, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(4.dp))
                        Text(if (state.loading) "جارٍ التحديث…" else "تحديث القائمة")
                    }

                    if (state.testing) {
                        Button(
                            onClick = { vm.cancelTest() },
                            colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
                            modifier = Modifier.weight(1f),
                        ) {
                            Icon(Icons.Filled.Close, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(4.dp))
                            Text("إيقاف الفحص")
                        }
                    } else {
                        Button(
                            onClick = { vm.startTest() },
                            enabled = !state.loading && state.servers.isNotEmpty() && state.engineReady,
                            modifier = Modifier.weight(1f),
                        ) {
                            Icon(Icons.Filled.Speed, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(4.dp))
                            Text("فحص السرعة")
                        }
                    }
                }

                state.progress?.let { p ->
                    val frac = if (p.total > 0) p.done.toFloat() / p.total else 0f
                    LinearProgressIndicator(progress = { frac }, modifier = Modifier.fillMaxWidth())
                    Text(
                        "${p.stage}: ${p.done} / ${p.total}  •  شغّال: ${p.alive}",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
        }

        // ── سجل آخر الاتصالات الناجحة (بدون بيانات اعتماد سرية) ──
        if (state.connectionHistory.isNotEmpty()) {
            ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text("سجل آخر الاتصالات", style = MaterialTheme.typography.titleMedium)
                        TextButton(onClick = { vm.clearConnectionHistory() }) {
                            Text("مسح", style = MaterialTheme.typography.labelSmall)
                        }
                    }
                    state.connectionHistory.take(5).forEach { entry ->
                        val flag = if (entry.country.isNotBlank()) "${VpnStateManager.countryFlag(entry.country)} ${entry.country} • " else ""
                        val agoMin = ((System.currentTimeMillis() - entry.timestampMs) / 60_000L).coerceAtLeast(0L)
                        val timeTxt = when {
                            agoMin < 1L -> "الآن"
                            agoMin < 60L -> "منذ ${agoMin}د"
                            agoMin < 1440L -> "منذ ${agoMin / 60L}س"
                            else -> "منذ ${agoMin / 1440L}ي"
                        }
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "$flag${entry.label} (${entry.proto})",
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = FontWeight.Medium,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                                Text(
                                    text = "${entry.endpoint} • $timeTxt",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.secondary,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            }
                            if (entry.pingMs > 0L) {
                                LatencyBadge(entry.pingMs)
                            }
                        }
                    }
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  2) شاشة قائمة السيرفرات (السيرفرات)
// ═══════════════════════════════════════════════════════════════════════════
@Composable
fun ServersListScreen(
    state: UiState,
    vpnStatus: VpnStatus,
    vm: AppViewModel,
    modifier: Modifier = Modifier,
    onConnectServer: (ServerItem) -> Unit,
    onReadClipboard: () -> String,
    onCopy: (String, String) -> Unit,
) {
    var searchQuery by remember { mutableStateOf("") }
    var selectedFilter by remember { mutableStateOf("ALL") }
    var showImportDialog by remember { mutableStateOf(false) }
    var manualImportText by remember { mutableStateOf("") }

    if (showImportDialog) {
        AlertDialog(
            onDismissRequest = { showImportDialog = false },
            title = { Text("إضافة كانفيغ إلى bahrain-vpn") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        "الصق رابط كانفيغ واحد أو عدة أسطر (vless / vmess / trojan / hy2 / ss / tuic) أو نص اشتراك Base64:",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    OutlinedTextField(
                        value = manualImportText,
                        onValueChange = { manualImportText = it },
                        placeholder = { Text("vless://...") },
                        minLines = 3,
                        maxLines = 6,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    OutlinedButton(
                        onClick = { manualImportText = onReadClipboard() },
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Icon(Icons.Filled.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("جلب من الحافظة")
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        val txt = manualImportText.ifBlank { onReadClipboard() }
                        vm.importConfigsFromText(txt)
                        manualImportText = ""
                        showImportDialog = false
                    }
                ) {
                    Text("إضافة")
                }
            },
            dismissButton = {
                TextButton(onClick = { showImportDialog = false }) {
                    Text("إلغاء")
                }
            },
        )
    }

    val filteredServers = remember(state.servers, searchQuery, selectedFilter, state.filterCountry) {
        state.servers.filter { srv ->
            val passFilter = when (selectedFilter) {
                "ALL" -> true
                "FAV" -> srv.isFavorite
                "STABLE" -> srv.stabilityRuns >= 2 || srv.score >= 70.0
                else -> srv.proto.equals(selectedFilter, ignoreCase = true)
            }
            val passCountry = state.filterCountry == "ALL" ||
                srv.country.equals(state.filterCountry, ignoreCase = true)
            val q = searchQuery.trim()
            val passSearch = q.isEmpty() ||
                srv.name.contains(q, ignoreCase = true) ||
                srv.endpoint.contains(q, ignoreCase = true) ||
                srv.proto.contains(q, ignoreCase = true) ||
                srv.country.contains(q, ignoreCase = true)
            passFilter && passCountry && passSearch
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 14.dp, vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        // ── العنوان وأزرار التحكم السريعة ──
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column {
                Text("قائمة سيرفرات bahrain-vpn", style = MaterialTheme.typography.titleLarge)
                val updatedPart = if (state.lastUpdatedLabel.isNotBlank()) " • ${state.lastUpdatedLabel}" else ""
                Text(
                    "اضغط للاتصال أو التبديل الفوري (${filteredServers.size})$updatedPart",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
            }
            IconButton(onClick = { vm.refresh() }, enabled = !state.loading) {
                Icon(Icons.Filled.Refresh, contentDescription = "تحديث القائمة")
            }
        }

        // ── أزرار الفحص وإضافة كانفيغ ──
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            if (state.testing) {
                Button(
                    onClick = { vm.cancelTest() },
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp),
                ) {
                    Icon(Icons.Filled.Close, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("إيقاف الفحص")
                }
            } else {
                Button(
                    onClick = { vm.startTest() },
                    enabled = state.servers.isNotEmpty() && state.engineReady,
                    modifier = Modifier.weight(1.15f),
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp),
                ) {
                    Icon(Icons.Filled.Speed, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("فحص السرعة")
                }
                OutlinedButton(
                    onClick = { vm.startQuickPingTest() },
                    enabled = state.servers.isNotEmpty() && state.engineReady,
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp),
                ) {
                    Icon(Icons.Filled.Bolt, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("فحص التأخير")
                }
            }
            OutlinedButton(
                onClick = {
                    val clip = onReadClipboard().trim()
                    manualImportText = if (clip.contains("://")) clip else ""
                    showImportDialog = true
                },
                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp),
            ) {
                Icon(Icons.Filled.Add, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(4.dp))
                Text("إضافة")
            }
        }

        state.progress?.let { p ->
            val frac = if (p.total > 0) p.done.toFloat() / p.total else 0f
            LinearProgressIndicator(progress = { frac }, modifier = Modifier.fillMaxWidth())
            Text(
                "${p.stage}: ${p.done}/${p.total} • شغّال: ${p.alive}",
                style = MaterialTheme.typography.labelSmall,
            )
        }

        state.info?.let { BannerCard(text = it, isError = false) }
        state.error?.let { BannerCard(text = it, isError = true) }

        // ── حقل البحث ──
        OutlinedTextField(
            value = searchQuery,
            onValueChange = { searchQuery = it },
            placeholder = { Text("ابحث بالرقم (مثل 12) أو البروتوكول أو العنوان…") },
            leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
            trailingIcon = {
                if (searchQuery.isNotEmpty()) {
                    IconButton(onClick = { searchQuery = "" }) {
                        Icon(Icons.Filled.Close, contentDescription = "مسح")
                    }
                }
            },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )

        // ── شريط خيارات الترتيب الخمسة («الأسرع في التنزيل» افتراضيًا) ──
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = "الترتيب:",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.secondary,
            )
            ServerSortMode.entries.forEach { mode ->
                FilterChip(
                    selected = ServerSortMode.fromKey(state.sortMode) == mode,
                    onClick = { vm.setSortMode(mode.key) },
                    label = { Text(mode.titleAr) },
                )
            }
        }

        // ── شرائح الفلترة (البروتوكولات + المفضلة + المستقرة) ──
        val chips = listOf(
            "ALL" to "الكل",
            "FAV" to "⭐ المفضلة",
            "STABLE" to "🛡️ المستقرة",
            "HY2" to "HY2",
            "VLESS" to "VLESS",
            "TROJAN" to "TROJAN",
            "VMESS" to "VMESS",
            "SS" to "SS",
            "TUIC" to "TUIC",
        )
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            chips.forEach { (key, title) ->
                FilterChip(
                    selected = selectedFilter == key,
                    onClick = { selectedFilter = key },
                    label = { Text(title) },
                )
            }
        }

        // ── فلتر الدول الديناميكي ──
        if (state.availableCountries.isNotEmpty()) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                FilterChip(
                    selected = state.filterCountry == "ALL",
                    onClick = { vm.setFilterCountry("ALL") },
                    label = { Text("🌍 كل الدول") },
                )
                state.availableCountries.forEach { (cc, count) ->
                    val flag = VpnStateManager.countryFlag(cc)
                    FilterChip(
                        selected = state.filterCountry == cc,
                        onClick = { vm.setFilterCountry(cc) },
                        label = { Text("$flag $cc ($count)") },
                    )
                }
            }
        }

        // ── قائمة السيرفرات ──
        if (filteredServers.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(24.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    when {
                        state.loading -> "${UiMessages.MSG_UPDATING}…"
                        state.servers.isEmpty() -> "${UiMessages.MSG_NO_SERVERS}."
                        else -> "لا توجد سيرفرات مطابقة للفلتر الحالي."
                    },
                    style = MaterialTheme.typography.bodyLarge,
                )
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                contentPadding = PaddingValues(bottom = 16.dp),
            ) {
                items(filteredServers, key = { it.cfg }) { srv ->
                    val isActiveVpn = vpnStatus.isActive && vpnStatus.activeCfg == srv.cfg
                    val isSelected = state.selectedCfg == srv.cfg
                    ServerCard(
                        item = srv,
                        isActiveVpn = isActiveVpn,
                        isSelected = isSelected,
                        isPinging = state.pingingSingleCfg == srv.cfg,
                        onConnect = { onConnectServer(srv) },
                        onToggleFav = { vm.toggleFavorite(srv.cfg) },
                        onPing = { vm.pingSingleServer(srv) },
                        onCopy = {
                            if (srv.isVip) {
                                onCopy("", "عقدة VIP مشفّرة ومحمية — مخصّصة للاتصال المباشر فقط")
                            } else {
                                onCopy(srv.exportUri, "نُسخ ${srv.name} للحافظة")
                            }
                        },
                        onDeleteCustom = if (srv.isCustom) ({ vm.removeCustomServer(srv.cfg) }) else null,
                    )
                }
            }
        }
    }
}

@Composable
private fun ServerCard(
    item: ServerItem,
    isActiveVpn: Boolean,
    isSelected: Boolean,
    isPinging: Boolean,
    onConnect: () -> Unit,
    onToggleFav: () -> Unit,
    onPing: () -> Unit,
    onCopy: () -> Unit,
    onDeleteCustom: (() -> Unit)?,
) {
    val borderStroke = when {
        isActiveVpn -> BorderStroke(2.dp, VpnConnectedGreen)
        isSelected -> BorderStroke(1.2.dp, MaterialTheme.colorScheme.primary)
        else -> null
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onConnect),
        border = borderStroke,
        colors = CardDefaults.cardColors(
            containerColor = if (isActiveVpn) {
                MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.45f)
            } else {
                MaterialTheme.colorScheme.surface
            }
        ),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    modifier = Modifier.weight(1f),
                ) {
                    ProtoChip(item.proto)
                    if (item.country.isNotBlank()) {
                        Surface(
                            color = MaterialTheme.colorScheme.secondaryContainer,
                            shape = RoundedCornerShape(6.dp),
                        ) {
                            Text(
                                text = "${VpnStateManager.countryFlag(item.country)} ${item.country}",
                                color = MaterialTheme.colorScheme.onSecondaryContainer,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Medium,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                            )
                        }
                    }
                    Text(
                        text = item.name,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    if (item.isVip) {
                        Surface(
                            color = Color(0xFFFFB300).copy(alpha = 0.22f),
                            shape = RoundedCornerShape(6.dp),
                        ) {
                            Text(
                                "VIP 💎",
                                color = Color(0xFFFFA000),
                                fontSize = 10.sp,
                                fontWeight = FontWeight.ExtraBold,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                            )
                        }
                    }
                    if (item.isCustom) {
                        AssistChip(
                            onClick = onConnect,
                            label = { Text("مخصّص", fontSize = 10.sp) },
                            modifier = Modifier.height(24.dp),
                        )
                    }
                    if (isActiveVpn) {
                        Surface(
                            color = VpnConnectedGreen,
                            shape = RoundedCornerShape(6.dp),
                        ) {
                            Text(
                                "متّصل",
                                color = Color.White,
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                            )
                        }
                    }
                }

                LatencyBadge(
                    ms = item.latencyMs,
                    locallyTested = item.locallyTested,
                    localFailed = item.localFailed,
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = item.endpoint,
                        style = MaterialTheme.typography.bodyMedium,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.secondary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    if (item.locallyTested && item.speedKbps > 0.0) {
                        Text(
                            text = formatPhoneSpeedLabel(item.speedKbps),
                            style = MaterialTheme.typography.labelSmall,
                            color = phoneSpeedColor(item.speedKbps),
                            fontWeight = FontWeight.Medium,
                        )
                    }
                    val telemetryParts = buildList {
                        if (item.securityAssessment == "Verified") add("🔒 تشفير موثّق")
                        else if (item.securityAssessment == "Failed") add("⚠ تحذير تشفير")
                        if (item.privacyAssessment == "Verified") add("🛡 خصوصية موثّقة")
                        else if (item.privacyAssessment == "Unverified") add("مشغّل عام غير موثّق")
                        if (item.locallyTested) add("✓ فُحص على شبكتك")
                        if (item.overallScore > 0.0) add("الإجمالي ${item.overallScore.toInt()}%")
                        if (item.stabilityRuns >= 2) add("مستقر ×${item.stabilityRuns}")
                        if (item.jitterMs > 0.5) add("تذبذب ±${item.jitterMs.toInt()}ms")
                        if (item.lastTestedAtMs > 0L) {
                            val agoMin = ((System.currentTimeMillis() - item.lastTestedAtMs) / 60_000L).coerceAtLeast(0L)
                            val testedLbl = when {
                                agoMin < 1L -> "اختُبر الآن"
                                agoMin < 60L -> "اختُبر منذ ${agoMin}د"
                                agoMin < 1440L -> "اختُبر منذ ${agoMin / 60L}س"
                                else -> "اختُبر منذ ${agoMin / 1440L}ي"
                            }
                            add(testedLbl)
                        }
                    }
                    if (telemetryParts.isNotEmpty()) {
                        Text(
                            text = telemetryParts.joinToString(" • "),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.secondary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }

                Row(verticalAlignment = Alignment.CenterVertically) {
                    IconButton(onClick = onToggleFav, modifier = Modifier.size(34.dp)) {
                        Icon(
                            imageVector = if (item.isFavorite) Icons.Filled.Star else Icons.Filled.StarBorder,
                            contentDescription = "مفضلة",
                            tint = if (item.isFavorite) VpnConnectingAmber else MaterialTheme.colorScheme.secondary,
                            modifier = Modifier.size(19.dp),
                        )
                    }
                    IconButton(onClick = onPing, enabled = !isPinging, modifier = Modifier.size(34.dp)) {
                        if (isPinging) {
                            CircularProgressIndicator(modifier = Modifier.size(15.dp), strokeWidth = 2.dp)
                        } else {
                            Icon(
                                Icons.Filled.NetworkCheck,
                                contentDescription = "فحص البينغ",
                                modifier = Modifier.size(18.dp),
                            )
                        }
                    }
                    IconButton(onClick = onCopy, modifier = Modifier.size(34.dp)) {
                        Icon(
                            Icons.Filled.ContentCopy,
                            contentDescription = "نسخ",
                            modifier = Modifier.size(17.dp),
                        )
                    }
                    if (onDeleteCustom != null) {
                        IconButton(onClick = onDeleteCustom, modifier = Modifier.size(34.dp)) {
                            Icon(
                                Icons.Filled.Delete,
                                contentDescription = "حذف",
                                tint = MaterialTheme.colorScheme.error,
                                modifier = Modifier.size(18.dp),
                            )
                        }
                    }
                }
            }
        }
    }
}

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
        Text("التحكم بالتطبيقات (Split Tunneling)", style = MaterialTheme.typography.titleLarge)
        Text(
            "استثنِ تطبيقات البنوك والخدمات المحلية لتعمل على شبكتك العادية بينما يعمل الـ VPN لبقية التطبيقات.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.secondary,
        )

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
                        "تغيّرت قائمة التطبيقات أثناء الاتصال",
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.weight(1f),
                    )
                    Button(onClick = { vm.applyTunnelReload() }) {
                        Icon(Icons.Filled.Check, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("تطبيق الآن")
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
                label = { Text("استثناء المحدد من VPN") },
            )
            FilterChip(
                selected = state.splitIncludeOnly,
                onClick = { vm.setSplitIncludeOnly(true) },
                label = { Text("تشغيل VPN للمحدد فقط") },
            )
        }

        OutlinedTextField(
            value = search,
            onValueChange = { search = it },
            placeholder = { Text("ابحث عن تطبيق (واتساب، يوتيوب، البنك…)…") },
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
                Text("إظهار تطبيقات النظام", style = MaterialTheme.typography.bodyMedium)
            }
            if (state.splitApps.isNotEmpty()) {
                TextButton(onClick = { vm.clearAppSplit() }) {
                    Text("إلغاء تحديد الكل (${state.splitApps.size})")
                }
            }
        }

        if (state.appsLoading) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    CircularProgressIndicator()
                    Spacer(Modifier.height(8.dp))
                    Text("جارٍ قراءة التطبيقات المثبّتة…")
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

// ═══════════════════════════════════════════════════════════════════════════
//  4) شاشة الإعدادات والتصدير (الإعدادات)
// ═══════════════════════════════════════════════════════════════════════════
@Composable
fun SettingsAndExportScreen(
    vm: AppViewModel,
    state: UiState,
    modifier: Modifier = Modifier,
    onCopy: (String, String) -> Unit,
    onCopyFile: (File) -> Unit,
    onShareFile: (File) -> Unit,
) {
    val p = vm.settings()
    var dnsServer by remember { mutableStateOf(p.dnsServer) }
    var dnsDoh by remember { mutableStateOf(p.dnsDoh) }
    var enableIpv6 by remember { mutableStateOf(p.enableIpv6) }
    var udpInTcp by remember { mutableStateOf(p.udpInTcp) }
    var autoFailover by remember { mutableStateOf(p.autoFailover) }
    var killSwitch by remember { mutableStateOf(p.killSwitch) }
    var failoverMode by remember { mutableStateOf(p.failoverMode) }
    var testTop by remember { mutableStateOf(p.testTop.toString()) }
    var speedTop by remember { mutableStateOf(p.speedTop.toString()) }
    var bestN by remember { mutableStateOf(p.bestN.toString()) }
    var conc by remember { mutableStateOf(p.concurrency.toString()) }
    var timeout by remember { mutableStateOf(p.timeoutSec.toString()) }
    var defaultSort by remember(state.sortMode) { mutableStateOf(ServerSortMode.fromKey(state.sortMode).key) }
    var autoRef by remember { mutableStateOf(p.autoRefresh) }
    var showLicensesDialog by remember { mutableStateOf(false) }

    if (showLicensesDialog) {
        AlertDialog(
            onDismissRequest = { showLicensesDialog = false },
            title = { Text("الإشعارات القانونية والتراخيص مفتوحة المصدر") },
            text = {
                Column(
                    modifier = Modifier.verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        "يستخدم تطبيق bahrain-vpn المكوّنات مفتوحة المصدر التالية وفق تراخيصها القانونية المعتمدة:",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Text(
                        "• sing-box — Copyright © SagerNet Contributors (GNU General Public License v3.0 or later).",
                        style = MaterialTheme.typography.labelSmall,
                    )
                    Text(
                        "• hev-socks5-tunnel — Copyright © Heiher (MIT License).",
                        style = MaterialTheme.typography.labelSmall,
                    )
                    Text(
                        "• AndroidX & Jetpack Compose Material 3 — Copyright © The Android Open Source Project (Apache License 2.0).",
                        style = MaterialTheme.typography.labelSmall,
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = { showLicensesDialog = false }) {
                    Text("إغلاق")
                }
            },
        )
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("إعدادات bahrain-vpn", style = MaterialTheme.typography.titleLarge)

        state.info?.let { BannerCard(text = it, isError = false) }
        state.error?.let { BannerCard(text = it, isError = true) }

        // ── إعدادات النفق و DNS ──
        ElevatedCard(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("إعدادات النفق و DNS", style = MaterialTheme.typography.titleMedium)

                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    listOf("1.1.1.1" to "Cloudflare", "8.8.8.8" to "Google", "9.9.9.9" to "Quad9").forEach { (ip, name) ->
                        FilterChip(
                            selected = dnsServer == ip,
                            onClick = { dnsServer = ip },
                            label = { Text("$name ($ip)") },
                        )
                    }
                }

                OutlinedTextField(
                    value = dnsServer,
                    onValueChange = { dnsServer = it },
                    label = { Text("خادم DNS الأساسي") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )

                SettingToggleRow(
                    title = "DNS مشفّر عبر HTTPS (DoH)",
                    subtitle = "مفيد إذا كان مزوّد الخدمة يحجب أو يتلاعب بـ UDP 53",
                    checked = dnsDoh,
                    onCheckedChange = { dnsDoh = it },
                )
                SettingToggleRow(
                    title = "مفتاح الإيقاف الصارم (Kill Switch)",
                    subtitle = "يحجب مرور بيانات التطبيقات خارج النفق أثناء الربط أو عند انقطاع السيرفر",
                    checked = killSwitch,
                    onCheckedChange = { killSwitch = it },
                )
                SettingToggleRow(
                    title = "التبديل التلقائي عند انقطاع السيرفر",
                    subtitle = "ينتقل تلقائيًا لأفضل سيرفر بديل دون قطع نفق الـ VPN",
                    checked = autoFailover,
                    onCheckedChange = {
                        autoFailover = it
                        failoverMode = if (!it) "OFF" else if (failoverMode == "OFF") "SMART" else failoverMode
                    },
                )
                SettingToggleRow(
                    title = "تمرير UDP عبر TCP (UDP-in-TCP)",
                    subtitle = "فعّله فقط إن كانت الشبكة تحظر حزم UDP",
                    checked = udpInTcp,
                    onCheckedChange = { udpInTcp = it },
                )
                SettingToggleRow(
                    title = "تفعيل توجيه IPv6 داخل النفق",
                    subtitle = "يُفضّل إبقاؤه مغلقًا إلا إذا كان السيرفر يدعم IPv6 كاملًا",
                    checked = enableIpv6,
                    onCheckedChange = { enableIpv6 = it },
                )
            }
        }

        // ── إعدادات الفحص والترتيب والتحديث التلقائي ──
        ElevatedCard(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("معاملات الفحص والترتيب والتحديث", style = MaterialTheme.typography.titleMedium)
                NumField(testTop, { testTop = it }, "عدد السيرفرات المفحوصة في الفحص الشامل")
                NumField(speedTop, { speedTop = it }, "عدد السيرفرات المقاسة سرعة تنزيلها عبر النفق")
                NumField(conc, { conc = it }, "التوازي أثناء الفحص (1–12)")
                NumField(timeout, { timeout = it }, "مهلة اختبار كل سيرفر بالثواني")
                NumField(bestN, { bestN = it }, "عدد أفضل السيرفرات المحفوظة للتصدير")

                Text("معيار الترتيب الافتراضي للقائمة", style = MaterialTheme.typography.labelSmall)
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    ServerSortMode.entries.forEach { mode ->
                        FilterChip(
                            selected = ServerSortMode.fromKey(defaultSort) == mode,
                            onClick = { defaultSort = mode.key },
                            label = { Text(mode.titleAr) },
                        )
                    }
                }

                SettingToggleRow(
                    title = "تحديث قائمة السيرفرات تلقائيًا في الخلفية",
                    subtitle = "يجلب أحدث سيرفرات bahrain-vpn دوريًا دون استهلاك بطارية",
                    checked = autoRef,
                    onCheckedChange = { autoRef = it },
                )

                HorizontalDivider()
                Text("نمط التغذية المفضّل", style = MaterialTheme.typography.labelSmall)
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    listOf(
                        "smart" to "الذكي الشامل",
                        "reliable" to "الأكثر استقرارًا",
                        "low_latency" to "الأقل تأخيرًا",
                        "high_throughput" to "الأعلى سرعة",
                        "privacy_aware" to "الأعلى أمانًا",
                    ).forEach { (key, title) ->
                        FilterChip(
                            selected = state.feedProfile == key,
                            onClick = { vm.setFeedProfile(key) },
                            label = { Text(title) },
                        )
                    }
                }
            }
        }

        Button(
            onClick = {
                vm.saveSettings(
                    dnsServer = dnsServer,
                    dnsDoh = dnsDoh,
                    enableIpv6 = enableIpv6,
                    udpInTcp = udpInTcp,
                    autoFailover = autoFailover,
                    testTop = testTop.toIntOrNull() ?: 400,
                    speedTop = speedTop.toIntOrNull() ?: 80,
                    bestN = bestN.toIntOrNull() ?: 100,
                    concurrency = conc.toIntOrNull() ?: 8,
                    timeoutSec = timeout.toIntOrNull() ?: 5,
                    defaultSortMode = defaultSort,
                    autoRefresh = autoRef,
                    killSwitch = killSwitch,
                    failoverMode = failoverMode,
                )
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("حفظ الإعدادات وتطبيقها")
        }

        // ── التصدير والمشاركة المحلية بدون كشف المصدر ──
        ElevatedCard(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("تصدير ومشاركة قوائم bahrain-vpn", style = MaterialTheme.typography.titleMedium)
                Text(
                    "يمكنك نسخ أو مشاركة القوائم المولّدة محليًا على جهازك بالاسم الموحّد bahrain-vpn.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
                ExportFileRow("قائمة أفضل السيرفرات المفحوصة", state.bestFile, onCopyFile, onShareFile)
                ExportFileRow("حزمة الاشتراك المحلية (Base64)", state.subFile, onCopyFile, onShareFile)
                ExportFileRow("قائمة جميع السيرفرات المتاحة", state.allFile, onCopyFile, onShareFile)
            }
        }

        // ── حول التطبيق والإشعارات القانونية المطلوبة ──
        ElevatedCard(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("حول التطبيق والتراخيص القانونية", style = MaterialTheme.typography.titleMedium)
                val aboutUpdated = if (state.lastUpdatedLabel.isNotBlank()) " • ${state.lastUpdatedLabel}" else ""
                Text(
                    "bahrain-vpn v3.2$aboutUpdated",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
                OutlinedButton(
                    onClick = { showLicensesDialog = true },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("عرض تراخيص المكوّنات مفتوحة المصدر")
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  مكوّنات مساعدة مشتركة
// ═══════════════════════════════════════════════════════════════════════════
@Composable
private fun StatusPill(phase: VpnPhase) {
    val (bg, fg, label) = when (phase) {
        VpnPhase.CONNECTED -> Triple(VpnConnectedGreen.copy(alpha = 0.16f), VpnConnectedGreen, "● متّصل ومحمي")
        VpnPhase.CONNECTION_DEGRADED -> Triple(VpnConnectingAmber.copy(alpha = 0.16f), VpnConnectingAmber, "● متّصل (تذبذب)")
        VpnPhase.CONNECTING -> Triple(VpnConnectingAmber.copy(alpha = 0.16f), VpnConnectingAmber, "● جارٍ الاتصال…")
        VpnPhase.RECONNECTING -> Triple(VpnConnectingAmber.copy(alpha = 0.16f), VpnConnectingAmber, "● استعادة المسار…")
        VpnPhase.SWITCHING_SERVER -> Triple(VpnConnectingAmber.copy(alpha = 0.16f), VpnConnectingAmber, "● جارٍ التبديل…")
        VpnPhase.PROTECTION_ACTIVE -> Triple(VpnConnectingAmber.copy(alpha = 0.18f), VpnConnectingAmber, "🛡 Kill Switch نشط")
        VpnPhase.CONNECTION_FAILED -> Triple(VpnDangerRed.copy(alpha = 0.16f), VpnDangerRed, "● تعذّر الاتصال")
        VpnPhase.DISCONNECTED -> Triple(
            MaterialTheme.colorScheme.surfaceVariant,
            MaterialTheme.colorScheme.secondary,
            "○ غير متّصل",
        )
    }
    Surface(color = bg, shape = RoundedCornerShape(50)) {
        Text(
            text = label,
            color = fg,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
        )
    }
}

@Composable
private fun TelemetryCard(
    modifier: Modifier = Modifier,
    title: String,
    mainValue: String,
    subValue: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    accent: Color,
) {
    ElevatedCard(modifier = modifier) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Icon(icon, contentDescription = null, tint = accent, modifier = Modifier.size(16.dp))
                Text(title, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.secondary)
            }
            Text(
                text = mainValue,
                style = MaterialTheme.typography.titleLarge,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold,
            )
            Text(
                text = subValue,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.secondary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

@Composable
private fun ProtoChip(proto: String) {
    Surface(
        color = MaterialTheme.colorScheme.primaryContainer,
        shape = RoundedCornerShape(6.dp),
    ) {
        Text(
            text = proto.uppercase(),
            color = MaterialTheme.colorScheme.onPrimaryContainer,
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(horizontal = 7.dp, vertical = 2.dp),
        )
    }
}

private fun phoneSpeedColor(speedKbps: Double): Color = when {
    speedKbps >= 1024.0 -> VpnConnectedGreen
    speedKbps >= 250.0 -> VpnConnectingAmber
    else -> VpnWeakPurple
}

private fun formatPhoneSpeedLabel(speedKbps: Double): String = when {
    speedKbps >= 1024.0 -> String.format(java.util.Locale.US, "سرعة الاختبار على جهازك: %.2f MB/s", speedKbps / 1024.0)
    speedKbps >= 250.0 -> "سرعة الاختبار على جهازك: ${speedKbps.toInt()} KB/s"
    else -> "سرعة الاختبار على جهازك: ${speedKbps.toInt()} KB/s (ضعيف)"
}

@Composable
private fun LatencyBadge(
    ms: Long,
    locallyTested: Boolean = false,
    localFailed: Boolean = false,
) {
    val isDisconnected = localFailed || ms < 0L
    val isUntested = !isDisconnected && (!locallyTested || ms == 0L)
    val color = when {
        isDisconnected -> VpnDangerRed
        isUntested -> VpnUntestedGray
        ms <= 250L -> VpnConnectedGreen
        ms <= 500L -> VpnConnectingAmber
        else -> VpnWeakPurple
    }
    val label = when {
        isDisconnected -> "منقطع"
        isUntested -> "لم يُفحص"
        ms <= 500L -> "⚡ $ms ms"
        else -> "⚡ $ms ms • ضعيف"
    }
    Surface(
        color = color.copy(alpha = 0.14f),
        shape = RoundedCornerShape(8.dp),
    ) {
        Text(
            text = label,
            color = color,
            fontFamily = FontFamily.Monospace,
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
        )
    }
}

@Composable
private fun BannerCard(text: String, isError: Boolean) {
    Surface(
        color = if (isError) {
            MaterialTheme.colorScheme.errorContainer
        } else {
            MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.65f)
        },
        shape = RoundedCornerShape(10.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text(
            text = text,
            color = if (isError) MaterialTheme.colorScheme.onErrorContainer else MaterialTheme.colorScheme.onPrimaryContainer,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
        )
    }
}

@Composable
private fun SettingToggleRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f).padding(end = 8.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Medium)
            Text(subtitle, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.secondary)
        }
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

@Composable
private fun NumField(v: String, set: (String) -> Unit, label: String) {
    OutlinedTextField(
        value = v,
        onValueChange = { set(it.filter(Char::isDigit)) },
        label = { Text(label) },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
private fun ExportFileRow(
    title: String,
    file: File?,
    onCopyFile: (File) -> Unit,
    onShareFile: (File) -> Unit,
) {
    val ready = file != null && file.exists() && file.length() > 0
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
            Text(
                if (ready) "${file!!.length() / 1024} KB" else "يُولّد بعد التحديث أو الفحص",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.secondary,
            )
        }
        Row {
            IconButton(onClick = { file?.let(onCopyFile) }, enabled = ready) {
                Icon(Icons.Filled.ContentCopy, contentDescription = "نسخ")
            }
            IconButton(onClick = { file?.let(onShareFile) }, enabled = ready) {
                Icon(Icons.Filled.Share, contentDescription = "مشاركة")
            }
        }
    }
}
