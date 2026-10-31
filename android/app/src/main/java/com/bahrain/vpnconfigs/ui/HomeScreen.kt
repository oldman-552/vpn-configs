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
//  1) شاشة الاتصال الرئيسية (الاتصال)
// ═══════════════════════════════════════════════════════════════════════════
@Composable
fun ConnectHomeScreen(
    state: UiState,
    vpnStatus: VpnStatus,
    vm: AppViewModel,
    modifier: Modifier = Modifier,
    onToggleConnect: () -> Unit,
    onConnectBestSmart: () -> Unit = onToggleConnect,
    onNextServer: () -> Unit,
    onOpenServersTab: () -> Unit,
    onOpenHotspot: () -> Unit = {},
    onOpenCommunityTesting: () -> Unit = {},
    onCopy: (String, String) -> Unit,
) {
    val ctx = LocalContext.current
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
                modifier = Modifier.weight(1f),
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
                        append(tr("${state.servers.size} سيرفر متاح", "${state.servers.size} servers ready"))
                        if (state.lastUpdatedLabel.isNotBlank()) {
                            append(" • ").append(state.lastUpdatedLabel)
                        }
                    }
                    Text(
                        homeSub,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.secondary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }

            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Surface(
                    color = MaterialTheme.colorScheme.secondaryContainer,
                    shape = RoundedCornerShape(50),
                    modifier = Modifier.clickable {
                        AppI18n.toggleLanguage(ctx)
                        vm.refreshLanguageLabels()
                    },
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                    ) {
                        Icon(
                            Icons.Filled.Language,
                            contentDescription = tr("تبديل اللغة إلى الإنجليزية", "Switch language to Arabic"),
                            tint = MaterialTheme.colorScheme.onSecondaryContainer,
                            modifier = Modifier.size(15.dp),
                        )
                        Spacer(Modifier.width(4.dp))
                        Text(
                            text = if (AppI18n.isEnglish) "عربي" else "EN",
                            color = MaterialTheme.colorScheme.onSecondaryContainer,
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.Bold,
                        )
                    }
                }
                StatusPill(phase = vpnStatus.phase)
            }
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
                            contentDescription = tr("اتصال / إيقاف", "Connect / Disconnect"),
                            tint = if (isConnected) Color.White else ringColor,
                            modifier = Modifier.size(48.dp),
                        )
                    }
                    Spacer(Modifier.height(6.dp))
                    Text(
                        text = when {
                            vpnStatus.phase == VpnPhase.CONNECTION_DEGRADED -> tr("متّصل (بطيء)", "Connected (Slow)")
                            isConnected -> tr("متّصل", "Connected")
                            isProtectedLock -> tr("حجب التسرب نشط", "Kill Switch Active")
                            isBusy -> tr("جارٍ الربط…", "Connecting…")
                            else -> tr("اضغط للاتصال", "Tap to Connect")
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
                title = tr("سرعة التنزيل", "Download Speed"),
                mainValue = VpnStateManager.formatSpeed(vpnStatus.downSpeedBps),
                subValue = tr("الإجمالي: ${VpnStateManager.formatBytes(vpnStatus.totalDownBytes)}", "Total: ${VpnStateManager.formatBytes(vpnStatus.totalDownBytes)}"),
                icon = Icons.Filled.ArrowDownward,
                accent = VpnConnectedGreen,
            )
            TelemetryCard(
                modifier = Modifier.weight(1f),
                title = tr("سرعة الرفع", "Upload Speed"),
                mainValue = VpnStateManager.formatSpeed(vpnStatus.upSpeedBps),
                subValue = if (vpnStatus.livePingMs > 0) {
                    tr("البينغ الحيّ: ${vpnStatus.livePingMs} ms", "Live Ping: ${vpnStatus.livePingMs} ms")
                } else {
                    tr("الإجمالي: ${VpnStateManager.formatBytes(vpnStatus.totalUpBytes)}", "Total: ${VpnStateManager.formatBytes(vpnStatus.totalUpBytes)}")
                },
                icon = Icons.Filled.ArrowUpward,
                accent = MaterialTheme.colorScheme.primary,
            )
        }

        // ── لوحة الاختيار الذكي الموزون + المراقب اللحظي لحركة النفق (v1) ──
        SmartSelectionSummaryCard(
            smartAutoEnabled = state.smartAutoSelect,
            preferredCountry = state.preferredCountry,
            decision = state.smartDecision,
            onToggleSmartAuto = { vm.setSmartAutoSelect(it) },
            onConnectBestNow = onConnectBestSmart,
        )

        RealTimeConnectionMonitorCard(
            vpnStatus = vpnStatus,
            elapsedSeconds = elapsedSec,
        )

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
                        text = if (vpnStatus.isActive) tr("السيرفر المتّصل حاليًا", "Active Server") else tr("السيرفر المختار للاتصال", "Selected Server"),
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
                            Text(tr("القائمة", "Servers"))
                        }
                        if (vpnStatus.isActive) {
                            OutlinedButton(
                                onClick = onNextServer,
                                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp),
                            ) {
                                Icon(Icons.Filled.SkipNext, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(Modifier.width(4.dp))
                                Text(tr("التالي", "Next"))
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
                            Text(tr("فحص السرعة", "Ping Test"))
                        }
                        IconButton(
                            onClick = {
                                onCopy(currentServer.exportUri, tr("نُسخ ${currentServer.name} للحافظة", "Copied ${currentServer.name}"))
                            }
                        ) {
                            Icon(Icons.Filled.ContentCopy, contentDescription = tr("نسخ", "Copy"))
                        }
                    }
                } else {
                    Text(
                        tr(
                            "${UiMessages.MSG_NO_SERVERS}. اضغط «تحديث القائمة» بالأسفل.",
                            "${UiMessages.msgNoServers()}. Tap \"Refresh List\" below.",
                        ),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
        }

        // ── وصول سريع لمشاركة VPN عبر الهوتسبوت (بدون روت) والفحص المجتمعي الموثّق ──
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            OutlinedButton(
                onClick = onOpenHotspot,
                modifier = Modifier.weight(1f),
                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 10.dp),
            ) {
                Icon(Icons.Filled.WifiTethering, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(6.dp))
                Text(
                    tr("نقطة اتصال VPN", "VPN Hotspot"),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            OutlinedButton(
                onClick = onOpenCommunityTesting,
                modifier = Modifier.weight(1f),
                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 10.dp),
            ) {
                Icon(Icons.Filled.Public, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(6.dp))
                Text(
                    tr("فحص المجتمع (IR)", "Community (IR)"),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
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
                        Text(tr("التبديل التلقائي عند الانقطاع", "Auto-Failover on Drop"), style = MaterialTheme.typography.titleMedium)
                        Text(
                            tr(
                                "ينتقل تلقائيًا إلى السيرفر التالي إن توقّف السيرفر الحالي",
                                "Automatically switches to the next verified server if the tunnel drops",
                            ),
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
                        Text(if (state.loading) tr("جارٍ التحديث…", "Refreshing…") else tr("تحديث القائمة", "Refresh List"))
                    }

                    if (state.testing) {
                        Button(
                            onClick = { vm.cancelTest() },
                            colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
                            modifier = Modifier.weight(1f),
                        ) {
                            Icon(Icons.Filled.Close, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(4.dp))
                            Text(tr("إيقاف الفحص", "Stop Scan"))
                        }
                    } else {
                        Button(
                            onClick = { vm.startQuickScan() },
                            enabled = !state.loading && state.servers.isNotEmpty() && state.engineReady,
                            modifier = Modifier.weight(1f),
                        ) {
                            Icon(Icons.Filled.Bolt, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(4.dp))
                            Text(tr("فحص سريع", "Quick Scan"))
                        }
                    }
                }

                Text(
                    tr(
                        "${state.activeNetworkProfile.labelAr}: أفضل ${state.top50Count}/50 مخصّصة • الاحتياطي المؤهّل: ${state.backupPoolCount}",
                        "${state.activeNetworkProfile.labelEn}: Personalized Top ${state.top50Count}/50 • Qualified Backup: ${state.backupPoolCount}",
                    ),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.secondary,
                )

                state.progress?.let { p ->
                    val frac = if (p.total > 0) p.done.toFloat() / p.total else 0f
                    LinearProgressIndicator(progress = { frac }, modifier = Modifier.fillMaxWidth())
                    Text(
                        tr("${p.stage}: ${p.done} / ${p.total}  •  شغّال: ${p.alive}", "${p.stage}: ${p.done} / ${p.total}  •  Alive: ${p.alive}"),
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
                        Text(tr("سجل آخر الاتصالات", "Recent Connections"), style = MaterialTheme.typography.titleMedium)
                        TextButton(onClick = { vm.clearConnectionHistory() }) {
                            Text(tr("مسح", "Clear"), style = MaterialTheme.typography.labelSmall)
                        }
                    }
                    state.connectionHistory.take(5).forEach { entry ->
                        val flag = if (entry.country.isNotBlank()) "${VpnStateManager.countryFlag(entry.country)} ${entry.country} • " else ""
                        val agoMin = ((System.currentTimeMillis() - entry.timestampMs) / 60_000L).coerceAtLeast(0L)
                        val timeTxt = when {
                            agoMin < 1L -> tr("الآن", "Just now")
                            agoMin < 60L -> tr("منذ ${agoMin}د", "${agoMin}m ago")
                            agoMin < 1440L -> tr("منذ ${agoMin / 60L}س", "${agoMin / 60L}h ago")
                            else -> tr("منذ ${agoMin / 1440L}ي", "${agoMin / 1440L}d ago")
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
