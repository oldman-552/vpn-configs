// =====================================================================
// Screens.kt — الواجهات الأربع لتطبيق bahrain-vpn (v1) بتصميم Material 3
// ودعم ثنائي اللغة (العربية أساسية RTL + الإنجليزية LTR):
//   1) ConnectHomeScreen      — زر الاتصال الدائري، العداد، السرعة الحية، السيرفر النشط
//   2) ServersListScreen      — قائمة سيرفرات bahrain-vpn كاملة مع الفلاتر والفحص والمفضلة
//   3) AppsSplitScreen        — استثناء التطبيقات من النفق (Split Tunneling)
//   4) SettingsAndExportScreen — إعدادات اللغة و DNS والنفق والفحص وتصدير الملفات
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
            title = { Text(tr("إضافة كانفيغ إلى bahrain-vpn", "Import Config to bahrain-vpn")) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        tr(
                            "الصق رابط كانفيغ واحد أو عدة أسطر (vless / vmess / trojan / hy2 / ss / tuic) أو نص اشتراك Base64:",
                            "Paste one or more config URIs (vless / vmess / trojan / hy2 / ss / tuic) or Base64 subscription text:",
                        ),
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
                        Text(tr("جلب من الحافظة", "Paste from Clipboard"))
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
                    Text(tr("إضافة", "Import"))
                }
            },
            dismissButton = {
                TextButton(onClick = { showImportDialog = false }) {
                    Text(tr("إلغاء", "Cancel"))
                }
            },
        )
    }

    val filteredServers = remember(state.servers, searchQuery, selectedFilter, state.filterCountry) {
        state.servers.filter { srv ->
            val passFilter = when (selectedFilter) {
                "ALL" -> true
                "TOP_50" -> srv.localPoolTier == LocalPoolTier.TOP_50 || srv.isVip
                "BACKUP" -> srv.localPoolTier == LocalPoolTier.BACKUP_POOL
                "FAV" -> srv.isFavorite
                "STABLE" -> srv.stabilityScore >= 70.0 || srv.stabilityRuns >= 2
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
            Column(modifier = Modifier.weight(1f)) {
                Text(tr("قائمة سيرفرات bahrain-vpn", "bahrain-vpn Server Pool"), style = MaterialTheme.typography.titleLarge)
                val poolTotal = state.datasetQualifiedCount.takeIf { it > 0 } ?: state.configs.size
                val updatedPart = if (state.lastUpdatedLabel.isNotBlank()) " • ${state.lastUpdatedLabel}" else ""
                Text(
                    tr(
                        "${state.activeNetworkProfile.labelAr}: أفضل ${state.top50Count}/50 • احتياطي ${state.backupPoolCount} • المرشّحات $poolTotal/500$updatedPart",
                        "${state.activeNetworkProfile.labelEn}: Top ${state.top50Count}/50 • Backup ${state.backupPoolCount} • Pool $poolTotal/500$updatedPart",
                    ),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
            }
            IconButton(onClick = { vm.refresh() }, enabled = !state.loading) {
                Icon(Icons.Filled.Refresh, contentDescription = tr("تحديث القائمة", "Refresh list"))
            }
        }

        // ── أزرار الفحص السريع (Top 50) والفحص الشامل (500) وإضافة كانفيغ ──
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
                    Text(tr("إيقاف الفحص", "Stop Scan"))
                }
            } else {
                Button(
                    onClick = { vm.startQuickScan() },
                    enabled = state.servers.isNotEmpty() && state.engineReady,
                    modifier = Modifier.weight(1.1f),
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 8.dp),
                ) {
                    Icon(Icons.Filled.Bolt, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(4.dp))
                    Text(tr("فحص سريع (50)", "Quick Scan (50)"))
                }
                OutlinedButton(
                    onClick = { vm.startFullScan() },
                    enabled = state.servers.isNotEmpty() && state.engineReady,
                    modifier = Modifier.weight(1.1f),
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 8.dp),
                ) {
                    Icon(Icons.Filled.Speed, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(4.dp))
                    Text(tr("فحص شامل (500)", "Full Scan (500)"))
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
                Text(tr("إضافة", "Add"))
            }
        }

        state.progress?.let { p ->
            val frac = if (p.total > 0) p.done.toFloat() / p.total else 0f
            LinearProgressIndicator(progress = { frac }, modifier = Modifier.fillMaxWidth())
            Text(
                tr("${p.stage}: ${p.done}/${p.total} • شغّال: ${p.alive}", "${p.stage}: ${p.done}/${p.total} • Alive: ${p.alive}"),
                style = MaterialTheme.typography.labelSmall,
            )
        }

        state.info?.let { BannerCard(text = it, isError = false) }
        state.error?.let { BannerCard(text = it, isError = true) }

        // ── حقل البحث ──
        OutlinedTextField(
            value = searchQuery,
            onValueChange = { searchQuery = it },
            placeholder = { Text(tr("ابحث بالرقم (مثل 12) أو البروتوكول أو العنوان…", "Search by number, protocol, country, or host…")) },
            leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
            trailingIcon = {
                if (searchQuery.isNotEmpty()) {
                    IconButton(onClick = { searchQuery = "" }) {
                        Icon(Icons.Filled.Close, contentDescription = tr("مسح", "Clear"))
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
                text = tr("الترتيب:", "Sort:"),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.secondary,
            )
            ServerSortMode.entries.forEach { mode ->
                FilterChip(
                    selected = ServerSortMode.fromKey(state.sortMode) == mode,
                    onClick = { vm.setSortMode(mode.key) },
                    label = { Text(mode.displayTitle) },
                )
            }
        }

        // ── شرائح الفلترة (أفضل 50 للشبكة + الاحتياطي + البروتوكولات + المفضلة) ──
        val chips = listOf(
            "ALL" to tr("الكل (${state.servers.size})", "All (${state.servers.size})"),
            "TOP_50" to tr("🏆 أفضل 50 (${state.top50Count})", "🏆 Top 50 (${state.top50Count})"),
            "BACKUP" to tr("🛡️ الاحتياطي (${state.backupPoolCount})", "🛡️ Backup (${state.backupPoolCount})"),
            "FAV" to tr("⭐ المفضلة", "⭐ Favorites"),
            "STABLE" to tr("المستقرة", "Stable"),
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
                    label = { Text(tr("🌍 كل الدول", "🌍 All Countries")) },
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
                        state.loading -> UiMessages.msgUpdating()
                        state.servers.isEmpty() -> "${UiMessages.msgNoServers()}."
                        else -> tr("لا توجد سيرفرات مطابقة للفلتر الحالي.", "No servers match the selected filter.")
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
                                onCopy("", tr("عقدة VIP مشفّرة ومحمية — مخصّصة للاتصال المباشر فقط", "Encrypted VIP node — direct tunnel connection only"))
                            } else {
                                onCopy(srv.exportUri, tr("نُسخ ${srv.name} للحافظة", "Copied ${srv.name}"))
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
                    } else if (item.localPoolTier == LocalPoolTier.TOP_50 && item.personalizedRank > 0) {
                        Surface(
                            color = VpnConnectedGreen.copy(alpha = 0.18f),
                            shape = RoundedCornerShape(6.dp),
                        ) {
                            Text(
                                "Top #${item.personalizedRank}",
                                color = VpnConnectedGreen,
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                            )
                        }
                    } else if (item.localPoolTier == LocalPoolTier.BACKUP_POOL && item.personalizedRank > 50) {
                        Surface(
                            color = MaterialTheme.colorScheme.tertiaryContainer,
                            shape = RoundedCornerShape(6.dp),
                        ) {
                            Text(
                                tr("احتياطي #${item.personalizedRank - 50}", "Backup #${item.personalizedRank - 50}"),
                                color = MaterialTheme.colorScheme.onTertiaryContainer,
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Medium,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                            )
                        }
                    }
                    if (item.isCustom) {
                        AssistChip(
                            onClick = onConnect,
                            label = { Text(tr("مخصّص", "Custom"), fontSize = 10.sp) },
                            modifier = Modifier.height(24.dp),
                        )
                    }
                    if (isActiveVpn) {
                        Surface(
                            color = VpnConnectedGreen,
                            shape = RoundedCornerShape(6.dp),
                        ) {
                            Text(
                                tr("متّصل", "Connected"),
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
                        if (item.securityAssessment == "Verified") add(tr("🔒 تشفير موثّق", "🔒 Verified TLS"))
                        else if (item.securityAssessment == "Failed") add(tr("⚠ تحذير تشفير", "⚠ Weak TLS"))
                        if (item.privacyAssessment == "Verified") add(tr("🛡 خصوصية موثّقة", "🛡 Verified Privacy"))
                        else if (item.privacyAssessment == "Unverified") add(tr("مشغّل عام غير موثّق", "Unverified public operator"))
                        if (item.locallyTested) add(tr("✓ فُحص على شبكتك", "✓ Tested locally"))
                        if (item.overallScore > 0.0) add(tr("الإجمالي ${item.overallScore.toInt()}%", "Score ${item.overallScore.toInt()}%"))
                        if (item.stabilityRuns >= 2) add(tr("مستقر ×${item.stabilityRuns}", "Stable ×${item.stabilityRuns}"))
                        if (item.jitterMs > 0.5) add(tr("تذبذب ±${item.jitterMs.toInt()}ms", "Jitter ±${item.jitterMs.toInt()}ms"))
                        if (item.lastTestedAtMs > 0L) {
                            val agoMin = ((System.currentTimeMillis() - item.lastTestedAtMs) / 60_000L).coerceAtLeast(0L)
                            val testedLbl = when {
                                agoMin < 1L -> tr("اختُبر الآن", "Tested now")
                                agoMin < 60L -> tr("اختُبر منذ ${agoMin}د", "Tested ${agoMin}m ago")
                                agoMin < 1440L -> tr("اختُبر منذ ${agoMin / 60L}س", "Tested ${agoMin / 60L}h ago")
                                else -> tr("اختُبر منذ ${agoMin / 1440L}ي", "Tested ${agoMin / 1440L}d ago")
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
                            contentDescription = tr("مفضلة", "Favorite"),
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
                                contentDescription = tr("فحص البينغ", "Ping test"),
                                modifier = Modifier.size(18.dp),
                            )
                        }
                    }
                    IconButton(onClick = onCopy, modifier = Modifier.size(34.dp)) {
                        Icon(
                            Icons.Filled.ContentCopy,
                            contentDescription = tr("نسخ", "Copy"),
                            modifier = Modifier.size(17.dp),
                        )
                    }
                    if (onDeleteCustom != null) {
                        IconButton(onClick = onDeleteCustom, modifier = Modifier.size(34.dp)) {
                            Icon(
                                Icons.Filled.Delete,
                                contentDescription = tr("حذف", "Delete"),
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
    onOpenSplitApps: () -> Unit = {},
    onOpenEnterpriseHub: () -> Unit = {},
    onOpenHotspot: () -> Unit = {},
    onOpenCommunityTesting: () -> Unit = {},
) {
    val ctx = LocalContext.current
    val p = vm.settings()
    var dnsServer by remember { mutableStateOf(p.dnsServer) }
    var dnsDoh by remember { mutableStateOf(p.dnsDoh) }
    var enableIpv6 by remember { mutableStateOf(p.enableIpv6) }
    var udpInTcp by remember { mutableStateOf(p.udpInTcp) }
    var bypassIrDomains by remember(state.bypassIrDomains) { mutableStateOf(state.bypassIrDomains) }
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
            title = { Text(tr("الإشعارات القانونية والتراخيص مفتوحة المصدر", "Open-Source Licenses & Legal Notices")) },
            text = {
                Column(
                    modifier = Modifier.verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        tr(
                            "يستخدم تطبيق bahrain-vpn المكوّنات مفتوحة المصدر التالية وفق تراخيصها القانونية المعتمدة:",
                            "bahrain-vpn includes the following open-source components under their respective licenses:",
                        ),
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
                    Text(tr("إغلاق", "Close"))
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
        Text(tr("إعدادات bahrain-vpn", "bahrain-vpn Settings"), style = MaterialTheme.typography.titleLarge)

        // ── بطاقة اختيار لغة التطبيق (اللغة العربية هي الأساسية افتراضيًا + الإنجليزية) ──
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        Icons.Filled.Language,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(20.dp),
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        tr("لغة التطبيق (App Language)", "App Language (لغة التطبيق)"),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                    )
                }
                Text(
                    tr(
                        "اللغة العربية هي اللغة الأساسية والافتراضية للتطبيق، ويمكنك التبديل الفوري للإنجليزية في أي وقت.",
                        "Arabic is the primary default language; switch between Arabic (RTL) and English (LTR) anytime.",
                    ),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    FilterChip(
                        selected = AppI18n.current == AppLang.AR,
                        onClick = {
                            AppI18n.setLanguage(ctx, AppLang.AR)
                            vm.refreshLanguageLabels()
                        },
                        label = { Text("العربية (الأساسية)") },
                    )
                    FilterChip(
                        selected = AppI18n.current == AppLang.EN,
                        onClick = {
                            AppI18n.setLanguage(ctx, AppLang.EN)
                            vm.refreshLanguageLabels()
                        },
                        label = { Text("English") },
                    )
                }
            }
        }

        // ── الوصول السريع لاستثناء التطبيقات والمركز المؤسسي (فحص السرعة والحساب) ──
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Button(
                onClick = onOpenSplitApps,
                modifier = Modifier.weight(1f),
            ) {
                Text(tr("استثناء التطبيقات (${state.splitApps.size})", "Split Tunnel (${state.splitApps.size})"))
            }
            OutlinedButton(
                onClick = onOpenEnterpriseHub,
                modifier = Modifier.weight(1f),
            ) {
                Text(tr("المركز المؤسسي والسرعة", "Account & Speed Studio"))
            }
        }

        // ── الوصول السريع لنقطة اتصال الـ VPN بدون روت والفحص المجتمعي الموثّق ──
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            OutlinedButton(
                onClick = onOpenHotspot,
                modifier = Modifier.weight(1f),
            ) {
                Icon(Icons.Filled.WifiTethering, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(4.dp))
                Text(tr("نقطة اتصال VPN", "VPN Hotspot"))
            }
            OutlinedButton(
                onClick = onOpenCommunityTesting,
                modifier = Modifier.weight(1f),
            ) {
                Icon(Icons.Filled.Public, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(4.dp))
                Text(tr("فحص المجتمع (IR)", "Community (IR)"))
            }
        }

        // ── الدولة المفضّلة للاختيار الذكي ──
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(tr("تفضيلات الاختيار الذكي والسجل", "Smart Selection Preferences"), style = MaterialTheme.typography.titleMedium)
                SettingToggleRow(
                    title = tr("الاختيار التلقائي الذكي للسيرفر", "Automatic Smart Server Selection"),
                    subtitle = tr(
                        "يختار أفضل سيرفر موثوق حسب الموثوقية والتأخير والسرعة وفقدان الحزم",
                        "Selects the best verified server by reliability, latency, throughput, and packet loss",
                    ),
                    checked = state.smartAutoSelect,
                    onCheckedChange = { vm.setSmartAutoSelect(it) },
                )
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    FilterChip(
                        selected = state.preferredCountry == "ALL",
                        onClick = { vm.setPreferredCountry("ALL") },
                        label = { Text(tr("أي دولة (تلقائي)", "Any Country (Auto)")) },
                    )
                    state.availableCountries.take(8).forEach { (cc, _) ->
                        FilterChip(
                            selected = state.preferredCountry == cc,
                            onClick = { vm.setPreferredCountry(cc) },
                            label = { Text("${VpnStateManager.countryFlag(cc)} $cc") },
                        )
                    }
                }
            }
        }

        state.info?.let { BannerCard(text = it, isError = false) }
        state.error?.let { BannerCard(text = it, isError = true) }

        // ── إعدادات النفق و DNS والتوجيه المباشر لنطاقات .ir ──
        ElevatedCard(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(tr("إعدادات النفق والتوجيه و DNS", "Tunnel, Routing & DNS Settings"), style = MaterialTheme.typography.titleMedium)

                SettingToggleRow(
                    title = tr(
                        "استثناء نطاقات .ir من الـ VPN تلقائياً",
                        "Bypass .ir Domains Directly (No VPN)",
                    ),
                    subtitle = tr(
                        "مفعّل افتراضياً — يمرّر جميع مواقع وسيرفرات .ir و .ایران مباشرة عبر إنترنت جهازك دون المرور على سيرفر الـ VPN",
                        "Enabled by default — routes all .ir and .ایران domains/servers directly via your local internet without passing through the VPN server",
                    ),
                    checked = bypassIrDomains,
                    onCheckedChange = {
                        bypassIrDomains = it
                        vm.setBypassIrDomains(it)
                    },
                )
                HorizontalDivider()

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
                    label = { Text(tr("خادم DNS الأساسي", "Primary DNS Resolver")) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )

                SettingToggleRow(
                    title = tr("DNS مشفّر عبر HTTPS (DoH)", "Encrypted DNS-over-HTTPS (DoH)"),
                    subtitle = tr(
                        "مفيد إذا كان مزوّد الخدمة يحجب أو يتلاعب بـ UDP 53",
                        "Recommended if your ISP intercepts or tampers with UDP port 53",
                    ),
                    checked = dnsDoh,
                    onCheckedChange = { dnsDoh = it },
                )
                SettingToggleRow(
                    title = tr("مفتاح الإيقاف الصارم (Kill Switch)", "Fail-Closed Kill Switch"),
                    subtitle = tr(
                        "يحجب مرور بيانات التطبيقات خارج النفق أثناء الربط أو عند انقطاع السيرفر",
                        "Blocks unprotected app traffic while connecting or if the VPN server drops",
                    ),
                    checked = killSwitch,
                    onCheckedChange = { killSwitch = it },
                )
                SettingToggleRow(
                    title = tr("التبديل التلقائي عند انقطاع السيرفر", "Auto-Failover on Server Drop"),
                    subtitle = tr(
                        "ينتقل تلقائيًا لأفضل سيرفر بديل دون قطع نفق الـ VPN",
                        "Seamlessly switches to the best backup server without tearing down TUN",
                    ),
                    checked = autoFailover,
                    onCheckedChange = {
                        autoFailover = it
                        failoverMode = if (!it) "OFF" else if (failoverMode == "OFF") "SMART" else failoverMode
                    },
                )
                SettingToggleRow(
                    title = tr("تمرير UDP عبر TCP (UDP-in-TCP)", "Encapsulate UDP over TCP"),
                    subtitle = tr(
                        "فعّله فقط إن كانت الشبكة تحظر حزم UDP",
                        "Enable only on restrictive networks that block raw UDP packets",
                    ),
                    checked = udpInTcp,
                    onCheckedChange = { udpInTcp = it },
                )
                SettingToggleRow(
                    title = tr("تفعيل توجيه IPv6 داخل النفق", "Route IPv6 Inside Tunnel"),
                    subtitle = tr(
                        "يُفضّل إبقاؤه مغلقًا إلا إذا كان السيرفر يدعم IPv6 كاملًا",
                        "Keep disabled unless your selected server supports full dual-stack IPv6",
                    ),
                    checked = enableIpv6,
                    onCheckedChange = { enableIpv6 = it },
                )
            }
        }

        // ── إعدادات الفحص والترتيب والتحديث التلقائي ──
        ElevatedCard(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(tr("معاملات الفحص والترتيب والتحديث", "Scan, Ranking & Sync Parameters"), style = MaterialTheme.typography.titleMedium)
                NumField(testTop, { testTop = it }, tr("عدد السيرفرات المفحوصة في الفحص الشامل", "Max servers tested in Full Scan"))
                NumField(speedTop, { speedTop = it }, tr("عدد السيرفرات المقاسة سرعة تنزيلها عبر النفق", "Max servers speed-tested through tunnel"))
                NumField(conc, { conc = it }, tr("التوازي أثناء الفحص (1–12)", "Pre-filter concurrency (1–12)"))
                NumField(timeout, { timeout = it }, tr("مهلة اختبار كل سيرفر بالثواني", "Per-server probe timeout (seconds)"))
                NumField(bestN, { bestN = it }, tr("عدد أفضل السيرفرات المحفوظة للتصدير", "Top verified servers saved for export"))

                Text(tr("معيار الترتيب الافتراضي للقائمة", "Default Server List Sort Mode"), style = MaterialTheme.typography.labelSmall)
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
                            label = { Text(mode.displayTitle) },
                        )
                    }
                }

                SettingToggleRow(
                    title = tr("تحديث قائمة السيرفرات تلقائيًا في الخلفية", "Background Server Pool Auto-Sync"),
                    subtitle = tr(
                        "يجلب أحدث سيرفرات bahrain-vpn دوريًا دون استهلاك بطارية",
                        "Fetches updated bahrain-vpn candidate lists periodically with minimal battery impact",
                    ),
                    checked = autoRef,
                    onCheckedChange = { autoRef = it },
                )

                HorizontalDivider()
                Text(tr("نمط التغذية المفضّل", "Preferred Candidate Feed Profile"), style = MaterialTheme.typography.labelSmall)
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    listOf(
                        "smart" to tr("الذكي الشامل", "Smart Balanced"),
                        "iran_community" to tr("🇮🇷 إيران (المجتمع)", "🇮🇷 Iran Community"),
                        "reliable" to tr("الأكثر استقرارًا", "Most Reliable"),
                        "low_latency" to tr("الأقل تأخيرًا", "Low Latency"),
                        "high_throughput" to tr("الأعلى سرعة", "High Throughput"),
                        "privacy_aware" to tr("الأعلى أمانًا", "Privacy-Aware"),
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
                    bypassIrDomains = bypassIrDomains,
                )
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(tr("حفظ الإعدادات وتطبيقها", "Save & Apply Settings"))
        }

        // ── التصدير والمشاركة المحلية بدون كشف المصدر ──
        ElevatedCard(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(tr("تصدير ومشاركة قوائم bahrain-vpn", "Export & Share bahrain-vpn Lists"), style = MaterialTheme.typography.titleMedium)
                Text(
                    tr(
                        "يمكنك نسخ أو مشاركة القوائم المولّدة محليًا على جهازك بالاسم الموحّد bahrain-vpn.",
                        "Copy or share locally verified server lists formatted under the unified bahrain-vpn name.",
                    ),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
                ExportFileRow(tr("قائمة أفضل السيرفرات المفحوصة", "Top Verified Servers List"), state.bestFile, onCopyFile, onShareFile)
                ExportFileRow(tr("حزمة الاشتراك المحلية (Base64)", "Local Subscription Bundle (Base64)"), state.subFile, onCopyFile, onShareFile)
                ExportFileRow(tr("قائمة جميع السيرفرات المتاحة", "Full Candidate Pool List"), state.allFile, onCopyFile, onShareFile)
            }
        }

        // ── حول التطبيق والإشعارات القانونية المطلوبة ──
        ElevatedCard(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(tr("حول التطبيق والتراخيص القانونية", "About & Open-Source Licenses"), style = MaterialTheme.typography.titleMedium)
                val aboutUpdated = if (state.lastUpdatedLabel.isNotBlank()) " • ${state.lastUpdatedLabel}" else ""
                Text(
                    "bahrain-vpn v1$aboutUpdated",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
                OutlinedButton(
                    onClick = { showLicensesDialog = true },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(tr("عرض تراخيص المكوّنات مفتوحة المصدر", "View Open-Source Component Licenses"))
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
        VpnPhase.CONNECTED -> Triple(VpnConnectedGreen.copy(alpha = 0.16f), VpnConnectedGreen, tr("● متّصل ومحمي", "● Connected"))
        VpnPhase.CONNECTION_DEGRADED -> Triple(VpnConnectingAmber.copy(alpha = 0.16f), VpnConnectingAmber, tr("● متّصل (تذبذب)", "● Degraded"))
        VpnPhase.CONNECTING -> Triple(VpnConnectingAmber.copy(alpha = 0.16f), VpnConnectingAmber, tr("● جارٍ الاتصال…", "● Connecting…"))
        VpnPhase.RECONNECTING -> Triple(VpnConnectingAmber.copy(alpha = 0.16f), VpnConnectingAmber, tr("● استعادة المسار…", "● Reconnecting…"))
        VpnPhase.SWITCHING_SERVER -> Triple(VpnConnectingAmber.copy(alpha = 0.16f), VpnConnectingAmber, tr("● جارٍ التبديل…", "● Switching…"))
        VpnPhase.PROTECTION_ACTIVE -> Triple(VpnConnectingAmber.copy(alpha = 0.18f), VpnConnectingAmber, tr("🛡 Kill Switch نشط", "🛡 Kill Switch"))
        VpnPhase.CONNECTION_FAILED -> Triple(VpnDangerRed.copy(alpha = 0.16f), VpnDangerRed, tr("● تعذّر الاتصال", "● Failed"))
        VpnPhase.DISCONNECTED -> Triple(
            MaterialTheme.colorScheme.surfaceVariant,
            MaterialTheme.colorScheme.secondary,
            tr("○ غير متّصل", "○ Disconnected"),
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
    speedKbps >= 1024.0 -> String.format(
        java.util.Locale.US,
        tr("سرعة الاختبار على جهازك: %.2f MB/s", "Tested speed on your device: %.2f MB/s"),
        speedKbps / 1024.0,
    )
    speedKbps >= 250.0 -> tr(
        "سرعة الاختبار على جهازك: ${speedKbps.toInt()} KB/s",
        "Tested speed on your device: ${speedKbps.toInt()} KB/s",
    )
    else -> tr(
        "سرعة الاختبار على جهازك: ${speedKbps.toInt()} KB/s (ضعيف)",
        "Tested speed on your device: ${speedKbps.toInt()} KB/s (Weak)",
    )
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
        isDisconnected -> tr("منقطع", "Offline")
        isUntested -> tr("لم يُفحص", "Untested")
        ms <= 500L -> "⚡ $ms ms"
        else -> tr("⚡ $ms ms • ضعيف", "⚡ $ms ms • Weak")
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
                if (ready) "${file!!.length() / 1024} KB" else tr("يُولّد بعد التحديث أو الفحص", "Generated after refresh or scan"),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.secondary,
            )
        }
        Row {
            IconButton(onClick = { file?.let(onCopyFile) }, enabled = ready) {
                Icon(Icons.Filled.ContentCopy, contentDescription = tr("نسخ", "Copy"))
            }
            IconButton(onClick = { file?.let(onShareFile) }, enabled = ready) {
                Icon(Icons.Filled.Share, contentDescription = tr("مشاركة", "Share"))
            }
        }
    }
}
