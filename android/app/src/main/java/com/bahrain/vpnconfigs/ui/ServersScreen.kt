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
