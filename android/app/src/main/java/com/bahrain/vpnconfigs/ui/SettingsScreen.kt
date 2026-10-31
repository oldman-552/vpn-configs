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
                    "bahrain-vpn v2$aboutUpdated",
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
