// =====================================================================
// AppViewModel.kt — إدارة السيرفرات الموحّدة (bahrain-vpn)، فلتر الدول،
// مؤشرات الجودة والموثوقية، سجل الاتصالات، الفحص، المفضلة، واستثناء التطبيقات.
// =====================================================================
package com.bahrain.vpnconfigs.ui

import android.app.Application
import android.util.Base64
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.bahrain.vpnconfigs.data.ConnectionHistoryEntry
import com.bahrain.vpnconfigs.data.Prefs
import com.bahrain.vpnconfigs.data.RemoteMeta
import com.bahrain.vpnconfigs.data.Repo
import com.bahrain.vpnconfigs.data.ResultLine
import com.bahrain.vpnconfigs.data.ServerHint
import com.bahrain.vpnconfigs.engine.Converters
import com.bahrain.vpnconfigs.engine.TestProgress
import com.bahrain.vpnconfigs.engine.TestResult
import com.bahrain.vpnconfigs.engine.Tester
import com.bahrain.vpnconfigs.vpn.AppEntry
import com.bahrain.vpnconfigs.vpn.BahrainVpnService
import com.bahrain.vpnconfigs.vpn.InstalledApps
import com.bahrain.vpnconfigs.vpn.ServerCandidate
import com.bahrain.vpnconfigs.vpn.VpnStateManager
import com.bahrain.vpnconfigs.work.RefreshWorker
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.util.concurrent.TimeUnit

data class ServerItem(
    val cfg: String,
    val name: String,
    val proto: String,
    val endpoint: String,
    val latencyMs: Long = 0L,
    val jitterMs: Double = 0.0,
    val speedKbps: Double = 0.0,
    val score: Double = 0.0,
    val country: String = "",
    val stabilityRuns: Int = 0,
    val verifiedAt: String = "",
    val locallyTested: Boolean = false,
    val localFailed: Boolean = false,
    val isFavorite: Boolean = false,
    val isCustom: Boolean = false,
) {
    val exportUri: String
        get() = Converters.namedUri(cfg, name)
}

data class UiState(
    val loading: Boolean = false,
    val testing: Boolean = false,
    val pingingSingleCfg: String? = null,
    val configs: List<String> = emptyList(),
    val servers: List<ServerItem> = emptyList(),
    val availableCountries: List<Pair<String, Int>> = emptyList(),
    val filterCountry: String = "ALL",
    val sortMode: String = "REAL_DELAY",
    val feedProfile: String = "smart",
    val connectionHistory: List<ConnectionHistoryEntry> = emptyList(),
    val selectedCfg: String = "",
    val meta: RemoteMeta = RemoteMeta(),
    val source: String = "—",
    val error: String? = null,
    val info: String? = null,
    val progress: TestProgress? = null,
    val results: List<TestResult> = emptyList(),
    val bestFile: File? = null,
    val subFile: File? = null,
    val allFile: File? = null,
    val engineReady: Boolean = false,
    val subUrl: String = "",
    val reliableSubUrl: String = "",
    val lowLatencyUrl: String = "",
    val highThroughputUrl: String = "",
    val autoFailover: Boolean = true,
    val appsLoading: Boolean = false,
    val installedApps: List<AppEntry> = emptyList(),
    val splitApps: Set<String> = emptySet(),
    val splitIncludeOnly: Boolean = false,
    val tunnelNeedsReload: Boolean = false,
) {
    val selectedServer: ServerItem?
        get() = servers.firstOrNull { it.cfg == selectedCfg } ?: servers.firstOrNull()
}

class AppViewModel(app: Application) : AndroidViewModel(app) {

    private val prefs = Prefs(app)
    private val tester = Tester(app)

    private var serverLatencies: Map<String, Long> = emptyMap()
    private var serverHints: Map<String, ServerHint> = emptyMap()
    private val failedConfigs: MutableSet<String> = HashSet()

    var state by mutableStateOf(
        run {
            val r = buildRepo()
            UiState(
                engineReady = tester.engineAvailable,
                sortMode = prefs.sortMode,
                feedProfile = prefs.feedProfile,
                connectionHistory = prefs.connectionHistory,
                subUrl = r.subscriptionUrl,
                reliableSubUrl = r.reliableSubUrl,
                lowLatencyUrl = r.lowLatencyUrl,
                highThroughputUrl = r.highThroughputUrl,
                selectedCfg = prefs.selectedCfg,
                autoFailover = prefs.autoFailover,
                splitApps = prefs.splitApps,
                splitIncludeOnly = prefs.splitIncludeOnly,
            )
        }
    )
        private set

    private var testJob: Job? = null

    init {
        viewModelScope.launch {
            VpnStateManager.status.collectLatest {
                val latestHistory = prefs.connectionHistory
                if (latestHistory != state.connectionHistory) {
                    state = state.copy(connectionHistory = latestHistory)
                }
            }
        }

        viewModelScope.launch {
            val r = buildRepo()
            val profile = prefs.feedProfile
            val cached = withContext(Dispatchers.IO) { r.loadCached(profile) }
            val savedResults = withContext(Dispatchers.IO) { r.loadSavedBest() }
            val allF = withContext(Dispatchers.IO) { r.existingAllFile() }
            val bestF = withContext(Dispatchers.IO) { r.existingBestFile() }
            val subF = withContext(Dispatchers.IO) { r.existingSubFile() }

            serverLatencies = cached?.serverLatencies ?: emptyMap()
            serverHints = cached?.serverHints ?: emptyMap()
            val cfgs = cached?.configs ?: emptyList()
            val built = buildServerList(cfgs, savedResults)
            val countries = computeCountryCounts(built)
            val chosen = resolveSelected(prefs.selectedCfg, built)

            state = state.copy(
                configs = cfgs,
                servers = built,
                availableCountries = countries,
                selectedCfg = chosen,
                meta = cached?.meta ?: RemoteMeta(),
                source = cached?.source ?: "—",
                results = savedResults,
                allFile = allF,
                bestFile = bestF,
                subFile = subF,
                engineReady = tester.engineAvailable,
                subUrl = r.subscriptionUrl,
                reliableSubUrl = r.reliableSubUrl,
                lowLatencyUrl = r.lowLatencyUrl,
                highThroughputUrl = r.highThroughputUrl,
            )

            if (cached == null) {
                refresh()
            } else {
                refresh(silent = true)
            }
        }
    }

    private fun buildRepo(): Repo {
        val owner = prefs.owner.ifBlank { Repo.DEFAULT_OWNER }
        val rep = prefs.repo.ifBlank { Repo.DEFAULT_REPO }
        return Repo(getApplication(), owner, rep)
    }

    private fun computeCountryCounts(items: List<ServerItem>): List<Pair<String, Int>> {
        val counts = HashMap<String, Int>()
        for (item in items) {
            if (item.country.length == 2) {
                counts[item.country] = (counts[item.country] ?: 0) + 1
            }
        }
        return counts.entries
            .sortedByDescending { it.value }
            .take(18)
            .map { it.key to it.value }
    }

    private fun resolveSelected(current: String, list: List<ServerItem>): String {
        if (current.isNotBlank() && list.any { it.cfg == current }) return current
        val first = list.firstOrNull()
        if (first != null) {
            prefs.selectedCfg = first.cfg
            prefs.selectedLabel = first.name
            return first.cfg
        }
        return ""
    }

    private fun buildServerList(
        remoteConfigs: List<String>,
        localResults: List<TestResult>,
        mode: String = prefs.sortMode,
    ): List<ServerItem> {
        val favSet = prefs.favorites.map { Converters.cleanUri(it) }.toHashSet()
        val customs = prefs.customConfigs.map { Converters.cleanUri(it) }
        val customSet = customs.toHashSet()
        val resultMap = localResults.filter { it.ok && it.latencyMs > 0L }
            .associateBy { Converters.cleanUri(it.cfg) }

        val allUnique = LinkedHashSet<String>()
        favSet.forEach { if (Converters.isSupported(it)) allUnique.add(it) }
        localResults.filter { it.ok }.forEach {
            val cleaned = Converters.cleanUri(it.cfg)
            if (Converters.isSupported(cleaned)) allUnique.add(cleaned)
        }
        customs.forEach { if (Converters.isSupported(it)) allUnique.add(it) }
        remoteConfigs.forEach {
            val cleaned = Converters.cleanUri(it)
            if (Converters.isSupported(cleaned)) allUnique.add(cleaned)
        }

        val unsorted = allUnique.map { cfg ->
            val local = resultMap[cfg]
            val failed = local == null && cfg in failedConfigs
            val hint = serverHints[cfg]
            val hintMs = hint?.latencyMs?.takeIf { it > 0L } ?: (serverLatencies[cfg] ?: 0L)
            val effectiveLatency = when {
                failed -> -1L
                local != null && local.latencyMs > 0L -> local.latencyMs
                else -> hintMs
            }
            ServerItem(
                cfg = cfg,
                name = "",
                proto = Converters.protocolBadge(cfg),
                endpoint = Converters.endpointLabel(cfg),
                latencyMs = effectiveLatency,
                jitterMs = hint?.jitterMs ?: 0.0,
                speedKbps = if ((local?.speedKbps ?: 0.0) > 0.0) local!!.speedKbps else (hint?.speedKbps ?: 0.0),
                score = hint?.score ?: 0.0,
                country = hint?.country.orEmpty(),
                stabilityRuns = hint?.stabilityRuns ?: 0,
                verifiedAt = hint?.verifiedAt.orEmpty(),
                locallyTested = local != null,
                localFailed = failed,
                isFavorite = cfg in favSet,
                isCustom = cfg in customSet,
            )
        }

        fun delayRank(ms: Long): Long = if (ms > 0L) ms else Long.MAX_VALUE

        val metricComparator: Comparator<ServerItem> = when (mode) {
            "SPEED" -> compareByDescending<ServerItem> { it.speedKbps > 0.0 }
                .thenByDescending { it.locallyTested }
                .thenByDescending { it.speedKbps }
                .thenBy { delayRank(it.latencyMs) }
                .thenByDescending { it.score }

            "STABILITY" -> compareByDescending<ServerItem> { it.locallyTested }
                .thenByDescending { it.stabilityRuns }
                .thenByDescending { it.score }
                .thenBy { delayRank(it.latencyMs) }

            else -> compareByDescending<ServerItem> { it.locallyTested }
                .thenBy { delayRank(it.latencyMs) }
                .thenByDescending { it.speedKbps }
                .thenByDescending { it.score }
        }

        val fullComparator = compareByDescending<ServerItem> { it.isFavorite }
            .thenBy { it.localFailed }
            .thenByDescending { it.isCustom && !it.locallyTested && it.latencyMs <= 0L }
            .then(metricComparator)

        val items = unsorted.sortedWith(fullComparator).mapIndexed { idx, item ->
            item.copy(name = "bahrain-vpn #${idx + 1}")
        }

        VpnStateManager.serverPool = items.filterNot { it.localFailed }
            .ifEmpty { items }
            .map { ServerCandidate(it.cfg, it.name) }
        return items
    }

    fun setSortMode(mode: String) {
        val normalized = when (mode) {
            "SPEED", "STABILITY", "REAL_DELAY" -> mode
            else -> "REAL_DELAY"
        }
        prefs.sortMode = normalized
        prefs.rankBySpeed = (normalized == "SPEED")
        val rebuilt = buildServerList(state.configs, state.results, normalized)
        val sel = resolveSelected(state.selectedCfg, rebuilt)
        state = state.copy(sortMode = normalized, servers = rebuilt, selectedCfg = sel)
    }

    fun selectServer(item: ServerItem) {
        prefs.selectedCfg = item.cfg
        prefs.selectedLabel = item.name
        state = state.copy(selectedCfg = item.cfg, error = null)
    }

    fun setFilterCountry(cc: String) {
        state = state.copy(filterCountry = cc)
    }

    fun setFeedProfile(profile: String) {
        prefs.feedProfile = profile
        state = state.copy(feedProfile = profile, filterCountry = "ALL")
        refresh(silent = false)
    }

    fun clearConnectionHistory() {
        prefs.clearConnectionHistory()
        state = state.copy(connectionHistory = emptyList(), info = "تم مسح سجل الاتصالات")
    }

    fun toggleFavorite(cfg: String) {
        val next = prefs.favorites.toMutableSet()
        if (!next.add(cfg)) next.remove(cfg)
        prefs.favorites = next
        val rebuilt = buildServerList(state.configs, state.results)
        state = state.copy(servers = rebuilt)
    }

    fun removeCustomServer(cfg: String) {
        val next = prefs.customConfigs.filterNot { it == cfg }
        prefs.customConfigs = next
        val rebuilt = buildServerList(state.configs, state.results)
        val countries = computeCountryCounts(rebuilt)
        val sel = resolveSelected(state.selectedCfg, rebuilt)
        state = state.copy(
            servers = rebuilt,
            availableCountries = countries,
            selectedCfg = sel,
            info = "تم حذف الكانفيغ المضاف يدويًا",
        )
    }

    fun importConfigsFromText(rawText: String) {
        val trimmed = rawText.trim().take(4_000_000)
        if (trimmed.isBlank()) {
            state = state.copy(error = "الحافظة فارغة — انسخ رابط كانفيغ أو اشتراك أولًا")
            return
        }
        val decodedText = if (!trimmed.contains("://")) {
            runCatching {
                val cleanB64 = trimmed.replace(Regex("\\s+"), "")
                    .replace('-', '+')
                    .replace('_', '/')
                val padded = cleanB64 + "=".repeat((4 - cleanB64.length % 4) % 4)
                String(Base64.decode(padded, Base64.DEFAULT), Charsets.UTF_8)
            }.getOrDefault(trimmed)
        } else {
            trimmed
        }

        val extracted = decodedText.lineSequence()
            .take(2_000)
            .map { Converters.cleanUri(it) }
            .filter { it.contains("://") && Converters.isSupported(it) }
            .distinct()
            .toList()

        if (extracted.isEmpty()) {
            state = state.copy(error = "لم يُعثر على كانفيغ صالح وآمن في النص المنسوخ")
            return
        }

        val mergedCustom = (extracted + prefs.customConfigs).distinct().take(500)
        prefs.customConfigs = mergedCustom
        val rebuilt = buildServerList(state.configs, state.results)
        val countries = computeCountryCounts(rebuilt)
        val firstAdded = rebuilt.firstOrNull { it.cfg == extracted.first() }
        val newSel = firstAdded?.cfg ?: resolveSelected(state.selectedCfg, rebuilt)
        if (firstAdded != null) {
            prefs.selectedCfg = firstAdded.cfg
            prefs.selectedLabel = firstAdded.name
        }

        state = state.copy(
            servers = rebuilt,
            availableCountries = countries,
            selectedCfg = newSel,
            error = null,
            info = "تمت إضافة ${extracted.size} سيرفر تحت اسم bahrain-vpn",
        )
    }

    fun setAutoFailover(enabled: Boolean) {
        prefs.autoFailover = enabled
        state = state.copy(autoFailover = enabled)
    }

    // ── تنزيل القائمة الحيّة مع دعم التحديث الصامت و ETag ──
    fun refresh(silent: Boolean = false) {
        if (state.loading) return
        val r = buildRepo()
        val profile = prefs.feedProfile
        if (!silent) {
            state = state.copy(
                loading = true,
                error = null,
                info = null,
                subUrl = r.subscriptionUrl,
                reliableSubUrl = r.reliableSubUrl,
                lowLatencyUrl = r.lowLatencyUrl,
                highThroughputUrl = r.highThroughputUrl,
            )
        }
        viewModelScope.launch {
            val res = withContext(Dispatchers.IO) { r.loadRemote(profile) }
            if (res.serverLatencies.isNotEmpty()) {
                serverLatencies = res.serverLatencies
            }
            if (res.serverHints.isNotEmpty()) {
                serverHints = res.serverHints
            }
            val newConfigs = res.configs.ifEmpty { state.configs }
            val allFile = if (res.configs.isNotEmpty()) {
                withContext(Dispatchers.IO) { runCatching { r.writeAll(res.configs) }.getOrNull() }
            } else {
                state.allFile
            }
            val rebuilt = buildServerList(newConfigs, state.results)
            val countries = computeCountryCounts(rebuilt)
            val sel = resolveSelected(state.selectedCfg, rebuilt)

            state = state.copy(
                loading = false,
                configs = newConfigs,
                servers = rebuilt,
                availableCountries = countries,
                selectedCfg = sel,
                meta = if (res.meta.generatedAt != "—") res.meta else state.meta,
                source = res.source,
                allFile = allFile,
                error = if (!silent) res.error else null,
                info = if (!silent && res.error == null && res.configs.isNotEmpty()) {
                    if (countries.isNotEmpty()) {
                        "تم تحديث ${rebuilt.size} سيرفر bahrain-vpn (${countries.size} دولة)"
                    } else {
                        "تم تحديث ${rebuilt.size} سيرفر bahrain-vpn جاهز"
                    }
                } else state.info,
            )
        }
    }

    // ── فحص سريع Real Delay (Current) بدون استهلاك بيانات السرعة ──
    fun startQuickPingTest() {
        prefs.sortMode = "REAL_DELAY"
        prefs.rankBySpeed = false
        state = state.copy(sortMode = "REAL_DELAY")
        runTestInternal(quickPingOnly = true)
    }

    // ── فحص شامل (Real Delay + سرعة التنزيل) ──
    fun startTest() {
        runTestInternal(quickPingOnly = false)
    }

    private fun runTestInternal(quickPingOnly: Boolean) {
        val pool = (prefs.customConfigs + state.configs).distinct()
        if (pool.isEmpty()) {
            state = state.copy(error = "حدّث القائمة أولًا بالضغط على زر التحديث")
            return
        }
        if (!tester.engineAvailable) {
            state = state.copy(error = "نواة sing-box غير مثبتة في هذا البناء (libsingbox.so مفقود)")
            return
        }
        testJob?.cancel()
        state = state.copy(testing = true, error = null, info = null, progress = null)
        testJob = viewModelScope.launch {
            try {
                val topLimit = if (quickPingOnly) minOf(prefs.testTop, 250) else prefs.testTop
                val spdLimit = if (quickPingOnly) 0 else prefs.speedTop
                val useSpeedRank = !quickPingOnly && (prefs.sortMode == "SPEED" || prefs.rankBySpeed)
                val results = tester.run(
                    configs = pool,
                    testTop = topLimit,
                    speedTop = spdLimit,
                    concurrency = prefs.concurrency,
                    timeoutSec = prefs.timeoutSec,
                    rankBySpeed = useSpeedRank,
                    dnsServer = prefs.dnsServer,
                    useDoh = prefs.dnsDoh,
                ) { p ->
                    withContext(Dispatchers.Main.immediate) {
                        state = state.copy(progress = p)
                    }
                }

                // إزالة أي سيرفر نجح من قائمة الفشل المحلية
                results.forEach { if (it.ok) failedConfigs.remove(Converters.cleanUri(it.cfg)) }

                val r = buildRepo()
                val allFile = withContext(Dispatchers.IO) {
                    runCatching { r.writeAll(pool) }.getOrNull()
                }
                val bestPair = if (results.isNotEmpty()) {
                    withContext(Dispatchers.IO) {
                        runCatching {
                            r.writeBest(
                                results.map { ResultLine(it.cfg, it.latencyMs, it.speedKbps) },
                                prefs.bestN,
                            )
                        }.getOrNull()
                    }
                } else null

                val activeMode = if (quickPingOnly) "REAL_DELAY" else prefs.sortMode
                val rebuilt = buildServerList(state.configs, results, activeMode)
                val countries = computeCountryCounts(rebuilt)
                // اختيار أسرع سيرفر تلقائيًا إذا لم يكن الـ VPN متّصلًا حاليًا
                val autoPicked = if (!VpnStateManager.status.value.isActive && results.isNotEmpty()) {
                    rebuilt.first().also {
                        prefs.selectedCfg = it.cfg
                        prefs.selectedLabel = it.name
                    }.cfg
                } else {
                    resolveSelected(state.selectedCfg, rebuilt)
                }

                val topItem = rebuilt.firstOrNull()
                state = state.copy(
                    testing = false,
                    sortMode = activeMode,
                    results = results,
                    servers = rebuilt,
                    availableCountries = countries,
                    selectedCfg = autoPicked,
                    progress = null,
                    allFile = allFile ?: state.allFile,
                    bestFile = bestPair?.first ?: state.bestFile,
                    subFile = bestPair?.second ?: state.subFile,
                    info = if (results.isNotEmpty() && topItem != null) {
                        "نجح ${results.size} سيرفر — الأسرع ${topItem.name} (${topItem.latencyMs} ms)"
                    } else null,
                    error = if (results.isEmpty()) "لم تنجح أي عقدة — جرّب زيادة المهلة أو تحديث القائمة" else null,
                )
            } catch (_: CancellationException) {
                state = state.copy(testing = false, progress = null, info = "تم إيقاف الفحص")
            } catch (e: Exception) {
                state = state.copy(
                    testing = false,
                    progress = null,
                    error = "خطأ أثناء الفحص: ${e.localizedMessage ?: e.javaClass.simpleName}",
                )
            }
        }
    }

    fun pingSingleServer(item: ServerItem) {
        if (state.pingingSingleCfg != null) return
        state = state.copy(pingingSingleCfg = item.cfg, error = null, info = null)
        viewModelScope.launch {
            val res = tester.testSingle(
                cfg = item.cfg,
                timeoutSec = prefs.timeoutSec,
                dnsServer = prefs.dnsServer,
                useDoh = prefs.dnsDoh,
            )
            val cleanedCfg = Converters.cleanUri(item.cfg)
            if (res.ok && res.latencyMs > 0L) {
                failedConfigs.remove(cleanedCfg)
                val prevSpeed = state.results.firstOrNull { Converters.cleanUri(it.cfg) == cleanedCfg }?.speedKbps ?: 0.0
                val mergedRes = res.copy(speedKbps = prevSpeed)
                val updatedResults = buildList {
                    add(mergedRes)
                    state.results.forEach { if (Converters.cleanUri(it.cfg) != cleanedCfg) add(it) }
                }
                val rebuilt = buildServerList(state.configs, updatedResults)
                val newItem = rebuilt.firstOrNull { it.cfg == cleanedCfg }
                state = state.copy(
                    pingingSingleCfg = null,
                    results = updatedResults,
                    servers = rebuilt,
                    info = "${newItem?.name ?: item.name}: Real Delay = ${res.latencyMs} ms",
                )
            } else {
                failedConfigs.add(cleanedCfg)
                val updatedResults = state.results.filterNot { Converters.cleanUri(it.cfg) == cleanedCfg }
                val rebuilt = buildServerList(state.configs, updatedResults)
                state = state.copy(
                    pingingSingleCfg = null,
                    results = updatedResults,
                    servers = rebuilt,
                    error = "${item.name}: لم يستجب (${res.error})",
                )
            }
        }
    }

    fun cancelTest() {
        testJob?.cancel()
        state = state.copy(testing = false, progress = null, info = "تم إيقاف الفحص")
    }

    // ── استثناء التطبيقات (Split Tunneling) ──
    fun ensureAppsLoaded() {
        if (state.installedApps.isNotEmpty() || state.appsLoading) return
        state = state.copy(appsLoading = true)
        viewModelScope.launch {
            val apps = withContext(Dispatchers.IO) { InstalledApps.loadAll(getApplication()) }
            state = state.copy(appsLoading = false, installedApps = apps)
        }
    }

    fun toggleAppSplit(packageName: String) {
        val next = state.splitApps.toMutableSet()
        if (!next.add(packageName)) next.remove(packageName)
        prefs.splitApps = next
        state = state.copy(
            splitApps = next,
            tunnelNeedsReload = VpnStateManager.status.value.isActive,
        )
    }

    fun clearAppSplit() {
        prefs.splitApps = emptySet()
        state = state.copy(
            splitApps = emptySet(),
            tunnelNeedsReload = VpnStateManager.status.value.isActive,
        )
    }

    fun setSplitIncludeOnly(includeOnly: Boolean) {
        prefs.splitIncludeOnly = includeOnly
        state = state.copy(
            splitIncludeOnly = includeOnly,
            tunnelNeedsReload = VpnStateManager.status.value.isActive,
        )
    }

    fun applyTunnelReload() {
        BahrainVpnService.reloadTunnelIfConnected(getApplication())
        state = state.copy(tunnelNeedsReload = false, info = "تم تحديث قواعد التطبيقات في النفق النشط")
    }

    // ── إعدادات شاملة ──
    fun saveSettings(
        owner: String,
        repoName: String,
        dnsServer: String,
        dnsDoh: Boolean,
        enableIpv6: Boolean,
        udpInTcp: Boolean,
        autoFailover: Boolean,
        testTop: Int,
        speedTop: Int,
        bestN: Int,
        concurrency: Int,
        timeoutSec: Int,
        rankBySpeed: Boolean,
        autoRefresh: Boolean,
    ) {
        prefs.owner = owner
        prefs.repo = repoName
        prefs.dnsServer = dnsServer
        prefs.dnsDoh = dnsDoh
        prefs.enableIpv6 = enableIpv6
        prefs.udpInTcp = udpInTcp
        prefs.autoFailover = autoFailover
        prefs.testTop = testTop
        prefs.speedTop = speedTop
        prefs.bestN = bestN
        prefs.concurrency = concurrency
        prefs.timeoutSec = timeoutSec
        prefs.rankBySpeed = rankBySpeed
        prefs.sortMode = if (rankBySpeed) "SPEED" else "REAL_DELAY"
        prefs.autoRefresh = autoRefresh

        val wm = WorkManager.getInstance(getApplication())
        if (autoRefresh) {
            val req = PeriodicWorkRequestBuilder<RefreshWorker>(1, TimeUnit.HOURS).build()
            wm.enqueueUniquePeriodicWork("refresh", ExistingPeriodicWorkPolicy.KEEP, req)
        } else {
            wm.cancelUniqueWork("refresh")
        }

        if (VpnStateManager.status.value.isActive) {
            BahrainVpnService.reloadTunnelIfConnected(getApplication())
        }

        val r = buildRepo()
        val rebuilt = buildServerList(state.configs, state.results, prefs.sortMode)
        state = state.copy(
            error = null,
            info = "تم حفظ الإعدادات بنجاح",
            sortMode = prefs.sortMode,
            servers = rebuilt,
            subUrl = r.subscriptionUrl,
            reliableSubUrl = r.reliableSubUrl,
            lowLatencyUrl = r.lowLatencyUrl,
            highThroughputUrl = r.highThroughputUrl,
            autoFailover = autoFailover,
        )
    }

    fun settings() = prefs
}
