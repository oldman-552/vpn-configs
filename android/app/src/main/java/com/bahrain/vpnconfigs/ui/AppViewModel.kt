// =====================================================================
// AppViewModel.kt — إدارة السيرفرات الموحّدة (bahrain-vpn)، نظام الترتيب
// الخماسي الموزون، فلتر الدول، سجل الاتصالات، الفحص الفعلي، واستثناء التطبيقات
// دون كشف تفاصيل المصدر الداخلي للمستخدم.
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
import com.bahrain.vpnconfigs.engine.RankableServer
import com.bahrain.vpnconfigs.engine.ServerRanker
import com.bahrain.vpnconfigs.engine.ServerSortMode
import com.bahrain.vpnconfigs.engine.TestProgress
import com.bahrain.vpnconfigs.engine.TestResult
import com.bahrain.vpnconfigs.engine.Tester
import com.bahrain.vpnconfigs.util.AppDiag
import com.bahrain.vpnconfigs.util.UiMessages
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
import java.util.Locale
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
    val overallScore: Double = 0.0,
    val country: String = "",
    val stabilityRuns: Int = 0,
    val verifiedAt: String = "",
    val lastTestedAtMs: Long = 0L,
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
    val sortMode: String = ServerSortMode.DEFAULT.key,
    val feedProfile: String = "smart",
    val lastUpdatedLabel: String = "",
    val connectionHistory: List<ConnectionHistoryEntry> = emptyList(),
    val selectedCfg: String = "",
    val meta: RemoteMeta = RemoteMeta(),
    val error: String? = null,
    val info: String? = null,
    val progress: TestProgress? = null,
    val results: List<TestResult> = emptyList(),
    val bestFile: File? = null,
    val subFile: File? = null,
    val allFile: File? = null,
    val engineReady: Boolean = false,
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
        UiState(
            engineReady = tester.engineAvailable,
            sortMode = prefs.sortMode,
            feedProfile = prefs.feedProfile,
            lastUpdatedLabel = UiMessages.formatLastUpdated(null, prefs.lastRefreshWallMs),
            connectionHistory = prefs.connectionHistory,
            selectedCfg = prefs.selectedCfg,
            autoFailover = prefs.autoFailover,
            splitApps = prefs.splitApps,
            splitIncludeOnly = prefs.splitIncludeOnly,
        )
    )
        private set

    private var testJob: Job? = null

    init {
        AppDiag.init(app)

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
            val built = buildServerList(cfgs, savedResults, prefs.sortMode)
            val countries = computeCountryCounts(built)
            val chosen = resolveSelected(prefs.selectedCfg, built)
            val metaObj = cached?.meta ?: RemoteMeta()

            state = state.copy(
                configs = cfgs,
                servers = built,
                availableCountries = countries,
                selectedCfg = chosen,
                meta = metaObj,
                lastUpdatedLabel = UiMessages.formatLastUpdated(metaObj.generatedAt, prefs.lastRefreshWallMs),
                results = savedResults,
                allFile = allF,
                bestFile = bestF,
                subFile = subF,
                engineReady = tester.engineAvailable,
            )

            if (cached == null) {
                refresh(silent = false)
            } else {
                refresh(silent = true)
            }
        }
    }

    private fun buildRepo(): Repo = Repo(getApplication())

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

    /**
     * يحسم السيرفر المحدد دون أن يغيّر السيرفر المتصل به المستخدم حاليًا عند إعادة الترتيب أو التحديث.
     */
    private fun resolveSelected(current: String, list: List<ServerItem>): String {
        val vpnSt = VpnStateManager.status.value
        val resolved = ServerRanker.resolveSelectedPreservingActive(
            currentSelectedCfg = current,
            activeVpnCfg = vpnSt.activeCfg,
            isVpnActive = vpnSt.isActive,
            sortedConfigs = list.map { it.cfg },
        )
        if (!vpnSt.isActive && resolved.isNotBlank() && resolved != prefs.selectedCfg) {
            list.firstOrNull { it.cfg == resolved }?.let { picked ->
                prefs.selectedCfg = picked.cfg
                prefs.selectedLabel = picked.name
            }
        }
        return resolved
    }

    private fun buildServerList(
        remoteConfigs: List<String>,
        localResults: List<TestResult>,
        modeKey: String = prefs.sortMode,
    ): List<ServerItem> {
        val nowMs = System.currentTimeMillis()
        val sortMode = ServerSortMode.fromKey(modeKey)
        val favSet = prefs.favorites.map { Converters.cleanUri(it) }.toHashSet()
        val customs = prefs.customConfigs.map { Converters.cleanUri(it) }
        val customSet = customs.toHashSet()
        val resultMap = localResults.filter { it.ok && (it.latencyMs > 0L || it.speedKbps > 0.0) }
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

        val rankablePairs = allUnique.map { cfg ->
            val local = resultMap[cfg]
            val failed = local == null && cfg in failedConfigs
            val hint = serverHints[cfg]
            val hintMs = hint?.latencyMs?.takeIf { it > 0L } ?: (serverLatencies[cfg] ?: 0L)
            val effectiveLatency = when {
                failed -> -1L
                local != null && local.latencyMs > 0L -> local.latencyMs
                else -> hintMs
            }
            val effectiveSpeed = when {
                failed -> 0.0
                local != null && local.speedKbps > 0.0 -> local.speedKbps
                else -> hint?.speedKbps?.takeIf { it > 0.0 } ?: 0.0
            }
            val cloudTestedMs = UiMessages.parseIsoUtcMillis(hint?.verifiedAt)
            val localTestedMs = local?.testedAtMs ?: 0L
            val effectiveTestedMs = maxOf(localTestedMs, cloudTestedMs)

            val rankable = RankableServer(
                cfg = cfg,
                latencyMs = effectiveLatency,
                jitterMs = hint?.jitterMs ?: 0.0,
                speedKbps = effectiveSpeed,
                stabilityRuns = hint?.stabilityRuns ?: 0,
                cloudQualityHint = hint?.score ?: 0.0,
                locallyTested = local != null,
                localFailed = failed,
                isFavorite = cfg in favSet,
                isCustom = cfg in customSet,
                lastTestedAtMs = effectiveTestedMs,
            )
            val computedOverall = ServerRanker.computeOverallScore(rankable, nowMs)
            val item = ServerItem(
                cfg = cfg,
                name = "",
                proto = Converters.protocolBadge(cfg),
                endpoint = Converters.endpointLabel(cfg),
                latencyMs = effectiveLatency,
                jitterMs = hint?.jitterMs ?: 0.0,
                speedKbps = effectiveSpeed,
                score = hint?.score ?: 0.0,
                overallScore = computedOverall,
                country = hint?.country.orEmpty(),
                stabilityRuns = hint?.stabilityRuns ?: 0,
                verifiedAt = hint?.verifiedAt.orEmpty(),
                lastTestedAtMs = effectiveTestedMs,
                locallyTested = local != null,
                localFailed = failed,
                isFavorite = cfg in favSet,
                isCustom = cfg in customSet,
            )
            rankable to item
        }

        val comp = ServerRanker.comparatorFor(sortMode, nowMs)
        val sortedItems = rankablePairs
            .sortedWith { a, b -> comp.compare(a.first, b.first) }
            .mapIndexed { idx, pair ->
                pair.second.copy(name = "bahrain-vpn #${idx + 1}")
            }

        VpnStateManager.serverPool = sortedItems.filterNot { it.localFailed }
            .ifEmpty { sortedItems }
            .map { ServerCandidate(it.cfg, it.name) }
        return sortedItems
    }

    /**
     * تغيير وضع الترتيب يعيد فرز القائمة فقط دون قطع أو تغيير السيرفر المتصل به المستخدم حاليًا.
     */
    fun setSortMode(mode: String) {
        val normalized = ServerSortMode.fromKey(mode)
        prefs.sortMode = normalized.key
        prefs.rankBySpeed = (normalized == ServerSortMode.FASTEST_DOWNLOAD)
        val rebuilt = buildServerList(state.configs, state.results, normalized.key)
        val sel = resolveSelected(state.selectedCfg, rebuilt)
        state = state.copy(sortMode = normalized.key, servers = rebuilt, selectedCfg = sel)
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
        val rebuilt = buildServerList(state.configs, state.results, state.sortMode)
        val sel = resolveSelected(state.selectedCfg, rebuilt)
        state = state.copy(servers = rebuilt, selectedCfg = sel)
    }

    fun removeCustomServer(cfg: String) {
        val next = prefs.customConfigs.filterNot { it == cfg }
        prefs.customConfigs = next
        val rebuilt = buildServerList(state.configs, state.results, state.sortMode)
        val countries = computeCountryCounts(rebuilt)
        val sel = resolveSelected(state.selectedCfg, rebuilt)
        state = state.copy(
            servers = rebuilt,
            availableCountries = countries,
            selectedCfg = sel,
            info = "تم حذف السيرفر المخصّص",
        )
    }

    fun importConfigsFromText(rawText: String) {
        val trimmed = rawText.trim().take(4_000_000)
        if (trimmed.isBlank()) {
            state = state.copy(error = "الحافظة فارغة — انسخ رابط سيرفر أو حزمة اشتراك أولًا")
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
            state = state.copy(error = "لم يُعثر على إعداد اتصال صالح وآمن في النص المدخل")
            return
        }

        val mergedCustom = (extracted + prefs.customConfigs).distinct().take(500)
        prefs.customConfigs = mergedCustom
        val rebuilt = buildServerList(state.configs, state.results, state.sortMode)
        val countries = computeCountryCounts(rebuilt)
        val vpnActive = VpnStateManager.status.value.isActive
        val firstAdded = rebuilt.firstOrNull { it.cfg == extracted.first() }
        val newSel = if (!vpnActive && firstAdded != null) {
            prefs.selectedCfg = firstAdded.cfg
            prefs.selectedLabel = firstAdded.name
            firstAdded.cfg
        } else {
            resolveSelected(state.selectedCfg, rebuilt)
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

    // ── تحديث قائمة السيرفرات برسائل عامة بدون تسريب المصدر أو عرض نجاح مضلل ──
    fun refresh(silent: Boolean = false) {
        if (state.loading) return
        val r = buildRepo()
        val profile = prefs.feedProfile
        if (!silent) {
            state = state.copy(
                loading = true,
                error = null,
                info = "${UiMessages.MSG_UPDATING}…",
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

            val refreshSucceededLive = res.error == null && !res.fromCacheFallback && res.configs.isNotEmpty()
            if (refreshSucceededLive) {
                prefs.lastRefreshWallMs = System.currentTimeMillis()
            }

            val newConfigs = res.configs.ifEmpty { state.configs }
            val allFile = if (res.configs.isNotEmpty()) {
                withContext(Dispatchers.IO) { runCatching { r.writeAll(res.configs) }.getOrNull() }
            } else {
                state.allFile
            }
            val rebuilt = buildServerList(newConfigs, state.results, state.sortMode)
            val countries = computeCountryCounts(rebuilt)
            val sel = resolveSelected(state.selectedCfg, rebuilt)
            val metaObj = if (res.meta.generatedAt != "—") res.meta else state.meta
            val updatedLbl = UiMessages.formatLastUpdated(metaObj.generatedAt, prefs.lastRefreshWallMs)

            state = state.copy(
                loading = false,
                configs = newConfigs,
                servers = rebuilt,
                availableCountries = countries,
                selectedCfg = sel,
                meta = metaObj,
                lastUpdatedLabel = updatedLbl,
                allFile = allFile,
                error = if (!silent && !refreshSucceededLive) {
                    UiMessages.sanitizeError(res.error, UiMessages.MSG_UPDATE_FAILED)
                } else null,
                info = if (!silent) {
                    if (refreshSucceededLive) {
                        "تم تحديث قائمة السيرفرات (${rebuilt.size} سيرفر متاح)"
                    } else null
                } else state.info,
            )
        }
    }

    // ── فحص سريع للتأخير فقط ──
    fun startQuickPingTest() {
        runTestInternal(quickPingOnly = true)
    }

    // ── فحص شامل (قياس فعلي لسرعة التنزيل عبر النفق + التأخير) ──
    fun startTest() {
        runTestInternal(quickPingOnly = false)
    }

    private fun runTestInternal(quickPingOnly: Boolean) {
        val pool = (prefs.customConfigs + state.configs).distinct()
        if (pool.isEmpty()) {
            state = state.copy(error = UiMessages.MSG_NO_SERVERS)
            return
        }
        if (!tester.engineAvailable) {
            state = state.copy(error = UiMessages.MSG_ENGINE_UNAVAILABLE)
            return
        }
        testJob?.cancel()
        state = state.copy(testing = true, error = null, info = null, progress = null)
        testJob = viewModelScope.launch {
            try {
                val topLimit = if (quickPingOnly) minOf(prefs.testTop, 250) else prefs.testTop
                val spdLimit = if (quickPingOnly) 0 else maxOf(prefs.speedTop, 20)
                val useSpeedRank = !quickPingOnly && ServerSortMode.fromKey(prefs.sortMode) == ServerSortMode.FASTEST_DOWNLOAD
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

                results.forEach { if (it.ok) failedConfigs.remove(Converters.cleanUri(it.cfg)) }

                // دمج سرعة التنزيل المقاسة سابقًا إن كان الفحص الحالي للتأخير فقط دون اختلاق درجات
                val prevSpeedByCfg = state.results.associate { Converters.cleanUri(it.cfg) to it.speedKbps }
                val mergedResults = if (quickPingOnly) {
                    results.map { r ->
                        val prevSpd = prevSpeedByCfg[Converters.cleanUri(r.cfg)] ?: 0.0
                        if (r.speedKbps <= 0.0 && prevSpd > 0.0) r.copy(speedKbps = prevSpd) else r
                    }
                } else {
                    results
                }

                val r = buildRepo()
                val allFile = withContext(Dispatchers.IO) {
                    runCatching { r.writeAll(pool) }.getOrNull()
                }
                val bestPair = if (mergedResults.isNotEmpty()) {
                    withContext(Dispatchers.IO) {
                        runCatching {
                            r.writeBest(
                                mergedResults.map { ResultLine(it.cfg, it.latencyMs, it.speedKbps, it.testedAtMs) },
                                prefs.bestN,
                            )
                        }.getOrNull()
                    }
                } else null

                val activeMode = prefs.sortMode
                val rebuilt = buildServerList(state.configs, mergedResults, activeMode)
                val countries = computeCountryCounts(rebuilt)
                // عدم تغيير السيرفر المتصل به حاليًا عند انتهاء الفحص
                val autoPicked = if (!VpnStateManager.status.value.isActive && mergedResults.isNotEmpty()) {
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
                    results = mergedResults,
                    servers = rebuilt,
                    availableCountries = countries,
                    selectedCfg = autoPicked,
                    progress = null,
                    allFile = allFile ?: state.allFile,
                    bestFile = bestPair?.first ?: state.bestFile,
                    subFile = bestPair?.second ?: state.subFile,
                    info = if (mergedResults.isNotEmpty() && topItem != null) {
                        val metricTxt = if (topItem.speedKbps >= 1024.0) {
                            String.format(Locale.US, "%.2f MB/s • %d ms", topItem.speedKbps / 1024.0, topItem.latencyMs)
                        } else if (topItem.speedKbps > 0.0) {
                            "${topItem.speedKbps.toInt()} KB/s • ${topItem.latencyMs} ms"
                        } else {
                            "${topItem.latencyMs} ms"
                        }
                        "اكتمل فحص ${mergedResults.size} سيرفر — المتصدر ${topItem.name} ($metricTxt)"
                    } else null,
                    error = if (mergedResults.isEmpty()) "لم يستجب أي سيرفر حاليًا — حاول تحديث القائمة أو المحاولة لاحقًا" else null,
                )
            } catch (_: CancellationException) {
                state = state.copy(testing = false, progress = null, info = "تم إيقاف الفحص")
            } catch (e: Exception) {
                AppDiag.w("AppViewModel", "batch server test failed", e)
                state = state.copy(
                    testing = false,
                    progress = null,
                    error = UiMessages.MSG_TEST_FAILED,
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
                measureSpeed = true,
                dnsServer = prefs.dnsServer,
                useDoh = prefs.dnsDoh,
            )
            val cleanedCfg = Converters.cleanUri(item.cfg)
            if (res.ok && res.latencyMs > 0L) {
                failedConfigs.remove(cleanedCfg)
                val prevSpeed = state.results.firstOrNull { Converters.cleanUri(it.cfg) == cleanedCfg }?.speedKbps ?: 0.0
                val mergedRes = if (res.speedKbps > 0.0) res else res.copy(speedKbps = prevSpeed)
                val updatedResults = buildList {
                    add(mergedRes)
                    state.results.forEach { if (Converters.cleanUri(it.cfg) != cleanedCfg) add(it) }
                }
                val rebuilt = buildServerList(state.configs, updatedResults, state.sortMode)
                val sel = resolveSelected(state.selectedCfg, rebuilt)
                val newItem = rebuilt.firstOrNull { it.cfg == cleanedCfg }
                val speedSummary = if (mergedRes.speedKbps >= 1024.0) {
                    String.format(Locale.US, " • %.2f MB/s", mergedRes.speedKbps / 1024.0)
                } else if (mergedRes.speedKbps > 0.0) {
                    " • ${mergedRes.speedKbps.toInt()} KB/s"
                } else ""
                state = state.copy(
                    pingingSingleCfg = null,
                    results = updatedResults,
                    servers = rebuilt,
                    selectedCfg = sel,
                    info = "${newItem?.name ?: item.name}: ${res.latencyMs} ms$speedSummary",
                )
            } else {
                AppDiag.d("AppViewModel", "single server check failed code=${res.error}")
                failedConfigs.add(cleanedCfg)
                val updatedResults = state.results.filterNot { Converters.cleanUri(it.cfg) == cleanedCfg }
                val rebuilt = buildServerList(state.configs, updatedResults, state.sortMode)
                val sel = resolveSelected(state.selectedCfg, rebuilt)
                state = state.copy(
                    pingingSingleCfg = null,
                    results = updatedResults,
                    servers = rebuilt,
                    selectedCfg = sel,
                    error = "${item.name}: ${UiMessages.MSG_SERVER_UNREACHABLE}",
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

    // ── حفظ الإعدادات دون تغيير هوية المستودع التشغيلي أو قطع السيرفر النشط بدون داعٍ ──
    fun saveSettings(
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
        defaultSortMode: String,
        autoRefresh: Boolean,
    ) {
        val dnsOrTunChanged =
            prefs.dnsServer != dnsServer ||
                prefs.dnsDoh != dnsDoh ||
                prefs.enableIpv6 != enableIpv6 ||
                prefs.udpInTcp != udpInTcp

        val normalizedSort = ServerSortMode.fromKey(defaultSortMode)
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
        prefs.sortMode = normalizedSort.key
        prefs.rankBySpeed = (normalizedSort == ServerSortMode.FASTEST_DOWNLOAD)
        prefs.autoRefresh = autoRefresh

        val wm = WorkManager.getInstance(getApplication())
        if (autoRefresh) {
            val req = PeriodicWorkRequestBuilder<RefreshWorker>(1, TimeUnit.HOURS).build()
            wm.enqueueUniquePeriodicWork("refresh", ExistingPeriodicWorkPolicy.KEEP, req)
        } else {
            wm.cancelUniqueWork("refresh")
        }

        if (dnsOrTunChanged && VpnStateManager.status.value.isActive) {
            BahrainVpnService.reloadTunnelIfConnected(getApplication())
        }

        val rebuilt = buildServerList(state.configs, state.results, normalizedSort.key)
        val sel = resolveSelected(state.selectedCfg, rebuilt)
        state = state.copy(
            error = null,
            info = "تم حفظ الإعدادات بنجاح",
            sortMode = normalizedSort.key,
            servers = rebuilt,
            selectedCfg = sel,
            autoFailover = autoFailover,
        )
    }

    fun settings() = prefs
}
