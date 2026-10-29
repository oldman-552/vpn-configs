// =====================================================================
// AppViewModel.kt — إدارة السيرفرات الموحّدة (bahrain-vpn)، الفحص، المفضلة،
// استيراد الكانفيغات، واستثناء التطبيقات (Split Tunneling).
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
import com.bahrain.vpnconfigs.data.Prefs
import com.bahrain.vpnconfigs.data.RemoteMeta
import com.bahrain.vpnconfigs.data.Repo
import com.bahrain.vpnconfigs.data.ResultLine
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
    val speedKbps: Double = 0.0,
    val locallyTested: Boolean = false,
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

    private var serverHints: Map<String, Long> = emptyMap()

    var state by mutableStateOf(
        UiState(
            engineReady = tester.engineAvailable,
            subUrl = buildRepo().subscriptionUrl,
            selectedCfg = prefs.selectedCfg,
            autoFailover = prefs.autoFailover,
            splitApps = prefs.splitApps,
            splitIncludeOnly = prefs.splitIncludeOnly,
        )
    )
        private set

    private var testJob: Job? = null

    init {
        viewModelScope.launch {
            val r = buildRepo()
            val cached = withContext(Dispatchers.IO) { r.loadCached() }
            val savedResults = withContext(Dispatchers.IO) { r.loadSavedBest() }
            val allF = withContext(Dispatchers.IO) { r.existingAllFile() }
            val bestF = withContext(Dispatchers.IO) { r.existingBestFile() }
            val subF = withContext(Dispatchers.IO) { r.existingSubFile() }

            serverHints = cached?.serverLatencies ?: emptyMap()
            val cfgs = cached?.configs ?: emptyList()
            val built = buildServerList(cfgs, savedResults)
            val chosen = resolveSelected(prefs.selectedCfg, built)

            state = state.copy(
                configs = cfgs,
                servers = built,
                selectedCfg = chosen,
                meta = cached?.meta ?: RemoteMeta(),
                source = cached?.source ?: "—",
                results = savedResults,
                allFile = allF,
                bestFile = bestF,
                subFile = subF,
                engineReady = tester.engineAvailable,
                subUrl = r.subscriptionUrl,
            )

            if (cached == null) {
                refresh()
            }
        }
    }

    private fun buildRepo(): Repo {
        val owner = prefs.owner.ifBlank { Repo.DEFAULT_OWNER }
        val rep = prefs.repo.ifBlank { Repo.DEFAULT_REPO }
        return Repo(getApplication(), owner, rep)
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
    ): List<ServerItem> {
        val favSet = prefs.favorites
        val customs = prefs.customConfigs
        val customSet = customs.toHashSet()
        val resultMap = localResults.associateBy { it.cfg }

        val orderedRaw = LinkedHashSet<String>()
        // 1) السيرفرات المفحوصة محليًا والناجحة أولًا (الأسرع في الأعلى)
        localResults.filter { it.ok }.forEach { orderedRaw.add(it.cfg) }
        // 2) السيرفرات المضافة يدويًا من المستخدم
        customs.forEach { if (Converters.isSupported(it)) orderedRaw.add(it) }
        // 3) بقية السيرفرات الحيّة من فرع data
        remoteConfigs.forEach { if (Converters.isSupported(it)) orderedRaw.add(it) }

        val items = orderedRaw.mapIndexed { idx, cfg ->
            val name = "bahrain-vpn #${idx + 1}"
            val local = resultMap[cfg]
            val hintMs = serverHints[cfg] ?: 0L
            ServerItem(
                cfg = cfg,
                name = name,
                proto = Converters.protocolBadge(cfg),
                endpoint = Converters.endpointLabel(cfg),
                latencyMs = local?.latencyMs ?: hintMs,
                speedKbps = local?.speedKbps ?: 0.0,
                locallyTested = local != null,
                isFavorite = cfg in favSet,
                isCustom = cfg in customSet,
            )
        }

        VpnStateManager.serverPool = items.map { ServerCandidate(it.cfg, it.name) }
        return items
    }

    fun selectServer(item: ServerItem) {
        prefs.selectedCfg = item.cfg
        prefs.selectedLabel = item.name
        state = state.copy(selectedCfg = item.cfg, error = null)
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
        val sel = resolveSelected(state.selectedCfg, rebuilt)
        state = state.copy(
            servers = rebuilt,
            selectedCfg = sel,
            info = "تم حذف الكانفيغ المضاف يدويًا",
        )
    }

    fun importConfigsFromText(rawText: String) {
        val trimmed = rawText.trim()
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
            .map { Converters.cleanUri(it) }
            .filter { it.contains("://") && Converters.isSupported(it) }
            .distinct()
            .toList()

        if (extracted.isEmpty()) {
            state = state.copy(error = "لم يُعثر على كانفيغ صالح في النص المنسوخ")
            return
        }

        val mergedCustom = (extracted + prefs.customConfigs).distinct()
        prefs.customConfigs = mergedCustom
        val rebuilt = buildServerList(state.configs, state.results)
        val firstAdded = rebuilt.firstOrNull { it.cfg == extracted.first() }
        val newSel = firstAdded?.cfg ?: resolveSelected(state.selectedCfg, rebuilt)
        if (firstAdded != null) {
            prefs.selectedCfg = firstAdded.cfg
            prefs.selectedLabel = firstAdded.name
        }

        state = state.copy(
            servers = rebuilt,
            selectedCfg = newSel,
            error = null,
            info = "تمت إضافة ${extracted.size} سيرفر تحت اسم bahrain-vpn",
        )
    }

    fun setAutoFailover(enabled: Boolean) {
        prefs.autoFailover = enabled
        state = state.copy(autoFailover = enabled)
    }

    // ── تنزيل القائمة الحيّة ──
    fun refresh() {
        val r = buildRepo()
        state = state.copy(loading = true, error = null, info = null, subUrl = r.subscriptionUrl)
        viewModelScope.launch {
            val res = withContext(Dispatchers.IO) { r.loadRemote() }
            if (res.serverLatencies.isNotEmpty()) {
                serverHints = res.serverLatencies
            }
            val newConfigs = res.configs.ifEmpty { state.configs }
            val allFile = if (res.configs.isNotEmpty()) {
                withContext(Dispatchers.IO) { runCatching { r.writeAll(res.configs) }.getOrNull() }
            } else {
                state.allFile
            }
            val rebuilt = buildServerList(newConfigs, state.results)
            val sel = resolveSelected(state.selectedCfg, rebuilt)

            state = state.copy(
                loading = false,
                configs = newConfigs,
                servers = rebuilt,
                selectedCfg = sel,
                meta = if (res.meta.generatedAt != "—") res.meta else state.meta,
                source = res.source,
                allFile = allFile,
                error = res.error,
                info = if (res.error == null && res.configs.isNotEmpty()) {
                    "تم تحديث ${rebuilt.size} سيرفر bahrain-vpn جاهز"
                } else null,
            )
        }
    }

    // ── فحص سريع (Ping فقط بدون استهلاك بيانات السرعة) ──
    fun startQuickPingTest() {
        runTestInternal(quickPingOnly = true)
    }

    // ── فحص شامل (Ping + سرعة التنزيل) ──
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
                val results = tester.run(
                    configs = pool,
                    testTop = topLimit,
                    speedTop = spdLimit,
                    concurrency = prefs.concurrency,
                    timeoutSec = prefs.timeoutSec,
                    rankBySpeed = !quickPingOnly && prefs.rankBySpeed,
                    dnsServer = prefs.dnsServer,
                    useDoh = prefs.dnsDoh,
                ) { p ->
                    withContext(Dispatchers.Main.immediate) {
                        state = state.copy(progress = p)
                    }
                }

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

                val rebuilt = buildServerList(state.configs, results)
                // اختيار أسرع سيرفر تلقائيًا إذا لم يكن الـ VPN متّصلًا حاليًا
                val autoPicked = if (!VpnStateManager.status.value.isActive && results.isNotEmpty()) {
                    rebuilt.first().also {
                        prefs.selectedCfg = it.cfg
                        prefs.selectedLabel = it.name
                    }.cfg
                } else {
                    resolveSelected(state.selectedCfg, rebuilt)
                }

                state = state.copy(
                    testing = false,
                    results = results,
                    servers = rebuilt,
                    selectedCfg = autoPicked,
                    progress = null,
                    allFile = allFile ?: state.allFile,
                    bestFile = bestPair?.first ?: state.bestFile,
                    subFile = bestPair?.second ?: state.subFile,
                    info = if (results.isNotEmpty()) {
                        "نجح ${results.size} سيرفر — تم اختيار ${rebuilt.first().name} (${results.first().latencyMs} ms)"
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
            if (res.ok) {
                val updatedResults = buildList {
                    add(res)
                    state.results.forEach { if (it.cfg != res.cfg) add(it) }
                }
                val rebuilt = buildServerList(state.configs, updatedResults)
                state = state.copy(
                    pingingSingleCfg = null,
                    results = updatedResults,
                    servers = rebuilt,
                    info = "${item.name}: متاح (${res.latencyMs} ms)",
                )
            } else {
                state = state.copy(
                    pingingSingleCfg = null,
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
        state = state.copy(
            error = null,
            info = "تم حفظ الإعدادات بنجاح",
            subUrl = r.subscriptionUrl,
            autoFailover = autoFailover,
        )
    }

    fun settings() = prefs
}
