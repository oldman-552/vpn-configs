// =====================================================================
// ScanRuntimeCoordinator.kt — منسّق الفحص المركزي المستقل عن دورة حياة الواجهة:
//   • ينفّذ الفحص فائق السرعة على CoroutineScope بمستوى التطبيق (SupervisorJob)
//     مدعومًا بـ ServerScanForegroundService حتى يستمر بأقصى سرعة عند الانتقال
//     لأي تطبيق آخر أو إغلاق شاشة التطبيق.
//   • يحفظ النتائج فور اكتمالها في قاعدة البيانات (SQLite) وملفات الشبكة الدائمة
//     (local_results_WIFI.json / local_results_MOBILE_DATA.json) وقوائم التصدير
//     ويسجّل طابع الفحص الزمني لدورة الـ 4 ساعات المنتظمة.
// =====================================================================
package com.bahrain.vpnconfigs.engine

import android.content.Context
import android.os.SystemClock
import com.bahrain.vpnconfigs.community.CommunityTestingManager
import com.bahrain.vpnconfigs.data.ClientDatabase
import com.bahrain.vpnconfigs.data.DeadConfigPurgePolicy
import com.bahrain.vpnconfigs.data.LocalPoolTier
import com.bahrain.vpnconfigs.data.Prefs
import com.bahrain.vpnconfigs.data.Repo
import com.bahrain.vpnconfigs.data.ResultLine
import com.bahrain.vpnconfigs.data.ScanNetworkProfile
import com.bahrain.vpnconfigs.enterprise.EnterpriseLicenseGuard
import com.bahrain.vpnconfigs.util.AppDiag
import com.bahrain.vpnconfigs.util.UiMessages
import com.bahrain.vpnconfigs.util.tr
import com.bahrain.vpnconfigs.vpn.NetworkAwarenessMonitor
import com.bahrain.vpnconfigs.vpn.ServerScanForegroundService
import com.bahrain.vpnconfigs.vpn.VpnStateManager
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.io.File
import java.util.concurrent.atomic.AtomicLong

data class ScanLiveState(
    val testing: Boolean = false,
    val activeScanMode: LocalScanMode? = null,
    val networkProfile: ScanNetworkProfile = ScanNetworkProfile.WIFI,
    val progress: TestProgress? = null,
    val previewSeq: Long = 0L,
    val previewAlive: List<TestResult> = emptyList(),
    val previewFailedUris: Set<String> = emptySet(),
    val completionSeq: Long = 0L,
    val completedProfile: ScanNetworkProfile? = null,
    val remainingConfigs: List<String> = emptyList(),
    val mergedResults: List<TestResult> = emptyList(),
    val failedCleanUris: Set<String> = emptySet(),
    val offlineGuardTriggered: Boolean = false,
    val purgedCount: Int = 0,
    val qualifiedTop100Count: Int = 0,
    val allFile: File? = null,
    val bestFile: File? = null,
    val subFile: File? = null,
    val errorMessage: String? = null,
    val cancelledByUser: Boolean = false,
)

object ScanRuntimeCoordinator {

    private val appScanScope = CoroutineScope(SupervisorJob() + Tester.scanIoDispatcher)
    private val seqGen = AtomicLong(0L)

    @Volatile
    private var activeJob: Job? = null

    private val _state = MutableStateFlow(ScanLiveState())
    val state: StateFlow<ScanLiveState> = _state.asStateFlow()

    val isScanning: Boolean
        get() = _state.value.testing && activeJob?.isActive == true

    fun startInteractiveScan(
        ctx: Context,
        scanMode: LocalScanMode,
        baseConfigs: List<String>,
        fingerprintsById: Map<String, String>,
        basePrevResults: List<TestResult>,
    ) {
        val appCtx = ctx.applicationContext
        val prefs = Prefs(appCtx)
        val repo = Repo(appCtx)
        val licenseGuard = EnterpriseLicenseGuard(appCtx)
        val netMonitor = NetworkAwarenessMonitor(appCtx)
        val netSnap = netMonitor.refreshNow()
        val scanProfile = ScanNetworkProfile.fromTransportCode(netSnap.transport.code)
        val isMetered = netSnap.isMetered || scanProfile == ScanNetworkProfile.MOBILE_DATA

        val vipUris = licenseGuard.getAuthorizedVipNodes().map { it.uri }
        val eliteUris = repo.loadEliteServersForProfile(scanProfile).map { it.cfg }
        val pool = (vipUris + eliteUris + prefs.customConfigs + baseConfigs).distinct()
        if (pool.isEmpty()) return

        activeJob?.cancel()

        val fgTitle = tr(
            "فحص أفضل السيرفرات (${scanProfile.labelAr})",
            "Scanning Best Servers (${scanProfile.labelEn})",
        )
        ServerScanForegroundService.start(
            ctx = appCtx,
            title = fgTitle,
            detail = tr(
                "جارٍ الفحص فائق السرعة لـ ${pool.size} سيرفر في الخلفية…",
                "Ultra-fast scanning ${pool.size} servers at full speed…",
            ),
            done = 0,
            total = pool.size,
        )

        _state.update {
            it.copy(
                testing = true,
                activeScanMode = scanMode,
                networkProfile = scanProfile,
                progress = TestProgress(fgTitle, 0, pool.size, 0),
                errorMessage = null,
                cancelledByUser = false,
            )
        }

        activeJob = appScanScope.launch {
            try {
                executeScanAndPersistInternal(
                    appCtx = appCtx,
                    scanMode = scanMode,
                    pool = pool,
                    baseConfigs = baseConfigs,
                    fingerprintsById = fingerprintsById,
                    basePrevResults = basePrevResults,
                    scanProfile = scanProfile,
                    isMetered = isMetered,
                    isScheduledBackground = false,
                    useForegroundNotification = true,
                    fgTitle = fgTitle,
                )
            } catch (_: CancellationException) {
                _state.update {
                    it.copy(
                        testing = false,
                        activeScanMode = null,
                        progress = null,
                        cancelledByUser = true,
                    )
                }
            } catch (e: Exception) {
                AppDiag.w("ScanCoordinator", "interactive scan failed", e)
                _state.update {
                    it.copy(
                        testing = false,
                        activeScanMode = null,
                        progress = null,
                        completionSeq = seqGen.incrementAndGet(),
                        errorMessage = UiMessages.msgTestFailed(),
                    )
                }
            } finally {
                ServerScanForegroundService.stop(appCtx)
            }
        }
    }

    /**
     * يُستدعى كل ساعة من RefreshWorker لفحص السيرفرات مباشرةً وحفظ النتائج تلقائيًا في كافة القوائم
     * (بما فيها ترقية وتحديث قائمة «المميزة جداً» بمهلة 6 ساعات) دون المساس بأي فحص تفاعلي جارٍ حاليًا.
     */
    suspend fun executeScheduledHourlyScan(
        ctx: Context,
        baseConfigs: List<String>,
        fingerprintsById: Map<String, String>,
        scanProfile: ScanNetworkProfile,
        isMetered: Boolean,
        customScanner: SequentialTunnelScanner? = null,
        activeNetworkSupplier: (() -> ScanNetworkProfile)? = null,
    ): Boolean {
        if (isScanning) return true
        val appCtx = ctx.applicationContext
        val prefs = Prefs(appCtx)
        val repo = Repo(appCtx)
        val licenseGuard = EnterpriseLicenseGuard(appCtx)
        val vipUris = licenseGuard.getAuthorizedVipNodes().map { it.uri }
        val eliteUris = repo.loadEliteServersForProfile(scanProfile).map { it.cfg }
        val pool = (vipUris + eliteUris + prefs.customConfigs + baseConfigs).distinct()
        if (pool.isEmpty()) return false

        val prevSaved = repo.loadSavedResultsForProfile(scanProfile)
        return try {
            executeScanAndPersistInternal(
                appCtx = appCtx,
                scanMode = LocalScanMode.FULL_SCAN,
                pool = pool,
                baseConfigs = baseConfigs,
                fingerprintsById = fingerprintsById,
                basePrevResults = prevSaved,
                scanProfile = scanProfile,
                isMetered = isMetered,
                isScheduledBackground = true,
                useForegroundNotification = false,
                fgTitle = "",
                customScanner = customScanner,
                overrideNetworkSupplier = activeNetworkSupplier,
            )
            true
        } catch (e: Exception) {
            AppDiag.w("ScanCoordinator", "scheduled 1h scan failed", e)
            false
        }
    }

    suspend fun executeScheduledFourHourScan(
        ctx: Context,
        baseConfigs: List<String>,
        fingerprintsById: Map<String, String>,
        scanProfile: ScanNetworkProfile,
        isMetered: Boolean,
        customScanner: SequentialTunnelScanner? = null,
        activeNetworkSupplier: (() -> ScanNetworkProfile)? = null,
    ): Boolean = executeScheduledHourlyScan(
        ctx = ctx,
        baseConfigs = baseConfigs,
        fingerprintsById = fingerprintsById,
        scanProfile = scanProfile,
        isMetered = isMetered,
        customScanner = customScanner,
        activeNetworkSupplier = activeNetworkSupplier,
    )

    fun cancelActiveScan(ctx: Context) {
        activeJob?.cancel()
        activeJob = null
        ServerScanForegroundService.stop(ctx.applicationContext)
        _state.update {
            it.copy(
                testing = false,
                activeScanMode = null,
                progress = null,
                cancelledByUser = true,
            )
        }
    }

    private suspend fun executeScanAndPersistInternal(
        appCtx: Context,
        scanMode: LocalScanMode,
        pool: List<String>,
        baseConfigs: List<String>,
        fingerprintsById: Map<String, String>,
        basePrevResults: List<TestResult>,
        scanProfile: ScanNetworkProfile,
        isMetered: Boolean,
        isScheduledBackground: Boolean,
        useForegroundNotification: Boolean,
        fgTitle: String,
        customScanner: SequentialTunnelScanner? = null,
        overrideNetworkSupplier: (() -> ScanNetworkProfile)? = null,
    ) {
        val prefs = Prefs(appCtx)
        val repo = Repo(appCtx)
        val clientDb = ClientDatabase.getInstance(appCtx)
        val licenseGuard = EnterpriseLicenseGuard(appCtx)
        val netMonitor = NetworkAwarenessMonitor(appCtx)
        val scanner = customScanner ?: SequentialTunnelScanner(appCtx, clientDb = clientDb)

        var lastUiTickMs = 0L
        var lastNotifTickMs = 0L

        val summary = scanner.executeScan(
            scanMode = scanMode,
            allCandidateConfigs = pool,
            fingerprintsById = fingerprintsById,
            networkProfile = scanProfile,
            isMetered = isMetered,
            timeoutSec = prefs.timeoutSec,
            dnsServer = prefs.dnsServer,
            useDoh = prefs.dnsDoh,
            isBackgroundRun = isScheduledBackground,
            skipFreshWithinTtl = false,
            activeNetworkSupplier = overrideNetworkSupplier ?: {
                val snap = netMonitor.refreshNow()
                if (snap.connected) ScanNetworkProfile.fromTransportCode(snap.transport.code) else scanProfile
            },
            onProgress = { p ->
                val nowElapsed = runCatching { SystemClock.elapsedRealtime() }.getOrDefault(System.currentTimeMillis())
                if (!isScheduledBackground && (p.done == 0 || p.done >= p.total || nowElapsed - lastUiTickMs >= 65L)) {
                    lastUiTickMs = nowElapsed
                    _state.update { it.copy(progress = p) }
                }
                if (useForegroundNotification && (p.done >= p.total || nowElapsed - lastNotifTickMs >= 280L)) {
                    lastNotifTickMs = nowElapsed
                    val detail = tr(
                        "${p.stage}: ${p.done} / ${p.total} • ${p.alive} شغّال",
                        "${p.stage}: ${p.done} / ${p.total} • ${p.alive} alive",
                    )
                    ServerScanForegroundService.updateIfRunning(appCtx, fgTitle, detail, p.done, p.total)
                }
            },
            onRankingUpdated = { _, aliveSoFar, failedSoFar ->
                if (!isScheduledBackground && aliveSoFar.isNotEmpty()) {
                    _state.update {
                        it.copy(
                            previewSeq = seqGen.incrementAndGet(),
                            previewAlive = aliveSoFar,
                            previewFailedUris = failedSoFar,
                        )
                    }
                }
            },
        )

        val postNetSnap = netMonitor.refreshNow()
        val effectivelyOffline = summary.offlineGuardTriggered ||
            (summary.results.isEmpty() && !postNetSnap.connected)
        if (effectivelyOffline) {
            _state.update {
                it.copy(
                    testing = false,
                    activeScanMode = null,
                    progress = null,
                    completionSeq = seqGen.incrementAndGet(),
                    completedProfile = scanProfile,
                    remainingConfigs = baseConfigs,
                    mergedResults = basePrevResults,
                    offlineGuardTriggered = true,
                    errorMessage = tr(
                        "الشبكة غير متصلة حاليًا — تم الاحتفاظ بآخر السيرفرات الشغّالة دون حذف",
                        "Device network offline — preserved last working servers without deletion",
                    ),
                )
            }
            return
        }

        val completedWallMs = System.currentTimeMillis()
        val vipProtectedSet = licenseGuard.getAuthorizedVipNodes()
            .map { Converters.cleanUri(it.uri) }
            .toHashSet()
        val activeConnectedClean = VpnStateManager.status.value.activeCfg
            ?.takeIf { VpnStateManager.status.value.isActive && it.isNotBlank() }
            ?.let { setOf(Converters.cleanUri(it)) }
            ?: emptySet()
        val favClean = prefs.favorites.map { Converters.cleanUri(it) }.toHashSet()
        val favIds = clientDb.favoriteServerIds()

        // ترقية السيرفرات المميزة جداً تلقائياً وتطبيق مهلة الـ 6 ساعات قبل السماح بحذف أي سيرفر مميز جداً
        val eliteRec = repo.reconcileAndSaveEliteAfterScan(
            profile = scanProfile,
            aliveResults = summary.results,
            failedUris = summary.failedCleanUris,
            deviceOnline = true,
            nowMs = completedWallMs,
            vipCleanUris = vipProtectedSet,
        )

        val purgeDecision = DeadConfigPurgePolicy.evaluate(
            currentPool = (eliteRec.retainedCleanUris + baseConfigs).distinct(),
            failedUris = summary.failedCleanUris + eliteRec.expiredCleanUris,
            testedCount = summary.testedCount,
            aliveCount = summary.aliveCount,
            deviceOnline = true,
            favoriteCleanUris = favClean + activeConnectedClean,
            favoriteServerIds = favIds,
            vipCleanUris = vipProtectedSet,
            eliteRetainedCleanUris = eliteRec.retainedCleanUris,
            eliteRetainedServerIds = eliteRec.retainedServerIds,
        )
        if (purgeDecision.shouldPurge) {
            if (prefs.customConfigs.isNotEmpty()) {
                prefs.customConfigs = prefs.customConfigs.filterNot {
                    Converters.cleanUri(it) in purgeDecision.purgeableCleanUris
                }
            }
            repo.recordPurgedDeadAndCleanFiles(
                profile = scanProfile,
                purgeableCleanUris = purgeDecision.purgeableCleanUris,
                remainingPool = purgeDecision.remainingPool,
                bestLimit = minOf(prefs.bestN, PersonalizedTop50Ranker.PERSONALIZED_TOP_LIMIT),
                nowMs = completedWallMs,
            )
        }

        summary.failedCleanUris.forEach { VpnStateManager.markServerDropped(it) }
        summary.results.forEach { VpnStateManager.markServerHealthy(Converters.cleanUri(it.cfg)) }

        val nextConfigs = if (purgeDecision.shouldPurge) {
            purgeDecision.remainingPool
        } else {
            (eliteRec.retainedCleanUris + baseConfigs).distinct()
        }
        val freshAliveSet = summary.results.map { Converters.cleanUri(it.cfg) }.toHashSet()
        val untouchedPrev = basePrevResults.filter { old ->
            val c = Converters.cleanUri(old.cfg)
            c !in freshAliveSet && c !in summary.failedCleanUris && c !in eliteRec.expiredCleanUris
        }
        val mergedResults = (summary.results + untouchedPrev).sortedWith(
            compareByDescending<TestResult> { it.speedKbps }
                .thenByDescending { it.stabilityScore }
                .thenBy { if (it.latencyMs > 0L) it.latencyMs else Long.MAX_VALUE }
                .thenBy { it.jitterMs }
        )

        // Persist permanently into per-network saved list + exported files + 1-hour scan wall clock!
        repo.saveProfileResults(scanProfile, mergedResults)
        prefs.setLastScanWallMs(scanProfile, completedWallMs)

        val exportPool = (prefs.customConfigs + nextConfigs)
            .distinct()
            .filterNot { Converters.cleanUri(it) in vipProtectedSet }
        val exportTop100Ids = summary.rankingBundle.top100.map { it.serverId }.toHashSet()
        val exportMerged = mergedResults.filter {
            val clean = Converters.cleanUri(it.cfg)
            clean !in vipProtectedSet && (exportTop100Ids.isEmpty() || Converters.stableServerId(clean) in exportTop100Ids)
        }

        val allFile = runCatching { repo.writeAll(exportPool) }.getOrNull()
        val bestPair = if (exportMerged.isNotEmpty()) {
            prefs.sortMode = ServerSortMode.FASTEST_DOWNLOAD.key
            prefs.rankBySpeed = true
            runCatching {
                repo.writeBest(
                    exportMerged.map { ResultLine(it.cfg, it.latencyMs, it.speedKbps, it.testedAtMs) },
                    minOf(prefs.bestN, PersonalizedTop50Ranker.PERSONALIZED_TOP_LIMIT),
                )
            }.getOrNull()
        } else null

        // Auto-select #1 ranked server if VPN is not actively connected
        if (!VpnStateManager.status.value.isActive && mergedResults.isNotEmpty()) {
            val topRankId = summary.rankingBundle.top100.firstOrNull()?.serverId
            val bestItemCfg = if (topRankId != null) {
                mergedResults.firstOrNull { Converters.stableServerId(Converters.cleanUri(it.cfg)) == topRankId }?.cfg
            } else {
                mergedResults.firstOrNull()?.cfg
            }
            if (!bestItemCfg.isNullOrBlank()) {
                prefs.selectedCfg = Converters.cleanUri(bestItemCfg)
                prefs.selectedLabel = "bahrain-vpn #1"
            }
        }

        runCatching {
            CommunityTestingManager.syncFromUnifiedQualityScanIfOptedIn(
                ctx = appCtx,
                aliveResults = summary.results,
            )
        }

        _state.update {
            it.copy(
                testing = false,
                activeScanMode = null,
                progress = null,
                completionSeq = seqGen.incrementAndGet(),
                completedProfile = scanProfile,
                remainingConfigs = nextConfigs,
                mergedResults = mergedResults,
                failedCleanUris = summary.failedCleanUris,
                offlineGuardTriggered = false,
                purgedCount = purgeDecision.purgeableCleanUris.size,
                qualifiedTop100Count = summary.rankingBundle.top100.size,
                allFile = allFile,
                bestFile = bestPair?.first,
                subFile = bestPair?.second,
                errorMessage = if (summary.results.isEmpty() && summary.rankingBundle.top100.isEmpty()) {
                    tr(
                        "لم يتأهل أي سيرفر على ${scanProfile.labelAr} حاليًا — حاول التحديث أو المحاولة لاحقًا",
                        "No server qualified on ${scanProfile.labelEn} right now — try Refresh or retry shortly",
                    )
                } else null,
                cancelledByUser = false,
            )
        }
    }
}
