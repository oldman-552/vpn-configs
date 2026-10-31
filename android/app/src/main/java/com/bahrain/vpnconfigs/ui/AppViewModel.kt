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
import com.bahrain.vpnconfigs.data.ClientDatabase
import com.bahrain.vpnconfigs.data.ConnectionHistoryEntry
import com.bahrain.vpnconfigs.data.FavoriteServerRecord
import com.bahrain.vpnconfigs.data.FavoriteSortOrder
import com.bahrain.vpnconfigs.data.HistorySortOrder
import com.bahrain.vpnconfigs.data.LocalPoolTier
import com.bahrain.vpnconfigs.data.LocalServerTelemetry
import com.bahrain.vpnconfigs.data.Prefs
import com.bahrain.vpnconfigs.data.ProtectionEventRecord
import com.bahrain.vpnconfigs.data.RemoteMeta
import com.bahrain.vpnconfigs.data.Repo
import com.bahrain.vpnconfigs.data.ResolvedPromoBanner
import com.bahrain.vpnconfigs.data.ResultLine
import com.bahrain.vpnconfigs.data.ScanNetworkProfile
import com.bahrain.vpnconfigs.data.ServerHint
import com.bahrain.vpnconfigs.data.ServerSessionRecord
import com.bahrain.vpnconfigs.engine.Converters
import com.bahrain.vpnconfigs.engine.LocalScanMode
import com.bahrain.vpnconfigs.engine.PersonalizedTop50Ranker
import com.bahrain.vpnconfigs.engine.RankableServer
import com.bahrain.vpnconfigs.engine.SecurityEvaluator
import com.bahrain.vpnconfigs.engine.SequentialTunnelScanner
import com.bahrain.vpnconfigs.engine.ServerRanker
import com.bahrain.vpnconfigs.engine.ServerSortMode
import com.bahrain.vpnconfigs.engine.SmartSelectionDecision
import com.bahrain.vpnconfigs.engine.SmartSelectionWeights
import com.bahrain.vpnconfigs.engine.SmartServerCandidateInput
import com.bahrain.vpnconfigs.engine.SmartServerSelector
import com.bahrain.vpnconfigs.engine.TestProgress
import com.bahrain.vpnconfigs.engine.TestResult
import com.bahrain.vpnconfigs.engine.Tester
import com.bahrain.vpnconfigs.enterprise.AccountLicenseState
import com.bahrain.vpnconfigs.enterprise.AppHealthMonitor
import com.bahrain.vpnconfigs.util.AppI18n
import com.bahrain.vpnconfigs.util.tr
import com.bahrain.vpnconfigs.enterprise.AppHealthSnapshot
import com.bahrain.vpnconfigs.enterprise.AppUpdateInfo
import com.bahrain.vpnconfigs.enterprise.AppUpdateManager
import com.bahrain.vpnconfigs.enterprise.ClientDiagnosticsEngine
import com.bahrain.vpnconfigs.enterprise.EnterpriseLicenseGuard
import com.bahrain.vpnconfigs.enterprise.ExplicitUrlProbeResult
import com.bahrain.vpnconfigs.enterprise.NetworkDiagnosticReport
import com.bahrain.vpnconfigs.enterprise.SpeedTestRecord
import com.bahrain.vpnconfigs.util.AppDiag
import com.bahrain.vpnconfigs.util.UiMessages
import com.bahrain.vpnconfigs.vpn.AppEntry
import com.bahrain.vpnconfigs.vpn.BahrainVpnService
import com.bahrain.vpnconfigs.vpn.ConnectionSecurityClassifier
import com.bahrain.vpnconfigs.vpn.InstalledApps
import com.bahrain.vpnconfigs.vpn.NetworkAwarenessMonitor
import com.bahrain.vpnconfigs.vpn.SecurityStatusReport
import com.bahrain.vpnconfigs.vpn.ServerCandidate
import com.bahrain.vpnconfigs.vpn.VpnPhase
import com.bahrain.vpnconfigs.vpn.VpnStateManager
import com.bahrain.vpnconfigs.vpn.VpnStatus
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
    val isVip: Boolean = false,
    val securityAssessment: String = "Unknown",
    val privacyAssessment: String = "Unknown",
    val riskLevel: String = "UNKNOWN",
    val securitySummaryAr: String = "",
    val localPoolTier: LocalPoolTier = LocalPoolTier.CANDIDATE_ONLY,
    val personalizedRank: Int = 0,
    val personalizedScore: Double = 0.0,
    val stabilityScore: Double = 0.0,
    val packetLossPct: Double = 0.0,
    val establishMs: Long = 0L,
    val configFingerprint: String = "",
) {
    val serverId: String
        get() = Converters.stableServerId(cfg)

    val exportUri: String
        get() = if (isVip) "" else Converters.namedUri(cfg, name)
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
    val failoverMode: String = "SMART",
    val killSwitch: Boolean = true,
    val appsLoading: Boolean = false,
    val installedApps: List<AppEntry> = emptyList(),
    val splitApps: Set<String> = emptySet(),
    val splitIncludeOnly: Boolean = false,
    val tunnelNeedsReload: Boolean = false,
    val activePromo: ResolvedPromoBanner? = null,
    // ── مؤشرات ULTIMATE VPN ENTERPRISE (حساب، تجربة 48 ساعة، سرعة، تشخيص، تحديثات) ──
    val accountState: AccountLicenseState = AccountLicenseState(),
    val authLoading: Boolean = false,
    val authError: String? = null,
    val speedTestRunning: Boolean = false,
    val speedTestStage: String = "",
    val liveSpeedGaugeMbps: Double = 0.0,
    val liveSpeedCurve: List<Double> = emptyList(),
    val latestSpeedRecord: SpeedTestRecord? = null,
    val speedHistory: List<SpeedTestRecord> = emptyList(),
    val netDiagRunning: Boolean = false,
    val netDiagReport: NetworkDiagnosticReport? = null,
    val urlProbeResult: ExplicitUrlProbeResult? = null,
    val appHealth: AppHealthSnapshot = AppHealthSnapshot(20L, 0.0, 0, 0, 0, false, emptyList()),
    val availableUpdate: AppUpdateInfo? = null,
    val updatingApk: Boolean = false,
    // ── v3.3 الذكاء التاريخي والمفضّلة المتقدمة والاختيار الذكي ──
    val smartAutoSelect: Boolean = true,
    val preferredCountry: String = "ALL",
    val smartDecision: SmartSelectionDecision = SmartSelectionDecision(null, null, emptyList()),
    val favoritesList: List<FavoriteServerRecord> = emptyList(),
    val favoriteGroups: List<String> = listOf("عام", "العمل", "الألعاب", "البث"),
    val favoriteGroupFilter: String = "ALL",
    val favoriteSortOrder: FavoriteSortOrder = FavoriteSortOrder.RECENT,
    val sqliteHistory: List<ServerSessionRecord> = emptyList(),
    val sqliteHistoryTotal: Int = 0,
    val historySearchQuery: String = "",
    val historyDateDays: Int = 0,
    val historySortOrder: HistorySortOrder = HistorySortOrder.RECENT,
    val historyPageLimit: Int = 30,
    val historyRetentionDays: Int = 30,
    val telemetryById: Map<String, LocalServerTelemetry> = emptyMap(),
    val protectionEvents: List<ProtectionEventRecord> = emptyList(),
    // ── v3.4 Central Top 500 + Local Personalized Top 50 (Wi-Fi vs Mobile Data) ──
    val activeNetworkProfile: ScanNetworkProfile = ScanNetworkProfile.WIFI,
    val datasetVersion: Long = 0L,
    val datasetQualifiedCount: Int = 0,
    val top50Count: Int = 0,
    val backupPoolCount: Int = 0,
    val activeScanMode: LocalScanMode? = null,
) {
    val selectedServer: ServerItem?
        get() = servers.firstOrNull { it.cfg == selectedCfg } ?: servers.firstOrNull()
}

class AppViewModel(app: Application) : AndroidViewModel(app) {

    private val prefs = Prefs(app)
    private val clientDb = ClientDatabase.getInstance(app).also {
        runCatching {
            it.migrateLegacyFavoritesIfNeeded(prefs)
            it.pruneExpiredHistory(prefs.historyRetentionDays)
        }
    }
    private val tester = Tester(app)
    private val netAwareness = NetworkAwarenessMonitor(app).also {
        runCatching { it.start { _, _ -> } }
    }
    private val sequentialScanner = SequentialTunnelScanner(app, clientDb)
    private val licenseGuard = EnterpriseLicenseGuard(app)
    private val diagnosticsEngine = ClientDiagnosticsEngine(app)

    private var serverLatencies: Map<String, Long> = emptyMap()
    private var serverHints: Map<String, ServerHint> = emptyMap()
    private var serverFingerprints: Map<String, String> = emptyMap()
    private val failedConfigs: MutableSet<String> = HashSet()

    private fun currentNetworkProfile(): ScanNetworkProfile =
        ScanNetworkProfile.fromTransportCode(netAwareness.snapshot.value.transport.code)

    var state by mutableStateOf(
        UiState(
            engineReady = sequentialScanner.engineAvailable,
            sortMode = prefs.sortMode,
            feedProfile = prefs.feedProfile,
            lastUpdatedLabel = UiMessages.formatLastUpdated(null, prefs.lastRefreshWallMs),
            connectionHistory = prefs.connectionHistory,
            selectedCfg = prefs.selectedCfg,
            autoFailover = prefs.autoFailover,
            failoverMode = prefs.failoverMode,
            killSwitch = prefs.killSwitch,
            splitApps = prefs.splitApps,
            splitIncludeOnly = prefs.splitIncludeOnly,
            accountState = licenseGuard.currentState(),
            speedHistory = diagnosticsEngine.loadSpeedHistory(),
            latestSpeedRecord = diagnosticsEngine.loadSpeedHistory().firstOrNull(),
            appHealth = AppHealthMonitor.snapshot(app),
            smartAutoSelect = prefs.smartAutoSelect,
            preferredCountry = prefs.preferredCountry,
            favoritesList = clientDb.listFavorites(),
            favoriteGroups = clientDb.listFavoriteGroups(),
            sqliteHistory = clientDb.querySessionHistory(limit = 30),
            sqliteHistoryTotal = clientDb.countSessionHistory(),
            historyRetentionDays = prefs.historyRetentionDays,
            telemetryById = clientDb.getAllServerTelemetryMap(),
            protectionEvents = clientDb.recentProtectionEvents(),
            activeNetworkProfile = ScanNetworkProfile.fromTransportCode(netAwareness.snapshot.value.transport.code),
        )
    )
        private set

    private var testJob: Job? = null
    private var promoJob: Job? = null
    private var lastObservedDropped: Set<String> = emptySet()
    private var promoSyncedWhileConnected: Boolean = false

    init {
        AppDiag.init(app)
        AppHealthMonitor.install(app)
        syncEnterpriseBundle()

        // تحميل الإعلان المتناوب عند فتح التطبيق وتحديث بقية الصور الخمس في الخلفية
        triggerNextPromoBanner()

        // مراقبة تغيّر نوع الشبكة الفعلي (Wi-Fi مقابل بيانات الجوال) وتبديل قائمة Top-50 المخصّصة فورًا
        viewModelScope.launch {
            netAwareness.snapshot.collectLatest { netSnap ->
                val newProfile = ScanNetworkProfile.fromTransportCode(netSnap.transport.code)
                if (newProfile != state.activeNetworkProfile && state.configs.isNotEmpty()) {
                    val rebuilt = withContext(Dispatchers.IO) {
                        buildServerList(state.configs, state.results, state.sortMode, newProfile)
                    }
                    val topCnt = rebuilt.count { it.localPoolTier == LocalPoolTier.TOP_50 }
                    val bakCnt = rebuilt.count { it.localPoolTier == LocalPoolTier.BACKUP_POOL }
                    val sel = resolveSelected(state.selectedCfg, rebuilt)
                    state = state.copy(
                        activeNetworkProfile = newProfile,
                        servers = rebuilt,
                        top50Count = topCnt,
                        backupPoolCount = bakCnt,
                        selectedCfg = sel,
                        smartDecision = computeSmartDecisionFor(rebuilt),
                    )
                } else if (newProfile != state.activeNetworkProfile) {
                    state = state.copy(activeNetworkProfile = newProfile)
                }
            }
        }

        viewModelScope.launch {
            VpnStateManager.status.collectLatest { vpnSt ->
                val latestHistory = prefs.connectionHistory
                val droppedChanged = vpnSt.droppedConfigs != lastObservedDropped
                if (droppedChanged) {
                    val newlyDropped = vpnSt.droppedConfigs - lastObservedDropped
                    val recovered = lastObservedDropped - vpnSt.droppedConfigs
                    lastObservedDropped = vpnSt.droppedConfigs
                    failedConfigs.addAll(newlyDropped)
                    failedConfigs.removeAll(recovered)
                    val filteredResults = if (newlyDropped.isNotEmpty()) {
                        state.results.filterNot { Converters.cleanUri(it.cfg) in newlyDropped }
                    } else {
                        state.results
                    }
                    val rebuilt = buildServerList(state.configs, filteredResults, state.sortMode)
                    val sel = resolveSelected(state.selectedCfg, rebuilt)
                    state = state.copy(
                        connectionHistory = latestHistory,
                        results = filteredResults,
                        servers = rebuilt,
                        selectedCfg = sel,
                        smartDecision = computeSmartDecisionFor(rebuilt),
                    )
                    refreshPersistenceSnapshotAsync()
                } else if (latestHistory != state.connectionHistory) {
                    state = state.copy(connectionHistory = latestHistory)
                    refreshPersistenceSnapshotAsync()
                }

                if (vpnSt.isTunnelVerified && !promoSyncedWhileConnected) {
                    promoSyncedWhileConnected = true
                    viewModelScope.launch(Dispatchers.IO) {
                        runCatching { buildRepo().syncAllPromoAssets() }
                    }
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
            serverFingerprints = cached?.serverFingerprints ?: emptyMap()
            val cfgs = cached?.configs ?: emptyList()
            val curProf = currentNetworkProfile()
            val built = withContext(Dispatchers.IO) { buildServerList(cfgs, savedResults, prefs.sortMode, curProf) }
            val countries = computeCountryCounts(built)
            val chosen = resolveSelected(prefs.selectedCfg, built)
            val metaObj = cached?.meta ?: RemoteMeta()

            state = state.copy(
                configs = cfgs,
                servers = built,
                availableCountries = countries,
                selectedCfg = chosen,
                smartDecision = computeSmartDecisionFor(built),
                meta = metaObj,
                lastUpdatedLabel = UiMessages.formatLastUpdated(metaObj.generatedAt, prefs.lastRefreshWallMs),
                results = savedResults,
                allFile = allF,
                bestFile = bestF,
                subFile = subF,
                engineReady = sequentialScanner.engineAvailable,
                activeNetworkProfile = curProf,
                datasetVersion = cached?.datasetVersion ?: 0L,
                datasetQualifiedCount = cfgs.size,
                top50Count = built.count { it.localPoolTier == LocalPoolTier.TOP_50 },
                backupPoolCount = built.count { it.localPoolTier == LocalPoolTier.BACKUP_POOL },
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
        networkProfile: ScanNetworkProfile = currentNetworkProfile(),
    ): List<ServerItem> {
        val nowMs = System.currentTimeMillis()
        val sortMode = ServerSortMode.fromKey(modeKey)
        val favSet = prefs.favorites.map { Converters.cleanUri(it) }.toHashSet()
        val favIdSet = clientDb.favoriteServerIds()
        val customs = prefs.customConfigs.map { Converters.cleanUri(it) }
        val customSet = customs.toHashSet()
        val vipNodes = licenseGuard.getAuthorizedVipNodes()
        val vipByClean = vipNodes.associateBy { Converters.cleanUri(it.uri) }
        val resultMap = localResults.filter { it.ok && (it.latencyMs > 0L || it.speedKbps > 0.0) }
            .associateBy { Converters.cleanUri(it.cfg) }
        val netStatsById = clientDb.getNetworkStatsMap(networkProfile)

        val allUnique = LinkedHashSet<String>()
        vipNodes.forEach {
            val cleaned = Converters.cleanUri(it.uri)
            if (Converters.isSupported(cleaned)) allUnique.add(cleaned)
        }
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

        // Compute personalized Top 50 + Qualified Backup Pool strictly from local measurements on `networkProfile`
        val rankBundle = PersonalizedTop50Ranker.computeRankings(
            candidateConfigs = allUnique.toList(),
            fingerprintsById = serverFingerprints,
            statsById = netStatsById,
            profile = networkProfile,
            nowMs = nowMs,
        )

        val droppedNow = VpnStateManager.status.value.droppedConfigs
        val rankablePairs = allUnique.mapNotNull { cfg ->
            val vipNode = vipByClean[cfg]
            val hint = serverHints[cfg]
            val secProfile = SecurityEvaluator.evaluate(
                rawCfg = cfg,
                isVipAttested = vipNode != null,
                hintSecurity = hint?.securityAssessment.orEmpty(),
                hintPrivacy = hint?.privacyAssessment.orEmpty(),
                hintRisk = hint?.riskLevel.orEmpty(),
            )
            if (secProfile.quarantined) return@mapNotNull null

            val sid = Converters.stableServerId(cfg)
            val fp = serverFingerprints[sid] ?: Converters.configFingerprint(cfg)
            val netStat = netStatsById[sid]
            val personalEntry = rankBundle.entriesById[sid]
            val failed = cfg in failedConfigs || cfg in droppedNow || (netStat != null && netStat.consecutiveFailures >= 3)
            val local = if (failed) null else resultMap[cfg]

            // القياسات المعروضة والمعتمدة في الترتيب الشخصي تأتي فقط من الفحص الحقيقي على نفس نوع الشبكة (WIFI أو MOBILE_DATA)
            val localProfileLat = if (!failed && netStat != null && netStat.isQualifiedLocally) {
                netStat.latestLatencyMs
            } else if (!failed && local != null && local.latencyMs > 0L && netStat != null) {
                local.latencyMs
            } else {
                0L
            }
            val displayLatency = when {
                failed -> -1L
                localProfileLat > 0L -> localProfileLat
                else -> 0L
            }
            val effectiveSpeed = when {
                failed -> 0.0
                netStat != null && netStat.isQualifiedLocally && netStat.latestThroughputKbps > 0.0 -> netStat.latestThroughputKbps
                netStat != null && netStat.isQualifiedLocally && netStat.bestThroughputKbps > 0.0 -> netStat.bestThroughputKbps
                else -> 0.0
            }
            val effectiveJitter = if (!failed && netStat != null && netStat.isQualifiedLocally) netStat.ewmaJitterMs else 0.0
            val effectiveLoss = if (!failed && netStat != null && netStat.scanCount > 0) netStat.ewmaPacketLossPct else 0.0
            val effectiveEstab = if (!failed && netStat != null) netStat.latestEstablishMs else 0L
            val effectiveTestedMs = netStat?.lastScanAtMs ?: 0L
            val isLocallyVerifiedForProfile = !failed && personalEntry != null

            val isFav = cfg in favSet || sid in favIdSet
            val rankable = RankableServer(
                cfg = cfg,
                latencyMs = displayLatency,
                jitterMs = effectiveJitter,
                speedKbps = effectiveSpeed,
                packetLossPct = effectiveLoss,
                uptimePct = if (netStat != null && netStat.scanCount > 0) netStat.connectionSuccessRate * 100.0 else 0.0,
                stabilityRuns = netStat?.successCount ?: 0,
                // لا يُستخدم تقييم GitHub المركزي أبدًا كبديل للترتيب الشخصي؛ فقط كترتيب مبدئي للمرشّحات غير المفحوصة بعد
                cloudQualityHint = if (vipNode != null) 98.0 else 0.0,
                securityAssessment = secProfile.securityAssessment,
                privacyAssessment = secProfile.privacyAssessment,
                riskLevel = secProfile.riskLevel,
                locallyTested = isLocallyVerifiedForProfile,
                localFailed = failed,
                isFavorite = isFav || vipNode != null,
                isCustom = cfg in customSet,
                lastTestedAtMs = effectiveTestedMs,
            )
            val computedOverall = if (personalEntry != null) {
                personalEntry.personalizedScore
            } else {
                ServerRanker.computeOverallScore(rankable, nowMs)
            }
            val customFavName = clientDb.getFavorite(sid)?.customName.orEmpty()
            val item = ServerItem(
                cfg = cfg,
                name = customFavName.ifBlank { vipNode?.label.orEmpty() },
                proto = Converters.protocolBadge(cfg),
                endpoint = if (vipNode != null) tr("عقدة VIP مشفّرة ومحمية", "Encrypted VIP Node") else Converters.endpointLabel(cfg),
                latencyMs = displayLatency,
                jitterMs = effectiveJitter,
                speedKbps = effectiveSpeed,
                score = personalEntry?.personalizedScore ?: 0.0,
                overallScore = computedOverall,
                country = vipNode?.country?.takeIf { it.isNotBlank() } ?: hint?.country.orEmpty(),
                stabilityRuns = netStat?.successCount ?: 0,
                verifiedAt = hint?.verifiedAt.orEmpty(),
                lastTestedAtMs = effectiveTestedMs,
                locallyTested = isLocallyVerifiedForProfile,
                localFailed = failed,
                isFavorite = isFav,
                isCustom = cfg in customSet,
                isVip = vipNode != null,
                securityAssessment = secProfile.securityAssessment,
                privacyAssessment = secProfile.privacyAssessment,
                riskLevel = secProfile.riskLevel,
                securitySummaryAr = secProfile.summaryAr,
                localPoolTier = personalEntry?.poolTier ?: LocalPoolTier.CANDIDATE_ONLY,
                personalizedRank = personalEntry?.rankPosition ?: 0,
                personalizedScore = personalEntry?.personalizedScore ?: 0.0,
                stabilityScore = personalEntry?.stabilityScore ?: (netStat?.stabilityScore ?: 0.0),
                packetLossPct = effectiveLoss,
                establishMs = effectiveEstab,
                configFingerprint = fp,
            )
            rankable to item
        }

        val comp = ServerRanker.comparatorFor(sortMode, nowMs)
        val sortedItems = rankablePairs
            .sortedWith { a, b ->
                val itemA = a.second
                val itemB = b.second
                if (itemA.isVip != itemB.isVip && itemA.localFailed == itemB.localFailed) {
                    if (itemA.isVip) -1 else 1
                } else if (itemA.localPoolTier != itemB.localPoolTier) {
                    // TOP_50 (0) -> BACKUP_POOL (1) -> CANDIDATE_ONLY (2)
                    itemA.localPoolTier.ordinal.compareTo(itemB.localPoolTier.ordinal)
                } else if (itemA.localPoolTier != LocalPoolTier.CANDIDATE_ONLY && sortMode == ServerSortMode.BEST_OVERALL) {
                    itemA.personalizedRank.compareTo(itemB.personalizedRank)
                } else {
                    comp.compare(a.first, b.first)
                }
            }
            .mapIndexed { idx, pair ->
                val itm = pair.second
                val finalName = when {
                    itm.name.isNotBlank() && !itm.isVip -> itm.name
                    itm.isVip && itm.name.isNotBlank() -> "bahrain-vpn VIP • ${itm.name}"
                    else -> "bahrain-vpn #${idx + 1}"
                }
                itm.copy(name = finalName)
            }

        VpnStateManager.serverPool = sortedItems.filterNot { it.localFailed }
            .ifEmpty { sortedItems }
            .map {
                ServerCandidate(
                    cfg = it.cfg,
                    label = it.name,
                    speedKbps = it.speedKbps,
                    latencyMs = it.latencyMs,
                    isVip = it.isVip,
                    securityAssessment = it.securityAssessment,
                    riskLevel = it.riskLevel,
                )
            }
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
        clientDb.clearAllHistory()
        state = state.copy(
            connectionHistory = emptyList(),
            sqliteHistory = emptyList(),
            sqliteHistoryTotal = 0,
            info = tr("تم مسح سجل الاتصالات", "Connection history cleared"),
        )
    }

    /** يعيد توليد الملصقات المعتمدة على اللغة («آخر تحديث» وعناوين VIP) عند التبديل الحي للغة. */
    fun refreshLanguageLabels() {
        AppI18n.initFromPrefs(getApplication())
        val updatedLbl = UiMessages.formatLastUpdated(state.meta.generatedAt, prefs.lastRefreshWallMs)
        val rebuilt = buildServerList(state.configs, state.results, state.sortMode)
        state = state.copy(
            lastUpdatedLabel = updatedLbl,
            servers = rebuilt,
            info = null,
            error = null,
        )
    }

    fun toggleFavorite(cfg: String) {
        val clean = Converters.cleanUri(cfg)
        val sid = Converters.stableServerId(clean)
        val existingFav = clientDb.isFavorite(sid)
        val next = prefs.favorites.toMutableSet()
        if (existingFav || clean in next) {
            next.remove(clean)
            next.remove(cfg)
            clientDb.removeFavorite(sid)
        } else {
            next.add(clean)
            val srv = state.servers.firstOrNull { Converters.cleanUri(it.cfg) == clean }
            clientDb.upsertFavorite(
                cfgOrServerId = clean,
                defaultLabel = srv?.name.orEmpty(),
                protocol = srv?.proto ?: Converters.protocolBadge(clean),
                maskedEndpoint = Converters.maskedEndpointLabel(clean),
                country = srv?.country.orEmpty(),
            )
        }
        prefs.favorites = next
        val rebuilt = buildServerList(state.configs, state.results, state.sortMode)
        val sel = resolveSelected(state.selectedCfg, rebuilt)
        state = state.copy(
            servers = rebuilt,
            selectedCfg = sel,
            favoritesList = clientDb.listFavorites(state.favoriteGroupFilter, state.favoriteSortOrder),
            favoriteGroups = clientDb.listFavoriteGroups(),
        )
    }

    // ─────────────────── v3.3 الذكاء التاريخي والاختيار الذكي والمفضّلة ───────────────────

    private fun computeSmartDecisionFor(items: List<ServerItem>): SmartSelectionDecision {
        val telMap = clientDb.getAllServerTelemetryMap()
        val vpnSt = VpnStateManager.status.value
        val problematicIds = vpnSt.droppedConfigs.map { Converters.stableServerId(it) }.toHashSet()
        val weights = SmartSelectionWeights.fromJsonOrDefault(prefs.smartWeightsJson)
        val inputs = items.map { srv ->
            val clean = Converters.cleanUri(srv.cfg)
            SmartServerCandidateInput(
                cfg = srv.cfg,
                label = srv.name,
                country = srv.country,
                isVip = srv.isVip,
                available = true,
                localLatencyMs = srv.latencyMs.coerceAtLeast(0L),
                localJitterMs = srv.jitterMs,
                localDownloadKbps = srv.speedKbps,
                locallyTested = srv.locallyTested,
                localFailed = srv.localFailed,
                lastTestedAtMs = srv.lastTestedAtMs,
                securityAssessment = srv.securityAssessment,
                riskLevel = srv.riskLevel,
                cloudHint = serverHints[clean],
                localTelemetry = telMap[srv.serverId],
            )
        }
        return SmartServerSelector.selectBestAndFallback(
            candidates = inputs,
            weights = weights,
            preferredCountry = prefs.preferredCountry,
            networkType = vpnSt.underlyingNetwork,
            isMeteredNetwork = vpnSt.isMeteredNetwork,
            recentlyProblematicIds = problematicIds,
        )
    }

    fun refreshPersistenceSnapshotAsync() {
        viewModelScope.launch {
            val sinceMs = if (state.historyDateDays > 0) {
                System.currentTimeMillis() - state.historyDateDays.toLong() * 86_400_000L
            } else 0L
            val hist = withContext(Dispatchers.IO) {
                clientDb.querySessionHistory(
                    serverQuery = state.historySearchQuery,
                    sinceMs = sinceMs,
                    sort = state.historySortOrder,
                    limit = state.historyPageLimit,
                )
            }
            val total = withContext(Dispatchers.IO) {
                clientDb.countSessionHistory(state.historySearchQuery, sinceMs)
            }
            val favs = withContext(Dispatchers.IO) {
                clientDb.listFavorites(state.favoriteGroupFilter, state.favoriteSortOrder)
            }
            val groups = withContext(Dispatchers.IO) { clientDb.listFavoriteGroups() }
            val tel = withContext(Dispatchers.IO) { clientDb.getAllServerTelemetryMap() }
            val prot = withContext(Dispatchers.IO) { clientDb.recentProtectionEvents() }
            state = state.copy(
                sqliteHistory = hist,
                sqliteHistoryTotal = total,
                favoritesList = favs,
                favoriteGroups = groups,
                telemetryById = tel,
                protectionEvents = prot,
                smartDecision = computeSmartDecisionFor(state.servers),
            )
        }
    }

    fun setSmartAutoSelect(enabled: Boolean) {
        prefs.smartAutoSelect = enabled
        val decision = computeSmartDecisionFor(state.servers)
        val sel = if (enabled && !VpnStateManager.status.value.isActive && decision.primary != null) {
            prefs.selectedCfg = decision.primary.cfg
            prefs.selectedLabel = decision.primary.label
            decision.primary.cfg
        } else {
            state.selectedCfg
        }
        state = state.copy(smartAutoSelect = enabled, smartDecision = decision, selectedCfg = sel)
    }

    fun setPreferredCountry(countryCode: String) {
        prefs.preferredCountry = countryCode
        val decision = computeSmartDecisionFor(state.servers)
        state = state.copy(preferredCountry = prefs.preferredCountry, smartDecision = decision)
    }

    fun updateFavoriteDetails(serverId: String, customName: String, groupName: String) {
        clientDb.upsertFavorite(
            cfgOrServerId = serverId,
            customName = customName,
            groupName = groupName,
        )
        val rebuilt = buildServerList(state.configs, state.results, state.sortMode)
        state = state.copy(
            servers = rebuilt,
            favoritesList = clientDb.listFavorites(state.favoriteGroupFilter, state.favoriteSortOrder),
            favoriteGroups = clientDb.listFavoriteGroups(),
            info = tr("تم تحديث السيرفر المفضّل", "Favorite server updated"),
        )
    }

    fun removeFavoriteById(serverId: String) {
        clientDb.removeFavorite(serverId)
        val cleaned = prefs.favorites.filterNot { Converters.stableServerId(it) == serverId }.toSet()
        prefs.favorites = cleaned
        val rebuilt = buildServerList(state.configs, state.results, state.sortMode)
        state = state.copy(
            servers = rebuilt,
            favoritesList = clientDb.listFavorites(state.favoriteGroupFilter, state.favoriteSortOrder),
            favoriteGroups = clientDb.listFavoriteGroups(),
            info = tr("تمت إزالة السيرفر من المفضّلة", "Removed from favorites"),
        )
    }

    fun setFavoriteGroupFilter(group: String) {
        state = state.copy(
            favoriteGroupFilter = group,
            favoritesList = clientDb.listFavorites(group, state.favoriteSortOrder),
        )
    }

    fun setFavoriteSortOrder(order: FavoriteSortOrder) {
        state = state.copy(
            favoriteSortOrder = order,
            favoritesList = clientDb.listFavorites(state.favoriteGroupFilter, order),
        )
    }

    fun setHistorySearchQuery(query: String) {
        state = state.copy(historySearchQuery = query, historyPageLimit = 30)
        refreshPersistenceSnapshotAsync()
    }

    fun setHistoryDateDays(days: Int) {
        state = state.copy(historyDateDays = days, historyPageLimit = 30)
        refreshPersistenceSnapshotAsync()
    }

    fun setHistorySortOrder(order: HistorySortOrder) {
        state = state.copy(historySortOrder = order)
        refreshPersistenceSnapshotAsync()
    }

    fun setHistoryRetentionDays(days: Int) {
        prefs.historyRetentionDays = days
        clientDb.pruneExpiredHistory(prefs.historyRetentionDays)
        state = state.copy(historyRetentionDays = prefs.historyRetentionDays)
        refreshPersistenceSnapshotAsync()
    }

    fun loadMoreHistory() {
        state = state.copy(historyPageLimit = state.historyPageLimit + 30)
        refreshPersistenceSnapshotAsync()
    }

    fun deleteHistoryRecord(id: Long) {
        clientDb.deleteHistoryEntry(id)
        refreshPersistenceSnapshotAsync()
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
            info = tr("تم حذف السيرفر المخصّص", "Custom server removed"),
        )
    }

    fun importConfigsFromText(rawText: String) {
        val trimmed = rawText.trim().take(4_000_000)
        if (trimmed.isBlank()) {
            state = state.copy(
                error = tr(
                    "الحافظة فارغة — انسخ رابط سيرفر أو حزمة اشتراك أولًا",
                    "Clipboard is empty — copy a config URI or subscription bundle first",
                )
            )
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
            state = state.copy(
                error = tr(
                    "لم يُعثر على إعداد اتصال صالح وآمن في النص المدخل",
                    "No valid supported VPN config found in input text",
                )
            )
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
            info = tr(
                "تمت إضافة ${extracted.size} سيرفر تحت اسم bahrain-vpn",
                "Imported ${extracted.size} server(s) to bahrain-vpn",
            ),
        )
    }

    fun setAutoFailover(enabled: Boolean) {
        prefs.autoFailover = enabled
        val mode = prefs.failoverMode
        state = state.copy(autoFailover = enabled, failoverMode = mode)
        VpnStateManager.update { it.copy(failoverMode = mode) }
    }

    fun setFailoverMode(modeKey: String) {
        prefs.failoverMode = modeKey
        val norm = prefs.failoverMode
        state = state.copy(failoverMode = norm, autoFailover = norm != "OFF")
        VpnStateManager.update { it.copy(failoverMode = norm) }
    }

    fun setKillSwitch(enabled: Boolean) {
        prefs.killSwitch = enabled
        state = state.copy(killSwitch = enabled)
        VpnStateManager.update { it.copy(killSwitchActive = enabled) }
    }

    // ── تحديث حزمة المرشّحين المركزية Top-500 مع التحقق من البصمات وتشغيل الفحص السريع الذكي ──
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
            if (res.serverFingerprints.isNotEmpty()) {
                serverFingerprints = res.serverFingerprints
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

            val netProfile = currentNetworkProfile()
            val existingPersonalTop50 = withContext(Dispatchers.IO) {
                clientDb.getPersonalizedRankings(netProfile, LocalPoolTier.TOP_50)
            }
            val shouldAutoQuickScan = sequentialScanner.engineAvailable && newConfigs.isNotEmpty() && (
                refreshSucceededLive || !silent || existingPersonalTop50.isEmpty()
                )

            val targetSortMode = if (shouldAutoQuickScan) {
                prefs.sortMode = ServerSortMode.FASTEST_DOWNLOAD.key
                prefs.rankBySpeed = true
                ServerSortMode.FASTEST_DOWNLOAD.key
            } else {
                state.sortMode
            }

            val rebuilt = withContext(Dispatchers.IO) {
                buildServerList(newConfigs, state.results, targetSortMode, netProfile)
            }
            val countries = computeCountryCounts(rebuilt)
            val sel = resolveSelected(state.selectedCfg, rebuilt)
            val metaObj = if (res.meta.generatedAt != "—") res.meta else state.meta
            val updatedLbl = UiMessages.formatLastUpdated(metaObj.generatedAt, prefs.lastRefreshWallMs)
            val dsVer = if (res.datasetVersion > 0L) res.datasetVersion else state.datasetVersion

            state = state.copy(
                loading = false,
                sortMode = targetSortMode,
                configs = newConfigs,
                servers = rebuilt,
                availableCountries = countries,
                selectedCfg = sel,
                smartDecision = computeSmartDecisionFor(rebuilt),
                meta = metaObj,
                lastUpdatedLabel = updatedLbl,
                allFile = allFile,
                activeNetworkProfile = netProfile,
                datasetVersion = dsVer,
                datasetQualifiedCount = newConfigs.size,
                top50Count = rebuilt.count { it.localPoolTier == LocalPoolTier.TOP_50 },
                backupPoolCount = rebuilt.count { it.localPoolTier == LocalPoolTier.BACKUP_POOL },
                error = if (!silent && !refreshSucceededLive) {
                    UiMessages.sanitizeError(res.error, UiMessages.msgUpdateFailed())
                } else null,
                info = if (!silent) {
                    if (refreshSucceededLive) {
                        val deltaTag = if (res.incrementalApplied) tr(" (تحديث تفاضلي موثّق)", " (verified delta)") else ""
                        tr(
                            "تم تحديث حزمة المرشّحين (${newConfigs.size} سيرفر)$deltaTag — جارٍ الفحص السريع لـ ${netProfile.labelAr}…",
                            "Updated candidate pool (${newConfigs.size} servers)$deltaTag — running Quick Scan on ${netProfile.labelEn}…",
                        )
                    } else if (res.recoveredFromLastValid) {
                        tr(
                            "تمت استعادة آخر حزمة محقّقة محليًا (${newConfigs.size} سيرفر)",
                            "Restored last locally verified pool (${newConfigs.size} servers)",
                        )
                    } else null
                } else state.info,
            )

            // بعد تنزيل حزمة المرشّحين: تشغيل Quick Scan تسلسلي على شبكة المستخدم لبناء أفضل 50 مخصّصة دون فحص كامل الـ 500 بلا داعٍ
            if (shouldAutoQuickScan) {
                runSequentialScanInternal(scanMode = LocalScanMode.QUICK_SCAN, autoAfterRefresh = true)
            }
        }
    }

    /** فحص سريع تسلسلي (القسم 3): يختبر الناجحة مؤخرًا + أفضل 50 الحالية + الاحتياطي عند الحاجة ويتوقف فور الاكتفاء. */
    fun startQuickScan() {
        runSequentialScanInternal(scanMode = LocalScanMode.QUICK_SCAN, autoAfterRefresh = false)
    }

    /** فحص شامل تسلسلي (القسم 4): يقيّم كامل حزمة الـ Top 500 لاكتشاف سيرفرات تتفوق على أفضل 50 الحالية وتحديث الاحتياطي. */
    fun startFullScan() {
        runSequentialScanInternal(scanMode = LocalScanMode.FULL_SCAN, autoAfterRefresh = false)
    }

    // توافق رجعي مع الأزرار والاستدعاءات السابقة
    fun startQuickPingTest() = startQuickScan()
    fun startTest() = startFullScan()

    private fun runSequentialScanInternal(scanMode: LocalScanMode, autoAfterRefresh: Boolean = false) {
        val vipUris = licenseGuard.getAuthorizedVipNodes().map { it.uri }
        val pool = (vipUris + prefs.customConfigs + state.configs).distinct()
        if (pool.isEmpty()) {
            if (!autoAfterRefresh) state = state.copy(error = UiMessages.msgNoServers())
            return
        }
        if (!sequentialScanner.engineAvailable) {
            if (!autoAfterRefresh) state = state.copy(error = UiMessages.msgEngineUnavailable())
            return
        }
        testJob?.cancel()
        val netSnap = netAwareness.refreshNow()
        val scanProfile = ScanNetworkProfile.fromTransportCode(netSnap.transport.code)
        val isMetered = netSnap.isMetered || scanProfile == ScanNetworkProfile.MOBILE_DATA

        state = state.copy(
            testing = true,
            activeScanMode = scanMode,
            activeNetworkProfile = scanProfile,
            error = if (autoAfterRefresh) state.error else null,
            info = if (autoAfterRefresh && state.info != null) state.info else tr(
                "جارٍ ${scanMode.labelAr} بالتسلسل على ${scanProfile.labelAr}…",
                "Running sequential ${scanMode.labelEn} on ${scanProfile.labelEn}…",
            ),
            progress = null,
        )

        testJob = viewModelScope.launch {
            try {
                val basePrevResults = state.results
                val summary = sequentialScanner.executeScan(
                    scanMode = scanMode,
                    allCandidateConfigs = pool,
                    fingerprintsById = serverFingerprints,
                    networkProfile = scanProfile,
                    isMetered = isMetered,
                    timeoutSec = prefs.timeoutSec,
                    dnsServer = prefs.dnsServer,
                    useDoh = prefs.dnsDoh,
                    activeNetworkSupplier = { currentNetworkProfile() },
                    onProgress = { p ->
                        withContext(Dispatchers.Main.immediate) {
                            state = state.copy(progress = p)
                        }
                    },
                    onRankingUpdated = { _, aliveSoFar, failedSoFar ->
                        withContext(Dispatchers.Main.immediate) {
                            failedSoFar.forEach { failedConfigs.add(it) }
                            aliveSoFar.forEach { failedConfigs.remove(Converters.cleanUri(it.cfg)) }
                            val aliveCleanSet = aliveSoFar.map { Converters.cleanUri(it.cfg) }.toHashSet()
                            val untouched = basePrevResults.filter { old ->
                                val c = Converters.cleanUri(old.cfg)
                                c !in aliveCleanSet && c !in failedSoFar
                            }
                            val liveMerged = aliveSoFar + untouched
                            val liveBuilt = withContext(Dispatchers.IO) {
                                buildServerList(state.configs, liveMerged, state.sortMode, scanProfile)
                            }
                            val liveSel = if (!VpnStateManager.status.value.isActive && liveBuilt.any { it.localPoolTier == LocalPoolTier.TOP_50 }) {
                                liveBuilt.first { it.localPoolTier == LocalPoolTier.TOP_50 }.also {
                                    prefs.selectedCfg = it.cfg
                                    prefs.selectedLabel = it.name
                                }.cfg
                            } else {
                                resolveSelected(state.selectedCfg, liveBuilt)
                            }
                            state = state.copy(
                                results = liveMerged,
                                servers = liveBuilt,
                                top50Count = liveBuilt.count { it.localPoolTier == LocalPoolTier.TOP_50 },
                                backupPoolCount = liveBuilt.count { it.localPoolTier == LocalPoolTier.BACKUP_POOL },
                                selectedCfg = liveSel,
                            )
                        }
                    },
                )

                summary.failedCleanUris.forEach { deadCfg ->
                    failedConfigs.add(deadCfg)
                    VpnStateManager.markServerDropped(deadCfg)
                }
                summary.results.forEach { okRes ->
                    val clean = Converters.cleanUri(okRes.cfg)
                    failedConfigs.remove(clean)
                    VpnStateManager.markServerHealthy(clean)
                }

                val freshAliveSet = summary.results.map { Converters.cleanUri(it.cfg) }.toHashSet()
                val untouchedPrev = basePrevResults.filter { old ->
                    val c = Converters.cleanUri(old.cfg)
                    c !in freshAliveSet && c !in summary.failedCleanUris
                }
                val mergedResults = summary.results + untouchedPrev

                val vipProtectedSet = licenseGuard.getAuthorizedVipNodes()
                    .map { Converters.cleanUri(it.uri) }
                    .toHashSet()
                val exportPool = pool.filterNot { Converters.cleanUri(it) in vipProtectedSet }
                val exportTop50Ids = summary.rankingBundle.top50.map { it.serverId }.toHashSet()
                val exportMerged = mergedResults.filter {
                    val clean = Converters.cleanUri(it.cfg)
                    clean !in vipProtectedSet && (exportTop50Ids.isEmpty() || Converters.stableServerId(clean) in exportTop50Ids)
                }

                val r = buildRepo()
                val allFile = withContext(Dispatchers.IO) {
                    runCatching { r.writeAll(exportPool) }.getOrNull()
                }
                val bestPair = if (exportMerged.isNotEmpty()) {
                    withContext(Dispatchers.IO) {
                        runCatching {
                            r.writeBest(
                                exportMerged.map { ResultLine(it.cfg, it.latencyMs, it.speedKbps, it.testedAtMs) },
                                minOf(prefs.bestN, PersonalizedTop50Ranker.PERSONALIZED_TOP_LIMIT),
                            )
                        }.getOrNull()
                    }
                } else null

                val rebuilt = withContext(Dispatchers.IO) {
                    buildServerList(state.configs, mergedResults, state.sortMode, scanProfile)
                }
                val countries = computeCountryCounts(rebuilt)
                val autoPicked = if (!VpnStateManager.status.value.isActive && rebuilt.any { it.localPoolTier == LocalPoolTier.TOP_50 }) {
                    rebuilt.first { it.localPoolTier == LocalPoolTier.TOP_50 }.also {
                        prefs.selectedCfg = it.cfg
                        prefs.selectedLabel = it.name
                    }.cfg
                } else {
                    resolveSelected(state.selectedCfg, rebuilt)
                }

                val top50Cnt = rebuilt.count { it.localPoolTier == LocalPoolTier.TOP_50 }
                val bakCnt = rebuilt.count { it.localPoolTier == LocalPoolTier.BACKUP_POOL }
                val topItem = rebuilt.firstOrNull { it.localPoolTier == LocalPoolTier.TOP_50 } ?: rebuilt.firstOrNull()
                state = state.copy(
                    testing = false,
                    activeScanMode = null,
                    results = mergedResults,
                    servers = rebuilt,
                    availableCountries = countries,
                    selectedCfg = autoPicked,
                    smartDecision = computeSmartDecisionFor(rebuilt),
                    telemetryById = clientDb.getAllServerTelemetryMap(),
                    top50Count = top50Cnt,
                    backupPoolCount = bakCnt,
                    progress = null,
                    allFile = allFile ?: state.allFile,
                    bestFile = bestPair?.first ?: state.bestFile,
                    subFile = bestPair?.second ?: state.subFile,
                    info = if (top50Cnt > 0 && topItem != null) {
                        val earlyTxt = if (summary.stoppedEarly) tr(" (توقف ذكي بعد الاكتفاء)", " (smart early stop)") else ""
                        tr(
                            "أفضل $top50Cnt سيرفرًا مخصّصة لـ ${scanProfile.labelAr}$earlyTxt • الاحتياطي: $bakCnt • المتصدر ${topItem.name} (${topItem.latencyMs} ms)",
                            "Top $top50Cnt personalized for ${scanProfile.labelEn}$earlyTxt • Backup: $bakCnt • Best: ${topItem.name} (${topItem.latencyMs} ms)",
                        )
                    } else null,
                    error = if (summary.results.isEmpty() && top50Cnt == 0) {
                        tr(
                            "لم يتأهل أي سيرفر على ${scanProfile.labelAr} حاليًا — جرّب الفحص الشامل أو المحاولة لاحقًا",
                            "No server qualified on ${scanProfile.labelEn} right now — try Full Scan or retry shortly",
                        )
                    } else null,
                )
            } catch (_: CancellationException) {
                state = state.copy(testing = false, activeScanMode = null, progress = null, info = tr("تم إيقاف الفحص", "Scan stopped"))
            } catch (e: Exception) {
                AppDiag.w("AppViewModel", "sequential scan failed", e)
                state = state.copy(
                    testing = false,
                    activeScanMode = null,
                    progress = null,
                    error = UiMessages.msgTestFailed(),
                )
            }
        }
    }

    fun pingSingleServer(item: ServerItem) {
        if (state.pingingSingleCfg != null) return
        val netProfile = currentNetworkProfile()
        state = state.copy(pingingSingleCfg = item.cfg, error = null, info = null)
        viewModelScope.launch {
            val cleanedCfg = Converters.cleanUri(item.cfg)
            val sid = Converters.stableServerId(cleanedCfg)
            val fp = serverFingerprints[sid] ?: Converters.configFingerprint(cleanedCfg)
            val vipUris = licenseGuard.getAuthorizedVipNodes().map { it.uri }
            val allPool = (vipUris + prefs.customConfigs + state.configs).distinct()

            val res = tester.testSingle(
                cfg = item.cfg,
                timeoutSec = prefs.timeoutSec,
                measureSpeed = true,
                dnsServer = prefs.dnsServer,
                useDoh = prefs.dnsDoh,
            )
            val ok = res.ok && res.latencyMs > 0L
            withContext(Dispatchers.IO) {
                clientDb.recordNetworkScanMeasurement(
                    cfgOrServerId = cleanedCfg,
                    configFingerprint = fp,
                    networkProfile = netProfile,
                    scanMode = "SINGLE_CHECK",
                    success = ok,
                    establishMs = res.establishMs.takeIf { it > 0L } ?: res.latencyMs,
                    latencyMs = res.latencyMs,
                    jitterMs = res.jitterMs,
                    packetLossPct = if (ok) res.packetLossPct else 100.0,
                    throughputKbps = res.speedKbps,
                    stabilityScore = if (ok) 85.0 else 0.0,
                    failureReason = if (ok) "" else res.error,
                )
                val stats = clientDb.getNetworkStatsMap(netProfile)
                val bundle = PersonalizedTop50Ranker.computeRankings(allPool, serverFingerprints, stats, netProfile)
                clientDb.savePersonalizedNetworkRankings(netProfile, "SINGLE_CHECK", bundle.allQualifiedEntries, recordHistorySnapshot = true)
            }

            if (ok) {
                failedConfigs.remove(cleanedCfg)
                VpnStateManager.markServerHealthy(cleanedCfg)
                val updatedResults = buildList {
                    add(res)
                    state.results.forEach { if (Converters.cleanUri(it.cfg) != cleanedCfg) add(it) }
                }
                val rebuilt = withContext(Dispatchers.IO) {
                    buildServerList(state.configs, updatedResults, state.sortMode, netProfile)
                }
                val sel = resolveSelected(state.selectedCfg, rebuilt)
                val newItem = rebuilt.firstOrNull { it.cfg == cleanedCfg }
                val speedSummary = if (res.speedKbps >= 1024.0) {
                    String.format(Locale.US, tr(" • سرعة جهازك %.2f MB/s", " • Speed %.2f MB/s"), res.speedKbps / 1024.0)
                } else if (res.speedKbps > 0.0) {
                    tr(" • سرعة جهازك ${res.speedKbps.toInt()} KB/s", " • Speed ${res.speedKbps.toInt()} KB/s")
                } else ""
                state = state.copy(
                    pingingSingleCfg = null,
                    results = updatedResults,
                    servers = rebuilt,
                    top50Count = rebuilt.count { it.localPoolTier == LocalPoolTier.TOP_50 },
                    backupPoolCount = rebuilt.count { it.localPoolTier == LocalPoolTier.BACKUP_POOL },
                    selectedCfg = sel,
                    info = "${newItem?.name ?: item.name} (${netProfile.displayLabel}): ${res.latencyMs} ms$speedSummary",
                )
            } else {
                AppDiag.d("AppViewModel", "single server check failed code=${res.error}")
                failedConfigs.add(cleanedCfg)
                VpnStateManager.markServerDropped(cleanedCfg)
                val updatedResults = state.results.filterNot { Converters.cleanUri(it.cfg) == cleanedCfg }
                val rebuilt = withContext(Dispatchers.IO) {
                    buildServerList(state.configs, updatedResults, state.sortMode, netProfile)
                }
                val sel = resolveSelected(state.selectedCfg, rebuilt)
                state = state.copy(
                    pingingSingleCfg = null,
                    results = updatedResults,
                    servers = rebuilt,
                    top50Count = rebuilt.count { it.localPoolTier == LocalPoolTier.TOP_50 },
                    backupPoolCount = rebuilt.count { it.localPoolTier == LocalPoolTier.BACKUP_POOL },
                    selectedCfg = sel,
                    error = "${item.name}: ${UiMessages.MSG_SERVER_UNREACHABLE}",
                )
            }
        }
    }

    fun cancelTest() {
        testJob?.cancel()
        state = state.copy(testing = false, activeScanMode = null, progress = null, info = tr("تم إيقاف الفحص", "Scan stopped"))
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
        state = state.copy(
            tunnelNeedsReload = false,
            info = tr("تم تحديث قواعد التطبيقات في النفق النشط", "Updated split-tunnel app rules on active VPN"),
        )
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
        killSwitch: Boolean = prefs.killSwitch,
        failoverMode: String = prefs.failoverMode,
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
        prefs.killSwitch = killSwitch
        prefs.failoverMode = if (!autoFailover) "OFF" else if (failoverMode == "OFF") "SMART" else failoverMode
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
            info = tr("تم حفظ الإعدادات بنجاح", "Settings saved and applied"),
            sortMode = normalizedSort.key,
            servers = rebuilt,
            selectedCfg = sel,
            autoFailover = prefs.autoFailover,
            failoverMode = prefs.failoverMode,
            killSwitch = prefs.killSwitch,
        )
    }

    // ── نافذة الإعلانات المتناوبة (5 صور تتغير مع كل فتح) ──
    fun triggerNextPromoBanner() {
        if (state.activePromo != null) return
        promoJob?.cancel()
        promoJob = viewModelScope.launch {
            val repo = buildRepo()
            val next = withContext(Dispatchers.IO) {
                runCatching { repo.selectNextPromoBanner(prefs) }.getOrNull()
            }
            if (next != null) {
                state = state.copy(activePromo = next)
            }
            withContext(Dispatchers.IO) {
                runCatching { repo.syncAllPromoAssets() }
            }
        }
    }

    fun dismissPromo() {
        state = state.copy(activePromo = null)
    }

    // ── وظائف ULTIMATE VPN ENTERPRISE (حساب، سرعة، تشخيص، صحة، تحديثات) ──
    fun refreshEnterpriseState() {
        val acct = licenseGuard.currentState()
        val upd = AppUpdateManager.evaluateAvailableUpdate(getApplication(), licenseGuard.getVerifiedAppUpdates())
        val rebuilt = buildServerList(state.configs, state.results, state.sortMode)
        val countries = computeCountryCounts(rebuilt)
        val sel = resolveSelected(state.selectedCfg, rebuilt)
        state = state.copy(
            accountState = acct,
            availableUpdate = upd,
            servers = rebuilt,
            availableCountries = countries,
            selectedCfg = sel,
            appHealth = AppHealthMonitor.snapshot(getApplication()),
        )
        if (!acct.canConnectVpn && VpnStateManager.status.value.isActive) {
            BahrainVpnService.stopVpn(getApplication())
        }
    }

    fun syncEnterpriseBundle() {
        viewModelScope.launch {
            val raw = withContext(Dispatchers.IO) {
                runCatching { buildRepo().fetchEnterpriseBundleRaw() }.getOrNull()
            }
            if (!raw.isNullOrBlank()) {
                withContext(Dispatchers.IO) { licenseGuard.applySignedBundleRaw(raw) }
            }
            refreshEnterpriseState()
        }
    }

    fun loginEnterpriseAccount(username: String, password: String, rememberMe: Boolean) {
        if (state.authLoading) return
        state = state.copy(authLoading = true, authError = null)
        viewModelScope.launch {
            val raw = withContext(Dispatchers.IO) {
                runCatching { buildRepo().fetchEnterpriseBundleRaw() }.getOrNull()
            }
            if (!raw.isNullOrBlank()) {
                withContext(Dispatchers.IO) { licenseGuard.applySignedBundleRaw(raw) }
            }
            val result = withContext(Dispatchers.IO) {
                licenseGuard.loginWithBundle(username, password, rememberMe)
            }
            result.fold(
                onSuccess = { acct ->
                    val rebuilt = buildServerList(state.configs, state.results, state.sortMode)
                    val countries = computeCountryCounts(rebuilt)
                    val sel = resolveSelected(state.selectedCfg, rebuilt)
                    val vipMsg = if (acct.vipNodesUnlocked > 0) {
                        tr(" • تم فتح ${acct.vipNodesUnlocked} عقدة VIP خاصة", " • Unlocked ${acct.vipNodesUnlocked} VIP node(s)")
                    } else ""
                    state = state.copy(
                        authLoading = false,
                        authError = null,
                        accountState = acct,
                        servers = rebuilt,
                        availableCountries = countries,
                        selectedCfg = sel,
                        info = tr("تم تسجيل الدخول بنجاح (${acct.username})$vipMsg", "Signed in as ${acct.username}$vipMsg"),
                    )
                },
                onFailure = { err ->
                    state = state.copy(
                        authLoading = false,
                        authError = err.message ?: tr("تعذّر تسجيل الدخول", "Sign-in failed"),
                        accountState = licenseGuard.currentState(),
                    )
                },
            )
        }
    }

    fun logoutEnterpriseAccount() {
        licenseGuard.logout("USER_LOGOUT")
        val nextAcct = licenseGuard.currentState()
        if (VpnStateManager.status.value.isActive && (nextAcct.authRequired || state.selectedServer?.isVip == true)) {
            BahrainVpnService.stopVpn(getApplication())
        }
        val rebuilt = buildServerList(state.configs, state.results, state.sortMode)
        val countries = computeCountryCounts(rebuilt)
        val sel = resolveSelected(state.selectedCfg, rebuilt)
        state = state.copy(
            accountState = nextAcct,
            servers = rebuilt,
            availableCountries = countries,
            selectedCfg = sel,
            info = tr("تم تسجيل الخروج وإغلاق عقد VIP الخاصة", "Signed out and locked private VIP nodes"),
        )
    }

    fun runFullClientSpeedTest() {
        if (state.speedTestRunning) return
        val vpnSt = VpnStateManager.status.value
        val viaVpn = vpnSt.isTunnelVerified
        val label = if (viaVpn) vpnSt.activeLabel else tr("الشبكة المباشرة", "Direct Network")
        val bw = state.accountState.bandwidth
        state = state.copy(
            speedTestRunning = true,
            speedTestStage = tr("جارٍ تهيئة القياس…", "Initializing speed test…"),
            liveSpeedGaugeMbps = 0.0,
            liveSpeedCurve = emptyList(),
        )
        viewModelScope.launch {
            val rec = diagnosticsEngine.runRealSpeedTest(
                viaVpnTunnel = viaVpn,
                serverLabel = label,
                bandwidthPolicy = bw,
                onStageUpdate = { stg, liveMbps, samples ->
                    withContext(Dispatchers.Main.immediate) {
                        state = state.copy(
                            speedTestStage = stg,
                            liveSpeedGaugeMbps = liveMbps,
                            liveSpeedCurve = samples,
                        )
                    }
                },
            )
            state = state.copy(
                speedTestRunning = false,
                speedTestStage = "",
                latestSpeedRecord = rec,
                speedHistory = diagnosticsEngine.loadSpeedHistory(),
                info = String.format(
                    Locale.US,
                    tr("اكتمل القياس: ↓ %.2f Mbps • ↑ %.2f Mbps", "Speed test complete: ↓ %.2f Mbps • ↑ %.2f Mbps"),
                    rec.downloadMbps,
                    rec.uploadMbps,
                ),
            )
        }
    }

    fun runNetworkDiagnosticsSuite() {
        if (state.netDiagRunning) return
        val vpnSt = VpnStateManager.status.value
        val viaVpn = vpnSt.isTunnelVerified
        state = state.copy(netDiagRunning = true)
        viewModelScope.launch {
            val report = diagnosticsEngine.runNetworkDiagnostics(
                viaVpnTunnel = viaVpn,
                configuredDns = prefs.dnsServer,
                killSwitchEnabled = prefs.killSwitch,
                osLockdownActive = vpnSt.osLockdownActive,
                splitIncludeOnly = prefs.splitIncludeOnly,
                splitApps = prefs.splitApps,
            )
            state = state.copy(
                netDiagRunning = false,
                netDiagReport = report,
                appHealth = AppHealthMonitor.snapshot(getApplication()),
            )
        }
    }

    fun probeExplicitTestUrl(url: String) {
        val viaVpn = VpnStateManager.status.value.isTunnelVerified
        viewModelScope.launch {
            val res = diagnosticsEngine.probeExplicitUrl(url, viaVpn)
            state = state.copy(urlProbeResult = res)
        }
    }

    fun setDiagnosticConsent(enabled: Boolean) {
        AppHealthMonitor.setDiagnosticConsent(getApplication(), enabled)
        state = state.copy(appHealth = AppHealthMonitor.snapshot(getApplication()))
    }

    fun buildRedactedDiagnosticReportJson(): String {
        val h = AppHealthMonitor.snapshot(getApplication())
        val o = org.json.JSONObject()
            .put("app_version", AppUpdateManager.currentVersionName(getApplication()))
            .put("startup_ms", h.startupTimeMs)
            .put("memory_mb", h.memoryUsedMb)
            .put("crash_count", h.crashCount)
            .put("tunnel_errors", h.tunnelErrorCount)
            .put("dns_errors", h.dnsErrorCount)
            .put("device_install_id", state.accountState.deviceInstallId)
        state.latestSpeedRecord?.let { spd ->
            o.put("last_dl_mbps", spd.downloadMbps)
                .put("last_ul_mbps", spd.uploadMbps)
                .put("last_ping_ms", spd.pingMs)
        }
        return o.toString(2)
    }

    fun downloadAndInstallSignedUpdate() {
        val upd = state.availableUpdate ?: return
        if (state.updatingApk) return
        state = state.copy(updatingApk = true, error = null)
        val res = AppUpdateManager.openVerifiedUpdateInSystemBrowser(getApplication(), upd)
        res.fold(
            onSuccess = {
                val shaHint = if (upd.apkSha256.length == 64) tr(" (تم نسخ بصمة SHA-256 للتحقق)", " (SHA-256 copied)") else ""
                state = state.copy(
                    updatingApk = false,
                    info = tr(
                        "تم فتح رابط التحديث الرسمي الآمن لحزمة ${upd.selectedAbi} في المتصفح$shaHint",
                        "Opened official HTTPS download for ${upd.selectedAbi} in browser$shaHint",
                    ),
                )
            },
            onFailure = { err ->
                state = state.copy(
                    updatingApk = false,
                    error = err.message ?: tr("تعذّر فتح رابط التحديث الرسمي", "Could not open official update URL"),
                )
            },
        )
    }

    fun evaluateSecurityReport(vpnStatus: VpnStatus): SecurityStatusReport {
        val activeClean = vpnStatus.activeCfg?.let { Converters.cleanUri(it) }
        val isVip = activeClean != null && licenseGuard.getAuthorizedVipNodes().any {
            Converters.cleanUri(it.uri) == activeClean
        }
        val netSnap = NetworkAwarenessMonitor(getApplication()).readCurrentPhysicalNetwork()
        val diagLeak = state.netDiagReport?.ipLeakDetected == true
        return ConnectionSecurityClassifier.classify(
            vpnStatus = vpnStatus,
            activeCfg = activeClean,
            isVipAttested = isVip,
            networkSnapshot = netSnap,
            configuredDns = prefs.dnsServer,
            useDoh = prefs.dnsDoh,
            enableIpv6 = prefs.enableIpv6,
            tunCapturesIpv6Route = true,
            dnsBypassObserved = diagLeak,
            ipv6BypassObserved = false,
        )
    }

    override fun onCleared() {
        runCatching { netAwareness.stop() }
        super.onCleared()
    }

    fun settings() = prefs
}
