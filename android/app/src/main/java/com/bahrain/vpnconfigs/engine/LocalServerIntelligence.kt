// =====================================================================
// LocalServerIntelligence.kt — محرك الذكاء المحلي المخصّص فائق السرعة على أندرويد (v2):
//   • السلطة الوحيدة والحصرية لاختيار أفضل 100 سيرفر مخصّص (Personalized Top 100)
//     ومجمّع الاحتياطي المؤهّل (Backup Pool) بناءً على الفحص الفعلي على شبكة المستخدم.
//   • فصل صارم ومستقل تمامًا بين ترتيب وسجل شبكة Wi-Fi وبين بيانات الجوال (Mobile Data)
//     مع صلاحية قياس (TTL) متوافقة مع دورة الـ 3 ساعات (3 HOURS).
//   • المعادلة المركزية الموحّدة (45% سرعة تنزيل فعلية / 30% ثبات واستقرار / 25% بنق وتذبذب)
//     مع صفر نقاط مجانية لغير المقاس واستبعاد أمني مسبق صارم لـ allowInsecure=1.
//   • محرّك الفحص الدفعي المتوازي (Batch Multi-Port SingBox) على الجهاز الحقيقي:
//     يختبر كامل حزمة الـ 500 كونفيق خلال ثوانٍ معدودة مع حارس ذكي ضد انقطاع إنترنت الهاتف.
// =====================================================================
package com.bahrain.vpnconfigs.engine

import android.content.Context
import com.bahrain.vpnconfigs.data.ClientDatabase
import com.bahrain.vpnconfigs.data.LocalPoolTier
import com.bahrain.vpnconfigs.data.NetworkServerProfileStats
import com.bahrain.vpnconfigs.data.PersonalizedRankEntry
import com.bahrain.vpnconfigs.data.ScanNetworkProfile
import com.bahrain.vpnconfigs.util.tr
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.net.ServerSocket
import kotlin.coroutines.coroutineContext
import kotlin.math.ln
import kotlin.math.max
import kotlin.math.min

enum class LocalScanMode(val code: String, val labelAr: String, val labelEn: String) {
    QUICK_SCAN("QUICK_SCAN", "فحص سريع (أفضل 100)", "Quick Scan (Top 100)"),
    FULL_SCAN("FULL_SCAN", "فحص شامل سريع (500 → أفضل 100)", "Fast Scan (500 → Top 100)");

    val displayLabel: String
        get() = tr(labelAr, labelEn)
}

data class TunnelProbeRequest(
    val cfg: String,
    val networkProfile: ScanNetworkProfile,
    val isMetered: Boolean,
    val scanMode: LocalScanMode,
    val measureThroughput: Boolean,
    val throughputBudgetBytes: Long,
    val probeSamples: Int,
    val timeoutSec: Int,
    val dnsServer: String,
    val useDoh: Boolean,
)

fun interface TunnelProbeExecutor {
    fun executeSequential(req: TunnelProbeRequest): TestResult
}

data class PersonalizedRankingBundle(
    val networkProfile: ScanNetworkProfile,
    val top50: List<PersonalizedRankEntry>,
    val backupPool: List<PersonalizedRankEntry>,
    val entriesById: Map<String, PersonalizedRankEntry>,
) {
    /** أفضل 100 سيرفر مخصّص للشبكة الحالية (مع الإبقاء على اسم الحقل top50 للتوافق الداخلي). */
    val top100: List<PersonalizedRankEntry>
        get() = top50

    val allQualifiedEntries: List<PersonalizedRankEntry>
        get() = top50 + backupPool
}

data class ScanExecutionSummary(
    val scanMode: LocalScanMode,
    val networkProfile: ScanNetworkProfile,
    val plannedCount: Int,
    val testedCount: Int,
    val qualifiedAliveCount: Int,
    val stoppedEarly: Boolean,
    val rankingBundle: PersonalizedRankingBundle,
    val results: List<TestResult>,
    val failedCleanUris: Set<String>,
    val offlineGuardTriggered: Boolean = false,
)

typealias PersonalizedTop100Ranker = PersonalizedTop50Ranker

object PersonalizedTop50Ranker {
    const val PERSONALIZED_TOP_LIMIT = 100
    const val QUALIFIED_BACKUP_LIMIT = 100
    const val STALE_WIFI_MS = CentralScoringWeights.FRESHNESS_TTL_MS   // 3 hours
    const val STALE_MOBILE_MS = CentralScoringWeights.FRESHNESS_TTL_MS // 3 hours
    const val OFFLINE_GUARD_MIN_TESTED = 15

    fun staleThresholdMs(profile: ScanNetworkProfile): Long =
        if (profile == ScanNetworkProfile.MOBILE_DATA) STALE_MOBILE_MS else STALE_WIFI_MS

    fun isMeasurementStale(
        stats: NetworkServerProfileStats?,
        expectedFingerprint: String,
        profile: ScanNetworkProfile,
        nowMs: Long = System.currentTimeMillis(),
    ): Boolean {
        if (stats == null || stats.lastScanAtMs <= 0L) return true
        if (expectedFingerprint.isNotBlank() && stats.configFingerprint.isNotBlank() &&
            stats.configFingerprint != expectedFingerprint
        ) {
            return true
        }
        return (nowMs - stats.lastScanAtMs) > staleThresholdMs(profile)
    }

    /**
     * يحسب الدرجة المخصّصة (0..100) حصريًا من القياسات الحقيقية على شبكة المستخدم (WIFI أو MOBILE_DATA)
     * وفق المعادلة الموحّدة الصارمة:
     *   • سرعة التنزيل الفعلية (45%) — 0.0 إذا لم تُقس السرعة (صفر نقاط مجانية!).
     *   • ثبات واستقرار الاتصال (30%) — الاستقرار وانعدام فقدان الحزم.
     *   • البنق والتذبذب وزمن التأسيس (25%).
     */
    fun calculatePersonalizedScore(
        stats: NetworkServerProfileStats,
        currentFingerprint: String = "",
        nowMs: Long = System.currentTimeMillis(),
    ): Double {
        if (!stats.isQualifiedLocally) return 0.0

        // 1) Real Download Throughput [0..100] -> 45% weight (strictly 0.0 when unmeasured!)
        val effTpKbps = if (stats.latestThroughputKbps > 0.0) {
            0.75 * stats.latestThroughputKbps + 0.25 * max(stats.bestThroughputKbps, stats.latestThroughputKbps)
        } else if (stats.bestThroughputKbps > 0.0) {
            stats.bestThroughputKbps * 0.70
        } else {
            0.0
        }
        val throughputNorm = if (effTpKbps <= 0.0) {
            0.0
        } else {
            ((ln(1.0 + effTpKbps / 128.0) / ln(1.0 + 10_240.0 / 128.0)) * 100.0).coerceIn(5.0, 100.0)
        }

        // 2) Connection Stability [0..100] -> 30% weight
        val stabilityNorm = stats.stabilityScore.coerceIn(0.0, 100.0)
        val packetLossNorm = (100.0 - stats.ewmaPacketLossPct * 2.0).coerceIn(0.0, 100.0)
        val stabilityComposite = (0.65 * stabilityNorm + 0.35 * packetLossNorm).coerceIn(0.0, 100.0)

        // 3) Ping & Jitter [0..100] -> 25% weight
        val blendedLat = if (stats.ewmaLatencyMs > 0.0) {
            0.65 * stats.latestLatencyMs.toDouble() + 0.35 * stats.ewmaLatencyMs
        } else {
            stats.latestLatencyMs.toDouble()
        }
        val latencyNorm = when {
            blendedLat <= 45.0 -> 100.0
            blendedLat >= 1800.0 -> 0.0
            else -> ((1800.0 - blendedLat) / (1800.0 - 45.0)) * 100.0
        }
        val jitterNorm = when {
            stats.ewmaJitterMs <= 8.0 -> 100.0
            stats.ewmaJitterMs >= 250.0 -> 0.0
            else -> ((250.0 - stats.ewmaJitterMs) / (250.0 - 8.0)) * 100.0
        }
        val establishNorm = when {
            stats.latestEstablishMs <= 0L -> 50.0
            stats.latestEstablishMs <= 350L -> 100.0
            stats.latestEstablishMs >= 4500L -> 0.0
            else -> ((4500.0 - stats.latestEstablishMs.toDouble()) / (4500.0 - 350.0)) * 100.0
        }
        val pingJitterComposite = (0.65 * latencyNorm + 0.25 * jitterNorm + 0.10 * establishNorm).coerceIn(0.0, 100.0)

        var rawScore =
            CentralScoringWeights.THROUGHPUT_WEIGHT * throughputNorm +
                CentralScoringWeights.STABILITY_WEIGHT * stabilityComposite +
                CentralScoringWeights.PING_JITTER_WEIGHT * pingJitterComposite

        // 3-hour TTL freshness decay
        val ageMs = (nowMs - stats.lastScanAtMs).coerceAtLeast(0L)
        val staleWindow = staleThresholdMs(stats.networkProfile)
        if (ageMs > staleWindow) {
            val extraHours = ((ageMs - staleWindow) / 3_600_000.0).coerceAtMost(24.0)
            rawScore *= (1.0 - (extraHours / 24.0) * 0.18)
        }
        if (currentFingerprint.isNotBlank() && stats.configFingerprint.isNotBlank() &&
            stats.configFingerprint != currentFingerprint
        ) {
            rawScore *= 0.85
        }
        if (stats.consecutiveFailures > 0) {
            rawScore -= stats.consecutiveFailures * 14.0
        }

        return (kotlin.math.round(rawScore.coerceIn(0.0, 100.0) * 100.0) / 100.0)
    }

    /**
     * يبني قائمة أفضل 100 سيرفر مخصّصة + مجمّع الاحتياطي المؤهّل لشبكة محددة (WIFI أو MOBILE_DATA)
     * مع استبعاد أمني صارم لـ allowInsecure=1 والعقد المحجورة قبل الترتيب.
     */
    fun computeRankings(
        candidateConfigs: List<String>,
        fingerprintsById: Map<String, String>,
        statsById: Map<String, NetworkServerProfileStats>,
        profile: ScanNetworkProfile,
        nowMs: Long = System.currentTimeMillis(),
    ): PersonalizedRankingBundle {
        data class ScoredCandidate(
            val serverId: String,
            val fingerprint: String,
            val score: Double,
            val throughputKbps: Double,
            val stability: Double,
            val latencyMs: Long,
            val jitterMs: Double,
        )

        val seen = HashSet<String>()
        val qualified = ArrayList<ScoredCandidate>()

        for (rawCfg in candidateConfigs) {
            val clean = Converters.cleanUri(rawCfg)
            if (!clean.contains("://") || !Converters.isSupported(clean)) continue
            // Hard Security Pre-Filter before Personalized Top 100 ranking
            if (!Tester.passesHardSecurityPreFilter(clean)) continue
            val sid = Converters.stableServerId(clean)
            if (sid.isBlank() || !seen.add(sid)) continue
            val st = statsById[sid] ?: continue
            if (st.networkProfile != profile || !st.isQualifiedLocally) continue
            val fp = fingerprintsById[sid] ?: Converters.configFingerprint(clean)
            val pScore = calculatePersonalizedScore(st, fp, nowMs)
            if (pScore <= 0.0) continue
            val effTp = if (st.latestThroughputKbps > 0.0) st.latestThroughputKbps else st.bestThroughputKbps
            qualified.add(
                ScoredCandidate(
                    serverId = sid,
                    fingerprint = fp,
                    score = pScore,
                    throughputKbps = effTp,
                    stability = st.stabilityScore,
                    latencyMs = st.latestLatencyMs,
                    jitterMs = st.ewmaJitterMs,
                )
            )
        }

        qualified.sortWith(
            compareByDescending<ScoredCandidate> { it.score }
                .thenByDescending { it.throughputKbps }
                .thenByDescending { it.stability }
                .thenBy { if (it.latencyMs > 0L) it.latencyMs else Long.MAX_VALUE }
                .thenBy { it.jitterMs }
                .thenBy { it.serverId }
        )

        val top100 = ArrayList<PersonalizedRankEntry>(min(PERSONALIZED_TOP_LIMIT, qualified.size))
        val backup = ArrayList<PersonalizedRankEntry>(QUALIFIED_BACKUP_LIMIT)
        val byId = LinkedHashMap<String, PersonalizedRankEntry>()

        qualified.take(PERSONALIZED_TOP_LIMIT + QUALIFIED_BACKUP_LIMIT).forEachIndexed { idx, item ->
            val rankPos = idx + 1
            val tier = if (rankPos <= PERSONALIZED_TOP_LIMIT) LocalPoolTier.TOP_50 else LocalPoolTier.BACKUP_POOL
            val entry = PersonalizedRankEntry(
                networkProfile = profile,
                serverId = item.serverId,
                configFingerprint = item.fingerprint,
                poolTier = tier,
                rankPosition = rankPos,
                personalizedScore = item.score,
                stabilityScore = item.stability,
                updatedAtMs = nowMs,
            )
            if (tier == LocalPoolTier.TOP_50) top100.add(entry) else backup.add(entry)
            byId[item.serverId] = entry
        }

        return PersonalizedRankingBundle(
            networkProfile = profile,
            top50 = top100,
            backupPool = backup,
            entriesById = byId,
        )
    }
}

object QuickScanPlanner {
    fun buildOrderedPlan(
        allCandidateConfigs: List<String>,
        currentRankings: List<PersonalizedRankEntry>,
        statsById: Map<String, NetworkServerProfileStats>,
        profile: ScanNetworkProfile,
        isMetered: Boolean,
        maxQuickCandidates: Int = if (profile == ScanNetworkProfile.MOBILE_DATA || isMetered) 65 else 115,
    ): List<String> {
        val cfgById = LinkedHashMap<String, String>()
        for (raw in allCandidateConfigs) {
            val clean = Converters.cleanUri(raw)
            if (!clean.contains("://") || !Converters.isSupported(clean)) continue
            if (!Tester.passesHardSecurityPreFilter(clean)) continue
            val sid = Converters.stableServerId(clean)
            if (sid.isNotBlank() && !cfgById.containsKey(sid)) {
                cfgById[sid] = clean
            }
        }
        if (cfgById.isEmpty()) return emptyList()

        val cap = min(maxQuickCandidates.coerceAtLeast(15), cfgById.size)
        val orderedIds = LinkedHashSet<String>()

        currentRankings
            .filter { r ->
                val st = statsById[r.serverId]
                r.poolTier == LocalPoolTier.TOP_50 &&
                    cfgById.containsKey(r.serverId) &&
                    st != null &&
                    st.networkProfile == profile &&
                    st.lastSuccessfulConnectionMs > 0L &&
                    st.consecutiveFailures == 0
            }
            .sortedBy { it.rankPosition }
            .forEach { r ->
                if (orderedIds.size < cap) orderedIds.add(r.serverId)
            }

        if (orderedIds.size < cap) {
            val recentSuccess = statsById.values
                .filter {
                    it.networkProfile == profile &&
                        it.lastSuccessfulConnectionMs > 0L &&
                        it.consecutiveFailures == 0 &&
                        cfgById.containsKey(it.serverId)
                }
                .sortedWith(
                    compareByDescending<NetworkServerProfileStats> { it.lastSuccessfulConnectionMs }
                        .thenByDescending { it.stabilityScore }
                )
            for (st in recentSuccess) {
                orderedIds.add(st.serverId)
                if (orderedIds.size >= cap) break
            }
        }

        if (orderedIds.size < cap) {
            currentRankings
                .filter { it.poolTier == LocalPoolTier.TOP_50 && cfgById.containsKey(it.serverId) }
                .sortedBy { it.rankPosition }
                .forEach { r ->
                    if (orderedIds.size < cap) orderedIds.add(r.serverId)
                }
        }

        val healthyTopCount = currentRankings.count {
            it.poolTier == LocalPoolTier.TOP_50 &&
                (statsById[it.serverId]?.consecutiveFailures ?: 0) == 0 &&
                cfgById.containsKey(it.serverId)
        }
        if (orderedIds.size < cap && healthyTopCount < PersonalizedTop50Ranker.PERSONALIZED_TOP_LIMIT) {
            currentRankings
                .filter { it.poolTier == LocalPoolTier.BACKUP_POOL && cfgById.containsKey(it.serverId) }
                .sortedBy { it.rankPosition }
                .forEach { r ->
                    if (orderedIds.size < cap) orderedIds.add(r.serverId)
                }
        }

        if (orderedIds.size < cap && healthyTopCount < min(60, cfgById.size)) {
            for (sid in cfgById.keys) {
                val st = statsById[sid]
                if (st != null && st.consecutiveFailures >= 3) continue
                orderedIds.add(sid)
                if (orderedIds.size >= cap) break
            }
        }

        return orderedIds.mapNotNull { cfgById[it] }
    }
}

object FullScanPlanner {
    fun buildOrderedPlan(
        allCandidateConfigs: List<String>,
        fingerprintsById: Map<String, String>,
        statsById: Map<String, NetworkServerProfileStats>,
        profile: ScanNetworkProfile,
        nowMs: Long = System.currentTimeMillis(),
        skipFreshWithinTtl: Boolean = false,
    ): List<String> {
        val staleKnown = ArrayList<String>()
        val undiscovered = ArrayList<String>()
        val freshKnown = ArrayList<String>()
        val seen = HashSet<String>()

        for (raw in allCandidateConfigs) {
            val clean = Converters.cleanUri(raw)
            if (!clean.contains("://") || !Converters.isSupported(clean)) continue
            if (!Tester.passesHardSecurityPreFilter(clean)) continue
            val sid = Converters.stableServerId(clean)
            if (sid.isBlank() || !seen.add(sid)) continue

            val st = statsById[sid]
            val fp = fingerprintsById[sid] ?: Converters.configFingerprint(clean)
            when {
                st == null || st.scanCount == 0 -> undiscovered.add(clean)
                PersonalizedTop50Ranker.isMeasurementStale(st, fp, profile, nowMs) -> staleKnown.add(clean)
                else -> if (!skipFreshWithinTtl) freshKnown.add(clean)
            }
        }
        return staleKnown + undiscovered + freshKnown
    }
}

class SequentialTunnelScanner(
    private val ctx: Context,
    private val clientDb: ClientDatabase = ClientDatabase.getInstance(ctx),
    private val customProbeExecutor: TunnelProbeExecutor? = null,
) {
    companion object {
        private val sequentialScanMutex = Mutex()
        private const val BATCH_SIZE = 45
        private const val STAGE1_PARALLELISM = 28
        private const val STAGE2_PARALLELISM = 6
        const val BACKGROUND_STAGE2_TOP_LIMIT = 15

        private fun pickSingleFreePort(basePort: Int = 22800): Int {
            val loopback = InetAddress.getByName("127.0.0.1")
            for (cand in basePort until (basePort + 400)) {
                val ok = try {
                    ServerSocket(cand, 1, loopback).use { true }
                } catch (_: Exception) {
                    false
                }
                if (ok) return cand
            }
            return basePort
        }
    }

    private val singBox by lazy { SingBox(ctx) }

    val engineAvailable: Boolean
        get() = customProbeExecutor != null || singBox.isAvailable

    private val defaultExecutor = TunnelProbeExecutor { req ->
        val port = pickSingleFreePort()
        singBox.testRealTunnelSequential(
            cfg = req.cfg,
            port = port,
            timeoutSec = req.timeoutSec,
            probeSamples = req.probeSamples,
            measureThroughput = req.measureThroughput,
            throughputBudgetBytes = req.throughputBudgetBytes,
            dnsServer = req.dnsServer,
            useDoh = req.useDoh,
        )
    }

    private suspend fun probeBatchChunkWithFallback(
        chunk: List<String>,
        basePort: Int,
        timeoutMs: Int,
        dnsServer: String,
        useDoh: Boolean,
        onItemDone: suspend (TestResult) -> Unit,
    ): List<TestResult> = coroutineScope {
        if (chunk.isEmpty()) return@coroutineScope emptyList()
        val ports = Tester.allocateFreePorts(chunk.size, basePort = basePort)
        val paired = chunk.mapIndexed { idx, c -> c to ports[idx] }
        val session = runInterruptible(Dispatchers.IO) {
            singBox.startBatchDaemon(paired, dnsServer = dnsServer, useDoh = useDoh, waitMs = 2200L)
        }
        if (session == null) {
            if (chunk.size > 1) {
                val mid = (chunk.size + 1) / 2
                val left = probeBatchChunkWithFallback(chunk.subList(0, mid), basePort, timeoutMs, dnsServer, useDoh, onItemDone)
                val right = probeBatchChunkWithFallback(chunk.subList(mid, chunk.size), basePort + mid + 5, timeoutMs, dnsServer, useDoh, onItemDone)
                return@coroutineScope left + right
            }
            val single = runInterruptible(Dispatchers.IO) {
                singBox.testRealTunnelSequential(
                    cfg = chunk.first(),
                    port = ports.first(),
                    timeoutSec = (timeoutMs / 1000).coerceAtLeast(2),
                    probeSamples = 1,
                    measureThroughput = false,
                    throughputBudgetBytes = 0L,
                    dnsServer = dnsServer,
                    useDoh = useDoh,
                )
            }
            onItemDone(single)
            return@coroutineScope listOf(single)
        }

        val slotByClean = session.slots.associateBy { Converters.cleanUri(it.cfg) }
        val sem = Semaphore(STAGE1_PARALLELISM)
        try {
            chunk.map { rawCfg ->
                async(Dispatchers.IO) {
                    ensureActive()
                    val clean = Converters.cleanUri(rawCfg)
                    val slot = slotByClean[clean]
                    val res = if (slot == null) {
                        TestResult(rawCfg, ok = false, error = "unsupported", packetLossPct = 100.0)
                    } else {
                        sem.withPermit {
                            ensureActive()
                            runInterruptible(Dispatchers.IO) {
                                singBox.probeSlotOnRunningBatch(
                                    slot = slot,
                                    timeoutMs = timeoutMs,
                                    measureThroughput = false,
                                    throughputBudgetBytes = 0L,
                                )
                            }
                        }
                    }
                    onItemDone(res)
                    res
                }
            }.awaitAll()
        } finally {
            singBox.stopBatchDaemon(session)
        }
    }

    /**
     * على الجهاز الفعلي (`customProbeExecutor == null`): يشغّل الفحص الدفعي المتوازي فائق السرعة
     * لكامل حزمة الـ 500 كونفيق خلال ثوانٍ معدودة (المرحلة 1 حياة واستجابة + المرحلة 2 تنزيل حقيقي 600 KB).
     * وفي اختبارات الوحدة المحاكاة (`customProbeExecutor != null`): يحافظ على المنفّذ المخصّص.
     */
    suspend fun executeScan(
        scanMode: LocalScanMode,
        allCandidateConfigs: List<String>,
        fingerprintsById: Map<String, String> = emptyMap(),
        networkProfile: ScanNetworkProfile,
        isMetered: Boolean = (networkProfile == ScanNetworkProfile.MOBILE_DATA),
        timeoutSec: Int = 4,
        dnsServer: String = "1.1.1.1",
        useDoh: Boolean = false,
        isBackgroundRun: Boolean = false,
        skipFreshWithinTtl: Boolean = isBackgroundRun,
        quickStopTargetQualified: Int = if (networkProfile == ScanNetworkProfile.MOBILE_DATA || isMetered) 50 else 100,
        activeNetworkSupplier: (() -> ScanNetworkProfile)? = null,
        onProgress: suspend (TestProgress) -> Unit = {},
        onRankingUpdated: suspend (
            bundle: PersonalizedRankingBundle,
            aliveResults: List<TestResult>,
            failedUris: Set<String>,
        ) -> Unit = { _, _, _ -> },
    ): ScanExecutionSummary = withContext(Dispatchers.IO) {
        if (!engineAvailable) {
            val existing = PersonalizedTop50Ranker.computeRankings(
                allCandidateConfigs,
                fingerprintsById,
                clientDb.getNetworkStatsMap(networkProfile),
                networkProfile,
            )
            return@withContext ScanExecutionSummary(
                scanMode = scanMode,
                networkProfile = networkProfile,
                plannedCount = 0,
                testedCount = 0,
                qualifiedAliveCount = 0,
                stoppedEarly = false,
                rankingBundle = existing,
                results = emptyList(),
                failedCleanUris = emptySet(),
            )
        }

        sequentialScanMutex.withLock {
            val nowStart = System.currentTimeMillis()
            val initialStats = clientDb.getNetworkStatsMap(networkProfile)
            val initialRanks = clientDb.getPersonalizedRankings(networkProfile)

            // Collect insecure/quarantined URIs upfront so the caller can purge them immediately!
            val securityRejectedClean = LinkedHashSet<String>()
            for (raw in allCandidateConfigs) {
                val clean = Converters.cleanUri(raw)
                if (clean.contains("://") && Converters.isSupported(clean) && !Tester.passesHardSecurityPreFilter(clean)) {
                    securityRejectedClean.add(clean)
                }
            }

            val plan = when (scanMode) {
                LocalScanMode.QUICK_SCAN -> QuickScanPlanner.buildOrderedPlan(
                    allCandidateConfigs = allCandidateConfigs,
                    currentRankings = initialRanks,
                    statsById = initialStats,
                    profile = networkProfile,
                    isMetered = isMetered,
                )
                LocalScanMode.FULL_SCAN -> FullScanPlanner.buildOrderedPlan(
                    allCandidateConfigs = allCandidateConfigs,
                    fingerprintsById = fingerprintsById,
                    statsById = initialStats,
                    profile = networkProfile,
                    nowMs = nowStart,
                    skipFreshWithinTtl = skipFreshWithinTtl,
                )
            }

            if (plan.isEmpty()) {
                val emptyBundle = PersonalizedTop50Ranker.computeRankings(
                    allCandidateConfigs,
                    fingerprintsById,
                    initialStats,
                    networkProfile,
                    nowStart,
                )
                return@withLock ScanExecutionSummary(
                    scanMode = scanMode,
                    networkProfile = networkProfile,
                    plannedCount = 0,
                    testedCount = 0,
                    qualifiedAliveCount = emptyBundle.top50.size,
                    stoppedEarly = false,
                    rankingBundle = emptyBundle,
                    results = emptyList(),
                    failedCleanUris = securityRejectedClean,
                )
            }

            // ── المسار أ: منفّذ الفحص الدفعي فائق السرعة على أندرويد الفعلي (customProbeExecutor == null) ──
            if (customProbeExecutor == null) {
                val stage1Label = tr(
                    "فحص فائق السرعة (${networkProfile.labelAr})",
                    "Ultra-Fast Tunnel Scan (${networkProfile.labelEn})",
                )
                onProgress(TestProgress(stage1Label, 0, plan.size, 0))

                val stage1TimeoutMs = (timeoutSec.coerceIn(2, 5) * 600).coerceIn(1_800, 2_500)
                var doneStage1 = 0
                var aliveStage1 = 0
                var stoppedEarly = false
                val stage1All = ArrayList<TestResult>(plan.size)

                val chunks = plan.chunked(BATCH_SIZE)
                for ((cIdx, chunk) in chunks.withIndex()) {
                    coroutineContext.ensureActive()
                    if (activeNetworkSupplier != null && activeNetworkSupplier.invoke() != networkProfile) {
                        stoppedEarly = true
                        break
                    }
                    val chunkRes = probeBatchChunkWithFallback(
                        chunk = chunk,
                        basePort = 23200 + (cIdx % 6) * 60,
                        timeoutMs = stage1TimeoutMs,
                        dnsServer = dnsServer,
                        useDoh = useDoh,
                    ) { r ->
                        var snap: TestProgress? = null
                        synchronized(this@SequentialTunnelScanner) {
                            doneStage1++
                            if (r.ok && r.latencyMs > 0L) aliveStage1++
                            if (doneStage1 % 8 == 0 || doneStage1 == plan.size) {
                                snap = TestProgress(stage1Label, doneStage1, plan.size, aliveStage1)
                            }
                        }
                        snap?.let { onProgress(it) }
                    }
                    stage1All.addAll(chunkRes)
                    if (scanMode == LocalScanMode.QUICK_SCAN &&
                        aliveStage1 >= quickStopTargetQualified &&
                        doneStage1 < plan.size
                    ) {
                        stoppedEarly = true
                        break
                    }
                }

                // Offline Guard: if >= 15 configs were tested and 0 responded, device internet itself is down!
                if (stage1All.size >= PersonalizedTop50Ranker.OFFLINE_GUARD_MIN_TESTED && aliveStage1 == 0) {
                    val preservedBundle = PersonalizedTop50Ranker.computeRankings(
                        allCandidateConfigs,
                        fingerprintsById,
                        initialStats,
                        networkProfile,
                        System.currentTimeMillis(),
                    )
                    return@withLock ScanExecutionSummary(
                        scanMode = scanMode,
                        networkProfile = networkProfile,
                        plannedCount = plan.size,
                        testedCount = stage1All.size,
                        qualifiedAliveCount = preservedBundle.top50.size,
                        stoppedEarly = stoppedEarly,
                        rankingBundle = preservedBundle,
                        results = emptyList(),
                        failedCleanUris = emptySet(),
                        offlineGuardTriggered = true,
                    )
                }

                val responsiveSorted = stage1All
                    .filter { it.ok && it.latencyMs > 0L }
                    .sortedWith(compareBy<TestResult> { it.latencyMs }.thenBy { it.jitterMs })

                // Stage 2: Real 600 KB HTTPS Download Benchmark on top responsive safe servers
                val stage2Limit = when {
                    isBackgroundRun -> BACKGROUND_STAGE2_TOP_LIMIT // Top 15 (~9 MB strict budget)
                    networkProfile == ScanNetworkProfile.MOBILE_DATA || isMetered -> 18
                    else -> 30
                }
                val speedCandidates = responsiveSorted.take(stage2Limit)
                val speedByClean = HashMap<String, Double>(speedCandidates.size)

                if (speedCandidates.isNotEmpty()) {
                    val stage2Label = tr(
                        "قياس سرعة التنزيل الحقيقية (${networkProfile.labelAr})",
                        "Measuring Real Download Speed (${networkProfile.labelEn})",
                    )
                    onProgress(TestProgress(stage2Label, 0, speedCandidates.size, 0))
                    var sDone = 0
                    for ((sIdx, sChunk) in speedCandidates.map { it.cfg }.chunked(BATCH_SIZE).withIndex()) {
                        coroutineContext.ensureActive()
                        if (activeNetworkSupplier != null && activeNetworkSupplier.invoke() != networkProfile) {
                            stoppedEarly = true
                            break
                        }
                        val ports = Tester.allocateFreePorts(sChunk.size, basePort = 24400 + (sIdx % 3) * 60)
                        val paired = sChunk.mapIndexed { idx, c -> c to ports[idx] }
                        val session = runInterruptible(Dispatchers.IO) {
                            singBox.startBatchDaemon(paired, dnsServer = dnsServer, useDoh = useDoh, waitMs = 2200L)
                        }
                        if (session != null) {
                            val sem = Semaphore(STAGE2_PARALLELISM)
                            try {
                                coroutineScope {
                                    session.slots.map { slot ->
                                        async(Dispatchers.IO) {
                                            ensureActive()
                                            val kbps = sem.withPermit {
                                                ensureActive()
                                                runInterruptible(Dispatchers.IO) {
                                                    SingBox.measureDownloadThroughputOnPort(
                                                        port = slot.listenPort,
                                                        timeoutMs = 6_500,
                                                        budgetBytes = SingBox.SPEED_BYTES,
                                                    )
                                                }
                                            }
                                            var snap: TestProgress? = null
                                            synchronized(this@SequentialTunnelScanner) {
                                                if (kbps > 0.0) {
                                                    speedByClean[Converters.cleanUri(slot.cfg)] = kbps
                                                }
                                                sDone++
                                                if (sDone % 3 == 0 || sDone == speedCandidates.size) {
                                                    snap = TestProgress(stage2Label, sDone, speedCandidates.size, speedByClean.size)
                                                }
                                            }
                                            snap?.let { onProgress(it) }
                                        }
                                    }.awaitAll()
                                }
                            } finally {
                                singBox.stopBatchDaemon(session)
                            }
                        }
                    }
                }

                // Commit measurements to network-isolated SQLite tables on Dispatchers.IO
                val liveAlive = ArrayList<TestResult>(responsiveSorted.size)
                val liveFailed = LinkedHashSet<String>(securityRejectedClean)
                val commitNowMs = System.currentTimeMillis()

                for (rawRes in stage1All) {
                    val clean = Converters.cleanUri(rawRes.cfg)
                    val sid = Converters.stableServerId(clean)
                    val fp = fingerprintsById[sid] ?: Converters.configFingerprint(clean)
                    val measuredSpd = speedByClean[clean] ?: rawRes.speedKbps
                    val finalRes = if (measuredSpd > 0.0) rawRes.copy(speedKbps = measuredSpd, testedAtMs = commitNowMs) else rawRes
                    val probeOk = finalRes.ok && finalRes.latencyMs > 0L && finalRes.packetLossPct < 60.0

                    if (probeOk) {
                        liveAlive.add(finalRes)
                        liveFailed.remove(clean)
                    } else {
                        liveFailed.add(clean)
                    }

                    clientDb.recordNetworkScanMeasurement(
                        cfgOrServerId = clean,
                        configFingerprint = fp,
                        networkProfile = networkProfile,
                        scanMode = scanMode.code,
                        success = probeOk,
                        establishMs = finalRes.establishMs,
                        latencyMs = finalRes.latencyMs,
                        jitterMs = finalRes.jitterMs,
                        packetLossPct = if (probeOk) finalRes.packetLossPct else 100.0,
                        throughputKbps = finalRes.speedKbps,
                        stabilityScore = finalRes.stabilityScore,
                        failureReason = if (probeOk) "" else finalRes.error.ifBlank { "TUNNEL_PROBE_FAILED" },
                        nowMs = commitNowMs,
                    )
                    clientDb.recordServerProbeOrSessionOutcome(
                        cfgOrServerId = clean,
                        ok = probeOk,
                        latencyMs = finalRes.latencyMs,
                        establishMs = finalRes.establishMs,
                        jitterMs = finalRes.jitterMs,
                        packetLossPct = if (probeOk) finalRes.packetLossPct else 100.0,
                        downloadKbps = finalRes.speedKbps,
                        networkType = networkProfile.code,
                        failureCategory = if (probeOk) "" else "BATCH_SCAN_FAIL",
                        nowMs = commitNowMs,
                    )
                }

                val finalStats = clientDb.getNetworkStatsMap(networkProfile)
                val finalBundle = PersonalizedTop50Ranker.computeRankings(
                    allCandidateConfigs,
                    fingerprintsById,
                    finalStats,
                    networkProfile,
                    commitNowMs,
                )
                clientDb.savePersonalizedNetworkRankings(
                    profile = networkProfile,
                    scanMode = scanMode.code,
                    entries = finalBundle.allQualifiedEntries,
                    recordHistorySnapshot = true,
                    nowMs = commitNowMs,
                )
                onRankingUpdated(finalBundle, liveAlive.toList(), liveFailed.toSet())

                return@withLock ScanExecutionSummary(
                    scanMode = scanMode,
                    networkProfile = networkProfile,
                    plannedCount = plan.size,
                    testedCount = stage1All.size,
                    qualifiedAliveCount = finalBundle.top50.size,
                    stoppedEarly = stoppedEarly,
                    rankingBundle = finalBundle,
                    results = liveAlive.toList(),
                    failedCleanUris = liveFailed.toSet(),
                    offlineGuardTriggered = false,
                )
            }

            // ── المسار ب: المنفّذ المخصّص المحقون لاختبارات المحاكاة الحتمية (customProbeExecutor != null) ──
            val executor = customProbeExecutor
            val liveAlive = ArrayList<TestResult>()
            val liveFailed = LinkedHashSet<String>(securityRejectedClean)
            val bufferedProbes = ArrayList<Pair<String, TestResult>>(plan.size)
            var tested = 0
            var stoppedEarly = false
            var throughputMeasuredCount = 0

            val stageLabel = "${scanMode.labelAr} • ${networkProfile.labelAr}"
            onProgress(TestProgress(stageLabel, 0, plan.size, 0))

            for (cfg in plan) {
                coroutineContext.ensureActive()
                if (activeNetworkSupplier != null && activeNetworkSupplier.invoke() != networkProfile) {
                    stoppedEarly = true
                    break
                }

                val maxTpSamples = when {
                    isBackgroundRun -> BACKGROUND_STAGE2_TOP_LIMIT
                    scanMode == LocalScanMode.QUICK_SCAN && (networkProfile == ScanNetworkProfile.MOBILE_DATA || isMetered) -> 15
                    scanMode == LocalScanMode.QUICK_SCAN -> 35
                    networkProfile == ScanNetworkProfile.MOBILE_DATA || isMetered -> 45
                    else -> 110
                }
                val shouldSampleTp = throughputMeasuredCount < maxTpSamples
                val tpBytes = SingBox.SPEED_BYTES
                val pSamples = if (scanMode == LocalScanMode.QUICK_SCAN && (networkProfile == ScanNetworkProfile.MOBILE_DATA || isMetered)) 2 else 3

                val req = TunnelProbeRequest(
                    cfg = cfg,
                    networkProfile = networkProfile,
                    isMetered = isMetered,
                    scanMode = scanMode,
                    measureThroughput = shouldSampleTp,
                    throughputBudgetBytes = tpBytes,
                    probeSamples = pSamples,
                    timeoutSec = timeoutSec,
                    dnsServer = dnsServer,
                    useDoh = useDoh,
                )

                val res = runInterruptible(Dispatchers.IO) {
                    executor.executeSequential(req)
                }

                tested++
                val clean = Converters.cleanUri(cfg)
                val probeOk = res.ok && res.latencyMs > 0L && res.packetLossPct < 60.0
                bufferedProbes.add(clean to res)

                if (probeOk) {
                    if (res.speedKbps > 0.0) throughputMeasuredCount++
                    liveAlive.add(res)
                    liveFailed.remove(clean)
                } else {
                    liveFailed.add(clean)
                }

                onProgress(TestProgress(stageLabel, tested, plan.size, liveAlive.size))

                if (scanMode == LocalScanMode.QUICK_SCAN &&
                    liveAlive.size >= quickStopTargetQualified &&
                    tested < plan.size
                ) {
                    stoppedEarly = true
                    break
                }
            }

            if (tested >= PersonalizedTop50Ranker.OFFLINE_GUARD_MIN_TESTED && liveAlive.isEmpty()) {
                val preservedBundle = PersonalizedTop50Ranker.computeRankings(
                    allCandidateConfigs,
                    fingerprintsById,
                    initialStats,
                    networkProfile,
                    System.currentTimeMillis(),
                )
                return@withLock ScanExecutionSummary(
                    scanMode = scanMode,
                    networkProfile = networkProfile,
                    plannedCount = plan.size,
                    testedCount = tested,
                    qualifiedAliveCount = preservedBundle.top50.size,
                    stoppedEarly = stoppedEarly,
                    rankingBundle = preservedBundle,
                    results = emptyList(),
                    failedCleanUris = emptySet(),
                    offlineGuardTriggered = true,
                )
            }

            val commitNow = System.currentTimeMillis()
            for ((clean, res) in bufferedProbes) {
                val sid = Converters.stableServerId(clean)
                val fp = fingerprintsById[sid] ?: Converters.configFingerprint(clean)
                val probeOk = res.ok && res.latencyMs > 0L && res.packetLossPct < 60.0
                clientDb.recordNetworkScanMeasurement(
                    cfgOrServerId = clean,
                    configFingerprint = fp,
                    networkProfile = networkProfile,
                    scanMode = scanMode.code,
                    success = probeOk,
                    establishMs = res.establishMs,
                    latencyMs = res.latencyMs,
                    jitterMs = res.jitterMs,
                    packetLossPct = if (probeOk) res.packetLossPct else 100.0,
                    throughputKbps = res.speedKbps,
                    stabilityScore = res.stabilityScore,
                    failureReason = if (probeOk) "" else res.error.ifBlank { "TUNNEL_PROBE_FAILED" },
                    nowMs = commitNow,
                )
                clientDb.recordServerProbeOrSessionOutcome(
                    cfgOrServerId = clean,
                    ok = probeOk,
                    latencyMs = res.latencyMs,
                    establishMs = res.establishMs,
                    jitterMs = res.jitterMs,
                    packetLossPct = if (probeOk) res.packetLossPct else 100.0,
                    downloadKbps = res.speedKbps,
                    networkType = networkProfile.code,
                    failureCategory = if (probeOk) "" else "SEQ_SCAN_FAIL",
                    nowMs = commitNow,
                )
            }

            val finalStats = clientDb.getNetworkStatsMap(networkProfile)
            val finalBundle = PersonalizedTop50Ranker.computeRankings(
                allCandidateConfigs,
                fingerprintsById,
                finalStats,
                networkProfile,
                commitNow,
            )
            clientDb.savePersonalizedNetworkRankings(
                profile = networkProfile,
                scanMode = scanMode.code,
                entries = finalBundle.allQualifiedEntries,
                recordHistorySnapshot = true,
                nowMs = commitNow,
            )
            onRankingUpdated(finalBundle, liveAlive.toList(), liveFailed.toSet())

            ScanExecutionSummary(
                scanMode = scanMode,
                networkProfile = networkProfile,
                plannedCount = plan.size,
                testedCount = tested,
                qualifiedAliveCount = finalBundle.top50.size,
                stoppedEarly = stoppedEarly,
                rankingBundle = finalBundle,
                results = liveAlive.toList(),
                failedCleanUris = liveFailed.toSet(),
                offlineGuardTriggered = false,
            )
        }
    }
}
