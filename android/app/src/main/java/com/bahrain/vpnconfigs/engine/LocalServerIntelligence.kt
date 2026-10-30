// =====================================================================
// LocalServerIntelligence.kt — محرك الذكاء المحلي المخصّص على أندرويد (v3.4):
//   • السلطة الوحيدة والحصرية لاختيار أفضل 50 سيرفرًا مخصّصًا (Personalized Top 50)
//     ومجمّع الاحتياطي المؤهّل (Backup Pool) بناءً على الفحص الفعلي على شبكة المستخدم.
//   • فصل صارم ومستقل تمامًا بين ترتيب وسجل شبكة Wi-Fi وبين بيانات الجوال (Mobile Data).
//   • فحص أنفاق VPN الحقيقية بالتسلسل الصارم (واحد تلو الآخر — Mutex تسلسلي) احترامًا
//     لقيود Android VpnService ومنعًا لفتح مئات الأنفاق المتزامنة.
//   • وضعان ذكيان للفحص:
//       1) Quick Scan: يختبر الناجحة مؤخرًا + الـ Top 50 الحالية + الاحتياطي عند الحاجة
//          ويتوقف مبكرًا فور توفر عدد كافٍ من السيرفرات المؤهّلة توفيرًا للبطارية والبيانات.
//       2) Full Scan : يقيّم كامل حزمة الـ Top 500 بالتسلسل لاكتشاف سيرفرات تتفوّق على
//          الـ Top 50 الحالية وإعادة فحص القراءات المتقادمة وتحديث مجمّع الاحتياطي.
// =====================================================================
package com.bahrain.vpnconfigs.engine

import android.content.Context
import com.bahrain.vpnconfigs.data.ClientDatabase
import com.bahrain.vpnconfigs.data.LocalPoolTier
import com.bahrain.vpnconfigs.data.NetworkServerProfileStats
import com.bahrain.vpnconfigs.data.PersonalizedRankEntry
import com.bahrain.vpnconfigs.data.ScanNetworkProfile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.net.ServerSocket
import kotlin.coroutines.coroutineContext
import kotlin.math.max
import kotlin.math.min

enum class LocalScanMode(val code: String, val labelAr: String) {
    QUICK_SCAN("QUICK_SCAN", "فحص سريع (Top 50)"),
    FULL_SCAN("FULL_SCAN", "فحص شامل (500)");
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
)

object PersonalizedTop50Ranker {
    const val PERSONALIZED_TOP_LIMIT = 50
    const val QUALIFIED_BACKUP_LIMIT = 30
    const val STALE_WIFI_MS = 6L * 3_600_000L
    const val STALE_MOBILE_MS = 3L * 3_600_000L

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
     * يحسب الدرجة المخصّصة (0..100) حصريًا من القياسات الحقيقية على شبكة المستخدم (WIFI أو MOBILE_DATA).
     * لا يستخدم ترتيب GitHub المركزي كبديل أبدًا، ولا يساوي السرعة العالية بالأمان أو الخصوصية.
     */
    fun calculatePersonalizedScore(
        stats: NetworkServerProfileStats,
        currentFingerprint: String = "",
        nowMs: Long = System.currentTimeMillis(),
    ): Double {
        if (!stats.isQualifiedLocally) return 0.0

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

        val effTpKbps = if (stats.latestThroughputKbps > 0.0) {
            0.70 * stats.latestThroughputKbps + 0.30 * max(stats.bestThroughputKbps, stats.latestThroughputKbps)
        } else {
            stats.bestThroughputKbps * 0.65
        }
        // Conservative neutral credit when throughput was skipped to save mobile data — never 100!
        val throughputNorm = when {
            effTpKbps <= 0.0 -> 35.0
            effTpKbps >= 8_000.0 -> 100.0
            else -> (20.0 + (effTpKbps / 8_000.0) * 80.0).coerceIn(0.0, 100.0)
        }

        val stabilityNorm = stats.stabilityScore.coerceIn(0.0, 100.0)
        val packetLossNorm = (100.0 - stats.ewmaPacketLossPct * 2.0).coerceIn(0.0, 100.0)
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

        var rawScore =
            latencyNorm * 0.25 +
                throughputNorm * 0.22 +
                stabilityNorm * 0.20 +
                packetLossNorm * 0.13 +
                jitterNorm * 0.10 +
                establishNorm * 0.10

        // Gentle freshness decay if measurement is stale or fingerprint shifted
        val ageMs = (nowMs - stats.lastScanAtMs).coerceAtLeast(0L)
        val staleWindow = staleThresholdMs(stats.networkProfile)
        if (ageMs > staleWindow) {
            val extraHours = ((ageMs - staleWindow) / 3_600_000.0).coerceAtMost(24.0)
            rawScore *= (1.0 - (extraHours / 24.0) * 0.12)
        }
        if (currentFingerprint.isNotBlank() && stats.configFingerprint.isNotBlank() &&
            stats.configFingerprint != currentFingerprint
        ) {
            rawScore *= 0.85
        }
        if (stats.consecutiveFailures > 0) {
            rawScore -= stats.consecutiveFailures * 12.0
        }

        return (kotlin.math.round(rawScore.coerceIn(0.0, 100.0) * 100.0) / 100.0)
    }

    /**
     * يبني قائمة الـ Top 50 المخصّصة + مجمّع الاحتياطي المؤهّل لشبكة محددة (WIFI أو MOBILE_DATA).
     * لا يدخل أي سيرفر لم ينجح فعليًا في الفحص المحلي على نفس نوع الشبكة.
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
            val stability: Double,
            val latencyMs: Long,
        )

        val seen = HashSet<String>()
        val qualified = ArrayList<ScoredCandidate>()

        for (rawCfg in candidateConfigs) {
            val clean = Converters.cleanUri(rawCfg)
            if (!clean.contains("://") || !Converters.isSupported(clean)) continue
            val sid = Converters.stableServerId(clean)
            if (sid.isBlank() || !seen.add(sid)) continue
            val st = statsById[sid] ?: continue
            if (st.networkProfile != profile || !st.isQualifiedLocally) continue
            val fp = fingerprintsById[sid] ?: Converters.configFingerprint(clean)
            val pScore = calculatePersonalizedScore(st, fp, nowMs)
            if (pScore <= 0.0) continue
            qualified.add(
                ScoredCandidate(
                    serverId = sid,
                    fingerprint = fp,
                    score = pScore,
                    stability = st.stabilityScore,
                    latencyMs = st.latestLatencyMs,
                )
            )
        }

        qualified.sortWith(
            compareByDescending<ScoredCandidate> { it.score }
                .thenByDescending { it.stability }
                .thenBy { if (it.latencyMs > 0L) it.latencyMs else Long.MAX_VALUE }
                .thenBy { it.serverId }
        )

        val top50 = ArrayList<PersonalizedRankEntry>(min(PERSONALIZED_TOP_LIMIT, qualified.size))
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
            if (tier == LocalPoolTier.TOP_50) top50.add(entry) else backup.add(entry)
            byId[item.serverId] = entry
        }

        return PersonalizedRankingBundle(
            networkProfile = profile,
            top50 = top50,
            backupPool = backup,
            entriesById = byId,
        )
    }
}

object QuickScanPlanner {
    /**
     * يبني خطة الفحص السريع الذكي (القسم 3):
     *   1) السيرفرات الناجحة مؤخرًا وذات القياسات الموثوقة الحديثة على نفس الشبكة.
     *   2) أعضاء الـ Top 50 المحلية الحالية لهذه الشبكة.
     *   3) سيرفرات الاحتياطي المؤهّل (Backup Pool) عند وجود نقص أو فشل في الـ Top 50.
     *   4) شريحة تأسيسية محدودة من حزمة الـ 500 فقط عندما تكون الـ Top 50 المحلية غير مكتملة،
     *      مع عدم فحص كامل الـ 500 بدون داعٍ أبدًا!
     */
    fun buildOrderedPlan(
        allCandidateConfigs: List<String>,
        currentRankings: List<PersonalizedRankEntry>,
        statsById: Map<String, NetworkServerProfileStats>,
        profile: ScanNetworkProfile,
        isMetered: Boolean,
        maxQuickCandidates: Int = if (profile == ScanNetworkProfile.MOBILE_DATA || isMetered) 40 else 65,
    ): List<String> {
        val cfgById = LinkedHashMap<String, String>()
        for (raw in allCandidateConfigs) {
            val clean = Converters.cleanUri(raw)
            if (!clean.contains("://") || !Converters.isSupported(clean)) continue
            val sid = Converters.stableServerId(clean)
            if (sid.isNotBlank() && !cfgById.containsKey(sid)) {
                cfgById[sid] = clean
            }
        }
        if (cfgById.isEmpty()) return emptyList()

        val cap = min(maxQuickCandidates.coerceAtLeast(10), cfgById.size)
        val orderedIds = LinkedHashSet<String>()

        // 1. Recently successful reliable servers on this network profile
        val recentSuccess = statsById.values
            .filter { it.networkProfile == profile && it.lastSuccessfulConnectionMs > 0L && it.consecutiveFailures == 0 && cfgById.containsKey(it.serverId) }
            .sortedWith(
                compareByDescending<NetworkServerProfileStats> { it.lastSuccessfulConnectionMs }
                    .thenByDescending { it.stabilityScore }
            )
        for (st in recentSuccess) {
            orderedIds.add(st.serverId)
            if (orderedIds.size >= cap) break
        }

        // 2. Current local Top 50 for this network profile
        if (orderedIds.size < cap) {
            currentRankings
                .filter { it.poolTier == LocalPoolTier.TOP_50 && cfgById.containsKey(it.serverId) }
                .sortedBy { it.rankPosition }
                .forEach { r ->
                    if (orderedIds.size < cap) orderedIds.add(r.serverId)
                }
        }

        // 3. Qualified Backup Pool when Top 50 needs reinforcement or replacement
        val healthyTop50Count = currentRankings.count {
            it.poolTier == LocalPoolTier.TOP_50 &&
                (statsById[it.serverId]?.consecutiveFailures ?: 0) == 0 &&
                cfgById.containsKey(it.serverId)
        }
        if (orderedIds.size < cap && healthyTop50Count < PersonalizedTop50Ranker.PERSONALIZED_TOP_LIMIT) {
            currentRankings
                .filter { it.poolTier == LocalPoolTier.BACKUP_POOL && cfgById.containsKey(it.serverId) }
                .sortedBy { it.rankPosition }
                .forEach { r ->
                    if (orderedIds.size < cap) orderedIds.add(r.serverId)
                }
        }

        // 4. Cold-start / under-filled Top-50 bootstrap from bounded Central Top-500 slice (never all 500!)
        if (orderedIds.size < cap && healthyTop50Count < min(30, cfgById.size)) {
            for (sid in cfgById.keys) {
                val st = statsById[sid]
                // Skip repeatedly failing nodes during Quick Scan to save battery & mobile data
                if (st != null && st.consecutiveFailures >= 3) continue
                orderedIds.add(sid)
                if (orderedIds.size >= cap) break
            }
        }

        return orderedIds.mapNotNull { cfgById[it] }
    }
}

object FullScanPlanner {
    /**
     * يبني خطة الفحص الشامل (القسم 4) لتقييم جميع الإعدادات المتاحة في حزمة الـ Top 500،
     * مع إعطاء الأولوية أولًا للسيرفرات المتقادمة القياس والسيرفرات الجديدة غير المفحوصة بعد
     * لاكتشاف البدائل الأسرع مبكرًا، ثم استكمال تقييم بقية الحزمة بالتسلسل.
     */
    fun buildOrderedPlan(
        allCandidateConfigs: List<String>,
        fingerprintsById: Map<String, String>,
        statsById: Map<String, NetworkServerProfileStats>,
        profile: ScanNetworkProfile,
        nowMs: Long = System.currentTimeMillis(),
    ): List<String> {
        val staleKnown = ArrayList<String>()
        val undiscovered = ArrayList<String>()
        val freshKnown = ArrayList<String>()
        val seen = HashSet<String>()

        for (raw in allCandidateConfigs) {
            val clean = Converters.cleanUri(raw)
            if (!clean.contains("://") || !Converters.isSupported(clean)) continue
            val sid = Converters.stableServerId(clean)
            if (sid.isBlank() || !seen.add(sid)) continue

            val st = statsById[sid]
            val fp = fingerprintsById[sid] ?: Converters.configFingerprint(clean)
            when {
                st == null || st.scanCount == 0 -> undiscovered.add(clean)
                PersonalizedTop50Ranker.isMeasurementStale(st, fp, profile, nowMs) -> staleKnown.add(clean)
                else -> freshKnown.add(clean)
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
        /** قفل تسلسلي صارم على مستوى العملية يضمن عدم تشغيل أكثر من نفق فحص واحد في آنٍ واحد أبدًا. */
        private val sequentialScanMutex = Mutex()

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

    /**
     * ينفّذ Quick Scan أو Full Scan بالتسلسل التام (توازي = 1 فقط)،
     * يحفظ كل قياس في السجل التاريخي المحلي دون مسح القديم، ويعيد حساب
     * أفضل 50 سيرفرًا مخصّصًا + الاحتياطي لشبكة المستخدم الحالية (WIFI أو MOBILE_DATA).
     */
    suspend fun executeScan(
        scanMode: LocalScanMode,
        allCandidateConfigs: List<String>,
        fingerprintsById: Map<String, String> = emptyMap(),
        networkProfile: ScanNetworkProfile,
        isMetered: Boolean = (networkProfile == ScanNetworkProfile.MOBILE_DATA),
        timeoutSec: Int = 5,
        dnsServer: String = "1.1.1.1",
        useDoh: Boolean = false,
        quickStopTargetQualified: Int = if (networkProfile == ScanNetworkProfile.MOBILE_DATA || isMetered) 25 else 50,
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
                    qualifiedAliveCount = 0,
                    stoppedEarly = false,
                    rankingBundle = emptyBundle,
                    results = emptyList(),
                    failedCleanUris = emptySet(),
                )
            }

            val executor = customProbeExecutor ?: defaultExecutor
            val liveAlive = ArrayList<TestResult>()
            val liveFailed = LinkedHashSet<String>()
            var tested = 0
            var stoppedEarly = false
            var throughputMeasuredCount = 0

            val stageLabel = "${scanMode.labelAr} • ${networkProfile.labelAr}"
            onProgress(TestProgress(stageLabel, 0, plan.size, 0))

            for (cfg in plan) {
                coroutineContext.ensureActive()

                // Never cross-contaminate WIFI vs MOBILE_DATA profiles if user's physical network switches mid-scan!
                if (activeNetworkSupplier != null && activeNetworkSupplier.invoke() != networkProfile) {
                    stoppedEarly = true
                    break
                }

                // Bandwidth & battery smart budgeting per probe
                val maxTpSamples = when {
                    scanMode == LocalScanMode.QUICK_SCAN && (networkProfile == ScanNetworkProfile.MOBILE_DATA || isMetered) -> 12
                    scanMode == LocalScanMode.QUICK_SCAN -> 30
                    networkProfile == ScanNetworkProfile.MOBILE_DATA || isMetered -> 35
                    else -> 80
                }
                val shouldSampleTp = throughputMeasuredCount < maxTpSamples
                val tpBytes = if (networkProfile == ScanNetworkProfile.MOBILE_DATA || isMetered) 180_000L else 600_000L
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
                val sid = Converters.stableServerId(clean)
                val fp = fingerprintsById[sid] ?: Converters.configFingerprint(clean)
                val probeOk = res.ok && res.latencyMs > 0L && res.packetLossPct < 60.0
                val nowProbeMs = System.currentTimeMillis()

                if (probeOk) {
                    if (res.speedKbps > 0.0) throughputMeasuredCount++
                    liveAlive.add(res)
                    liveFailed.remove(clean)
                } else {
                    liveFailed.add(clean)
                }

                // Append-only historical measurement + per-network stat update
                val updatedStat = clientDb.recordNetworkScanMeasurement(
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
                    nowMs = nowProbeMs,
                )

                // Also keep legacy telemetry synchronized so Favorites & SmartServerSelector stay coherent
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
                    nowMs = nowProbeMs,
                )

                if (updatedStat != null && probeOk) {
                    val pScore = PersonalizedTop50Ranker.calculatePersonalizedScore(updatedStat, fp, nowProbeMs)
                    if (pScore > 0.0) {
                        // Update live progressive ranking every 3 probes so user sees Top 50 form immediately
                        if (tested % 3 == 0 || tested == plan.size) {
                            val progStats = clientDb.getNetworkStatsMap(networkProfile)
                            val progBundle = PersonalizedTop50Ranker.computeRankings(
                                allCandidateConfigs,
                                fingerprintsById,
                                progStats,
                                networkProfile,
                                nowProbeMs,
                            )
                            clientDb.savePersonalizedNetworkRankings(
                                profile = networkProfile,
                                scanMode = scanMode.code,
                                entries = progBundle.allQualifiedEntries,
                                recordHistorySnapshot = false,
                                nowMs = nowProbeMs,
                            )
                            onRankingUpdated(progBundle, liveAlive.toList(), liveFailed.toSet())
                        }
                    }
                } else if (tested % 5 == 0) {
                    val progStats = clientDb.getNetworkStatsMap(networkProfile)
                    val progBundle = PersonalizedTop50Ranker.computeRankings(
                        allCandidateConfigs,
                        fingerprintsById,
                        progStats,
                        networkProfile,
                        nowProbeMs,
                    )
                    onRankingUpdated(progBundle, liveAlive.toList(), liveFailed.toSet())
                }

                onProgress(TestProgress(stageLabel, tested, plan.size, liveAlive.size))

                // Section 3: Quick Scan stops early once sufficient fresh qualified servers are verified!
                if (scanMode == LocalScanMode.QUICK_SCAN &&
                    liveAlive.size >= quickStopTargetQualified &&
                    tested < plan.size
                ) {
                    stoppedEarly = true
                    break
                }
            }

            // Final ranking recalculation + append-only local_ranking_history snapshot!
            val finalNow = System.currentTimeMillis()
            val finalStats = clientDb.getNetworkStatsMap(networkProfile)
            val finalBundle = PersonalizedTop50Ranker.computeRankings(
                allCandidateConfigs,
                fingerprintsById,
                finalStats,
                networkProfile,
                finalNow,
            )
            clientDb.savePersonalizedNetworkRankings(
                profile = networkProfile,
                scanMode = scanMode.code,
                entries = finalBundle.allQualifiedEntries,
                recordHistorySnapshot = true,
                nowMs = finalNow,
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
            )
        }
    }
}
