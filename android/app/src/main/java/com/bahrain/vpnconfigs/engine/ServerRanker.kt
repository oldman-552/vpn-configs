// =====================================================================
// ServerRanker.kt — محرّك التقييم والترتيب الخماسي الموثّق لسيرفرات VPN.
//
// صيغة «الأفضل إجمالًا» (BEST_OVERALL):
//   OverallScore = StaleFactor × (
//       0.50 × SpeedScore       [سرعة التنزيل الفعلية عبر النفق: 50%]
//     + 0.20 × LatencyScore     [التأخير الفعلي Real Delay:     20%]
//     + 0.20 × StabilityScore   [الاستقرار وتماسك الاستجابة:     20%]
//     + 0.10 × SuccessScore     [نجاح الاتصال والتحقّق الفعلي:   10%]
//   )
//
// قواعد الصدق مع البيانات المفقودة أو القديمة:
//   1) لا تُختلق أي درجة لمقياس غائب: إذا لم تُقس سرعة التنزيل فعليًا عبر النفق
//      (speedKbps <= 0) فإن مساهمة مكوّن السرعة تكون 0.0 وليس متوسّطًا مفترضًا،
//      ولا يُشتقّ أي تقدير للسرعة من زمن البينغ وحده.
//   2) السيرفر الذي يفشل اتصاله الفعلي (localFailed = true) يحصل على 0.0 وينزل لأسفل القائمة.
//   3) القياسات القديمة تتآكل تدريجيًا بمعامل صريح:
//      • عمر القياس ≤ 12 ساعة  -> معامل حداثة 1.00
//      • عمر القياس > 12 ساعة  -> معامل حداثة 0.85
//      • عمر القياس > 48 ساعة  -> معامل حداثة 0.70
// =====================================================================
package com.bahrain.vpnconfigs.engine

import kotlin.math.ln

enum class ServerSortMode(val key: String, val titleAr: String) {
    FASTEST_DOWNLOAD("FASTEST_DOWNLOAD", "الأسرع في التنزيل"),
    LOWEST_LATENCY("LOWEST_LATENCY", "الأقل تأخيرًا"),
    MOST_STABLE("MOST_STABLE", "الأكثر استقرارًا"),
    BEST_OVERALL("BEST_OVERALL", "الأفضل إجمالًا"),
    PRIVACY_AWARE("PRIVACY_AWARE", "الأعلى أمانًا وخصوصية"),
    RECENTLY_TESTED("RECENTLY_TESTED", "الأحدث اختبارًا");

    companion object {
        val DEFAULT: ServerSortMode = FASTEST_DOWNLOAD

        fun fromKey(raw: String?): ServerSortMode = when (raw?.trim()?.uppercase()) {
            "FASTEST_DOWNLOAD", "SPEED", "HIGH_SPEED" -> FASTEST_DOWNLOAD
            "LOWEST_LATENCY", "REAL_DELAY", "LOW_LATENCY" -> LOWEST_LATENCY
            "MOST_STABLE", "STABILITY", "HIGH_RELIABILITY" -> MOST_STABLE
            "BEST_OVERALL", "OVERALL", "BALANCED" -> BEST_OVERALL
            "PRIVACY_AWARE", "SECURITY" -> PRIVACY_AWARE
            "RECENTLY_TESTED", "RECENT" -> RECENTLY_TESTED
            else -> DEFAULT
        }
    }
}

data class RankableServer(
    val cfg: String,
    val latencyMs: Long = 0L,
    val jitterMs: Double = 0.0,
    val speedKbps: Double = 0.0,
    val uploadKbps: Double = 0.0,
    val packetLossPct: Double = 0.0,
    val uptimePct: Double = 100.0,
    val recentFailures: Int = 0,
    val stabilityRuns: Int = 0,
    val cloudQualityHint: Double = 0.0,
    val securityAssessment: String = "Unknown",
    val privacyAssessment: String = "Unknown",
    val riskLevel: String = "UNKNOWN",
    val locallyTested: Boolean = false,
    val localFailed: Boolean = false,
    val isFavorite: Boolean = false,
    val isCustom: Boolean = false,
    val lastTestedAtMs: Long = 0L,
)

object ServerRanker {

    const val WEIGHT_DOWNLOAD_SPEED = 0.50
    const val WEIGHT_LATENCY = 0.20
    const val WEIGHT_STABILITY = 0.20
    const val WEIGHT_CONNECTION_SUCCESS = 0.10

    private const val STALE_12H_MS = 12L * 3600L * 1000L
    private const val STALE_48H_MS = 48L * 3600L * 1000L

    /**
     * يحوّل سرعة التنزيل الفعلية المقاسة عبر النفق (KB/s) إلى درجة [0..100].
     * يُرجع null إذا لم تُقس السرعة فعليًا (لا يشتقّ السرعة من Ping أبدًا).
     */
    fun computeSpeedComponent(speedKbps: Double): Double? {
        if (speedKbps <= 0.0 || speedKbps.isNaN() || speedKbps.isInfinite()) return null
        val normalized = ln(1.0 + speedKbps / 128.0) / ln(1.0 + 10240.0 / 128.0)
        return (normalized * 100.0).coerceIn(0.0, 100.0)
    }

    /**
     * يحوّل زمن التأخير الفعلي Real Delay (ms) إلى درجة [0..100].
     * يُرجع null إذا لم يتوفّر قياس تأخير صالح.
     */
    fun computeLatencyComponent(latencyMs: Long, localFailed: Boolean = false): Double? {
        if (localFailed || latencyMs <= 0L) return null
        val normalized = (1200.0 - latencyMs.toDouble()) / (1200.0 - 40.0)
        return (normalized * 100.0).coerceIn(0.0, 100.0)
    }

    /**
     * يحسب درجة الاستقرار [0..100] من عدد جولات الثبات المتتالية وتذبذب الاستجابة (Jitter).
     * يُرجع null عند غياب جميع دلائل الاستقرار بدل اختلاق رقم افتراضي.
     */
    fun computeStabilityComponent(
        stabilityRuns: Int,
        jitterMs: Double,
        locallyTested: Boolean,
        latencyMs: Long,
        localFailed: Boolean = false,
    ): Double? {
        if (localFailed) return 0.0
        val hasRuns = stabilityRuns > 0
        val hasJitter = jitterMs > 0.0 && !jitterMs.isNaN()
        if (!hasRuns && !hasJitter && !locallyTested) return null

        val runsScore = when {
            hasRuns -> (stabilityRuns.coerceAtMost(5) / 5.0) * 75.0
            locallyTested && latencyMs > 0L -> 35.0
            else -> 0.0
        }
        val jitterScore = when {
            hasJitter -> ((1.0 - (jitterMs / 200.0)).coerceIn(0.0, 1.0)) * 25.0
            hasRuns -> 15.0
            locallyTested && latencyMs in 1L..250L -> 15.0
            else -> 0.0
        }
        return (runsScore + jitterScore).coerceIn(0.0, 100.0)
    }

    /**
     * يحسب درجة نجاح الاتصال [0..100] بناءً على نتيجة التحقق الفعلي فقط.
     * يُرجع null للعقد غير المختبرة إطلاقًا.
     */
    fun computeConnectionSuccessComponent(
        locallyTested: Boolean,
        localFailed: Boolean,
        latencyMs: Long,
        speedKbps: Double,
        lastTestedAtMs: Long,
    ): Double? {
        if (localFailed) return 0.0
        if (locallyTested && (latencyMs > 0L || speedKbps > 0.0)) return 100.0
        if (latencyMs > 0L || speedKbps > 0.0 || lastTestedAtMs > 0L) return 75.0
        return null
    }

    /** معامل حداثة القياس للتعامل الشفاف مع القياسات القديمة دون حذفها أو تضخيمها. */
    fun computeFreshnessFactor(lastTestedAtMs: Long, nowMs: Long): Double {
        if (lastTestedAtMs <= 0L || nowMs <= lastTestedAtMs) return 1.0
        val ageMs = nowMs - lastTestedAtMs
        return when {
            ageMs > STALE_48H_MS -> 0.70
            ageMs > STALE_12H_MS -> 0.85
            else -> 1.0
        }
    }

    /**
     * يحسب التقييم الإجمالي الموزون [0..100] بالأوزان المعتمدة:
     *   50% سرعة التنزيل + 20% التأخير + 20% الاستقرار + 10% نجاح الاتصال.
     * أي مكوّن غير مقاس يساهم بـ 0.0 (لا يتم اختلاق درجات).
     */
    fun computeOverallScore(item: RankableServer, nowMs: Long = System.currentTimeMillis()): Double {
        if (item.localFailed) return 0.0

        val speedScore = computeSpeedComponent(item.speedKbps)
        val latencyScore = computeLatencyComponent(item.latencyMs, item.localFailed)
        val stabilityScore = computeStabilityComponent(
            stabilityRuns = item.stabilityRuns,
            jitterMs = item.jitterMs,
            locallyTested = item.locallyTested,
            latencyMs = item.latencyMs,
            localFailed = item.localFailed,
        )
        val successScore = computeConnectionSuccessComponent(
            locallyTested = item.locallyTested,
            localFailed = item.localFailed,
            latencyMs = item.latencyMs,
            speedKbps = item.speedKbps,
            lastTestedAtMs = item.lastTestedAtMs,
        )

        if (speedScore == null && latencyScore == null && stabilityScore == null && successScore == null) {
            return 0.0
        }

        val weightedSum =
            WEIGHT_DOWNLOAD_SPEED * (speedScore ?: 0.0) +
                WEIGHT_LATENCY * (latencyScore ?: 0.0) +
                WEIGHT_STABILITY * (stabilityScore ?: 0.0) +
                WEIGHT_CONNECTION_SUCCESS * (successScore ?: 0.0)

        val freshness = if (item.lastTestedAtMs > 0L) {
            computeFreshnessFactor(item.lastTestedAtMs, nowMs)
        } else {
            0.90
        }
        return (weightedSum * freshness).coerceIn(0.0, 100.0)
    }

    /**
     * يحسب درجة مخصّصة لكل ملف تعريف (BALANCED, LOW_LATENCY, HIGH_SPEED, HIGH_RELIABILITY, PRIVACY_AWARE)
     * مع دمج فقدان الحزم، التذبذب، سرعة التنزيل والرفع، وقت التشغيل التاريخي، الإخفاقات الأخيرة، ومستوى أمان النقل.
     */
    fun computeProfileScore(
        item: RankableServer,
        profileKey: String,
        nowMs: Long = System.currentTimeMillis(),
    ): Double {
        if (item.localFailed) return 0.0
        val mode = ServerSortMode.fromKey(profileKey)
        val dl = computeSpeedComponent(item.speedKbps) ?: 0.0
        val ul = computeSpeedComponent(item.uploadKbps) ?: 0.0
        val throughput = if (item.uploadKbps > 0.0) (0.75 * dl + 0.25 * ul) else dl
        val lat = computeLatencyComponent(item.latencyMs, item.localFailed) ?: 0.0
        val stab = computeStabilityComponent(
            item.stabilityRuns,
            item.jitterMs,
            item.locallyTested,
            item.latencyMs,
            item.localFailed,
        ) ?: 0.0
        val lossScore = (100.0 - item.packetLossPct * 2.0).coerceIn(0.0, 100.0)
        val upScore = item.uptimePct.coerceIn(0.0, 100.0)
        val failPenalty = (item.recentFailures * 10.0).coerceAtMost(35.0)

        val secScore = when (item.securityAssessment) {
            "Verified" -> 100.0
            "Partial" -> 58.0
            "Unknown" -> 30.0
            else -> 0.0
        }
        val privScore = when (item.privacyAssessment) {
            "Verified" -> 100.0
            "Unverified" -> 65.0
            "Unknown" -> 35.0
            else -> 0.0
        }
        val riskPenalty = when (item.riskLevel) {
            "CRITICAL" -> 100.0
            "HIGH" -> 55.0
            "MEDIUM" -> 15.0
            else -> 0.0
        }

        val raw = when (mode) {
            ServerSortMode.FASTEST_DOWNLOAD ->
                0.60 * throughput + 0.20 * lat + 0.15 * stab + 0.05 * lossScore - failPenalty * 0.4
            ServerSortMode.LOWEST_LATENCY ->
                0.55 * lat + 0.20 * stab + 0.15 * lossScore + 0.10 * throughput - failPenalty * 0.5
            ServerSortMode.MOST_STABLE ->
                0.35 * stab + 0.25 * upScore + 0.25 * lossScore + 0.15 * lat - failPenalty
            ServerSortMode.PRIVACY_AWARE -> {
                if (item.securityAssessment == "Failed" ||
                    item.privacyAssessment == "High Risk" ||
                    item.riskLevel in setOf("HIGH", "CRITICAL")
                ) {
                    return 0.0
                }
                0.42 * secScore + 0.23 * privScore + 0.15 * stab + 0.10 * lat + 0.10 * throughput - riskPenalty - failPenalty * 0.5
            }
            else ->
                0.35 * throughput + 0.25 * lat + 0.20 * stab + 0.10 * upScore + 0.10 * secScore - failPenalty * 0.6
        }
        val freshness = if (item.lastTestedAtMs > 0L) computeFreshnessFactor(item.lastTestedAtMs, nowMs) else 0.90
        return (raw * freshness).coerceIn(0.0, 100.0)
    }

    /** مقارن معتمد لجميع أوضاع الترتيب الستة. */
    fun comparatorFor(mode: ServerSortMode, nowMs: Long = System.currentTimeMillis()): Comparator<RankableServer> {
        fun delayRank(ms: Long): Long = if (ms > 0L) ms else Long.MAX_VALUE
        fun stabilityValue(s: RankableServer): Double =
            computeStabilityComponent(s.stabilityRuns, s.jitterMs, s.locallyTested, s.latencyMs, s.localFailed) ?: -1.0

        val modeComp: Comparator<RankableServer> = when (mode) {
            ServerSortMode.FASTEST_DOWNLOAD ->
                compareByDescending<RankableServer> { it.speedKbps > 0.0 }
                    .thenByDescending { it.speedKbps }
                    .thenByDescending { it.locallyTested }
                    .thenBy { delayRank(it.latencyMs) }
                    .thenByDescending { computeOverallScore(it, nowMs) }

            ServerSortMode.LOWEST_LATENCY ->
                compareByDescending<RankableServer> { it.latencyMs > 0L }
                    .thenByDescending { it.locallyTested }
                    .thenBy { delayRank(it.latencyMs) }
                    .thenByDescending { it.speedKbps }

            ServerSortMode.MOST_STABLE ->
                compareByDescending<RankableServer> { stabilityValue(it) >= 0.0 }
                    .thenByDescending { stabilityValue(it) }
                    .thenByDescending { it.stabilityRuns }
                    .thenBy { delayRank(it.latencyMs) }
                    .thenByDescending { it.speedKbps }

            ServerSortMode.BEST_OVERALL ->
                compareByDescending<RankableServer> { computeOverallScore(it, nowMs) }
                    .thenByDescending { it.speedKbps }
                    .thenBy { delayRank(it.latencyMs) }

            ServerSortMode.PRIVACY_AWARE ->
                compareByDescending<RankableServer> { computeProfileScore(it, ServerSortMode.PRIVACY_AWARE.key, nowMs) }
                    .thenByDescending { computeOverallScore(it, nowMs) }
                    .thenBy { delayRank(it.latencyMs) }

            ServerSortMode.RECENTLY_TESTED ->
                compareByDescending<RankableServer> { it.lastTestedAtMs > 0L }
                    .thenByDescending { it.lastTestedAtMs }
                    .thenByDescending { it.locallyTested }
                    .thenByDescending { computeOverallScore(it, nowMs) }
        }

        return compareByDescending<RankableServer> { it.isFavorite }
            .thenBy { it.localFailed }
            .then(modeComp)
    }

    /**
     * يحافظ على السيرفر المتّصل حاليًا دون أي تغيير عند تبديل ترتيب القائمة أو تحديثها.
     */
    fun resolveSelectedPreservingActive(
        currentSelectedCfg: String,
        activeVpnCfg: String?,
        isVpnActive: Boolean,
        sortedConfigs: List<String>,
    ): String {
        if (isVpnActive && !activeVpnCfg.isNullOrBlank()) {
            return activeVpnCfg
        }
        if (currentSelectedCfg.isNotBlank() && sortedConfigs.contains(currentSelectedCfg)) {
            return currentSelectedCfg
        }
        return sortedConfigs.firstOrNull().orEmpty()
    }
}
