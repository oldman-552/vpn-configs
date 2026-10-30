// =====================================================================
// SmartFailoverEngine.kt — محرك التبديل الاستباقي الذكي ومراقبة التدهور (Phase 6).
//
// المزايا الهندسية:
//   • ثلاث سياسات تشغيل: OFF (يدوي)، SMART (عند السقوط أو التدهور الشديد)،
//     AGGRESSIVE (استباقي ينتقل تلقائيًا عند توفر بديل أسرع بفارق جوهري).
//   • كشف التدهور قبل الانقطاع الكامل (ارتفاع Ping المستمر، التذبذب Jitter، فقدان الحزم).
//   • منع التذبذب والحلقات (Hysteresis + Minimum Dwell Time + Cooldown Window).
//   • جدولة فحص تكيّفية موفّرة للبطارية (Adaptive Polling) تطيل الفترة عند استقرار النفق.
// =====================================================================
package com.bahrain.vpnconfigs.vpn

import com.bahrain.vpnconfigs.engine.Converters
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.abs
import kotlin.math.roundToInt

enum class FailoverMode(val key: String, val titleAr: String, val subtitleAr: String) {
    OFF("OFF", "إيقاف (يدوي)", "البقاء على السيرفر المختار دون تبديل تلقائي"),
    SMART("SMART", "ذكي ومتوازن", "تبديل تلقائي سلس عند انقطاع السيرفر أو تدهوره الحاد"),
    AGGRESSIVE("AGGRESSIVE", "استباقي فائق", "ينتقل تلقائيًا لأفضل سيرفر بديل فور رصد بطء ملحوظ");

    companion object {
        fun fromKey(raw: String?): FailoverMode = when (raw?.trim()?.uppercase()) {
            "OFF", "MANUAL", "DISABLED" -> OFF
            "AGGRESSIVE", "PROACTIVE", "FAST" -> AGGRESSIVE
            else -> SMART
        }
    }
}

data class TunnelHealthSnapshot(
    val qualityLabelAr: String,
    val isDegraded: Boolean,
    val shouldProactiveSwitch: Boolean,
    val jitterMs: Double,
    val packetLossPct: Double,
    val reasonAr: String = "",
)

object SmartFailoverEngine {

    const val COOLDOWN_WINDOW_MS: Long = 120_000L
    const val MIN_DWELL_BETWEEN_PROACTIVE_SWITCHES_MS: Long = 25_000L
    const val HEALTHY_CHECK_INTERVAL_MS: Long = 8_000L
    const val RAPID_CONFIRM_DELAY_MS: Long = 600L
    const val SECONDARY_CONFIRM_URL: String = "https://cp.cloudflare.com/generate_204"
    const val AGGRESSIVE_IMPROVEMENT_FACTOR: Double = 0.72

    private val dropTimestampsMs = ConcurrentHashMap<String, Long>()

    fun recordServerDrop(cfg: String, nowMs: Long = System.currentTimeMillis()) {
        val clean = Converters.cleanUri(cfg)
        if (clean.isNotEmpty()) {
            dropTimestampsMs[clean] = nowMs
        }
    }

    fun recordServerHealthy(cfg: String) {
        val clean = Converters.cleanUri(cfg)
        if (clean.isNotEmpty()) {
            dropTimestampsMs.remove(clean)
        }
    }

    fun clearForTesting() {
        dropTimestampsMs.clear()
    }

    fun isInCooldown(cfg: String, nowMs: Long = System.currentTimeMillis()): Boolean {
        val clean = Converters.cleanUri(cfg)
        val ts = dropTimestampsMs[clean] ?: return false
        return (nowMs - ts) in 0L until COOLDOWN_WINDOW_MS
    }

    /**
     * يحسم قرار التبديل التلقائي عند الفشل الكلي:
     * - إذا كان الوضع OFF، لا يبدّل تلقائيًا أبدًا (يُحترم اختيار المستخدم).
     * - إذا ماتت عملية النواة (processAlive=false) ننتقل فورًا دون انتظار.
     * - إذا فشل الفحص الأساسي، نتحقق بفحص تأكيدي ثانٍ خلال 600ms؛
     *   فإن فشل كلاهما انتقلنا فورًا لسيرفر بديل موثّق.
     */
    fun shouldTriggerFailover(
        processAlive: Boolean,
        primaryProbeOk: Boolean,
        secondaryConfirmOk: Boolean,
        mode: FailoverMode = FailoverMode.SMART,
    ): Boolean {
        if (mode == FailoverMode.OFF) return false
        if (!processAlive) return true
        return !primaryProbeOk && !secondaryConfirmOk
    }

    /**
     * يقيّم جودة النفق الحيّة ويرصد التدهور (ارتفاع التأخير، التذبذب، فقدان الحزم) قبل الانقطاع الكامل
     * مع تطبيق Hysteresis وفترة استقرار دنيا لمنع حلقات التبديل السريع (Anti-Oscillation).
     */
    fun evaluateTunnelHealth(
        recentSamplesMs: List<Long>,
        recentOutcomes: List<Boolean>,
        mode: FailoverMode,
        lastSwitchAtMs: Long,
        nowMs: Long = System.currentTimeMillis(),
        bestCandidateLatencyMs: Long = 0L,
    ): TunnelHealthSnapshot {
        val validLat = recentSamplesMs.filter { it > 0L }
        val latestLat = validLat.lastOrNull() ?: 0L
        val avgLat = if (validLat.isNotEmpty()) validLat.average() else 0.0
        val jitter = if (validLat.size >= 2) {
            ((1 until validLat.size).map { abs(validLat[it] - validLat[it - 1]).toDouble() }.average() * 10.0).roundToInt() / 10.0
        } else 0.0

        val lossPct = if (recentOutcomes.isNotEmpty()) {
            val fails = recentOutcomes.count { !it }
            ((fails.toDouble() / recentOutcomes.size.toDouble()) * 1000.0).roundToInt() / 10.0
        } else 0.0

        val severelyDegraded = (validLat.size >= 3 && avgLat >= 950.0) || lossPct >= 50.0 || jitter >= 320.0
        val moderatelyDegraded = severelyDegraded || latestLat >= 650L || lossPct >= 25.0 || jitter >= 180.0

        val qualityAr = when {
            severelyDegraded -> "ضعيفة (متدهورة)"
            moderatelyDegraded -> "متوسطة (تذبذب)"
            latestLat in 1L..220L && jitter < 60.0 && lossPct == 0.0 -> "ممتازة"
            latestLat > 0L -> "جيدة ومستقرة"
            else -> "قيد القياس"
        }

        val dwellSatisfied = lastSwitchAtMs <= 0L || (nowMs - lastSwitchAtMs) >= MIN_DWELL_BETWEEN_PROACTIVE_SWITCHES_MS
        if (mode == FailoverMode.OFF || !dwellSatisfied) {
            return TunnelHealthSnapshot(
                qualityLabelAr = qualityAr,
                isDegraded = moderatelyDegraded,
                shouldProactiveSwitch = false,
                jitterMs = jitter,
                packetLossPct = lossPct,
            )
        }

        if (mode == FailoverMode.SMART && severelyDegraded) {
            return TunnelHealthSnapshot(
                qualityLabelAr = qualityAr,
                isDegraded = true,
                shouldProactiveSwitch = true,
                jitterMs = jitter,
                packetLossPct = lossPct,
                reasonAr = "رُصد تدهور حاد في استجابة السيرفر (${avgLat.toInt()} ms)",
            )
        }

        if (mode == FailoverMode.AGGRESSIVE) {
            val candidateMuchFaster = bestCandidateLatencyMs in 1L..350L &&
                avgLat >= 380.0 &&
                bestCandidateLatencyMs.toDouble() <= (avgLat * AGGRESSIVE_IMPROVEMENT_FACTOR)
            if (severelyDegraded || (moderatelyDegraded && validLat.size >= 2) || candidateMuchFaster) {
                return TunnelHealthSnapshot(
                    qualityLabelAr = qualityAr,
                    isDegraded = moderatelyDegraded,
                    shouldProactiveSwitch = true,
                    jitterMs = jitter,
                    packetLossPct = lossPct,
                    reasonAr = "انتقال استباقي إلى سيرفر أسرع وأكثر استقرارًا",
                )
            }
        }

        return TunnelHealthSnapshot(
            qualityLabelAr = qualityAr,
            isDegraded = moderatelyDegraded,
            shouldProactiveSwitch = false,
            jitterMs = jitter,
            packetLossPct = lossPct,
        )
    }

    /**
     * يضبط فترة المراقبة التكيّفية لتوفير البطارية (Phase 9 Battery Efficiency):
     * فحص سريع عند التدهور، ومتباعد تدريجيًا عند الثبات الطويل.
     */
    fun computeAdaptiveCheckIntervalMs(consecutiveHealthyProbes: Int, isDegraded: Boolean): Long = when {
        isDegraded -> 3_500L
        consecutiveHealthyProbes >= 8 -> 24_000L
        consecutiveHealthyProbes >= 4 -> 15_000L
        else -> HEALTHY_CHECK_INTERVAL_MS
    }

    /**
     * يرتب السيرفرات البديلة مع استبعاد السيرفر الحالي والسيرفرات المعزولة (Cooldown)
     * والسيرفرات ذات المخاطر الأمنية الحرجة (CRITICAL)، مع إعطاء الأولوية لعقد VIP والسرعة المقاسة.
     */
    fun rankFailoverCandidates(
        excludeCfg: String,
        pool: List<ServerCandidate>,
        nowMs: Long = System.currentTimeMillis(),
        maxCandidates: Int = 16,
    ): List<ServerCandidate> {
        val cleanExclude = Converters.cleanUri(excludeCfg)
        val indexed = pool.mapIndexedNotNull { idx, cand ->
            val clean = Converters.cleanUri(cand.cfg)
            if (clean.isEmpty() || clean == cleanExclude || cand.riskLevel == "CRITICAL") null
            else Triple(idx, clean, cand)
        }
        if (indexed.isEmpty()) return emptyList()

        val (inCooldown, ready) = indexed.partition { (_, clean, _) ->
            val ts = dropTimestampsMs[clean]
            ts != null && (nowMs - ts) in 0L until COOLDOWN_WINDOW_MS
        }

        val comparator = Comparator<Triple<Int, String, ServerCandidate>> { a, b ->
            val ca = a.third
            val cb = b.third
            if (ca.isVip != cb.isVip) {
                return@Comparator if (ca.isVip) -1 else 1
            }
            val aHasSpeed = ca.speedKbps > 0.0
            val bHasSpeed = cb.speedKbps > 0.0
            if (aHasSpeed != bHasSpeed) {
                return@Comparator if (aHasSpeed) -1 else 1
            }
            if (aHasSpeed && bHasSpeed && ca.speedKbps != cb.speedKbps) {
                return@Comparator cb.speedKbps.compareTo(ca.speedKbps)
            }
            val aLat = if (ca.latencyMs > 0L) ca.latencyMs else Long.MAX_VALUE
            val bLat = if (cb.latencyMs > 0L) cb.latencyMs else Long.MAX_VALUE
            if (aLat != bLat) {
                return@Comparator aLat.compareTo(bLat)
            }
            a.first.compareTo(b.first)
        }

        val sortedReady = ready.sortedWith(comparator).map { it.third }
        if (sortedReady.size >= maxCandidates || inCooldown.isEmpty()) {
            return sortedReady.take(maxCandidates)
        }

        val sortedFallback = inCooldown
            .sortedBy { (_, clean, _) -> dropTimestampsMs[clean] ?: 0L }
            .map { it.third }

        return (sortedReady + sortedFallback).take(maxCandidates)
    }
}
