// =====================================================================
// SmartServerSelector.kt — محرك الاختيار الذكي الموحّد للسيرفرات (v2):
//
// العقد الهندسي الموحّد (45% / 30% / 25%):
//   • سرعة التنزيل الفعلية عبر النفق (Real Download Throughput) = 45%
//   • ثبات واستقرار الاتصال (Connection Stability & Reliability) = 30%
//   • البنق والتذبذب (Ping & Jitter)                             = 25%
//
// الضوابط الصارمة:
//   • استبعاد أمني مسبق صارم (Hard Security Pre-Filter) لأي سيرفر يحتوي allowInsecure=1
//     أو مصنّف Failed / QUARANTINED / CRITICAL قبل الترتيب (لا عقوبة ناعمة 0.55 بعد الآن).
//   • عدم منح أي نقاط سرعة مجانية للسيرفر غير المقاس (0 KB/s -> 0.0).
//   • تلاشي الثقة والدرجة للقياسات الأقدم من دورة الـ 4 ساعات (4h Freshness TTL).
// =====================================================================
package com.bahrain.vpnconfigs.engine

import com.bahrain.vpnconfigs.data.LocalServerTelemetry
import com.bahrain.vpnconfigs.data.ServerHint
import com.bahrain.vpnconfigs.util.AppI18n
import com.bahrain.vpnconfigs.util.tr
import org.json.JSONObject
import kotlin.math.ln
import kotlin.math.roundToInt
import kotlin.math.sqrt

object CentralScoringWeights {
    const val THROUGHPUT_WEIGHT: Double = 0.45
    const val STABILITY_WEIGHT: Double = 0.30
    const val PING_JITTER_WEIGHT: Double = 0.25
    const val REFRESH_INTERVAL_HOURS: Long = 4L
    const val FRESHNESS_TTL_MS: Long = REFRESH_INTERVAL_HOURS * 3_600_000L
}

data class SmartSelectionWeights(
    // Stability group = 0.16 + 0.08 + 0.03 + 0.03 = 0.30 (30%)
    val connectionReliability: Double = 0.16,
    // Ping & Jitter group = 0.17 + 0.08 = 0.25 (25%)
    val latency: Double = 0.17,
    val packetLoss: Double = 0.08,
    // Real Download Throughput = 0.45 (45%)
    val downloadSpeed: Double = CentralScoringWeights.THROUGHPUT_WEIGHT,
    val historicalUptime: Double = 0.03,
    val jitter: Double = 0.08,
    val recentStability: Double = 0.03,
) {
    fun normalized(): SmartSelectionWeights {
        val sum = connectionReliability + latency + packetLoss + downloadSpeed +
            historicalUptime + jitter + recentStability
        if (sum <= 0.0001) return SmartSelectionWeights()
        return SmartSelectionWeights(
            connectionReliability = connectionReliability / sum,
            latency = latency / sum,
            packetLoss = packetLoss / sum,
            downloadSpeed = downloadSpeed / sum,
            historicalUptime = historicalUptime / sum,
            jitter = jitter / sum,
            recentStability = recentStability / sum,
        )
    }

    fun toJsonString(): String = JSONObject()
        .put("connection_reliability", connectionReliability)
        .put("latency", latency)
        .put("packet_loss", packetLoss)
        .put("download_speed", downloadSpeed)
        .put("historical_uptime", historicalUptime)
        .put("jitter", jitter)
        .put("recent_stability", recentStability)
        .toString()

    companion object {
        fun fromJsonOrDefault(raw: String?): SmartSelectionWeights {
            if (raw.isNullOrBlank()) return SmartSelectionWeights()
            return runCatching {
                val o = JSONObject(raw)
                SmartSelectionWeights(
                    connectionReliability = o.optDouble("connection_reliability", 0.16).coerceAtLeast(0.0),
                    latency = o.optDouble("latency", 0.17).coerceAtLeast(0.0),
                    packetLoss = o.optDouble("packet_loss", 0.08).coerceAtLeast(0.0),
                    downloadSpeed = o.optDouble("download_speed", CentralScoringWeights.THROUGHPUT_WEIGHT).coerceAtLeast(0.0),
                    historicalUptime = o.optDouble("historical_uptime", 0.03).coerceAtLeast(0.0),
                    jitter = o.optDouble("jitter", 0.08).coerceAtLeast(0.0),
                    recentStability = o.optDouble("recent_stability", 0.03).coerceAtLeast(0.0),
                ).normalized()
            }.getOrDefault(SmartSelectionWeights())
        }
    }
}

enum class MeasurementConfidence(val labelAr: String, val labelEn: String) {
    HIGH("ثقة عالية (مقاس محليًا)", "High (Locally Verified)"),
    MEDIUM("ثقة متوسطة (قياسات جزئية)", "Medium (Partial Measurements)"),
    LOW("ثقة منخفضة (بيانات سحابية فقط)", "Low (Cloud Hint Only)"),
    INSUFFICIENT("بيانات غير كافية", "Insufficient Data");

    val displayLabel: String
        get() = tr(labelAr, labelEn)
}

data class SmartServerCandidateInput(
    val cfg: String,
    val label: String,
    val country: String = "",
    val isVip: Boolean = false,
    val available: Boolean = true,
    val localLatencyMs: Long = 0L,
    val localJitterMs: Double = 0.0,
    val localDownloadKbps: Double = 0.0,
    val localUploadKbps: Double = 0.0,
    val locallyTested: Boolean = false,
    val localFailed: Boolean = false,
    val lastTestedAtMs: Long = 0L,
    val securityAssessment: String = "Unknown",
    val riskLevel: String = "UNKNOWN",
    val cloudHint: ServerHint? = null,
    val localTelemetry: LocalServerTelemetry? = null,
) {
    val serverId: String
        get() = Converters.stableServerId(cfg)
}

data class ScoredSmartCandidate(
    val serverId: String,
    val cfg: String,
    val label: String,
    val score: Double,
    val effectiveLatencyMs: Long,
    val recentReliabilityPct: Double,
    val lastSuccessfulTestMs: Long,
    val confidencePct: Int,
    val confidenceLevel: MeasurementConfidence,
    val reasonsAr: List<String>,
    val reasonsEn: List<String>,
    val excludedCooldown: Boolean = false,
    val excludedSecurity: Boolean = false,
) {
    val displayReasons: List<String>
        get() = if (AppI18n.isEnglish) reasonsEn.ifEmpty { reasonsAr } else reasonsAr
}

data class SmartSelectionDecision(
    val primary: ScoredSmartCandidate?,
    val fallback: ScoredSmartCandidate?,
    val allRanked: List<ScoredSmartCandidate>,
)

object SmartServerSelector {

    const val FAILURE_COOLDOWN_MS: Long = 180_000L // 3 minutes temporary exclusion

    fun isHardExcludedBySecurity(cand: SmartServerCandidateInput): Boolean {
        if (!cand.available) return true
        val riskUp = cand.riskLevel.trim().uppercase()
        val secUp = cand.securityAssessment.trim().uppercase()
        if (riskUp in setOf("CRITICAL", "QUARANTINED") || secUp in setOf("FAILED", "QUARANTINED")) {
            return true
        }
        return !Tester.passesHardSecurityPreFilter(cand.cfg, isVipAttested = cand.isVip)
    }

    fun evaluateCandidate(
        cand: SmartServerCandidateInput,
        weights: SmartSelectionWeights = SmartSelectionWeights(),
        preferredCountry: String = "ALL",
        networkType: String = "WIFI",
        isMeteredNetwork: Boolean = false,
        recentlyProblematicIds: Set<String> = emptySet(),
        nowMs: Long = System.currentTimeMillis(),
        protocolBonus: (cfg: String) -> Double = { 0.0 },
    ): ScoredSmartCandidate {
        val w = weights.normalized()
        val sid = cand.serverId
        val tel = cand.localTelemetry
        val hint = cand.cloudHint

        // Hard Security Pre-Filter: exclude allowInsecure=1, Failed security, and QUARANTINED/CRITICAL configs outright
        if (isHardExcludedBySecurity(cand)) {
            return ScoredSmartCandidate(
                serverId = sid,
                cfg = cand.cfg,
                label = cand.label,
                score = 0.0,
                effectiveLatencyMs = 0L,
                recentReliabilityPct = 0.0,
                lastSuccessfulTestMs = tel?.lastSuccessAtMs ?: 0L,
                confidencePct = 0,
                confidenceLevel = MeasurementConfidence.INSUFFICIENT,
                reasonsAr = listOf("مستبعد أمنيًا: الإعداد غير آمن (allowInsecure أو فشل فحص الأمان)"),
                reasonsEn = listOf("Excluded by security pre-filter (allowInsecure or failed security verification)"),
                excludedCooldown = true,
                excludedSecurity = true,
            )
        }

        val lastFailAgo = if ((tel?.lastFailureAtMs ?: 0L) > 0L) nowMs - tel!!.lastFailureAtMs else Long.MAX_VALUE
        val inCooldown = cand.localFailed ||
            ((tel?.consecutiveFailures ?: 0) >= 2 && lastFailAgo in 0L until FAILURE_COOLDOWN_MS)

        // 1) Connection Reliability [0..100]
        val hasLocalHistory = (tel?.attempts ?: 0) > 0
        val hasCloudRel = (hint?.reliabilityScore ?: 0.0) > 0.0
        val rawSuccessPct = when {
            hasLocalHistory -> tel!!.successRate * 100.0
            cand.locallyTested && !cand.localFailed -> 92.0
            hasCloudRel -> (hint!!.reliabilityScore * 0.78).coerceIn(0.0, 82.0)
            else -> 0.0
        }
        val estabBonus = when {
            (tel?.avgEstablishMs ?: 0L) in 1L..900L -> 8.0
            (tel?.avgEstablishMs ?: 0L) in 901L..2200L -> 3.0
            (tel?.avgEstablishMs ?: 0L) > 3500L -> -8.0
            else -> 0.0
        }
        val recentFailPenalty = ((tel?.consecutiveFailures ?: 0) * 18.0).coerceAtMost(60.0)
        val reliabilityComp = (rawSuccessPct + estabBonus - recentFailPenalty).coerceIn(0.0, 100.0)

        // 2) Latency + Variance [0..100]
        val effLatMs = when {
            cand.localLatencyMs > 0L -> cand.localLatencyMs
            (tel?.ewmaLatencyMs ?: 0.0) > 0.0 -> tel!!.ewmaLatencyMs.roundToInt().toLong()
            (hint?.latencyMs ?: 0L) > 0L -> hint!!.latencyMs
            else -> 0L
        }
        val latStdDev = if ((tel?.latencyVarianceMs2 ?: 0.0) > 0.0) sqrt(tel!!.latencyVarianceMs2) else 0.0
        val latencyComp = if (effLatMs > 0L) {
            val baseLat = (((1200.0 - effLatMs.toDouble()) / (1200.0 - 35.0)) * 100.0).coerceIn(0.0, 100.0)
            val varPenalty = (latStdDev / 12.0).coerceAtMost(20.0)
            (baseLat - varPenalty).coerceIn(0.0, 100.0)
        } else {
            0.0
        }

        // 3) Packet Loss [0..100]
        val hasMeasuredLoss = hasLocalHistory || cand.locallyTested || hint != null
        val effLossPct = when {
            hasLocalHistory -> tel!!.ewmaPacketLossPct
            cand.locallyTested && !cand.localFailed -> 0.0
            hint != null -> hint.packetLossPct
            else -> -1.0
        }
        val packetLossComp = if (hasMeasuredLoss && effLossPct >= 0.0) {
            (100.0 - effLossPct * 2.5).coerceIn(0.0, 100.0)
        } else {
            0.0
        }

        // 4) Real Download Throughput [0..100] — STRICT 0.0 when unmeasured (no free credit!)
        // Strict network isolation: prefer local active-network download speed; cloud hint is heavily discounted when untested locally.
        val effDlKbps = when {
            cand.localDownloadKbps > 0.0 -> cand.localDownloadKbps
            cand.locallyTested && (tel?.bestDownloadKbps ?: 0.0) > 0.0 -> tel!!.bestDownloadKbps
            !cand.locallyTested && (hint?.speedKbps ?: 0.0) > 0.0 -> hint!!.speedKbps * 0.35
            else -> 0.0
        }
        val effUlKbps = maxOf(cand.localUploadKbps, tel?.bestUploadKbps ?: 0.0)
        val dlNorm = if (effDlKbps > 0.0) {
            ((ln(1.0 + effDlKbps / 128.0) / ln(1.0 + 12_000.0 / 128.0)) * 100.0).coerceIn(0.0, 100.0)
        } else 0.0
        val ulNorm = if (effUlKbps > 0.0) {
            ((ln(1.0 + effUlKbps / 128.0) / ln(1.0 + 6_000.0 / 128.0)) * 100.0).coerceIn(0.0, 100.0)
        } else 0.0
        val rawSpeedComp = if (effUlKbps > 0.0) (0.85 * dlNorm + 0.15 * ulNorm) else dlNorm
        // Guardrail: never select a server solely because of high speed if reliability < 45
        val speedComp = if (reliabilityComp < 45.0) minOf(rawSpeedComp, 25.0) else rawSpeedComp

        // 5) Historical Uptime [0..100]
        val hasUptime = hint != null && (hint.stabilityRuns > 0 || hint.verifiedAt.isNotBlank())
        val uptimeComp = when {
            hasUptime -> hint!!.uptimePct.coerceIn(0.0, 100.0)
            (tel?.successes ?: 0) >= 2 -> (tel!!.successRate * 100.0).coerceIn(0.0, 100.0)
            else -> 0.0
        }

        // 6) Jitter [0..100]
        val effJitter = when {
            cand.localJitterMs > 0.0 -> cand.localJitterMs
            (tel?.ewmaJitterMs ?: 0.0) > 0.0 -> tel!!.ewmaJitterMs
            (hint?.jitterMs ?: 0.0) > 0.0 -> hint!!.jitterMs
            cand.locallyTested && effLatMs in 1L..250L -> 18.0
            else -> -1.0
        }
        val jitterComp = if (effJitter >= 0.0) {
            ((1.0 - (effJitter / 220.0)).coerceIn(0.0, 1.0)) * 100.0
        } else 0.0

        // 7) Recent Stability & Trend [0..100]
        val stabRuns = (hint?.stabilityRuns ?: 0) + (tel?.successes?.coerceAtMost(5) ?: 0)
        val trendBonus = ((tel?.recentTrendDelta ?: 0.0) / 10.0).coerceIn(-15.0, 15.0)
        val stabilityComp = if (stabRuns > 0 || cand.locallyTested) {
            (((stabRuns.coerceAtMost(6) / 6.0) * 85.0) + trendBonus).coerceIn(0.0, 100.0)
        } else 0.0

        var weighted =
            w.downloadSpeed * speedComp +
                w.connectionReliability * reliabilityComp +
                w.packetLoss * packetLossComp +
                w.historicalUptime * uptimeComp +
                w.recentStability * stabilityComp +
                w.latency * latencyComp +
                w.jitter * jitterComp

        // 3-Hour Freshness TTL decay on stale local benchmarks
        val lastSuccMs = maxOf(cand.lastTestedAtMs, tel?.lastSuccessAtMs ?: 0L)
        if (lastSuccMs > 0L && nowMs > lastSuccMs) {
            val ageMs = nowMs - lastSuccMs
            if (ageMs > CentralScoringWeights.FRESHNESS_TTL_MS) {
                val extraHours = ((ageMs - CentralScoringWeights.FRESHNESS_TTL_MS) / 3_600_000.0).coerceAtMost(24.0)
                weighted *= (1.0 - (extraHours / 24.0) * 0.18)
            }
        }

        // Network compatibility & protocol suitability adjustment
        val scheme = Converters.schemeOf(cand.cfg)
        if (networkType.equals("CELLULAR", ignoreCase = true) || isMeteredNetwork) {
            if (scheme in setOf("hysteria2", "hy2", "vless")) weighted += 2.5
        }
        val netAffinity = if (networkType.equals("WIFI", ignoreCase = true)) {
            tel?.wifiSuccesses ?: 0
        } else {
            tel?.cellularSuccesses ?: 0
        }
        if (netAffinity >= 2) weighted += 3.0

        weighted += protocolBonus(cand.cfg)

        val cleanPref = preferredCountry.trim().uppercase()
        val candCc = cand.country.ifBlank { hint?.country.orEmpty() }.trim().uppercase()
        val geoMatched = cleanPref.isNotEmpty() && cleanPref != "ALL" && candCc == cleanPref
        if (geoMatched) {
            weighted += 8.0
        } else if (cleanPref.isNotEmpty() && cleanPref != "ALL" && candCc.isNotEmpty()) {
            weighted -= 12.0
        }

        if (cand.isVip) {
            weighted += 5.0
        }

        if (sid in recentlyProblematicIds) {
            weighted *= 0.45
        }
        if (inCooldown) {
            weighted *= 0.15
        }

        val finalScore = ((weighted.coerceIn(0.0, 100.0)) * 10.0).roundToInt() / 10.0

        // Measurement Confidence [0..100%] with 4-hour TTL staleness decay
        var conf = 0
        if (cand.locallyTested || (tel?.attempts ?: 0) >= 1) conf += 45
        if ((tel?.attempts ?: 0) >= 3) conf += 15
        if (cand.localDownloadKbps > 0.0 || (tel?.bestDownloadKbps ?: 0.0) > 0.0) conf += 22
        if (hint != null && hint.latencyMs > 0L) conf += 10
        if (hint != null && hint.stabilityRuns >= 2) conf += 8
        if (lastSuccMs > 0L && (nowMs - lastSuccMs) > CentralScoringWeights.FRESHNESS_TTL_MS) {
            conf -= 15
        }
        conf = conf.coerceIn(0, 100)

        val confLevel = when {
            conf >= 70 -> MeasurementConfidence.HIGH
            conf >= 45 -> MeasurementConfidence.MEDIUM
            conf >= 12 -> MeasurementConfidence.LOW
            else -> MeasurementConfidence.INSUFFICIENT
        }

        val reasonsAr = ArrayList<String>(4)
        val reasonsEn = ArrayList<String>(4)
        if (cand.isVip) {
            reasonsAr.add("عقدة VIP مخصّصة وموثّقة")
            reasonsEn.add("Attested dedicated VIP node")
        }
        if (effDlKbps >= 1024.0) {
            val mbps = ((effDlKbps * 8.0) / 1024.0 * 10.0).roundToInt() / 10.0
            reasonsAr.add("سرعة تنزيل فعلية ($mbps Mbps)")
            reasonsEn.add("Verified throughput ($mbps Mbps)")
        }
        if (reliabilityComp >= 80.0) {
            reasonsAr.add("موثوقية اتصال عالية (${reliabilityComp.roundToInt()}%)")
            reasonsEn.add("High connection reliability (${reliabilityComp.roundToInt()}%)")
        }
        if (effLatMs in 1L..180L) {
            reasonsAr.add("زمن استجابة منخفض (${effLatMs} ms)")
            reasonsEn.add("Low latency (${effLatMs} ms)")
        }
        if (geoMatched) {
            reasonsAr.add("مطابق للدولة المفضّلة ($candCc)")
            reasonsEn.add("Matches preferred country ($candCc)")
        }
        if (reasonsAr.isEmpty()) {
            reasonsAr.add("أفضل توازن متاح بين السرعة والاستقرار والاستجابة")
            reasonsEn.add("Best available speed, stability, and latency balance")
        }

        return ScoredSmartCandidate(
            serverId = sid,
            cfg = cand.cfg,
            label = cand.label,
            score = finalScore,
            effectiveLatencyMs = effLatMs,
            recentReliabilityPct = (reliabilityComp * 10.0).roundToInt() / 10.0,
            lastSuccessfulTestMs = lastSuccMs,
            confidencePct = conf,
            confidenceLevel = confLevel,
            reasonsAr = reasonsAr.take(3),
            reasonsEn = reasonsEn.take(3),
            excludedCooldown = inCooldown,
            excludedSecurity = false,
        )
    }

    fun selectBestAndFallback(
        candidates: List<SmartServerCandidateInput>,
        weights: SmartSelectionWeights = SmartSelectionWeights(),
        preferredCountry: String = "ALL",
        networkType: String = "WIFI",
        isMeteredNetwork: Boolean = false,
        recentlyProblematicIds: Set<String> = emptySet(),
        nowMs: Long = System.currentTimeMillis(),
        protocolBonus: (cfg: String) -> Double = { 0.0 },
    ): SmartSelectionDecision {
        if (candidates.isEmpty()) {
            return SmartSelectionDecision(null, null, emptyList())
        }
        val evaluated = candidates.map {
            evaluateCandidate(
                cand = it,
                weights = weights,
                preferredCountry = preferredCountry,
                networkType = networkType,
                isMeteredNetwork = isMeteredNetwork,
                recentlyProblematicIds = recentlyProblematicIds,
                nowMs = nowMs,
                protocolBonus = protocolBonus,
            )
        }.sortedWith(
            compareBy<ScoredSmartCandidate> { it.excludedSecurity }
                .thenBy { it.excludedCooldown }
                .thenByDescending { it.score }
                .thenBy { if (it.effectiveLatencyMs > 0L) it.effectiveLatencyMs else Long.MAX_VALUE }
                .thenBy { it.serverId }
        )

        val securitySafe = evaluated.filterNot { it.excludedSecurity }
        val eligible = securitySafe.filterNot { it.excludedCooldown && it.score <= 0.0 }
        val primary = eligible.firstOrNull() ?: securitySafe.firstOrNull()
        val fallback = eligible.firstOrNull { it.serverId != primary?.serverId }
            ?: securitySafe.firstOrNull { it.serverId != primary?.serverId }

        return SmartSelectionDecision(
            primary = primary,
            fallback = fallback,
            allRanked = evaluated,
        )
    }
}
