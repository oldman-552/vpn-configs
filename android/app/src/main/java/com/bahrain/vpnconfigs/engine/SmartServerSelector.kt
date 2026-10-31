// =====================================================================
// SmartServerSelector.kt — محرك الاختيار الذكي للسيرفرات (Part 2.1).
//
// المزايا الهندسية الصارمة:
//   • أوزان معيارية قابلة للتخصيص (الافتراضي: الموثوقية 25%، التأخير 20%، فقدان الحزم 15%،
//     سرعة التنزيل 15%، الجاهزية التاريخية 10%، التذبذب 10%، الاستقرار الحديث 5%).
//   • عدم معاملة القياسات الغائبة على أنها مثالية (تساهم بـ 0.0 مع خفض مؤشر الثقة).
//   • عدم اختيار سيرفر لمجرد سرعة معلنة مرتفعة إذا كانت موثوقيته أو أمانه متدنيين.
//   • استبعاد مؤقت للسيرفرات الفاشلة حديثًا ومنع تكرار اختيار السيرفر المتعثر نفسه.
//   • حتمي وقابل للتفسير الكامل (يعرض الدرجة، أسباب الاختيار، مستوى الثقة، والبديل الاحتياطي).
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

data class SmartSelectionWeights(
    val connectionReliability: Double = 0.25,
    val latency: Double = 0.20,
    val packetLoss: Double = 0.15,
    val downloadSpeed: Double = 0.15,
    val historicalUptime: Double = 0.10,
    val jitter: Double = 0.10,
    val recentStability: Double = 0.05,
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
                    connectionReliability = o.optDouble("connection_reliability", 0.25).coerceAtLeast(0.0),
                    latency = o.optDouble("latency", 0.20).coerceAtLeast(0.0),
                    packetLoss = o.optDouble("packet_loss", 0.15).coerceAtLeast(0.0),
                    downloadSpeed = o.optDouble("download_speed", 0.15).coerceAtLeast(0.0),
                    historicalUptime = o.optDouble("historical_uptime", 0.10).coerceAtLeast(0.0),
                    jitter = o.optDouble("jitter", 0.10).coerceAtLeast(0.0),
                    recentStability = o.optDouble("recent_stability", 0.05).coerceAtLeast(0.0),
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

    fun evaluateCandidate(
        cand: SmartServerCandidateInput,
        weights: SmartSelectionWeights = SmartSelectionWeights(),
        preferredCountry: String = "ALL",
        networkType: String = "WIFI",
        isMeteredNetwork: Boolean = false,
        recentlyProblematicIds: Set<String> = emptySet(),
        nowMs: Long = System.currentTimeMillis(),
    ): ScoredSmartCandidate {
        val w = weights.normalized()
        val sid = cand.serverId
        val tel = cand.localTelemetry
        val hint = cand.cloudHint

        if (!cand.available || cand.riskLevel == "CRITICAL") {
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
                reasonsAr = listOf("مستبعد: السيرفر غير متاح أو مصنّف بمخاطر أمنية حرجة"),
                reasonsEn = listOf("Excluded: Server unavailable or critical security risk"),
                excludedCooldown = true,
            )
        }

        val lastFailAgo = if ((tel?.lastFailureAtMs ?: 0L) > 0L) nowMs - tel!!.lastFailureAtMs else Long.MAX_VALUE
        val inCooldown = cand.localFailed ||
            ((tel?.consecutiveFailures ?: 0) >= 2 && lastFailAgo in 0L until FAILURE_COOLDOWN_MS)

        // 1) Connection Reliability [0..100] (actual success rate + establishment time + failure penalty)
        val hasLocalHistory = (tel?.attempts ?: 0) > 0
        val hasCloudRel = (hint?.reliabilityScore ?: 0.0) > 0.0
        val rawSuccessPct = when {
            hasLocalHistory -> tel!!.successRate * 100.0
            cand.locallyTested && !cand.localFailed -> 92.0
            hasCloudRel -> (hint!!.reliabilityScore * 0.78).coerceIn(0.0, 82.0) // Unverified locally -> conservative cap
            else -> 0.0 // Missing measurement NOT treated as perfect!
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
            0.0 // Missing latency NOT treated as 0ms!
        }

        // 3) Packet Loss [0..100] (only measured packet loss earns score; unmeasured gets 0.0!)
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

        // 4) Download + Upload Throughput [0..100] (capped contribution when reliability is weak so fast-flaky servers cannot win)
        val effDlKbps = maxOf(cand.localDownloadKbps, tel?.bestDownloadKbps ?: 0.0, (hint?.speedKbps ?: 0.0) * 0.65)
        val effUlKbps = maxOf(cand.localUploadKbps, tel?.bestUploadKbps ?: 0.0)
        val dlNorm = if (effDlKbps > 0.0) {
            ((ln(1.0 + effDlKbps / 128.0) / ln(1.0 + 12_000.0 / 128.0)) * 100.0).coerceIn(0.0, 100.0)
        } else 0.0
        val ulNorm = if (effUlKbps > 0.0) {
            ((ln(1.0 + effUlKbps / 128.0) / ln(1.0 + 6_000.0 / 128.0)) * 100.0).coerceIn(0.0, 100.0)
        } else 0.0
        val rawSpeedComp = if (effUlKbps > 0.0) (0.80 * dlNorm + 0.20 * ulNorm) else dlNorm
        // Guardrail: never select a server solely because of high speed if reliability < 45
        val speedComp = if (reliabilityComp < 45.0) minOf(rawSpeedComp, 40.0) else rawSpeedComp

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
            w.connectionReliability * reliabilityComp +
                w.latency * latencyComp +
                w.packetLoss * packetLossComp +
                w.downloadSpeed * speedComp +
                w.historicalUptime * uptimeComp +
                w.jitter * jitterComp +
                w.recentStability * stabilityComp

        // Network compatibility & protocol suitability adjustment
        val scheme = Converters.schemeOf(cand.cfg)
        if (networkType.equals("CELLULAR", ignoreCase = true) || isMeteredNetwork) {
            // QUIC/Hysteria2 & Reality handle mobile NAT rebinding well, while metered links slightly penalize high loss
            if (scheme in setOf("hysteria2", "hy2", "vless")) weighted += 2.5
        }
        val netAffinity = if (networkType.equals("WIFI", ignoreCase = true)) {
            tel?.wifiSuccesses ?: 0
        } else {
            tel?.cellularSuccesses ?: 0
        }
        if (netAffinity >= 2) weighted += 3.0

        // Geographic preference bonus/filter
        val cleanPref = preferredCountry.trim().uppercase()
        val candCc = cand.country.ifBlank { hint?.country.orEmpty() }.trim().uppercase()
        val geoMatched = cleanPref.isNotEmpty() && cleanPref != "ALL" && candCc == cleanPref
        if (geoMatched) {
            weighted += 8.0
        } else if (cleanPref.isNotEmpty() && cleanPref != "ALL" && candCc.isNotEmpty()) {
            weighted -= 12.0
        }

        // Security hygiene adjustment: penalize Failed/HIGH-risk configs so safe peers win
        if (cand.securityAssessment == "Failed" || cand.riskLevel == "HIGH") {
            weighted *= 0.55
        } else if (cand.isVip) {
            weighted += 5.0
        }

        // Anti-repeat problematic server penalty & cooldown suppression
        if (sid in recentlyProblematicIds) {
            weighted *= 0.45
        }
        if (inCooldown) {
            weighted *= 0.15
        }

        val finalScore = ((weighted.coerceIn(0.0, 100.0)) * 10.0).roundToInt() / 10.0

        // Measurement Confidence [0..100%]
        var conf = 0
        if (cand.locallyTested || (tel?.attempts ?: 0) >= 1) conf += 45
        if ((tel?.attempts ?: 0) >= 3) conf += 20
        if (cand.localDownloadKbps > 0.0 || (tel?.bestDownloadKbps ?: 0.0) > 0.0) conf += 15
        if (hint != null && hint.latencyMs > 0L) conf += 12
        if (hint != null && hint.stabilityRuns >= 2) conf += 8
        conf = conf.coerceIn(0, 100)

        val confLevel = when {
            conf >= 70 -> MeasurementConfidence.HIGH
            conf >= 45 -> MeasurementConfidence.MEDIUM
            conf >= 12 -> MeasurementConfidence.LOW
            else -> MeasurementConfidence.INSUFFICIENT
        }

        // Deterministic, human-readable selection reasons
        val reasonsAr = ArrayList<String>(4)
        val reasonsEn = ArrayList<String>(4)
        if (cand.isVip) {
            reasonsAr.add("عقدة VIP مخصّصة وموثّقة")
            reasonsEn.add("Attested dedicated VIP node")
        }
        if (reliabilityComp >= 80.0) {
            reasonsAr.add("موثوقية اتصال عالية (${reliabilityComp.roundToInt()}%)")
            reasonsEn.add("High connection reliability (${reliabilityComp.roundToInt()}%)")
        }
        if (effLatMs in 1L..180L) {
            reasonsAr.add("زمن استجابة منخفض (${effLatMs} ms)")
            reasonsEn.add("Low latency (${effLatMs} ms)")
        }
        if (effDlKbps >= 1024.0) {
            val mbps = ((effDlKbps * 8.0) / 1024.0 * 10.0).roundToInt() / 10.0
            reasonsAr.add("سرعة تنزيل مقاسة ($mbps Mbps)")
            reasonsEn.add("Verified throughput ($mbps Mbps)")
        }
        if (geoMatched) {
            reasonsAr.add("مطابق للدولة المفضّلة ($candCc)")
            reasonsEn.add("Matches preferred country ($candCc)")
        }
        if (reasonsAr.isEmpty()) {
            reasonsAr.add("أفضل توازن متاح بين الاستقرار والاستجابة")
            reasonsEn.add("Best available stability and latency balance")
        }

        val lastSuccMs = maxOf(cand.lastTestedAtMs, tel?.lastSuccessAtMs ?: 0L)

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
            )
        }.sortedWith(
            compareBy<ScoredSmartCandidate> { it.excludedCooldown }
                .thenByDescending { it.score }
                .thenBy { if (it.effectiveLatencyMs > 0L) it.effectiveLatencyMs else Long.MAX_VALUE }
                .thenBy { it.serverId }
        )

        val eligible = evaluated.filterNot { it.excludedCooldown && it.score <= 0.0 }
        val primary = eligible.firstOrNull() ?: evaluated.firstOrNull()
        val fallback = eligible.firstOrNull { it.serverId != primary?.serverId }
            ?: evaluated.firstOrNull { it.serverId != primary?.serverId }

        return SmartSelectionDecision(
            primary = primary,
            fallback = fallback,
            allRanked = evaluated,
        )
    }
}
