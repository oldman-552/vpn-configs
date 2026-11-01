// =====================================================================
// Repo.kt — تنزيل القائمة الحيّة الغنية بالمؤشرات (alive.json + القوائم المتخصّصة)
// مع التخزين المؤقت التدريجي (ETag / 304) والحماية من المدخلات المشوّهة أو الضخمة.
// يحافظ بالكامل على الاتصال بالمستودع الحالي وتحديثاته دون كشف تفاصيل المصدر للواجهة.
// =====================================================================
package com.bahrain.vpnconfigs.data

import android.content.ContentValues
import android.content.Context
import android.os.Build
import android.os.Environment
import android.os.SystemClock
import android.provider.MediaStore
import android.util.Base64
import com.bahrain.vpnconfigs.engine.Converters
import com.bahrain.vpnconfigs.engine.SingBox
import com.bahrain.vpnconfigs.engine.TestResult
import com.bahrain.vpnconfigs.util.AppDiag
import com.bahrain.vpnconfigs.util.UiMessages
import com.bahrain.vpnconfigs.util.tr
import com.bahrain.vpnconfigs.vpn.VpnStateManager
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import java.security.MessageDigest
import java.util.Locale

data class DeadConfigPurgeDecision(
    val shouldPurge: Boolean,
    val offlineGuardTriggered: Boolean,
    val purgeableCleanUris: Set<String>,
    val remainingPool: List<String>,
)

object DeadConfigPurgePolicy {
    const val OFFLINE_GUARD_MIN_BATCH: Int = 15
    const val PURGE_TTL_MS: Long = 4L * 3_600_000L

    /**
     * يحسم الحذف التلقائي الفوري للكونفقات غير الشغّالة وفق الضوابط الثلاثة الصارمة:
     *   1) حماية انقطاع إنترنت الهاتف (Offline Guard): إذا كان الهاتف بلا إنترنت أو فشل 100% من دفعة >= 15 كونفيق،
     *      لا يُحذف أي سيرفر محفوظ (Last Known Good).
     *   2) حماية المفضّلة (⭐) وعقد VIP الموثّقة: لا تُحذف تلقائيًا أبدًا.
     *   3) حذف فوري لكافة الكونفقات العامة الفاشلة حتى تبقى القائمة صافية 100%.
     */
    fun evaluate(
        currentPool: List<String>,
        failedUris: Set<String>,
        testedCount: Int,
        aliveCount: Int,
        deviceOnline: Boolean = true,
        favoriteCleanUris: Set<String> = emptySet(),
        favoriteServerIds: Set<String> = emptySet(),
        vipCleanUris: Set<String> = emptySet(),
    ): DeadConfigPurgeDecision {
        val offlineSuspected = !deviceOnline || (testedCount >= OFFLINE_GUARD_MIN_BATCH && aliveCount == 0)
        if (offlineSuspected || failedUris.isEmpty()) {
            return DeadConfigPurgeDecision(
                shouldPurge = false,
                offlineGuardTriggered = offlineSuspected,
                purgeableCleanUris = emptySet(),
                remainingPool = currentPool,
            )
        }

        val failedClean = failedUris.map { Converters.cleanUri(it) }.filter { it.isNotBlank() }.toHashSet()
        val purgeable = LinkedHashSet<String>()
        for (c in failedClean) {
            val sid = Converters.stableServerId(c)
            val isProtected = c in favoriteCleanUris || c in vipCleanUris || (sid.isNotBlank() && sid in favoriteServerIds)
            if (!isProtected) {
                purgeable.add(c)
            }
        }
        if (purgeable.isEmpty()) {
            return DeadConfigPurgeDecision(
                shouldPurge = false,
                offlineGuardTriggered = false,
                purgeableCleanUris = emptySet(),
                remainingPool = currentPool,
            )
        }

        val purgeableIds = purgeable.mapNotNull { Converters.stableServerId(it).takeIf { id -> id.isNotBlank() } }.toHashSet()
        val remaining = currentPool.filterNot { raw ->
            val clean = Converters.cleanUri(raw)
            val sid = Converters.stableServerId(clean)
            clean in purgeable || (sid.isNotBlank() && sid in purgeableIds)
        }
        // Safety floor: if somehow every single config in currentPool would become empty while aliveCount == 0, keep LKG
        if (remaining.isEmpty() && aliveCount == 0 && currentPool.isNotEmpty()) {
            return DeadConfigPurgeDecision(
                shouldPurge = false,
                offlineGuardTriggered = true,
                purgeableCleanUris = emptySet(),
                remainingPool = currentPool,
            )
        }

        return DeadConfigPurgeDecision(
            shouldPurge = true,
            offlineGuardTriggered = false,
            purgeableCleanUris = purgeable,
            remainingPool = remaining,
        )
    }
}

data class RemoteMeta(
    val generatedAt: String = "—",
    val alive: Int = 0,
    val tested: Int = 0,
    val channelsOk: Int = 0,
    val channelsTotal: Int = 0,
    val byProtocol: Map<String, Int> = emptyMap(),
    val byCountry: Map<String, Int> = emptyMap(),
    val degradedMode: Boolean = false,
)

data class ServerHint(
    val latencyMs: Long = 0L,
    val jitterMs: Double = 0.0,
    val speedKbps: Double = 0.0,
    val score: Double = 0.0,
    val performanceScore: Double = 0.0,
    val reliabilityScore: Double = 0.0,
    val securityAssessment: String = "",
    val privacyAssessment: String = "",
    val riskLevel: String = "",
    val packetLossPct: Double = 0.0,
    val uptimePct: Double = 100.0,
    val country: String = "",
    val stabilityRuns: Int = 0,
    val verifiedAt: String = "",
)

data class ResultLine(
    val cfg: String,
    val latencyMs: Long,
    val speedKbps: Double,
    val testedAtMs: Long = System.currentTimeMillis(),
)

data class Top500ServerEntry(
    val centralRank: Int,
    val serverId: String,
    val configFingerprint: String,
    val cfg: String,
    val protocol: String = "",
    val country: String = "",
    val preliminaryLatencyMs: Long = 0L,
    val centralQualityScore: Double = 0.0,
    val stabilityRuns: Int = 0,
    val securityAssessment: String = "",
    val privacyAssessment: String = "",
    val riskLevel: String = "",
    val trustPosture: String = "UNTRUSTED_PUBLIC_SERVER",
)

data class Top500SyncOutcome(
    val datasetVersion: Long,
    val generatedAt: String,
    val generatedAtEpoch: Long,
    val configsSha256: String,
    val qualifiedCount: Int,
    val servers: List<Top500ServerEntry>,
    val liveSuccess: Boolean,
    val incrementalApplied: Boolean = false,
    val notModified304: Boolean = false,
    val rollbackRejected: Boolean = false,
    val checksumVerified: Boolean = true,
    val recoveredFromLastValid: Boolean = false,
    val error: String? = null,
)

data class LoadResult(
    val configs: List<String>,
    val serverLatencies: Map<String, Long>,
    val meta: RemoteMeta,
    val source: String,
    val error: String? = null,
    val serverHints: Map<String, ServerHint> = emptyMap(),
    val fromCacheFallback: Boolean = false,
    val datasetVersion: Long = 0L,
    val datasetConfigsSha256: String = "",
    val serverFingerprints: Map<String, String> = emptyMap(),
    val incrementalApplied: Boolean = false,
    val rollbackRejected: Boolean = false,
    val recoveredFromLastValid: Boolean = false,
)

class Repo(
    private val ctx: Context,
    private val owner: String = DEFAULT_OWNER,
    private val repo: String = DEFAULT_REPO,
    private val mirrorOverride: ((String) -> List<String>)? = null,
    private val httpTimeoutMs: Int = 20000,
) {

    private val dir = File(ctx.filesDir, "data").apply { mkdirs() }

    private fun candidates(file: String): List<String> =
        mirrorOverride?.invoke(file) ?: listOf(
            "https://cdn.jsdelivr.net/gh/$owner/$repo@data/$file",
            "https://raw.githubusercontent.com/$owner/$repo/data/$file",
            "https://$owner.github.io/$repo/$file",
        )

    private data class HttpResp(
        val status: Int,
        val body: String? = null,
        val etag: String? = null,
    )

    private data class FetchResult(
        val body: String,
        val liveSuccess: Boolean,
    )

    /** قراءة HTTP محدودة الحجم مع دعم If-None-Match لتوفير استهلاك البيانات والزمن. */
    private fun httpGetBounded(url: String, etag: String?, timeoutMs: Int = httpTimeoutMs): HttpResp? {
        var conn: HttpURLConnection? = null
        return try {
            conn = (URL(url).openConnection() as HttpURLConnection).apply {
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                requestMethod = "GET"
                setRequestProperty("User-Agent", "bahrain-vpn/2.4")
                if (!etag.isNullOrBlank()) {
                    setRequestProperty("If-None-Match", etag)
                }
                instanceFollowRedirects = true
            }
            val code = conn.responseCode
            if (conn.date > 0L) {
                com.bahrain.vpnconfigs.enterprise.EnterpriseClock.recordNetworkUtc(conn.date)
            }
            if (code == HttpURLConnection.HTTP_NOT_MODIFIED) {
                return HttpResp(status = 304, etag = conn.getHeaderField("ETag") ?: etag)
            }
            if (code !in 200..299) {
                AppDiag.d("Repo", "mirror returned HTTP $code")
                return null
            }
            val contentLength = conn.contentLengthLong
            if (contentLength > MAX_BODY_BYTES) return null

            val sb = StringBuilder()
            conn.inputStream.bufferedReader(Charsets.UTF_8).use { reader ->
                val buf = CharArray(8192)
                var read: Int
                while (reader.read(buf).also { read = it } != -1) {
                    if (sb.length + read > MAX_BODY_CHARS) break
                    sb.append(buf, 0, read)
                }
            }
            HttpResp(status = code, body = sb.toString(), etag = conn.getHeaderField("ETag"))
        } catch (e: Exception) {
            AppDiag.w("Repo", "mirror fetch failed", e)
            null
        } finally {
            conn?.disconnect()
        }
    }

    private fun writeAtomic(target: File, content: String) {
        target.parentFile?.mkdirs()
        val tmp = File(target.parentFile, "${target.name}.tmp")
        tmp.writeText(content, Charsets.UTF_8)
        if (!tmp.renameTo(target)) {
            target.writeText(content, Charsets.UTF_8)
            tmp.delete()
        }
    }

    /** يجلب ملفًا مع دعم ETag ويعود للكاش المحلي تلقائيًا عند انقطاع الشبكة مع تمييز نجاح الجلب الحي. */
    private fun fetch(file: String): FetchResult? {
        val cachedFile = File(dir, file)
        val etagFile = File(dir, "$file.etag")
        val savedEtag = if (cachedFile.exists() && etagFile.exists()) {
            runCatching { etagFile.readText(Charsets.UTF_8).trim() }.getOrNull()
        } else null

        for (url in candidates(file)) {
            val resp = httpGetBounded(url, savedEtag)
            if (resp != null) {
                if (resp.status == 304 && cachedFile.exists()) {
                    val cachedBody = runCatching { cachedFile.readText(Charsets.UTF_8) }.getOrNull()
                    if (!cachedBody.isNullOrBlank()) {
                        return FetchResult(body = cachedBody, liveSuccess = true)
                    }
                }
                if (!resp.body.isNullOrBlank()) {
                    writeAtomic(cachedFile, resp.body)
                    if (!resp.etag.isNullOrBlank()) {
                        writeAtomic(etagFile, resp.etag)
                    }
                    return FetchResult(body = resp.body, liveSuccess = true)
                }
            }
        }
        if (cachedFile.exists()) {
            val fallbackBody = runCatching { cachedFile.readText(Charsets.UTF_8) }.getOrNull()
            if (!fallbackBody.isNullOrBlank()) {
                return FetchResult(body = fallbackBody, liveSuccess = false)
            }
        }
        return null
    }

    fun parseMeta(json: String?): RemoteMeta {
        if (json.isNullOrBlank()) return RemoteMeta()
        return try {
            val o = JSONObject(json)
            val byProto = LinkedHashMap<String, Int>()
            o.optJSONObject("alive_by_protocol")?.let { p ->
                p.keys().forEach { k -> byProto[k] = p.optInt(k) }
            }
            val byCountry = LinkedHashMap<String, Int>()
            o.optJSONObject("countries_summary")?.let { c ->
                c.keys().forEach { k -> byCountry[k] = c.optInt(k) }
            }
            RemoteMeta(
                generatedAt = o.optString("generated_at", "—"),
                alive = o.optInt("alive", 0),
                tested = o.optInt("tested", 0),
                channelsOk = o.optInt("channels_ok", 0),
                channelsTotal = o.optInt("channels_total", 0),
                byProtocol = byProto,
                byCountry = byCountry,
                degradedMode = o.optBoolean("degraded_mode", false),
            )
        } catch (_: Exception) {
            RemoteMeta()
        }
    }

    /** تحليل alive.json الغني بالمؤشرات (يدعم صيغة الكائن {"servers":[...]} وصيغة المصفوفة [...]). */
    private fun parseAliveJson(rawJson: String): Pair<List<String>, Map<String, ServerHint>> {
        val cfgs = LinkedHashSet<String>()
        val hints = HashMap<String, ServerHint>()
        runCatching {
            val trimmed = rawJson.trim()
            val arr: JSONArray = if (trimmed.startsWith("[")) {
                JSONArray(trimmed)
            } else {
                JSONObject(trimmed).optJSONArray("servers") ?: JSONArray()
            }
            for (i in 0 until minOf(arr.length(), MAX_PARSED_SERVERS)) {
                val item = arr.optJSONObject(i) ?: continue
                val rawUri = item.optString("cfg").ifBlank { item.optString("uri") }
                if (!rawUri.contains("://")) continue
                val cleaned = Converters.cleanUri(rawUri)
                if (!cleaned.contains("://") || !Converters.isSupported(cleaned)) continue
                cfgs.add(cleaned)
                val cc = item.optString("exit_country", "").uppercase().let {
                    if (it == "XX" || it.length != 2) "" else it
                }
                hints.putIfAbsent(
                    cleaned,
                    ServerHint(
                        latencyMs = item.optLong("median_latency_ms", item.optLong("latency_ms", 0L)).coerceAtLeast(0L),
                        jitterMs = item.optDouble("jitter_ms", 0.0).let { if (it.isNaN()) 0.0 else it },
                        speedKbps = item.optDouble("speed_kbps", 0.0).let { if (it.isNaN()) 0.0 else it },
                        score = item.optDouble("score", 0.0).let { if (it.isNaN()) 0.0 else it },
                        performanceScore = item.optDouble("performance_score", item.optDouble("score", 0.0)).let { if (it.isNaN()) 0.0 else it },
                        reliabilityScore = item.optDouble("reliability_score", item.optDouble("score", 0.0)).let { if (it.isNaN()) 0.0 else it },
                        securityAssessment = item.optString("security_assessment", ""),
                        privacyAssessment = item.optString("privacy_assessment", ""),
                        riskLevel = item.optString("risk_level", ""),
                        packetLossPct = item.optDouble("packet_loss_pct", 0.0).let { if (it.isNaN()) 0.0 else it },
                        uptimePct = item.optDouble("uptime_pct", 100.0).let { if (it.isNaN()) 100.0 else it },
                        country = cc,
                        stabilityRuns = item.optInt("stability_runs", item.optInt("consecutive_alive", 0)),
                        verifiedAt = item.optString("verified_at", ""),
                    ),
                )
            }
        }.onFailure { err ->
            AppDiag.w("Repo", "parseAliveJson ignored malformed payload", err)
        }
        return cfgs.toList() to hints
    }

    /** قراءة الأسطر النصية بمرونة واستخلاص زمن الاستجابة والدولة من الوسم إن وُجدا مع تجاهل التالف بأمان. */
    private fun parseConfigLinesWithHints(rawText: String): Pair<List<String>, Map<String, ServerHint>> {
        val cfgs = LinkedHashSet<String>()
        val hints = HashMap<String, ServerHint>()
        val msRegex = Regex("(\\d+)\\s*ms", RegexOption.IGNORE_CASE)
        val ccRegex = Regex("\\b([A-Z]{2})\\b")
        var count = 0
        for (rawLine in rawText.lineSequence()) {
            if (count >= MAX_PARSED_SERVERS) break
            val trimmed = rawLine.trim()
            if (!trimmed.contains("://")) continue
            val cleaned = Converters.cleanUri(trimmed)
            if (!cleaned.contains("://") || !Converters.isSupported(cleaned)) continue
            cfgs.add(cleaned)
            count++
            val remark = Converters.extractRemark(trimmed)
            val ms = msRegex.find(remark)?.groupValues?.getOrNull(1)?.toLongOrNull() ?: 0L
            val cc = ccRegex.findAll(remark)
                .map { it.groupValues[1] }
                .firstOrNull { it !in setOf("MS", "KB", "MB", "SS", "WS") }
                ?: ""
            if (ms > 0 || cc.isNotEmpty()) {
                hints.putIfAbsent(cleaned, ServerHint(latencyMs = ms, country = cc))
            }
        }
        return cfgs.toList() to hints
    }

    /** قراءة الكاش المحلي فورًا عند فتح التطبيق بدون طلب شبكي (مع تفضيل نسخة Top-500 الصالحة والمحقّقة). */
    fun loadCached(feedProfile: String = "smart"): LoadResult? {
        val metaFile = File(dir, "meta.json")
        val meta = if (metaFile.exists()) parseMeta(runCatching { metaFile.readText(Charsets.UTF_8) }.getOrNull()) else RemoteMeta()

        if (feedProfile == "smart") {
            val localTop500 = loadLastValidTop500Dataset()
            if (localTop500 != null && localTop500.servers.isNotEmpty()) {
                return top500OutcomeToLoadResult(localTop500, meta, forceCacheSource = true)
            }
        }
        communityProfileCountrySlug(feedProfile)?.let { slug ->
            val commJson = File(dir, "$slug-top500.json")
            if (commJson.exists()) {
                val (cCfgs, cHints) = parseCommunityTop500Json(runCatching { commJson.readText(Charsets.UTF_8) }.getOrDefault(""))
                if (cCfgs.isNotEmpty()) {
                    return LoadResult(
                        configs = cCfgs,
                        serverLatencies = cHints.mapValues { it.value.latencyMs }.filterValues { it > 0L },
                        meta = meta,
                        source = "cache",
                        serverHints = cHints,
                        fromCacheFallback = true,
                    )
                }
            }
        }

        val jsonFile = File(dir, "alive.json")
        val jsonPair = if (jsonFile.exists()) {
            parseAliveJson(runCatching { jsonFile.readText(Charsets.UTF_8) }.getOrDefault(""))
        } else emptyList<String>() to emptyMap()

        val profileFile = profileFileName(feedProfile)
        if (profileFile != "alive.json") {
            val pf = File(dir, profileFile)
            if (pf.exists()) {
                val (pCfgs, pHints) = parseConfigLinesWithHints(runCatching { pf.readText(Charsets.UTF_8) }.getOrDefault(""))
                if (pCfgs.isNotEmpty()) {
                    val mergedHints = HashMap(pHints).apply { putAll(jsonPair.second) }
                    return LoadResult(
                        configs = pCfgs,
                        serverLatencies = mergedHints.mapValues { it.value.latencyMs }.filterValues { it > 0L },
                        meta = meta,
                        source = "cache",
                        serverHints = mergedHints,
                        fromCacheFallback = true,
                    )
                }
            }
        }

        if (jsonPair.first.isNotEmpty()) {
            return LoadResult(
                configs = jsonPair.first,
                serverLatencies = jsonPair.second.mapValues { it.value.latencyMs }.filterValues { it > 0L },
                meta = meta,
                source = "cache",
                serverHints = jsonPair.second,
                fromCacheFallback = true,
            )
        }

        val listFile = File(dir, "alive.txt")
        if (!listFile.exists()) return null
        val (cfgs, hints) = parseConfigLinesWithHints(runCatching { listFile.readText(Charsets.UTF_8) }.getOrDefault(""))
        if (cfgs.isEmpty()) return null
        return LoadResult(
            configs = cfgs,
            serverLatencies = hints.mapValues { it.value.latencyMs }.filterValues { it > 0L },
            meta = meta,
            source = "cache",
            serverHints = hints,
            fromCacheFallback = true,
        )
    }

    private fun communityProfileCountrySlug(profile: String): String? = when (profile) {
        "iran_community" -> "iran"
        "germany_community" -> "germany"
        "france_community" -> "france"
        "turkey_community" -> "turkey"
        "russia_community" -> "russia"
        else -> null
    }

    private fun parseCommunityTop500Json(rawJson: String): Pair<List<String>, Map<String, ServerHint>> {
        val cfgs = LinkedHashSet<String>()
        val hints = HashMap<String, ServerHint>()
        runCatching {
            val root = JSONObject(rawJson.trim())
            val countryIso = root.optString("country_code", "").uppercase().let {
                if (it.length == 2 && it != "XX") it else ""
            }
            val arr = root.optJSONArray("servers") ?: JSONArray()
            for (i in 0 until minOf(arr.length(), MAX_TOP500_CAPACITY)) {
                val item = arr.optJSONObject(i) ?: continue
                val rawUri = item.optString("cfg").ifBlank { item.optString("uri") }
                if (!rawUri.contains("://")) continue
                val cleaned = Converters.cleanUri(rawUri)
                if (!cleaned.contains("://") || !Converters.isSupported(cleaned)) continue
                cfgs.add(cleaned)
                val srvCc = item.optString("exit_country", countryIso).uppercase().let {
                    if (it.length == 2 && it != "XX") it else countryIso
                }
                hints.putIfAbsent(
                    cleaned,
                    ServerHint(
                        latencyMs = item.optLong("median_latency_ms", item.optLong("latency_ms", 0L)).coerceAtLeast(0L),
                        speedKbps = item.optDouble("median_speed_kbps", item.optDouble("speed_kbps", 0.0)).coerceAtLeast(0.0),
                        score = item.optDouble("trust_score", item.optDouble("score", 0.0)).coerceAtLeast(0.0),
                        performanceScore = item.optDouble("trust_score", 0.0).coerceAtLeast(0.0),
                        reliabilityScore = (item.optDouble("success_rate", 0.0) * 100.0).coerceIn(0.0, 100.0),
                        securityAssessment = item.optString("security_assessment", ""),
                        privacyAssessment = item.optString("privacy_assessment", ""),
                        riskLevel = item.optString("risk_level", ""),
                        country = srvCc,
                        stabilityRuns = item.optInt("distinct_reporters", 1).coerceAtLeast(1),
                        verifiedAt = item.optString("last_verified_at", root.optString("generated_at", "")),
                    ),
                )
            }
        }
        return cfgs.toList() to hints
    }

    private fun profileFileName(profile: String): String = when (profile) {
        "reliable" -> "reliable.txt"
        "low_latency" -> "low_latency.txt"
        "high_throughput" -> "high_throughput.txt"
        "privacy_aware" -> "privacy_aware.txt"
        "iran_community" -> "iran-top500.txt"
        "germany_community" -> "germany-top500.json"
        "france_community" -> "france-top500.json"
        "turkey_community" -> "turkey-top500.json"
        "russia_community" -> "russia-top500.json"
        else -> "alive.json"
    }

    /** تنزيل القائمة الحيّة + حزمة المرشّحين المركزية Top-500 مع التحقق من البصمات وحماية التراجع واستعادة آخر نسخة صالحة. */
    fun loadRemote(feedProfile: String = "smart"): LoadResult {
        val metaRaw = fetch("meta.json")
        val meta = parseMeta(metaRaw?.body)

        if (feedProfile == "smart") {
            val top500 = syncTop500Dataset()
            if (top500 != null && top500.servers.isNotEmpty()) {
                return top500OutcomeToLoadResult(top500, meta, forceCacheSource = false)
            }
        }
        communityProfileCountrySlug(feedProfile)?.let { slug ->
            val commRaw = fetch("$slug-top500.json")
            if (commRaw != null) {
                val (cCfgs, cHints) = parseCommunityTop500Json(commRaw.body)
                if (cCfgs.isNotEmpty()) {
                    return LoadResult(
                        configs = cCfgs,
                        serverLatencies = cHints.mapValues { it.value.latencyMs }.filterValues { it > 0L },
                        meta = meta,
                        source = if (commRaw.liveSuccess) "remote" else "cache",
                        error = if (commRaw.liveSuccess) null else UiMessages.MSG_UPDATE_FAILED,
                        serverHints = cHints,
                        fromCacheFallback = !commRaw.liveSuccess,
                    )
                }
            }
        }

        val jsonRaw = fetch("alive.json")
        val jsonParsed = if (jsonRaw != null) parseAliveJson(jsonRaw.body) else (emptyList<String>() to emptyMap())

        val targetFile = profileFileName(feedProfile)
        if (targetFile != "alive.json") {
            val specialRaw = fetch(targetFile)
            if (specialRaw != null) {
                val (sCfgs, sHints) = parseConfigLinesWithHints(specialRaw.body)
                if (sCfgs.isNotEmpty()) {
                    val mergedHints = HashMap(sHints).apply { putAll(jsonParsed.second) }
                    val liveOk = specialRaw.liveSuccess || (jsonRaw?.liveSuccess == true)
                    return LoadResult(
                        configs = sCfgs,
                        serverLatencies = mergedHints.mapValues { it.value.latencyMs }.filterValues { it > 0L },
                        meta = meta,
                        source = if (liveOk) "remote" else "cache",
                        error = if (liveOk) null else UiMessages.MSG_UPDATE_FAILED,
                        serverHints = mergedHints,
                        fromCacheFallback = !liveOk,
                    )
                }
            }
        }

        if (jsonParsed.first.isNotEmpty()) {
            val liveOk = jsonRaw?.liveSuccess == true
            return LoadResult(
                configs = jsonParsed.first,
                serverLatencies = jsonParsed.second.mapValues { it.value.latencyMs }.filterValues { it > 0L },
                meta = meta,
                source = if (liveOk) "remote" else "cache",
                error = if (liveOk) null else UiMessages.MSG_UPDATE_FAILED,
                serverHints = jsonParsed.second,
                fromCacheFallback = !liveOk,
            )
        }

        val listRaw = fetch("alive.txt")
        if (listRaw == null) {
            return LoadResult(
                configs = emptyList(),
                serverLatencies = emptyMap(),
                meta = meta,
                source = "none",
                error = UiMessages.MSG_UPDATE_FAILED,
            )
        }
        val (cfgs, hints) = parseConfigLinesWithHints(listRaw.body)
        if (cfgs.isEmpty()) {
            return LoadResult(
                configs = emptyList(),
                serverLatencies = emptyMap(),
                meta = meta,
                source = "none",
                error = UiMessages.MSG_UPDATE_FAILED,
            )
        }
        val liveOk = listRaw.liveSuccess
        return LoadResult(
            configs = cfgs,
            serverLatencies = hints.mapValues { it.value.latencyMs }.filterValues { it > 0L },
            meta = meta,
            source = if (liveOk) "remote" else "cache",
            error = if (liveOk) null else UiMessages.MSG_UPDATE_FAILED,
            serverHints = hints,
            fromCacheFallback = !liveOk,
        )
    }

    // ─────────── كتابة واسترجاع الملفات النهائية باسم موحّد bahrain-vpn ───────────
    val outDir: File
        get() = File(ctx.getExternalFilesDir(null) ?: ctx.filesDir, "configs")
            .apply { mkdirs() }

    private val localResultsMetaFile: File
        get() = File(dir, "local_results_meta.json")

    fun existingAllFile(): File? =
        File(outDir, "bahrain-vpn-all.txt").takeIf { it.exists() && it.length() > 0 }
            ?: File(outDir, "config.txt").takeIf { it.exists() && it.length() > 0 }

    fun existingBestFile(): File? =
        File(outDir, "bahrain-vpn-best.txt").takeIf { it.exists() && it.length() > 0 }
            ?: File(outDir, "best100.txt").takeIf { it.exists() && it.length() > 0 }

    fun existingSubFile(): File? =
        File(outDir, "bahrain-vpn-sub.txt").takeIf { it.exists() && it.length() > 0 }
            ?: File(outDir, "sub.txt").takeIf { it.exists() && it.length() > 0 }

    fun writeAll(configs: List<String>): File {
        val f = File(outDir, "bahrain-vpn-all.txt")
        val named = configs.mapIndexed { idx, cfg ->
            Converters.namedUri(cfg, "bahrain-vpn ${idx + 1}")
        }
        writeAtomic(f, named.joinToString("\n") + "\n")
        return f
    }

    private fun diversify(results: List<ResultLine>, limit: Int, maxPerHost: Int = 3): List<ResultLine> {
        if (maxPerHost <= 0 || results.size <= 1) return results.take(limit)
        val counts = HashMap<String, Int>()
        val picked = ArrayList<ResultLine>(minOf(limit, results.size))
        val deferred = ArrayList<ResultLine>()
        for (r in results) {
            val h = Converters.hostOf(r.cfg)
            val cur = if (h.isNotEmpty()) counts[h] ?: 0 else 0
            if (h.isNotEmpty() && cur >= maxPerHost) {
                deferred.add(r)
            } else {
                if (h.isNotEmpty()) counts[h] = cur + 1
                picked.add(r)
                if (picked.size >= limit) return picked
            }
        }
        for (r in deferred) {
            if (picked.size >= limit) break
            picked.add(r)
        }
        return picked
    }

    fun writeBest(results: List<ResultLine>, limit: Int): Pair<File, File> {
        val bestList = diversify(results, limit)
        val lines = bestList.mapIndexed { i, r ->
            val speed = if (r.speedKbps > 0) "${r.speedKbps.toInt()}KB/s" else "—"
            val label = "bahrain-vpn ${i + 1} | ${r.latencyMs}ms | $speed"
            Converters.namedUri(r.cfg, label)
        }
        val plainText = lines.joinToString("\n") + "\n"
        val bestFile = File(outDir, "bahrain-vpn-best.txt")
        writeAtomic(bestFile, plainText)

        val subFile = File(outDir, "bahrain-vpn-sub.txt")
        val b64 = Base64.encodeToString(plainText.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
        writeAtomic(subFile, b64 + "\n")

        runCatching {
            val arr = JSONArray()
            results.take(500).forEach { r ->
                arr.put(
                    JSONObject()
                        .put("cfg", Converters.cleanUri(r.cfg))
                        .put("latency_ms", r.latencyMs)
                        .put("speed_kbps", r.speedKbps)
                        .put("tested_at_ms", r.testedAtMs),
                )
            }
            writeAtomic(localResultsMetaFile, arr.toString())
        }

        return bestFile to subFile
    }

    fun loadSavedBest(): List<TestResult> {
        if (localResultsMetaFile.exists()) {
            val parsedMeta = runCatching {
                val arr = JSONArray(localResultsMetaFile.readText(Charsets.UTF_8))
                buildList {
                    for (i in 0 until arr.length()) {
                        val o = arr.optJSONObject(i) ?: continue
                        val cfg = Converters.cleanUri(o.optString("cfg"))
                        if (!cfg.contains("://") || !Converters.isSupported(cfg)) continue
                        add(
                            TestResult(
                                cfg = cfg,
                                ok = true,
                                latencyMs = o.optLong("latency_ms", 0L),
                                speedKbps = o.optDouble("speed_kbps", 0.0),
                                testedAtMs = o.optLong("tested_at_ms", 0L),
                            )
                        )
                    }
                }
            }.getOrDefault(emptyList())
            if (parsedMeta.isNotEmpty()) return parsedMeta
        }

        val f = existingBestFile() ?: return emptyList()
        val fileModifiedMs = f.lastModified().coerceAtLeast(0L)
        return runCatching {
            f.readLines(Charsets.UTF_8).mapNotNull { line ->
                val trimmed = line.trim()
                if (!trimmed.contains("://")) return@mapNotNull null
                val cfg = Converters.cleanUri(trimmed)
                if (!Converters.isSupported(cfg)) return@mapNotNull null
                val remark = Converters.extractRemark(trimmed)
                val parts = remark.split("|").map { it.trim() }
                val lat = parts.getOrNull(1)?.removeSuffix("ms")?.trim()?.toLongOrNull() ?: 0L
                val spd = parts.getOrNull(2)?.removeSuffix("KB/s")?.trim()?.toDoubleOrNull() ?: 0.0
                TestResult(cfg = cfg, ok = true, latencyMs = lat, speedKbps = spd, testedAtMs = fileModifiedMs)
            }
        }.getOrDefault(emptyList())
    }

    private fun profileResultsFile(profile: ScanNetworkProfile): File =
        File(dir, "local_results_${profile.code}.json")

    /** يحفظ نتائج الفحص الشغّالة الخاصة بنوع الشبكة الحالي (WIFI أو MOBILE_DATA) بشكل دائم على القرص. */
    fun saveProfileResults(profile: ScanNetworkProfile, results: List<TestResult>) {
        runCatching {
            val arr = JSONArray()
            val seen = HashSet<String>()
            results.filter { it.ok && (it.latencyMs > 0L || it.speedKbps > 0.0) }
                .take(500)
                .forEach { r ->
                    val clean = Converters.cleanUri(r.cfg)
                    if (clean.contains("://") && seen.add(clean)) {
                        arr.put(
                            JSONObject()
                                .put("cfg", clean)
                                .put("latency_ms", r.latencyMs)
                                .put("speed_kbps", r.speedKbps)
                                .put("jitter_ms", r.jitterMs)
                                .put("establish_ms", r.establishMs)
                                .put("stability_score", r.stabilityScore)
                                .put("tested_at_ms", r.testedAtMs)
                        )
                    }
                }
            writeAtomic(profileResultsFile(profile), arr.toString())
        }
    }

    /** يستعيد نتائج الفحص المحفوظة للشبكة الحالية فور فتح التطبيق دون الحاجة لإعادة الفحص. */
    fun loadSavedResultsForProfile(profile: ScanNetworkProfile): List<TestResult> {
        val pf = profileResultsFile(profile)
        if (pf.exists()) {
            val parsed = runCatching {
                val arr = JSONArray(pf.readText(Charsets.UTF_8))
                buildList {
                    for (i in 0 until arr.length()) {
                        val o = arr.optJSONObject(i) ?: continue
                        val cfg = Converters.cleanUri(o.optString("cfg"))
                        if (!cfg.contains("://") || !Converters.isSupported(cfg)) continue
                        add(
                            TestResult(
                                cfg = cfg,
                                ok = true,
                                latencyMs = o.optLong("latency_ms", 0L),
                                speedKbps = o.optDouble("speed_kbps", 0.0),
                                testedAtMs = o.optLong("tested_at_ms", 0L),
                                establishMs = o.optLong("establish_ms", 0L),
                                jitterMs = o.optDouble("jitter_ms", 0.0),
                                stabilityScore = o.optDouble("stability_score", 0.0),
                            )
                        )
                    }
                }
            }.getOrDefault(emptyList())
            if (parsed.isNotEmpty()) return parsed
            return emptyList()
        }
        val otherProfileFile = profileResultsFile(
            if (profile == ScanNetworkProfile.WIFI) ScanNetworkProfile.MOBILE_DATA else ScanNetworkProfile.WIFI
        )
        if (!otherProfileFile.exists() &&
            ClientDatabase.getInstance(ctx).getPersonalizedRankings(profile, LocalPoolTier.TOP_50).isNotEmpty()
        ) {
            return loadSavedBest()
        }
        return emptyList()
    }

    // ─────────── سجل الحذف الفوري المعزول حسب الشبكة (دورة 4 ساعات) دون المساس ببصمات Top-500 ───────────
    private fun purgedDeadFile(profile: ScanNetworkProfile): File =
        File(dir, "purged_dead_${profile.code}.json")

    fun getActivePurgedDeadServerIds(
        profile: ScanNetworkProfile,
        nowMs: Long = System.currentTimeMillis(),
    ): Set<String> {
        val f = purgedDeadFile(profile)
        if (!f.exists()) return emptySet()
        return runCatching {
            val obj = JSONObject(f.readText(Charsets.UTF_8))
            val cutoff = nowMs - DeadConfigPurgePolicy.PURGE_TTL_MS
            val out = HashSet<String>()
            val keys = obj.keys()
            while (keys.hasNext()) {
                val sid = keys.next()
                if (obj.optLong(sid, 0L) >= cutoff) out.add(sid)
            }
            out
        }.getOrDefault(emptySet())
    }

    fun clearPurgedDeadForProfile(profile: ScanNetworkProfile) {
        runCatching { purgedDeadFile(profile).delete() }
    }

    fun recordPurgedDeadAndCleanFiles(
        profile: ScanNetworkProfile,
        purgeableCleanUris: Set<String>,
        remainingPool: List<String>,
        bestLimit: Int = 100,
        nowMs: Long = System.currentTimeMillis(),
    ) {
        if (purgeableCleanUris.isEmpty()) return
        val deadIds = purgeableCleanUris.mapNotNull { Converters.stableServerId(it).takeIf { id -> id.isNotBlank() } }.toHashSet()
        runCatching {
            val f = purgedDeadFile(profile)
            val existing = if (f.exists()) runCatching { JSONObject(f.readText(Charsets.UTF_8)) }.getOrNull() ?: JSONObject() else JSONObject()
            val next = JSONObject()
            val cutoff = nowMs - DeadConfigPurgePolicy.PURGE_TTL_MS
            val itKeys = existing.keys()
            while (itKeys.hasNext()) {
                val k = itKeys.next()
                val ts = existing.optLong(k, 0L)
                if (ts >= cutoff) next.put(k, ts)
            }
            deadIds.forEach { next.put(it, nowMs) }
            writeAtomic(f, next.toString())
        }
        runCatching {
            if (remainingPool.isNotEmpty()) {
                writeAll(remainingPool)
            }
            val savedProf = loadSavedResultsForProfile(profile).filterNot { r ->
                val c = Converters.cleanUri(r.cfg)
                val sid = Converters.stableServerId(c)
                c in purgeableCleanUris || (sid.isNotBlank() && sid in deadIds)
            }
            if (savedProf.isNotEmpty()) {
                saveProfileResults(profile, savedProf)
            }
            val savedBest = loadSavedBest().filterNot { r ->
                val c = Converters.cleanUri(r.cfg)
                val sid = Converters.stableServerId(c)
                c in purgeableCleanUris || (sid.isNotBlank() && sid in deadIds)
            }
            if (savedBest.isNotEmpty()) {
                writeBest(
                    savedBest.map { ResultLine(it.cfg, it.latencyMs, it.speedKbps, it.testedAtMs) },
                    bestLimit,
                )
            }
        }
    }

    /** يجلب حزمة التراخيص والإعدادات الموقّعة رقميًا (ECDSA P-256) من الفرع الحي مع كاش ETag. */
    fun fetchEnterpriseBundleRaw(): String? = fetch("enterprise/bundle.json")?.body

    // ─────────────────── Central Top-500 Dataset Delivery (ETag + Checksums + Delta + Rollback Guard) ───────────────────

    private val lastValidTop500File: File
        get() = File(dir, "top500.last_valid.json")

    private val top500ManifestEtagFile: File
        get() = File(dir, "top500.manifest.json.etag")

    private fun sha256HexBytes(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private fun stripFragmentForHash(rawUri: String): String =
        rawUri.trim().substringBefore("#").trim()

    fun computeTop500ConfigsSetSha256(entries: List<Top500ServerEntry>): String {
        val canonicalLines = entries.joinToString("\n") { e ->
            "${e.serverId}|${e.configFingerprint}|${stripFragmentForHash(e.cfg)}"
        }
        return sha256HexBytes(canonicalLines.toByteArray(Charsets.UTF_8))
    }

    private fun parseTop500ServerItem(obj: JSONObject, fallbackRank: Int): Top500ServerEntry? {
        val rawCfg = obj.optString("cfg").ifBlank { obj.optString("uri") }.trim()
        if (!rawCfg.contains("://")) return null
        val cleaned = Converters.cleanUri(rawCfg)
        if (!cleaned.contains("://") || !Converters.isSupported(cleaned)) return null
        val sid = obj.optString("server_id").trim().ifBlank { Converters.stableServerId(cleaned) }
        val fp = obj.optString("config_fingerprint").trim().ifBlank { Converters.configFingerprint(cleaned) }
        if (sid.isBlank() || fp.isBlank()) return null
        val cc = obj.optString("country", "").uppercase().let { if (it == "XX" || it.length != 2) "" else it }
        return Top500ServerEntry(
            centralRank = obj.optInt("central_rank", fallbackRank),
            serverId = sid,
            configFingerprint = fp,
            cfg = rawCfg,
            protocol = obj.optString("protocol", Converters.schemeOf(cleaned)),
            country = cc,
            preliminaryLatencyMs = obj.optLong("preliminary_latency_ms", 0L).coerceAtLeast(0L),
            centralQualityScore = obj.optDouble("central_quality_score", 0.0).let { if (it.isNaN()) 0.0 else it },
            stabilityRuns = obj.optInt("stability_runs", 0).coerceAtLeast(0),
            securityAssessment = obj.optString("security_assessment", ""),
            privacyAssessment = obj.optString("privacy_assessment", ""),
            riskLevel = obj.optString("risk_level", ""),
            trustPosture = obj.optString("trust_posture", "UNTRUSTED_PUBLIC_SERVER"),
        )
    }

    private fun parseAndValidateTop500Document(
        rawJson: String,
        expectedConfigsSha256: String? = null,
    ): Top500SyncOutcome? {
        return runCatching {
            val root = JSONObject(rawJson)
            val version = root.optLong("dataset_version", 0L)
            val generatedAt = root.optString("generated_at", "—")
            val generatedAtEpoch = root.optLong("generated_at_epoch", 0L)
            val claimedSha = root.optString("configs_sha256", "").lowercase()
            val arr = root.optJSONArray("servers") ?: return null
            if (arr.length() > MAX_TOP500_CAPACITY) return null

            val parsed = ArrayList<Top500ServerEntry>(minOf(arr.length(), MAX_TOP500_CAPACITY))
            val seenIds = HashSet<String>()
            for (i in 0 until arr.length()) {
                val itemObj = arr.optJSONObject(i) ?: return null
                val entry = parseTop500ServerItem(itemObj, i + 1) ?: return null
                if (!seenIds.add(entry.serverId)) return null
                parsed.add(entry)
            }

            val actualConfigsSha = computeTop500ConfigsSetSha256(parsed)
            if (claimedSha.isNotEmpty() && !claimedSha.equals(actualConfigsSha, ignoreCase = true)) {
                AppDiag.w("Repo", "Top500 internal configs_sha256 mismatch")
                return null
            }
            if (!expectedConfigsSha256.isNullOrBlank() && !expectedConfigsSha256.equals(actualConfigsSha, ignoreCase = true)) {
                AppDiag.w("Repo", "Top500 manifest configs_sha256 mismatch")
                return null
            }

            Top500SyncOutcome(
                datasetVersion = version,
                generatedAt = generatedAt,
                generatedAtEpoch = generatedAtEpoch,
                configsSha256 = actualConfigsSha,
                qualifiedCount = parsed.size,
                servers = parsed,
                liveSuccess = true,
                checksumVerified = true,
            )
        }.getOrNull()
    }

    private fun serializeTop500Document(outcome: Top500SyncOutcome): String {
        val arr = JSONArray()
        outcome.servers.forEachIndexed { idx, s ->
            arr.put(
                JSONObject()
                    .put("central_rank", idx + 1)
                    .put("server_id", s.serverId)
                    .put("config_fingerprint", s.configFingerprint)
                    .put("cfg", s.cfg)
                    .put("protocol", s.protocol)
                    .put("country", s.country)
                    .put("preliminary_latency_ms", s.preliminaryLatencyMs)
                    .put("central_quality_score", s.centralQualityScore)
                    .put("stability_runs", s.stabilityRuns)
                    .put("security_assessment", s.securityAssessment)
                    .put("privacy_assessment", s.privacyAssessment)
                    .put("risk_level", s.riskLevel)
                    .put("trust_posture", s.trustPosture)
            )
        }
        return JSONObject()
            .put("schema_version", "1.0.0")
            .put("dataset_version", outcome.datasetVersion)
            .put("generated_at", outcome.generatedAt)
            .put("generated_at_epoch", outcome.generatedAtEpoch)
            .put("role", "CENTRAL_CANDIDATE_POOL")
            .put("personalized_top50_authority", "ANDROID_LOCAL_ONLY")
            .put("qualified_count", outcome.servers.size)
            .put("configs_sha256", outcome.configsSha256)
            .put("servers", arr)
            .toString()
    }

    /** يستعيد آخر حزمة Top-500 محقّقة البصمة من التخزين المحلي الآمن. */
    fun loadLastValidTop500Dataset(): Top500SyncOutcome? {
        if (!lastValidTop500File.exists()) return null
        val raw = runCatching { lastValidTop500File.readText(Charsets.UTF_8) }.getOrNull() ?: return null
        return parseAndValidateTop500Document(raw)?.copy(liveSuccess = false)
    }

    private fun fetchFreshMirrorBody(file: String, etag: String? = null): HttpResp? {
        for (url in candidates(file)) {
            val resp = httpGetBounded(url, etag)
            if (resp != null && (resp.status == 304 || !resp.body.isNullOrBlank())) {
                return resp
            }
        }
        return null
    }

    /**
     * يزامن قاعدة المرشّحين المركزية Top-500 مع:
     *   1) ETag / 304 لتجنب التنزيل المكرر.
     *   2) التحقق الصارم من بصمات SHA-256 للملف وللمحتوى المعياري.
     *   3) التحديث التفاضلي الاختياري (top500.delta.json) عند تطابق النسخة الأساسية.
     *   4) الحماية من التراجع لإصدار أقدم (Rollback Protection).
     *   5) الاستعادة التلقائية لآخر حزمة صالحة معروفة (Last-Known-Valid Recovery).
     */
    fun syncTop500Dataset(): Top500SyncOutcome? {
        val localValid = loadLastValidTop500Dataset()
        val savedEtag = if (localValid != null && top500ManifestEtagFile.exists()) {
            runCatching { top500ManifestEtagFile.readText(Charsets.UTF_8).trim() }.getOrNull()
        } else null

        val manifestResp = fetchFreshMirrorBody("top500.manifest.json", savedEtag)
        if (manifestResp != null && manifestResp.status == 304 && localValid != null) {
            return localValid.copy(liveSuccess = true, notModified304 = true, checksumVerified = true)
        }

        if (manifestResp != null && !manifestResp.body.isNullOrBlank() &&
            !ManifestSignature.isTrusted(manifestResp.body) { fetchFreshMirrorBody("top500.manifest.json.sig")?.body }
        ) {
            AppDiag.w("Repo", "Rejected Top500 manifest: missing or invalid signature")
            return localValid?.copy(
                liveSuccess = false,
                recoveredFromLastValid = true,
                error = UiMessages.MSG_UPDATE_FAILED,
            )
        }

        if (manifestResp != null && !manifestResp.body.isNullOrBlank()) {
            val manifestParsed = runCatching { JSONObject(manifestResp.body) }.getOrNull()
            if (manifestParsed != null) {
                val targetVersion = manifestParsed.optLong("dataset_version", 0L)
                val targetGeneratedAt = manifestParsed.optString("generated_at", "—")
                val targetEpoch = manifestParsed.optLong("generated_at_epoch", 0L)
                val checksums = manifestParsed.optJSONObject("checksums") ?: JSONObject()
                val expectedJsonSha = checksums.optString("top500_json_sha256", "").lowercase()
                val expectedConfigsSha = checksums.optString("configs_sha256", "").lowercase()
                val expectedDeltaSha = checksums.optString("delta_json_sha256", "").lowercase()

                // Rollback protection: reject stale/replayed older versions or timestamps
                if (localValid != null && (
                        (targetVersion > 0L && localValid.datasetVersion > 0L && targetVersion < localValid.datasetVersion) ||
                            (targetEpoch > 0L && localValid.generatedAtEpoch > 0L && targetEpoch < localValid.generatedAtEpoch)
                        )
                ) {
                    AppDiag.w("Repo", "Rejected Top500 dataset rollback attempt")
                    return localValid.copy(
                        liveSuccess = false,
                        rollbackRejected = true,
                        recoveredFromLastValid = true,
                        error = UiMessages.MSG_UPDATE_FAILED,
                    )
                }

                // Identical canonical content already stored locally -> update metadata without re-downloading
                if (localValid != null && expectedConfigsSha.isNotBlank() &&
                    expectedConfigsSha.equals(localValid.configsSha256, ignoreCase = true)
                ) {
                    val refreshed = localValid.copy(
                        datasetVersion = maxOf(targetVersion, localValid.datasetVersion),
                        generatedAt = if (targetGeneratedAt != "—") targetGeneratedAt else localValid.generatedAt,
                        generatedAtEpoch = maxOf(targetEpoch, localValid.generatedAtEpoch),
                        liveSuccess = true,
                        checksumVerified = true,
                    )
                    writeAtomic(lastValidTop500File, serializeTop500Document(refreshed))
                    manifestResp.etag?.takeIf { it.isNotBlank() }?.let { writeAtomic(top500ManifestEtagFile, it) }
                    return refreshed
                }

                // Optional incremental update via top500.delta.json when base matches local valid snapshot
                val deltaAvail = manifestParsed.optBoolean("delta_available", false)
                val deltaBaseSha = manifestParsed.optString("delta_base_configs_sha256", "")
                if (localValid != null && deltaAvail && deltaBaseSha.equals(localValid.configsSha256, ignoreCase = true)) {
                    val deltaResp = fetchFreshMirrorBody("top500.delta.json", null)
                    if (deltaResp != null && !deltaResp.body.isNullOrBlank()) {
                        val actualDeltaSha = sha256HexBytes(deltaResp.body.toByteArray(Charsets.UTF_8))
                        val deltaShaOk = expectedDeltaSha.isBlank() || expectedDeltaSha.equals(actualDeltaSha, ignoreCase = true)
                        if (deltaShaOk) {
                            val reconstructed = applyIncrementalDelta(
                                base = localValid,
                                deltaJson = deltaResp.body,
                                expectedTargetConfigsSha = expectedConfigsSha,
                                targetVersion = targetVersion,
                                targetGeneratedAt = targetGeneratedAt,
                                targetEpoch = targetEpoch,
                            )
                            if (reconstructed != null) {
                                writeAtomic(lastValidTop500File, serializeTop500Document(reconstructed))
                                manifestResp.etag?.takeIf { it.isNotBlank() }?.let { writeAtomic(top500ManifestEtagFile, it) }
                                return reconstructed
                            }
                        }
                    }
                }

                // Full top500.json download + raw SHA-256 & canonical configs_sha256 verification
                val fullResp = fetchFreshMirrorBody("top500.json", null)
                if (fullResp != null && !fullResp.body.isNullOrBlank()) {
                    val rawSha = sha256HexBytes(fullResp.body.toByteArray(Charsets.UTF_8))
                    val rawShaOk = expectedJsonSha.isBlank() || expectedJsonSha.equals(rawSha, ignoreCase = true)
                    if (rawShaOk) {
                        val verifiedDoc = parseAndValidateTop500Document(fullResp.body, expectedConfigsSha)
                        if (verifiedDoc != null) {
                            writeAtomic(lastValidTop500File, fullResp.body)
                            manifestResp.etag?.takeIf { it.isNotBlank() }?.let { writeAtomic(top500ManifestEtagFile, it) }
                            return verifiedDoc
                        }
                    } else {
                        AppDiag.w("Repo", "Top500 raw file SHA-256 verification failed")
                    }
                }

                // Manifest existed, but payload failed integrity or download -> recover from last-known-valid!
                if (localValid != null) {
                    return localValid.copy(
                        liveSuccess = false,
                        recoveredFromLastValid = true,
                        error = UiMessages.MSG_UPDATE_FAILED,
                    )
                }
            }
        }

        // Direct fallback check for top500.json without manifest or offline recovery from last-known-valid
        val directResp = fetchFreshMirrorBody("top500.json", null)
        if (directResp != null && !directResp.body.isNullOrBlank()) {
            val verifiedDirect = parseAndValidateTop500Document(directResp.body, null)
            if (verifiedDirect != null) {
                if (localValid != null && (
                        (verifiedDirect.datasetVersion > 0L && verifiedDirect.datasetVersion < localValid.datasetVersion) ||
                            (verifiedDirect.generatedAtEpoch > 0L && verifiedDirect.generatedAtEpoch < localValid.generatedAtEpoch)
                        )
                ) {
                    return localValid.copy(
                        liveSuccess = false,
                        rollbackRejected = true,
                        recoveredFromLastValid = true,
                        error = UiMessages.MSG_UPDATE_FAILED,
                    )
                }
                writeAtomic(lastValidTop500File, directResp.body)
                return verifiedDirect
            }
        }

        return localValid?.copy(
            liveSuccess = false,
            recoveredFromLastValid = true,
            error = UiMessages.MSG_UPDATE_FAILED,
        )
    }

    private fun applyIncrementalDelta(
        base: Top500SyncOutcome,
        deltaJson: String,
        expectedTargetConfigsSha: String,
        targetVersion: Long,
        targetGeneratedAt: String,
        targetEpoch: Long,
    ): Top500SyncOutcome? {
        return runCatching {
            val dObj = JSONObject(deltaJson)
            val map = LinkedHashMap<String, Top500ServerEntry>()
            base.servers.forEach { map[it.serverId] = it }

            val remArr = dObj.optJSONArray("removed_server_ids") ?: JSONArray()
            for (i in 0 until remArr.length()) {
                map.remove(remArr.optString(i))
            }
            val upArr = dObj.optJSONArray("added_or_updated") ?: JSONArray()
            for (i in 0 until upArr.length()) {
                val uObj = upArr.optJSONObject(i) ?: continue
                val parsed = parseTop500ServerItem(uObj, i + 1) ?: return null
                map[parsed.serverId] = parsed
            }
            val orderArr = dObj.optJSONArray("ordered_server_ids") ?: return null
            if (orderArr.length() > MAX_TOP500_CAPACITY) return null
            val ordered = ArrayList<Top500ServerEntry>(orderArr.length())
            for (i in 0 until orderArr.length()) {
                val sid = orderArr.optString(i)
                val entry = map[sid] ?: return null
                ordered.add(entry.copy(centralRank = i + 1))
            }
            val computedSha = computeTop500ConfigsSetSha256(ordered)
            val targetSha = expectedTargetConfigsSha.ifBlank { dObj.optString("target_configs_sha256", "") }
            if (targetSha.isNotBlank() && !targetSha.equals(computedSha, ignoreCase = true)) {
                return null
            }
            Top500SyncOutcome(
                datasetVersion = if (targetVersion > 0L) targetVersion else dObj.optLong("target_dataset_version", base.datasetVersion + 1L),
                generatedAt = if (targetGeneratedAt != "—") targetGeneratedAt else dObj.optString("target_generated_at", base.generatedAt),
                generatedAtEpoch = if (targetEpoch > 0L) targetEpoch else dObj.optLong("target_generated_at_epoch", base.generatedAtEpoch),
                configsSha256 = computedSha,
                qualifiedCount = ordered.size,
                servers = ordered,
                liveSuccess = true,
                incrementalApplied = true,
                checksumVerified = true,
            )
        }.getOrNull()
    }

    private fun top500OutcomeToLoadResult(
        outcome: Top500SyncOutcome,
        fallbackMeta: RemoteMeta,
        forceCacheSource: Boolean,
    ): LoadResult {
        val cfgs = ArrayList<String>(outcome.servers.size)
        val hints = HashMap<String, ServerHint>(outcome.servers.size)
        val fps = HashMap<String, String>(outcome.servers.size)

        for (entry in outcome.servers) {
            val cleaned = Converters.cleanUri(entry.cfg)
            if (!cleaned.contains("://") || !Converters.isSupported(cleaned)) continue
            cfgs.add(cleaned)
            fps[entry.serverId] = entry.configFingerprint
            hints[cleaned] = ServerHint(
                latencyMs = entry.preliminaryLatencyMs,
                score = entry.centralQualityScore,
                performanceScore = entry.centralQualityScore,
                reliabilityScore = entry.centralQualityScore,
                securityAssessment = entry.securityAssessment,
                privacyAssessment = entry.privacyAssessment,
                riskLevel = entry.riskLevel,
                country = entry.country,
                stabilityRuns = entry.stabilityRuns,
                verifiedAt = outcome.generatedAt,
            )
        }

        val liveOk = outcome.liveSuccess && !forceCacheSource
        val effMeta = if (fallbackMeta.generatedAt != "—") fallbackMeta else RemoteMeta(
            generatedAt = outcome.generatedAt,
            alive = cfgs.size,
            tested = cfgs.size,
        )
        return LoadResult(
            configs = cfgs,
            serverLatencies = hints.mapValues { it.value.latencyMs }.filterValues { it > 0L },
            meta = effMeta,
            source = if (liveOk) "remote" else "cache",
            error = if (liveOk) null else (outcome.error ?: if (forceCacheSource) null else UiMessages.MSG_UPDATE_FAILED),
            serverHints = hints,
            fromCacheFallback = !liveOk,
            datasetVersion = outcome.datasetVersion,
            datasetConfigsSha256 = outcome.configsSha256,
            serverFingerprints = fps,
            incrementalApplied = outcome.incrementalApplied,
            rollbackRejected = outcome.rollbackRejected,
            recoveredFromLastValid = outcome.recoveredFromLastValid,
        )
    }

    data class StableApkDownloadResult(
        val savedDisplayName: String,
        val abiLabel: String,
        val sizeBytes: Long,
        val sha256: String,
        val checksumVerified: Boolean,
    )

    fun resolveDeviceReleaseAsset(
        supportedAbis: Array<String> = Build.SUPPORTED_ABIS,
    ): Pair<String, String> {
        for (abi in supportedAbis) {
            when (abi.trim()) {
                "arm64-v8a" -> return "arm64-v8a" to "app-arm64-v8a-release.apk"
                "x86_64" -> return "x86_64" to "app-x86_64-release.apk"
            }
        }
        return "universal" to "app-universal-release.apk"
    }

    private fun releaseAssetUrl(fileName: String): String =
        mirrorOverride?.invoke("release/$fileName")?.firstOrNull()
            ?: "https://github.com/$owner/$repo/releases/latest/download/$fileName"

    private fun openFollowedReleaseConnection(
        initialUrl: String,
        proxy: Proxy,
        connectTimeoutMs: Int,
        readTimeoutMs: Int,
    ): HttpURLConnection? {
        val enforceHttps = (mirrorOverride == null)
        var currentUrl = initialUrl
        for (hop in 0..6) {
            val parsed = runCatching { URL(currentUrl) }.getOrNull() ?: return null
            if (enforceHttps && !parsed.protocol.equals("https", ignoreCase = true)) {
                return null
            }
            val conn = (parsed.openConnection(proxy) as HttpURLConnection).apply {
                connectTimeout = connectTimeoutMs
                readTimeout = readTimeoutMs
                requestMethod = "GET"
                instanceFollowRedirects = false
                setRequestProperty("User-Agent", "bahrain-vpn/2.0")
                setRequestProperty("Accept", "application/octet-stream, text/plain, */*")
            }
            val code = runCatching { conn.responseCode }.getOrElse {
                runCatching { conn.disconnect() }
                return null
            }
            if (code in listOf(301, 302, 303, 307, 308)) {
                val loc = conn.getHeaderField("Location")?.trim().orEmpty()
                runCatching { conn.disconnect() }
                if (loc.isEmpty()) return null
                val resolved = runCatching { URL(parsed, loc).toString() }.getOrNull() ?: return null
                if (enforceHttps && !resolved.lowercase(Locale.US).startsWith("https://")) {
                    return null
                }
                currentUrl = resolved
                continue
            }
            if (code in 200..299) {
                return conn
            }
            runCatching { conn.disconnect() }
            return null
        }
        return null
    }

    private fun openReleaseStreamWithTunnelFallback(
        targetUrl: String,
        connectTimeoutMs: Int,
        readTimeoutMs: Int,
    ): HttpURLConnection? {
        val preferTunnelProxy = mirrorOverride == null && VpnStateManager.status.value.isTunnelVerified
        if (preferTunnelProxy) {
            val socksProxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", SingBox.VPN_SOCKS_PORT))
            val viaTunnel = openFollowedReleaseConnection(targetUrl, socksProxy, connectTimeoutMs, readTimeoutMs)
            if (viaTunnel != null) return viaTunnel
        }
        return openFollowedReleaseConnection(targetUrl, Proxy.NO_PROXY, connectTimeoutMs, readTimeoutMs)
    }

    private fun fetchExpectedSha256ForAsset(assetFileName: String): String {
        val sumsUrl = releaseAssetUrl("SHA256SUMS.txt")
        val conn = openReleaseStreamWithTunnelFallback(sumsUrl, connectTimeoutMs = 12_000, readTimeoutMs = 12_000)
            ?: return ""
        return try {
            val text = conn.inputStream.bufferedReader(Charsets.UTF_8).use { reader ->
                val sb = StringBuilder()
                val buf = CharArray(2048)
                var total = 0
                while (true) {
                    val n = reader.read(buf)
                    if (n <= 0) break
                    total += n
                    if (total > 64 * 1024) break
                    sb.append(buf, 0, n)
                }
                sb.toString()
            }
            var found = ""
            for (rawLine in text.lineSequence()) {
                val parts = rawLine.trim().split(Regex("\\s+"), limit = 2)
                if (parts.size == 2) {
                    val hash = parts[0].trim().lowercase(Locale.US)
                    val name = parts[1].trim().removePrefix("*").substringAfterLast('/')
                    if (name == assetFileName && hash.length == 64 && hash.all { it in '0'..'9' || it in 'a'..'f' }) {
                        found = hash
                        break
                    }
                }
            }
            found
        } catch (_: Exception) {
            ""
        } finally {
            runCatching { conn.disconnect() }
        }
    }

    /**
     * ينزّل آخر نسخة مستقرة رسمية متوافقة مع معالج الجهاز مباشرةً من داخل التطبيق
     * ويحفظها في مجلد التنزيلات (Downloads) باسم موحّد نظيف دون كشف أي رابط أو مصدر للواجهة،
     * مع التحقق الصارم من بصمة SHA-256 وترويسة الحزمة قبل الحفظ.
     */
    fun downloadLatestStableApk(
        supportedAbis: Array<String> = Build.SUPPORTED_ABIS,
        expectedSha256Override: String = "",
        isCancelled: () -> Boolean = { false },
        onProgress: (percent: Int, downloadedBytes: Long, totalBytes: Long) -> Unit = { _, _, _ -> },
    ): Result<StableApkDownloadResult> {
        val (abiLabel, assetName) = resolveDeviceReleaseAsset(supportedAbis)
        val cleanOverrideSha = expectedSha256Override.trim().lowercase(Locale.US)
            .takeIf { it.length == 64 && it.all { c -> c in '0'..'9' || c in 'a'..'f' } }
            .orEmpty()
        val expectedSha = cleanOverrideSha.ifEmpty { fetchExpectedSha256ForAsset(assetName) }
        if (isCancelled()) {
            return Result.failure(InterruptedException(tr("تم إلغاء التحميل", "Download cancelled")))
        }

        val updatesCacheDir = File(ctx.cacheDir, "updates").apply { mkdirs() }
        val tempFile = File(updatesCacheDir, "bahrain-vpn-stable.part")
        runCatching { if (tempFile.exists()) tempFile.delete() }

        val targetUrl = releaseAssetUrl(assetName)
        var conn: HttpURLConnection? = null
        return try {
            onProgress(0, 0L, 0L)
            conn = openReleaseStreamWithTunnelFallback(
                targetUrl = targetUrl,
                connectTimeoutMs = 18_000,
                readTimeoutMs = 45_000,
            ) ?: return Result.failure(
                IllegalStateException(
                    tr(
                        "تعذّر الاتصال بخادم التحديث حاليًا — تحقّق من الإنترنت وحاول مرة أخرى",
                        "Could not reach update service right now — check your connection and retry",
                    )
                )
            )

            val declaredTotal = conn.contentLengthLong
            if (declaredTotal > MAX_APK_DOWNLOAD_BYTES) {
                return Result.failure(
                    IllegalStateException(tr("حجم ملف التحديث يتجاوز الحد الآمن", "Update package exceeds safe size limit"))
                )
            }

            val md = MessageDigest.getInstance("SHA-256")
            val headerMagic = ByteArray(4)
            var magicFilled = 0
            var totalRead = 0L
            var lastProgressTickMs = 0L

            conn.inputStream.use { input ->
                FileOutputStream(tempFile).use { out ->
                    val buf = ByteArray(32 * 1024)
                    while (true) {
                        if (isCancelled()) {
                            throw InterruptedException(tr("تم إلغاء التحميل", "Download cancelled"))
                        }
                        val n = input.read(buf)
                        if (n <= 0) break
                        if (magicFilled < 4) {
                            val copyLen = minOf(4 - magicFilled, n)
                            System.arraycopy(buf, 0, headerMagic, magicFilled, copyLen)
                            magicFilled += copyLen
                        }
                        totalRead += n
                        if (totalRead > MAX_APK_DOWNLOAD_BYTES) {
                            throw IllegalStateException(
                                tr("حجم ملف التحديث يتجاوز الحد الآمن", "Update package exceeds safe size limit")
                            )
                        }
                        md.update(buf, 0, n)
                        out.write(buf, 0, n)

                        val nowTick = runCatching { SystemClock.elapsedRealtime() }.getOrDefault(System.currentTimeMillis())
                        if (nowTick - lastProgressTickMs >= 100L) {
                            lastProgressTickMs = nowTick
                            val pct = if (declaredTotal > 0L) {
                                ((totalRead * 100L) / declaredTotal).toInt().coerceIn(1, 99)
                            } else {
                                -1
                            }
                            onProgress(pct, totalRead, declaredTotal.coerceAtLeast(0L))
                        }
                    }
                    out.fd.sync()
                }
            }

            val validZipMagic = magicFilled == 4 &&
                headerMagic[0] == 0x50.toByte() &&
                headerMagic[1] == 0x4B.toByte() &&
                headerMagic[2] == 0x03.toByte() &&
                headerMagic[3] == 0x04.toByte()
            if (!validZipMagic || totalRead < MIN_APK_DOWNLOAD_BYTES) {
                return Result.failure(
                    IllegalStateException(
                        tr("الملف المستلم غير مكتمل أو تالف — لم يتم حفظه", "Downloaded package was incomplete or invalid")
                    )
                )
            }

            val actualSha = md.digest().joinToString("") { "%02x".format(it) }
            if (expectedSha.isNotEmpty() && !actualSha.equals(expectedSha, ignoreCase = true)) {
                return Result.failure(
                    SecurityException(
                        tr(
                            "فشل التحقق من بصمة الأمان SHA-256 للنسخة المحمّلة — تم رفض الملف لحمايتك",
                            "SHA-256 integrity check failed — rejected package for your safety",
                        )
                    )
                )
            }

            val savedDisplayName = STABLE_DOWNLOAD_FILE_NAME
            val savedViaMediaStore = saveVerifiedFileToPublicDownloads(tempFile, savedDisplayName)
            if (!savedViaMediaStore) {
                val fallbackDir = File(
                    ctx.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS) ?: File(ctx.filesDir, "downloads"),
                    "",
                ).apply { mkdirs() }
                val dest = File(fallbackDir, savedDisplayName)
                tempFile.copyTo(dest, overwrite = true)
            }

            onProgress(100, totalRead, totalRead)
            Result.success(
                StableApkDownloadResult(
                    savedDisplayName = savedDisplayName,
                    abiLabel = abiLabel,
                    sizeBytes = totalRead,
                    sha256 = actualSha,
                    checksumVerified = expectedSha.isNotEmpty(),
                )
            )
        } catch (ie: InterruptedException) {
            Result.failure(ie)
        } catch (e: Exception) {
            AppDiag.w("Repo", "opaque stable download error")
            Result.failure(
                IllegalStateException(
                    UiMessages.sanitizeError(
                        e.message,
                        tr(
                            "تعذّر إكمال تحميل النسخة المستقرة — حاول مجددًا",
                            "Could not complete downloading the latest stable version — please retry",
                        ),
                    )
                )
            )
        } finally {
            runCatching { conn?.disconnect() }
            runCatching { if (tempFile.exists()) tempFile.delete() }
        }
    }

    private fun saveVerifiedFileToPublicDownloads(sourceFile: File, displayName: String): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return false
        return runCatching {
            val resolver = ctx.contentResolver
            val collection = MediaStore.Downloads.EXTERNAL_CONTENT_URI
            runCatching {
                resolver.delete(
                    collection,
                    "${MediaStore.MediaColumns.DISPLAY_NAME} = ?",
                    arrayOf(displayName),
                )
            }
            val values = ContentValues().apply {
                put(MediaStore.MediaColumns.DISPLAY_NAME, displayName)
                put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                put(MediaStore.MediaColumns.IS_PENDING, 1)
            }
            val itemUri = resolver.insert(collection, values) ?: return@runCatching false
            val wroteOk = resolver.openOutputStream(itemUri)?.use { out ->
                sourceFile.inputStream().use { input ->
                    input.copyTo(out, bufferSize = 32 * 1024)
                }
                out.flush()
                true
            } ?: false
            if (!wroteOk) {
                runCatching { resolver.delete(itemUri, null, null) }
                return@runCatching false
            }
            val publishValues = ContentValues().apply {
                put(MediaStore.MediaColumns.IS_PENDING, 0)
            }
            resolver.update(itemUri, publishValues, null, null)
            true
        }.getOrDefault(false)
    }

    companion object {
        @JvmField
        internal val DEFAULT_OWNER: String = "oldman-552"
        @JvmField
        internal val DEFAULT_REPO: String = "vpn-configs"
        const val STABLE_DOWNLOAD_FILE_NAME: String = "bahrain-vpn-latest.apk"
        private const val MAX_BODY_BYTES = 10L * 1024L * 1024L
        private const val MAX_APK_DOWNLOAD_BYTES = 140L * 1024L * 1024L
        private const val MIN_APK_DOWNLOAD_BYTES = 16L * 1024L
        private const val MAX_BODY_CHARS = 8_000_000
        private const val MAX_PARSED_SERVERS = 5_000
        private const val MAX_TOP500_CAPACITY = 500

        fun containsSourceIdentifier(text: String): Boolean =
            text.contains(DEFAULT_OWNER, ignoreCase = true) ||
                text.contains(DEFAULT_REPO, ignoreCase = true)
    }
}
