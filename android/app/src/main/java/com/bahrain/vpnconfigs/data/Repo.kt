// =====================================================================
// Repo.kt — تنزيل القائمة الحيّة الغنية بالمؤشرات (alive.json + القوائم المتخصّصة)
// مع التخزين المؤقت التدريجي (ETag / 304) والحماية من المدخلات المشوّهة أو الضخمة.
// يحافظ بالكامل على الاتصال بالمستودع الحالي وتحديثاته دون كشف تفاصيل المصدر للواجهة.
// =====================================================================
package com.bahrain.vpnconfigs.data

import android.content.Context
import android.util.Base64
import com.bahrain.vpnconfigs.engine.Converters
import com.bahrain.vpnconfigs.engine.TestResult
import com.bahrain.vpnconfigs.util.AppDiag
import com.bahrain.vpnconfigs.util.UiMessages
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

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
    private val promoDir = File(ctx.filesDir, "promo").apply { mkdirs() }

    private fun candidates(file: String): List<String> =
        mirrorOverride?.invoke(file) ?: listOf(
            "https://cdn.jsdelivr.net/gh/$owner/$repo@data/$file",
            "https://raw.githubusercontent.com/$owner/$repo/data/$file",
            "https://$owner.github.io/$repo/$file",
        )

    private fun promoCandidates(fileOrUrl: String): List<String> {
        val trimmed = fileOrUrl.trim()
        if (trimmed.startsWith("https://", ignoreCase = true)) {
            val safe = sanitizePromoLink(trimmed)
            return if (safe.isNotEmpty()) listOf(safe) else emptyList()
        }
        val cleanRel = trimmed
            .removePrefix("/")
            .removePrefix("promo/")
            .replace("..", "")
            .trim()
        if (cleanRel.isEmpty()) return emptyList()
        return mirrorOverride?.invoke("promo/$cleanRel") ?: listOf(
            "https://raw.githubusercontent.com/$owner/$repo/main/promo/$cleanRel",
            "https://cdn.jsdelivr.net/gh/$owner/$repo@main/promo/$cleanRel",
        )
    }

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

    // ═══════════════════════════════════════════════════════════════════════
    //  نظام الإعلانات المتناوبة (5 صور متغيّرة + تحديث تلقائي عبر ETag)
    // ═══════════════════════════════════════════════════════════════════════

    private data class HttpBytesResp(
        val status: Int,
        val bytes: ByteArray? = null,
        val etag: String? = null,
    )

    private fun httpGetBytesBounded(
        url: String,
        etag: String?,
        maxBytes: Int = MAX_PROMO_IMAGE_BYTES,
        timeoutMs: Int = 5000,
    ): HttpBytesResp? {
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
            if (code == HttpURLConnection.HTTP_NOT_MODIFIED) {
                return HttpBytesResp(status = 304, etag = conn.getHeaderField("ETag") ?: etag)
            }
            if (code !in 200..299) return null
            val contentLength = conn.contentLengthLong
            if (contentLength > maxBytes) return null

            val out = java.io.ByteArrayOutputStream()
            conn.inputStream.use { input ->
                val buf = ByteArray(8192)
                var read: Int
                while (input.read(buf).also { read = it } != -1) {
                    if (out.size() + read > maxBytes) return null
                    out.write(buf, 0, read)
                }
            }
            HttpBytesResp(status = code, bytes = out.toByteArray(), etag = conn.getHeaderField("ETag"))
        } catch (e: Exception) {
            AppDiag.d("Repo", "promo binary fetch skipped: ${e.javaClass.simpleName}")
            null
        } finally {
            conn?.disconnect()
        }
    }

    private fun writeBytesAtomic(target: File, bytes: ByteArray) {
        target.parentFile?.mkdirs()
        val tmp = File(target.parentFile, "${target.name}.tmp")
        tmp.writeBytes(bytes)
        if (!tmp.renameTo(target)) {
            target.writeBytes(bytes)
            tmp.delete()
        }
    }

    internal fun isValidImageMagic(bytes: ByteArray): Boolean {
        if (bytes.size < 12) return false
        val isPng = bytes.size >= 16 &&
            bytes[0] == 0x89.toByte() &&
            bytes[1] == 0x50.toByte() &&
            bytes[2] == 0x4E.toByte() &&
            bytes[3] == 0x47.toByte()
        if (isPng) return true

        val isJpeg = bytes[0] == 0xFF.toByte() &&
            bytes[1] == 0xD8.toByte() &&
            bytes[2] == 0xFF.toByte()
        if (isJpeg) return true

        val isWebp = bytes.size >= 16 &&
            bytes[0] == 'R'.code.toByte() &&
            bytes[1] == 'I'.code.toByte() &&
            bytes[2] == 'F'.code.toByte() &&
            bytes[3] == 'F'.code.toByte() &&
            bytes[8] == 'W'.code.toByte() &&
            bytes[9] == 'E'.code.toByte() &&
            bytes[10] == 'B'.code.toByte() &&
            bytes[11] == 'P'.code.toByte()
        if (isWebp) return true

        val isGif = bytes[0] == 'G'.code.toByte() &&
            bytes[1] == 'I'.code.toByte() &&
            bytes[2] == 'F'.code.toByte() &&
            bytes[3] == '8'.code.toByte()
        return isGif
    }

    internal fun sanitizePromoLink(raw: String?): String {
        val trimmed = raw?.trim().orEmpty()
        if (trimmed.isEmpty()) return ""
        return try {
            val uri = java.net.URI(trimmed)
            val scheme = uri.scheme?.lowercase() ?: return ""
            val host = uri.host?.trim()?.lowercase() ?: return ""
            if (scheme != "https" || host.isBlank()) return ""
            if (host == "localhost" || host.startsWith("127.") || host.startsWith("10.") || host.startsWith("192.168.")) {
                return ""
            }
            trimmed
        } catch (_: Exception) {
            ""
        }
    }

    private fun promoImageCacheFile(imageRef: String): File {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
            .digest(imageRef.trim().toByteArray(Charsets.UTF_8))
            .take(10)
            .joinToString("") { "%02x".format(it) }
        val ext = imageRef.substringBefore('?').substringAfterLast('.', "img")
            .lowercase()
            .filter { it in 'a'..'z' || it in '0'..'9' }
            .take(5)
            .ifBlank { "img" }
        return File(promoDir, "slot_$digest.$ext")
    }

    private fun parsePromoManifest(raw: String): PromoManifest? {
        return try {
            val obj = JSONObject(raw)
            val enabled = obj.optBoolean("enabled", true)
            val closeSec = obj.optInt("close_delay_sec", 3).coerceIn(0, 15)
            val arr = obj.optJSONArray("ads") ?: JSONArray()
            val items = ArrayList<PromoItem>()
            for (i in 0 until minOf(arr.length(), 20)) {
                val itemObj = arr.optJSONObject(i) ?: continue
                val img = itemObj.optString("image").trim()
                if (img.isEmpty()) continue
                items.add(
                    PromoItem(
                        id = itemObj.optString("id", "ad${i + 1}").trim().ifBlank { "ad${i + 1}" },
                        enabled = itemObj.optBoolean("enabled", true),
                        image = img,
                        title = itemObj.optString("title").trim().take(120),
                        link = sanitizePromoLink(itemObj.optString("link")),
                        buttonText = itemObj.optString("button_text").trim().take(40),
                    )
                )
            }
            PromoManifest(enabled = enabled, closeDelaySec = closeSec, ads = items)
        } catch (e: Exception) {
            AppDiag.w("Repo", "invalid promo manifest", e)
            null
        }
    }

    private fun fetchOrLoadPromoManifest(timeoutMs: Int = 3000): PromoManifest? {
        val manifestFile = File(promoDir, "ads_manifest.json")
        val etagFile = File(promoDir, "ads_manifest.etag")
        val savedEtag = if (manifestFile.exists() && etagFile.exists()) {
            runCatching { etagFile.readText(Charsets.UTF_8).trim() }.getOrNull()
        } else null

        for (url in promoCandidates("ads.json")) {
            val resp = httpGetBounded(url, savedEtag, timeoutMs = timeoutMs) ?: continue
            if (resp.status == 304 && manifestFile.exists()) {
                val cachedTxt = runCatching { manifestFile.readText(Charsets.UTF_8) }.getOrNull()
                val parsed = cachedTxt?.let { parsePromoManifest(it) }
                if (parsed != null) return parsed
            }
            val body = resp.body
            if (!body.isNullOrBlank()) {
                val parsed = parsePromoManifest(body)
                if (parsed != null) {
                    runCatching {
                        writeAtomic(manifestFile, body)
                        if (!resp.etag.isNullOrBlank()) writeAtomic(etagFile, resp.etag)
                    }
                    return parsed
                }
            }
        }

        if (manifestFile.exists()) {
            val cachedTxt = runCatching { manifestFile.readText(Charsets.UTF_8) }.getOrNull()
            return cachedTxt?.let { parsePromoManifest(it) }
        }
        return null
    }

    private fun fetchOrLoadPromoImage(imageRef: String, timeoutMs: Int = 4000): File? {
        val target = promoImageCacheFile(imageRef)
        val etagFile = File(promoDir, "${target.name}.etag")
        val hasValidCached = target.exists() && runCatching {
            val head = ByteArray(16)
            val n = target.inputStream().use { it.read(head) }
            n >= 12 && isValidImageMagic(head.copyOf(n))
        }.getOrDefault(false)
        val savedEtag = if (hasValidCached && etagFile.exists()) {
            runCatching { etagFile.readText(Charsets.UTF_8).trim() }.getOrNull()
        } else null

        for (url in promoCandidates(imageRef)) {
            val resp = httpGetBytesBounded(url, savedEtag, timeoutMs = timeoutMs) ?: continue
            if (resp.status == 304 && hasValidCached) {
                return target
            }
            val bytes = resp.bytes
            if (bytes != null && isValidImageMagic(bytes)) {
                runCatching {
                    writeBytesAtomic(target, bytes)
                    if (!resp.etag.isNullOrBlank()) writeAtomic(etagFile, resp.etag)
                }
                return target
            }
        }

        return if (hasValidCached) target else null
    }

    /**
     * يختار الإعلان التالي بالتناوب في كل مرة يُفتح فيها التطبيق (1 -> 2 -> 3 -> 4 -> 5 -> 1)
     * مع التحقق السريع من أي تحديث للصور عبر ETag والرجوع السلس للكاش المحفوظ عند بطء الشبكة.
     */
    fun selectNextPromoBanner(prefs: Prefs): ResolvedPromoBanner? {
        val manifest = fetchOrLoadPromoManifest(timeoutMs = minOf(httpTimeoutMs, 3000)) ?: return null
        if (!manifest.enabled) return null
        val activeAds = manifest.ads.filter { it.enabled && it.image.isNotBlank() }
        if (activeAds.isEmpty()) return null

        val startIdx = (prefs.lastPromoRotationIndex + 1).mod(activeAds.size)
        for (offset in activeAds.indices) {
            val idx = (startIdx + offset) % activeAds.size
            val item = activeAds[idx]
            val imgFile = fetchOrLoadPromoImage(item.image, timeoutMs = minOf(httpTimeoutMs, 4000))
            if (imgFile != null && imgFile.exists()) {
                prefs.lastPromoRotationIndex = idx
                return ResolvedPromoBanner(
                    id = item.id,
                    imageFile = imgFile,
                    title = item.title,
                    link = item.link,
                    buttonText = item.buttonText,
                    closeDelaySec = manifest.closeDelaySec,
                    slotIndex = idx,
                    totalSlots = activeAds.size,
                )
            }
        }
        return null
    }

    /** يحمّل ويحدّث جميع صور الإعلانات الخمس في الخلفية لتكون جاهزة فورًا عند الفتحات القادمة. */
    fun syncAllPromoAssets() {
        val manifest = fetchOrLoadPromoManifest(timeoutMs = minOf(httpTimeoutMs, 5000)) ?: return
        if (!manifest.enabled) return
        manifest.ads.filter { it.enabled && it.image.isNotBlank() }.forEach { item ->
            fetchOrLoadPromoImage(item.image, timeoutMs = minOf(httpTimeoutMs, 6000))
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

    companion object {
        @JvmField
        internal val DEFAULT_OWNER: String = "oldman-552"
        @JvmField
        internal val DEFAULT_REPO: String = "vpn-configs"
        private const val MAX_BODY_BYTES = 10L * 1024L * 1024L
        private const val MAX_BODY_CHARS = 8_000_000
        private const val MAX_PARSED_SERVERS = 5_000
        private const val MAX_TOP500_CAPACITY = 500
        private const val MAX_PROMO_IMAGE_BYTES = 5 * 1024 * 1024

        fun containsSourceIdentifier(text: String): Boolean =
            text.contains(DEFAULT_OWNER, ignoreCase = true) ||
                text.contains(DEFAULT_REPO, ignoreCase = true)
    }
}
