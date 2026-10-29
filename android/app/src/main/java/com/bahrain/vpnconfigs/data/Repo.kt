// =====================================================================
// Repo.kt — تنزيل القائمة الحيّة الغنية بالمؤشرات (alive.json + القوائم المتخصّصة)
// مع التخزين المؤقت التدريجي (ETag / 304) والحماية من المدخلات المشوّهة أو الضخمة.
// =====================================================================
package com.bahrain.vpnconfigs.data

import android.content.Context
import android.util.Base64
import com.bahrain.vpnconfigs.engine.Converters
import com.bahrain.vpnconfigs.engine.TestResult
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

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
    val country: String = "",
    val stabilityRuns: Int = 0,
    val verifiedAt: String = "",
)

data class ResultLine(
    val cfg: String,
    val latencyMs: Long,
    val speedKbps: Double,
)

data class LoadResult(
    val configs: List<String>,
    val serverLatencies: Map<String, Long>,
    val meta: RemoteMeta,
    val source: String,
    val error: String? = null,
    val serverHints: Map<String, ServerHint> = emptyMap(),
)

class Repo(private val ctx: Context, private val owner: String, private val repo: String) {

    private val dir = File(ctx.filesDir, "data").apply { mkdirs() }

    val subscriptionUrl: String
        get() = "https://cdn.jsdelivr.net/gh/$owner/$repo@data/sub.txt"

    val reliableSubUrl: String
        get() = "https://cdn.jsdelivr.net/gh/$owner/$repo@data/reliable_sub.txt"

    val lowLatencyUrl: String
        get() = "https://cdn.jsdelivr.net/gh/$owner/$repo@data/low_latency.txt"

    val highThroughputUrl: String
        get() = "https://cdn.jsdelivr.net/gh/$owner/$repo@data/high_throughput.txt"

    val best100Url: String
        get() = "https://cdn.jsdelivr.net/gh/$owner/$repo@data/best100.txt"

    private fun candidates(file: String): List<String> = listOf(
        "https://cdn.jsdelivr.net/gh/$owner/$repo@data/$file",
        "https://raw.githubusercontent.com/$owner/$repo/data/$file",
        "https://$owner.github.io/$repo/$file",
    )

    private data class HttpResp(
        val status: Int,
        val body: String? = null,
        val etag: String? = null,
    )

    /** قراءة HTTP محدودة الحجم مع دعم If-None-Match لتوفير استهلاك البيانات والزمن. */
    private fun httpGetBounded(url: String, etag: String?, timeoutMs: Int = 20000): HttpResp? {
        var conn: HttpURLConnection? = null
        return try {
            conn = (URL(url).openConnection() as HttpURLConnection).apply {
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                requestMethod = "GET"
                setRequestProperty("User-Agent", "bahrain-vpn/2.1")
                if (!etag.isNullOrBlank()) {
                    setRequestProperty("If-None-Match", etag)
                }
                instanceFollowRedirects = true
            }
            val code = conn.responseCode
            if (code == HttpURLConnection.HTTP_NOT_MODIFIED) {
                return HttpResp(status = 304, etag = conn.getHeaderField("ETag") ?: etag)
            }
            if (code !in 200..299) return null
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
        } catch (_: Exception) {
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

    /** يجلب ملفًا مع دعم ETag ويعود للكاش المحلي تلقائيًا عند عدم التغيّر أو انقطاع الشبكة. */
    private fun fetch(file: String): Pair<String, String>? {
        val cachedFile = File(dir, file)
        val etagFile = File(dir, "$file.etag")
        val savedEtag = if (cachedFile.exists() && etagFile.exists()) {
            runCatching { etagFile.readText(Charsets.UTF_8).trim() }.getOrNull()
        } else null

        for (url in candidates(file)) {
            val resp = httpGetBounded(url, savedEtag)
            if (resp != null) {
                if (resp.status == 304 && cachedFile.exists()) {
                    return cachedFile.readText(Charsets.UTF_8) to "304:$url"
                }
                if (!resp.body.isNullOrBlank()) {
                    writeAtomic(cachedFile, resp.body)
                    if (!resp.etag.isNullOrBlank()) {
                        writeAtomic(etagFile, resp.etag)
                    }
                    return resp.body to url
                }
            }
        }
        if (cachedFile.exists()) {
            return runCatching { cachedFile.readText(Charsets.UTF_8) to "cache:${cachedFile.name}" }.getOrNull()
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
                alive = o.optInt("alive"),
                tested = o.optInt("tested"),
                channelsOk = o.optInt("channels_ok"),
                channelsTotal = o.optInt("channels_total"),
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
                if (!cleaned.contains("://")) continue
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
                        country = cc,
                        stabilityRuns = item.optInt("stability_runs", item.optInt("consecutive_alive", 0)),
                        verifiedAt = item.optString("verified_at", ""),
                    ),
                )
            }
        }
        return cfgs.toList() to hints
    }

    /** قراءة الأسطر النصية بمرونة واستخلاص زمن الاستجابة والدولة من الوسم إن وُجدا. */
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
            if (!cleaned.contains("://")) continue
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

    /** قراءة الكاش المحلي فورًا عند فتح التطبيق بدون طلب شبكي. */
    fun loadCached(feedProfile: String = "smart"): LoadResult? {
        val metaFile = File(dir, "meta.json")
        val meta = if (metaFile.exists()) parseMeta(runCatching { metaFile.readText(Charsets.UTF_8) }.getOrNull()) else RemoteMeta()

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
                        source = "cache:$profileFile",
                        serverHints = mergedHints,
                    )
                }
            }
        }

        if (jsonPair.first.isNotEmpty()) {
            return LoadResult(
                configs = jsonPair.first,
                serverLatencies = jsonPair.second.mapValues { it.value.latencyMs }.filterValues { it > 0L },
                meta = meta,
                source = "cache:alive.json",
                serverHints = jsonPair.second,
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
            source = "cache:alive.txt",
            serverHints = hints,
        )
    }

    private fun profileFileName(profile: String): String = when (profile) {
        "reliable" -> "reliable.txt"
        "low_latency" -> "low_latency.txt"
        "high_throughput" -> "high_throughput.txt"
        else -> "alive.json"
    }

    /** تنزيل القائمة الحيّة + مؤشرات الجودة والدول. */
    fun loadRemote(feedProfile: String = "smart"): LoadResult {
        val metaRaw = fetch("meta.json")
        val meta = parseMeta(metaRaw?.first)
        val jsonRaw = fetch("alive.json")
        val jsonParsed = if (jsonRaw != null) parseAliveJson(jsonRaw.first) else (emptyList<String>() to emptyMap())

        val targetFile = profileFileName(feedProfile)
        if (targetFile != "alive.json") {
            val specialRaw = fetch(targetFile)
            if (specialRaw != null) {
                val (sCfgs, sHints) = parseConfigLinesWithHints(specialRaw.first)
                if (sCfgs.isNotEmpty()) {
                    val mergedHints = HashMap(sHints).apply { putAll(jsonParsed.second) }
                    return LoadResult(
                        configs = sCfgs,
                        serverLatencies = mergedHints.mapValues { it.value.latencyMs }.filterValues { it > 0L },
                        meta = meta,
                        source = specialRaw.second,
                        serverHints = mergedHints,
                    )
                }
            }
        }

        if (jsonParsed.first.isNotEmpty()) {
            return LoadResult(
                configs = jsonParsed.first,
                serverLatencies = jsonParsed.second.mapValues { it.value.latencyMs }.filterValues { it > 0L },
                meta = meta,
                source = jsonRaw?.second ?: "alive.json",
                serverHints = jsonParsed.second,
            )
        }

        val listRaw = fetch("alive.txt")
        if (listRaw == null) {
            return LoadResult(
                emptyList(),
                emptyMap(),
                meta,
                "—",
                "تعذّر تنزيل القائمة الحيّة حاليًا — تأكّد من اتصال الإنترنت وحاول مجددًا",
            )
        }
        val (cfgs, hints) = parseConfigLinesWithHints(listRaw.first)
        return LoadResult(
            configs = cfgs,
            serverLatencies = hints.mapValues { it.value.latencyMs }.filterValues { it > 0L },
            meta = meta,
            source = listRaw.second,
            serverHints = hints,
        )
    }

    // ─────────── كتابة واسترجاع الملفات النهائية باسم موحّد bahrain-vpn ───────────
    val outDir: File
        get() = File(ctx.getExternalFilesDir(null) ?: ctx.filesDir, "configs")
            .apply { mkdirs() }

    fun existingAllFile(): File? = File(outDir, "config.txt").takeIf { it.exists() && it.length() > 0 }
    fun existingBestFile(): File? = File(outDir, "best100.txt").takeIf { it.exists() && it.length() > 0 }
    fun existingSubFile(): File? = File(outDir, "sub.txt").takeIf { it.exists() && it.length() > 0 }

    fun writeAll(configs: List<String>): File {
        val f = File(outDir, "config.txt")
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
        val bestFile = File(outDir, "best100.txt")
        writeAtomic(bestFile, plainText)

        val subFile = File(outDir, "sub.txt")
        val b64 = Base64.encodeToString(plainText.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
        writeAtomic(subFile, b64 + "\n")

        return bestFile to subFile
    }

    fun loadSavedBest(): List<TestResult> {
        val f = existingBestFile() ?: return emptyList()
        return runCatching {
            f.readLines(Charsets.UTF_8).mapNotNull { line ->
                val trimmed = line.trim()
                if (!trimmed.contains("://")) return@mapNotNull null
                val cfg = Converters.cleanUri(trimmed)
                val remark = Converters.extractRemark(trimmed)
                val parts = remark.split("|").map { it.trim() }
                val lat = parts.getOrNull(1)?.removeSuffix("ms")?.trim()?.toLongOrNull() ?: 0L
                val spd = parts.getOrNull(2)?.removeSuffix("KB/s")?.trim()?.toDoubleOrNull() ?: 0.0
                TestResult(cfg = cfg, ok = true, latencyMs = lat, speedKbps = spd)
            }
        }.getOrDefault(emptyList())
    }

    companion object {
        const val DEFAULT_OWNER = "oldman-552"
        const val DEFAULT_REPO = "vpn-configs"
        private const val MAX_BODY_BYTES = 10L * 1024L * 1024L
        private const val MAX_BODY_CHARS = 8_000_000
        private const val MAX_PARSED_SERVERS = 5_000
    }
}
