// =====================================================================
// Repo.kt — تنزيل القائمة الحيّة من GitHub (عبر jsDelivr مع بدائل)
// وتخزينها محليًا، وتصدير الكانفيغات باسم موحّد (bahrain-vpn).
// =====================================================================
package com.bahrain.vpnconfigs.data

import android.content.Context
import android.util.Base64
import com.bahrain.vpnconfigs.engine.Converters
import com.bahrain.vpnconfigs.engine.TestResult
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
)

class Repo(private val ctx: Context, private val owner: String, private val repo: String) {

    private val dir = File(ctx.filesDir, "data").apply { mkdirs() }

    val subscriptionUrl: String
        get() = "https://cdn.jsdelivr.net/gh/$owner/$repo@data/sub.txt"

    val best100Url: String
        get() = "https://cdn.jsdelivr.net/gh/$owner/$repo@data/best100.txt"

    /** كل الروابط المرشّحة بالترتيب: jsDelivr ثم raw ثم GitHub Pages. */
    private fun candidates(file: String): List<String> = listOf(
        "https://cdn.jsdelivr.net/gh/$owner/$repo@data/$file",
        "https://raw.githubusercontent.com/$owner/$repo/data/$file",
        "https://$owner.github.io/$repo/$file",
    )

    private fun httpGet(url: String, timeoutMs: Int = 20000): String? {
        var conn: HttpURLConnection? = null
        return try {
            conn = (URL(url).openConnection() as HttpURLConnection).apply {
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                requestMethod = "GET"
                setRequestProperty("User-Agent", "bahrain-vpn/2.0")
                instanceFollowRedirects = true
            }
            if (conn.responseCode !in 200..299) return null
            conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
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

    /** يجلب ملفًا من أول مصدر ينجح ويحفظه محليًا (كاش احتياطي). */
    private fun fetch(file: String): Pair<String, String>? {
        for (url in candidates(file)) {
            val body = httpGet(url)
            if (!body.isNullOrBlank()) {
                writeAtomic(File(dir, file), body)
                return body to url
            }
        }
        val cached = File(dir, file)
        if (cached.exists()) return cached.readText(Charsets.UTF_8) to "cache:${cached.name}"
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
            RemoteMeta(
                generatedAt = o.optString("generated_at", "—"),
                alive = o.optInt("alive"),
                tested = o.optInt("tested"),
                channelsOk = o.optInt("channels_ok"),
                channelsTotal = o.optInt("channels_total"),
                byProtocol = byProto,
            )
        } catch (_: Exception) {
            RemoteMeta()
        }
    }

    /** قراءة الأسطر واستخلاص أي زمن استجابة مبدئي مرفق من الخادم (إن وُجد). */
    private fun parseConfigLinesWithHints(rawText: String): Pair<List<String>, Map<String, Long>> {
        val cfgs = LinkedHashSet<String>()
        val hints = HashMap<String, Long>()
        val msRegex = Regex("(\\d+)\\s*ms", RegexOption.IGNORE_CASE)
        rawText.lineSequence().forEach { rawLine ->
            val trimmed = rawLine.trim()
            if (!trimmed.contains("://")) return@forEach
            val cleaned = Converters.cleanUri(trimmed)
            if (!cleaned.contains("://")) return@forEach
            cfgs.add(cleaned)
            val remark = Converters.extractRemark(trimmed)
            msRegex.find(remark)?.groupValues?.getOrNull(1)?.toLongOrNull()?.let { ms ->
                if (ms > 0) hints.putIfAbsent(cleaned, ms)
            }
        }
        return cfgs.toList() to hints
    }

    /** قراءة الكاش المحلي فورًا عند فتح التطبيق بدون طلب شبكي. */
    fun loadCached(): LoadResult? {
        val listFile = File(dir, "alive.txt")
        if (!listFile.exists()) return null
        val metaFile = File(dir, "meta.json")
        val meta = if (metaFile.exists()) parseMeta(metaFile.readText(Charsets.UTF_8)) else RemoteMeta()
        val (cfgs, hints) = parseConfigLinesWithHints(listFile.readText(Charsets.UTF_8))
        if (cfgs.isEmpty()) return null
        return LoadResult(cfgs, hints, meta, "cache:alive.txt")
    }

    /** تنزيل القائمة الحيّة + البيانات الوصفية. */
    fun loadRemote(): LoadResult {
        val metaRaw = fetch("meta.json")
        val listRaw = fetch("alive.txt")
        val meta = parseMeta(metaRaw?.first)
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
        return LoadResult(cfgs, hints, meta, listRaw.second)
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

    /** تنويع المضيفين بحد أقصى لكل مضيف مع استكمال العدد إن لزم. */
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

    /** استرجاع نتائج آخر فحص محفوظة في best100.txt عند إعادة فتح التطبيق. */
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
    }
}
