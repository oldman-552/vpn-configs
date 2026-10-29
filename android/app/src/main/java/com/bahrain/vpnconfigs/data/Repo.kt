// =====================================================================
// Repo.kt — تنزيل القائمة الحيّة من GitHub (عبر jsDelivr مع بدائل)
// وتخزينها محليًا، وكتابة ملفات المخرجات (config.txt / best100.txt).
// =====================================================================
package com.bahrain.vpnconfigs.data

import android.content.Context
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
    val meta: RemoteMeta,
    val source: String,
    val error: String? = null,
)

class Repo(private val ctx: Context, private val owner: String, private val repo: String) {

    private val dir = File(ctx.filesDir, "data").apply { mkdirs() }

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
                setRequestProperty("User-Agent", "BahrainConfigs/1.0")
                instanceFollowRedirects = true
            }
            if (conn.responseCode !in 200..299) return null
            conn.inputStream.bufferedReader().use { it.readText() }
        } catch (_: Exception) {
            null
        } finally {
            conn?.disconnect()
        }
    }

    /** يجلب ملفًا من أول مصدر ينجح ويحفظه محليًا (كاش احتياطي). */
    private fun fetch(file: String): Pair<String, String>? {
        for (url in candidates(file)) {
            val body = httpGet(url)
            if (!body.isNullOrBlank()) {
                File(dir, file).writeText(body)
                return body to url
            }
        }
        // فشل الشبكة: استخدم الكاش
        val cached = File(dir, file)
        if (cached.exists()) return cached.readText() to "cache:${cached.name}"
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

    /** تنزيل القائمة الحيّة + البيانات الوصفية. */
    fun loadRemote(): LoadResult {
        val metaRaw = fetch("meta.json")
        val listRaw = fetch("alive.txt")
        val meta = parseMeta(metaRaw?.first)
        if (listRaw == null) {
            return LoadResult(emptyList(), meta, "—", "تعذّر التنزيل ولا يوجد كاش محلي")
        }
        val cfgs = listRaw.first.lineSequence()
            .map { it.trim() }
            .filter { it.contains("://") }
            .map { it.substringBefore("#") }
            .distinct()
            .toList()
        return LoadResult(cfgs, meta, listRaw.second)
    }

    // ─────────── كتابة الملفات النهائية ───────────
    val outDir: File get() = File(ctx.getExternalFilesDir(null) ?: ctx.filesDir, "configs")
        .apply { mkdirs() }

    fun writeAll(configs: List<String>): File {
        val f = File(outDir, "config.txt")
        f.writeText(configs.joinToString("\n") { it } + "\n")
        return f
    }

    fun writeBest(results: List<ResultLine>, limit: Int): File {
        val f = File(outDir, "best100.txt")
        val sb = StringBuilder()
        results.take(limit).forEachIndexed { i, r ->
            val speed = if (r.speedKbps > 0) "${r.speedKbps.toInt()}KB/s" else "—"
            sb.append(r.cfg).append("#").append(i + 1)
                .append(" | ").append(r.latencyMs).append("ms")
                .append(" | ").append(speed).append('\n')
        }
        f.writeText(sb.toString())
        return f
    }

    companion object {
        const val DEFAULT_OWNER = "OWNER"
        const val DEFAULT_REPO = "REPO"
    }
}
