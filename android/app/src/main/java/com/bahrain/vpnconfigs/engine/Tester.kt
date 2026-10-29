// =====================================================================
// Tester.kt — فحص متوازٍ للكانفيغات على شبكة الهاتف + ترتيب الأفضل.
// مرحلتان: (1) فحص اتصال حقيقي لكل الكانفيغات (2) قياس سرعة لأفضل N.
// =====================================================================
package com.bahrain.vpnconfigs.engine

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext

data class TestProgress(
    val stage: String,
    val done: Int,
    val total: Int,
    val alive: Int,
)

class Tester(private val ctx: Context) {

    private val engine = SingBox(ctx)

    val engineAvailable: Boolean get() = engine.isAvailable

    /** توزيع عيّنة متوازنة بين البروتوكولات (round-robin) بدل أخذ أول N فقط. */
    fun pickBalanced(configs: List<String>, limit: Int): List<String> {
        val groups = LinkedHashMap<String, MutableList<String>>()
        configs.forEach { c -> groups.getOrPut(c.substringBefore("://")) { mutableListOf() }.add(c) }
        val idx = groups.keys.associateWith { 0 }.toMutableMap()
        val out = ArrayList<String>(minOf(limit, configs.size))
        while (out.size < limit) {
            var progressed = false
            for (s in groups.keys) {
                val i = idx[s] ?: 0
                val list = groups[s] ?: continue
                if (i < list.size) {
                    out.add(list[i])
                    idx[s] = i + 1
                    progressed = true
                    if (out.size >= limit) break
                }
            }
            if (!progressed) break
        }
        return out
    }

    /**
     * الفحص الكامل. onProgress يُنادى بعد كل عقدة (استخدمه لتحديث الواجهة).
     * @return قائمة مرتّبة (الأفضل أولًا) بالنتائج الناجحة فقط.
     */
    suspend fun run(
        configs: List<String>,
        testTop: Int,
        speedTop: Int,
        concurrency: Int,
        timeoutSec: Int,
        rankBySpeed: Boolean,
        onProgress: (TestProgress) -> Unit = {},
    ): List<TestResult> = withContext(Dispatchers.IO) {
        if (!engine.isAvailable) return@withContext emptyList()

        val supported = configs.filter { Converters.isSupported(it) }
        val candidates = pickBalanced(supported, testTop)
        if (candidates.isEmpty()) return@withContext emptyList()

        // ── المرحلة 1: فحص الاتصال ──
        val sem = Semaphore(concurrency.coerceIn(1, 12))
        var done = 0
        var alive = 0
        val basePort = 21000

        val firstStage = coroutineScope {
            candidates.mapIndexed { i, cfg ->
                async {
                    sem.withPermit {
                        val port = basePort + (i % concurrency.coerceIn(1, 12))
                        val r = engine.test(cfg, port, timeoutSec, measureSpeed = false)
                        synchronized(this@Tester) {
                            done++
                            if (r.ok) alive++
                            if (done % 5 == 0 || done == candidates.size) {
                                onProgress(TestProgress("فحص الاتصال", done, candidates.size, alive))
                            }
                        }
                        r
                    }
                }
            }.awaitAll()
        }

        val okList = firstStage.filter { it.ok }.sortedBy { it.latencyMs }
        if (okList.isEmpty()) return@withContext emptyList()

        // ── المرحلة 2: قياس السرعة ──
        val speedPool = okList.take(maxOf(speedTop, 0))
        var sdone = 0
        val speedMap = HashMap<String, Double>()

        coroutineScope {
            speedPool.mapIndexed { i, res ->
                async {
                    sem.withPermit {
                        val port = basePort + (i % concurrency.coerceIn(1, 12))
                        val r = engine.test(res.cfg, port, timeoutSec, measureSpeed = true)
                        synchronized(this@Tester) {
                            if (r.ok && r.speedKbps > 0) speedMap[res.cfg] = r.speedKbps
                            sdone++
                            onProgress(TestProgress("قياس السرعة", sdone, speedPool.size,
                                speedMap.size))
                        }
                    }
                }
            }.awaitAll()
        }

        val merged = okList.map { r ->
            r.copy(speedKbps = speedMap[r.cfg] ?: 0.0)
        }
        if (rankBySpeed) {
            merged.sortedWith(compareByDescending<TestResult> { it.speedKbps > 0 }
                .thenByDescending { it.speedKbps }
                .thenBy { it.latencyMs })
        } else {
            merged.sortedBy { it.latencyMs }
        }
    }
}
