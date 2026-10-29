// =====================================================================
// Tester.kt — فحص متوازٍ للكانفيغات على شبكة الهاتف + ترتيب الأفضل.
// مرحلتان: (1) فحص اتصال حقيقي لكل الكانفيغات (2) قياس سرعة لأفضل N.
// =====================================================================
package com.bahrain.vpnconfigs.engine

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.net.ServerSocket

data class TestProgress(
    val stage: String,
    val done: Int,
    val total: Int,
    val alive: Int,
)

class Tester(private val ctx: Context) {

    private val engine = SingBox(ctx)

    val engineAvailable: Boolean get() = engine.isAvailable

    /** توزيع عيّنة متوازنة بين البروتوكولات الموحّدة (round-robin) بدل أخذ أول N فقط. */
    fun pickBalanced(configs: List<String>, limit: Int): List<String> {
        if (limit <= 0 || configs.isEmpty()) return emptyList()
        val groups = LinkedHashMap<String, MutableList<String>>()
        configs.forEach { c ->
            groups.getOrPut(Converters.protocolBadge(c)) { mutableListOf() }.add(c)
        }
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

    /** تخصيص منافذ محلية متاحة وغير متصادمة بعدد العمليات المتوازية. */
    private fun allocatePortPool(conc: Int, basePort: Int = 21000): Channel<Int> {
        val pool = Channel<Int>(conc)
        var candidate = basePort
        var count = 0
        val loopback = InetAddress.getByName("127.0.0.1")
        while (count < conc && candidate < 60000) {
            val free = try {
                ServerSocket(candidate, 1, loopback).use { true }
            } catch (_: Exception) {
                false
            }
            if (free) {
                pool.trySend(candidate)
                count++
            }
            candidate++
        }
        while (count < conc) {
            pool.trySend(basePort + count)
            count++
        }
        return pool
    }

    suspend fun testSingle(
        cfg: String,
        timeoutSec: Int = 5,
        dnsServer: String = "1.1.1.1",
        useDoh: Boolean = false,
    ): TestResult = withContext(Dispatchers.IO) {
        if (!engine.isAvailable) return@withContext TestResult(cfg, error = "engine-missing")
        val pool = allocatePortPool(1, basePort = 22500)
        val port = pool.receive()
        pool.close()
        runInterruptible(Dispatchers.IO) {
            engine.test(cfg, port, timeoutSec, measureSpeed = false, dnsServer = dnsServer, useDoh = useDoh)
        }
    }

    /**
     * الفحص الكامل مع مجمّع منافذ آمن ضد التصادم ودعم الإيقاف الفوري.
     * @return قائمة مرتّبة (الأفضل أولًا) بالنتائج الناجحة فقط.
     */
    suspend fun run(
        configs: List<String>,
        testTop: Int,
        speedTop: Int,
        concurrency: Int,
        timeoutSec: Int,
        rankBySpeed: Boolean,
        dnsServer: String = "1.1.1.1",
        useDoh: Boolean = false,
        onProgress: suspend (TestProgress) -> Unit = {},
    ): List<TestResult> = withContext(Dispatchers.IO) {
        if (!engine.isAvailable) return@withContext emptyList()

        val supported = configs.filter { Converters.isSupported(it) }
        val candidates = pickBalanced(supported, testTop)
        if (candidates.isEmpty()) return@withContext emptyList()

        val conc = concurrency.coerceIn(1, 12)
        val ports = allocatePortPool(conc)

        // ── المرحلة 1: فحص الاتصال ──
        var done = 0
        var alive = 0
        onProgress(TestProgress("فحص الاتصال", 0, candidates.size, 0))

        val firstStage = coroutineScope {
            candidates.map { cfg ->
                async {
                    ensureActive()
                    val port = ports.receive()
                    val r = try {
                        ensureActive()
                        runInterruptible(Dispatchers.IO) {
                            engine.test(cfg, port, timeoutSec, measureSpeed = false, dnsServer = dnsServer, useDoh = useDoh)
                        }
                    } finally {
                        ports.trySend(port)
                    }
                    var snap: TestProgress? = null
                    synchronized(this@Tester) {
                        done++
                        if (r.ok) alive++
                        if (done % 4 == 0 || done == candidates.size) {
                            snap = TestProgress("قياس Real Delay", done, candidates.size, alive)
                        }
                    }
                    snap?.let { onProgress(it) }
                    r
                }
            }.awaitAll()
        }

        ports.close()

        val okList = firstStage.filter { it.ok && it.latencyMs > 0L }.sortedBy { it.latencyMs }
        if (okList.isEmpty()) return@withContext emptyList()

        // ── المرحلة 2: قياس السرعة الفعلي (توازي مضبوط ≤ 3 لمنع تشبّع الشبكة وتضخم التأخير) ──
        val speedPool = okList.take(maxOf(speedTop, 0))
        val speedMap = HashMap<String, Double>()

        if (speedPool.isNotEmpty()) {
            val speedConc = minOf(conc, 3)
            val speedPorts = allocatePortPool(speedConc, basePort = 21600)
            var sdone = 0
            onProgress(TestProgress("قياس السرعة", 0, speedPool.size, 0))
            try {
                coroutineScope {
                    speedPool.map { res ->
                        async {
                            ensureActive()
                            val port = speedPorts.receive()
                            val kbps = try {
                                ensureActive()
                                runInterruptible(Dispatchers.IO) {
                                    engine.measureSpeedOnly(
                                        res.cfg,
                                        port,
                                        timeoutSec + 2,
                                        dnsServer = dnsServer,
                                        useDoh = useDoh,
                                    )
                                }
                            } finally {
                                speedPorts.trySend(port)
                            }
                            var snap: TestProgress? = null
                            synchronized(this@Tester) {
                                if (kbps > 0.0) speedMap[res.cfg] = kbps
                                sdone++
                                snap = TestProgress("قياس السرعة", sdone, speedPool.size, speedMap.size)
                            }
                            snap?.let { onProgress(it) }
                        }
                    }.awaitAll()
                }
            } finally {
                speedPorts.close()
            }
        }

        val merged = okList.map { r ->
            r.copy(speedKbps = speedMap[r.cfg] ?: 0.0)
        }
        if (rankBySpeed) {
            merged.sortedWith(
                compareByDescending<TestResult> { it.speedKbps > 0 }
                    .thenByDescending { it.speedKbps }
                    .thenBy { it.latencyMs }
            )
        } else {
            merged.sortedWith(
                compareBy<TestResult> { it.latencyMs }
                    .thenByDescending { it.speedKbps }
            )
        }
    }
}
