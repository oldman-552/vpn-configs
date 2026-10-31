// =====================================================================
// Tester.kt — فحص دفعي متوازٍ فائق السرعة للكانفيغات على شبكة الهاتف (v2):
//   • استبعاد أمني مسبق صارم (Hard Pre-Filter) لأي إعداد يحتوي allowInsecure=1 أو محجور أمنيًا.
//   • المرحلة 1: فحص حياة النفق المشفّر والكمون والتذبذب بدفعات موحّدة داخل نواة sing-box واحدة
//     (حتى 45 كونفيق في العملية الواحدة بتوازي 24–28 مسارًا ومهلة ذكية قصيرة ~2.3 ثانية).
//   • المرحلة 2: قياس سرعة التنزيل الحقيقية (600 KB HTTPS) لأفضل السيرفرات المستجيبة
//     بمعادلة دقيقة: KB/s = DownloadedBytes / 1024.0 / ElapsedSeconds.
// =====================================================================
package com.bahrain.vpnconfigs.engine

import android.content.Context
import com.bahrain.vpnconfigs.util.tr
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
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

    companion object {
        const val DEFAULT_BATCH_SIZE = 45
        const val DEFAULT_STAGE1_CONCURRENCY = 26
        const val DEFAULT_STAGE2_CONCURRENCY = 6
        const val BACKGROUND_SPEED_CAP = 15

        /** فحص أمني مسبق صارم يستبعد allowInsecure=1 والعقد المحجورة قبل إضاعة وقت الفحص أو الترتيب. */
        fun passesHardSecurityPreFilter(rawCfg: String, isVipAttested: Boolean = false): Boolean {
            val clean = Converters.cleanUri(rawCfg)
            if (clean.isBlank() || !Converters.isSupported(clean)) return false
            val sec = SecurityEvaluator.evaluate(rawCfg = clean, isVipAttested = isVipAttested)
            return !sec.quarantined && !sec.allowInsecure && sec.riskLevel != "CRITICAL"
        }

        fun allocateFreePorts(count: Int, basePort: Int = 23000): List<Int> {
            if (count <= 0) return emptyList()
            val out = ArrayList<Int>(count)
            val loopback = InetAddress.getByName("127.0.0.1")
            var cand = basePort
            while (out.size < count && cand < 61000) {
                val ok = try {
                    ServerSocket(cand, 1, loopback).use { true }
                } catch (_: Exception) {
                    false
                }
                if (ok) out.add(cand)
                cand++
            }
            while (out.size < count) {
                out.add(basePort + out.size)
            }
            return out
        }
    }

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

    suspend fun testSingle(
        cfg: String,
        timeoutSec: Int = 4,
        measureSpeed: Boolean = true,
        dnsServer: String = "1.1.1.1",
        useDoh: Boolean = false,
    ): TestResult = withContext(Dispatchers.IO) {
        if (!engine.isAvailable) return@withContext TestResult(cfg, error = "engine-missing")
        if (!passesHardSecurityPreFilter(cfg)) {
            return@withContext TestResult(cfg, ok = false, error = "insecure-blocked", packetLossPct = 100.0)
        }
        val port = allocateFreePorts(1, basePort = 22500).first()
        runInterruptible(Dispatchers.IO) {
            engine.test(cfg, port, timeoutSec.coerceIn(2, 10), measureSpeed = measureSpeed, dnsServer = dnsServer, useDoh = useDoh)
        }
    }

    private suspend fun runBatchProbeChunk(
        chunk: List<String>,
        basePort: Int,
        timeoutMs: Int,
        parallelism: Int,
        measureThroughput: Boolean,
        throughputBudgetBytes: Long,
        dnsServer: String,
        useDoh: Boolean,
        onItemDone: suspend (TestResult) -> Unit,
    ): List<TestResult> = coroutineScope {
        if (chunk.isEmpty()) return@coroutineScope emptyList()
        val ports = allocateFreePorts(chunk.size, basePort = basePort)
        val paired = chunk.mapIndexed { idx, c -> c to ports[idx] }
        val session = runInterruptible(Dispatchers.IO) {
            engine.startBatchDaemon(paired, dnsServer = dnsServer, useDoh = useDoh, waitMs = 2200L)
        }

        if (session == null) {
            // Fault-tolerant fallback: if >1 config in batch had an invalid outbound edge case, bisect cleanly
            if (chunk.size > 1) {
                val mid = (chunk.size + 1) / 2
                val left = runBatchProbeChunk(
                    chunk.subList(0, mid), basePort, timeoutMs, parallelism,
                    measureThroughput, throughputBudgetBytes, dnsServer, useDoh, onItemDone,
                )
                val right = runBatchProbeChunk(
                    chunk.subList(mid, chunk.size), basePort + mid + 5, timeoutMs, parallelism,
                    measureThroughput, throughputBudgetBytes, dnsServer, useDoh, onItemDone,
                )
                return@coroutineScope left + right
            }
            val singlePort = ports.first()
            val singleRes = runInterruptible(Dispatchers.IO) {
                engine.testRealTunnelSequential(
                    cfg = chunk.first(),
                    port = singlePort,
                    timeoutSec = (timeoutMs / 1000).coerceAtLeast(2),
                    probeSamples = 1,
                    measureThroughput = measureThroughput,
                    throughputBudgetBytes = throughputBudgetBytes,
                    dnsServer = dnsServer,
                    useDoh = useDoh,
                )
            }
            onItemDone(singleRes)
            return@coroutineScope listOf(singleRes)
        }

        val slotByClean = session.slots.associateBy { Converters.cleanUri(it.cfg) }
        val sem = Semaphore(parallelism.coerceIn(1, 32))
        try {
            chunk.map { rawCfg ->
                async(Dispatchers.IO) {
                    ensureActive()
                    val clean = Converters.cleanUri(rawCfg)
                    val slot = slotByClean[clean]
                    val res = if (slot == null) {
                        TestResult(rawCfg, ok = false, error = "unsupported", packetLossPct = 100.0)
                    } else {
                        sem.withPermit {
                            ensureActive()
                            runInterruptible(Dispatchers.IO) {
                                engine.probeSlotOnRunningBatch(
                                    slot = slot,
                                    timeoutMs = timeoutMs,
                                    measureThroughput = measureThroughput,
                                    throughputBudgetBytes = throughputBudgetBytes,
                                )
                            }
                        }
                    }
                    onItemDone(res)
                    res
                }
            }.awaitAll()
        } finally {
            engine.stopBatchDaemon(session)
        }
    }

    /**
     * الفحص الدفعي المتوازي فائق السرعة لـ 500 كونفيق (المرحلة 1 حياة واستجابة + المرحلة 2 تنزيل حقيقي 600 KB).
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
        throughputBudgetBytes: Long = SingBox.SPEED_BYTES,
        onProgress: suspend (TestProgress) -> Unit = {},
        onDeadDetected: (Set<String>) -> Unit = {},
        onPartialResults: suspend (aliveSoFar: List<TestResult>, deadSoFar: Set<String>) -> Unit = { _, _ -> },
    ): List<TestResult> = withContext(Dispatchers.IO) {
        if (!engine.isAvailable) return@withContext emptyList()

        val allSupported = configs.filter { Converters.isSupported(it) }
        val insecureRejected = LinkedHashSet<String>()
        val safeSupported = ArrayList<String>(allSupported.size)
        for (c in allSupported) {
            if (passesHardSecurityPreFilter(c)) {
                safeSupported.add(c)
            } else {
                insecureRejected.add(Converters.cleanUri(c))
            }
        }
        val candidates = pickBalanced(safeSupported, testTop)
        if (candidates.isEmpty()) {
            if (insecureRejected.isNotEmpty()) onDeadDetected(insecureRejected)
            return@withContext emptyList()
        }

        val stage1Parallelism = maxOf(concurrency, DEFAULT_STAGE1_CONCURRENCY).coerceIn(8, 30)
        val stage1TimeoutMs = (timeoutSec.coerceIn(2, 5) * 650).coerceIn(1_800, 2_800)

        var done = 0
        var alive = 0
        val liveAlive = ArrayList<TestResult>()
        val liveDead = LinkedHashSet<String>(insecureRejected)
        onProgress(TestProgress(tr("فحص الأنفاق فائق السرعة", "Fast Tunnel Check"), 0, candidates.size, 0))

        val firstStage = ArrayList<TestResult>(candidates.size)
        val batches = candidates.chunked(DEFAULT_BATCH_SIZE)
        for ((bIdx, batch) in batches.withIndex()) {
            ensureActive()
            val batchResults = runBatchProbeChunk(
                chunk = batch,
                basePort = 23000 + (bIdx % 6) * 60,
                timeoutMs = stage1TimeoutMs,
                parallelism = stage1Parallelism,
                measureThroughput = false,
                throughputBudgetBytes = 0L,
                dnsServer = dnsServer,
                useDoh = useDoh,
            ) { r ->
                var snap: TestProgress? = null
                synchronized(this@Tester) {
                    done++
                    if (r.ok && r.latencyMs > 0L) {
                        alive++
                        liveAlive.add(r)
                    } else {
                        liveDead.add(Converters.cleanUri(r.cfg))
                    }
                    if (done % 8 == 0 || done == candidates.size) {
                        snap = TestProgress(tr("فحص الأنفاق فائق السرعة", "Fast Tunnel Check"), done, candidates.size, alive)
                    }
                }
                snap?.let { onProgress(it) }
            }
            firstStage.addAll(batchResults)
            onPartialResults(synchronized(this@Tester) { liveAlive.toList() }, synchronized(this@Tester) { liveDead.toSet() })
        }

        val deadSet = LinkedHashSet<String>(insecureRejected)
        firstStage.filterNot { it.ok && it.latencyMs > 0L }.forEach { deadSet.add(Converters.cleanUri(it.cfg)) }
        if (deadSet.isNotEmpty()) {
            onDeadDetected(deadSet)
        }

        val okList = firstStage.filter { it.ok && it.latencyMs > 0L }
            .sortedWith(
                compareBy<TestResult> { it.latencyMs }
                    .thenBy { it.jitterMs }
            )
        if (okList.isEmpty()) return@withContext emptyList()

        // ── المرحلة 2: قياس سرعة التنزيل الحقيقية (600 KB HTTPS) داخل دفعة sing-box دافئة واحدة ──
        val effectiveSpeedTop = speedTop.coerceIn(0, 60)
        val speedPool = okList.take(effectiveSpeedTop)
        val speedMap = HashMap<String, Double>()
        val speedTsMap = HashMap<String, Long>()

        if (speedPool.isNotEmpty() && throughputBudgetBytes >= 16_384L) {
            var sdone = 0
            onProgress(TestProgress(tr("قياس سرعة التنزيل الفعلية", "Measuring Real Download Speed"), 0, speedPool.size, 0))
            for ((sIdx, sBatch) in speedPool.map { it.cfg }.chunked(DEFAULT_BATCH_SIZE).withIndex()) {
                ensureActive()
                val ports = allocateFreePorts(sBatch.size, basePort = 24200 + (sIdx % 3) * 60)
                val paired = sBatch.mapIndexed { idx, c -> c to ports[idx] }
                val session = runInterruptible(Dispatchers.IO) {
                    engine.startBatchDaemon(paired, dnsServer = dnsServer, useDoh = useDoh, waitMs = 2200L)
                }
                if (session != null) {
                    val sem = Semaphore(DEFAULT_STAGE2_CONCURRENCY)
                    try {
                        coroutineScope {
                            session.slots.map { slot ->
                                async(Dispatchers.IO) {
                                    ensureActive()
                                    val kbps = sem.withPermit {
                                        ensureActive()
                                        runInterruptible(Dispatchers.IO) {
                                            SingBox.measureDownloadThroughputOnPort(
                                                port = slot.listenPort,
                                                timeoutMs = 6_500,
                                                budgetBytes = throughputBudgetBytes,
                                            )
                                        }
                                    }
                                    var snap: TestProgress? = null
                                    synchronized(this@Tester) {
                                        if (kbps > 0.0) {
                                            speedMap[slot.cfg] = kbps
                                            speedTsMap[slot.cfg] = System.currentTimeMillis()
                                        }
                                        sdone++
                                        if (sdone % 3 == 0 || sdone == speedPool.size) {
                                            snap = TestProgress(
                                                tr("قياس سرعة التنزيل الفعلية", "Measuring Real Download Speed"),
                                                sdone,
                                                speedPool.size,
                                                speedMap.size,
                                            )
                                        }
                                    }
                                    snap?.let { onProgress(it) }
                                }
                            }.awaitAll()
                        }
                    } finally {
                        engine.stopBatchDaemon(session)
                    }
                }
            }
        }

        val nowCompletedMs = System.currentTimeMillis()
        val merged = okList.map { r ->
            val spd = speedMap[r.cfg] ?: 0.0
            val ts = speedTsMap[r.cfg] ?: nowCompletedMs
            r.copy(
                speedKbps = spd,
                testedAtMs = if (spd > 0.0) ts else r.testedAtMs,
            )
        }
        if (rankBySpeed) {
            merged.sortedWith(
                compareByDescending<TestResult> { it.speedKbps }
                    .thenByDescending { it.stabilityScore }
                    .thenBy { it.latencyMs }
                    .thenBy { it.jitterMs }
            )
        } else {
            merged.sortedWith(
                compareBy<TestResult> { it.latencyMs }
                    .thenBy { it.jitterMs }
                    .thenByDescending { it.speedKbps }
            )
        }
    }
}
