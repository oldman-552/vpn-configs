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
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicInteger

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
        const val DEFAULT_BATCH_SIZE = 180
        const val DEFAULT_STAGE1_CONCURRENCY = 120
        const val DEFAULT_STAGE2_CONCURRENCY = 15
        const val BACKGROUND_SPEED_CAP = 15

        /** مجمّع خيوط IO مخصّص للفحص المتوازي يكسر سقف الـ 64 خيطًا الافتراضي في Dispatchers.IO. */
        val scanIoDispatcher = Dispatchers.IO.limitedParallelism(140)

        private val portCursor = AtomicInteger(25_000)
        private val rawIpv4Regex = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
        private val udpOutboundTypes = setOf("hysteria2", "hy2", "tuic", "wireguard")

        /** فحص أمني مسبق صارم يستبعد allowInsecure=1 والعقد المحجورة قبل إضاعة وقت الفحص أو الترتيب. */
        fun passesHardSecurityPreFilter(rawCfg: String, isVipAttested: Boolean = false): Boolean {
            val clean = Converters.cleanUri(rawCfg)
            if (clean.isBlank() || !Converters.isSupported(clean)) return false
            val sec = SecurityEvaluator.evaluate(rawCfg = clean, isVipAttested = isVipAttested)
            return !sec.quarantined && !sec.allowInsecure && sec.riskLevel != "CRITICAL"
        }

        fun allocateFreePorts(count: Int, basePort: Int = 0): List<Int> {
            if (count <= 0) return emptyList()
            val out = ArrayList<Int>(count)
            val loopback = InetAddress.getByName("127.0.0.1")
            val start = if (basePort in 20_000..56_000) {
                basePort
            } else {
                portCursor.getAndUpdate { cur ->
                    val next = cur + count + 20
                    if (next > 56_000) 25_000 else next
                }
            }
            var cand = start
            while (out.size < count && cand < 61_000) {
                val ok = try {
                    ServerSocket(cand, 1, loopback).use { true }
                } catch (_: Exception) {
                    false
                }
                if (ok) out.add(cand)
                cand++
            }
            var wrap = 23_000
            while (out.size < count && wrap < start) {
                val ok = try {
                    ServerSocket(wrap, 1, loopback).use { true }
                } catch (_: Exception) {
                    false
                }
                if (ok) out.add(wrap)
                wrap++
            }
            while (out.size < count) {
                out.add(25_000 + out.size)
            }
            return out
        }

        /**
         * فلترة TCP SYN فائقة السرعة (~600ms بتوازي 140) لعناوين IPv4 الخام لبروتوكولات TCP فقط:
         * • تمرّر تلقائيًا جميع بروتوكولات UDP/QUIC (HY2 / TUIC) دون لمسها.
         * • تمرّر تلقائيًا جميع النطاقات (Domains / CDN) لتجنب تسميم DNS المحلي على الشبكات المحجوبة.
         * • تستبعد فورًا السيرفرات المطفأة التي تستخدم IP خام قبل استهلاك وقت ومنافذ sing-box.
         */
        suspend fun fastTcpIpPreScreen(
            configs: List<String>,
            timeoutMs: Int = 480,
            onProgressTick: suspend (deadSoFar: Int) -> Unit = {},
        ): Pair<List<String>, List<String>> = coroutineScope {
            if (configs.isEmpty()) return@coroutineScope emptyList<String>() to emptyList()
            val tcpTargetsByEndpoint = LinkedHashMap<Pair<String, Int>, Int>()
            val endpointForIndex = arrayOfNulls<Pair<String, Int>>(configs.size)

            configs.forEachIndexed { idx, raw ->
                val ob = Converters.toOutbound(raw) ?: return@forEachIndexed
                val obType = ob.optString("type").lowercase()
                if (obType in udpOutboundTypes) return@forEachIndexed
                val transType = ob.optJSONObject("transport")?.optString("type")?.lowercase().orEmpty()
                if (transType == "quic") return@forEachIndexed
                val host = ob.optString("server").trim()
                val port = ob.optInt("server_port", 0)
                if (port in 1..65535 && rawIpv4Regex.matches(host)) {
                    val ep = host to port
                    endpointForIndex[idx] = ep
                    tcpTargetsByEndpoint[ep] = (tcpTargetsByEndpoint[ep] ?: 0) + 1
                }
            }

            if (tcpTargetsByEndpoint.isEmpty()) {
                return@coroutineScope configs to emptyList()
            }

            val sem = Semaphore(140)
            val reachableSet = HashSet<Pair<String, Int>>(tcpTargetsByEndpoint.size)
            val deadConfigEstimate = AtomicInteger(0)
            val reachableEpCount = AtomicInteger(0)

            tcpTargetsByEndpoint.entries.map { (ep, weight) ->
                async(scanIoDispatcher) {
                    ensureActive()
                    val ok = sem.withPermit {
                        ensureActive()
                        runInterruptible(scanIoDispatcher) {
                            try {
                                Socket().use { s ->
                                    s.tcpNoDelay = true
                                    s.connect(InetSocketAddress(ep.first, ep.second), timeoutMs)
                                    true
                                }
                            } catch (_: Exception) {
                                false
                            }
                        }
                    }
                    if (ok) {
                        reachableEpCount.incrementAndGet()
                    } else {
                        val est = deadConfigEstimate.addAndGet(weight)
                        if (reachableEpCount.get() > 0 && est % 10 < weight) {
                            onProgressTick(est)
                        }
                    }
                    ep to ok
                }
            }.awaitAll().forEach { (ep, ok) ->
                if (ok) reachableSet.add(ep)
            }

            // Offline safety: if >12 raw TCP IPs were probed and ZERO TCP SYN succeeded, pass all to Stage 1
            // so Stage 1's formal Offline Guard evaluates accurately without false mass-filtering!
            if (reachableSet.isEmpty() && tcpTargetsByEndpoint.size >= 12) {
                return@coroutineScope configs to emptyList()
            }

            val passed = ArrayList<String>(configs.size)
            val deadRawIpConfigs = ArrayList<String>()
            configs.forEachIndexed { idx, cfg ->
                val ep = endpointForIndex[idx]
                if (ep == null || ep in reachableSet) {
                    passed.add(cfg)
                } else {
                    deadRawIpConfigs.add(Converters.cleanUri(cfg))
                }
            }
            passed to deadRawIpConfigs
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
        val session = runInterruptible(scanIoDispatcher) {
            engine.startBatchDaemon(paired, dnsServer = dnsServer, useDoh = useDoh, waitMs = 1600L)
        }

        if (session == null) {
            // Fault-tolerant fallback: if >1 config in batch had an invalid outbound edge case, bisect cleanly
            if (chunk.size > 1) {
                val mid = (chunk.size + 1) / 2
                val left = runBatchProbeChunk(
                    chunk.subList(0, mid), 0, timeoutMs, parallelism,
                    measureThroughput, throughputBudgetBytes, dnsServer, useDoh, onItemDone,
                )
                val right = runBatchProbeChunk(
                    chunk.subList(mid, chunk.size), 0, timeoutMs, parallelism,
                    measureThroughput, throughputBudgetBytes, dnsServer, useDoh, onItemDone,
                )
                return@coroutineScope left + right
            }
            val singlePort = ports.first()
            val singleRes = runInterruptible(scanIoDispatcher) {
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
        val sem = Semaphore(parallelism.coerceIn(1, 140))
        try {
            chunk.map { rawCfg ->
                async(scanIoDispatcher) {
                    ensureActive()
                    val clean = Converters.cleanUri(rawCfg)
                    val slot = slotByClean[clean]
                    val res = if (slot == null) {
                        TestResult(rawCfg, ok = false, error = "unsupported", packetLossPct = 100.0)
                    } else {
                        sem.withPermit {
                            ensureActive()
                            runInterruptible(scanIoDispatcher) {
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

        val stage1Parallelism = maxOf(concurrency, DEFAULT_STAGE1_CONCURRENCY).coerceIn(8, 130)
        val stage1TimeoutMs = (timeoutSec.coerceIn(2, 5) * 380).coerceIn(1_150, 1_550)
        val stage1Title = tr("فحص الأنفاق فائق السرعة", "Fast Tunnel Check")

        onProgress(TestProgress(stage1Title, 0, candidates.size, 0))
        val (tunnelTargets, tcpDeadCleanList) = fastTcpIpPreScreen(candidates, timeoutMs = 480) { estDead ->
            onProgress(TestProgress(stage1Title, estDead.coerceAtMost(candidates.size - 1), candidates.size, 0))
        }
        var done = tcpDeadCleanList.size
        var alive = 0
        val liveAlive = ArrayList<TestResult>()
        val liveDead = LinkedHashSet<String>(insecureRejected).apply { addAll(tcpDeadCleanList) }
        if (done > 0) {
            onProgress(TestProgress(stage1Title, done, candidates.size, 0))
        }

        val firstStage = ArrayList<TestResult>(candidates.size)
        for (deadClean in tcpDeadCleanList) {
            firstStage.add(TestResult(deadClean, ok = false, error = "tcp-down", packetLossPct = 100.0))
        }

        val speedMap = HashMap<String, Double>()
        val speedTsMap = HashMap<String, Long>()
        var okList: List<TestResult> = emptyList()

        // Start all batch daemons concurrently upfront and keep warm sockets open through Stage 2 -> ZERO mid-scan pauses!
        val activeSessions = ArrayList<BatchDaemonSession>(3)
        try {
            if (tunnelTargets.isNotEmpty()) {
                val allPorts = allocateFreePorts(tunnelTargets.size, basePort = 0)
                val pairedAll = tunnelTargets.mapIndexed { idx, c -> c to allPorts[idx] }
                val startedSessions = coroutineScope {
                    pairedAll.chunked(DEFAULT_BATCH_SIZE).map { sub ->
                        async(scanIoDispatcher) {
                            runInterruptible(scanIoDispatcher) {
                                engine.startBatchDaemon(sub, dnsServer = dnsServer, useDoh = useDoh, waitMs = 1500L)
                            }
                        }
                    }.awaitAll().filterNotNull()
                }
                activeSessions.addAll(startedSessions)

                val slotByClean = HashMap<String, BatchOutboundSlot>(tunnelTargets.size)
                for (sess in activeSessions) {
                    for (slot in sess.slots) {
                        slotByClean[Converters.cleanUri(slot.cfg)] = slot
                    }
                }

                val sem1 = Semaphore(stage1Parallelism)
                val stage1Wave = coroutineScope {
                    tunnelTargets.map { rawCfg ->
                        async(scanIoDispatcher) {
                            ensureActive()
                            val clean = Converters.cleanUri(rawCfg)
                            val slot = slotByClean[clean]
                            val res = if (slot != null) {
                                sem1.withPermit {
                                    ensureActive()
                                    runInterruptible(scanIoDispatcher) {
                                        engine.probeSlotOnRunningBatch(
                                            slot = slot,
                                            timeoutMs = stage1TimeoutMs,
                                            measureThroughput = false,
                                            throughputBudgetBytes = 0L,
                                        )
                                    }
                                }
                            } else {
                                TestResult(rawCfg, ok = false, error = "invalid-config", packetLossPct = 100.0)
                            }
                            var snap: TestProgress? = null
                            synchronized(this@Tester) {
                                done++
                                if (res.ok && res.latencyMs > 0L) {
                                    alive++
                                    liveAlive.add(res)
                                } else {
                                    liveDead.add(clean)
                                }
                                if (done % 6 == 0 || done == candidates.size) {
                                    snap = TestProgress(stage1Title, done, candidates.size, alive)
                                }
                            }
                            snap?.let { onProgress(it) }
                            res
                        }
                    }.awaitAll()
                }
                firstStage.addAll(stage1Wave)
                onPartialResults(synchronized(this@Tester) { liveAlive.toList() }, synchronized(this@Tester) { liveDead.toSet() })

                val deadSet = LinkedHashSet<String>(insecureRejected)
                firstStage.filterNot { it.ok && it.latencyMs > 0L }.forEach { deadSet.add(Converters.cleanUri(it.cfg)) }
                if (deadSet.isNotEmpty()) {
                    onDeadDetected(deadSet)
                }

                okList = firstStage.filter { it.ok && it.latencyMs > 0L }
                    .sortedWith(compareBy<TestResult> { it.latencyMs }.thenBy { it.jitterMs })

                // ── المرحلة 2: قياس سرعة التنزيل الحقيقية (600 KB HTTPS) فورًا على نفس المنافذ الدافئة دون إعادة تشغيل sing-box ──
                val effectiveSpeedTop = speedTop.coerceIn(0, 60)
                val speedPool = okList.take(effectiveSpeedTop)
                if (speedPool.isNotEmpty() && throughputBudgetBytes >= 16_384L) {
                    var sdone = 0
                    val stage2Title = tr("قياس سرعة التنزيل الفعلية", "Measuring Real Download Speed")
                    onProgress(TestProgress(stage2Title, 0, speedPool.size, 0))
                    val sem2 = Semaphore(DEFAULT_STAGE2_CONCURRENCY)
                    coroutineScope {
                        speedPool.map { cand ->
                            async(scanIoDispatcher) {
                                ensureActive()
                                val clean = Converters.cleanUri(cand.cfg)
                                val slot = slotByClean[clean]
                                val kbps = if (slot != null) {
                                    sem2.withPermit {
                                        ensureActive()
                                        runInterruptible(scanIoDispatcher) {
                                            SingBox.measureFastBatchThroughputOnPort(
                                                port = slot.listenPort,
                                                connectTimeoutMs = 1_750,
                                                maxTransferMs = 1_650L,
                                                budgetBytes = throughputBudgetBytes,
                                            )
                                        }
                                    }
                                } else {
                                    0.0
                                }
                                var snap: TestProgress? = null
                                synchronized(this@Tester) {
                                    if (kbps > 0.0) {
                                        speedMap[cand.cfg] = kbps
                                        speedMap[clean] = kbps
                                        speedTsMap[cand.cfg] = System.currentTimeMillis()
                                    }
                                    sdone++
                                    snap = TestProgress(stage2Title, sdone, speedPool.size, speedTsMap.size)
                                }
                                snap?.let { onProgress(it) }
                            }
                        }.awaitAll()
                    }
                }
            } else {
                val deadSet = LinkedHashSet<String>(insecureRejected).apply { addAll(tcpDeadCleanList) }
                if (deadSet.isNotEmpty()) onDeadDetected(deadSet)
            }
        } finally {
            activeSessions.forEach { engine.stopBatchDaemon(it) }
        }

        if (okList.isEmpty()) return@withContext emptyList()

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
