// =====================================================================
// SingBox.kt — تشغيل نواة sing-box محليًا (للفحص المتوازي أو لنفق الـ VPN).
//
// النواة تُشحن كـ libsingbox.so داخل jniLibs لتكون قابلة للتنفيذ في أندرويد.
// تضم إعداد DNS متوافق مع sing-box 1.14+ (domain_resolver) لضمان عمل العُقد
// التي تستخدم أسماء نطاقات بدل عناوين IP على أندرويد بدون /etc/resolv.conf.
// =====================================================================
package com.bahrain.vpnconfigs.engine

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.TimeUnit

data class TestResult(
    val cfg: String,
    val ok: Boolean = false,
    val latencyMs: Long = 0,
    val speedKbps: Double = 0.0,
    val error: String = "",
    val engine: String = "sing-box",
    val testedAtMs: Long = System.currentTimeMillis(),
    val establishMs: Long = 0L,
    val jitterMs: Double = 0.0,
    val packetLossPct: Double = 0.0,
    val stabilityScore: Double = 0.0,
)

data class RunningDaemon(
    val process: Process,
    val configFile: File,
    val port: Int,
)

data class BatchOutboundSlot(
    val index: Int,
    val cfg: String,
    val listenPort: Int,
)

data class BatchDaemonSession(
    val process: Process,
    val configFile: File,
    val slots: List<BatchOutboundSlot>,
)

class SingBox(private val ctx: Context) {

    companion object {
        const val TEST_URL = "https://www.gstatic.com/generate_204"
        const val SPEED_URL = "https://speed.cloudflare.com/__down?bytes=600000"
        const val VPN_SOCKS_PORT = 20808
        const val SPEED_BYTES = 600_000L
        val DEFAULT_SPEED_ENDPOINTS: List<String> = listOf(
            SPEED_URL,
            "https://nbg1-speed.hetzner.com/1MB.bin",
            "https://ash-speed.hetzner.com/1MB.bin",
        )
        val IR_DOMAIN_SUFFIXES: List<String> = listOf(".ir", ".xn--mgba3a4f16a")

        fun resolveSpeedEndpoints(
            budgetBytes: Long = SPEED_BYTES,
            customPrimaryUrl: String = "",
        ): List<String> {
            val out = ArrayList<String>(4)
            val custom = customPrimaryUrl.trim()
            if (custom.startsWith("https://", ignoreCase = true)) {
                out.add(custom)
            }
            val cfUrl = if (budgetBytes in 16_384L until SPEED_BYTES) {
                "https://speed.cloudflare.com/__down?bytes=$budgetBytes"
            } else {
                SPEED_URL
            }
            if (cfUrl !in out) out.add(cfUrl)
            DEFAULT_SPEED_ENDPOINTS.drop(1).forEach { if (it !in out) out.add(it) }
            return out
        }

        fun measureDownloadThroughputOnPort(
            port: Int,
            timeoutMs: Int,
            budgetBytes: Long = SPEED_BYTES,
            customPrimaryUrl: String = "",
        ): Double {
            if (budgetBytes < 8_192L) return 0.0
            val endpoints = resolveSpeedEndpoints(budgetBytes, customPrimaryUrl)
            val cappedTimeout = timeoutMs.coerceIn(2_500, 12_000)
            for ((idx, url) in endpoints.withIndex()) {
                if (Thread.currentThread().isInterrupted) return 0.0
                val perTryTimeout = if (idx == 0) cappedTimeout else minOf(cappedTimeout, 4_500)
                val sp = runCatching {
                    Socks.get(port, url, perTryTimeout, budgetBytes)
                }.getOrNull() ?: continue
                val dtSec = maxOf(sp.transferMs / 1000.0, 0.005)
                if (sp.status in listOf(200, 206) && sp.bytes >= 8_192L) {
                    return (sp.bytes / 1024.0) / dtSec
                }
            }
            return 0.0
        }
    }

    /** مسار النواة داخل مجلد المكتبات الأصلية (قابل للتنفيذ). */
    val binaryPath: String by lazy {
        File(ctx.applicationInfo.nativeLibraryDir, "libsingbox.so").absolutePath
    }

    val isAvailable: Boolean
        get() = File(binaryPath).let { it.exists() && it.canExecute() }

    private val prefs by lazy { com.bahrain.vpnconfigs.data.Prefs(ctx) }

    /** TLS fragmentation for the current network (setting ON/OFF, or AUTO from the last block probe). */
    private fun tlsFragmentEnabled(): Boolean = runCatching {
        TlsFragment.shouldEnable(
            prefs.tlsFragmentMode,
            BlockingProfile.fromJson(prefs.blockingProfileJson),
            com.bahrain.vpnconfigs.vpn.VpnStateManager.status.value.underlyingNetwork,
        )
    }.getOrDefault(false)

    private val tmpDir: File by lazy {
        File(ctx.cacheDir, "sbx").apply { mkdirs() }
    }

    private val ipv4LiteralRe = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")

    private fun isIpLiteral(host: String): Boolean {
        val h = host.trim().removeSurrounding("[", "]")
        return ipv4LiteralRe.matches(h) || h.contains(':')
    }

    /**
     * يختار عنوان IPv4 صالح ومباشر لمحلّل `direct-dns` الخاص بنطاقات `.ir` (يتجنب عناوين النفق الوهمية أو Loopback).
     */
    fun resolveDirectDnsServer(physicalDnsServer: String?): String {
        val cand = physicalDnsServer?.trim().orEmpty()
        if (ipv4LiteralRe.matches(cand)) {
            val parts = cand.split('.').mapNotNull { it.toIntOrNull() }
            if (parts.size == 4 && parts.all { it in 0..255 }) {
                val p0 = parts[0]
                val p1 = parts[1]
                val isLoopbackOrZero = p0 == 0 || p0 == 127
                val isLinkLocal = p0 == 169 && p1 == 254
                val isTunSynthetic = (p0 == 198 && (p1 == 18 || p1 == 19)) || p0 >= 224
                if (!isLoopbackOrZero && !isLinkLocal && !isTunSynthetic) {
                    return cand
                }
            }
        }
        return "1.1.1.1"
    }

    /**
     * بناء ملف إعداد كامل متوافق مع sing-box 1.14.4 مع حماية صارمة من تسرب DNS و IPv6
     * وتوجيه مباشر اختياري (مفعّل افتراضيًا في النفق) لنطاقات `.ir` و `.ایران`:
     *   • خادم `bootstrap` (1.1.1.1 مباشر) يُستخدم حصريًا لحل اسم نطاق سيرفر البروكسي نفسه.
     *   • خادم `tunnel-dns` يحمل `"detour": "proxy"` ويُعيّن كـ `dns.final` و`default_domain_resolver`
     *     بحيث تمرّ استعلامات DNS داخل النفق المشفّر ولا تتسرب لمزوّد الإنترنت.
     *   • عند تفعيل `bypassIrDomains`: تُحلّ نطاقات `.ir` و `.xn--mgba3a4f16a` عبر `direct-dns` وتُوجَّه
     *     مباشرة عبر `direct` مع تفعيل `sniff` لكشف `TLS SNI / HTTP Host` حتى للاتصالات المباشرة بالـ IP.
     */
    fun buildConfig(
        cfg: String,
        port: Int,
        dnsServer: String = "1.1.1.1",
        useDoh: Boolean = false,
        enableIpv6: Boolean = false,
        bypassIrDomains: Boolean = false,
        physicalDnsServer: String? = null,
    ): String? {
        val warp = if (WarpManager.isWarp(cfg)) WarpAccount.fromJson(prefs.warpAccountJson) ?: return null else null
        val out = if (warp == null) Converters.toOutbound(cfg) ?: return null else null
        val safeDns = com.bahrain.vpnconfigs.vpn.LeakProtectionEngine.sanitizeDnsServer(dnsServer)
        val domainStrategy = if (enableIpv6) "prefer_ipv4" else "ipv4_only"

        val dnsServers = JSONArray()
        // 1. محلّل التمهيد المباشر لحل عنوان سيرفر الـ VPN نفسه دون حلقة توجيه (Routing Loop)
        dnsServers.put(
            JSONObject()
                .put("type", "udp")
                .put("tag", "bootstrap")
                .put("server", "1.1.1.1")
        )

        // 2. محلّل النفق المشفّر لجميع طلبات التطبيقات والمستخدم (يمرّ إجباريًا داخل proxy)
        val tunnelDns = JSONObject()
            .put("type", if (useDoh) "https" else "udp")
            .put("tag", "tunnel-dns")
            .put("server", safeDns)
            .put("detour", "proxy")

        if (!isIpLiteral(safeDns)) {
            tunnelDns.put("domain_resolver", "bootstrap")
        }
        dnsServers.put(tunnelDns)

        out?.let {
            if (tlsFragmentEnabled()) TlsFragment.apply(it)
            it.put("tag", "proxy")
            it.put("domain_resolver", "bootstrap")
        }

        val dnsObj = JSONObject()
            .put("servers", dnsServers)
            .put("final", "tunnel-dns")
            .put("strategy", domainStrategy)

        val routeObj = JSONObject()
            .put("final", "proxy")
            .put("default_domain_resolver", "tunnel-dns")

        val outboundsArr = JSONArray()
        out?.let { outboundsArr.put(it) }

        if (bypassIrDomains) {
            val irSuffixArr = JSONArray().apply {
                IR_DOMAIN_SUFFIXES.forEach { put(it) }
            }
            val directDnsIp = resolveDirectDnsServer(physicalDnsServer)
            dnsServers.put(
                JSONObject()
                    .put("type", "udp")
                    .put("tag", "direct-dns")
                    .put("server", directDnsIp)
            )
            dnsObj.put(
                "rules",
                JSONArray().put(
                    JSONObject()
                        .put("domain_suffix", irSuffixArr)
                        .put("action", "route")
                        .put("server", "direct-dns")
                )
            )
            routeObj.put(
                "rules",
                JSONArray()
                    .put(JSONObject().put("action", "sniff"))
                    .put(
                        JSONObject()
                            .put("domain_suffix", JSONArray().apply { IR_DOMAIN_SUFFIXES.forEach { put(it) } })
                            .put("action", "route")
                            .put("outbound", "direct")
                    )
            )
            outboundsArr.put(
                JSONObject()
                    .put("type", "direct")
                    .put("tag", "direct")
                    .put("domain_resolver", "direct-dns")
            )
        }

        val conf = JSONObject()
            .put("log", JSONObject().put("level", "error").put("timestamp", false))
            .put("dns", dnsObj)
            .put("route", routeObj)
            .put(
                "inbounds",
                JSONArray().put(
                    JSONObject()
                        .put("type", "mixed")
                        .put("tag", "in")
                        .put("listen", "127.0.0.1")
                        .put("listen_port", port)
                ),
            )
            .put("outbounds", outboundsArr)
        warp?.let { conf.put("endpoints", JSONArray().put(it.toSingBoxEndpoint())) }
        return conf.toString()
    }

    /**
     * بناء ملف إعداد دفعي متوافق 100% مع sing-box 1.14.4 يجمع حتى 50 كونفيق داخل عملية نظام واحدة فقط:
     * يربط كل منفذ محلي `in-$i` (`127.0.0.1:port_i`) بالـ outbound المشفّر المقابل `proxy-$i`
     * مما يقضي نهائيًا على بطء تشغيل 500 عملية منفصلة ويجعل فحص الـ 500 كونفيق يتم خلال ثوانٍ.
     */
    fun buildBatchConfig(
        items: List<Pair<String, Int>>,
        dnsServer: String = "1.1.1.1",
        useDoh: Boolean = false,
    ): Pair<String, List<BatchOutboundSlot>>? {
        if (items.isEmpty()) return null
        val safeDns = com.bahrain.vpnconfigs.vpn.LeakProtectionEngine.sanitizeDnsServer(dnsServer)
        val applyFrag = tlsFragmentEnabled()

        val inboundsArr = JSONArray()
        val outboundsArr = JSONArray()
        val rulesArr = JSONArray()
        val validSlots = ArrayList<BatchOutboundSlot>(items.size)
        val usedPorts = HashSet<Int>(items.size)

        items.forEachIndexed { rawIdx, (cfg, listenPort) ->
            if (listenPort !in 1025..65534 || !usedPorts.add(listenPort)) return@forEachIndexed
            if (WarpManager.isWarp(cfg)) return@forEachIndexed
            val out = Converters.toOutbound(cfg) ?: return@forEachIndexed
            val slotIdx = validSlots.size
            val inTag = "in-$slotIdx"
            val outTag = "proxy-$slotIdx"

            if (applyFrag) TlsFragment.apply(out)
            out.put("tag", outTag)
            out.put("domain_resolver", "bootstrap")

            inboundsArr.put(
                JSONObject()
                    .put("type", "mixed")
                    .put("tag", inTag)
                    .put("listen", "127.0.0.1")
                    .put("listen_port", listenPort)
            )
            outboundsArr.put(out)
            rulesArr.put(
                JSONObject()
                    .put("inbound", inTag)
                    .put("action", "route")
                    .put("outbound", outTag)
            )
            validSlots.add(BatchOutboundSlot(index = rawIdx, cfg = cfg, listenPort = listenPort))
        }

        if (validSlots.isEmpty()) return null

        val dnsServers = JSONArray()
        val bootstrapServerIp = if (isIpLiteral(safeDns)) safeDns else "1.1.1.1"
        dnsServers.put(
            JSONObject()
                .put("type", if (useDoh && isIpLiteral(safeDns)) "https" else "udp")
                .put("tag", "bootstrap")
                .put("server", bootstrapServerIp)
        )

        outboundsArr.put(
            JSONObject()
                .put("type", "direct")
                .put("tag", "direct")
                .put("domain_resolver", "bootstrap")
        )

        val dnsObj = JSONObject()
            .put("servers", dnsServers)
            .put("final", "bootstrap")
            .put("strategy", "ipv4_only")

        val routeObj = JSONObject()
            .put("rules", rulesArr)
            .put("final", "direct")
            .put("default_domain_resolver", "bootstrap")

        val conf = JSONObject()
            .put("log", JSONObject().put("level", "error").put("timestamp", false))
            .put("dns", dnsObj)
            .put("inbounds", inboundsArr)
            .put("outbounds", outboundsArr)
            .put("route", routeObj)

        return conf.toString() to validSlots
    }

    fun startBatchDaemon(
        items: List<Pair<String, Int>>,
        dnsServer: String = "1.1.1.1",
        useDoh: Boolean = false,
        waitMs: Long = 2400L,
    ): BatchDaemonSession? {
        if (!isAvailable) return null
        val built = buildBatchConfig(items, dnsServer, useDoh) ?: return null
        val (json, slots) = built
        val firstPort = slots.first().listenPort
        val confFile = File(tmpDir, "cfg-batch-$firstPort-${System.nanoTime() and 0xFFFFF}.json")
        confFile.writeText(json, Charsets.UTF_8)

        val devNull = File("/dev/null")
        var proc: Process? = null
        return try {
            val pb = ProcessBuilder(binaryPath, "run", "-c", confFile.absolutePath)
            if (devNull.exists()) {
                pb.redirectOutput(devNull)
                pb.redirectError(devNull)
            } else {
                pb.redirectErrorStream(true)
            }
            proc = pb.start()

            val deadline = System.currentTimeMillis() + waitMs
            var up = false
            while (System.currentTimeMillis() < deadline) {
                if (Thread.currentThread().isInterrupted || !proc.isAlive) break
                try {
                    Socket().use { s ->
                        s.connect(InetSocketAddress("127.0.0.1", firstPort), 50)
                        up = true
                    }
                    if (up) break
                } catch (_: Exception) {
                    Thread.sleep(20)
                }
            }
            if (!up) {
                stopProcess(proc, confFile)
                null
            } else {
                BatchDaemonSession(proc, confFile, slots)
            }
        } catch (_: Exception) {
            stopProcess(proc, confFile)
            null
        }
    }

    fun stopBatchDaemon(session: BatchDaemonSession?) {
        if (session == null) return
        stopProcess(session.process, session.configFile)
    }

    fun probeSlotOnRunningBatch(
        slot: BatchOutboundSlot,
        timeoutMs: Int = 2400,
        measureThroughput: Boolean = false,
        throughputBudgetBytes: Long = SPEED_BYTES,
        customSpeedUrl: String = "",
    ): TestResult {
        return try {
            val probe = Socks.measureRealDelay(slot.listenPort, TEST_URL, timeoutMs.coerceIn(1_200, 10_000))
            if (probe.status !in listOf(200, 204) || probe.elapsedMs <= 0L) {
                return TestResult(slot.cfg, ok = false, error = "http-${probe.status}", packetLossPct = 100.0)
            }
            val establishMs = probe.establishMs.coerceAtLeast(probe.elapsedMs)
            val jitter = probe.jitterMs.coerceAtLeast(0.0)
            val speedKbps = if (measureThroughput && !Thread.currentThread().isInterrupted) {
                measureDownloadThroughputOnPort(
                    port = slot.listenPort,
                    timeoutMs = maxOf(timeoutMs + 3_500, 6_500),
                    budgetBytes = throughputBudgetBytes,
                    customPrimaryUrl = customSpeedUrl,
                )
            } else {
                0.0
            }
            val stabScore = (
                55.0 +
                    ((1.0 - (jitter / 200.0)).coerceIn(0.0, 1.0) * 25.0) +
                    ((1.0 - (establishMs / 4500.0)).coerceIn(0.0, 1.0) * 20.0)
                ).coerceIn(0.0, 100.0)
            TestResult(
                cfg = slot.cfg,
                ok = true,
                latencyMs = probe.elapsedMs,
                speedKbps = speedKbps,
                testedAtMs = System.currentTimeMillis(),
                establishMs = establishMs,
                jitterMs = jitter,
                packetLossPct = 0.0,
                stabilityScore = stabScore,
            )
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            TestResult(slot.cfg, ok = false, error = "cancelled", packetLossPct = 100.0)
        } catch (e: Exception) {
            TestResult(slot.cfg, ok = false, error = e.javaClass.simpleName, packetLossPct = 100.0)
        }
    }

    /**
     * تشغيل sing-box كعملية خلفية لنفق الـ VPN والانتظار حتى يفتح المنفذ المحلي.
     */
    fun startDaemon(
        cfg: String,
        port: Int = VPN_SOCKS_PORT,
        dnsServer: String = "1.1.1.1",
        useDoh: Boolean = false,
        tag: String = "vpn",
        waitMs: Long = 3500L,
        enableIpv6: Boolean = false,
        bypassIrDomains: Boolean = true,
        physicalDnsServer: String? = null,
    ): RunningDaemon? {
        if (!isAvailable) return null
        val json = buildConfig(
            cfg = cfg,
            port = port,
            dnsServer = dnsServer,
            useDoh = useDoh,
            enableIpv6 = enableIpv6,
            bypassIrDomains = bypassIrDomains,
            physicalDnsServer = physicalDnsServer,
        ) ?: return null
        val confFile = File(tmpDir, "cfg-$tag-$port.json")
        confFile.writeText(json, Charsets.UTF_8)

        val devNull = File("/dev/null")
        var proc: Process? = null
        try {
            val pb = ProcessBuilder(binaryPath, "run", "-c", confFile.absolutePath)
            if (devNull.exists()) {
                pb.redirectOutput(devNull)
                pb.redirectError(devNull)
            } else {
                pb.redirectErrorStream(true)
            }
            proc = pb.start()

            val deadline = System.currentTimeMillis() + waitMs
            var up = false
            while (System.currentTimeMillis() < deadline) {
                if (!proc.isAlive) break
                try {
                    Socket().use { s ->
                        s.connect(InetSocketAddress("127.0.0.1", port), 80)
                        up = true
                    }
                    if (up) break
                } catch (_: Exception) {
                    Thread.sleep(30)
                }
            }
            if (!up) {
                stopProcess(proc, confFile)
                return null
            }
            return RunningDaemon(proc, confFile, port)
        } catch (_: Exception) {
            stopProcess(proc, confFile)
            return null
        }
    }

    fun stopDaemon(daemon: RunningDaemon?) {
        if (daemon == null) return
        stopProcess(daemon.process, daemon.configFile)
    }

    private fun stopProcess(proc: Process?, confFile: File?) {
        proc?.let {
            try {
                it.destroy()
                if (!it.waitFor(1200, TimeUnit.MILLISECONDS)) {
                    it.destroyForcibly()
                    it.waitFor(400, TimeUnit.MILLISECONDS)
                }
            } catch (_: Exception) {
                runCatching { it.destroyForcibly() }
            }
        }
        runCatching { confFile?.delete() }
    }

    /**
     * فحص كانفيغ واحد: يشغّل النواة، ينتظر المنفذ، يطلب generate_204،
     * ثم (اختياريًا) يقيس سرعة تنزيل 1MB.
     */
    fun test(
        cfg: String,
        port: Int,
        timeoutSec: Int = 6,
        measureSpeed: Boolean = false,
        dnsServer: String = "1.1.1.1",
        useDoh: Boolean = false,
    ): TestResult {
        if (!isAvailable) return TestResult(cfg, error = "engine-missing")
        val json = buildConfig(cfg, port, dnsServer, useDoh) ?: return TestResult(cfg, error = "unsupported")

        val confFile = File(tmpDir, "cfg-$port.json")
        confFile.writeText(json, Charsets.UTF_8)

        val devNull = File("/dev/null")
        var proc: Process? = null
        return try {
            val pb = ProcessBuilder(binaryPath, "run", "-c", confFile.absolutePath)
            if (devNull.exists()) {
                pb.redirectOutput(devNull)
                pb.redirectError(devNull)
            } else {
                pb.redirectErrorStream(true)
            }
            proc = pb.start()

            val deadline = System.currentTimeMillis() + 2500
            var up = false
            while (System.currentTimeMillis() < deadline) {
                if (Thread.currentThread().isInterrupted) {
                    return TestResult(cfg, error = "cancelled")
                }
                if (!proc.isAlive) return TestResult(cfg, error = "engine-exit")
                try {
                    Socket().use { s ->
                        s.connect(InetSocketAddress("127.0.0.1", port), 60)
                        up = true
                    }
                    if (up) break
                } catch (_: Exception) {
                    Thread.sleep(30)
                }
            }
            if (!up) return TestResult(cfg, error = "no-listen")

            val probe = Socks.measureRealDelay(port, TEST_URL, timeoutSec * 1000)
            if (probe.status !in listOf(200, 204)) {
                return TestResult(cfg, error = "http-${probe.status}")
            }

            var speed = 0.0
            if (measureSpeed && !Thread.currentThread().isInterrupted) {
                speed = measureDownloadThroughputOnPort(port, 8000, SPEED_BYTES)
            }
            TestResult(
                cfg,
                ok = true,
                latencyMs = probe.elapsedMs,
                speedKbps = speed,
                establishMs = probe.establishMs.coerceAtLeast(probe.elapsedMs),
                jitterMs = probe.jitterMs,
            )
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            TestResult(cfg, error = "cancelled")
        } catch (e: Exception) {
            TestResult(cfg, error = e.javaClass.simpleName)
        } finally {
            stopProcess(proc, confFile)
        }
    }

    /** قياس سرعة التنزيل مباشرةً لعقدة تم التحقّق من عملها للتوّ دون تكرار نبضة البينغ. */
    fun measureSpeedOnly(
        cfg: String,
        port: Int,
        timeoutSec: Int = 6,
        dnsServer: String = "1.1.1.1",
        useDoh: Boolean = false,
    ): Double {
        if (!isAvailable) return 0.0
        val json = buildConfig(cfg, port, dnsServer, useDoh) ?: return 0.0
        val confFile = File(tmpDir, "cfg-spd-$port.json")
        confFile.writeText(json, Charsets.UTF_8)

        val devNull = File("/dev/null")
        var proc: Process? = null
        return try {
            val pb = ProcessBuilder(binaryPath, "run", "-c", confFile.absolutePath)
            if (devNull.exists()) {
                pb.redirectOutput(devNull)
                pb.redirectError(devNull)
            } else {
                pb.redirectErrorStream(true)
            }
            proc = pb.start()

            val deadline = System.currentTimeMillis() + 2500
            var up = false
            while (System.currentTimeMillis() < deadline) {
                if (Thread.currentThread().isInterrupted || !proc.isAlive) return 0.0
                try {
                    Socket().use { s ->
                        s.connect(InetSocketAddress("127.0.0.1", port), 60)
                        up = true
                    }
                    if (up) break
                } catch (_: Exception) {
                    Thread.sleep(25)
                }
            }
            if (!up) return 0.0

            measureDownloadThroughputOnPort(port, maxOf(timeoutSec * 1000, 7500), SPEED_BYTES)
        } catch (_: Exception) {
            0.0
        } finally {
            stopProcess(proc, confFile)
        }
    }

    /**
     * فحص نفق VPN مشفّر حقيقي بشكل تسلسلي آمن (واحد تلو الآخر) على شبكة المستخدم الفعلية:
     * يقيس زمن تأسيس الاتصال، الوسيط الزمني للتأخير (Latency)، التذبذب (Jitter)،
     * فقدان الحزم (Packet Loss)، وسرعة التنزيل الفعلية عبر النفق دون كشف أي بيانات سرية.
     */
    fun testRealTunnelSequential(
        cfg: String,
        port: Int = 22650,
        timeoutSec: Int = 5,
        probeSamples: Int = 3,
        measureThroughput: Boolean = true,
        throughputBudgetBytes: Long = SPEED_BYTES,
        dnsServer: String = "1.1.1.1",
        useDoh: Boolean = false,
    ): TestResult {
        if (!isAvailable) return TestResult(cfg, error = "engine-missing")
        val json = buildConfig(cfg, port, dnsServer, useDoh) ?: return TestResult(cfg, error = "unsupported")
        val confFile = File(tmpDir, "cfg-seq-$port.json")
        confFile.writeText(json, Charsets.UTF_8)

        val devNull = File("/dev/null")
        var proc: Process? = null
        val tStartMs = System.currentTimeMillis()
        return try {
            val pb = ProcessBuilder(binaryPath, "run", "-c", confFile.absolutePath)
            if (devNull.exists()) {
                pb.redirectOutput(devNull)
                pb.redirectError(devNull)
            } else {
                pb.redirectErrorStream(true)
            }
            proc = pb.start()

            val deadline = System.currentTimeMillis() + 2600L
            var up = false
            while (System.currentTimeMillis() < deadline) {
                if (Thread.currentThread().isInterrupted) return TestResult(cfg, error = "cancelled")
                if (!proc.isAlive) return TestResult(cfg, error = "engine-exit")
                try {
                    Socket().use { s ->
                        s.connect(InetSocketAddress("127.0.0.1", port), 60)
                        up = true
                    }
                    if (up) break
                } catch (_: Exception) {
                    Thread.sleep(25)
                }
            }
            if (!up) return TestResult(cfg, error = "no-listen")

            val totalProbes = probeSamples.coerceIn(1, 5)
            val rtts = ArrayList<Long>(totalProbes)
            var establishMs = 0L
            var failedProbes = 0

            for (idx in 0 until totalProbes) {
                if (Thread.currentThread().isInterrupted) return TestResult(cfg, error = "cancelled")
                val pr = if (idx == 0) {
                    Socks.measureRealDelay(port, TEST_URL, timeoutSec * 1000)
                } else {
                    Socks.get(port, TEST_URL, timeoutSec * 1000, maxBytes = 0)
                }
                if (pr.status in listOf(200, 204) && pr.elapsedMs > 0L) {
                    if (establishMs <= 0L) {
                        establishMs = (System.currentTimeMillis() - tStartMs).coerceAtLeast(pr.elapsedMs)
                    }
                    rtts.add(pr.elapsedMs)
                } else {
                    failedProbes++
                    if (idx == 0) {
                        // First encrypted handshake failed outright -> fast-fail to keep sequential scan snappy
                        return TestResult(cfg, error = "http-${pr.status}", packetLossPct = 100.0)
                    }
                }
            }

            if (rtts.isEmpty()) {
                return TestResult(cfg, error = "all-probes-failed", packetLossPct = 100.0)
            }

            val sortedRtts = rtts.sorted()
            val medianLatency = sortedRtts[sortedRtts.size / 2]
            val jitter = if (rtts.size >= 2) {
                var sumDiff = 0.0
                for (i in 1 until rtts.size) {
                    sumDiff += kotlin.math.abs(rtts[i] - rtts[i - 1]).toDouble()
                }
                sumDiff / (rtts.size - 1).toDouble()
            } else {
                0.0
            }
            val lossPct = (failedProbes.toDouble() / totalProbes.toDouble()) * 100.0

            var speedKbps = 0.0
            if (measureThroughput && throughputBudgetBytes >= 16_384L && !Thread.currentThread().isInterrupted) {
                speedKbps = measureDownloadThroughputOnPort(
                    port = port,
                    timeoutMs = maxOf(timeoutSec * 1000 + 2000, 7000),
                    budgetBytes = throughputBudgetBytes,
                )
            }

            val stabScore = (
                ((100.0 - lossPct) * 0.55) +
                    ((1.0 - (jitter / 200.0)).coerceIn(0.0, 1.0) * 25.0) +
                    ((1.0 - (establishMs / 4500.0)).coerceIn(0.0, 1.0) * 20.0)
                ).coerceIn(0.0, 100.0)

            TestResult(
                cfg = cfg,
                ok = true,
                latencyMs = medianLatency,
                speedKbps = speedKbps,
                testedAtMs = System.currentTimeMillis(),
                establishMs = establishMs,
                jitterMs = jitter,
                packetLossPct = lossPct,
                stabilityScore = stabScore,
            )
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            TestResult(cfg, error = "cancelled")
        } catch (e: Exception) {
            TestResult(cfg, error = e.javaClass.simpleName)
        } finally {
            stopProcess(proc, confFile)
        }
    }
}
