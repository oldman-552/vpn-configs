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
)

data class RunningDaemon(
    val process: Process,
    val configFile: File,
    val port: Int,
)

class SingBox(private val ctx: Context) {

    companion object {
        const val TEST_URL = "https://www.gstatic.com/generate_204"
        const val SPEED_URL = "https://speed.cloudflare.com/__down?bytes=600000"
        const val VPN_SOCKS_PORT = 20808
        private const val SPEED_BYTES = 600_000L
    }

    /** مسار النواة داخل مجلد المكتبات الأصلية (قابل للتنفيذ). */
    val binaryPath: String by lazy {
        File(ctx.applicationInfo.nativeLibraryDir, "libsingbox.so").absolutePath
    }

    val isAvailable: Boolean
        get() = File(binaryPath).let { it.exists() && it.canExecute() }

    private val tmpDir: File by lazy {
        File(ctx.cacheDir, "sbx").apply { mkdirs() }
    }

    private val ipv4LiteralRe = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")

    private fun isIpLiteral(host: String): Boolean {
        val h = host.trim().removeSurrounding("[", "]")
        return ipv4LiteralRe.matches(h) || h.contains(':')
    }

    /**
     * بناء ملف إعداد كامل متوافق مع sing-box 1.14.4 مع حماية صارمة من تسرب DNS و IPv6:
     *   • خادم `bootstrap` (1.1.1.1 مباشر) يُستخدم حصريًا لحل اسم نطاق سيرفر البروكسي نفسه.
     *   • خادم `tunnel-dns` يحمل `"detour": "proxy"` ويُعيّن كـ `dns.final` و`default_domain_resolver`
     *     بحيث تمرّ 100% من استعلامات DNS الخاصة بالتطبيقات داخل النفق المشفّر ولا تتسرب لمزوّد الإنترنت.
     */
    fun buildConfig(
        cfg: String,
        port: Int,
        dnsServer: String = "1.1.1.1",
        useDoh: Boolean = false,
        enableIpv6: Boolean = false,
    ): String? {
        val out = Converters.toOutbound(cfg) ?: return null
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

        out.put("tag", "proxy")
        out.put("domain_resolver", "bootstrap")

        val conf = JSONObject()
            .put("log", JSONObject().put("level", "error").put("timestamp", false))
            .put(
                "dns",
                JSONObject()
                    .put("servers", dnsServers)
                    .put("final", "tunnel-dns")
                    .put("strategy", domainStrategy)
            )
            .put("route", JSONObject().put("default_domain_resolver", "tunnel-dns"))
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
            .put("outbounds", JSONArray().put(out))
        return conf.toString()
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
    ): RunningDaemon? {
        if (!isAvailable) return null
        val json = buildConfig(cfg, port, dnsServer, useDoh, enableIpv6) ?: return null
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
                val sp = Socks.get(port, SPEED_URL, 8000, SPEED_BYTES)
                val dtSec = maxOf(sp.transferMs / 1000.0, 0.005)
                if (sp.status in listOf(200, 206) && sp.bytes >= 8192L) {
                    speed = (sp.bytes / 1024.0) / dtSec
                }
            }
            TestResult(cfg, ok = true, latencyMs = probe.elapsedMs, speedKbps = speed)
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

            val sp = Socks.get(port, SPEED_URL, maxOf(timeoutSec * 1000, 7500), SPEED_BYTES)
            val dtSec = maxOf(sp.transferMs / 1000.0, 0.005)
            if (sp.status in listOf(200, 206) && sp.bytes >= 8192L) {
                (sp.bytes / 1024.0) / dtSec
            } else 0.0
        } catch (_: Exception) {
            0.0
        } finally {
            stopProcess(proc, confFile)
        }
    }
}
