// =====================================================================
// SingBox.kt — تشغيل نواة sing-box محليًا لفحص كانفيغ واحد.
//
// الطريقة: النواة تأتي كـ libsingbox.so داخل jniLibs (لأن أندرويد يمنع
// تنفيذ ملفات من مجلد بيانات التطبيق). نشغّلها مع inbound من نوع mixed
// على منفذ محلي، ثم نمرّر طلب generate_204 عبره عبر Socks.get().
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
)

class SingBox(private val ctx: Context) {

    companion object {
        const val TEST_URL = "https://www.gstatic.com/generate_204"
        const val SPEED_URL = "https://speed.cloudflare.com/__down?bytes=1000000"
        private const val SPEED_BYTES = 1_000_000L
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

    /** بناء ملف إعداد كامل لكانفيغ واحد على منفذ محلي محدّد. */
    private fun buildConfig(cfg: String, port: Int): String? {
        val out = Converters.toOutbound(cfg) ?: return null
        out.put("tag", "proxy")
        val conf = JSONObject()
            .put("log", JSONObject().put("level", "error").put("timestamp", false))
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
     * فحص كانفيغ واحد: يشغّل النواة، ينتظر المنفذ، يطلب generate_204،
     * ثم (اختياريًا) يقيس سرعة تنزيل 1MB.
     */
    fun test(cfg: String, port: Int, timeoutSec: Int = 6, measureSpeed: Boolean = false): TestResult {
        if (!isAvailable) return TestResult(cfg, error = "engine-missing")
        val json = buildConfig(cfg, port) ?: return TestResult(cfg, error = "unsupported")

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

            // انتظار فتح منفذ socks
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

            val probe = Socks.get(port, TEST_URL, timeoutSec * 1000, 4096)
            if (probe.status !in listOf(200, 204)) {
                return TestResult(cfg, error = "http-${probe.status}")
            }

            var speed = 0.0
            if (measureSpeed && !Thread.currentThread().isInterrupted) {
                val t0 = System.nanoTime()
                val sp = Socks.get(port, SPEED_URL, 8000, SPEED_BYTES)
                val dt = maxOf((System.nanoTime() - t0) / 1e9, 0.001)
                if (sp.status in listOf(200, 206) && sp.bytes > 0) {
                    speed = (sp.bytes / 1024.0) / dt
                }
            }
            TestResult(cfg, ok = true, latencyMs = probe.elapsedMs, speedKbps = speed)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            TestResult(cfg, error = "cancelled")
        } catch (e: Exception) {
            TestResult(cfg, error = e.javaClass.simpleName)
        } finally {
            proc?.let {
                try {
                    it.destroy()
                    if (!it.waitFor(1500, TimeUnit.MILLISECONDS)) {
                        it.destroyForcibly()
                        it.waitFor(500, TimeUnit.MILLISECONDS)
                    }
                } catch (_: Exception) {
                    runCatching { it.destroyForcibly() }
                }
            }
            confFile.delete()
        }
    }
}
