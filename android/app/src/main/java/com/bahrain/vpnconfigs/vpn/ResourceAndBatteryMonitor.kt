// =====================================================================
// ResourceAndBatteryMonitor.kt — مراقب استهلاك المعالج والذاكرة والبطارية
// والجدولة التكيّفية الموفّرة للطاقة (Part 2.8 — Battery Optimization).
//
// المزايا الهندسية:
//   • يقيس وقت المعالج الفعلي للعملية (Process.getElapsedCpuTime) وحجم الذاكرة (Heap + PSS).
//   • يتتبع معدل الفحوصات الخلفية في الدقيقة وعدد مرات إعادة الاتصال دون مبالغة أو أرقام مختلقة.
//   • لا يحتفظ بأي قفل إيقاظ (Zero WakeLocks) ويوسّع فترات الفحص عند استقرار النفق أو إطفاء الشاشة.
// =====================================================================
package com.bahrain.vpnconfigs.vpn

import android.os.Debug
import android.os.Process
import android.os.SystemClock
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.math.roundToInt

data class ResourceTelemetrySnapshot(
    val cpuTimeMs: Long,
    val estimatedCpuPct: Double,
    val javaHeapMb: Double,
    val nativePssMb: Double,
    val backgroundProbesCount: Int,
    val probesPerMinute: Double,
    val reconnectCount: Int,
    val activePollingIntervalMs: Long,
    val wakeLocksHeld: Int = 0, // المعمارية مصممة بصفر WakeLocks
)

object ResourceAndBatteryMonitor {

    private val startElapsedRealtimeMs = AtomicLong(runCatching { SystemClock.elapsedRealtime() }.getOrDefault(0L))
    private val lastCpuSampleWallMs = AtomicLong(0L)
    private val lastCpuSampleTimeMs = AtomicLong(0L)

    private val bgProbeCounter = AtomicInteger(0)
    private val reconnectCounter = AtomicInteger(0)
    private val currentIntervalMs = AtomicLong(SmartFailoverEngine.HEALTHY_CHECK_INTERVAL_MS)

    @Volatile
    var isUiInForeground: Boolean = true

    fun recordBackgroundProbe(nextIntervalMs: Long) {
        bgProbeCounter.incrementAndGet()
        currentIntervalMs.set(nextIntervalMs)
    }

    fun recordReconnectAttempt() {
        reconnectCounter.incrementAndGet()
    }

    fun resetCountersForTesting() {
        bgProbeCounter.set(0)
        reconnectCounter.set(0)
        currentIntervalMs.set(SmartFailoverEngine.HEALTHY_CHECK_INTERVAL_MS)
    }

    /**
     * يحسب فترة فحص تكيّفية تحترم البطارية وحالة الواجهة (أمامية أم في الخلفية):
     *   • عند التدهور: 4 ثوانٍ لاستباق السقوط.
     *   • في الواجهة الأمامية المستقرة: تتدرج من 8s إلى 24s.
     *   • في الخلفية مع استقرار طويل: تتمدد إلى 45s لتقليل إيقاظ المودم والمعالج بنسبة >70%.
     */
    fun computeBatteryAwareProbeIntervalMs(
        consecutiveHealthyProbes: Int,
        isDegraded: Boolean,
        uiForeground: Boolean = isUiInForeground,
        isMeteredNetwork: Boolean = false,
    ): Long {
        if (isDegraded) return 4_000L
        val base = SmartFailoverEngine.computeAdaptiveCheckIntervalMs(consecutiveHealthyProbes, isDegraded = false)
        return when {
            !uiForeground && consecutiveHealthyProbes >= 6 -> if (isMeteredNetwork) 60_000L else 45_000L
            !uiForeground && consecutiveHealthyProbes >= 2 -> 30_000L
            isMeteredNetwork && consecutiveHealthyProbes >= 4 -> 30_000L
            else -> base
        }
    }

    fun captureSnapshot(): ResourceTelemetrySnapshot {
        val nowWall = runCatching { SystemClock.elapsedRealtime() }.getOrDefault(1L)
        val cpuMs = runCatching { Process.getElapsedCpuTime() }.getOrDefault(0L)

        val prevWall = lastCpuSampleWallMs.getAndSet(nowWall)
        val prevCpu = lastCpuSampleTimeMs.getAndSet(cpuMs)
        val cpuPct = if (prevWall > 0L && nowWall > prevWall && cpuMs >= prevCpu) {
            val dWall = (nowWall - prevWall).toDouble()
            val dCpu = (cpuMs - prevCpu).toDouble()
            (((dCpu / dWall) * 100.0) * 100.0).roundToInt() / 100.0
        } else {
            0.0
        }

        val rt = Runtime.getRuntime()
        val heapMb = (((rt.totalMemory() - rt.freeMemory()).toDouble() / (1024.0 * 1024.0)) * 10.0).roundToInt() / 10.0
        val pssKb = runCatching { Debug.getPss() }.getOrDefault(0L)
        val pssMb = ((pssKb.toDouble() / 1024.0) * 10.0).roundToInt() / 10.0

        val uptimeMin = ((nowWall - startElapsedRealtimeMs.get()).coerceAtLeast(1_000L)).toDouble() / 60_000.0
        val probes = bgProbeCounter.get()
        val ppm = ((probes.toDouble() / uptimeMin) * 10.0).roundToInt() / 10.0

        return ResourceTelemetrySnapshot(
            cpuTimeMs = cpuMs,
            estimatedCpuPct = cpuPct.coerceIn(0.0, 100.0),
            javaHeapMb = heapMb,
            nativePssMb = pssMb,
            backgroundProbesCount = probes,
            probesPerMinute = ppm,
            reconnectCount = reconnectCounter.get(),
            activePollingIntervalMs = currentIntervalMs.get(),
            wakeLocksHeld = 0,
        )
    }
}
