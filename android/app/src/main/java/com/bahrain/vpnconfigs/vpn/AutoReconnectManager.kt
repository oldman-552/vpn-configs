// =====================================================================
// AutoReconnectManager.kt — محرك إعادة الاتصال التلقائي المتين (Part 2.2).
//
// المزايا الهندسية الصارمة:
//   • كشف أسباب الانقطاع الـ 8 (انقطاع النفق، فقدان الشبكة، انتقال Wi-Fi <-> الجوال،
//     فشل DNS، انهيار عملية النواة، انتهاء المهلة، عدم استجابة النفق).
//   • تراجع أسي مع تذبذب عشوائي مضبوط (Exponential Backoff + Jitter):
//       المحاولة 1: 2s | المحاولة 2: 5s | المحاولة 3: 10s | المحاولة 4: 20s | المحاولة 5: 40s
//       المحاولات التالية: سقف قابل للتخصيص (الافتراضي 60s) مع حد أقصى يمنع استنزاف البطارية.
//   • منع محاولات الاتصال المتزامنة، دعم الإلغاء اليدوي، والتنبيه عند تكرار الفشل.
// =====================================================================
package com.bahrain.vpnconfigs.vpn

import kotlin.math.roundToLong
import kotlin.random.Random

enum class DisconnectTrigger(val code: String, val labelAr: String) {
    TUNNEL_DISCONNECTED("TUNNEL_DISCONNECTED", "انقطاع نفق الـ VPN"),
    UNDERLYING_NETWORK_LOST("UNDERLYING_NETWORK_LOST", "انقطاع الشبكة الأساسية"),
    WIFI_TO_MOBILE("WIFI_TO_MOBILE", "الانتقال من Wi-Fi إلى بيانات الجوال"),
    MOBILE_TO_WIFI("MOBILE_TO_WIFI", "الانتقال من بيانات الجوال إلى Wi-Fi"),
    DNS_RESOLUTION_FAILURE("DNS_RESOLUTION_FAILURE", "فشل حل أسماء النطاقات (DNS)"),
    ENGINE_CRASH("ENGINE_CRASH", "توقّف محرك النفق المفاجئ"),
    CONNECTION_TIMEOUT("CONNECTION_TIMEOUT", "انتهاء مهلة الاستجابة"),
    UNRESPONSIVE_TUNNEL("UNRESPONSIVE_TUNNEL", "النفق لا يستجيب لحركة المرور");
}

data class ReconnectPlan(
    val shouldRetry: Boolean,
    val attemptNumber: Int,
    val delayMs: Long,
    val notifyRepeatedFailure: Boolean,
    val trigger: DisconnectTrigger,
    val statusAr: String,
)

class AutoReconnectManager(
    private val baseScheduleMs: LongArray = longArrayOf(2_000L, 5_000L, 10_000L, 20_000L, 40_000L),
    var cappedIntervalMs: Long = 60_000L,
    var maxAttemptsBeforePause: Int = 12,
    private val jitterFraction: Double = 0.15,
) {
    private val lock = Any()
    private var currentAttempt: Int = 0
    private var cancelledByUser: Boolean = false
    private var connectingInFlight: Boolean = false

    val attemptCount: Int
        get() = synchronized(lock) { currentAttempt }

    val isCancelled: Boolean
        get() = synchronized(lock) { cancelledByUser }

    /** يمنع تشغيل محاولتي إعادة اتصال في اللحظة نفسها (Single-Flight Guard). */
    fun tryAcquireConnectionSlot(): Boolean = synchronized(lock) {
        if (cancelledByUser || connectingInFlight) return false
        connectingInFlight = true
        true
    }

    fun releaseConnectionSlot() = synchronized(lock) {
        connectingInFlight = false
    }

    fun onTunnelVerified() = synchronized(lock) {
        currentAttempt = 0
        cancelledByUser = false
        connectingInFlight = false
    }

    fun cancelByUser() = synchronized(lock) {
        cancelledByUser = true
        currentAttempt = 0
        connectingInFlight = false
    }

    fun resetForNewUserConnect() = synchronized(lock) {
        cancelledByUser = false
        currentAttempt = 0
    }

    /**
     * يحسب مهلة المحاولة رقم `attemptNumber` (تبدأ من 1) وفق الجدول المعتمد:
     * 2s -> 5s -> 10s -> 20s -> 40s -> cappedIntervalMs مع Jitter مضبوط لمنع العواصف.
     */
    fun computeBackoffDelayMs(
        attemptNumber: Int,
        deterministicJitterFactor: Double? = null,
    ): Long {
        val idx = (attemptNumber - 1).coerceAtLeast(0)
        val rawMs = if (idx < baseScheduleMs.size) {
            baseScheduleMs[idx]
        } else {
            cappedIntervalMs.coerceAtLeast(baseScheduleMs.last())
        }
        val jitterMult = deterministicJitterFactor
            ?: Random.Default.nextDouble(1.0 - jitterFraction, 1.0 + jitterFraction)
        return (rawMs.toDouble() * jitterMult).roundToLong().coerceAtLeast(500L)
    }

    fun nextReconnectPlan(
        trigger: DisconnectTrigger,
        networkAvailable: Boolean = true,
        deterministicJitterFactor: Double? = null,
    ): ReconnectPlan = synchronized(lock) {
        if (cancelledByUser) {
            return ReconnectPlan(
                shouldRetry = false,
                attemptNumber = currentAttempt,
                delayMs = 0L,
                notifyRepeatedFailure = false,
                trigger = trigger,
                statusAr = "تم إلغاء إعادة الاتصال بطلب المستخدم",
            )
        }
        if (!networkAvailable) {
            // لا نستنزف البطارية بمحاولات اتصال أثناء انقطاع إشارة الهاتف/الواي فاي كليًا
            return ReconnectPlan(
                shouldRetry = false,
                attemptNumber = currentAttempt,
                delayMs = 0L,
                notifyRepeatedFailure = false,
                trigger = DisconnectTrigger.UNDERLYING_NETWORK_LOST,
                statusAr = "بانتظار عودة اتصال الشبكة الأساسية لاستئناف النفق تلقائيًا…",
            )
        }
        if (currentAttempt >= maxAttemptsBeforePause) {
            return ReconnectPlan(
                shouldRetry = false,
                attemptNumber = currentAttempt,
                delayMs = 0L,
                notifyRepeatedFailure = true,
                trigger = trigger,
                statusAr = "توقّفت المحاولات التلقائية مؤقتًا بعد $currentAttempt محاولة لحماية البطارية",
            )
        }

        currentAttempt += 1
        val delayMs = computeBackoffDelayMs(currentAttempt, deterministicJitterFactor)
        val delaySec = (delayMs / 1000L).coerceAtLeast(1L)
        val notifyWarn = currentAttempt >= 3
        return ReconnectPlan(
            shouldRetry = true,
            attemptNumber = currentAttempt,
            delayMs = delayMs,
            notifyRepeatedFailure = notifyWarn,
            trigger = trigger,
            statusAr = "${trigger.labelAr} — المحاولة #$currentAttempt خلال ${delaySec}ث…",
        )
    }

    companion object {
        fun classifyDisconnectTrigger(
            processAlive: Boolean,
            probeError: String?,
            previousTransport: String,
            currentTransport: String,
            networkConnected: Boolean,
        ): DisconnectTrigger {
            if (!networkConnected) return DisconnectTrigger.UNDERLYING_NETWORK_LOST
            if (previousTransport == "WIFI" && currentTransport == "CELLULAR") return DisconnectTrigger.WIFI_TO_MOBILE
            if (previousTransport == "CELLULAR" && currentTransport == "WIFI") return DisconnectTrigger.MOBILE_TO_WIFI
            if (!processAlive) return DisconnectTrigger.ENGINE_CRASH
            val err = probeError?.lowercase().orEmpty()
            return when {
                err.contains("dns") || err.contains("unknownhost") || err.contains("nxdomain") ->
                    DisconnectTrigger.DNS_RESOLUTION_FAILURE
                err.contains("timeout") || err.contains("timed out") ->
                    DisconnectTrigger.CONNECTION_TIMEOUT
                err.isNotBlank() -> DisconnectTrigger.UNRESPONSIVE_TUNNEL
                else -> DisconnectTrigger.TUNNEL_DISCONNECTED
            }
        }
    }
}
