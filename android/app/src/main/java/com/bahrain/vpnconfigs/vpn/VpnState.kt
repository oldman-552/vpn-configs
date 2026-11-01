// =====================================================================
// VpnState.kt — إدارة الحالة المشتركة الموثّقة لاتصال الـ VPN ومؤشرات الأمان
// والتبديل التلقائي ومفتاح الإيقاف (Phases 4, 6 & 9).
//
// حالات الاتصال الثمان المعتمدة (لا يُعلَن CONNECTED إلا بعد نجاح التحقق الفعلي):
//   1. DISCONNECTED         — متوقف بطلب المستخدم
//   2. CONNECTING           — جارٍ إنشاء النفق والتحقق منه
//   3. CONNECTED            — متّصل ومتحقّق من مرور البيانات عبر النفق
//   4. RECONNECTING         — جارٍ استعادة الجلسة بعد تغيّر الشبكة (Wi-Fi / جوال)
//   5. SWITCHING_SERVER     — جارٍ الانتقال السلس إلى سيرفر بديل موثّق
//   6. CONNECTION_DEGRADED  — متّصل لكن رُصد ارتفاع تأخير أو تذبذب أو فقدان حزم
//   7. PROTECTION_ACTIVE    — مفتاح الإيقاف (Kill Switch) يحجب التسرب بعد سقوط النفق
//   8. CONNECTION_FAILED    — تعذّر الاتصال (مع إيقاف النفق عند تعطيل Kill Switch)
// =====================================================================
package com.bahrain.vpnconfigs.vpn

import com.bahrain.vpnconfigs.util.AppI18n
import com.bahrain.vpnconfigs.util.tr
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.util.Locale

enum class VpnPhase {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    RECONNECTING,
    SWITCHING_SERVER,
    CONNECTION_DEGRADED,
    PROTECTION_ACTIVE,
    CONNECTION_FAILED,
}

data class ServerCandidate(
    val cfg: String,
    val label: String,
    val speedKbps: Double = 0.0,
    val latencyMs: Long = 0L,
    val isVip: Boolean = false,
    val isElite: Boolean = false,
    val securityAssessment: String = "Unknown",
    val riskLevel: String = "UNKNOWN",
)

data class VpnStatus(
    val phase: VpnPhase = VpnPhase.DISCONNECTED,
    val activeCfg: String? = null,
    val activeLabel: String = "bahrain-vpn #1",
    val activeProto: String = "",
    val activeEndpoint: String = "",
    val connectedSinceMs: Long = 0L,
    val downSpeedBps: Long = 0L,
    val upSpeedBps: Long = 0L,
    val totalDownBytes: Long = 0L,
    val totalUpBytes: Long = 0L,
    val livePingMs: Long = 0L,
    val jitterMs: Double = 0.0,
    val packetLossPct: Double = 0.0,
    val connectionQuality: String = "—",
    val exitIp: String = "",
    val exitCountry: String = "",
    val failoverMode: String = "SMART",
    val switchingStatus: String = "مستقر",
    val previousServerLabel: String = "",
    val targetServerLabel: String = "",
    val lastSuccessfulSwitchAtMs: Long = 0L,
    val failoverCount: Int = 0,
    val killSwitchActive: Boolean = true,
    val osLockdownActive: Boolean = false,
    val reconnectAttempt: Int = 0,
    val underlyingNetwork: String = "WIFI",
    val underlyingNetworkAr: String = "واي فاي (Wi-Fi)",
    val isMeteredNetwork: Boolean = false,
    val lastProtectionEvent: String = "",
    val trafficHistoryBps: List<Pair<Long, Long>> = emptyList(),
    val recentEvents: List<String> = emptyList(),
    val droppedConfigs: Set<String> = emptySet(),
    val statusMessage: String? = null,
    val error: String? = null,
) {
    val isTunnelVerified: Boolean
        get() = phase == VpnPhase.CONNECTED || phase == VpnPhase.CONNECTION_DEGRADED

    val isTransitioning: Boolean
        get() = phase == VpnPhase.CONNECTING || phase == VpnPhase.RECONNECTING || phase == VpnPhase.SWITCHING_SERVER

    val isActive: Boolean
        get() = isTunnelVerified || isTransitioning || phase == VpnPhase.PROTECTION_ACTIVE

    val displayUnderlyingNetwork: String
        get() {
            if (!AppI18n.isEnglish) return underlyingNetworkAr
            return when (underlyingNetwork.uppercase(Locale.US)) {
                "WIFI" -> "Wi-Fi"
                "CELLULAR", "MOBILE", "MOBILE_DATA" -> "Mobile Data"
                "ETHERNET" -> "Ethernet"
                "NONE" -> "Offline"
                else -> "Other Network"
            }
        }

    val displayConnectionQuality: String
        get() {
            if (!AppI18n.isEnglish) return connectionQuality
            return when (connectionQuality.trim()) {
                "ممتاز", "ممتازة" -> "Excellent"
                "جيد جدًا", "جيدة ومستقرة" -> "Very Good"
                "جيد" -> "Good"
                "متوسط" -> "Fair"
                "ضعيف", "متراجع" -> "Degraded"
                "حجب طوارئ (Kill Switch)" -> "Kill Switch Active"
                else -> connectionQuality
            }
        }

    val displaySwitchingStatus: String
        get() {
            if (!AppI18n.isEnglish) return switchingStatus
            return when (switchingStatus.trim()) {
                "مستقر", "متّصل ومستقر" -> "Connected & Stable"
                "نجح الانتقال الذكي" -> "Smart Switch Complete"
                "رُصد بطء في الاستجابة" -> "Latency Degradation Detected"
                else -> switchingStatus
            }
        }
}

object VpnStateManager {
    private val _status = MutableStateFlow(VpnStatus())
    val status: StateFlow<VpnStatus> = _status.asStateFlow()

    @Volatile
    var serverPool: List<ServerCandidate> = emptyList()

    fun update(transform: (VpnStatus) -> VpnStatus) {
        _status.update(transform)
    }

    fun markServerDropped(cfg: String?) {
        val clean = cfg?.trim().orEmpty()
        if (clean.isEmpty()) return
        _status.update { prev -> prev.copy(droppedConfigs = prev.droppedConfigs + clean) }
    }

    fun markServerHealthy(cfg: String?) {
        val clean = cfg?.trim().orEmpty()
        if (clean.isEmpty()) return
        _status.update { prev ->
            if (clean in prev.droppedConfigs) prev.copy(droppedConfigs = prev.droppedConfigs - clean) else prev
        }
    }

    fun appendEvent(eventAr: String) {
        val stamp = java.text.SimpleDateFormat("HH:mm:ss", Locale.US).format(java.util.Date())
        val line = "[$stamp] $eventAr"
        _status.update { prev ->
            prev.copy(recentEvents = (listOf(line) + prev.recentEvents).take(20))
        }
    }

    fun resetDisconnected(errorMsg: String? = null, infoMsg: String? = null) {
        _status.update { prev ->
            VpnStatus(
                phase = if (errorMsg != null) VpnPhase.CONNECTION_FAILED else VpnPhase.DISCONNECTED,
                activeCfg = prev.activeCfg,
                activeLabel = prev.activeLabel,
                activeProto = prev.activeProto,
                activeEndpoint = prev.activeEndpoint,
                failoverMode = prev.failoverMode,
                previousServerLabel = prev.previousServerLabel,
                lastSuccessfulSwitchAtMs = prev.lastSuccessfulSwitchAtMs,
                killSwitchActive = prev.killSwitchActive,
                osLockdownActive = prev.osLockdownActive,
                underlyingNetwork = prev.underlyingNetwork,
                underlyingNetworkAr = prev.underlyingNetworkAr,
                isMeteredNetwork = prev.isMeteredNetwork,
                lastProtectionEvent = prev.lastProtectionEvent,
                recentEvents = prev.recentEvents,
                droppedConfigs = prev.droppedConfigs,
                statusMessage = infoMsg,
                error = errorMsg,
            )
        }
    }

    fun formatBytes(bytes: Long): String {
        if (bytes < 1024L) return "$bytes B"
        val kb = bytes / 1024.0
        if (kb < 1024.0) return String.format(Locale.US, "%.1f KB", kb)
        val mb = kb / 1024.0
        if (mb < 1024.0) return String.format(Locale.US, "%.2f MB", mb)
        val gb = mb / 1024.0
        return String.format(Locale.US, "%.2f GB", gb)
    }

    fun formatSpeed(bytesPerSec: Long): String {
        if (bytesPerSec <= 0L) return "0 KB/s"
        if (bytesPerSec < 1024L) return "$bytesPerSec B/s"
        val kb = bytesPerSec / 1024.0
        if (kb < 1024.0) return String.format(Locale.US, "%.1f KB/s", kb)
        val mb = kb / 1024.0
        return String.format(Locale.US, "%.2f MB/s", mb)
    }

    fun formatDuration(totalSec: Long): String {
        val s = totalSec.coerceAtLeast(0L)
        val hrs = s / 3600L
        val mins = (s % 3600L) / 60L
        val secs = s % 60L
        return String.format(Locale.US, "%02d:%02d:%02d", hrs, mins, secs)
    }

    fun countryFlag(isoCode: String): String {
        val c = isoCode.trim().uppercase(Locale.US)
        if (c.length != 2 || c[0] !in 'A'..'Z' || c[1] !in 'A'..'Z') return "🌐"
        val first = Character.toChars(0x1F1E6 + (c[0] - 'A'))
        val second = Character.toChars(0x1F1E6 + (c[1] - 'A'))
        return String(first) + String(second)
    }
}
