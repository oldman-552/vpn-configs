// =====================================================================
// VpnState.kt — إدارة الحالة المشتركة لاتصال الـ VPN والإحصاءات الحيّة.
// =====================================================================
package com.bahrain.vpnconfigs.vpn

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.util.Locale

enum class VpnPhase {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    SWITCHING,
    ERROR,
}

data class ServerCandidate(
    val cfg: String,
    val label: String,
    val speedKbps: Double = 0.0,
    val latencyMs: Long = 0L,
    val isVip: Boolean = false,
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
    val exitIp: String = "",
    val exitCountry: String = "",
    val failoverCount: Int = 0,
    val droppedConfigs: Set<String> = emptySet(),
    val statusMessage: String? = null,
    val error: String? = null,
) {
    val isActive: Boolean
        get() = phase == VpnPhase.CONNECTED || phase == VpnPhase.CONNECTING || phase == VpnPhase.SWITCHING
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

    fun resetDisconnected(errorMsg: String? = null, infoMsg: String? = null) {
        _status.update { prev ->
            VpnStatus(
                phase = if (errorMsg != null) VpnPhase.ERROR else VpnPhase.DISCONNECTED,
                activeCfg = prev.activeCfg,
                activeLabel = prev.activeLabel,
                activeProto = prev.activeProto,
                activeEndpoint = prev.activeEndpoint,
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
