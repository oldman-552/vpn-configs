// =====================================================================
// NetworkAwarenessMonitor.kt — مكون الوعي الذكي بحالة الشبكة (Part 2.7).
//
// المزايا والخصوصية:
//   • يستخدم حصريًا واجهات أندرويد الحديثة (ConnectivityManager + NetworkCapabilities + LinkProperties).
//   • لا يستخدم أي واجهات مهملة (NetworkInfo) ولا يجمع SSID للواي فاي أو الموقع الجغرافي نهائيًا.
//   • يرصد Wi-Fi، الجوال، Ethernet، انقطاع الشبكة، الشبكات المحدودة (Metered)، حالة التحقق (Validated)،
//     وتوفّر عناوين/مسارات IPv4 و IPv6 على الشبكة الفعلية.
// =====================================================================
package com.bahrain.vpnconfigs.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import com.bahrain.vpnconfigs.util.tr
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.net.Inet6Address

enum class UnderlyingTransport(val code: String, val labelAr: String, val labelEn: String) {
    WIFI("WIFI", "واي فاي (Wi-Fi)", "Wi-Fi"),
    CELLULAR("CELLULAR", "بيانات الجوال", "Mobile Data"),
    ETHERNET("ETHERNET", "إيثرنت سلكي", "Ethernet"),
    OTHER("OTHER", "شبكة أخرى", "Other Network"),
    NONE("NONE", "غير متّصل بالشبكة", "Offline");

    val displayLabel: String
        get() = tr(labelAr, labelEn)
}

data class NetworkSnapshot(
    val connected: Boolean = true,
    val transport: UnderlyingTransport = UnderlyingTransport.WIFI,
    val isMetered: Boolean = false,
    val isValidated: Boolean = false,
    val networkHandle: Long = 0L,
    val hasIpv4: Boolean = true,
    val hasGlobalIpv6: Boolean = false,
    val systemDnsServers: List<String> = emptyList(),
    val updatedAtMs: Long = System.currentTimeMillis(),
)

class NetworkAwarenessMonitor(ctx: Context) {

    private val appCtx = ctx.applicationContext
    private val cm = appCtx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    private val _snapshot = MutableStateFlow(readCurrentPhysicalNetwork())
    val snapshot: StateFlow<NetworkSnapshot> = _snapshot.asStateFlow()

    @Volatile
    private var registered = false

    private var onTransitionListener: ((previous: NetworkSnapshot, current: NetworkSnapshot) -> Unit)? = null

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            refreshAndDispatch(network)
        }

        override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
            refreshAndDispatch(network, networkCapabilities, null)
        }

        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
            refreshAndDispatch(network, null, linkProperties)
        }

        override fun onLost(network: Network) {
            val prev = _snapshot.value
            val next = readCurrentPhysicalNetwork()
            _snapshot.value = next
            if (prev.transport != next.transport || prev.connected != next.connected) {
                onTransitionListener?.invoke(prev, next)
            }
        }
    }

    fun start(onTransition: (previous: NetworkSnapshot, current: NetworkSnapshot) -> Unit) {
        onTransitionListener = onTransition
        if (registered) return
        runCatching {
            val req = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
            cm.registerNetworkCallback(req, callback)
            registered = true
            _snapshot.value = readCurrentPhysicalNetwork()
        }
    }

    fun stop() {
        if (!registered) return
        runCatching { cm.unregisterNetworkCallback(callback) }
        registered = false
        onTransitionListener = null
    }

    fun refreshNow(): NetworkSnapshot {
        val snap = readCurrentPhysicalNetwork()
        _snapshot.value = snap
        return snap
    }

    private fun refreshAndDispatch(
        net: Network,
        capsOverride: NetworkCapabilities? = null,
        lpOverride: LinkProperties? = null,
    ) {
        val caps = capsOverride ?: runCatching { cm.getNetworkCapabilities(net) }.getOrNull()
        if (caps != null && !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) {
            return
        }
        val lp = lpOverride ?: runCatching { cm.getLinkProperties(net) }.getOrNull()
        val prev = _snapshot.value
        val next = buildSnapshotFrom(net, caps, lp)
        _snapshot.value = next
        val meaningfulChange =
            prev.connected != next.connected ||
                prev.transport != next.transport ||
                (prev.networkHandle != 0L && next.networkHandle != 0L && prev.networkHandle != next.networkHandle) ||
                prev.isMetered != next.isMetered
        if (meaningfulChange) {
            onTransitionListener?.invoke(prev, next)
        }
    }

    fun readCurrentPhysicalNetwork(): NetworkSnapshot {
        return runCatching {
            val allNets = cm.allNetworks
            var chosenNet: Network? = null
            var chosenCaps: NetworkCapabilities? = null
            for (n in allNets) {
                val c = cm.getNetworkCapabilities(n) ?: continue
                if (c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                ) {
                    chosenNet = n
                    chosenCaps = c
                    if (c.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) break
                }
            }
            if (chosenNet == null || chosenCaps == null) {
                NetworkSnapshot(
                    connected = false,
                    transport = UnderlyingTransport.NONE,
                    isMetered = false,
                    isValidated = false,
                    networkHandle = 0L,
                    hasIpv4 = false,
                    hasGlobalIpv6 = false,
                )
            } else {
                buildSnapshotFrom(chosenNet, chosenCaps, cm.getLinkProperties(chosenNet))
            }
        }.getOrDefault(
            NetworkSnapshot(
                connected = true,
                transport = UnderlyingTransport.WIFI,
            )
        )
    }

    companion object {
        fun classifyCapabilities(
            hasInternet: Boolean,
            hasWifi: Boolean,
            hasCellular: Boolean,
            hasEthernet: Boolean,
        ): UnderlyingTransport = when {
            !hasInternet -> UnderlyingTransport.NONE
            hasWifi -> UnderlyingTransport.WIFI
            hasCellular -> UnderlyingTransport.CELLULAR
            hasEthernet -> UnderlyingTransport.ETHERNET
            else -> UnderlyingTransport.OTHER
        }

        private fun buildSnapshotFrom(
            net: Network,
            caps: NetworkCapabilities?,
            lp: LinkProperties?,
        ): NetworkSnapshot {
            if (caps == null) {
                return NetworkSnapshot(
                    connected = false,
                    transport = UnderlyingTransport.NONE,
                    networkHandle = net.networkHandle,
                )
            }
            val transport = classifyCapabilities(
                hasInternet = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET),
                hasWifi = caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI),
                hasCellular = caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR),
                hasEthernet = caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET),
            )
            val notMetered = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
            val validated = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            var hasV4 = false
            var hasGlobalV6 = false
            lp?.linkAddresses?.forEach { la ->
                val addr = la.address
                if (addr is Inet6Address) {
                    if (!addr.isLinkLocalAddress && !addr.isLoopbackAddress && !addr.isSiteLocalAddress) {
                        hasGlobalV6 = true
                    }
                } else if (!addr.isLoopbackAddress) {
                    hasV4 = true
                }
            }
            val dnsList = lp?.dnsServers?.mapNotNull { it.hostAddress }.orEmpty()
            return NetworkSnapshot(
                connected = transport != UnderlyingTransport.NONE,
                transport = transport,
                isMetered = !notMetered,
                isValidated = validated,
                networkHandle = net.networkHandle,
                hasIpv4 = hasV4,
                hasGlobalIpv6 = hasGlobalV6,
                systemDnsServers = dnsList,
            )
        }
    }
}
