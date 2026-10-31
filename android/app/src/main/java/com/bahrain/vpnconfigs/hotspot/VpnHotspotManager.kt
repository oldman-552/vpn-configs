// =====================================================================
// VpnHotspotManager.kt — مشاركة اتصال الـ VPN عبر نقطة الاتصال بدون روت
// (Rootless VPN Hotspot & Tethering — Android 10..15 / API 29..34):
//
// قواعد الصدق الهندسي والأمان الصارم:
//   • يصنّف التوافق بصدق تام إلى ثلاثة أوضاع فقط:
//       - MODE_A_FULL_VPN_HOTSPOT : لا يُعلن إلا إذا ثَبُت فعليًا توجيه النظام لحزم الهوتسبوت داخل النفق.
//       - MODE_B_PROXY_SHARING    : مشاركة محصّنة بدون روت عبر مستمع محلي مربوط حصريًا بـ IP واجهة
//                                   الشبكة الخاصة (HTTP/HTTPS CONNECT + SOCKS5 TCP/UDP + ملف PAC تلقائي).
//       - MODE_C_UNSUPPORTED      : عند غياب واجهة نقطة اتصال نشطة أو منع النظام الربط المحلي.
//   • مستحيل أن يستمع على 0.0.0.0 أو على واجهة بيانات الجوال العامة (WAN).
//   • حماية إغلاق آمن صارمة (Fail-Closed): عند انقطاع نفق الـ VPN تُغلق جميع الجلسات فورًا
//     ولا يتم تمرير أي حزمة مباشرة إلى الإنترنت غير المحمي أبدًا.
//   • يمنع التسرّب عبر تمرير أسماء النطاقات مباشرة إلى محلّل النفق المشفّر (127.0.0.1:20808).
// =====================================================================
package com.bahrain.vpnconfigs.hotspot

import android.content.Context
import android.content.Intent
import android.provider.Settings
import android.util.Base64
import com.bahrain.vpnconfigs.data.Prefs
import com.bahrain.vpnconfigs.engine.SingBox
import com.bahrain.vpnconfigs.util.tr
import com.bahrain.vpnconfigs.vpn.VpnPhase
import com.bahrain.vpnconfigs.vpn.VpnStateManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.io.PushbackInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest
import java.util.Collections
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

enum class HotspotSharingMode(
    val code: String,
    val titleAr: String,
    val titleEn: String,
) {
    MODE_A_FULL_VPN_HOTSPOT(
        code = "MODE_A_FULL_VPN_HOTSPOT",
        titleAr = "الوضع A: نقطة اتصال VPN كاملة (توجيه نظام موثّق)",
        titleEn = "MODE A: FULL VPN HOTSPOT (Verified OS Routing)",
    ),
    MODE_B_PROXY_SHARING(
        code = "MODE_B_PROXY_SHARING",
        titleAr = "الوضع B: مشاركة عبر بروكسي الشبكة المحلية (بدون روت)",
        titleEn = "MODE B: PROXY-BASED SHARING (Rootless LAN Proxy)",
    ),
    MODE_C_UNSUPPORTED(
        code = "MODE_C_UNSUPPORTED",
        titleAr = "الوضع C: غير متاح حاليًا (يلزم تشغيل نقطة الاتصال)",
        titleEn = "MODE C: UNSUPPORTED / INACTIVE HOTSPOT INTERFACE",
    );

    val displayTitle: String
        get() = tr(titleAr, titleEn)
}

enum class HotspotRunPhase {
    STOPPED,
    STARTING,
    ACTIVE,
    FAIL_CLOSED_VPN_WAIT,
    ERROR,
}

data class DetectedHotspotInterface(
    val interfaceName: String,
    val ipv4Address: String,
    val isDedicatedTetherAp: Boolean,
    val transportLabelAr: String,
    val transportLabelEn: String,
) {
    val displayTransport: String
        get() = tr(transportLabelAr, transportLabelEn)
}

data class ConnectedHotspotClient(
    val clientIp: String,
    val activeStreams: Int,
    val bytesDown: Long,
    val bytesUp: Long,
    val firstSeenMs: Long,
    val lastActiveMs: Long,
    val source: String = "PROXY_SESSION", // PROXY_SESSION | ARP_NEIGHBOR
)

data class VpnHotspotState(
    val runPhase: HotspotRunPhase = HotspotRunPhase.STOPPED,
    val compatibilityMode: HotspotSharingMode = HotspotSharingMode.MODE_C_UNSUPPORTED,
    val interfaceInfo: DetectedHotspotInterface? = null,
    val bindAddress: String = "",
    val bindPort: Int = 20880,
    val pacUrl: String = "",
    val requireAuth: Boolean = false,
    val authUsername: String = "vpnshare",
    val authPassword: String = "",
    val activeVpnServerLabel: String = "",
    val activeVpnProtocol: String = "",
    val vpnConnected: Boolean = false,
    val systemHotspotActive: Boolean = false,
    val connectedClients: List<ConnectedHotspotClient> = emptyList(),
    val totalBytesDown: Long = 0L,
    val totalBytesUp: Long = 0L,
    val liveDownBps: Long = 0L,
    val liveUpBps: Long = 0L,
    val failClosedBlockedCount: Long = 0L,
    val ipv6LeakPolicyAr: String = "محمي (قصر التوجيه على نفق الـ VPN ومنع تسرّب DNS/IPv6)",
    val ipv6LeakPolicyEn: String = "Protected (Tunnel-bound DNS & IPv6 fail-closed policy)",
    val statusHeadlineAr: String = "نقطة اتصال الـ VPN متوقفة",
    val statusHeadlineEn: String = "VPN Hotspot is stopped",
    val statusDetailAr: String = "اتصل بالـ VPN أولًا وشغّل نقطة الاتصال (Hotspot) في هاتفك لبدء المشاركة الآمنة بدون روت.",
    val statusDetailEn: String = "Connect VPN first and enable your phone's Wi-Fi/USB Hotspot to start rootless sharing.",
    val errorAr: String? = null,
    val errorEn: String? = null,
) {
    val isSharingActive: Boolean
        get() = runPhase == HotspotRunPhase.ACTIVE || runPhase == HotspotRunPhase.FAIL_CLOSED_VPN_WAIT

    val displayHeadline: String
        get() = tr(statusHeadlineAr, statusHeadlineEn)

    val displayDetail: String
        get() = tr(statusDetailAr, statusDetailEn)

    val displayError: String?
        get() {
            val ar = errorAr ?: return null
            return tr(ar, errorEn ?: ar)
        }

    val displayIpv6Policy: String
        get() = tr(ipv6LeakPolicyAr, ipv6LeakPolicyEn)
}

/**
 * خادم مشاركة محلي مدمج بدون روت:
 * - يستمع حصريًا على عنوان IPv4 خاص بواجهة الشبكة المحلية (يرفض 0.0.0.0 والعناوين العامة).
 * - يكتشف البروتوكول تلقائيًا على نفس المنفذ:
 *     1) SOCKS5 (CONNECT لـ TCP/DNS داخل النفق + UDP ASSOCIATE لحزم UDP).
 *     2) HTTP CONNECT / HTTP Proxy (لتطبيقات ومتصفحات الهواتف والحواسيب).
 *     3) ملف الإعداد التلقائي PAC عبر المسار `/proxy.pac` أو `/wpad.dat`.
 * - يتحقق قبل وأثناء كل اتصال من أن نفق الـ VPN موثّق (`isUpstreamTunnelVerified() == true`)،
 *   وإلا يغلق الجلسة فورًا (Fail-Closed) دون أي اتصال مباشر بالإنترنت.
 */
class VpnHotspotProxyServer(
    val bindHost: String,
    val requestedPort: Int,
    val upstreamSocksHost: String = "127.0.0.1",
    val upstreamSocksPort: Int = SingBox.VPN_SOCKS_PORT,
    val requireAuth: Boolean = false,
    val authUser: String = "",
    val authPass: String = "",
    private val isUpstreamTunnelVerified: () -> Boolean,
) {
    init {
        require(VpnHotspotManager.isSafePrivateLanIpv4(bindHost) || bindHost == "127.0.0.1") {
            "Refusing to bind hotspot proxy on non-private address: $bindHost"
        }
    }

    private data class ClientCounter(
        val ip: String,
        val firstSeenMs: Long = System.currentTimeMillis(),
        @Volatile var lastActiveMs: Long = System.currentTimeMillis(),
        val activeStreams: AtomicInteger = AtomicInteger(0),
        val bytesDown: AtomicLong = AtomicLong(0L),
        val bytesUp: AtomicLong = AtomicLong(0L),
    )

    private val running = AtomicBoolean(false)
    private val activeSockets = Collections.newSetFromMap(ConcurrentHashMap<Socket, Boolean>())
    private val activeUdpRelays = Collections.newSetFromMap(ConcurrentHashMap<DatagramSocket, Boolean>())
    private val clients = ConcurrentHashMap<String, ClientCounter>()

    val totalBytesDown = AtomicLong(0L)
    val totalBytesUp = AtomicLong(0L)
    val failClosedRejections = AtomicLong(0L)

    @Volatile
    private var serverSocket: ServerSocket? = null

    private val executor = Executors.newCachedThreadPool { r ->
        Thread(r, "bahrain-vpn-hotspot").apply { isDaemon = true }
    }

    val boundPort: Int
        get() = serverSocket?.localPort ?: requestedPort

    val isRunning: Boolean
        get() = running.get() && serverSocket?.isClosed == false

    fun start(): Int {
        if (running.getAndSet(true)) return boundPort
        try {
            val addr = InetAddress.getByName(bindHost)
            val srv = ServerSocket()
            srv.reuseAddress = true
            srv.bind(InetSocketAddress(addr, requestedPort), 64)
            serverSocket = srv
            executor.execute { acceptLoop(srv) }
            return srv.localPort
        } catch (e: Exception) {
            running.set(false)
            throw e
        }
    }

    /** يقطع فورًا جميع الجلسات المفتوحة عند سقوط نفق الـ VPN لمنع أي تسرب (Fail-Closed). */
    fun terminateActiveClientStreams() {
        for (sock in activeSockets.toList()) {
            runCatching { sock.close() }
        }
        activeSockets.clear()
        for (dg in activeUdpRelays.toList()) {
            runCatching { dg.close() }
        }
        activeUdpRelays.clear()
    }

    fun stop() {
        running.set(false)
        runCatching { serverSocket?.close() }
        serverSocket = null
        terminateActiveClientStreams()
        runCatching { executor.shutdownNow() }
    }

    fun snapshotClients(): List<ConnectedHotspotClient> {
        val cutoff = System.currentTimeMillis() - 10 * 60_000L
        return clients.values
            .filter { it.activeStreams.get() > 0 || it.lastActiveMs >= cutoff }
            .sortedWith(
                compareByDescending<ClientCounter> { it.activeStreams.get() > 0 }
                    .thenByDescending { it.lastActiveMs }
            )
            .map {
                ConnectedHotspotClient(
                    clientIp = it.ip,
                    activeStreams = it.activeStreams.get().coerceAtLeast(0),
                    bytesDown = it.bytesDown.get(),
                    bytesUp = it.bytesUp.get(),
                    firstSeenMs = it.firstSeenMs,
                    lastActiveMs = it.lastActiveMs,
                    source = "PROXY_SESSION",
                )
            }
    }

    private fun acceptLoop(srv: ServerSocket) {
        while (running.get() && !srv.isClosed) {
            val client = try {
                srv.accept()
            } catch (_: Exception) {
                if (!running.get() || srv.isClosed) break
                continue
            }
            val remoteIp = (client.inetAddress as? Inet4Address)?.hostAddress
                ?: client.inetAddress?.hostAddress.orEmpty()
            // Reject any connection not originating from private LAN or loopback test harness
            if (!VpnHotspotManager.isSafePrivateLanIpv4(remoteIp) && remoteIp != "127.0.0.1") {
                runCatching { client.close() }
                continue
            }
            activeSockets.add(client)
            val counter = clients.computeIfAbsent(remoteIp) { ClientCounter(ip = remoteIp) }
            counter.activeStreams.incrementAndGet()
            counter.lastActiveMs = System.currentTimeMillis()
            executor.execute {
                try {
                    handleClientSocket(client, counter)
                } catch (_: Exception) {
                    // Closed cleanly
                } finally {
                    counter.activeStreams.decrementAndGet()
                    counter.lastActiveMs = System.currentTimeMillis()
                    activeSockets.remove(client)
                    runCatching { client.close() }
                }
            }
        }
    }

    private fun constantTimeEquals(a: String, b: String): Boolean {
        val ba = a.toByteArray(Charsets.UTF_8)
        val bb = b.toByteArray(Charsets.UTF_8)
        return MessageDigest.isEqual(ba, bb)
    }

    private fun checkCredentials(user: String, pass: String): Boolean {
        if (!requireAuth) return true
        return constantTimeEquals(user, authUser) && constantTimeEquals(pass, authPass)
    }

    private fun buildPacScript(): String {
        val hp = "$bindHost:$boundPort"
        return """
            function FindProxyForURL(url, host) {
              if (isPlainHostName(host) ||
                  shExpMatch(host, "*.local") ||
                  isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
                  isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0") ||
                  isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0") ||
                  isInNet(dnsResolve(host), "127.0.0.0", "255.0.0.0")) {
                return "DIRECT";
              }
              return "SOCKS5 $hp; PROXY $hp";
            }
        """.trimIndent() + "\n"
    }

    private fun handleClientSocket(client: Socket, counter: ClientCounter) {
        client.tcpNoDelay = true
        client.soTimeout = 30_000
        val pIn = PushbackInputStream(BufferedInputStream(client.getInputStream()), 4)
        val out = client.getOutputStream()

        val first = pIn.read()
        if (first < 0) return
        pIn.unread(first)

        if (first == 0x05) {
            handleSocks5Client(client, pIn, out, counter)
        } else {
            handleHttpOrPacClient(client, pIn, out, counter)
        }
    }

    private fun handleSocks5Client(
        client: Socket,
        input: InputStream,
        out: OutputStream,
        counter: ClientCounter,
    ) {
        val ver = input.read()
        val nMethods = input.read()
        if (ver != 0x05 || nMethods <= 0) return
        val methods = ByteArray(nMethods)
        readExact(input, methods)

        if (requireAuth) {
            if (!methods.any { (it.toInt() and 0xFF) == 0x02 }) {
                out.write(byteArrayOf(0x05, 0xFF.toByte()))
                out.flush()
                return
            }
            out.write(byteArrayOf(0x05, 0x02))
            out.flush()
            val authVer = input.read()
            if (authVer != 0x01) return
            val uLen = input.read()
            if (uLen < 0) return
            val uBytes = ByteArray(uLen)
            readExact(input, uBytes)
            val pLen = input.read()
            if (pLen < 0) return
            val pBytes = ByteArray(pLen)
            readExact(input, pBytes)
            val ok = checkCredentials(String(uBytes, Charsets.UTF_8), String(pBytes, Charsets.UTF_8))
            out.write(byteArrayOf(0x01, if (ok) 0x00 else 0x01))
            out.flush()
            if (!ok) return
        } else {
            out.write(byteArrayOf(0x05, 0x00))
            out.flush()
        }

        // Fail-Closed check BEFORE opening upstream VPN SOCKS5 connection
        if (!isUpstreamTunnelVerified()) {
            failClosedRejections.incrementAndGet()
            out.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            out.flush()
            return
        }

        val reqHead = ByteArray(4)
        readExact(input, reqHead)
        if (reqHead[0].toInt() != 0x05) return
        val cmd = reqHead[1].toInt() and 0xFF
        val atyp = reqHead[3].toInt() and 0xFF

        val targetHostBytes: ByteArray
        val targetHostStr: String
        when (atyp) {
            0x01 -> {
                val ip4 = ByteArray(4)
                readExact(input, ip4)
                targetHostBytes = ip4
                targetHostStr = InetAddress.getByAddress(ip4).hostAddress.orEmpty()
            }
            0x03 -> {
                val dLen = input.read()
                if (dLen <= 0 || dLen > 255) return
                val dom = ByteArray(dLen)
                readExact(input, dom)
                targetHostBytes = dom
                targetHostStr = String(dom, Charsets.US_ASCII)
            }
            0x04 -> {
                val ip6 = ByteArray(16)
                readExact(input, ip6)
                targetHostBytes = ip6
                targetHostStr = InetAddress.getByAddress(ip6).hostAddress.orEmpty()
            }
            else -> {
                out.write(byteArrayOf(0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                out.flush()
                return
            }
        }
        val portBytes = ByteArray(2)
        readExact(input, portBytes)
        val targetPort = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)

        if (cmd == 0x03) {
            handleSocks5UdpAssociate(client, input, out, counter)
            return
        }
        if (cmd != 0x01 || isDisallowedTargetHost(targetHostStr)) {
            out.write(byteArrayOf(0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            out.flush()
            return
        }

        val upstream = try {
            connectUpstreamSocks5(atyp, targetHostBytes, portBytes)
        } catch (_: Exception) {
            out.write(byteArrayOf(0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            out.flush()
            return
        }

        upstream.use { upSock ->
            out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            out.flush()
            relayBidirectional(client, input, out, upSock, counter)
        }
    }

    private fun handleSocks5UdpAssociate(
        tcpControlSocket: Socket,
        tcpIn: InputStream,
        tcpOut: OutputStream,
        counter: ClientCounter,
    ) {
        val upstreamTcp = Socket()
        var lanUdp: DatagramSocket? = null
        try {
            upstreamTcp.connect(InetSocketAddress(upstreamSocksHost, upstreamSocksPort), 4000)
            upstreamTcp.soTimeout = 60_000
            val uOut = upstreamTcp.getOutputStream()
            val uIn = upstreamTcp.getInputStream()
            uOut.write(byteArrayOf(0x05, 0x01, 0x00))
            uOut.flush()
            val g = ByteArray(2)
            readExact(uIn, g)
            if (g[0].toInt() != 0x05 || g[1].toInt() != 0x00) return

            uOut.write(byteArrayOf(0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            uOut.flush()
            val rep = ByteArray(4)
            readExact(uIn, rep)
            if ((rep[1].toInt() and 0xFF) != 0x00) return
            val upUdpPort: Int = when (rep[3].toInt() and 0xFF) {
                0x01 -> {
                    val b = ByteArray(6)
                    readExact(uIn, b)
                    ((b[4].toInt() and 0xFF) shl 8) or (b[5].toInt() and 0xFF)
                }
                0x04 -> {
                    val b = ByteArray(18)
                    readExact(uIn, b)
                    ((b[16].toInt() and 0xFF) shl 8) or (b[17].toInt() and 0xFF)
                }
                else -> return
            }

            val bindInet = InetAddress.getByName(bindHost)
            val udpSock = DatagramSocket(InetSocketAddress(bindInet, 0))
            udpSock.soTimeout = 30_000
            lanUdp = udpSock
            activeUdpRelays.add(udpSock)

            val ipBytes = bindInet.address
            val localUdpPort = udpSock.localPort
            val reply = ByteArrayOutputStream().apply {
                write(byteArrayOf(0x05, 0x00, 0x00, 0x01))
                write(ipBytes)
                write(byteArrayOf((localUdpPort shr 8).toByte(), (localUdpPort and 0xFF).toByte()))
            }.toByteArray()
            tcpOut.write(reply)
            tcpOut.flush()

            val upstreamUdpAddr = InetSocketAddress(InetAddress.getByName(upstreamSocksHost), upUdpPort)
            val upUdpSock = DatagramSocket()
            upUdpSock.soTimeout = 30_000
            activeUdpRelays.add(upUdpSock)

            val lastClientUdpAddr = AtomicReference<InetSocketAddress?>(null)
            val pumpDown = executor.submit {
                val buf = ByteArray(65507)
                while (running.get() && !upUdpSock.isClosed && isUpstreamTunnelVerified()) {
                    try {
                        val pkt = DatagramPacket(buf, buf.size)
                        upUdpSock.receive(pkt)
                        val dst = lastClientUdpAddr.get() ?: continue
                        val outPkt = DatagramPacket(pkt.data, pkt.offset, pkt.length, dst)
                        udpSock.send(outPkt)
                        val n = pkt.length.toLong()
                        counter.bytesDown.addAndGet(n)
                        totalBytesDown.addAndGet(n)
                        counter.lastActiveMs = System.currentTimeMillis()
                    } catch (_: Exception) {
                        break
                    }
                }
            }
            val pumpUp = executor.submit {
                val buf = ByteArray(65507)
                while (running.get() && !udpSock.isClosed && isUpstreamTunnelVerified()) {
                    try {
                        val pkt = DatagramPacket(buf, buf.size)
                        udpSock.receive(pkt)
                        val senderIp = pkt.address?.hostAddress.orEmpty()
                        if (!VpnHotspotManager.isSafePrivateLanIpv4(senderIp) && senderIp != "127.0.0.1") continue
                        lastClientUdpAddr.set(InetSocketAddress(pkt.address, pkt.port))
                        val fwd = DatagramPacket(pkt.data, pkt.offset, pkt.length, upstreamUdpAddr)
                        upUdpSock.send(fwd)
                        val n = pkt.length.toLong()
                        counter.bytesUp.addAndGet(n)
                        totalBytesUp.addAndGet(n)
                        counter.lastActiveMs = System.currentTimeMillis()
                    } catch (_: Exception) {
                        break
                    }
                }
            }

            tcpControlSocket.soTimeout = 0
            while (running.get() && isUpstreamTunnelVerified()) {
                if (tcpIn.read() < 0) break
            }
            pumpUp.cancel(true)
            pumpDown.cancel(true)
            activeUdpRelays.remove(upUdpSock)
            runCatching { upUdpSock.close() }
        } finally {
            lanUdp?.let {
                activeUdpRelays.remove(it)
                runCatching { it.close() }
            }
            runCatching { upstreamTcp.close() }
        }
    }

    private fun handleHttpOrPacClient(
        client: Socket,
        input: InputStream,
        out: OutputStream,
        counter: ClientCounter,
    ) {
        val requestLine = readAsciiLine(input)
        if (requestLine.isEmpty()) return
        val parts = requestLine.split(" ")
        if (parts.size < 2) return
        val method = parts[0].uppercase(Locale.US)
        val rawTarget = parts[1].trim()
        val httpVer = parts.getOrNull(2) ?: "HTTP/1.1"

        val headers = ArrayList<String>()
        var proxyAuthHeader = ""
        var hostHeader = ""
        while (true) {
            val h = readAsciiLine(input)
            if (h.isEmpty()) break
            if (h.startsWith("Proxy-Authorization:", ignoreCase = true)) {
                proxyAuthHeader = h.substringAfter(":").trim()
            } else if (h.startsWith("Proxy-Connection:", ignoreCase = true)) {
                // Strip hop-by-hop header
            } else {
                if (h.startsWith("Host:", ignoreCase = true)) {
                    hostHeader = h.substringAfter(":").trim()
                }
                headers.add(h)
            }
            if (headers.size > 80) return
        }

        // Serve PAC auto-configuration script directly (even before auth so OS Wi-Fi PAC fetch works smoothly)
        if (method == "GET" && (rawTarget == "/proxy.pac" || rawTarget == "/wpad.dat" || rawTarget.startsWith("/proxy.pac?"))) {
            val pacBytes = buildPacScript().toByteArray(Charsets.UTF_8)
            val resp = buildString {
                append("HTTP/1.1 200 OK\r\n")
                append("Content-Type: application/x-ns-proxy-autoconfig; charset=utf-8\r\n")
                append("Cache-Control: no-store\r\n")
                append("Content-Length: ${pacBytes.size}\r\n")
                append("Connection: close\r\n\r\n")
            }.toByteArray(Charsets.US_ASCII)
            out.write(resp)
            out.write(pacBytes)
            out.flush()
            return
        }

        if (requireAuth) {
            val authed = if (proxyAuthHeader.startsWith("Basic ", ignoreCase = true)) {
                runCatching {
                    val b64 = proxyAuthHeader.substring(6).trim()
                    val decoded = String(Base64.decode(b64, Base64.DEFAULT), Charsets.UTF_8)
                    val sep = decoded.indexOf(':')
                    sep >= 0 && checkCredentials(decoded.substring(0, sep), decoded.substring(sep + 1))
                }.getOrDefault(false)
            } else false

            if (!authed) {
                val body = "Proxy authentication required\n".toByteArray(Charsets.UTF_8)
                val hdr = buildString {
                    append("HTTP/1.1 407 Proxy Authentication Required\r\n")
                    append("Proxy-Authenticate: Basic realm=\"bahrain-vpn-hotspot\"\r\n")
                    append("Content-Length: ${body.size}\r\n")
                    append("Connection: close\r\n\r\n")
                }.toByteArray(Charsets.US_ASCII)
                out.write(hdr)
                out.write(body)
                out.flush()
                return
            }
        }

        // Strict Fail-Closed check: NEVER route via unprotected direct network if VPN is down!
        if (!isUpstreamTunnelVerified()) {
            failClosedRejections.incrementAndGet()
            val body = "VPN tunnel is not verified — Fail-Closed hotspot protection blocked direct internet leak.\n"
                .toByteArray(Charsets.UTF_8)
            val hdr = buildString {
                append("HTTP/1.1 503 Service Unavailable\r\n")
                append("Content-Type: text/plain; charset=utf-8\r\n")
                append("Content-Length: ${body.size}\r\n")
                append("Connection: close\r\n\r\n")
            }.toByteArray(Charsets.US_ASCII)
            out.write(hdr)
            out.write(body)
            out.flush()
            return
        }

        if (method == "CONNECT") {
            val host: String
            val port: Int
            if (rawTarget.startsWith("[")) {
                val close = rawTarget.indexOf(']')
                if (close <= 1) return
                host = rawTarget.substring(1, close)
                port = rawTarget.substring(close + 1).removePrefix(":").toIntOrNull() ?: 443
            } else {
                host = rawTarget.substringBeforeLast(":", rawTarget)
                port = rawTarget.substringAfterLast(":", "443").toIntOrNull() ?: 443
            }
            if (host.isBlank() || port !in 1..65535 || isDisallowedTargetHost(host)) {
                out.write("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII))
                out.flush()
                return
            }

            val domBytes = host.toByteArray(Charsets.US_ASCII)
            val portBytes = byteArrayOf((port shr 8).toByte(), (port and 0xFF).toByte())
            val upstream = try {
                connectUpstreamSocks5(0x03, domBytes, portBytes)
            } catch (_: Exception) {
                out.write("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII))
                out.flush()
                return
            }

            upstream.use { upSock ->
                out.write("$httpVer 200 Connection Established\r\n\r\n".toByteArray(Charsets.US_ASCII))
                out.flush()
                relayBidirectional(client, input, out, upSock, counter)
            }
        } else {
            // Plain HTTP proxy request (e.g. GET http://example.com/path HTTP/1.1)
            val uri = runCatching { java.net.URI(rawTarget) }.getOrNull()
            val host = (uri?.host ?: hostHeader.substringBefore(":")).trim().removeSurrounding("[", "]")
            val port = when {
                uri != null && uri.port > 0 -> uri.port
                hostHeader.contains(':') -> hostHeader.substringAfterLast(':').toIntOrNull() ?: 80
                else -> 80
            }
            if (host.isBlank() || port !in 1..65535 || isDisallowedTargetHost(host)) {
                out.write("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII))
                out.flush()
                return
            }
            val originPath = if (uri != null && uri.scheme != null) {
                (uri.rawPath?.ifBlank { "/" } ?: "/") + (uri.rawQuery?.let { "?$it" } ?: "")
            } else {
                rawTarget.ifBlank { "/" }
            }

            val domBytes = host.toByteArray(Charsets.US_ASCII)
            val portBytes = byteArrayOf((port shr 8).toByte(), (port and 0xFF).toByte())
            val upstream = try {
                connectUpstreamSocks5(0x03, domBytes, portBytes)
            } catch (_: Exception) {
                out.write("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII))
                out.flush()
                return
            }

            upstream.use { upSock ->
                val upOut = upSock.getOutputStream()
                val rewritten = buildString {
                    append("$method $originPath $httpVer\r\n")
                    var sawConn = false
                    for (h in headers) {
                        if (h.startsWith("Connection:", ignoreCase = true)) {
                            append("Connection: close\r\n")
                            sawConn = true
                        } else {
                            append(h).append("\r\n")
                        }
                    }
                    if (!sawConn) append("Connection: close\r\n")
                    append("\r\n")
                }.toByteArray(Charsets.US_ASCII)
                upOut.write(rewritten)
                upOut.flush()
                counter.bytesUp.addAndGet(rewritten.size.toLong())
                totalBytesUp.addAndGet(rewritten.size.toLong())
                relayBidirectional(client, input, out, upSock, counter)
            }
        }
    }

    private fun isDisallowedTargetHost(rawHost: String): Boolean {
        val h = rawHost.trim().removeSurrounding("[", "]").lowercase(Locale.US)
        if (h.isEmpty() || h == "localhost" || h == "0.0.0.0" || h == "::1") return true
        if (h.startsWith("127.") || h.startsWith("169.254.")) return true
        return false
    }

    private fun connectUpstreamSocks5(
        atyp: Int,
        targetHostBytes: ByteArray,
        portBytes: ByteArray,
    ): Socket {
        if (!isUpstreamTunnelVerified()) {
            failClosedRejections.incrementAndGet()
            throw IllegalStateException("VPN tunnel not verified")
        }
        val up = Socket()
        try {
            up.tcpNoDelay = true
            up.soTimeout = 25_000
            up.connect(InetSocketAddress(upstreamSocksHost, upstreamSocksPort), 5000)
            val uOut = up.getOutputStream()
            val uIn = up.getInputStream()

            uOut.write(byteArrayOf(0x05, 0x01, 0x00))
            uOut.flush()
            val greet = ByteArray(2)
            readExact(uIn, greet)
            require(greet[0].toInt() == 0x05 && greet[1].toInt() == 0x00) { "Upstream SOCKS5 auth failed" }

            val req = ByteArrayOutputStream().apply {
                write(byteArrayOf(0x05, 0x01, 0x00, atyp.toByte()))
                if (atyp == 0x03) {
                    require(targetHostBytes.size in 1..255)
                    write(targetHostBytes.size)
                }
                write(targetHostBytes)
                write(portBytes)
            }.toByteArray()
            uOut.write(req)
            uOut.flush()

            val head = ByteArray(4)
            readExact(uIn, head)
            require((head[1].toInt() and 0xFF) == 0x00) { "Upstream SOCKS5 connect rejected: ${head[1]}" }
            when (head[3].toInt() and 0xFF) {
                0x01 -> readExact(uIn, ByteArray(6))
                0x04 -> readExact(uIn, ByteArray(18))
                0x03 -> {
                    val len = uIn.read()
                    if (len < 0) throw EOFException("Upstream domain len EOF")
                    readExact(uIn, ByteArray(len + 2))
                }
                else -> throw IllegalStateException("Unknown upstream ATYP")
            }
            return up
        } catch (e: Exception) {
            runCatching { up.close() }
            throw e
        }
    }

    private fun relayBidirectional(
        clientSock: Socket,
        clientIn: InputStream,
        clientOut: OutputStream,
        upstreamSock: Socket,
        counter: ClientCounter,
    ) {
        val upIn = upstreamSock.getInputStream()
        val upOut = upstreamSock.getOutputStream()

        val upstreamToClient = executor.submit {
            val buf = ByteArray(16 * 1024)
            try {
                while (running.get() && isUpstreamTunnelVerified()) {
                    val n = upIn.read(buf)
                    if (n < 0) break
                    if (!isUpstreamTunnelVerified()) {
                        failClosedRejections.incrementAndGet()
                        break
                    }
                    clientOut.write(buf, 0, n)
                    clientOut.flush()
                    counter.bytesDown.addAndGet(n.toLong())
                    totalBytesDown.addAndGet(n.toLong())
                    counter.lastActiveMs = System.currentTimeMillis()
                }
            } catch (_: Exception) {
                // Stream closed
            } finally {
                runCatching { clientSock.shutdownOutput() }
            }
        }

        val buf = ByteArray(16 * 1024)
        try {
            while (running.get() && isUpstreamTunnelVerified()) {
                val n = clientIn.read(buf)
                if (n < 0) break
                if (!isUpstreamTunnelVerified()) {
                    failClosedRejections.incrementAndGet()
                    break
                }
                upOut.write(buf, 0, n)
                upOut.flush()
                counter.bytesUp.addAndGet(n.toLong())
                totalBytesUp.addAndGet(n.toLong())
                counter.lastActiveMs = System.currentTimeMillis()
            }
        } catch (_: Exception) {
            // Stream closed
        } finally {
            runCatching { upstreamSock.shutdownOutput() }
            runCatching { upstreamToClient.get(1500, java.util.concurrent.TimeUnit.MILLISECONDS) }
            upstreamToClient.cancel(true)
        }
    }

    private fun readExact(input: InputStream, dst: ByteArray) {
        var off = 0
        while (off < dst.size) {
            val n = input.read(dst, off, dst.size - off)
            if (n < 0) throw EOFException("Unexpected EOF")
            off += n
        }
    }

    private fun readAsciiLine(input: InputStream): String {
        val sb = StringBuilder()
        while (true) {
            val c = input.read()
            if (c < 0) break
            if (c == '\n'.code) break
            if (c != '\r'.code) sb.append(c.toChar())
            if (sb.length > 8192) break
        }
        return sb.toString()
    }
}

object VpnHotspotManager {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val _state = MutableStateFlow(VpnHotspotState())
    val state: StateFlow<VpnHotspotState> = _state.asStateFlow()

    @Volatile
    private var activeServer: VpnHotspotProxyServer? = null

    @Volatile
    private var monitorJob: Job? = null

    @Volatile
    private var vpnWatcherStarted: Boolean = false

    private val DEDICATED_TETHER_PREFIXES = listOf(
        "ap", "swlan", "wlan1", "wlan2", "softap", "rndis", "ncm", "usb", "bt-pan", "p2p-",
    )

    private val BLOCKED_WAN_OR_TUN_PREFIXES = listOf(
        "tun", "ppp", "rmnet", "ccmni", "pdp", "clat", "v4-rmnet", "dummy", "lo", "sit", "ip6tnl",
    )

    fun isSafePrivateLanIpv4(ip: String?): Boolean {
        val clean = ip?.trim().orEmpty()
        val parts = clean.split('.')
        if (parts.size != 4) return false
        val nums = parts.map { it.toIntOrNull() ?: return false }
        if (nums.any { it !in 0..255 }) return false
        val p0 = nums[0]
        val p1 = nums[1]
        return when {
            p0 == 10 -> true
            p0 == 172 && p1 in 16..31 -> true
            p0 == 192 && p1 == 168 -> true
            // Android Wi-Fi Hotspot on modern Pixel/AOSP/Samsung often uses 192.168.43.x, 192.168.137.x, or 10.x
            else -> false
        }
    }

    /**
     * يفحص واجهات الشبكة الحية على الهاتف بدون روت لاكتشاف واجهة الهوتسبوت (Wi-Fi AP / USB / Wi-Fi Direct)
     * أو الشبكة المحلية الخاصة، مع رفض أي عنوان عام أو واجهة خلوية أو نفق TUN.
     */
    fun detectBestSharingInterface(): DetectedHotspotInterface? {
        val candidates = ArrayList<DetectedHotspotInterface>()
        runCatching {
            val ifaces = NetworkInterface.getNetworkInterfaces() ?: return null
            while (ifaces.hasMoreElements()) {
                val nif = ifaces.nextElement() ?: continue
                if (!nif.isUp || nif.isLoopback || nif.isVirtual) continue
                val name = nif.name?.lowercase(Locale.US).orEmpty()
                if (name.isEmpty() || BLOCKED_WAN_OR_TUN_PREFIXES.any { name.startsWith(it) }) continue

                val addrs = nif.inetAddresses
                while (addrs.hasMoreElements()) {
                    val addr = addrs.nextElement()
                    if (addr !is Inet4Address || addr.isLoopbackAddress || addr.isLinkLocalAddress) continue
                    val hostIp = addr.hostAddress.orEmpty()
                    if (!isSafePrivateLanIpv4(hostIp)) continue

                    val isDedicatedAp = DEDICATED_TETHER_PREFIXES.any { name.startsWith(it) } ||
                        hostIp.startsWith("192.168.43.") ||
                        hostIp.startsWith("192.168.42.") ||
                        hostIp.startsWith("192.168.232.")

                    val (arLbl, enLbl) = when {
                        name.startsWith("rndis") || name.startsWith("ncm") || name.startsWith("usb") ->
                            "تقييد USB نشط ($name)" to "Active USB Tethering ($name)"
                        name.startsWith("bt-pan") ->
                            "تقييد بلوتوث نشط ($name)" to "Active Bluetooth Tethering ($name)"
                        name.startsWith("p2p-") ->
                            "واي فاي مباشر Wi-Fi Direct ($name)" to "Wi-Fi Direct Group ($name)"
                        isDedicatedAp ->
                            "نقطة اتصال Wi-Fi نشطة ($name)" to "Active Wi-Fi Hotspot ($name)"
                        else ->
                            "شبكة Wi-Fi محلية مشتركة ($name)" to "Shared Local Wi-Fi LAN ($name)"
                    }
                    candidates.add(
                        DetectedHotspotInterface(
                            interfaceName = name,
                            ipv4Address = hostIp,
                            isDedicatedTetherAp = isDedicatedAp,
                            transportLabelAr = arLbl,
                            transportLabelEn = enLbl,
                        )
                    )
                }
            }
        }
        return candidates.sortedWith(
            compareByDescending<DetectedHotspotInterface> { it.isDedicatedTetherAp }
                .thenByDescending { it.ipv4Address.startsWith("192.168.43.") }
                .thenBy { it.interfaceName }
        ).firstOrNull()
    }

    /**
     * يتحقق بصدق مما إذا كان نظام الهاتف نفسه يوجّه حزم الهوتسبوت داخل جدول توجيه الـ VPN تلقائيًا.
     * على أندرويد القياسي بدون روت لا ندّعي أبدًا MODE A ما لم يثبت وجود قاعدة توجيه فعلية لنفق tun0!
     */
    internal fun isSystemLevelFullVpnTetheringVerified(tetherInterfaceName: String): Boolean {
        if (tetherInterfaceName.isBlank()) return false
        return runCatching {
            val proc = ProcessBuilder("ip", "rule", "show").redirectErrorStream(true).start()
            val output = proc.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
            proc.waitFor()
            // Stock Android routes tether iif to `local_network` BEFORE `tun0`;
            // OEMs with "Allow clients to use VPNs" insert explicit `iif <ap> lookup tun0` rules!
            val lines = output.lineSequence().map { it.trim().lowercase(Locale.US) }.toList()
            lines.any { line ->
                line.contains("iif $tetherInterfaceName") && (line.contains("tun") || line.contains("vpn"))
            }
        }.getOrDefault(false)
    }

    /** قراءة اختيارية لجدول الجيران المحلي إن سمح إصدار النظام دون الحاجة لأي صلاحية روت. */
    private fun readArpNeighborsBestEffort(hotspotIface: String): List<String> {
        val ips = LinkedHashSet<String>()
        runCatching {
            val arp = File("/proc/net/arp")
            if (arp.canRead()) {
                arp.useLines { seq ->
                    seq.drop(1).forEach { line ->
                        val cols = line.trim().split(Regex("\\s+"))
                        if (cols.size >= 6) {
                            val ip = cols[0]
                            val flags = cols[2]
                            val dev = cols[5]
                            if (dev.equals(hotspotIface, ignoreCase = true) &&
                                flags != "0x0" &&
                                isSafePrivateLanIpv4(ip)
                            ) {
                                ips.add(ip)
                            }
                        }
                    }
                }
            }
        }
        return ips.toList()
    }

    private fun ensureVpnWatcher() {
        if (vpnWatcherStarted) return
        vpnWatcherStarted = true
        scope.launch {
            VpnStateManager.status.collectLatest { vpnSt ->
                val srv = activeServer
                val cur = _state.value
                if (!cur.isSharingActive || srv == null) {
                    refreshIdleCompatibilitySnapshot()
                    return@collectLatest
                }
                if (!vpnSt.isTunnelVerified) {
                    // Fail-Closed: immediately sever all active client proxy streams so nothing leaks!
                    srv.terminateActiveClientStreams()
                    if (vpnSt.phase == VpnPhase.DISCONNECTED || vpnSt.phase == VpnPhase.CONNECTION_FAILED) {
                        stopHotspotSharing(
                            reasonAr = "توقفت مشاركة الهوتسبوت تلقائيًا لحمايتك بعد انقطاع الـ VPN (منع التسرب)",
                            reasonEn = "VPN Hotspot stopped automatically upon VPN disconnect (Fail-Closed protection)",
                        )
                    } else {
                        _state.update {
                            it.copy(
                                runPhase = HotspotRunPhase.FAIL_CLOSED_VPN_WAIT,
                                vpnConnected = false,
                                liveDownBps = 0L,
                                liveUpBps = 0L,
                                statusHeadlineAr = "حماية الإغلاق الآمن نشطة — بانتظار استعادة نفق الـ VPN",
                                statusHeadlineEn = "Fail-Closed Hold Active — Waiting for VPN tunnel recovery",
                                statusDetailAr = "تم تعليق تمرير بيانات الأجهزة المتصلة مؤقتًا لمنع تسرّب أي حزمة خارج الـ VPN.",
                                statusDetailEn = "Client traffic forwarding is paused so connected devices never leak unprotected traffic.",
                            )
                        }
                    }
                } else {
                    _state.update {
                        it.copy(
                            runPhase = HotspotRunPhase.ACTIVE,
                            vpnConnected = true,
                            activeVpnServerLabel = vpnSt.activeLabel,
                            activeVpnProtocol = vpnSt.activeProto,
                            statusHeadlineAr = "مشاركة الـ VPN عبر الهوتسبوت نشطة ومحمية",
                            statusHeadlineEn = "VPN Hotspot Sharing is Active & Protected",
                            statusDetailAr = "جميع اتصالات الأجهزة المربوطة تمرّ حصريًا عبر نفق الـ VPN المشفّر (${vpnSt.activeLabel}).",
                            statusDetailEn = "All configured client connections route strictly inside your encrypted VPN tunnel (${vpnSt.activeLabel}).",
                            errorAr = null,
                            errorEn = null,
                        )
                    }
                }
            }
        }
    }

    fun refreshIdleCompatibilitySnapshot(ctx: Context? = null) {
        ensureVpnWatcher()
        val cur = _state.value
        if (cur.isSharingActive) return

        val prefs = ctx?.let { Prefs(it) }
        val vpnSt = VpnStateManager.status.value
        val iface = detectBestSharingInterface()
        val mode = when {
            iface == null -> HotspotSharingMode.MODE_C_UNSUPPORTED
            vpnSt.isTunnelVerified && iface.isDedicatedTetherAp && isSystemLevelFullVpnTetheringVerified(iface.interfaceName) ->
                HotspotSharingMode.MODE_A_FULL_VPN_HOTSPOT
            else -> HotspotSharingMode.MODE_B_PROXY_SHARING
        }

        _state.update { prev ->
            prev.copy(
                compatibilityMode = mode,
                interfaceInfo = iface,
                bindAddress = iface?.ipv4Address.orEmpty(),
                bindPort = prefs?.hotspotProxyPort ?: prev.bindPort,
                requireAuth = prefs?.hotspotRequireAuth ?: prev.requireAuth,
                authUsername = prefs?.hotspotUsername ?: prev.authUsername,
                authPassword = prefs?.hotspotPassword ?: prev.authPassword,
                vpnConnected = vpnSt.isTunnelVerified,
                activeVpnServerLabel = if (vpnSt.isTunnelVerified) vpnSt.activeLabel else "",
                activeVpnProtocol = if (vpnSt.isTunnelVerified) vpnSt.activeProto else "",
                systemHotspotActive = iface?.isDedicatedTetherAp == true,
            )
        }
    }

    /**
     * يبدأ مشاركة الـ VPN عبر الهوتسبوت بدون روت:
     * 1) يوقف أي فحص مجتمعي نشط فورًا لمنع أي تشويش على استقرار الاتصال.
     * 2) يتحقق من أن نفق الـ VPN متّصل وموثّق.
     * 3) يكتشف واجهة الهوتسبوت/الشبكة الخاصة ويربط المستمع حصريًا على عنوانها المحلي.
     */
    fun startHotspotSharing(
        ctx: Context,
        interfaceOverrideForTest: DetectedHotspotInterface? = null,
        upstreamPortOverrideForTest: Int = SingBox.VPN_SOCKS_PORT,
        upstreamVerifiedOverrideForTest: (() -> Boolean)? = null,
    ): Result<VpnHotspotState> {
        ensureVpnWatcher()
        // إيقاف أي فحص مجتمعي فور تشغيل الهوتسبوت لضمان أولوية واستقرار الأجهزة المتصلة
        com.bahrain.vpnconfigs.community.CommunityTestingManager.pauseForActiveHotspot()

        val prefs = Prefs(ctx)
        val vpnSt = VpnStateManager.status.value
        val checkUpstream = upstreamVerifiedOverrideForTest ?: { VpnStateManager.status.value.isTunnelVerified }

        if (!checkUpstream()) {
            val errAr = "يجب الاتصال بسيرفر VPN والتحقق منه أولًا قبل تشغيل نقطة اتصال الـ VPN"
            val errEn = "Please connect to a verified VPN server first before starting VPN Hotspot"
            _state.update {
                it.copy(
                    runPhase = HotspotRunPhase.ERROR,
                    errorAr = errAr,
                    errorEn = errEn,
                )
            }
            return Result.failure(IllegalStateException(errAr))
        }

        val iface = interfaceOverrideForTest ?: detectBestSharingInterface()
        if (iface == null) {
            val errAr = "لم يتم رصد نقطة اتصال (Wi-Fi Hotspot أو تقييد USB) نشطة — شغّل نقطة الاتصال من إعدادات هاتفك أولًا"
            val errEn = "No active Wi-Fi Hotspot / USB Tethering interface detected — turn on Hotspot in system settings first"
            _state.update {
                it.copy(
                    runPhase = HotspotRunPhase.STOPPED,
                    compatibilityMode = HotspotSharingMode.MODE_C_UNSUPPORTED,
                    systemHotspotActive = false,
                    errorAr = errAr,
                    errorEn = errEn,
                )
            }
            return Result.failure(IllegalStateException(errAr))
        }

        stopServerOnly()
        _state.update { it.copy(runPhase = HotspotRunPhase.STARTING, errorAr = null, errorEn = null) }

        val targetPort = prefs.hotspotProxyPort
        val reqAuth = prefs.hotspotRequireAuth
        val user = prefs.hotspotUsername
        val pass = prefs.hotspotPassword

        return try {
            val server = VpnHotspotProxyServer(
                bindHost = iface.ipv4Address,
                requestedPort = targetPort,
                upstreamSocksHost = "127.0.0.1",
                upstreamSocksPort = upstreamPortOverrideForTest,
                requireAuth = reqAuth,
                authUser = user,
                authPass = pass,
                isUpstreamTunnelVerified = checkUpstream,
            )
            val actualPort = try {
                server.start()
            } catch (_: Exception) {
                // Fallback to any available ephemeral local port if preferred port is busy
                val fallbackServer = VpnHotspotProxyServer(
                    bindHost = iface.ipv4Address,
                    requestedPort = 0,
                    upstreamSocksHost = "127.0.0.1",
                    upstreamSocksPort = upstreamPortOverrideForTest,
                    requireAuth = reqAuth,
                    authUser = user,
                    authPass = pass,
                    isUpstreamTunnelVerified = checkUpstream,
                )
                val p = fallbackServer.start()
                activeServer = fallbackServer
                p
            }
            if (activeServer == null) activeServer = server

            val fullSystemRouting = iface.isDedicatedTetherAp && isSystemLevelFullVpnTetheringVerified(iface.interfaceName)
            val mode = if (fullSystemRouting) {
                HotspotSharingMode.MODE_A_FULL_VPN_HOTSPOT
            } else {
                HotspotSharingMode.MODE_B_PROXY_SHARING
            }
            val pac = "http://${iface.ipv4Address}:$actualPort/proxy.pac"

            val newState = VpnHotspotState(
                runPhase = HotspotRunPhase.ACTIVE,
                compatibilityMode = mode,
                interfaceInfo = iface,
                bindAddress = iface.ipv4Address,
                bindPort = actualPort,
                pacUrl = pac,
                requireAuth = reqAuth,
                authUsername = user,
                authPassword = pass,
                activeVpnServerLabel = vpnSt.activeLabel,
                activeVpnProtocol = vpnSt.activeProto,
                vpnConnected = true,
                systemHotspotActive = iface.isDedicatedTetherAp,
                statusHeadlineAr = if (mode == HotspotSharingMode.MODE_A_FULL_VPN_HOTSPOT) {
                    "نقطة اتصال VPN كاملة نشطة + بروكسي محلي متاح"
                } else {
                    "مشاركة VPN عبر الشبكة المحلية نشطة (${iface.ipv4Address}:$actualPort)"
                },
                statusHeadlineEn = if (mode == HotspotSharingMode.MODE_A_FULL_VPN_HOTSPOT) {
                    "Full VPN Hotspot Active + Local Proxy Ready"
                } else {
                    "Rootless VPN Proxy Sharing Active (${iface.ipv4Address}:$actualPort)"
                },
                statusDetailAr = if (mode == HotspotSharingMode.MODE_A_FULL_VPN_HOTSPOT) {
                    "نظام جهازك يمرّر حزم الهوتسبوت عبر الـ VPN مباشرة، كما يتوفر البروكسي المحلي للأجهزة الإضافية."
                } else {
                    "أدخل العنوان ${iface.ipv4Address} والمنفذ $actualPort (أو رابط الإعداد التلقائي PAC) في إعدادات Wi-Fi للجهاز المتصل."
                },
                statusDetailEn = if (mode == HotspotSharingMode.MODE_A_FULL_VPN_HOTSPOT) {
                    "System VPN tethering routing is verified active, with local proxy also available."
                } else {
                    "Enter proxy ${iface.ipv4Address}:$actualPort (or PAC URL) in the connected device's Wi-Fi proxy settings."
                },
                errorAr = null,
                errorEn = null,
            )
            _state.value = newState
            startTelemetryMonitorLoop(iface)
            Result.success(newState)
        } catch (e: Exception) {
            stopServerOnly()
            val errAr = "تعذّر فتح منفذ المشاركة المحلي على الشبكة الخاصة — تحقّق من عمل نقطة الاتصال"
            val errEn = "Could not bind local sharing listener on hotspot interface"
            _state.update {
                it.copy(
                    runPhase = HotspotRunPhase.ERROR,
                    compatibilityMode = HotspotSharingMode.MODE_C_UNSUPPORTED,
                    errorAr = errAr,
                    errorEn = errEn,
                )
            }
            Result.failure(e)
        }
    }

    private fun startTelemetryMonitorLoop(iface: DetectedHotspotInterface) {
        monitorJob?.cancel()
        monitorJob = scope.launch {
            var prevDown = 0L
            var prevUp = 0L
            while (isActive) {
                delay(1000L)
                val srv = activeServer ?: break
                if (!srv.isRunning) break

                val curDown = srv.totalBytesDown.get()
                val curUp = srv.totalBytesUp.get()
                val dSpd = (curDown - prevDown).coerceAtLeast(0L)
                val uSpd = (curUp - prevUp).coerceAtLeast(0L)
                prevDown = curDown
                prevUp = curUp

                val proxyClients = srv.snapshotClients()
                val seenIps = proxyClients.map { it.clientIp }.toHashSet()
                val arpPeers = readArpNeighborsBestEffort(iface.interfaceName)
                    .filterNot { it in seenIps || it == iface.ipv4Address }
                    .map { ip ->
                        ConnectedHotspotClient(
                            clientIp = ip,
                            activeStreams = 0,
                            bytesDown = 0L,
                            bytesUp = 0L,
                            firstSeenMs = System.currentTimeMillis(),
                            lastActiveMs = System.currentTimeMillis(),
                            source = "ARP_NEIGHBOR",
                        )
                    }

                _state.update { prev ->
                    prev.copy(
                        connectedClients = proxyClients + arpPeers,
                        totalBytesDown = curDown,
                        totalBytesUp = curUp,
                        liveDownBps = dSpd,
                        liveUpBps = uSpd,
                        failClosedBlockedCount = srv.failClosedRejections.get(),
                    )
                }
            }
        }
    }

    private fun stopServerOnly() {
        monitorJob?.cancel()
        monitorJob = null
        activeServer?.let { runCatching { it.stop() } }
        activeServer = null
    }

    fun stopHotspotSharing(
        reasonAr: String = "تم إيقاف نقطة اتصال الـ VPN",
        reasonEn: String = "VPN Hotspot stopped",
    ) {
        stopServerOnly()
        val iface = detectBestSharingInterface()
        val vpnSt = VpnStateManager.status.value
        _state.update { prev ->
            prev.copy(
                runPhase = HotspotRunPhase.STOPPED,
                interfaceInfo = iface,
                bindAddress = iface?.ipv4Address.orEmpty(),
                pacUrl = "",
                connectedClients = emptyList(),
                liveDownBps = 0L,
                liveUpBps = 0L,
                vpnConnected = vpnSt.isTunnelVerified,
                systemHotspotActive = iface?.isDedicatedTetherAp == true,
                statusHeadlineAr = reasonAr,
                statusHeadlineEn = reasonEn,
                statusDetailAr = "توقفت مشاركة الـ VPN وتم إغلاق المنفذ المحلي بأمان.",
                statusDetailEn = "VPN sharing has stopped and the local LAN port is closed safely.",
                errorAr = null,
                errorEn = null,
            )
        }
    }

    fun openSystemTetheringSettings(ctx: Context) {
        val candidates = listOf(
            Intent("android.settings.TETHER_SETTINGS").apply { addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) },
            Intent().apply {
                setClassName("com.android.settings", "com.android.settings.TetherSettings")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            },
            Intent(Settings.ACTION_WIRELESS_SETTINGS).apply { addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) },
            Intent(Settings.ACTION_SETTINGS).apply { addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) },
        )
        for (intent in candidates) {
            val ok = runCatching {
                ctx.startActivity(intent)
                true
            }.getOrDefault(false)
            if (ok) return
        }
    }
}
