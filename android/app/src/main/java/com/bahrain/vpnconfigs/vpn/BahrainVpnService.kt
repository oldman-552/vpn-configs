// =====================================================================
// BahrainVpnService.kt — خدمة نفق الـ VPN المتكاملة لتطبيق bahrain-vpn:
//   • إنشاء واجهة TUN عبر Android VpnService مع استثناء التطبيقات (Split Tunneling)
//   • تشغيل hev-socks5-tunnel (JNI C/lwIP + MapDNS لمنع تسريب DNS)
//   • تشغيل نواة sing-box محليًا والتبديل السلس بين السيرفرات دون هدم واجهة TUN
//   • اتصال ذكي متوازٍ (Smart Parallel Failover) يتحقق من عمل الإنترنت فعليًا على شبكة المستخدم
//   • مراقب ذكي (Watchdog) لقياس البينغ الحيّ والتبديل التلقائي عند سقوط العقدة
//   • إشعار دائم حيّ يعرض سرعة التنزيل والرفع والبينغ وأزرار التحكم السريع
// =====================================================================
package com.bahrain.vpnconfigs.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.bahrain.vpnconfigs.MainActivity
import com.bahrain.vpnconfigs.R
import com.bahrain.vpnconfigs.data.Prefs
import com.bahrain.vpnconfigs.data.Repo
import com.bahrain.vpnconfigs.engine.Converters
import com.bahrain.vpnconfigs.engine.RunningDaemon
import com.bahrain.vpnconfigs.engine.SingBox
import com.bahrain.vpnconfigs.engine.Socks
import com.bahrain.vpnconfigs.util.UiMessages
import hev.htproxy.TProxyService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.File

class BahrainVpnService : VpnService() {

    companion object {
        const val ACTION_CONNECT = "com.bahrain.vpnconfigs.action.CONNECT"
        const val ACTION_SWITCH = "com.bahrain.vpnconfigs.action.SWITCH"
        const val ACTION_NEXT = "com.bahrain.vpnconfigs.action.NEXT"
        const val ACTION_RELOAD_TUN = "com.bahrain.vpnconfigs.action.RELOAD_TUN"
        const val ACTION_DISCONNECT = "com.bahrain.vpnconfigs.action.DISCONNECT"

        const val EXTRA_CFG = "extra_cfg"
        const val EXTRA_LABEL = "extra_label"

        private const val CHANNEL_ID = "bahrain_vpn_tunnel"
        private const val NOTIF_ID = 1001

        @Volatile
        private var activeInstance: BahrainVpnService? = null

        fun startConnect(ctx: Context, cfg: String, label: String) {
            val appCtx = ctx.applicationContext
            val i = Intent(appCtx, BahrainVpnService::class.java).apply {
                action = if (VpnStateManager.status.value.phase == VpnPhase.CONNECTED) {
                    ACTION_SWITCH
                } else {
                    ACTION_CONNECT
                }
                putExtra(EXTRA_CFG, cfg)
                putExtra(EXTRA_LABEL, label)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                appCtx.startForegroundService(i)
            } else {
                appCtx.startService(i)
            }
        }

        fun reloadTunnelIfConnected(ctx: Context) {
            val inst = activeInstance
            if (inst != null) {
                inst.requestReloadTun()
            } else if (VpnStateManager.status.value.phase == VpnPhase.CONNECTED) {
                runCatching {
                    ctx.applicationContext.startService(
                        Intent(ctx.applicationContext, BahrainVpnService::class.java).apply {
                            action = ACTION_RELOAD_TUN
                        }
                    )
                }
            }
        }

        fun switchNextServer(ctx: Context) {
            val inst = activeInstance
            if (inst != null) {
                inst.requestNextServer()
            } else if (VpnStateManager.status.value.isActive) {
                runCatching {
                    ctx.applicationContext.startService(
                        Intent(ctx.applicationContext, BahrainVpnService::class.java).apply {
                            action = ACTION_NEXT
                        }
                    )
                }
            }
        }

        fun stopVpn(ctx: Context) {
            val inst = activeInstance
            if (inst != null) {
                inst.requestDisconnect()
            } else {
                VpnStateManager.resetDisconnected(infoMsg = "تم قطع الاتصال")
                QuickTileService.requestTileUpdate(ctx.applicationContext)
                runCatching {
                    ctx.applicationContext.startService(
                        Intent(ctx.applicationContext, BahrainVpnService::class.java).apply {
                            action = ACTION_DISCONNECT
                        }
                    )
                }
            }
        }
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val opLock = Mutex()

    private lateinit var prefs: Prefs
    private lateinit var singBox: SingBox

    @Volatile
    private var tunFd: ParcelFileDescriptor? = null

    @Volatile
    private var daemon: RunningDaemon? = null

    private var monitorJob: Job? = null
    private var probeJob: Job? = null
    private var traceJob: Job? = null

    @Volatile
    private var lastPhysicalNetHandle: Long = 0L

    private val netCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            val handle = network.networkHandle
            val prev = lastPhysicalNetHandle
            lastPhysicalNetHandle = handle
            // عند انتقال الهاتف الفعلي من Wi-Fi إلى 5G أو العكس نعيد ربط sing-box بسلاسة
            if (prev != 0L && prev != handle && VpnStateManager.status.value.phase == VpnPhase.CONNECTED) {
                serviceScope.launch {
                    delay(450L)
                    opLock.withLock {
                        val st = VpnStateManager.status.value
                        if (st.phase == VpnPhase.CONNECTED && st.activeCfg != null) {
                            handleConnect(st.activeCfg, st.activeLabel, forceRebuildTun = false)
                        }
                    }
                }
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        activeInstance = this
        prefs = Prefs(applicationContext)
        singBox = SingBox(applicationContext)
        ensureNotificationChannel()
        registerPhysicalNetworkWatcher()
    }

    fun requestNextServer() {
        serviceScope.launch {
            opLock.withLock {
                handleNextServer()
            }
        }
    }

    private fun registerPhysicalNetworkWatcher() {
        runCatching {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val req = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
            cm.registerNetworkCallback(req, netCallback)
        }
    }

    private fun unregisterPhysicalNetworkWatcher() {
        runCatching {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            cm.unregisterNetworkCallback(netCallback)
        }
    }

    fun requestDisconnect() {
        serviceScope.launch {
            opLock.withLock {
                teardownInternal(null, "تم قطع الاتصال")
            }
            stopSelf()
        }
    }

    fun requestReloadTun() {
        serviceScope.launch {
            opLock.withLock {
                val cur = VpnStateManager.status.value
                if (cur.activeCfg != null && cur.isActive) {
                    handleConnect(cur.activeCfg, cur.activeLabel, forceRebuildTun = true)
                }
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action ?: ACTION_CONNECT

        // دائمًا نستدعي promoteToForeground أولًا لتفادي استثناء أندرويد 8-15 عند البدء كخدمة أمامية
        val initialLabel = intent?.getStringExtra(EXTRA_LABEL)
            ?: VpnStateManager.status.value.activeLabel.ifBlank { prefs.selectedLabel }
        promoteToForeground(buildNotification("جارٍ المعالجة…", initialLabel, ""))

        if (action == ACTION_DISCONNECT) {
            requestDisconnect()
            return START_NOT_STICKY
        }

        val targetCfg = intent?.getStringExtra(EXTRA_CFG)
        val targetLabel = intent?.getStringExtra(EXTRA_LABEL)

        serviceScope.launch {
            opLock.withLock {
                when (action) {
                    ACTION_CONNECT -> handleConnect(targetCfg, targetLabel, forceRebuildTun = true)
                    ACTION_SWITCH -> handleConnect(targetCfg, targetLabel, forceRebuildTun = false)
                    ACTION_RELOAD_TUN -> {
                        val cur = VpnStateManager.status.value
                        if (cur.activeCfg != null) {
                            handleConnect(cur.activeCfg, cur.activeLabel, forceRebuildTun = true)
                        }
                    }
                    ACTION_NEXT -> handleNextServer()
                }
            }
        }

        return START_STICKY
    }

    private suspend fun handleConnect(rawCfg: String?, rawLabel: String?, forceRebuildTun: Boolean) {
        val pool = ensureServerPool()
        val chosenCfg = rawCfg?.takeIf { it.isNotBlank() }
            ?: prefs.selectedCfg.takeIf { it.isNotBlank() }
            ?: pool.firstOrNull()?.cfg

        if (chosenCfg.isNullOrBlank()) {
            teardownInternal(UiMessages.MSG_NO_SERVERS, null)
            stopSelf()
            return
        }

        val chosenLabel = rawLabel?.takeIf { it.isNotBlank() }
            ?: pool.firstOrNull { it.cfg == chosenCfg }?.label
            ?: prefs.selectedLabel.ifBlank { "bahrain-vpn #1" }

        prefs.selectedCfg = chosenCfg
        prefs.selectedLabel = chosenLabel

        val isSwitching = tunFd != null && !forceRebuildTun && TProxyService.TProxyIsRunning()

        VpnStateManager.update { prev ->
            prev.copy(
                phase = if (isSwitching) VpnPhase.SWITCHING else VpnPhase.CONNECTING,
                activeCfg = chosenCfg,
                activeLabel = chosenLabel,
                activeProto = Converters.protocolBadge(chosenCfg),
                activeEndpoint = Converters.endpointLabel(chosenCfg),
                statusMessage = if (isSwitching) "جارٍ التبديل إلى $chosenLabel…" else "جارٍ الربط والتحقق من الاتصال…",
                error = null,
            )
        }
        updateNotification("جارٍ الاتصال بـ $chosenLabel…", "")

        // 1) إيقاف عملية sing-box السابقة قبل تشغيل الجديدة على المنفذ 20808
        singBox.stopDaemon(daemon)
        daemon = null

        val newDaemon = singBox.startDaemon(
            cfg = chosenCfg,
            port = SingBox.VPN_SOCKS_PORT,
            dnsServer = prefs.dnsServer,
            useDoh = prefs.dnsDoh,
            tag = "vpn",
        )

        val initialPing = if (newDaemon != null) {
            val probe = runCatching {
                Socks.measureRealDelay(SingBox.VPN_SOCKS_PORT, SingBox.TEST_URL, 4200)
            }.getOrNull()
            if (probe != null && probe.status in listOf(200, 204)) probe.elapsedMs else -1L
        } else {
            -1L
        }

        if (newDaemon == null || initialPing < 0L) {
            singBox.stopDaemon(newDaemon)
            if (prefs.autoFailover && pool.size > 1) {
                VpnStateManager.update { prev ->
                    prev.copy(statusMessage = "$chosenLabel لم يستجب — جارٍ البحث الذكي عن أسرع بديل…")
                }
                updateNotification("جارٍ البحث الذكي عن سيرفر سريع…", "")
                val alt = findWorkingAlternativeParallel(excludeCfg = chosenCfg, pool = pool)
                if (alt != null) {
                    connectWithVerifiedDaemon(alt.first, alt.second, alt.third, forceRebuildTun)
                    return
                }
            }
            teardownInternal("تعذّر الاتصال عبر السيرفر المحدد — افحص القائمة لاختيار الأسرع على شبكتك", null)
            stopSelf()
            return
        }

        daemon = newDaemon

        // 2) إنشاء واجهة TUN وتشغيل hev-socks5-tunnel عند الحاجة
        if (!isSwitching) {
            stopTunLayer()
            if (!startTunLayer()) {
                teardownInternal("رفض النظام إنشاء واجهة الـ VPN (تحقّق من صلاحية الـ VPN)", null)
                stopSelf()
                return
            }
        }

        val now = System.currentTimeMillis()
        val chosenProto = Converters.protocolBadge(chosenCfg)
        val chosenEndpoint = Converters.endpointLabel(chosenCfg)
        prefs.recordConnection(
            label = chosenLabel,
            endpoint = chosenEndpoint,
            proto = chosenProto,
            pingMs = initialPing,
        )
        VpnStateManager.update { prev ->
            prev.copy(
                phase = VpnPhase.CONNECTED,
                activeCfg = chosenCfg,
                activeLabel = chosenLabel,
                activeProto = chosenProto,
                activeEndpoint = chosenEndpoint,
                connectedSinceMs = if (isSwitching && prev.connectedSinceMs > 0L) prev.connectedSinceMs else now,
                livePingMs = initialPing,
                exitIp = "",
                exitCountry = "",
                statusMessage = "متّصل بأمان عبر $chosenLabel (${initialPing} ms)",
                error = null,
            )
        }
        QuickTileService.requestTileUpdate(applicationContext)
        startMonitorLoop()
        fetchExitTraceAsync()
    }

    private suspend fun connectWithVerifiedDaemon(
        cand: ServerCandidate,
        verifiedDaemon: RunningDaemon,
        verifiedPingMs: Long,
        forceRebuildTun: Boolean,
    ) {
        daemon = verifiedDaemon
        prefs.selectedCfg = cand.cfg
        prefs.selectedLabel = cand.label

        if (tunFd == null || forceRebuildTun || !TProxyService.TProxyIsRunning()) {
            stopTunLayer()
            if (!startTunLayer()) {
                teardownInternal("تعذّر إنشاء نفق TUN", null)
                stopSelf()
                return
            }
        }

        val now = System.currentTimeMillis()
        val candProto = Converters.protocolBadge(cand.cfg)
        val candEndpoint = Converters.endpointLabel(cand.cfg)
        prefs.recordConnection(
            label = cand.label,
            endpoint = candEndpoint,
            proto = candProto,
            pingMs = verifiedPingMs,
        )
        VpnStateManager.update { prev ->
            prev.copy(
                phase = VpnPhase.CONNECTED,
                activeCfg = cand.cfg,
                activeLabel = cand.label,
                activeProto = candProto,
                activeEndpoint = candEndpoint,
                connectedSinceMs = if (prev.connectedSinceMs > 0L) prev.connectedSinceMs else now,
                livePingMs = verifiedPingMs,
                exitIp = "",
                exitCountry = "",
                failoverCount = prev.failoverCount + 1,
                statusMessage = "تم الربط الذكي عبر ${cand.label} (${verifiedPingMs} ms)",
                error = null,
            )
        }
        QuickTileService.requestTileUpdate(applicationContext)
        startMonitorLoop()
        fetchExitTraceAsync()
    }

    /** يجلب عنوان الخروج والدولة عبر Cloudflare Trace داخل النفق دون حجب الاتصال. */
    private fun fetchExitTraceAsync() {
        traceJob?.cancel()
        traceJob = serviceScope.launch {
            val trace = runCatching {
                Socks.get(
                    proxyPort = SingBox.VPN_SOCKS_PORT,
                    url = "https://1.1.1.1/cdn-cgi/trace",
                    timeoutMs = 5000,
                    maxBytes = 2048,
                    captureText = true,
                )
            }.getOrNull() ?: return@launch

            if (trace.status == 200 && trace.bodyText.isNotBlank()) {
                val map = trace.bodyText.lineSequence()
                    .filter { it.contains('=') }
                    .associate { it.substringBefore('=').trim() to it.substringAfter('=').trim() }
                val ip = map["ip"].orEmpty()
                val loc = map["loc"].orEmpty()
                if (ip.isNotEmpty() || loc.isNotEmpty()) {
                    val curEp = VpnStateManager.status.value.activeEndpoint
                    if (loc.isNotEmpty() && curEp.isNotEmpty()) {
                        prefs.updateLatestHistoryCountry(curEp, loc)
                    }
                    VpnStateManager.update { st ->
                        if (st.phase == VpnPhase.CONNECTED) {
                            st.copy(exitIp = ip, exitCountry = loc)
                        } else st
                    }
                }
            }
        }
    }

    private suspend fun handleNextServer() {
        val pool = ensureServerPool()
        if (pool.isEmpty()) return
        val curCfg = VpnStateManager.status.value.activeCfg
        val idx = pool.indexOfFirst { it.cfg == curCfg }
        val next = pool[(idx + 1) % pool.size]
        handleConnect(next.cfg, next.label, forceRebuildTun = false)
    }

    private fun startTunLayer(): Boolean {
        return try {
            val builder = Builder()
                .setSession("bahrain-vpn")
                .setBlocking(false)
                .setMtu(8500)
                .addAddress("198.18.0.1", 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("198.18.0.2")

            if (prefs.enableIpv6) {
                builder.addAddress("fc00::1", 128)
                builder.addRoute("::", 0)
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }

            val splitSet = prefs.splitApps
            if (prefs.splitIncludeOnly && splitSet.isNotEmpty()) {
                var addedAny = false
                for (pkg in splitSet) {
                    if (pkg == packageName) continue
                    val ok = runCatching { builder.addAllowedApplication(pkg); true }.getOrDefault(false)
                    if (ok) addedAny = true
                }
                if (!addedAny) {
                    runCatching { builder.addDisallowedApplication(packageName) }
                }
            } else {
                // استثناء تطبيقنا دائمًا لمنع حلقة التوجيه (Routing Loop) + التطبيقات المستثناة من المستخدم
                runCatching { builder.addDisallowedApplication(packageName) }
                for (pkg in splitSet) {
                    if (pkg != packageName) {
                        runCatching { builder.addDisallowedApplication(pkg) }
                    }
                }
            }

            val pfd = builder.establish() ?: return false
            tunFd = pfd

            val udpMode = if (prefs.udpInTcp) "tcp" else "udp"
            val ipv6Line = if (prefs.enableIpv6) "\n  ipv6: 'fc00::1'" else ""
            val hevConfig = """
                tunnel:
                  mtu: 8500
                  ipv4: 198.18.0.1$ipv6Line
                socks5:
                  port: ${SingBox.VPN_SOCKS_PORT}
                  address: 127.0.0.1
                  udp: '$udpMode'
                mapdns:
                  address: 198.18.0.2
                  port: 53
                  network: 240.0.0.0
                  netmask: 240.0.0.0
                  cache-size: 10000
                misc:
                  task-stack-size: 81920
                  log-level: warn
            """.trimIndent() + "\n"

            val hevFile = File(cacheDir, "hev-socks5-tunnel.yml")
            hevFile.writeText(hevConfig, Charsets.UTF_8)

            val started = TProxyService.TProxyStartService(hevFile.absolutePath, pfd.fd)
            if (!started) {
                runCatching { pfd.close() }
                tunFd = null
                return false
            }
            true
        } catch (_: Exception) {
            stopTunLayer()
            false
        }
    }

    private fun stopTunLayer() {
        runCatching {
            if (TProxyService.TProxyIsRunning()) {
                TProxyService.TProxyStopService()
            }
        }
        tunFd?.let { pfd ->
            runCatching { pfd.close() }
        }
        tunFd = null
    }

    private fun startMonitorLoop() {
        monitorJob?.cancel()
        probeJob?.cancel()

        monitorJob = serviceScope.launch {
            val initStats = runCatching { TProxyService.TProxyGetStats() }.getOrNull()
            var prevUp = initStats?.getOrNull(1) ?: 0L
            var prevDown = initStats?.getOrNull(3) ?: 0L
            var tick = 0

            while (isActive && VpnStateManager.status.value.phase == VpnPhase.CONNECTED) {
                delay(1000L)
                val stats = runCatching { TProxyService.TProxyGetStats() }.getOrNull()
                if (stats != null && stats.size >= 4) {
                    val curUp = stats[1].coerceAtLeast(0L)
                    val curDown = stats[3].coerceAtLeast(0L)
                    val upSpd = (curUp - prevUp).coerceAtLeast(0L)
                    val downSpd = (curDown - prevDown).coerceAtLeast(0L)
                    prevUp = curUp
                    prevDown = curDown

                    VpnStateManager.update { s ->
                        s.copy(
                            upSpeedBps = upSpd,
                            downSpeedBps = downSpd,
                            totalUpBytes = curUp,
                            totalDownBytes = curDown,
                        )
                    }

                    tick++
                    if (tick % 2 == 0) {
                        val st = VpnStateManager.status.value
                        val pingTxt = if (st.livePingMs > 0) " • ${st.livePingMs} ms" else ""
                        val detail = "↓ ${VpnStateManager.formatSpeed(downSpd)}  ↑ ${VpnStateManager.formatSpeed(upSpd)}$pingTxt"
                        updateNotification("متّصل (${st.activeLabel})", detail)
                    }
                }
            }
        }

        // فحص البينغ الحيّ ومراقب التبديل التلقائي (Watchdog) كل 12 ثانية
        probeJob = serviceScope.launch {
            delay(10_000L)
            var consecutiveFails = 0
            while (isActive && VpnStateManager.status.value.phase == VpnPhase.CONNECTED) {
                val aliveProc = daemon?.process?.isAlive == true
                val probe = if (aliveProc) {
                    runCatching {
                        Socks.measureRealDelay(SingBox.VPN_SOCKS_PORT, SingBox.TEST_URL, 5000)
                    }.getOrNull()
                } else null

                if (probe != null && probe.status in listOf(200, 204)) {
                    consecutiveFails = 0
                    VpnStateManager.update { s -> s.copy(livePingMs = probe.elapsedMs) }
                } else {
                    consecutiveFails++
                    if ((!aliveProc || consecutiveFails >= 2) && prefs.autoFailover) {
                        val switched = opLock.withLock {
                            if (VpnStateManager.status.value.phase != VpnPhase.CONNECTED) {
                                false
                            } else {
                                val pool = ensureServerPool()
                                val curCfg = VpnStateManager.status.value.activeCfg ?: ""
                                VpnStateManager.update { s ->
                                    s.copy(statusMessage = "انقطع السيرفر الحالي — جارٍ التبديل التلقائي…")
                                }
                                val alt = findWorkingAlternativeParallel(curCfg, pool)
                                if (alt != null) {
                                    singBox.stopDaemon(daemon)
                                    connectWithVerifiedDaemon(alt.first, alt.second, alt.third, forceRebuildTun = false)
                                    true
                                } else {
                                    false
                                }
                            }
                        }
                        if (switched) return@launch
                    }
                }
                delay(12_000L)
            }
        }
    }

    /**
     * يختبر دفعات من 4 سيرفرات بالتوازي على منافذ مؤقتة (20901..20904) لاختيار أسرع سيرفر شغّال
     * على شبكة المستخدم خلال ثوانٍ قليلة حتى بدون فحص مسبق.
     */
    private suspend fun findWorkingAlternativeParallel(
        excludeCfg: String,
        pool: List<ServerCandidate>,
    ): Triple<ServerCandidate, RunningDaemon, Long>? {
        val startIdx = pool.indexOfFirst { it.cfg == excludeCfg }.let { if (it < 0) 0 else it + 1 }
        val candidates = buildList {
            for (step in pool.indices) {
                val c = pool[(startIdx + step) % pool.size]
                if (c.cfg != excludeCfg) add(c)
                if (size >= 16) break
            }
        }
        for (batch in candidates.chunked(4)) {
            val tested = coroutineScope {
                batch.mapIndexed { idx, cand ->
                    async(Dispatchers.IO) {
                        val r = singBox.test(
                            cfg = cand.cfg,
                            port = 20901 + idx,
                            timeoutSec = 4,
                            measureSpeed = false,
                            dnsServer = prefs.dnsServer,
                            useDoh = prefs.dnsDoh,
                        )
                        cand to r
                    }
                }.awaitAll()
            }
            val winners = tested.filter { it.second.ok }.sortedBy { it.second.latencyMs }
            for ((winner, res) in winners) {
                singBox.stopDaemon(daemon)
                daemon = null
                val started = singBox.startDaemon(
                    cfg = winner.cfg,
                    port = SingBox.VPN_SOCKS_PORT,
                    dnsServer = prefs.dnsServer,
                    useDoh = prefs.dnsDoh,
                    tag = "vpn",
                )
                if (started != null) {
                    return Triple(winner, started, res.latencyMs)
                }
            }
        }
        return null
    }

    private fun ensureServerPool(): List<ServerCandidate> {
        val current = VpnStateManager.serverPool
        if (current.isNotEmpty()) return current

        val repo = Repo(applicationContext)
        val savedBest = repo.loadSavedBest().sortedWith(
            compareByDescending<com.bahrain.vpnconfigs.engine.TestResult> { it.speedKbps > 0.0 }
                .thenByDescending { it.speedKbps }
                .thenBy { if (it.latencyMs > 0L) it.latencyMs else Long.MAX_VALUE }
        ).map { it.cfg }
        val cached = repo.loadCached(prefs.feedProfile)
        val hints = cached?.serverHints ?: emptyMap()
        val cachedAll = (cached?.configs ?: emptyList()).sortedWith(
            compareByDescending<String> {
                val spd = hints[ConvergedKey(it)]?.speedKbps ?: hints[it]?.speedKbps ?: 0.0
                spd > 0.0
            }.thenByDescending {
                hints[ConvergedKey(it)]?.speedKbps ?: hints[it]?.speedKbps ?: 0.0
            }.thenBy {
                val lat = hints[ConvergedKey(it)]?.latencyMs ?: hints[it]?.latencyMs ?: 0L
                if (lat > 0L) lat else Long.MAX_VALUE
            }
        )
        val merged = (prefs.customConfigs + savedBest + cachedAll)
            .distinct()
            .filter { Converters.isSupported(it) }
        val built = merged.mapIndexed { idx, cfg ->
            ServerCandidate(cfg, "bahrain-vpn #${idx + 1}")
        }
        VpnStateManager.serverPool = built
        return built
    }

    private fun ConvergedKey(uri: String): String = Converters.cleanUri(uri)

    private fun teardownInternal(errorMsg: String?, infoMsg: String?) {
        monitorJob?.cancel()
        probeJob?.cancel()
        traceJob?.cancel()
        singBox.stopDaemon(daemon)
        daemon = null
        stopTunLayer()
        val cleanErr = errorMsg?.let { UiMessages.sanitizeError(it, UiMessages.MSG_SERVER_UNREACHABLE) }
        VpnStateManager.resetDisconnected(errorMsg = cleanErr, infoMsg = infoMsg)
        QuickTileService.requestTileUpdate(applicationContext)
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                stopForeground(STOP_FOREGROUND_REMOVE)
            } else {
                @Suppress("DEPRECATION")
                stopForeground(true)
            }
        }
    }

    override fun onRevoke() {
        requestDisconnect()
        super.onRevoke()
    }

    override fun onDestroy() {
        if (activeInstance === this) activeInstance = null
        unregisterPhysicalNetworkWatcher()
        teardownInternal(null, null)
        serviceScope.cancel()
        super.onDestroy()
    }

    // ─────────────────── الإشعارات ───────────────────
    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            val ch = NotificationChannel(
                CHANNEL_ID,
                "اتصال bahrain-vpn",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "يعرض حالة اتصال الـ VPN والسرعة الحيّة"
                setShowBadge(false)
            }
            nm.createNotificationChannel(ch)
        }
    }

    private fun promoteToForeground(notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIF_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIF_ID, notification)
        }
    }

    private fun updateNotification(titleSuffix: String, body: String) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIF_ID, buildNotification(titleSuffix, "", body))
    }

    private fun buildNotification(titleSuffix: String, fallbackLabel: String, body: String): Notification {
        val openAppIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val nextIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, BahrainVpnService::class.java).apply { action = ACTION_NEXT },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val stopIntent = PendingIntent.getService(
            this,
            2,
            Intent(this, BahrainVpnService::class.java).apply { action = ACTION_DISCONNECT },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val title = if (fallbackLabel.isNotBlank() && !titleSuffix.contains(fallbackLabel)) {
            "bahrain-vpn • $titleSuffix ($fallbackLabel)"
        } else {
            "bahrain-vpn • $titleSuffix"
        }

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_vpn_tile)
            .setContentTitle(title)
            .setContentText(body.ifBlank { "اضغط لفتح لوحة التحكم" })
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setContentIntent(openAppIntent)
            .addAction(0, "السيرفر التالي", nextIntent)
            .addAction(0, "قطع الاتصال", stopIntent)
            .build()
    }
}
