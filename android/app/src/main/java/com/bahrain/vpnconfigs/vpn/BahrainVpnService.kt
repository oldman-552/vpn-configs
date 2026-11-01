// =====================================================================
// BahrainVpnService.kt — خدمة نفق الـ VPN المتكاملة لتطبيق bahrain-vpn (v2):
//   • حماية صارمة من تسرب IPv6 و DNS (التقاط ::/0 دائمًا + tunnel-dns داخل النفق)
//   • مفتاح إيقاف حقيقي (Fail-Closed Kill Switch): يقفل واجهة TUN قبل الفحص،
//     ويحتفظ بالحجب في وضع PROTECTION_ACTIVE عند انقطاع جميع السيرفرات لمنع التسرب
//   • انتقال سلس بين شبكات Wi-Fi والجيل الخامس عبر ConnectivityManager.NetworkCallback
//   • محرك تبديل استباقي ذكي بثلاثة أوضاع (OFF / SMART / AGGRESSIVE) مع Hysteresis
//   • حالات اتصال موثّقة لا تعلن CONNECTED إلا بعد التحقق الفعلي من مرور البيانات
//   • جدولة مراقبة تكيّفية موفّرة للبطارية ومنع تكرار تحديثات الإشعار غير المتغيّرة
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
import com.bahrain.vpnconfigs.data.ClientDatabase
import com.bahrain.vpnconfigs.data.Prefs
import com.bahrain.vpnconfigs.data.Repo
import com.bahrain.vpnconfigs.data.ScanNetworkProfile
import com.bahrain.vpnconfigs.engine.Converters
import com.bahrain.vpnconfigs.engine.RunningDaemon
import com.bahrain.vpnconfigs.engine.SecurityEvaluator
import com.bahrain.vpnconfigs.engine.SingBox
import com.bahrain.vpnconfigs.engine.Socks
import com.bahrain.vpnconfigs.enterprise.AppHealthMonitor
import com.bahrain.vpnconfigs.enterprise.EnterpriseLicenseGuard
import com.bahrain.vpnconfigs.util.AppI18n
import com.bahrain.vpnconfigs.util.UiMessages
import com.bahrain.vpnconfigs.util.tr
import hev.htproxy.TProxyService
import kotlinx.coroutines.CompletableDeferred
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
            val curPhase = VpnStateManager.status.value.phase
            val i = Intent(appCtx, BahrainVpnService::class.java).apply {
                action = if (curPhase == VpnPhase.CONNECTED || curPhase == VpnPhase.CONNECTION_DEGRADED) {
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
            } else if (VpnStateManager.status.value.isActive) {
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
            val appCtx = ctx.applicationContext
            runCatching { Prefs(appCtx).wasVpnDesiredActive = false }
            val inst = activeInstance
            if (inst != null) {
                inst.requestDisconnect()
            } else {
                VpnStateManager.resetDisconnected(infoMsg = "تم قطع الاتصال")
                QuickTileService.requestTileUpdate(appCtx)
                runCatching {
                    appCtx.startService(
                        Intent(appCtx, BahrainVpnService::class.java).apply {
                            action = ACTION_DISCONNECT
                        }
                    )
                }
            }
        }

        fun reloadTunIfActive() {
            activeInstance?.requestReloadTun()
        }
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val opLock = Mutex()

    private lateinit var prefs: Prefs
    private lateinit var singBox: SingBox
    private lateinit var clientDb: ClientDatabase
    private lateinit var netAwareness: NetworkAwarenessMonitor
    private lateinit var reconnectManager: AutoReconnectManager

    @Volatile
    private var tunFd: ParcelFileDescriptor? = null

    @Volatile
    private var daemon: RunningDaemon? = null

    private var monitorJob: Job? = null
    private var probeJob: Job? = null
    private var recoveryJob: Job? = null
    private var traceJob: Job? = null

    @Volatile
    private var activeHistoryRowId: Long = 0L

    @Volatile
    private var sessionPeakDownBps: Long = 0L

    @Volatile
    private var sessionPeakUpBps: Long = 0L

    @Volatile
    private var lastNotifSignature: String = ""

    override fun onCreate() {
        super.onCreate()
        activeInstance = this
        prefs = Prefs(applicationContext)
        singBox = SingBox(applicationContext)
        clientDb = ClientDatabase.getInstance(applicationContext)
        runCatching {
            clientDb.migrateLegacyFavoritesIfNeeded(prefs)
            clientDb.pruneExpiredHistory(prefs.historyRetentionDays)
        }
        reconnectManager = AutoReconnectManager(
            cappedIntervalMs = prefs.reconnectCappedSec.toLong() * 1000L,
        )
        netAwareness = NetworkAwarenessMonitor(applicationContext)
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
        val initSnap = netAwareness.refreshNow()
        VpnStateManager.update {
            it.copy(
                underlyingNetwork = initSnap.transport.code,
                underlyingNetworkAr = initSnap.transport.labelAr,
                isMeteredNetwork = initSnap.isMetered,
            )
        }
        netAwareness.start { prev, curr ->
            VpnStateManager.update {
                it.copy(
                    underlyingNetwork = curr.transport.code,
                    underlyingNetworkAr = curr.transport.labelAr,
                    isMeteredNetwork = curr.isMetered,
                )
            }
            val cur = VpnStateManager.status.value
            if (!curr.connected) {
                if (cur.isTunnelVerified || cur.phase == VpnPhase.PROTECTION_ACTIVE) {
                    val msg = "انقطعت الشبكة الأساسية — بانتظار عودة الإشارة دون استنزاف البطارية"
                    VpnStateManager.appendEvent(msg)
                    runCatching { clientDb.recordProtectionEvent("NETWORK_LOST", "انقطاع الشبكة الأساسية", msg) }
                }
                return@start
            }

            val networkChanged = prev.transport != curr.transport ||
                (prev.networkHandle != 0L && curr.networkHandle != 0L && prev.networkHandle != curr.networkHandle) ||
                (!prev.connected && curr.connected)

            if (networkChanged && (cur.isTunnelVerified || cur.phase == VpnPhase.PROTECTION_ACTIVE)) {
                serviceScope.launch {
                    delay(450L)
                    // Part 2.7: نتحقق أولًا من صلاحية النفق الحالي بعد انتقال الشبكة قبل فرض إعادة ربط غير ضرورية
                    val aliveAndValid = cur.isTunnelVerified && daemon?.process?.isAlive == true && run {
                        val quick = runCatching {
                            Socks.measureRealDelay(SingBox.VPN_SOCKS_PORT, SingBox.TEST_URL, 2200)
                        }.getOrNull()
                        quick != null && quick.status in listOf(200, 204)
                    }
                    if (aliveAndValid) {
                        val note = "انتقلت الشبكة إلى ${curr.transport.labelAr} — استمر النفق دون انقطاع"
                        VpnStateManager.appendEvent(note)
                        VpnStateManager.update { it.copy(statusMessage = note) }
                        fetchExitTraceAsync()
                        return@launch
                    }

                    opLock.withLock {
                        val st = VpnStateManager.status.value
                        if ((st.isTunnelVerified || st.phase == VpnPhase.PROTECTION_ACTIVE) && st.activeCfg != null) {
                            val handoverNote = "تغيّرت الشبكة (${curr.transport.labelAr}) — جارٍ إعادة ربط النفق تلقائيًا…"
                            VpnStateManager.appendEvent(handoverNote)
                            runCatching {
                                clientDb.recordProtectionEvent("NETWORK_HANDOVER", "انتقال الشبكة الأساسية", handoverNote)
                            }
                            VpnStateManager.update {
                                it.copy(
                                    phase = VpnPhase.RECONNECTING,
                                    switchingStatus = handoverNote,
                                    statusMessage = "تغيّرت الشبكة الفعلية — جارٍ تأمين المسار دون تسريب…",
                                )
                            }
                            handleConnect(st.activeCfg, st.activeLabel, forceRebuildTun = false, isNetworkHandover = true)
                        }
                    }
                }
            }
        }
    }

    private fun unregisterPhysicalNetworkWatcher() {
        netAwareness.stop()
    }

    private fun finalizeActiveSessionRow(failureReason: String = "") {
        val rowId = activeHistoryRowId
        if (rowId <= 0L) return
        activeHistoryRowId = 0L
        val st = VpnStateManager.status.value
        runCatching {
            clientDb.completeSessionRecord(
                rowId = rowId,
                avgLatencyMs = st.livePingMs.coerceAtLeast(0L),
                jitterMs = st.jitterMs,
                packetLossPct = st.packetLossPct,
                peakDownloadBps = sessionPeakDownBps,
                peakUploadBps = sessionPeakUpBps,
                totalDownBytes = st.totalDownBytes,
                totalUpBytes = st.totalUpBytes,
                country = st.exitCountry,
                failureReason = failureReason,
            )
        }
        sessionPeakDownBps = 0L
        sessionPeakUpBps = 0L
    }

    fun requestDisconnect() {
        prefs.wasVpnDesiredActive = false
        reconnectManager.cancelByUser()
        com.bahrain.vpnconfigs.hotspot.VpnHotspotManager.stopHotspotSharing(
            reasonAr = "توقفت مشاركة الهوتسبوت تلقائيًا فور إيقاف الـ VPN (حماية منع التسرب)",
            reasonEn = "VPN Hotspot stopped immediately upon VPN disconnect (Fail-Closed guard)",
        )
        serviceScope.launch {
            opLock.withLock {
                finalizeActiveSessionRow()
                VpnStateManager.appendEvent(tr("تم قطع الاتصال بطلب المستخدم", "Disconnected by user"))
                teardownInternal(null, tr("تم قطع الاتصال", "Disconnected"), userInitiated = true)
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
        AppI18n.initFromPrefs(applicationContext)
        val action = intent?.action ?: ACTION_CONNECT

        val initialLabel = intent?.getStringExtra(EXTRA_LABEL)
            ?: VpnStateManager.status.value.activeLabel.ifBlank { prefs.selectedLabel }
        promoteToForeground(buildNotification(tr("جارٍ المعالجة…", "Processing…"), initialLabel, ""))

        if (action == ACTION_DISCONNECT) {
            requestDisconnect()
            return START_NOT_STICKY
        }

        prefs.wasVpnDesiredActive = true
        reconnectManager.cappedIntervalMs = prefs.reconnectCappedSec.toLong() * 1000L
        if (action == ACTION_CONNECT) {
            reconnectManager.resetForNewUserConnect()
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

    private suspend fun handleConnect(
        rawCfg: String?,
        rawLabel: String?,
        forceRebuildTun: Boolean,
        isNetworkHandover: Boolean = false,
    ) {
        recoveryJob?.cancel()
        val guard = EnterpriseLicenseGuard(applicationContext)
        val licState = guard.currentState()
        if (!licState.canConnectVpn) {
            prefs.wasVpnDesiredActive = false
            teardownInternal(licState.statusDetailAr.ifBlank { "غير مصرّح بالاتصال حاليًا" }, null, userInitiated = true)
            stopSelf()
            return
        }

        val pool = ensureServerPool()
        val chosenCfg = rawCfg?.takeIf { it.isNotBlank() }
            ?: prefs.selectedCfg.takeIf { it.isNotBlank() }
            ?: pool.firstOrNull()?.cfg

        if (chosenCfg.isNullOrBlank()) {
            prefs.wasVpnDesiredActive = false
            teardownInternal(UiMessages.MSG_NO_SERVERS, null, userInitiated = true)
            stopSelf()
            return
        }

        val prevLabel = VpnStateManager.status.value.activeLabel
        val chosenLabel = rawLabel?.takeIf { it.isNotBlank() }
            ?: pool.firstOrNull { it.cfg == chosenCfg }?.label
            ?: prefs.selectedLabel.ifBlank { "bahrain-vpn #1" }

        if (com.bahrain.vpnconfigs.engine.WarpManager.isWarp(chosenCfg)) {
            // Keep the user's chosen server as "selected"; WARP is only a fallback/manual extra.
        } else {
            warpFallbackAttempted = false
            prefs.selectedCfg = chosenCfg
            prefs.selectedLabel = chosenLabel
        }

        val osLockdown = KillSwitchController.isOsLockdownActive(this)
        val killSwitchOn = prefs.killSwitch
        val foMode = FailoverMode.fromKey(prefs.failoverMode)
        val tunAlreadyUp = tunFd != null && !forceRebuildTun && TProxyService.TProxyIsRunning()

        val initialPhase = when {
            isNetworkHandover -> VpnPhase.RECONNECTING
            tunAlreadyUp -> VpnPhase.SWITCHING_SERVER
            else -> VpnPhase.CONNECTING
        }

        VpnStateManager.update { prev ->
            prev.copy(
                phase = initialPhase,
                activeCfg = chosenCfg,
                activeLabel = chosenLabel,
                activeProto = Converters.protocolBadge(chosenCfg),
                activeEndpoint = Converters.endpointLabel(chosenCfg),
                failoverMode = foMode.key,
                killSwitchActive = killSwitchOn,
                osLockdownActive = osLockdown,
                targetServerLabel = chosenLabel,
                switchingStatus = when (initialPhase) {
                    VpnPhase.RECONNECTING -> "إعادة ربط بعد تغيّر الشبكة…"
                    VpnPhase.SWITCHING_SERVER -> "تبديل سلس إلى $chosenLabel…"
                    else -> "إنشاء نفق مشفّر والتحقق منه…"
                },
                statusMessage = if (initialPhase == VpnPhase.SWITCHING_SERVER) {
                    "جارٍ التبديل الآمن إلى $chosenLabel…"
                } else {
                    "جارٍ تأمين المسار والتحقق من الاتصال…"
                },
                error = null,
            )
        }
        updateNotification("جارٍ الاتصال بـ $chosenLabel…", "")

        // Phase 4 Kill Switch: قفل واجهة TUN قبل تشغيل وفحص السيرفر لمنع تسرب أي حزمة أثناء الربط
        if (KillSwitchController.shouldEstablishTunBeforeProbe(killSwitchOn) && !tunAlreadyUp) {
            stopTunLayer()
            if (!startTunLayer()) {
                prefs.wasVpnDesiredActive = false
                teardownInternal("رفض النظام إنشاء واجهة الـ VPN (تحقّق من صلاحية الـ VPN)", null, userInitiated = true)
                stopSelf()
                return
            }
        }

        // إيقاف عملية sing-box السابقة قبل تشغيل الجديدة على المنفذ 20808
        singBox.stopDaemon(daemon)
        daemon = null

        // Happy Eyeballs Top-4 Smart Connect Race: سباق متوازٍ لأفضل 4 سيرفرات لاختيار الأسرع فعليًا في أجزاء من الثانية
        var targetCfg = chosenCfg
        var targetLabel = chosenLabel
        var preVerifiedPingMs = -1L
        if (prefs.smartAutoSelect &&
            foMode != FailoverMode.OFF &&
            pool.size > 1 &&
            !com.bahrain.vpnconfigs.engine.WarpManager.isWarp(chosenCfg)
        ) {
            val primaryCand = pool.firstOrNull { Converters.cleanUri(it.cfg) == Converters.cleanUri(chosenCfg) }
                ?: ServerCandidate(cfg = chosenCfg, label = chosenLabel)
            val topBackups = SmartFailoverEngine.rankFailoverCandidates(
                excludeCfg = chosenCfg,
                pool = pool,
                maxCandidates = SmartFailoverEngine.PARALLEL_RACE_BATCH_SIZE - 1,
            )
            val racePool = listOf(primaryCand) + topBackups
            if (racePool.size >= 2) {
                val racedWinner = raceParallelCandidateBatch(
                    candidates = racePool,
                    preferFirstGraceMs = 85L,
                    timeoutMs = 2_300,
                )
                if (racedWinner != null) {
                    targetCfg = racedWinner.first.cfg
                    targetLabel = racedWinner.first.label
                    preVerifiedPingMs = racedWinner.second
                    if (Converters.cleanUri(targetCfg) != Converters.cleanUri(chosenCfg)) {
                        prefs.selectedCfg = targetCfg
                        prefs.selectedLabel = targetLabel
                    }
                }
            }
        }

        val establishStartMs = System.currentTimeMillis()
        val physicalDns = netAwareness.snapshot.value.systemDnsServers.firstOrNull()
        val newDaemon = singBox.startDaemon(
            cfg = targetCfg,
            port = SingBox.VPN_SOCKS_PORT,
            dnsServer = prefs.dnsServer,
            useDoh = prefs.dnsDoh,
            tag = "vpn",
            enableIpv6 = prefs.enableIpv6,
            bypassIrDomains = prefs.bypassIrDomains,
            physicalDnsServer = physicalDns,
        )

        val initialPing = if (newDaemon != null) {
            if (preVerifiedPingMs > 0L) {
                val quickVerify = runCatching {
                    Socks.measureRealDelay(SingBox.VPN_SOCKS_PORT, SingBox.TEST_URL, 2600)
                }.getOrNull()
                if (quickVerify != null && quickVerify.status in listOf(200, 204)) quickVerify.elapsedMs else preVerifiedPingMs
            } else {
                val probe = runCatching {
                    Socks.measureRealDelay(SingBox.VPN_SOCKS_PORT, SingBox.TEST_URL, 3200)
                }.getOrNull()
                if (probe != null && probe.status in listOf(200, 204)) probe.elapsedMs else -1L
            }
        } else {
            -1L
        }
        val establishDurationMs = (System.currentTimeMillis() - establishStartMs).coerceAtLeast(1L)
        val curNetCode = netAwareness.snapshot.value.transport.code

        if (newDaemon == null || initialPing < 0L) {
            singBox.stopDaemon(newDaemon)
            val cleanFailed = Converters.cleanUri(targetCfg)
            SmartFailoverEngine.recordServerDrop(cleanFailed)
            VpnStateManager.markServerDropped(cleanFailed)
            runCatching {
                clientDb.recordFailedConnectionAttempt(
                    cfg = cleanFailed,
                    serverLabel = targetLabel,
                    failureReason = if (newDaemon == null) "فشل تشغيل محرك النفق" else "انتهاء مهلة استجابة السيرفر",
                    networkType = curNetCode,
                )
                clientDb.recordServerProbeOrSessionOutcome(
                    cfgOrServerId = cleanFailed,
                    ok = false,
                    failureCategory = if (newDaemon == null) "ENGINE_START_FAIL" else "CONNECTION_TIMEOUT",
                    networkType = curNetCode,
                )
            }

            if (foMode != FailoverMode.OFF && pool.size > 1) {
                VpnStateManager.update { prev ->
                    prev.copy(
                        phase = VpnPhase.SWITCHING_SERVER,
                        switchingStatus = "بحث متوازٍ عن بديل شغّال…",
                        statusMessage = "$targetLabel لم يستجب — جارٍ البحث الذكي عن أسرع بديل…",
                    )
                }
                updateNotification("جارٍ البحث الذكي عن سيرفر بديل…", "")
                val alt = findWorkingAlternativeParallel(excludeCfg = targetCfg, pool = pool)
                if (alt != null) {
                    connectWithVerifiedDaemon(
                        cand = alt.first,
                        verifiedDaemon = alt.second,
                        verifiedPingMs = alt.third,
                        forceRebuildTun = false,
                        previousLabel = targetLabel,
                    )
                    return
                }
            }
            handleAllCandidatesFailed("تعذّر الاتصال عبر السيرفر المحدد — مفتاح الإيقاف يحمي اتصالك")
            return
        }

        daemon = newDaemon

        // ضمان عمل طبقة TUN إذا كان Kill Switch معطّلًا ولم تُنشأ بعد
        if (tunFd == null || (!tunAlreadyUp && !killSwitchOn)) {
            stopTunLayer()
            if (!startTunLayer()) {
                prefs.wasVpnDesiredActive = false
                teardownInternal("رفض النظام إنشاء واجهة الـ VPN (تحقّق من صلاحية الـ VPN)", null, userInitiated = true)
                stopSelf()
                return
            }
        }

        val now = System.currentTimeMillis()
        val chosenProto = Converters.protocolBadge(targetCfg)
        val chosenEndpoint = Converters.endpointLabel(targetCfg)
        finalizeActiveSessionRow()
        activeHistoryRowId = runCatching {
            clientDb.startSessionRecord(
                cfg = targetCfg,
                serverLabel = targetLabel,
                country = "",
                initialLatencyMs = initialPing,
                networkType = curNetCode,
                nowMs = now,
            )
        }.getOrDefault(0L)
        runCatching {
            clientDb.recordServerProbeOrSessionOutcome(
                cfgOrServerId = targetCfg,
                ok = true,
                establishMs = establishDurationMs,
                latencyMs = initialPing,
                networkType = curNetCode,
                nowMs = now,
            )
        }
        reconnectManager.onTunnelVerified()
        VpnStateManager.appendEvent("تم التحقق من الاتصال عبر $targetLabel (${initialPing} ms)")
        prefs.recordConnection(
            label = targetLabel,
            endpoint = chosenEndpoint,
            proto = chosenProto,
            pingMs = initialPing,
        )
        SmartFailoverEngine.recordServerHealthy(Converters.cleanUri(targetCfg))
        VpnStateManager.markServerHealthy(Converters.cleanUri(targetCfg))
        VpnStateManager.update { prev ->
            prev.copy(
                phase = VpnPhase.CONNECTED,
                activeCfg = targetCfg,
                activeLabel = targetLabel,
                activeProto = chosenProto,
                activeEndpoint = chosenEndpoint,
                connectedSinceMs = if (tunAlreadyUp && prev.connectedSinceMs > 0L) prev.connectedSinceMs else now,
                livePingMs = initialPing,
                jitterMs = 0.0,
                packetLossPct = 0.0,
                connectionQuality = if (initialPing <= 220L) "ممتازة" else "جيدة ومستقرة",
                exitIp = "",
                exitCountry = "",
                failoverMode = foMode.key,
                switchingStatus = "متّصل ومستقر",
                previousServerLabel = if (tunAlreadyUp && prevLabel != targetLabel) prevLabel else prev.previousServerLabel,
                targetServerLabel = "",
                lastSuccessfulSwitchAtMs = if (tunAlreadyUp && prevLabel != targetLabel) now else prev.lastSuccessfulSwitchAtMs,
                killSwitchActive = killSwitchOn,
                osLockdownActive = osLockdown,
                reconnectAttempt = 0,
                statusMessage = tr("متّصل بأمان عبر $targetLabel (${initialPing} ms)", "Connected via $targetLabel (${initialPing} ms)"),
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
        previousLabel: String = "",
    ) {
        daemon = verifiedDaemon
        prefs.selectedCfg = cand.cfg
        prefs.selectedLabel = cand.label

        if (tunFd == null || forceRebuildTun || !TProxyService.TProxyIsRunning()) {
            stopTunLayer()
            if (!startTunLayer()) {
                prefs.wasVpnDesiredActive = false
                teardownInternal("تعذّر إنشاء نفق TUN", null, userInitiated = true)
                stopSelf()
                return
            }
        }

        val now = System.currentTimeMillis()
        val candProto = Converters.protocolBadge(cand.cfg)
        val candEndpoint = Converters.endpointLabel(cand.cfg)
        val curNetCode = netAwareness.snapshot.value.transport.code
        finalizeActiveSessionRow(failureReason = if (previousLabel.isNotBlank()) "انتقال تلقائي إلى ${cand.label}" else "")
        activeHistoryRowId = runCatching {
            clientDb.startSessionRecord(
                cfg = cand.cfg,
                serverLabel = cand.label,
                country = "",
                initialLatencyMs = verifiedPingMs,
                networkType = curNetCode,
                nowMs = now,
            )
        }.getOrDefault(0L)
        runCatching {
            val curProf = ScanNetworkProfile.fromTransportCode(curNetCode)
            clientDb.recordNetworkScanMeasurement(
                cfgOrServerId = cand.cfg,
                networkProfile = curProf,
                scanMode = "LIVE_SESSION",
                success = true,
                establishMs = verifiedPingMs,
                latencyMs = verifiedPingMs,
                stabilityScore = 88.0,
                nowMs = now,
            )
            clientDb.recordServerProbeOrSessionOutcome(
                cfgOrServerId = cand.cfg,
                ok = true,
                latencyMs = verifiedPingMs,
                networkType = curNetCode,
                nowMs = now,
            )
        }
        reconnectManager.onTunnelVerified()
        VpnStateManager.appendEvent("انتقل الاتصال ذكيًا إلى ${cand.label} (${verifiedPingMs} ms)")
        prefs.recordConnection(
            label = cand.label,
            endpoint = candEndpoint,
            proto = candProto,
            pingMs = verifiedPingMs,
        )
        SmartFailoverEngine.recordServerHealthy(Converters.cleanUri(cand.cfg))
        VpnStateManager.markServerHealthy(Converters.cleanUri(cand.cfg))
        val osLockdown = KillSwitchController.isOsLockdownActive(this)
        VpnStateManager.update { prev ->
            prev.copy(
                phase = VpnPhase.CONNECTED,
                activeCfg = cand.cfg,
                activeLabel = cand.label,
                activeProto = candProto,
                activeEndpoint = candEndpoint,
                connectedSinceMs = if (prev.connectedSinceMs > 0L) prev.connectedSinceMs else now,
                livePingMs = verifiedPingMs,
                jitterMs = 0.0,
                packetLossPct = 0.0,
                connectionQuality = if (verifiedPingMs <= 220L) "ممتازة" else "جيدة ومستقرة",
                exitIp = "",
                exitCountry = "",
                failoverMode = prefs.failoverMode,
                switchingStatus = "نجح الانتقال الذكي",
                previousServerLabel = previousLabel.ifBlank { prev.activeLabel },
                targetServerLabel = "",
                lastSuccessfulSwitchAtMs = now,
                failoverCount = prev.failoverCount + 1,
                killSwitchActive = prefs.killSwitch,
                osLockdownActive = osLockdown,
                reconnectAttempt = 0,
                statusMessage = "تم الربط الذكي عبر ${cand.label} (${verifiedPingMs} ms)",
                error = null,
            )
        }
        QuickTileService.requestTileUpdate(applicationContext)
        startMonitorLoop()
        fetchExitTraceAsync()
    }

    /**
     * Phase 4 Kill Switch Hold: عند سقوط جميع السيرفرات وتفعيل Kill Switch، نُبقي واجهة TUN
     * مقفلة في حالة PROTECTION_ACTIVE لمنع تسرب بيانات التطبيقات عبر الشبكة غير المحمية،
     * ونشغّل حلقة استعادة هادئة في الخلفية حتى يعود اتصال موثّق أو يطلب المستخدم الإيقاف.
     */
    /** Set once WARP has been tried as a fallback; cleared when connecting to a regular server. */
    @Volatile
    private var warpFallbackAttempted = false

    private fun handleAllCandidatesFailed(reasonMsg: String) {
        // Free Cloudflare WARP as a last resort before giving up (once per failure chain).
        val activeIsWarp = com.bahrain.vpnconfigs.engine.WarpManager.isWarp(VpnStateManager.status.value.activeCfg)
        if (!warpFallbackAttempted && !activeIsWarp && prefs.wasVpnDesiredActive && prefs.warpFallback &&
            com.bahrain.vpnconfigs.engine.WarpAccount.fromJson(prefs.warpAccountJson) != null
        ) {
            warpFallbackAttempted = true
            VpnStateManager.appendEvent("كل السيرفرات فشلت — تجربة Cloudflare WARP المجاني كاحتياط")
            serviceScope.launch {
                handleConnect(
                    com.bahrain.vpnconfigs.engine.WarpManager.WARP_URI,
                    com.bahrain.vpnconfigs.engine.WarpManager.LABEL,
                    forceRebuildTun = false,
                )
            }
            return
        }
        monitorJob?.cancel()
        probeJob?.cancel()
        traceJob?.cancel()
        singBox.stopDaemon(daemon)
        daemon = null

        finalizeActiveSessionRow(failureReason = reasonMsg)
        val retainTun = KillSwitchController.shouldRetainTunOnFailure(
            appKillSwitchEnabled = prefs.killSwitch,
            userRequestedDisconnect = !prefs.wasVpnDesiredActive,
        )

        if (!retainTun) {
            teardownInternal(
                "تعذّر الاتصال عبر السيرفر المحدد — افحص القائمة لاختيار الأسرع على شبكتك",
                null,
                userInitiated = false,
            )
            stopSelf()
            return
        }

        // تأكد من بقاء واجهة TUN مقفلة لحجب أي تسرب عبر شبكة الهاتف المباشرة
        if (tunFd == null || !TProxyService.TProxyIsRunning()) {
            startTunLayer()
        }

        val osLockdown = KillSwitchController.isOsLockdownActive(this)
        val protHeadline = "تفعيل الحجب الوقائي (Kill Switch) لمنع تسرب البيانات"
        VpnStateManager.appendEvent(protHeadline)
        runCatching {
            clientDb.recordProtectionEvent("KILL_SWITCH_HOLD", protHeadline, reasonMsg)
        }
        VpnStateManager.update { prev ->
            prev.copy(
                phase = VpnPhase.PROTECTION_ACTIVE,
                downSpeedBps = 0L,
                upSpeedBps = 0L,
                livePingMs = -1L,
                connectionQuality = "حجب طوارئ (Kill Switch)",
                switchingStatus = "حماية Kill Switch تحجب التسرب — جدولة تراجع أسي…",
                killSwitchActive = true,
                osLockdownActive = osLockdown,
                lastProtectionEvent = "$protHeadline — $reasonMsg",
                statusMessage = "مفتاح الإيقاف نشط: تم حجب الإنترنت غير المحمي لحين استعادة النفق",
                error = reasonMsg,
            )
        }
        updateNotification("حماية Kill Switch نشطة", "تم حجب التسرب — جارٍ محاولة استعادة النفق…")
        QuickTileService.requestTileUpdate(applicationContext)

        recoveryJob?.cancel()
        recoveryJob = serviceScope.launch {
            while (isActive && VpnStateManager.status.value.phase == VpnPhase.PROTECTION_ACTIVE && prefs.wasVpnDesiredActive) {
                val netSnap = netAwareness.refreshNow()
                if (!netSnap.connected) {
                    VpnStateManager.update {
                        it.copy(switchingStatus = "بانتظار عودة إشارة الشبكة لاستئناف النفق…")
                    }
                    delay(5_000L)
                    continue
                }
                val plan = reconnectManager.nextReconnectPlan(
                    trigger = DisconnectTrigger.TUNNEL_DISCONNECTED,
                    networkAvailable = true,
                )
                if (!plan.shouldRetry) {
                    if (plan.notifyRepeatedFailure) {
                        updateNotification("تنبيه: تعذّر استعادة النفق", plan.statusAr)
                        VpnStateManager.appendEvent(plan.statusAr)
                    }
                    break
                }
                VpnStateManager.update {
                    it.copy(
                        reconnectAttempt = plan.attemptNumber,
                        switchingStatus = plan.statusAr,
                    )
                }
                if (plan.notifyRepeatedFailure) {
                    updateNotification("حماية Kill Switch نشطة", plan.statusAr)
                }
                delay(plan.delayMs)
                if (!reconnectManager.tryAcquireConnectionSlot()) continue
                try {
                    ResourceAndBatteryMonitor.recordReconnectAttempt()
                    opLock.withLock {
                        if (VpnStateManager.status.value.phase == VpnPhase.PROTECTION_ACTIVE && prefs.wasVpnDesiredActive) {
                            val pool = ensureServerPool()
                            val alt = findWorkingAlternativeParallel(excludeCfg = "", pool = pool)
                            if (alt != null) {
                                connectWithVerifiedDaemon(
                                    cand = alt.first,
                                    verifiedDaemon = alt.second,
                                    verifiedPingMs = alt.third,
                                    forceRebuildTun = false,
                                    previousLabel = VpnStateManager.status.value.activeLabel,
                                )
                            }
                        }
                    }
                } finally {
                    reconnectManager.releaseConnectionSlot()
                }
            }
        }
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
                        if (st.isTunnelVerified) {
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

    /**
     * Phase 3 Leak Protection: يلتقط المسارين 0.0.0.0/0 و ::/0 دائمًا داخل واجهة TUN؛
     * وعند تعطيل توجيه IPv6 يتم إسقاط حزم IPv6 داخل النفق لمنع تسربها عبر الشبكة المزدوجة.
     */
    private fun startTunLayer(): Boolean {
        return try {
            val plan = LeakProtectionEngine.buildTunProtectionPlan(
                enableIpv6Tunnel = prefs.enableIpv6,
                rawDnsServer = prefs.dnsServer,
                useDoh = prefs.dnsDoh,
            )

            val activeLanIps = com.bahrain.vpnconfigs.hotspot.VpnHotspotManager
                .detectAllSharingInterfaces()
                .map { it.ipv4Address }
            val ipv4Routes = LeakProtectionEngine.computeIpv4RoutesExcludingLocalLan(activeLanIps)

            val builder = Builder()
                .setSession("bahrain-vpn")
                .setBlocking(false)
                .setMtu(8500)
                .addAddress("198.18.0.1", 32)
                .addDnsServer(plan.mapDnsAddress)

            for (r in ipv4Routes) {
                builder.addRoute(r.address, r.prefixLength)
            }

            if (plan.captureIpv6Route) {
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
            val ipv6Line = if (plan.forwardIpv6Upstream) "\n  ipv6: 'fc00::1'" else ""
            val hevConfig = """
                tunnel:
                  mtu: 8500
                  ipv4: 198.18.0.1$ipv6Line
                socks5:
                  port: ${SingBox.VPN_SOCKS_PORT}
                  address: 127.0.0.1
                  udp: '$udpMode'
                mapdns:
                  address: ${plan.mapDnsAddress}
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
            val guard = EnterpriseLicenseGuard(applicationContext)

            while (isActive && VpnStateManager.status.value.isTunnelVerified) {
                delay(1000L)
                val stats = runCatching { TProxyService.TProxyGetStats() }.getOrNull()
                if (stats != null && stats.size >= 4) {
                    val curUp = stats[1].coerceAtLeast(0L)
                    val curDown = stats[3].coerceAtLeast(0L)
                    val upSpd = (curUp - prevUp).coerceAtLeast(0L)
                    val downSpd = (curDown - prevDown).coerceAtLeast(0L)
                    prevUp = curUp
                    prevDown = curDown

                    if (downSpd > sessionPeakDownBps) sessionPeakDownBps = downSpd
                    if (upSpd > sessionPeakUpBps) sessionPeakUpBps = upSpd
                    guard.recordTrafficDeltaBytes(downSpd, upSpd)

                    VpnStateManager.update { s ->
                        val nextSeries = (s.trafficHistoryBps + (downSpd to upSpd)).takeLast(30)
                        s.copy(
                            upSpeedBps = upSpd,
                            downSpeedBps = downSpd,
                            totalUpBytes = curUp,
                            totalDownBytes = curDown,
                            trafficHistoryBps = nextSeries,
                        )
                    }

                    tick++
                    if (tick % 60 == 0) {
                        runCatching {
                            Repo(applicationContext).fetchEnterpriseBundleRaw()?.let { guard.applySignedBundleRaw(it) }
                        }
                    }
                    if (tick % 5 == 0) {
                        val liveLic = guard.currentState()
                        if (!liveLic.canConnectVpn) {
                            opLock.withLock {
                                prefs.wasVpnDesiredActive = false
                                teardownInternal(liveLic.statusDetailAr.ifBlank { "انتهت صلاحية الجلسة أو الحصة" }, null, userInitiated = true)
                                stopSelf()
                            }
                            return@launch
                        }
                    }
                    // تحديث الإشعار كل 3 ثوانٍ فقط مع إلغاء الاستدعاء إذا لم يتغيّر النص لتوفير البطارية
                    if (tick % 3 == 0) {
                        val st = VpnStateManager.status.value
                        val pingTxt = if (st.livePingMs > 0) " • ${st.livePingMs} ms" else ""
                        val detail = "↓ ${VpnStateManager.formatSpeed(downSpd)}  ↑ ${VpnStateManager.formatSpeed(upSpd)}$pingTxt"
                        val prefix = if (st.phase == VpnPhase.CONNECTION_DEGRADED) {
                            tr("متّصل (تذبذب)", "Connected (Degraded)")
                        } else {
                            tr("متّصل", "Connected")
                        }
                        updateNotification("$prefix (${st.activeLabel})", detail)
                    }
                }
            }
        }

        // Phase 6 & 9: مراقب الجودة الاستباقي ورصد اختناق السرعة والتبديل الذكي التكيّفي
        probeJob = serviceScope.launch {
            val recentPings = ArrayDeque<Long>()
            val recentOutcomes = ArrayDeque<Boolean>()
            var consecutiveHealthy = 0
            var consecutiveTrafficStalls = 0
            val guard = EnterpriseLicenseGuard(applicationContext)

            delay(SmartFailoverEngine.HEALTHY_CHECK_INTERVAL_MS)

            while (isActive && VpnStateManager.status.value.isTunnelVerified) {
                val foMode = FailoverMode.fromKey(prefs.failoverMode)
                val aliveProc = daemon?.process?.isAlive == true
                val primaryProbe = if (aliveProc) {
                    runCatching {
                        Socks.measureRealDelay(SingBox.VPN_SOCKS_PORT, SingBox.TEST_URL, 3200)
                    }.getOrNull()
                } else null
                val primaryOk = primaryProbe != null && primaryProbe.status in listOf(200, 204)

                var secondaryOk = false
                var secondaryElapsed = -1L
                if (aliveProc && !primaryOk) {
                    delay(SmartFailoverEngine.RAPID_CONFIRM_DELAY_MS)
                    val confirmProbe = runCatching {
                        Socks.measureRealDelay(
                            SingBox.VPN_SOCKS_PORT,
                            SmartFailoverEngine.SECONDARY_CONFIRM_URL,
                            2200,
                        )
                    }.getOrNull()
                    if (confirmProbe != null && confirmProbe.status in listOf(200, 204)) {
                        secondaryOk = true
                        secondaryElapsed = confirmProbe.elapsedMs
                    }
                }

                val anyProbeOk = aliveProc && (primaryOk || secondaryOk)
                if (recentOutcomes.size >= 6) recentOutcomes.removeFirst()
                recentOutcomes.addLast(anyProbeOk)

                if (anyProbeOk) {
                    val newPing = if (primaryOk) primaryProbe!!.elapsedMs else secondaryElapsed
                    if (newPing > 0L) {
                        if (recentPings.size >= 5) recentPings.removeFirst()
                        recentPings.addLast(newPing)
                    }

                    val activeClean = Converters.cleanUri(VpnStateManager.status.value.activeCfg ?: "")
                    SmartFailoverEngine.recordServerHealthy(activeClean)
                    VpnStateManager.markServerHealthy(activeClean)

                    val curStatus = VpnStateManager.status.value
                    consecutiveTrafficStalls = if (
                        SmartFailoverEngine.isTrafficSampleStalled(curStatus.upSpeedBps, curStatus.downSpeedBps)
                    ) {
                        consecutiveTrafficStalls + 1
                    } else {
                        0
                    }
                    val bestCandLat = VpnStateManager.serverPool
                        .asSequence()
                        .filter { Converters.cleanUri(it.cfg) != activeClean && it.latencyMs > 0L }
                        .minOfOrNull { it.latencyMs } ?: 0L

                    val health = SmartFailoverEngine.evaluateTunnelHealth(
                        recentSamplesMs = recentPings.toList(),
                        recentOutcomes = recentOutcomes.toList(),
                        mode = foMode,
                        lastSwitchAtMs = curStatus.lastSuccessfulSwitchAtMs.coerceAtLeast(curStatus.connectedSinceMs),
                        bestCandidateLatencyMs = bestCandLat,
                        consecutiveTrafficStalls = consecutiveTrafficStalls,
                    )

                    consecutiveHealthy = if (health.isDegraded) 0 else (consecutiveHealthy + 1)

                    runCatching {
                        val stNow = VpnStateManager.status.value
                        clientDb.recordServerProbeOrSessionOutcome(
                            cfgOrServerId = activeClean,
                            ok = true,
                            latencyMs = newPing.coerceAtLeast(0L),
                            jitterMs = health.jitterMs,
                            packetLossPct = health.packetLossPct,
                            downloadKbps = stNow.downSpeedBps.toDouble() / 1024.0,
                            uploadKbps = stNow.upSpeedBps.toDouble() / 1024.0,
                            networkType = netAwareness.snapshot.value.transport.code,
                        )
                    }

                    VpnStateManager.update { s ->
                        s.copy(
                            phase = if (health.isDegraded) VpnPhase.CONNECTION_DEGRADED else VpnPhase.CONNECTED,
                            livePingMs = if (newPing > 0L) newPing else s.livePingMs,
                            jitterMs = health.jitterMs,
                            packetLossPct = health.packetLossPct,
                            connectionQuality = health.qualityLabelAr,
                            failoverMode = foMode.key,
                            switchingStatus = if (health.isDegraded) "رُصد ضعف في الاتصال" else "متّصل ومستقر",
                        )
                    }

                    val remoteAutoFailover = guard.getRemoteConfig().optBoolean("auto_failover_enabled", true)
                    if (health.shouldProactiveSwitch && remoteAutoFailover) {
                        val curAvgPing = recentPings.filter { it > 0L }.let { if (it.isNotEmpty()) it.average() else 0.0 }
                        val stallsNow = consecutiveTrafficStalls
                        val switched = opLock.withLock {
                            if (!VpnStateManager.status.value.isTunnelVerified) {
                                false
                            } else {
                                val pool = ensureServerPool()
                                val curCfg = VpnStateManager.status.value.activeCfg ?: ""
                                val prevLbl = VpnStateManager.status.value.activeLabel
                                VpnStateManager.update { s ->
                                    s.copy(
                                        phase = VpnPhase.SWITCHING_SERVER,
                                        switchingStatus = "سباق متوازٍ لاختيار بديل أسرع بالخلفية…",
                                        statusMessage = health.reasonAr.ifBlank { "جارٍ الانتقال السلس لسيرفر أفضل…" },
                                    )
                                }
                                // فحص أفضل 4 بدائل بالتوازي دون إيقاف النفق الحالي، ولا ننتقل إلا إذا ثبت أن البديل أسرع فعليًا!
                                val alt = probeVerifiedCandidateWithoutStoppingCurrent(
                                    excludeCfg = curCfg,
                                    pool = pool,
                                    currentAvgLatencyMs = curAvgPing,
                                    consecutiveTrafficStalls = stallsNow,
                                    isHardDrop = false,
                                )
                                if (alt != null) {
                                    consecutiveTrafficStalls = 0
                                    AppHealthMonitor.recordIssue(
                                        applicationContext,
                                        type = "PROACTIVE_FAILOVER",
                                        summary = "Proactively switched to ${alt.first.label} (${alt.second} ms)",
                                    )
                                    singBox.stopDaemon(daemon)
                                    daemon = null
                                    val physicalDns = netAwareness.snapshot.value.systemDnsServers.firstOrNull()
                                    val started = singBox.startDaemon(
                                        cfg = alt.first.cfg,
                                        port = SingBox.VPN_SOCKS_PORT,
                                        dnsServer = prefs.dnsServer,
                                        useDoh = prefs.dnsDoh,
                                        tag = "vpn",
                                        enableIpv6 = prefs.enableIpv6,
                                        bypassIrDomains = prefs.bypassIrDomains,
                                        physicalDnsServer = physicalDns,
                                    )
                                    if (started != null) {
                                        connectWithVerifiedDaemon(
                                            cand = alt.first,
                                            verifiedDaemon = started,
                                            verifiedPingMs = alt.second,
                                            forceRebuildTun = false,
                                            previousLabel = prevLbl,
                                        )
                                        true
                                    } else {
                                        false
                                    }
                                } else {
                                    // لا يوجد بديل أسرع فعليًا الآن (قد يكون ضعف التغطية من الشبكة المحلية) — أبقِ النفق الحالي دون تقطيع
                                    VpnStateManager.update { s ->
                                        s.copy(
                                            phase = VpnPhase.CONNECTION_DEGRADED,
                                            switchingStatus = "الإبقاء على النفق الحالي (لا يوجد بديل أسرع فعليًا)",
                                        )
                                    }
                                    false
                                }
                            }
                        }
                        if (switched) return@launch
                    }

                    val nextInterval = ResourceAndBatteryMonitor.computeBatteryAwareProbeIntervalMs(
                        consecutiveHealthyProbes = consecutiveHealthy,
                        isDegraded = health.isDegraded,
                        isMeteredNetwork = netAwareness.snapshot.value.isMetered,
                    )
                    ResourceAndBatteryMonitor.recordBackgroundProbe(nextInterval)
                    delay(nextInterval)
                } else {
                    consecutiveHealthy = 0
                    consecutiveTrafficStalls = 0
                    val droppedCur = VpnStateManager.status.value.activeCfg ?: ""
                    val prevLbl = VpnStateManager.status.value.activeLabel
                    if (droppedCur.isNotBlank()) {
                        val cleanDropped = Converters.cleanUri(droppedCur)
                        SmartFailoverEngine.recordServerDrop(cleanDropped)
                        VpnStateManager.markServerDropped(cleanDropped)
                    }
                    val remoteAutoFailover = guard.getRemoteConfig().optBoolean("auto_failover_enabled", true)
                    if (foMode != FailoverMode.OFF && remoteAutoFailover) {
                        val switched = opLock.withLock {
                            if (!VpnStateManager.status.value.isTunnelVerified) {
                                false
                            } else {
                                val pool = ensureServerPool()
                                val curCfg = VpnStateManager.status.value.activeCfg ?: ""
                                VpnStateManager.update { s ->
                                    s.copy(
                                        phase = VpnPhase.SWITCHING_SERVER,
                                        switchingStatus = "انقطع السيرفر — جارٍ التبديل الفوري…",
                                        statusMessage = "انقطع السيرفر الحالي — جارٍ الانتقال الذكي لأسرع بديل…",
                                    )
                                }
                                val alt = findWorkingAlternativeParallel(curCfg, pool)
                                if (alt != null) {
                                    AppHealthMonitor.recordIssue(
                                        applicationContext,
                                        type = "AUTO_FAILOVER",
                                        summary = "Switched to ${alt.first.label} (${alt.third} ms)",
                                    )
                                    connectWithVerifiedDaemon(
                                        cand = alt.first,
                                        verifiedDaemon = alt.second,
                                        verifiedPingMs = alt.third,
                                        forceRebuildTun = false,
                                        previousLabel = prevLbl,
                                    )
                                    true
                                } else {
                                    handleAllCandidatesFailed("انقطع السيرفر الحالي وتعذّر الوصول للبدائل")
                                    true
                                }
                            }
                        }
                        if (switched) return@launch
                    } else {
                        opLock.withLock {
                            handleAllCandidatesFailed("انقطع الاتصال بالسيرفر الحالي (التبديل التلقائي متوقف)")
                        }
                        return@launch
                    }
                }
            }
        }
    }

    /**
     * سباق Happy Eyeballs متوازٍ لدفعة من السيرفرات (حتى 4 سيرفرات معًا على منافذ 20910..20913)
     * يعيد أول سيرفر يستجيب فعليًا بأسرع زمن دون انتظار انتهاء مهلة السيرفرات الميتة،
     * ودون إيقاف نفق الـ VPN النشط على المنفذ 20808.
     */
    private suspend fun raceParallelCandidateBatch(
        candidates: List<ServerCandidate>,
        preferFirstGraceMs: Long = 0L,
        timeoutMs: Int = 2_400,
    ): Pair<ServerCandidate, Long>? = kotlinx.coroutines.withContext(Dispatchers.IO) {
        if (candidates.isEmpty() || !singBox.isAvailable) return@withContext null
        val curProf = ScanNetworkProfile.fromTransportCode(netAwareness.snapshot.value.transport.code)
        val batchPortItems = candidates.take(SmartFailoverEngine.PARALLEL_RACE_BATCH_SIZE)
            .mapIndexed { idx, cand -> cand.cfg to (20910 + idx) }
        val session = singBox.startBatchDaemon(
            items = batchPortItems,
            dnsServer = prefs.dnsServer,
            useDoh = prefs.dnsDoh,
            waitMs = 950L,
        ) ?: return@withContext null

        val candByPort = HashMap<Int, Pair<Int, ServerCandidate>>()
        candidates.take(SmartFailoverEngine.PARALLEL_RACE_BATCH_SIZE).forEachIndexed { idx, cand ->
            candByPort[20910 + idx] = idx to cand
        }

        try {
            val winnerDeferred = CompletableDeferred<Pair<ServerCandidate, Long>?>()
            val primaryAliveFlag = java.util.concurrent.atomic.AtomicBoolean(false)
            coroutineScope {
                val jobs = session.slots.mapNotNull { slot ->
                    val (origIdx, cand) = candByPort[slot.listenPort] ?: return@mapNotNull null
                    launch {
                        val probe = runCatching {
                            Socks.measureRealDelay(slot.listenPort, SingBox.TEST_URL, timeoutMs)
                        }.getOrNull()
                        val clean = Converters.cleanUri(cand.cfg)
                        val ok = probe != null && probe.status in listOf(200, 204) && probe.elapsedMs > 0L
                        if (ok) {
                            val pingMs = probe!!.elapsedMs
                            if (origIdx == 0) primaryAliveFlag.set(true)
                            VpnStateManager.markServerHealthy(clean)
                            runCatching {
                                clientDb.recordNetworkScanMeasurement(
                                    cfgOrServerId = clean,
                                    networkProfile = curProf,
                                    scanMode = "RACE_PROBE",
                                    success = true,
                                    establishMs = pingMs,
                                    latencyMs = pingMs,
                                    jitterMs = 0.0,
                                    packetLossPct = 0.0,
                                    stabilityScore = 88.0,
                                )
                            }
                            if (origIdx > 0 && preferFirstGraceMs > 0L && !primaryAliveFlag.get()) {
                                delay(preferFirstGraceMs)
                            }
                            winnerDeferred.complete(cand to pingMs)
                        } else {
                            VpnStateManager.markServerDropped(clean)
                        }
                    }
                }
                val monitorAllDone = launch {
                    jobs.forEach { it.join() }
                    winnerDeferred.complete(null)
                }
                val picked = winnerDeferred.await()
                jobs.forEach { it.cancel() }
                monitorAllDone.cancel()
                picked
            }
        } finally {
            singBox.stopBatchDaemon(session)
        }
    }

    /**
     * يختبر دفعات من 4 سيرفرات بديلة بالتوازي دون قطع النفق الحالي،
     * وفي التبديل الاستباقي لا يقبل البديل إلا إذا ثبت تفوّقه الفعلي عبر isReplacementWorthSwitching.
     */
    private suspend fun probeVerifiedCandidateWithoutStoppingCurrent(
        excludeCfg: String,
        pool: List<ServerCandidate>,
        currentAvgLatencyMs: Double = 0.0,
        consecutiveTrafficStalls: Int = 0,
        isHardDrop: Boolean = true,
    ): Pair<ServerCandidate, Long>? {
        val maxCheck = if (isHardDrop) 8 else SmartFailoverEngine.PARALLEL_RACE_BATCH_SIZE
        val candidates = SmartFailoverEngine.rankFailoverCandidates(
            excludeCfg = excludeCfg,
            pool = pool,
            maxCandidates = maxCheck,
        )
        if (candidates.isEmpty()) return null

        for (chunk in candidates.chunked(SmartFailoverEngine.PARALLEL_RACE_BATCH_SIZE)) {
            val winner = raceParallelCandidateBatch(
                candidates = chunk,
                preferFirstGraceMs = 45L,
                timeoutMs = if (isHardDrop) 2_600 else 2_100,
            )
            if (winner != null &&
                SmartFailoverEngine.isReplacementWorthSwitching(
                    currentAvgLatencyMs = currentAvgLatencyMs,
                    candidateLatencyMs = winner.second,
                    consecutiveTrafficStalls = consecutiveTrafficStalls,
                    isHardDrop = isHardDrop,
                )
            ) {
                return winner
            }
        }
        return null
    }

    /**
     * يختبر دفعات من 4 سيرفرات بالتوازي مرتبةً عبر SmartFailoverEngine
     * للانتقال الفوري عند انقطاع السيرفر دون هدم واجهة TUN (تبقى واجهة TUN مقفلة طوال العملية).
     */
    private suspend fun findWorkingAlternativeParallel(
        excludeCfg: String,
        pool: List<ServerCandidate>,
    ): Triple<ServerCandidate, RunningDaemon, Long>? {
        val winner = probeVerifiedCandidateWithoutStoppingCurrent(
            excludeCfg = excludeCfg,
            pool = pool,
            isHardDrop = true,
        )
        if (winner != null) {
            singBox.stopDaemon(daemon)
            daemon = null
            val physicalDns = netAwareness.snapshot.value.systemDnsServers.firstOrNull()
            val started = singBox.startDaemon(
                cfg = winner.first.cfg,
                port = SingBox.VPN_SOCKS_PORT,
                dnsServer = prefs.dnsServer,
                useDoh = prefs.dnsDoh,
                tag = "vpn",
                enableIpv6 = prefs.enableIpv6,
                bypassIrDomains = prefs.bypassIrDomains,
                physicalDnsServer = physicalDns,
            )
            if (started != null) {
                return Triple(winner.first, started, winner.second)
            }
        }
        return null
    }

    private fun ensureServerPool(): List<ServerCandidate> {
        val current = VpnStateManager.serverPool
        if (current.isNotEmpty()) return current

        val repo = Repo(applicationContext)
        val curProf = ScanNetworkProfile.fromTransportCode(netAwareness.snapshot.value.transport.code)
        val vipNodes = EnterpriseLicenseGuard(applicationContext).getAuthorizedVipNodes()
        val vipByClean = vipNodes.associateBy { Converters.cleanUri(it.uri) }
        val savedBestResults = repo.loadSavedResultsForProfile(curProf).ifEmpty { repo.loadSavedBest() }
        val bestByClean = savedBestResults.associateBy { Converters.cleanUri(it.cfg) }
        val netStatsById = clientDb.getNetworkStatsMap(curProf)
        val savedBest = savedBestResults.sortedWith(
            compareByDescending<com.bahrain.vpnconfigs.engine.TestResult> { it.speedKbps > 0.0 }
                .thenByDescending { it.speedKbps }
                .thenBy { if (it.latencyMs > 0L) it.latencyMs else Long.MAX_VALUE }
        ).map { it.cfg }
        val cached = repo.loadCached(prefs.feedProfile)
        val hints = cached?.serverHints ?: emptyMap()
        val cachedAll = (cached?.configs ?: emptyList())
        val purgedIds = repo.getActivePurgedDeadServerIds(curProf)
        val favSet = prefs.favorites.map { Converters.cleanUri(it) }.toHashSet()
        val favIds = clientDb.favoriteServerIds()
        val personalRanks = clientDb.getPersonalizedRankings(curProf)
        val cfgById = HashMap<String, String>()
        (savedBest + cachedAll).forEach { raw ->
            val cl = Converters.cleanUri(raw)
            val sid = Converters.stableServerId(cl)
            if (sid.isNotBlank() && !cfgById.containsKey(sid)) cfgById[sid] = cl
        }
        val personalOrderedCfgs = personalRanks.mapNotNull { cfgById[it.serverId] }
        val vipUris = vipNodes.map { Converters.cleanUri(it.uri) }
        val merged = (vipUris + prefs.customConfigs + personalOrderedCfgs + savedBest + cachedAll)
            .distinct()
            .filter { Converters.isSupported(it) }
        val built = merged.mapIndexedNotNull { idx, cfg ->
            val clean = Converters.cleanUri(cfg)
            val vip = vipByClean[clean]
            val sid = Converters.stableServerId(clean)
            val isProtected = vip != null || clean in favSet || sid in favIds
            if (!isProtected && sid in purgedIds) return@mapIndexedNotNull null
            val hint = hints[clean]
            val sec = SecurityEvaluator.evaluate(
                rawCfg = clean,
                isVipAttested = vip != null,
                hintSecurity = hint?.securityAssessment.orEmpty(),
                hintPrivacy = hint?.privacyAssessment.orEmpty(),
                hintRisk = hint?.riskLevel.orEmpty(),
            )
            if (sec.quarantined || sec.allowInsecure) return@mapIndexedNotNull null
            val localRes = bestByClean[clean]
            val netStat = netStatsById[sid]
            val effSpeed = localRes?.speedKbps?.takeIf { it > 0.0 } ?: (netStat?.latestThroughputKbps ?: 0.0)
            val effLat = localRes?.latencyMs?.takeIf { it > 0L }
                ?: netStat?.latestLatencyMs?.takeIf { it > 0L }
                ?: (hint?.latencyMs ?: 0L)
            ServerCandidate(
                cfg = cfg,
                label = if (vip != null) "💎 VIP • ${vip.label}" else "bahrain-vpn #${idx + 1}",
                speedKbps = effSpeed,
                latencyMs = effLat,
                isVip = vip != null,
                securityAssessment = sec.securityAssessment,
                riskLevel = sec.riskLevel,
            )
        }
        VpnStateManager.serverPool = built
        return built
    }

    private fun ConvergedKey(uri: String): String = Converters.cleanUri(uri)

    private fun teardownInternal(errorMsg: String?, infoMsg: String?, userInitiated: Boolean = true) {
        finalizeActiveSessionRow(failureReason = errorMsg ?: "")
        monitorJob?.cancel()
        probeJob?.cancel()
        recoveryJob?.cancel()
        traceJob?.cancel()
        singBox.stopDaemon(daemon)
        daemon = null
        stopTunLayer()
        lastNotifSignature = ""
        val cleanErr = if (userInitiated) null else errorMsg?.let { UiMessages.sanitizeError(it, UiMessages.MSG_SERVER_UNREACHABLE) }
        val finalErr = errorMsg?.takeIf { userInitiated && infoMsg == null }?.let { UiMessages.sanitizeError(it, UiMessages.MSG_SERVER_UNREACHABLE) } ?: cleanErr
        VpnStateManager.resetDisconnected(errorMsg = finalErr, infoMsg = infoMsg)
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
        com.bahrain.vpnconfigs.hotspot.VpnHotspotManager.stopHotspotSharing(
            reasonAr = "توقفت مشاركة الهوتسبوت تلقائيًا عند إنهاء خدمة الـ VPN",
            reasonEn = "VPN Hotspot stopped automatically on VPN service teardown",
        )
        unregisterPhysicalNetworkWatcher()
        teardownInternal(null, null, userInitiated = true)
        serviceScope.cancel()
        super.onDestroy()
    }

    // ─────────────────── الإشعارات الموفّرة للطاقة ───────────────────
    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            val ch = NotificationChannel(
                CHANNEL_ID,
                tr("اتصال bahrain-vpn", "bahrain-vpn Tunnel"),
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = tr(
                    "يعرض حالة اتصال الـ VPN ومفتاح الإيقاف والسرعة الحيّة",
                    "Shows VPN tunnel state, Kill Switch status, and live speed",
                )
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
        val sig = "$titleSuffix|$body"
        if (sig == lastNotifSignature) return
        lastNotifSignature = sig
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
            .setContentText(body.ifBlank { tr("اضغط لفتح لوحة التحكم", "Tap to open control panel") })
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setContentIntent(openAppIntent)
            .addAction(0, tr("السيرفر التالي", "Next Server"), nextIntent)
            .addAction(0, tr("قطع الاتصال", "Disconnect"), stopIntent)
            .build()
    }
}
