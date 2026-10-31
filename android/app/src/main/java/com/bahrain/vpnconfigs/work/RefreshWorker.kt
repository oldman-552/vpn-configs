// =====================================================================
// RefreshWorker.kt — العامل الدوري الموحّد كل 3 ساعات لفحص جودة السيرفرات:
//   • يحترم خيار الإعدادات Automatic Server Quality Testing والبطارية (>= 25%).
//   • يتخطى الفحص الثقيل فورًا إذا كان الـ VPN أو الـ VPN Hotspot نشطًا لعدم إزعاج التصفح.
//   • يحدّث حزمة الـ Top 500، يشغّل الفحص الدفعي مع قياس سرعة 600 KB لأفضل 15 سيرفر فقط (~9 MB)،
//     يخزّن النتائج معزولة بين WIFI و MOBILE_DATA، يحذف الميت فورًا (مع Offline Guard)،
//     ويزامن تقارير المجتمع Zero-PII من نفس القياسات دون إعادة فحص مزدوج.
// =====================================================================
package com.bahrain.vpnconfigs.work

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.bahrain.vpnconfigs.community.CommunityTestingManager
import com.bahrain.vpnconfigs.data.ClientDatabase
import com.bahrain.vpnconfigs.data.DeadConfigPurgePolicy
import com.bahrain.vpnconfigs.data.Prefs
import com.bahrain.vpnconfigs.data.Repo
import com.bahrain.vpnconfigs.data.ResultLine
import com.bahrain.vpnconfigs.data.ScanNetworkProfile
import com.bahrain.vpnconfigs.engine.Converters
import com.bahrain.vpnconfigs.engine.LocalScanMode
import com.bahrain.vpnconfigs.engine.PersonalizedTop50Ranker
import com.bahrain.vpnconfigs.engine.SequentialTunnelScanner
import com.bahrain.vpnconfigs.engine.ServerSortMode
import com.bahrain.vpnconfigs.enterprise.EnterpriseLicenseGuard
import com.bahrain.vpnconfigs.hotspot.VpnHotspotManager
import com.bahrain.vpnconfigs.vpn.NetworkAwarenessMonitor
import com.bahrain.vpnconfigs.vpn.VpnStateManager

class RefreshWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {

    override suspend fun doWork(): Result {
        val appCtx = applicationContext
        val prefs = Prefs(appCtx)
        if (!prefs.autoServerQualityTesting || !prefs.autoRefresh) {
            WorkScheduler.cancel(appCtx)
            return Result.success()
        }

        // Never run heavy background benchmarks while the user's VPN or VPN Hotspot is actively serving traffic
        if (VpnStateManager.status.value.isActive || VpnHotspotManager.state.value.isSharingActive) {
            return Result.success()
        }
        if (!WorkScheduler.isBatteryAboveThreshold(appCtx)) {
            return Result.retry()
        }

        val netMonitor = NetworkAwarenessMonitor(appCtx)
        val netSnap = netMonitor.refreshNow()
        if (!netSnap.connected) {
            return Result.retry()
        }
        val netProfile = ScanNetworkProfile.fromTransportCode(netSnap.transport.code)
        val isMetered = netSnap.isMetered || netProfile == ScanNetworkProfile.MOBILE_DATA

        val repo = Repo(appCtx)
        val res = repo.loadRemote(prefs.feedProfile)
        if (res.configs.isEmpty() || res.fromCacheFallback || res.error != null) {
            return Result.retry()
        }
        prefs.lastRefreshWallMs = System.currentTimeMillis()
        repo.clearPurgedDeadForProfile(netProfile)

        val scanner = SequentialTunnelScanner(appCtx)
        if (!scanner.engineAvailable) {
            runCatching { repo.writeAll(res.configs) }
            return Result.success()
        }

        val clientDb = ClientDatabase.getInstance(appCtx)
        val licenseGuard = EnterpriseLicenseGuard(appCtx)
        val vipClean = licenseGuard.getAuthorizedVipNodes().map { Converters.cleanUri(it.uri) }.toHashSet()
        val favClean = prefs.favorites.map { Converters.cleanUri(it) }.toHashSet()
        val favIds = clientDb.favoriteServerIds()
        val pool = (vipClean + prefs.customConfigs + res.configs).distinct()

        val summary = runCatching {
            scanner.executeScan(
                scanMode = LocalScanMode.FULL_SCAN,
                allCandidateConfigs = pool,
                fingerprintsById = res.serverFingerprints,
                networkProfile = netProfile,
                isMetered = isMetered,
                timeoutSec = prefs.timeoutSec,
                dnsServer = prefs.dnsServer,
                useDoh = prefs.dnsDoh,
                isBackgroundRun = true,
                skipFreshWithinTtl = true,
            )
        }.getOrNull() ?: return Result.success()

        if (!summary.offlineGuardTriggered) {
            val purgeDecision = DeadConfigPurgePolicy.evaluate(
                currentPool = res.configs,
                failedUris = summary.failedCleanUris,
                testedCount = summary.testedCount,
                aliveCount = summary.results.size,
                deviceOnline = netMonitor.refreshNow().connected,
                favoriteCleanUris = favClean,
                favoriteServerIds = favIds,
                vipCleanUris = vipClean,
            )
            if (purgeDecision.shouldPurge) {
                if (prefs.customConfigs.isNotEmpty()) {
                    prefs.customConfigs = prefs.customConfigs.filterNot {
                        Converters.cleanUri(it) in purgeDecision.purgeableCleanUris
                    }
                }
                repo.recordPurgedDeadAndCleanFiles(
                    profile = netProfile,
                    purgeableCleanUris = purgeDecision.purgeableCleanUris,
                    remainingPool = purgeDecision.remainingPool,
                    bestLimit = minOf(prefs.bestN, PersonalizedTop50Ranker.PERSONALIZED_TOP_LIMIT),
                )
            } else {
                runCatching { repo.writeAll(res.configs) }
            }

            if (summary.results.isNotEmpty()) {
                val top100Ids = summary.rankingBundle.top100.map { it.serverId }.toHashSet()
                val exportAlive = summary.results
                    .filter {
                        val c = Converters.cleanUri(it.cfg)
                        c !in vipClean && (top100Ids.isEmpty() || Converters.stableServerId(c) in top100Ids)
                    }
                    .sortedWith(
                        compareByDescending<com.bahrain.vpnconfigs.engine.TestResult> { it.speedKbps }
                            .thenByDescending { it.stabilityScore }
                            .thenBy { it.latencyMs }
                            .thenBy { it.jitterMs }
                    )
                if (exportAlive.isNotEmpty()) {
                    prefs.sortMode = ServerSortMode.FASTEST_DOWNLOAD.key
                    prefs.rankBySpeed = true
                    runCatching {
                        repo.writeBest(
                            exportAlive.map { ResultLine(it.cfg, it.latencyMs, it.speedKbps, it.testedAtMs) },
                            minOf(prefs.bestN, PersonalizedTop50Ranker.PERSONALIZED_TOP_LIMIT),
                        )
                    }
                }
            }

            // Unified Zero-PII community telemetry sync from the same scan (zero duplicate background probes!)
            runCatching {
                CommunityTestingManager.syncFromUnifiedQualityScanIfOptedIn(
                    ctx = appCtx,
                    aliveResults = summary.results,
                )
            }
        }

        return Result.success()
    }
}
