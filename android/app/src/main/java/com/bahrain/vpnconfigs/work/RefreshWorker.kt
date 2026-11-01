// =====================================================================
// RefreshWorker.kt — العامل الدوري الموحّد كل ساعة لتحديث وفحص جودة السيرفرات مباشرةً وحفظها في القوائم:
//   • يحترم خيار الإعدادات Automatic Server Quality Testing والبطارية (>= 25%).
//   • يتخطى الفحص الثقيل فورًا إذا كان الـ VPN أو الـ VPN Hotspot نشطًا لعدم إزعاج التصفح.
//   • يحدّث حزمة الـ Top 500 من GitHub (مع العودة للكاش المحلي الموثّق عند تعذّر الوصول المؤقت)،
//     يشغّل الفحص الدفعي مع قياس سرعة 600 KB لأفضل 25 سيرفر، ويحفظ كافة النتائج في قوائم التطبيق:
//     SQLite + local_results_<profile>.json + bahrain-vpn-best.txt + bahrain-vpn-sub.txt
//     مع عزل WIFI عن MOBILE_DATA وحذف الميت فورًا (مع Offline Guard) ومزامنة تقارير المجتمع.
// =====================================================================
package com.bahrain.vpnconfigs.work

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.bahrain.vpnconfigs.data.Prefs
import com.bahrain.vpnconfigs.data.Repo
import com.bahrain.vpnconfigs.data.ScanNetworkProfile
import com.bahrain.vpnconfigs.engine.ScanRuntimeCoordinator
import com.bahrain.vpnconfigs.engine.SequentialTunnelScanner
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
        val livePoolOk = res.configs.isNotEmpty() && !res.fromCacheFallback && res.error == null
        val cachedFallback = if (!livePoolOk) repo.loadCached(prefs.feedProfile) else null
        val resolvedConfigs = if (res.configs.isNotEmpty()) res.configs else cachedFallback?.configs.orEmpty()
        val resolvedFingerprints = if (res.serverFingerprints.isNotEmpty()) {
            res.serverFingerprints
        } else {
            cachedFallback?.serverFingerprints.orEmpty()
        }

        if (resolvedConfigs.isEmpty()) {
            return Result.retry()
        }
        if (livePoolOk) {
            prefs.lastRefreshWallMs = System.currentTimeMillis()
            repo.clearPurgedDeadForProfile(netProfile)
        }

        val scanner = SequentialTunnelScanner(appCtx)
        if (!scanner.engineAvailable) {
            runCatching { repo.writeAll(resolvedConfigs) }
            return Result.success()
        }

        val ok = ScanRuntimeCoordinator.executeScheduledHourlyScan(
            ctx = appCtx,
            baseConfigs = resolvedConfigs,
            fingerprintsById = resolvedFingerprints,
            scanProfile = netProfile,
            isMetered = isMetered,
            customScanner = scanner,
        )
        return if (ok) Result.success() else Result.retry()
    }
}
