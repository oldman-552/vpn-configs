// =====================================================================
// RefreshWorker.kt — تحديث دوري تلقائي لقائمة السيرفرات في الخلفية
// مع اختبار مباشر للاتصال والسرعة وترتيب الأسرع جاهزًا للمستخدم.
// =====================================================================
package com.bahrain.vpnconfigs.work

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.bahrain.vpnconfigs.data.Prefs
import com.bahrain.vpnconfigs.data.Repo
import com.bahrain.vpnconfigs.data.ResultLine
import com.bahrain.vpnconfigs.engine.Converters
import com.bahrain.vpnconfigs.engine.ServerSortMode
import com.bahrain.vpnconfigs.engine.Tester

class RefreshWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {

    override suspend fun doWork(): Result {
        val prefs = Prefs(applicationContext)
        if (!prefs.autoRefresh) return Result.success()

        val repo = Repo(applicationContext)
        val res = repo.loadRemote(prefs.feedProfile)
        if (res.configs.isEmpty() || res.fromCacheFallback || res.error != null) {
            return Result.retry()
        }
        prefs.lastRefreshWallMs = System.currentTimeMillis()
        runCatching { repo.writeAll(res.configs) }

        val tester = Tester(applicationContext)
        if (tester.engineAvailable) {
            runCatching {
                val pool = (prefs.customConfigs + res.configs).distinct()
                val tested = tester.run(
                    configs = pool,
                    testTop = minOf(prefs.testTop, 60),
                    speedTop = minOf(maxOf(prefs.speedTop, 10), 15),
                    concurrency = minOf(prefs.concurrency, 6),
                    timeoutSec = prefs.timeoutSec,
                    rankBySpeed = true,
                    dnsServer = prefs.dnsServer,
                    useDoh = prefs.dnsDoh,
                )
                if (tested.isNotEmpty()) {
                    val testedSet = tested.map { Converters.cleanUri(it.cfg) }.toHashSet()
                    val keptOld = repo.loadSavedBest().filterNot { Converters.cleanUri(it.cfg) in testedSet }
                    val combined = (tested + keptOld).sortedWith(
                        compareByDescending<com.bahrain.vpnconfigs.engine.TestResult> { it.speedKbps > 0.0 }
                            .thenByDescending { it.speedKbps }
                            .thenBy { if (it.latencyMs > 0L) it.latencyMs else Long.MAX_VALUE }
                    )
                    prefs.sortMode = ServerSortMode.FASTEST_DOWNLOAD.key
                    prefs.rankBySpeed = true
                    repo.writeBest(
                        combined.map { ResultLine(it.cfg, it.latencyMs, it.speedKbps, it.testedAtMs) },
                        prefs.bestN,
                    )
                }
            }
        }

        return Result.success()
    }
}
