// =====================================================================
// RefreshWorker.kt — تحديث دوري تلقائي لقائمة السيرفرات في الخلفية
// مع إعادة المحاولة التلقائية عند تعذّر الاتصال بالإنترنت.
// =====================================================================
package com.bahrain.vpnconfigs.work

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.bahrain.vpnconfigs.data.Prefs
import com.bahrain.vpnconfigs.data.Repo

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
        return Result.success()
    }
}
