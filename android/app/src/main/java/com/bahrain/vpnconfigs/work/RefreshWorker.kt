// =====================================================================
// RefreshWorker.kt — تحديث دوري للقائمة الحيّة فقط (بلا فحص، توفيرًا للبطارية).
// الفحص الحقيقي يبقى بزر يدوي لأن نتائجه تعتمد على شبكتك لحظة التشغيل.
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

        val owner = prefs.owner.ifBlank { Repo.DEFAULT_OWNER }
        val repoName = prefs.repo.ifBlank { Repo.DEFAULT_REPO }
        val repo = Repo(applicationContext, owner, repoName)

        val res = repo.loadRemote()
        if (res.configs.isEmpty()) return Result.retry()
        runCatching { repo.writeAll(res.configs) }
        return Result.success()
    }
}
