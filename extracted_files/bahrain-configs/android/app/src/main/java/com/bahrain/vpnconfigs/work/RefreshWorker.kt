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
        val owner = prefs.owner.ifBlank { "OWNER" }
        val repo = prefs.repo.ifBlank { "REPO" }
        if (owner == "OWNER" || repo == "REPO") return Result.success()

        val res = Repo(applicationContext, owner, repo).loadRemote()
        return if (res.configs.isEmpty()) Result.retry() else Result.success()
    }
}
