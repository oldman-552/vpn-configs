// =====================================================================
// WorkScheduler.kt — المنظّم المركزي الموحّد للفحص والتحديث الخلفي (كل ساعة):
//   • يوحّد الجدولة في UniquePeriodicWork ساعي واحد (1 HOUR) ويلغي الجدولات القديمة.
//   • يشترط توفر اتصال بالشبكة (NetworkType.CONNECTED) وعدم انخفاض البطارية.
//   • يحترم خيار المستخدم في الإعدادات (Automatic Server Quality Testing) فورًا:
//     عند الإيقاف يُلغي العمل الدوري مع الاحتفاظ بكافة النتائج المحفوظة للاتصال اللحظي.
// =====================================================================
package com.bahrain.vpnconfigs.work

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequest
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.bahrain.vpnconfigs.data.Prefs
import com.bahrain.vpnconfigs.engine.CentralScoringWeights
import java.util.concurrent.TimeUnit

object WorkScheduler {

    const val UNIQUE_WORK_NAME = "bahrain_vpn_quality_refresh_1h"
    const val LEGACY_WORK_NAME = "refresh"
    const val LEGACY_3H_WORK_NAME = "bahrain_vpn_quality_refresh_3h"
    const val LEGACY_4H_WORK_NAME = "bahrain_vpn_quality_refresh_4h"
    const val PERIOD_HOURS: Long = CentralScoringWeights.REFRESH_INTERVAL_HOURS // 1 HOUR
    const val MIN_BATTERY_PCT: Int = 25

    fun buildConstraints(): Constraints =
        Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .setRequiresBatteryNotLow(true)
            .build()

    fun buildPeriodicRequest(): PeriodicWorkRequest =
        PeriodicWorkRequestBuilder<RefreshWorker>(PERIOD_HOURS, TimeUnit.HOURS)
            .setConstraints(buildConstraints())
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 15, TimeUnit.MINUTES)
            .addTag(UNIQUE_WORK_NAME)
            .build()

    /** يزامن حالة العمل الدوري كل ساعة وفق تفضيل المستخدم ويزيل أي أعمال قديمة مكررة (3 ساعات أو 4 ساعات). */
    fun syncSchedule(ctx: Context) {
        val appCtx = ctx.applicationContext
        val prefs = Prefs(appCtx)
        val wm = WorkManager.getInstance(appCtx)
        wm.cancelUniqueWork(LEGACY_WORK_NAME)
        wm.cancelUniqueWork(LEGACY_3H_WORK_NAME)
        wm.cancelUniqueWork(LEGACY_4H_WORK_NAME)

        if (prefs.autoServerQualityTesting && prefs.autoRefresh) {
            wm.enqueueUniquePeriodicWork(
                UNIQUE_WORK_NAME,
                ExistingPeriodicWorkPolicy.UPDATE,
                buildPeriodicRequest(),
            )
        } else {
            wm.cancelUniqueWork(UNIQUE_WORK_NAME)
        }
    }

    /** يلغي الفحص التلقائي المستقبلي فورًا دون مسح السيرفرات أو القياسات المحفوظة محليًا. */
    fun cancel(ctx: Context) {
        val wm = WorkManager.getInstance(ctx.applicationContext)
        wm.cancelUniqueWork(LEGACY_WORK_NAME)
        wm.cancelUniqueWork(LEGACY_3H_WORK_NAME)
        wm.cancelUniqueWork(LEGACY_4H_WORK_NAME)
        wm.cancelUniqueWork(UNIQUE_WORK_NAME)
    }

    fun isBatteryAboveThreshold(ctx: Context, minPct: Int = MIN_BATTERY_PCT): Boolean =
        runCatching {
            val intent = ctx.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
                ?: return@runCatching true
            val level = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
            val scale = intent.getIntExtra(BatteryManager.EXTRA_SCALE, -1)
            if (level < 0 || scale <= 0) true else ((level * 100) / scale) >= minPct
        }.getOrDefault(true)
}
