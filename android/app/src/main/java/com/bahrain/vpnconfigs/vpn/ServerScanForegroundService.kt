// =====================================================================
// ServerScanForegroundService.kt — خدمة أمامية خفيفة ومؤقتة أثناء فحص السيرفرات:
//   • تضمن استمرار فحص الـ 500 سيرفر بأقصى سرعة للمعالج والشبكة حتى لو انتقل المستخدم
//     فوراً إلى أي تطبيق آخر (واتساب / يوتيوب / متصفح) دون خنق الخلفية في أندرويد.
//   • تعرض إشعار تقدم صامت وهادئ (IMPORTANCE_LOW) مع زر إيقاف اختياري، وتُغلق نفسها
//     تلقائيًا في نفس اللحظة التي يكتمل فيها الفحص وحفظ النتائج.
// =====================================================================
package com.bahrain.vpnconfigs.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.bahrain.vpnconfigs.MainActivity
import com.bahrain.vpnconfigs.R
import com.bahrain.vpnconfigs.engine.ScanRuntimeCoordinator
import com.bahrain.vpnconfigs.util.tr

class ServerScanForegroundService : Service() {

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP_SCAN_USER) {
            ScanRuntimeCoordinator.cancelActiveScan(applicationContext)
            stopForegroundCompat()
            stopSelf()
            return START_NOT_STICKY
        }

        val title = intent?.getStringExtra(EXTRA_TITLE).orEmpty().ifBlank {
            tr("فحص فائق السرعة لأفضل السيرفرات", "Ultra-Fast Best Server Scan")
        }
        val detail = intent?.getStringExtra(EXTRA_DETAIL).orEmpty().ifBlank {
            tr("يستمر الفحص بأقصى سرعة حتى عند الانتقال لتطبيق آخر…", "Scanning at full speed in background…")
        }
        val done = intent?.getIntExtra(EXTRA_DONE, 0) ?: 0
        val total = intent?.getIntExtra(EXTRA_TOTAL, 0) ?: 0

        ensureChannel()
        val notif = buildNotification(title, detail, done, total)
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(NOTIF_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(NOTIF_ID, notif)
            }
        }.onFailure {
            stopSelf()
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        stopForegroundCompat()
        super.onDestroy()
    }

    private fun stopForegroundCompat() {
        runCatching {
            stopForeground(STOP_FOREGROUND_REMOVE)
        }
    }

    private fun ensureChannel() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return
        if (nm.getNotificationChannel(CHANNEL_ID) != null) return
        val ch = NotificationChannel(
            CHANNEL_ID,
            tr("فحص جودة السيرفرات السريع", "Fast Server Quality Scan"),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = tr(
                "إشعار صامت مؤقت يحافظ على أقصى سرعة لفحص السيرفرات عند الانتقال لتطبيق آخر",
                "Silent temporary status keeping server scanning at full speed while switching apps",
            )
            setShowBadge(false)
            enableVibration(false)
            setSound(null, null)
        }
        nm.createNotificationChannel(ch)
    }

    private fun buildNotification(title: String, detail: String, done: Int, total: Int): Notification {
        val openPi = PendingIntent.getActivity(
            this,
            401,
            Intent(this, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val cancelPi = PendingIntent.getService(
            this,
            402,
            Intent(this, ServerScanForegroundService::class.java).apply {
                action = ACTION_STOP_SCAN_USER
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_vpn_tile)
            .setContentTitle(title)
            .setContentText(detail)
            .setContentIntent(openPi)
            .setOngoing(true)
            .setSilent(true)
            .setOnlyAlertOnce(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_PROGRESS)
            .addAction(0, tr("إيقاف", "Stop"), cancelPi)

        if (total > 0) {
            builder.setProgress(total, done.coerceIn(0, total), false)
        } else {
            builder.setProgress(100, 0, true)
        }
        return builder.build()
    }

    companion object {
        private const val CHANNEL_ID = "bahrain_vpn_fast_scan"
        private const val NOTIF_ID = 4402
        private const val ACTION_START_OR_UPDATE = "com.bahrain.vpnconfigs.action.SCAN_FG_UPDATE"
        const val ACTION_STOP_SCAN_USER = "com.bahrain.vpnconfigs.action.SCAN_FG_CANCEL"
        private const val EXTRA_TITLE = "title"
        private const val EXTRA_DETAIL = "detail"
        private const val EXTRA_DONE = "done"
        private const val EXTRA_TOTAL = "total"

        @Volatile
        private var isForegroundActive = false

        fun start(ctx: Context, title: String, detail: String, done: Int = 0, total: Int = 0) {
            val appCtx = ctx.applicationContext
            runCatching {
                val intent = Intent(appCtx, ServerScanForegroundService::class.java).apply {
                    action = ACTION_START_OR_UPDATE
                    putExtra(EXTRA_TITLE, title)
                    putExtra(EXTRA_DETAIL, detail)
                    putExtra(EXTRA_DONE, done)
                    putExtra(EXTRA_TOTAL, total)
                }
                ContextCompat.startForegroundService(appCtx, intent)
                isForegroundActive = true
            }
        }

        fun updateIfRunning(ctx: Context, title: String, detail: String, done: Int, total: Int) {
            if (!isForegroundActive) return
            val appCtx = ctx.applicationContext
            runCatching {
                val nm = appCtx.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return
                val openPi = PendingIntent.getActivity(
                    appCtx,
                    401,
                    Intent(appCtx, MainActivity::class.java).apply {
                        addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                    },
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                )
                val cancelPi = PendingIntent.getService(
                    appCtx,
                    402,
                    Intent(appCtx, ServerScanForegroundService::class.java).apply {
                        action = ACTION_STOP_SCAN_USER
                    },
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                )
                val notif = NotificationCompat.Builder(appCtx, CHANNEL_ID)
                    .setSmallIcon(R.drawable.ic_vpn_tile)
                    .setContentTitle(title)
                    .setContentText(detail)
                    .setContentIntent(openPi)
                    .setOngoing(true)
                    .setSilent(true)
                    .setOnlyAlertOnce(true)
                    .setPriority(NotificationCompat.PRIORITY_LOW)
                    .setCategory(NotificationCompat.CATEGORY_PROGRESS)
                    .setProgress(total.coerceAtLeast(1), done.coerceIn(0, total.coerceAtLeast(1)), total <= 0)
                    .addAction(0, tr("إيقاف", "Stop"), cancelPi)
                    .build()
                nm.notify(NOTIF_ID, notif)
            }
        }

        fun stop(ctx: Context) {
            isForegroundActive = false
            val appCtx = ctx.applicationContext
            runCatching {
                appCtx.stopService(Intent(appCtx, ServerScanForegroundService::class.java))
            }
            runCatching {
                val nm = appCtx.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
                nm?.cancel(NOTIF_ID)
            }
        }
    }
}
