// =====================================================================
// BootRestoreReceiver.kt — استعادة حماية الـ VPN ومفتاح الإيقاف تلقائيًا بعد
// إعادة تشغيل الجهاز أو تحديث الحزمة (Phase 4).
// =====================================================================
package com.bahrain.vpnconfigs.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import com.bahrain.vpnconfigs.data.Prefs
import com.bahrain.vpnconfigs.work.WorkScheduler

class BootRestoreReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        val act = intent?.action ?: return
        if (act != Intent.ACTION_BOOT_COMPLETED && act != Intent.ACTION_MY_PACKAGE_REPLACED) {
            return
        }
        val appCtx = context.applicationContext
        runCatching { WorkScheduler.syncSchedule(appCtx) }
        val prefs = Prefs(appCtx)
        if (!prefs.wasVpnDesiredActive || !prefs.killSwitch) return
        if (prefs.selectedCfg.isBlank()) return
        // لا يمكن بدء الخدمة تلقائيًا إلا إذا كان إذن الـ VPN ممنوحًا مسبقًا من المستخدم
        if (VpnService.prepare(appCtx) != null) return

        runCatching {
            BahrainVpnService.startConnect(
                appCtx,
                prefs.selectedCfg,
                prefs.selectedLabel.ifBlank { "bahrain-vpn #1" },
            )
        }
    }
}
