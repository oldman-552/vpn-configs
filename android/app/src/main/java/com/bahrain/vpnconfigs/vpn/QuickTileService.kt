// =====================================================================
// QuickTileService.kt — زر تشغيل/إيقاف سريع لـ bahrain-vpn في شريط الإشعارات.
// =====================================================================
package com.bahrain.vpnconfigs.vpn

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import com.bahrain.vpnconfigs.MainActivity
import com.bahrain.vpnconfigs.data.Prefs
import com.bahrain.vpnconfigs.util.AppI18n
import com.bahrain.vpnconfigs.util.tr

class QuickTileService : TileService() {

    companion object {
        fun requestTileUpdate(ctx: Context) {
            runCatching {
                requestListeningState(ctx, ComponentName(ctx, QuickTileService::class.java))
            }
        }
    }

    override fun onStartListening() {
        super.onStartListening()
        syncTile()
    }

    override fun onClick() {
        super.onClick()
        val st = VpnStateManager.status.value
        if (st.isActive) {
            BahrainVpnService.stopVpn(applicationContext)
            syncTile(forceActive = false)
            return
        }

        // إذا لم يُمنح إذن الـ VPN مسبقًا، نفتح التطبيق لطلب الإذن من المستخدم
        if (VpnService.prepare(applicationContext) != null) {
            val openIntent = Intent(this, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                val pi = android.app.PendingIntent.getActivity(
                    this,
                    10,
                    openIntent,
                    android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE,
                )
                startActivityAndCollapse(pi)
            } else {
                @Suppress("DEPRECATION")
                startActivityAndCollapse(openIntent)
            }
            return
        }

        val prefs = Prefs(applicationContext)
        BahrainVpnService.startConnect(
            applicationContext,
            prefs.selectedCfg,
            prefs.selectedLabel.ifBlank { "bahrain-vpn #1" },
        )
        syncTile(forceActive = true)
    }

    private fun syncTile(forceActive: Boolean? = null) {
        val tile = qsTile ?: return
        AppI18n.initFromPrefs(applicationContext)
        val st = VpnStateManager.status.value
        val active = forceActive ?: st.isActive
        tile.state = if (active) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = "bahrain-vpn"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = if (active) st.activeLabel else tr("غير متّصل", "Disconnected")
        }
        tile.updateTile()
    }
}
