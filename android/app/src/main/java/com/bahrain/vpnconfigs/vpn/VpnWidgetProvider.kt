package com.bahrain.vpnconfigs.vpn

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.widget.RemoteViews
import com.bahrain.vpnconfigs.MainActivity
import com.bahrain.vpnconfigs.R
import com.bahrain.vpnconfigs.data.Prefs
import com.bahrain.vpnconfigs.util.AppI18n
import com.bahrain.vpnconfigs.util.tr

/**
 * Home-screen widget: shows connection state and toggles the VPN on tap.
 * Refreshed from the same hook as the Quick Settings tile (QuickTileService.requestTileUpdate).
 */
class VpnWidgetProvider : AppWidgetProvider() {

    companion object {
        const val ACTION_TOGGLE = "com.bahrain.vpnconfigs.widget.TOGGLE"

        fun refreshAll(ctx: Context) {
            runCatching {
                val mgr = AppWidgetManager.getInstance(ctx)
                val ids = mgr.getAppWidgetIds(ComponentName(ctx, VpnWidgetProvider::class.java))
                if (ids.isNotEmpty()) render(ctx, mgr, ids)
            }
        }

        private fun render(ctx: Context, mgr: AppWidgetManager, ids: IntArray) {
            AppI18n.initFromPrefs(ctx)
            val st = VpnStateManager.status.value
            val views = RemoteViews(ctx.packageName, R.layout.widget_vpn)
            val (statusText, active) = when {
                st.isTunnelVerified -> tr("متّصل", "Connected") to true
                st.isTransitioning -> tr("جارٍ الاتصال…", "Connecting…") to true
                st.isActive -> tr("الحماية مفعّلة", "Protection on") to true
                else -> tr("غير متّصل — اضغط للاتصال", "Disconnected — tap to connect") to false
            }
            views.setTextViewText(R.id.widget_status, statusText)
            views.setTextViewText(
                R.id.widget_server,
                if (active && st.activeLabel.isNotBlank()) st.activeLabel else "bahrain-vpn",
            )
            views.setInt(
                R.id.widget_root,
                "setBackgroundResource",
                if (active) R.drawable.widget_bg_active else R.drawable.widget_bg,
            )
            val needsPermission = !active && runCatching { VpnService.prepare(ctx) != null }.getOrDefault(true)
            val toggle = if (needsPermission) {
                // VPN permission not granted yet: tapping opens the app so the user can grant it.
                PendingIntent.getActivity(
                    ctx,
                    1,
                    Intent(ctx, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                )
            } else {
                PendingIntent.getBroadcast(
                    ctx,
                    0,
                    Intent(ctx, VpnWidgetProvider::class.java).setAction(ACTION_TOGGLE),
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                )
            }
            views.setOnClickPendingIntent(R.id.widget_root, toggle)
            mgr.updateAppWidget(ids, views)
        }
    }

    override fun onUpdate(ctx: Context, mgr: AppWidgetManager, ids: IntArray) = render(ctx, mgr, ids)

    override fun onReceive(ctx: Context, intent: Intent) {
        super.onReceive(ctx, intent)
        if (intent.action != ACTION_TOGGLE) return
        val app = ctx.applicationContext
        if (VpnStateManager.status.value.isActive) {
            BahrainVpnService.stopVpn(app)
        } else if (VpnService.prepare(app) != null) {
            refreshAll(app) // permission was revoked: redraw so the next tap opens the app
            return
        } else {
            val prefs = Prefs(app)
            BahrainVpnService.startConnect(app, prefs.selectedCfg, prefs.selectedLabel.ifBlank { "bahrain-vpn #1" })
        }
        refreshAll(app)
    }
}
