// =====================================================================
// InstalledApps.kt — قراءة التطبيقات المثبّتة لميزة استثناء التطبيقات (Split Tunneling).
// =====================================================================
package com.bahrain.vpnconfigs.vpn

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.Drawable
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap

data class AppEntry(
    val packageName: String,
    val label: String,
    val isSystem: Boolean,
    val icon: ImageBitmap?,
)

object InstalledApps {

    fun loadAll(ctx: Context): List<AppEntry> {
        val pm = ctx.packageManager
        val selfPkg = ctx.packageName
        val apps = runCatching {
            pm.getInstalledApplications(PackageManager.GET_META_DATA)
        }.getOrDefault(emptyList())

        return apps.asSequence()
            .filter { info ->
                info.packageName != selfPkg && hasInternetPermission(pm, info.packageName)
            }
            .map { info ->
                val label = runCatching { pm.getApplicationLabel(info).toString() }
                    .getOrDefault(info.packageName)
                val isSys = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0 &&
                    (info.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0
                val iconBmp = runCatching {
                    drawableToBitmap(pm.getApplicationIcon(info), 72)
                }.getOrNull()
                AppEntry(
                    packageName = info.packageName,
                    label = label,
                    isSystem = isSys,
                    icon = iconBmp,
                )
            }
            .sortedWith(compareBy<AppEntry> { it.isSystem }.thenBy { it.label.lowercase() })
            .toList()
    }

    private fun hasInternetPermission(pm: PackageManager, pkg: String): Boolean =
        runCatching {
            pm.checkPermission(Manifest.permission.INTERNET, pkg) == PackageManager.PERMISSION_GRANTED
        }.getOrDefault(true)

    private fun drawableToBitmap(drawable: Drawable, sizePx: Int): ImageBitmap {
        val bmp = Bitmap.createBitmap(sizePx, sizePx, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bmp)
        drawable.setBounds(0, 0, sizePx, sizePx)
        drawable.draw(canvas)
        return bmp.asImageBitmap()
    }
}
