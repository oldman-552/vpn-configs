// =====================================================================
// Prefs.kt — إعدادات التطبيق (SharedPreferences: بسيطة وبلا تبعيات إضافية).
// =====================================================================
package com.bahrain.vpnconfigs.data

import android.content.Context
import androidx.core.content.edit

class Prefs(ctx: Context) {
    private val sp = ctx.getSharedPreferences("settings", Context.MODE_PRIVATE)

    var owner: String
        get() = sp.getString("owner", "") ?: ""
        set(v) = sp.edit { putString("owner", v.trim()) }

    var repo: String
        get() = sp.getString("repo", "") ?: ""
        set(v) = sp.edit { putString("repo", v.trim()) }

    var testTop: Int
        get() = sp.getInt("test_top", 600)
        set(v) = sp.edit { putInt("test_top", v) }

    var speedTop: Int
        get() = sp.getInt("speed_top", 120)
        set(v) = sp.edit { putInt("speed_top", v) }

    var bestN: Int
        get() = sp.getInt("best_n", 100)
        set(v) = sp.edit { putInt("best_n", v) }

    var concurrency: Int
        get() = sp.getInt("concurrency", 6)
        set(v) = sp.edit { putInt("concurrency", v) }

    var timeoutSec: Int
        get() = sp.getInt("timeout", 6)
        set(v) = sp.edit { putInt("timeout", v) }

    var rankBySpeed: Boolean
        get() = sp.getBoolean("rank_speed", true)
        set(v) = sp.edit { putBoolean("rank_speed", v) }

    var autoRefresh: Boolean
        get() = sp.getBoolean("auto_refresh", true)
        set(v) = sp.edit { putBoolean("auto_refresh", v) }
}
