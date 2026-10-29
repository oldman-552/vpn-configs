// =====================================================================
// Prefs.kt — إعدادات التطبيق (SharedPreferences: بسيطة وبلا تبعيات إضافية).
// =====================================================================
package com.bahrain.vpnconfigs.data

import android.content.Context
import androidx.core.content.edit

class Prefs(ctx: Context) {
    private val sp = ctx.getSharedPreferences("settings", Context.MODE_PRIVATE)

    var owner: String
        get() = (sp.getString("owner", Repo.DEFAULT_OWNER) ?: Repo.DEFAULT_OWNER)
            .ifBlank { Repo.DEFAULT_OWNER }
        set(v) = sp.edit { putString("owner", v.trim().ifBlank { Repo.DEFAULT_OWNER }) }

    var repo: String
        get() = (sp.getString("repo", Repo.DEFAULT_REPO) ?: Repo.DEFAULT_REPO)
            .ifBlank { Repo.DEFAULT_REPO }
        set(v) = sp.edit { putString("repo", v.trim().ifBlank { Repo.DEFAULT_REPO }) }

    var testTop: Int
        get() = sp.getInt("test_top", 600)
        set(v) = sp.edit { putInt("test_top", v.coerceAtLeast(10)) }

    var speedTop: Int
        get() = sp.getInt("speed_top", 120)
        set(v) = sp.edit { putInt("speed_top", v.coerceAtLeast(0)) }

    var bestN: Int
        get() = sp.getInt("best_n", 100)
        set(v) = sp.edit { putInt("best_n", v.coerceAtLeast(1)) }

    var concurrency: Int
        get() = sp.getInt("concurrency", 6)
        set(v) = sp.edit { putInt("concurrency", v.coerceIn(1, 12)) }

    var timeoutSec: Int
        get() = sp.getInt("timeout", 6)
        set(v) = sp.edit { putInt("timeout", v.coerceIn(2, 30)) }

    var rankBySpeed: Boolean
        get() = sp.getBoolean("rank_speed", true)
        set(v) = sp.edit { putBoolean("rank_speed", v) }

    var autoRefresh: Boolean
        get() = sp.getBoolean("auto_refresh", true)
        set(v) = sp.edit { putBoolean("auto_refresh", v) }
}
