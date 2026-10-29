// =====================================================================
// Prefs.kt — إعدادات تطبيق bahrain-vpn وحفظ السيرفر المختار والمفضلة والتطبيقات.
// =====================================================================
package com.bahrain.vpnconfigs.data

import android.content.Context
import androidx.core.content.edit
import org.json.JSONArray

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
        get() = sp.getInt("test_top", 400)
        set(v) = sp.edit { putInt("test_top", v.coerceAtLeast(10)) }

    var speedTop: Int
        get() = sp.getInt("speed_top", 80)
        set(v) = sp.edit { putInt("speed_top", v.coerceAtLeast(0)) }

    var bestN: Int
        get() = sp.getInt("best_n", 100)
        set(v) = sp.edit { putInt("best_n", v.coerceAtLeast(1)) }

    var concurrency: Int
        get() = sp.getInt("concurrency", 8)
        set(v) = sp.edit { putInt("concurrency", v.coerceIn(1, 12)) }

    var timeoutSec: Int
        get() = sp.getInt("timeout", 5)
        set(v) = sp.edit { putInt("timeout", v.coerceIn(2, 30)) }

    var rankBySpeed: Boolean
        get() = sp.getBoolean("rank_speed", true)
        set(v) = sp.edit { putBoolean("rank_speed", v) }

    var autoRefresh: Boolean
        get() = sp.getBoolean("auto_refresh", true)
        set(v) = sp.edit { putBoolean("auto_refresh", v) }

    // ─────────── إعدادات الـ VPN المدمج ───────────
    var selectedCfg: String
        get() = sp.getString("selected_cfg", "") ?: ""
        set(v) = sp.edit { putString("selected_cfg", v) }

    var selectedLabel: String
        get() = sp.getString("selected_label", "bahrain-vpn #1") ?: "bahrain-vpn #1"
        set(v) = sp.edit { putString("selected_label", v) }

    var autoFailover: Boolean
        get() = sp.getBoolean("auto_failover", true)
        set(v) = sp.edit { putBoolean("auto_failover", v) }

    var dnsServer: String
        get() = (sp.getString("dns_server", "1.1.1.1") ?: "1.1.1.1").ifBlank { "1.1.1.1" }
        set(v) = sp.edit { putString("dns_server", v.trim().ifBlank { "1.1.1.1" }) }

    var dnsDoh: Boolean
        get() = sp.getBoolean("dns_doh", false)
        set(v) = sp.edit { putBoolean("dns_doh", v) }

    var enableIpv6: Boolean
        get() = sp.getBoolean("enable_ipv6", false)
        set(v) = sp.edit { putBoolean("enable_ipv6", v) }

    var udpInTcp: Boolean
        get() = sp.getBoolean("udp_in_tcp", false)
        set(v) = sp.edit { putBoolean("udp_in_tcp", v) }

    // false = استثناء التطبيقات المحددة (الافتراضي)، true = تشغيل الـ VPN للتطبيقات المحددة فقط
    var splitIncludeOnly: Boolean
        get() = sp.getBoolean("split_include_only", false)
        set(v) = sp.edit { putBoolean("split_include_only", v) }

    var splitApps: Set<String>
        get() = HashSet(sp.getStringSet("split_apps", emptySet()) ?: emptySet())
        set(v) = sp.edit { putStringSet("split_apps", HashSet(v)) }

    var favorites: Set<String>
        get() = HashSet(sp.getStringSet("favorites", emptySet()) ?: emptySet())
        set(v) = sp.edit { putStringSet("favorites", HashSet(v)) }

    var customConfigs: List<String>
        get() {
            val raw = sp.getString("custom_configs_json", null) ?: return emptyList()
            return try {
                val arr = JSONArray(raw)
                buildList {
                    for (i in 0 until arr.length()) {
                        val s = arr.optString(i)
                        if (s.isNotBlank()) add(s)
                    }
                }
            } catch (_: Exception) {
                emptyList()
            }
        }
        set(list) {
            val arr = JSONArray()
            list.forEach { if (it.isNotBlank()) arr.put(it) }
            sp.edit { putString("custom_configs_json", arr.toString()) }
        }
}
