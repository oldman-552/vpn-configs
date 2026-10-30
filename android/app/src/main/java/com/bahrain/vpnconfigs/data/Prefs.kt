// =====================================================================
// Prefs.kt — إعدادات تطبيق bahrain-vpn، التفضيلات، وسجل الاتصالات الآمن.
// =====================================================================
package com.bahrain.vpnconfigs.data

import android.content.Context
import androidx.core.content.edit
import com.bahrain.vpnconfigs.engine.ServerSortMode
import org.json.JSONArray
import org.json.JSONObject

data class ConnectionHistoryEntry(
    val label: String,
    val endpoint: String,
    val proto: String,
    val country: String = "",
    val pingMs: Long = 0L,
    val timestampMs: Long = 0L,
)

class Prefs(ctx: Context) {
    private val sp = ctx.getSharedPreferences("settings", Context.MODE_PRIVATE)

    init {
        if (sp.contains("owner") || sp.contains("repo")) {
            sp.edit {
                remove("owner")
                remove("repo")
            }
        }
    }

    var feedProfile: String
        get() = (sp.getString("feed_profile", "smart") ?: "smart").ifBlank { "smart" }
        set(v) = sp.edit { putString("feed_profile", v.trim().ifBlank { "smart" }) }

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
        get() = sp.getBoolean("rank_speed_v2", true)
        set(v) = sp.edit { putBoolean("rank_speed_v2", v) }

    var sortMode: String
        get() = ServerSortMode.fromKey(sp.getString("sort_mode_v2", ServerSortMode.DEFAULT.key)).key
        set(v) = sp.edit { putString("sort_mode_v2", ServerSortMode.fromKey(v).key) }

    var lastRefreshWallMs: Long
        get() = sp.getLong("last_refresh_ms", 0L)
        set(v) = sp.edit { putLong("last_refresh_ms", v.coerceAtLeast(0L)) }

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
            list.take(500).forEach { if (it.isNotBlank()) arr.put(it) }
            sp.edit { putString("custom_configs_json", arr.toString()) }
        }

    // ─────────── سجل الاتصالات الآمن (بدون تخزين بيانات الاعتماد السرية) ───────────
    var connectionHistory: List<ConnectionHistoryEntry>
        get() {
            val raw = sp.getString("connection_history_json", null) ?: return emptyList()
            return try {
                val arr = JSONArray(raw)
                buildList {
                    for (i in 0 until arr.length()) {
                        val o = arr.optJSONObject(i) ?: continue
                        val label = o.optString("label")
                        val ep = o.optString("endpoint")
                        if (label.isBlank() && ep.isBlank()) continue
                        add(
                            ConnectionHistoryEntry(
                                label = label,
                                endpoint = ep,
                                proto = o.optString("proto"),
                                country = o.optString("country"),
                                pingMs = o.optLong("ping_ms", 0L),
                                timestampMs = o.optLong("ts_ms", 0L),
                            )
                        )
                    }
                }
            } catch (_: Exception) {
                emptyList()
            }
        }
        private set(list) {
            val arr = JSONArray()
            list.take(20).forEach { item ->
                arr.put(
                    JSONObject()
                        .put("label", item.label)
                        .put("endpoint", item.endpoint)
                        .put("proto", item.proto)
                        .put("country", item.country)
                        .put("ping_ms", item.pingMs)
                        .put("ts_ms", item.timestampMs)
                )
            }
            sp.edit { putString("connection_history_json", arr.toString()) }
        }

    fun recordConnection(
        label: String,
        endpoint: String,
        proto: String,
        country: String = "",
        pingMs: Long = 0L,
    ) {
        val now = System.currentTimeMillis()
        val entry = ConnectionHistoryEntry(
            label = label,
            endpoint = endpoint,
            proto = proto,
            country = country,
            pingMs = pingMs,
            timestampMs = now,
        )
        val filtered = connectionHistory.filterNot { it.endpoint == endpoint && it.proto == proto }
        connectionHistory = (listOf(entry) + filtered).take(20)
    }

    fun updateLatestHistoryCountry(endpoint: String, country: String) {
        if (country.isBlank()) return
        val cur = connectionHistory
        if (cur.isEmpty()) return
        connectionHistory = cur.mapIndexed { idx, item ->
            if (idx == 0 && item.endpoint == endpoint) item.copy(country = country) else item
        }
    }

    fun clearConnectionHistory() {
        connectionHistory = emptyList()
    }

    var lastPromoRotationIndex: Int
        get() = sp.getInt("last_promo_rotation_idx", -1)
        set(v) = sp.edit { putInt("last_promo_rotation_idx", v) }
}
