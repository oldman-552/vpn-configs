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

    /** لغة واجهة التطبيق: "ar" افتراضيًا (اللغة العربية هي الأساسية)، أو "en" للإنجليزية. */
    var appLanguage: String
        get() {
            val raw = (sp.getString("app_language", "ar") ?: "ar").trim().lowercase()
            return if (raw == "en") "en" else "ar"
        }
        set(v) {
            val norm = if (v.trim().equals("en", ignoreCase = true)) "en" else "ar"
            sp.edit { putString("app_language", norm) }
        }

    var testTop: Int
        get() = sp.getInt("test_top", 500)
        set(v) = sp.edit { putInt("test_top", v.coerceAtLeast(10)) }

    var speedTop: Int
        get() = sp.getInt("speed_top", 30)
        set(v) = sp.edit { putInt("speed_top", v.coerceAtLeast(0)) }

    var bestN: Int
        get() = sp.getInt("best_n", 100)
        set(v) = sp.edit { putInt("best_n", v.coerceAtLeast(1)) }

    var concurrency: Int
        get() = sp.getInt("concurrency", 24)
        set(v) = sp.edit { putInt("concurrency", v.coerceIn(1, 32)) }

    var timeoutSec: Int
        get() = sp.getInt("timeout", 4)
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

    fun getLastScanWallMs(profile: ScanNetworkProfile): Long =
        sp.getLong("last_scan_wall_ms_${profile.code}", 0L)

    fun setLastScanWallMs(profile: ScanNetworkProfile, wallMs: Long) {
        sp.edit { putLong("last_scan_wall_ms_${profile.code}", wallMs.coerceAtLeast(0L)) }
    }

    var autoRefresh: Boolean
        get() = sp.getBoolean("auto_refresh", true)
        set(v) = sp.edit {
            putBoolean("auto_refresh", v)
            putBoolean("auto_server_quality_testing_3h", v)
        }

    /** الفحص التلقائي لجودة السيرفرات في الخلفية (كل 4 ساعات) — مفعّل افتراضياً وبدون نوافذ منبثقة مزعجة. */
    var autoServerQualityTesting: Boolean
        get() = sp.getBoolean("auto_server_quality_testing_3h", sp.getBoolean("auto_refresh", true))
        set(v) = sp.edit {
            putBoolean("auto_server_quality_testing_3h", v)
            putBoolean("auto_refresh", v)
        }

    // ─────────── إعدادات الـ VPN المدمج ───────────
    var selectedCfg: String
        get() = sp.getString("selected_cfg", "") ?: ""
        set(v) = sp.edit { putString("selected_cfg", v) }

    var selectedLabel: String
        get() = sp.getString("selected_label", "bahrain-vpn #1") ?: "bahrain-vpn #1"
        set(v) = sp.edit { putString("selected_label", v) }

    var autoFailover: Boolean
        get() = sp.getBoolean("auto_failover", true)
        set(v) {
            sp.edit {
                putBoolean("auto_failover", v)
                if (!v) putString("failover_mode", "OFF")
                else if ((sp.getString("failover_mode", "SMART") ?: "SMART") == "OFF") {
                    putString("failover_mode", "SMART")
                }
            }
        }

    var failoverMode: String
        get() {
            val raw = (sp.getString("failover_mode", if (autoFailover) "SMART" else "OFF") ?: "SMART").uppercase()
            return if (raw in setOf("OFF", "SMART", "AGGRESSIVE")) raw else "SMART"
        }
        set(v) {
            val norm = v.trim().uppercase().let { if (it in setOf("OFF", "SMART", "AGGRESSIVE")) it else "SMART" }
            sp.edit {
                putString("failover_mode", norm)
                putBoolean("auto_failover", norm != "OFF")
            }
        }

    /** TLS ClientHello fragmentation: AUTO (on when SNI filtering detected), ON, OFF. */
    var tlsFragmentMode: String
        get() = sp.getString("tls_fragment_mode_v1", "AUTO") ?: "AUTO"
        set(v) = sp.edit { putString("tls_fragment_mode_v1", v) }

    /** Registered free Cloudflare WARP account (WarpAccount JSON), empty if not set up. */
    var warpAccountJson: String
        get() = sp.getString("warp_account_v1", "") ?: ""
        set(v) = sp.edit { putString("warp_account_v1", v) }

    /** Switch to WARP automatically when every server fails. */
    var warpFallback: Boolean
        get() = sp.getBoolean("warp_fallback_v1", true)
        set(v) = sp.edit { putBoolean("warp_fallback_v1", v) }

    /** Last censorship probe result (BlockingProfile JSON), used to bias protocol choice. */
    var blockingProfileJson: String
        get() = sp.getString("blocking_profile_v1", "") ?: ""
        set(v) = sp.edit { putString("blocking_profile_v1", v) }


    var killSwitch: Boolean
        get() = sp.getBoolean("kill_switch_v32", true)
        set(v) = sp.edit { putBoolean("kill_switch_v32", v) }

    var smartAutoSelect: Boolean
        get() = sp.getBoolean("smart_auto_select_v33", true)
        set(v) = sp.edit { putBoolean("smart_auto_select_v33", v) }

    var preferredCountry: String
        get() = (sp.getString("preferred_country_v33", "ALL") ?: "ALL").trim().uppercase().ifBlank { "ALL" }
        set(v) = sp.edit { putString("preferred_country_v33", v.trim().uppercase().ifBlank { "ALL" }) }

    var historyRetentionDays: Int
        get() = sp.getInt("history_retention_days_v33", 90).coerceIn(7, 365)
        set(v) = sp.edit { putInt("history_retention_days_v33", v.coerceIn(7, 365)) }

    var reconnectCappedSec: Int
        get() = sp.getInt("reconnect_capped_sec_v33", 60).coerceIn(20, 300)
        set(v) = sp.edit { putInt("reconnect_capped_sec_v33", v.coerceIn(20, 300)) }

    var smartWeightsJson: String
        get() = sp.getString("smart_weights_json_v33", "") ?: ""
        set(v) = sp.edit { putString("smart_weights_json_v33", v) }

    var favoritesMigratedV33: Boolean
        get() = sp.getBoolean("favorites_migrated_v33", false)
        set(v) = sp.edit { putBoolean("favorites_migrated_v33", v) }

    var wasVpnDesiredActive: Boolean
        get() = sp.getBoolean("vpn_desired_active", false)
        set(v) = sp.edit { putBoolean("vpn_desired_active", v) }

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

    /** استثناء نطاقات .ir و .ایران من الـ VPN وتمريرها مباشرة عبر الإنترنت المحلي (مفعّل افتراضياً). */
    var bypassIrDomains: Boolean
        get() = sp.getBoolean("bypass_ir_domains", true)
        set(v) = sp.edit { putBoolean("bypass_ir_domains", v) }

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


    // ─────────── إعدادات الفحص المجتمعي الطوعي (معطّل افتراضيًا — موافقة صريحة) ───────────
    var communityTestingEnabled: Boolean
        get() = sp.getBoolean("community_testing_enabled", false) && communityConsentAtMs > 0L
        set(v) = sp.edit { putBoolean("community_testing_enabled", v) }

    var communityConsentAtMs: Long
        get() = sp.getLong("community_consent_at_ms", 0L)
        set(v) = sp.edit { putLong("community_consent_at_ms", v.coerceAtLeast(0L)) }

    var communityWifiOnly: Boolean
        get() = sp.getBoolean("community_wifi_only", true)
        set(v) = sp.edit { putBoolean("community_wifi_only", v) }

    var communityMaxConfigsPerRun: Int
        get() = sp.getInt("community_max_configs_per_run", 15).coerceIn(5, 50)
        set(v) = sp.edit { putInt("community_max_configs_per_run", v.coerceIn(5, 50)) }

    var communityDailyLimit: Int
        get() = sp.getInt("community_daily_limit", 60).coerceIn(10, 250)
        set(v) = sp.edit { putInt("community_daily_limit", v.coerceIn(10, 250)) }

    var communityBackgroundScheduleEnabled: Boolean
        get() = sp.getBoolean("community_bg_schedule", false)
        set(v) = sp.edit { putBoolean("community_bg_schedule", v) }

    var communityEndpointOverride: String
        get() = (sp.getString("community_endpoint_override", "") ?: "").trim()
        set(v) {
            val clean = v.trim()
            val safe = if (clean.startsWith("https://", ignoreCase = true) || clean.startsWith("http://127.0.0.1:", ignoreCase = true)) {
                clean.trimEnd('/')
            } else ""
            sp.edit { putString("community_endpoint_override", safe) }
        }

    var communityInstallSalt: String
        get() {
            val cur = sp.getString("community_install_salt", "") ?: ""
            if (cur.length >= 24) return cur
            val generated = java.util.UUID.randomUUID().toString().replace("-", "") +
                java.util.UUID.randomUUID().toString().replace("-", "").take(16)
            sp.edit { putString("community_install_salt", generated) }
            return generated
        }
        private set(v) = sp.edit { putString("community_install_salt", v) }

    var lastVerifiedOriginCountry: String
        get() = (sp.getString("community_last_origin_cc", "") ?: "").trim().uppercase()
        set(v) = sp.edit { putString("community_last_origin_cc", v.trim().uppercase().take(4)) }

    var lastCommunityRunAtMs: Long
        get() = sp.getLong("community_last_run_ms", 0L)
        set(v) = sp.edit { putLong("community_last_run_ms", v.coerceAtLeast(0L)) }

    fun grantCommunityTestingConsent() {
        val now = System.currentTimeMillis()
        sp.edit {
            putLong("community_consent_at_ms", now)
            putBoolean("community_testing_enabled", true)
        }
    }

    fun revokeCommunityTestingConsent() {
        val freshSalt = java.util.UUID.randomUUID().toString().replace("-", "") +
            java.util.UUID.randomUUID().toString().replace("-", "").take(16)
        sp.edit {
            putBoolean("community_testing_enabled", false)
            putBoolean("community_bg_schedule", false)
            putLong("community_consent_at_ms", 0L)
            putString("community_install_salt", freshSalt)
            remove("community_last_origin_cc")
        }
    }

    // ─────────── إعدادات نقطة اتصال الـ VPN بدون روت (Rootless VPN Hotspot) ───────────
    var hotspotProxyPort: Int
        get() = sp.getInt("hotspot_proxy_port", 20880).coerceIn(10240, 65000)
        set(v) = sp.edit { putInt("hotspot_proxy_port", v.coerceIn(10240, 65000)) }

    var hotspotRequireAuth: Boolean
        get() = sp.getBoolean("hotspot_require_auth", false)
        set(v) = sp.edit { putBoolean("hotspot_require_auth", v) }

    var hotspotUsername: String
        get() = (sp.getString("hotspot_auth_user", "vpnshare") ?: "vpnshare").trim().ifBlank { "vpnshare" }
        set(v) = sp.edit { putString("hotspot_auth_user", v.trim().take(32).ifBlank { "vpnshare" }) }

    var hotspotPassword: String
        get() {
            val cur = (sp.getString("hotspot_auth_pass", "") ?: "").trim()
            if (cur.length >= 6) return cur
            val alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
            val rnd = java.security.SecureRandom()
            val generated = (1..10).map { alphabet[rnd.nextInt(alphabet.length)] }.joinToString("")
            sp.edit { putString("hotspot_auth_pass", generated) }
            return generated
        }
        set(v) {
            val clean = v.trim().take(48)
            if (clean.length >= 6) {
                sp.edit { putString("hotspot_auth_pass", clean) }
            }
        }
}
