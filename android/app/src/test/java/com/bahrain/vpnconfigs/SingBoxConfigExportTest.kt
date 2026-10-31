package com.bahrain.vpnconfigs

import androidx.test.core.app.ApplicationProvider
import com.bahrain.vpnconfigs.data.Prefs
import com.bahrain.vpnconfigs.engine.SingBox
import com.bahrain.vpnconfigs.engine.WarpAccount
import com.bahrain.vpnconfigs.engine.WarpManager
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
import java.util.Base64

/**
 * Builds real sing-box configs through SingBox.buildConfig and, when SINGBOX_CONFIG_EXPORT_DIR is
 * set (CI), writes them out so the workflow can validate them with `sing-box check`.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class SingBoxConfigExportTest {
    private val ctx = ApplicationProvider.getApplicationContext<android.app.Application>()
    private val key32 = Base64.getEncoder().encodeToString(ByteArray(32) { (it + 1).toByte() })

    private fun export(name: String, json: String) {
        val dir = System.getenv("SINGBOX_CONFIG_EXPORT_DIR")?.takeIf { it.isNotBlank() } ?: return
        File(dir).apply { mkdirs() }.resolve("$name.json").writeText(json)
    }

    @Test fun fragmentConfig() {
        Prefs(ctx).tlsFragmentMode = "ON"
        val json = SingBox(ctx).buildConfig(
            "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=ws&security=tls&sni=example.com&path=%2F#t",
            20808,
        )
        assertNotNull(json)
        val tls = JSONObject(json!!).getJSONArray("outbounds").getJSONObject(0).getJSONObject("tls")
        assertTrue(tls.getBoolean("fragment"))
        export("fragment-vless-ws", json)
    }

    @Test fun fragmentWithIrBypassConfig() {
        Prefs(ctx).tlsFragmentMode = "ON"
        val json = SingBox(ctx).buildConfig(
            "trojan://pass@example.com:443?security=tls&sni=example.com#t", 20808, bypassIrDomains = true,
        )!!
        export("fragment-trojan-irbypass", json)
    }

    @Test fun warpConfig() {
        val acc = WarpAccount(key32, key32, "172.16.0.2", "2606:4700:110::1", listOf(1, 2, 3))
        Prefs(ctx).warpAccountJson = acc.toJson()
        val json = SingBox(ctx).buildConfig(WarpManager.WARP_URI, 20808)
        assertNotNull(json)
        val ep = JSONObject(json!!).getJSONArray("endpoints").getJSONObject(0)
        assertEquals("wireguard", ep.getString("type"))
        export("warp", json)
        export("warp-irbypass", SingBox(ctx).buildConfig(WarpManager.WARP_URI, 20808, bypassIrDomains = true)!!)
    }
}
