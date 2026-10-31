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

    @Test fun batchMultiOutboundConfig() {
        Prefs(ctx).tlsFragmentMode = "OFF"
        val uris = listOf(
            "vless://11111111-2222-3333-4444-555555555555@vless.example.com:443?type=ws&security=tls&sni=vless.example.com&path=%2Fws#bahrain-vpn 1",
            "trojan://secretpass@trojan.example.com:443?security=tls&sni=trojan.example.com#bahrain-vpn 2",
            "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@198.51.100.12:8388#bahrain-vpn 3",
            "socks5://user1:pass1@198.51.100.15:1080#bahrain-vpn 4",
            "http://user2:pass2@198.51.100.16:8080#bahrain-vpn 5",
        )
        val paired = uris.mapIndexed { idx, uri -> uri to (22100 + idx) }
        val built = SingBox(ctx).buildBatchConfig(
            items = paired,
            dnsServer = "1.1.1.1",
            useDoh = true,
        )
        assertNotNull(built)
        assertEquals(5, built!!.second.size)
        val root = JSONObject(built.first)
        assertEquals(5, root.getJSONArray("inbounds").length())
        assertTrue(root.getJSONArray("outbounds").length() >= 6) // 5 proxy + direct
        assertEquals(5, root.getJSONObject("route").getJSONArray("rules").length())
        export("batch-multi-outbound", built.first)
    }

    @Test fun batchNormalizesUnsafeFingerprintsCiphersAndFiltersMalformedReality() {
        Prefs(ctx).tlsFragmentMode = "ON"
        val validRealityPbk = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { (it + 7).toByte() })
        val ssLegacyAlias = Base64.getEncoder().encodeToString("chacha20-poly1305:secretpass".toByteArray(Charsets.UTF_8))
        val vmessEdgeJson = JSONObject()
            .put("v", "2")
            .put("add", "vmess.example.com")
            .put("port", "443")
            .put("id", "22222222-3333-4444-5555-666666666666")
            .put("aid", "0")
            .put("scy", "chacha20-ietf-poly1305")
            .put("net", "ws")
            .put("path", "/ws")
            .put("tls", "tls")
            .put("fp", "unsafe")
            .toString()
        val vmessEdgeUri = "vmess://" + Base64.getEncoder().encodeToString(vmessEdgeJson.toByteArray(Charsets.UTF_8))

        val uris = listOf(
            "vless://11111111-2222-3333-4444-555555555555@edge1.example.com:443?type=ws&security=tls&fp=unsafe&sni=edge1.example.com&path=%2Fws#u1",
            "trojan://secret@edge2.example.com:443?security=tls&fp=chrome_psk&sni=edge2.example.com#u2",
            "ss://$ssLegacyAlias@198.51.100.21:8388#u3",
            vmessEdgeUri,
            "vless://11111111-2222-3333-4444-555555555555@edge3.example.com:443?type=tcp&flow=xtls-rprx-direct&security=tls&sni=edge3.example.com#u5",
            "hy2://hypass@198.51.100.22:8443?fp=unsafe&sni=hy2.example.com#u6",
            "vless://11111111-2222-3333-4444-555555555555@198.51.100.23:443?security=reality&pbk=$validRealityPbk&sid=a&sni=www.microsoft.com#u7",
            // Bad 7-char Reality pbk -> cleanly skipped from batch so sing-box never crashes!
            "vless://11111111-2222-3333-4444-555555555555@198.51.100.24:443?security=reality&pbk=shortpk&sid=01&sni=www.microsoft.com#bad",
        )
        val paired = uris.mapIndexed { idx, uri -> uri to (22300 + idx) }
        val built = SingBox(ctx).buildBatchConfig(items = paired, dnsServer = "1.1.1.1", useDoh = false)
        assertNotNull(built)
        // 7 valid normalized slots admitted, 1 malformed-pbk Reality slot surgically skipped!
        assertEquals(7, built!!.second.size)
        export("batch-normalized-edge-cases", built.first)
    }
}
