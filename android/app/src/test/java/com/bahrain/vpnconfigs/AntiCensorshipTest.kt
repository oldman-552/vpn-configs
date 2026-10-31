package com.bahrain.vpnconfigs

import com.bahrain.vpnconfigs.engine.BlockType
import com.bahrain.vpnconfigs.engine.BlockingProfile
import com.bahrain.vpnconfigs.engine.CdnDetector
import com.bahrain.vpnconfigs.engine.CensorshipProbe
import com.bahrain.vpnconfigs.engine.ProbeObservations
import com.bahrain.vpnconfigs.engine.TlsFragment
import com.bahrain.vpnconfigs.engine.WarpAccount
import com.bahrain.vpnconfigs.engine.WarpManager
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.Base64

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class AntiCensorshipTest {
    private val sniProfile = BlockingProfile(1_000L, "WIFI", true, setOf(BlockType.SNI), emptyMap())

    // ── TLS fragment ──
    @Test fun fragmentModes() {
        assertTrue(TlsFragment.shouldEnable("ON", null, "WIFI"))
        assertFalse(TlsFragment.shouldEnable("OFF", sniProfile, "WIFI", nowMs = 2_000L))
        assertTrue(TlsFragment.shouldEnable("AUTO", sniProfile, "WIFI", nowMs = 2_000L))
        assertFalse(TlsFragment.shouldEnable("AUTO", sniProfile, "CELLULAR", nowMs = 2_000L))
        assertFalse(TlsFragment.shouldEnable("AUTO", sniProfile, "WIFI", nowMs = 1_000L + CensorshipProbe.PROFILE_TTL_MS + 1))
        assertFalse(TlsFragment.shouldEnable("AUTO", null, "WIFI"))
    }

    @Test fun fragmentOnlyOnTcpTls() {
        val tls = JSONObject().put("type", "vless").put("tls", JSONObject().put("enabled", true))
        assertTrue(TlsFragment.apply(tls))
        assertTrue(tls.getJSONObject("tls").getBoolean("fragment"))

        val reality = JSONObject().put("type", "vless")
            .put("tls", JSONObject().put("enabled", true).put("reality", JSONObject().put("enabled", true)))
        assertFalse(TlsFragment.apply(reality))

        val hy2 = JSONObject().put("type", "hysteria2").put("tls", JSONObject().put("enabled", true))
        assertFalse(TlsFragment.apply(hy2))
        assertFalse(TlsFragment.apply(JSONObject().put("type", "shadowsocks")))
    }

    // ── CDN detection ──
    @Test fun detectsCdnConfigs() {
        assertTrue(CdnDetector.isCdnFronted("vless://u@cdn.example.com:443?type=ws&security=tls&host=a.b#x"))
        assertTrue(CdnDetector.isCdnFronted("vless://u@104.18.1.1:2096?type=grpc&security=tls"))
        assertTrue(CdnDetector.isCdnFronted("vless://u@example.com:8080?type=ws&security=none"))
        assertTrue(CdnDetector.isCdnFronted("trojan://p@ss@example.com:443?type=ws"))
        val vm = Base64.getEncoder().encodeToString(
            """{"add":"example.com","port":"443","net":"ws","tls":"tls","id":"x"}""".toByteArray(),
        )
        assertTrue(CdnDetector.isCdnFronted("vmess://$vm"))
    }

    @Test fun rejectsNonCdnConfigs() {
        assertFalse(CdnDetector.isCdnFronted("vless://u@1.2.3.4:443?type=tcp&security=reality"))
        assertFalse(CdnDetector.isCdnFronted("vless://u@example.com:12345?type=ws&security=tls"))
        assertFalse(CdnDetector.isCdnFronted("hysteria2://p@example.com:443"))
        assertFalse(CdnDetector.isCdnFronted("garbage"))
    }

    @Test fun cloudflareIpRanges() {
        assertTrue(CdnDetector.isCloudflareIp("104.16.0.1"))
        assertTrue(CdnDetector.isCloudflareIp("172.67.10.10"))
        assertFalse(CdnDetector.isCloudflareIp("8.8.8.8"))
        assertFalse(CdnDetector.isCloudflareIp("not-an-ip"))
    }

    @Test fun ipBlockingFavorsCdn() {
        val obs = ProbeObservations(listOf("1.1.1.1"), listOf("1.1.1.1"), true, true, false, true, true)
        val p = CensorshipProbe.classify(obs, "WIFI", nowMs = 0L)
        assertTrue(BlockType.IP in p.blocks)
        val cdn = CensorshipProbe.bonusFor("vless://u@cdn.example.com:443?type=ws&security=tls", p, nowMs = 1L)
        val plain = CensorshipProbe.bonusFor("vless://u@1.2.3.4:443?type=tcp&security=tls", p, nowMs = 1L)
        assertTrue(cdn > plain)
    }

    // ── WARP ──
    @Test fun parsesKeyPairOutput() {
        assertEquals("priv" to "pub", WarpManager.parseKeyPair("PrivateKey: priv\nPublicKey: pub\n"))
        assertNull(WarpManager.parseKeyPair("error"))
    }

    @Test fun parsesRegistrationAndBuildsEndpoint() {
        val body = """
            {"config":{"client_id":"AQID",
              "peers":[{"public_key":"PEERKEY=","endpoint":{"v4":"162.159.192.5:0","host":"engage.cloudflareclient.com:2408"}}],
              "interface":{"addresses":{"v4":"172.16.0.2","v6":"2606:4700:110::1"}}}}
        """.trimIndent()
        val acc = WarpManager.parseRegistration(body, "PRIVKEY=")
        assertNotNull(acc)
        acc!!
        assertEquals(listOf(1, 2, 3), acc.reserved)
        assertEquals("162.159.192.5", acc.endpointIp)
        assertEquals(acc, WarpAccount.fromJson(acc.toJson()))

        val ep = acc.toSingBoxEndpoint()
        assertEquals("wireguard", ep.getString("type"))
        assertEquals("proxy", ep.getString("tag"))
        val peer = ep.getJSONArray("peers").getJSONObject(0)
        assertEquals("PEERKEY=", peer.getString("public_key"))
        assertEquals(2408, peer.getInt("port"))
        assertEquals("172.16.0.2/32", ep.getJSONArray("address").getString(0))
    }

    @Test fun badRegistrationIsNull() = assertNull(WarpManager.parseRegistration("{}", "k"))

    @Test fun warpUriDetection() {
        assertTrue(WarpManager.isWarp(WarpManager.WARP_URI))
        assertFalse(WarpManager.isWarp("vless://x"))
        assertFalse(WarpManager.isWarp(null))
    }
}
