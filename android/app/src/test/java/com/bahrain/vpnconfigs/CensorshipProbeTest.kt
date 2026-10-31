package com.bahrain.vpnconfigs

import com.bahrain.vpnconfigs.engine.BlockType
import com.bahrain.vpnconfigs.engine.BlockingProfile
import com.bahrain.vpnconfigs.engine.CensorshipProbe
import com.bahrain.vpnconfigs.engine.ProbeObservations
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class CensorshipProbeTest {
    private val clean = ProbeObservations(
        systemDnsIps = listOf("142.250.1.1"), dohIps = listOf("142.250.1.1"),
        sniBlockedOk = true, sniControlOk = true, ipDirectOk = true, udpOk = true, internetOk = true,
    )

    @Test fun cleanNetworkHasNoBlocks() = assertTrue(CensorshipProbe.classify(clean, "WIFI").blocks.isEmpty())

    @Test fun detectsDnsTamperingWithIranStyleBogon() {
        val p = CensorshipProbe.classify(clean.copy(systemDnsIps = listOf("10.10.34.35")), "WIFI")
        assertEquals(setOf(BlockType.DNS), p.blocks)
    }

    @Test fun sniFilteringPrefersRealityAndQuic() {
        val p = CensorshipProbe.classify(clean.copy(sniBlockedOk = false), "CELLULAR", nowMs = 1000L)
        assertTrue(BlockType.SNI in p.blocks)
        assertEquals(8.0, CensorshipProbe.bonusFor("vless://u@h:443?security=reality&sni=x", p, nowMs = 2000L), 0.0)
        assertEquals(0.0, CensorshipProbe.bonusFor("vless://u@h:443?security=tls", p, nowMs = 2000L), 0.0)
        assertEquals(5.0, CensorshipProbe.bonusFor("hysteria2://p@h:443", p, nowMs = 2000L), 0.0)
    }

    @Test fun udpBlockedPenalizesQuic() {
        val p = CensorshipProbe.classify(clean.copy(udpOk = false), "WIFI", nowMs = 0L)
        assertEquals(-15.0, CensorshipProbe.bonusFor("tuic://x@h:443", p, nowMs = 1L), 0.0)
    }

    @Test fun staleProfileIsIgnored() {
        val p = CensorshipProbe.classify(clean.copy(udpOk = false), "WIFI", nowMs = 0L)
        assertEquals(0.0, CensorshipProbe.bonusFor("tuic://x@h:443", p, nowMs = CensorshipProbe.PROFILE_TTL_MS + 1), 0.0)
    }

    @Test fun profileJsonRoundTrip() {
        val p = CensorshipProbe.classify(clean.copy(sniBlockedOk = false, udpOk = false), "WIFI", nowMs = 42L)
        assertEquals(p, BlockingProfile.fromJson(p.toJson()))
    }

    @Test fun offlineYieldsNoBlocks() =
        assertTrue(CensorshipProbe.classify(clean.copy(internetOk = false), "WIFI").blocks.isEmpty())
}
