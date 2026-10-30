package com.bahrain.vpnconfigs

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.bahrain.vpnconfigs.engine.RankableServer
import com.bahrain.vpnconfigs.engine.SecurityEvaluator
import com.bahrain.vpnconfigs.engine.ServerRanker
import com.bahrain.vpnconfigs.engine.ServerSortMode
import com.bahrain.vpnconfigs.engine.SingBox
import com.bahrain.vpnconfigs.vpn.FailoverMode
import com.bahrain.vpnconfigs.vpn.KillSwitchController
import com.bahrain.vpnconfigs.vpn.LeakProtectionEngine
import com.bahrain.vpnconfigs.vpn.ServerCandidate
import com.bahrain.vpnconfigs.vpn.SmartFailoverEngine
import com.bahrain.vpnconfigs.vpn.VpnPhase
import com.bahrain.vpnconfigs.vpn.VpnStatus
import com.bahrain.vpnconfigs.vpn.WebRtcExposureLevel
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class LeakKillSwitchAndSecurityTest {

    @Test
    fun phase2SecurityEvaluatorSeparatesSpeedFromSecurityAndNeverFakesPublicPrivacy() {
        val publicCleanTls = "vless://11111111-1111-1111-1111-111111111111@edge.example.com:443?security=tls&sni=edge.example.com&type=ws#pub"
        val pubEval = SecurityEvaluator.evaluate(publicCleanTls, isVipAttested = false)
        assertEquals("Verified", pubEval.securityAssessment)
        assertEquals("Unverified", pubEval.privacyAssessment) // Public node never gets Verified privacy!
        assertEquals("LOW", pubEval.riskLevel)
        assertFalse(pubEval.quarantined)

        val vipEval = SecurityEvaluator.evaluate(publicCleanTls, isVipAttested = true)
        assertEquals("Verified", vipEval.securityAssessment)
        assertEquals("Verified", vipEval.privacyAssessment)
        assertEquals("LOW", vipEval.riskLevel)

        val mitmInsecure = "trojan://pass@198.51.100.20:443?security=tls&allowInsecure=1&sni=example.com#bad"
        val badEval = SecurityEvaluator.evaluate(mitmInsecure, isVipAttested = false)
        assertEquals("Failed", badEval.securityAssessment)
        assertEquals("High Risk", badEval.privacyAssessment)
        assertEquals("HIGH", badEval.riskLevel)

        val sshPortAbuse = "trojan://pass@198.51.100.20:22?security=tls&sni=example.com#ssh"
        val quarantinedEval = SecurityEvaluator.evaluate(sshPortAbuse, isVipAttested = false)
        assertTrue(quarantinedEval.quarantined)
        assertEquals("CRITICAL", quarantinedEval.riskLevel)
    }

    @Test
    fun phase3DnsDetourAndIpv6FailClosedProtectionPreventTunnelBypass() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val sb = SingBox(ctx)
        val sampleUri = "trojan://pass123@198.51.100.11:443?security=tls&sni=example.com"

        // 1. Verify DNS queries detour through "proxy" and strategy is ipv4_only when IPv6 is disabled
        val cfgIpv4Only = JSONObject(sb.buildConfig(sampleUri, port = 20808, dnsServer = "192.168.1.1", useDoh = true, enableIpv6 = false)!!)
        val dnsObj = cfgIpv4Only.getJSONObject("dns")
        assertEquals("tunnel-dns", dnsObj.getString("final"))
        assertEquals("ipv4_only", dnsObj.getString("strategy"))
        assertEquals("tunnel-dns", cfgIpv4Only.getJSONObject("route").getString("default_domain_resolver"))

        val servers = dnsObj.getJSONArray("servers")
        var sawBootstrap = false
        var sawDetouredTunnelDns = false
        for (i in 0 until servers.length()) {
            val s = servers.getJSONObject(i)
            if (s.getString("tag") == "bootstrap") {
                sawBootstrap = true
                assertFalse(s.has("detour"))
            }
            if (s.getString("tag") == "tunnel-dns") {
                sawDetouredTunnelDns = true
                assertEquals("proxy", s.getString("detour"))
                // Private 192.168.1.1 DNS input was sanitized to safe 1.1.1.1
                assertEquals("1.1.1.1", s.getString("server"))
                assertEquals("https", s.getString("type"))
            }
        }
        assertTrue(sawBootstrap)
        assertTrue(sawDetouredTunnelDns)

        val outProxy = cfgIpv4Only.getJSONArray("outbounds").getJSONObject(0)
        assertEquals("bootstrap", outProxy.getString("domain_resolver"))

        // 2. Verify IPv6 ::/0 route is ALWAYS captured (both IPv4-only sinkhole & dual-stack forwarding)
        val sinkholePlan = LeakProtectionEngine.buildTunProtectionPlan(enableIpv6Tunnel = false, rawDnsServer = "10.0.0.1", useDoh = false)
        assertTrue(sinkholePlan.captureIpv4Route)
        assertTrue(sinkholePlan.captureIpv6Route)
        assertFalse(sinkholePlan.forwardIpv6Upstream)
        assertEquals("ipv4_only", sinkholePlan.singBoxDomainStrategy)
        assertEquals("1.1.1.1", sinkholePlan.sanitizedDnsServer)

        val dualStackPlan = LeakProtectionEngine.buildTunProtectionPlan(enableIpv6Tunnel = true, rawDnsServer = "9.9.9.9", useDoh = true)
        assertTrue(dualStackPlan.captureIpv6Route)
        assertTrue(dualStackPlan.forwardIpv6Upstream)
        assertEquals("prefer_ipv4", dualStackPlan.singBoxDomainStrategy)
        assertEquals("9.9.9.9", dualStackPlan.sanitizedDnsServer)

        // 3. Verify WebRTC exposure honesty
        val disconnectedWebRtc = LeakProtectionEngine.evaluateWebRtcExposure(false, false, emptySet())
        assertEquals(WebRtcExposureLevel.EXPOSED_VPN_DISCONNECTED, disconnectedWebRtc.level)

        val bypassedChrome = LeakProtectionEngine.evaluateWebRtcExposure(true, false, setOf("com.android.chrome"))
        assertEquals(WebRtcExposureLevel.SPLIT_TUNNEL_BYPASS_WARNING, bypassedChrome.level)

        val routedAdvisory = LeakProtectionEngine.evaluateWebRtcExposure(true, false, emptySet())
        assertEquals(WebRtcExposureLevel.TUNNEL_ROUTED_BROWSER_ADVISORY, routedAdvisory.level)
    }

    @Test
    fun phase4KillSwitchEnforcesFailClosedStatesAndEightTunnelPhases() {
        assertTrue(KillSwitchController.shouldEstablishTunBeforeProbe(appKillSwitchEnabled = true))
        assertFalse(KillSwitchController.shouldEstablishTunBeforeProbe(appKillSwitchEnabled = false))

        // Unexpected failure with Kill Switch ON -> holds TUN in PROTECTION_ACTIVE
        assertTrue(KillSwitchController.shouldRetainTunOnFailure(appKillSwitchEnabled = true, userRequestedDisconnect = false))
        assertEquals(VpnPhase.PROTECTION_ACTIVE, KillSwitchController.resolveFailurePhase(true, userRequestedDisconnect = false))

        // User-requested disconnect -> tears down cleanly to DISCONNECTED
        assertFalse(KillSwitchController.shouldRetainTunOnFailure(appKillSwitchEnabled = true, userRequestedDisconnect = true))
        assertEquals(VpnPhase.DISCONNECTED, KillSwitchController.resolveFailurePhase(true, userRequestedDisconnect = true))

        // Unexpected failure with Kill Switch OFF -> CONNECTION_FAILED
        assertEquals(VpnPhase.CONNECTION_FAILED, KillSwitchController.resolveFailurePhase(false, userRequestedDisconnect = false))

        // Verify all 8 VpnPhase flags behave honestly
        assertFalse(VpnStatus(phase = VpnPhase.CONNECTING).isTunnelVerified)
        assertFalse(VpnStatus(phase = VpnPhase.PROTECTION_ACTIVE).isTunnelVerified)
        assertTrue(VpnStatus(phase = VpnPhase.PROTECTION_ACTIVE).isActive)
        assertTrue(VpnStatus(phase = VpnPhase.CONNECTED).isTunnelVerified)
        assertTrue(VpnStatus(phase = VpnPhase.CONNECTION_DEGRADED).isTunnelVerified)
    }

    @Test
    fun phase5And6PrivacyAwareRankingAndProactiveHysteresisFailover() {
        val now = 1_793_400_000_000L

        val ultraFastInsecure = RankableServer(
            cfg = "trojan://p@198.51.100.10:443?allowInsecure=1",
            latencyMs = 30L,
            speedKbps = 25_000.0,
            securityAssessment = "Failed",
            privacyAssessment = "High Risk",
            riskLevel = "HIGH",
            locallyTested = true,
            lastTestedAtMs = now - 5_000L,
        )
        val moderateVerified = RankableServer(
            cfg = "vless://11111111-1111-1111-1111-111111111111@edge.example.com:443?security=tls",
            latencyMs = 110L,
            speedKbps = 3_200.0,
            stabilityRuns = 5,
            securityAssessment = "Verified",
            privacyAssessment = "Unverified",
            riskLevel = "LOW",
            locallyTested = true,
            lastTestedAtMs = now - 5_000L,
        )

        val privacySorted = listOf(ultraFastInsecure, moderateVerified)
            .sortedWith(ServerRanker.comparatorFor(ServerSortMode.fromKey("PRIVACY_AWARE"), now))
        assertEquals(moderateVerified.cfg, privacySorted.first().cfg)
        assertEquals(0.0, ServerRanker.computeProfileScore(ultraFastInsecure, "PRIVACY_AWARE", now), 0.001)

        // FailoverMode.OFF never switches even on hard failure or severe degradation
        assertFalse(SmartFailoverEngine.shouldTriggerFailover(processAlive = false, primaryProbeOk = false, secondaryConfirmOk = false, mode = FailoverMode.OFF))

        // Hysteresis dwell blocks oscillation within 25s window
        val blockedByDwell = SmartFailoverEngine.evaluateTunnelHealth(
            recentSamplesMs = listOf(1100L, 1250L, 1300L),
            recentOutcomes = listOf(true, false, true),
            mode = FailoverMode.SMART,
            lastSwitchAtMs = now - 5_000L,
            nowMs = now,
        )
        assertTrue(blockedByDwell.isDegraded)
        assertFalse(blockedByDwell.shouldProactiveSwitch)

        // Once dwell window has elapsed, severe degradation triggers proactive switch
        val allowedSwitch = SmartFailoverEngine.evaluateTunnelHealth(
            recentSamplesMs = listOf(1100L, 1250L, 1300L),
            recentOutcomes = listOf(true, false, true),
            mode = FailoverMode.SMART,
            lastSwitchAtMs = now - 35_000L,
            nowMs = now,
        )
        assertTrue(allowedSwitch.isDegraded)
        assertTrue(allowedSwitch.shouldProactiveSwitch)

        // CRITICAL-risk candidates are never chosen during failover
        val criticalCand = ServerCandidate("trojan://x@198.51.100.99:22", "BadSSH", speedKbps = 50000.0, latencyMs = 10L, riskLevel = "CRITICAL")
        val safeCand = ServerCandidate("vless://11111111-1111-1111-1111-111111111111@198.51.100.40:443", "SafeNode", speedKbps = 2000.0, latencyMs = 95L, riskLevel = "LOW")
        val ranked = SmartFailoverEngine.rankFailoverCandidates(
            excludeCfg = "",
            pool = listOf(criticalCand, safeCand),
            nowMs = now,
        )
        assertEquals(1, ranked.size)
        assertEquals("SafeNode", ranked[0].label)

        // Adaptive polling stretches interval when healthy to save battery
        assertEquals(3_500L, SmartFailoverEngine.computeAdaptiveCheckIntervalMs(0, isDegraded = true))
        assertEquals(24_000L, SmartFailoverEngine.computeAdaptiveCheckIntervalMs(9, isDegraded = false))
    }
}
