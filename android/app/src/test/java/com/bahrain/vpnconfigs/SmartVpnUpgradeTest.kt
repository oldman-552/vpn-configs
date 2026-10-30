package com.bahrain.vpnconfigs

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.bahrain.vpnconfigs.data.ClientDatabase
import com.bahrain.vpnconfigs.data.FavoriteSortOrder
import com.bahrain.vpnconfigs.data.HistorySortOrder
import com.bahrain.vpnconfigs.data.LocalServerTelemetry
import com.bahrain.vpnconfigs.data.Prefs
import com.bahrain.vpnconfigs.data.ServerHint
import com.bahrain.vpnconfigs.engine.Converters
import com.bahrain.vpnconfigs.engine.MeasurementConfidence
import com.bahrain.vpnconfigs.engine.SmartSelectionWeights
import com.bahrain.vpnconfigs.engine.SmartServerCandidateInput
import com.bahrain.vpnconfigs.engine.SmartServerSelector
import com.bahrain.vpnconfigs.vpn.AutoReconnectManager
import com.bahrain.vpnconfigs.vpn.ConnectionSecurityClassifier
import com.bahrain.vpnconfigs.vpn.ConnectionSecurityState
import com.bahrain.vpnconfigs.vpn.DiagnosticOutcome
import com.bahrain.vpnconfigs.vpn.DisconnectTrigger
import com.bahrain.vpnconfigs.vpn.NetworkAwarenessMonitor
import com.bahrain.vpnconfigs.vpn.NetworkSnapshot
import com.bahrain.vpnconfigs.vpn.ResourceAndBatteryMonitor
import com.bahrain.vpnconfigs.vpn.UnderlyingTransport
import com.bahrain.vpnconfigs.vpn.VpnPhase
import com.bahrain.vpnconfigs.vpn.VpnStatus
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
class SmartVpnUpgradeTest {

    @Test
    fun canonicalServerIdIsStableAcrossRemarksAndNeverLeaksSecrets() {
        val secretUuid = "9f8e7d6c-5b4a-4321-9876-abcdef012345"
        val uri1 = "vless://$secretUuid@edge.example.com:443?security=tls&type=ws&path=%2Fws&sni=edge.example.com#OldRemark"
        val uri2 = "vless://$secretUuid@EDGE.EXAMPLE.COM:443?sni=edge.example.com&path=%2Fws&type=ws&security=tls#NewRemark"
        val id1 = Converters.stableServerId(uri1)
        val id2 = Converters.stableServerId(uri2)

        assertEquals(24, id1.length)
        assertEquals(id1, id2)
        assertFalse(id1.contains(secretUuid))
        val masked = Converters.maskedEndpointLabel(uri1)
        assertFalse(masked.contains(secretUuid))
    }

    @Test
    fun sqliteFavoritesAndSessionHistoryPersistFilterPaginateAndProtectCredentials() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val prefs = Prefs(ctx)
        val db = ClientDatabase.getInstance(ctx)
        db.clearAllHistory()

        val rawPass = "SuperSecretTrojanPassword!2026"
        val trojanUri = "trojan://$rawPass@198.51.100.44:443?security=tls&sni=cdn.example.org#NodeDE"
        val vlessUri = "vless://11111111-2222-3333-4444-555555555555@de2.example.org:443?security=tls&sni=de2.example.org#FastDE"

        // 1. Legacy favorite migration + custom name + groups + duplicate prevention
        prefs.favorites = setOf(trojanUri)
        prefs.favoritesMigratedV33 = false
        db.migrateLegacyFavoritesIfNeeded(prefs)
        assertTrue(db.isFavorite(trojanUri))

        // Duplicate insert updates metadata rather than creating duplicate rows
        val sidTrojan = Converters.stableServerId(trojanUri)
        db.upsertFavorite(trojanUri, defaultLabel = "bahrain-vpn #1", customName = "سيرفر العمل الألماني", groupName = "العمل", country = "DE")
        db.upsertFavorite(trojanUri, defaultLabel = "bahrain-vpn #99")
        val workFavs = db.listFavorites(groupFilter = "العمل", sort = FavoriteSortOrder.NAME)
        assertEquals(1, workFavs.size)
        assertEquals("سيرفر العمل الألماني", workFavs.first().displayName)
        assertFalse(workFavs.first().toString().contains(rawPass))
        assertEquals("***100.44:443", workFavs.first().maskedEndpoint)

        // 2. Session History: insert, complete, filter, sort, paginate, prune, delete
        val now = 1_793_400_000_000L
        val oldRow = db.startSessionRecord(vlessUri, "bahrain-vpn #Old", "NL", 110L, "WIFI", nowMs = now - 40L * 86_400_000L)
        db.completeSessionRecord(oldRow, disconnectedAtMs = now - 40L * 86_400_000L + 60_000L, peakDownloadBps = 500_000L)

        val row1 = db.startSessionRecord(trojanUri, "bahrain-vpn #1", "DE", 85L, "WIFI", nowMs = now - 3600_000L)
        db.completeSessionRecord(row1, disconnectedAtMs = now - 3000_000L, avgLatencyMs = 80L, peakDownloadBps = 4_500_000L, totalDownBytes = 50_000_000L)

        val row2 = db.startSessionRecord(vlessUri, "bahrain-vpn #2", "FR", 45L, "CELLULAR", nowMs = now - 1200_000L)
        db.completeSessionRecord(row2, disconnectedAtMs = now - 600_000L, avgLatencyMs = 42L, peakDownloadBps = 1_200_000L, totalDownBytes = 10_000_000L)

        // Ensure raw password is NEVER written into SQLite connection_history
        val allRows = db.querySessionHistory(limit = 20)
        assertEquals(3, allRows.size)
        allRows.forEach { r ->
            assertFalse(r.toString().contains(rawPass))
        }

        // Sort by BEST_PERFORMANCE puts row1 (4.5 MB/s) ahead of row2 (1.2 MB/s)
        val byPerf = db.querySessionHistory(sort = HistorySortOrder.BEST_PERFORMANCE, limit = 10)
        assertEquals(row1, byPerf.first().id)

        // Sort by LOWEST_LATENCY puts row2 (42ms) ahead of row1 (80ms)
        val byLat = db.querySessionRecordIdsHelper(db, HistorySortOrder.LOWEST_LATENCY)
        assertEquals(row2, byLat.first())

        // Pagination (limit = 1, offset = 1)
        val page2 = db.querySessionHistory(sort = HistorySortOrder.RECENT, limit = 1, offset = 1)
        assertEquals(1, page2.size)
        assertEquals(row1, page2.first().id)

        // Retention pruning removes 40-day-old record when retention = 30d
        val pruned = db.pruneExpiredHistory(retentionDays = 30, nowMs = now)
        assertEquals(1, pruned)
        assertEquals(2, db.countSessionHistory())

        // Individual deletion + clear all
        assertTrue(db.deleteHistoryEntry(row2))
        assertEquals(1, db.countSessionHistory())
        db.clearAllHistory()
        assertEquals(0, db.countSessionHistory())
        db.removeFavorite(sidTrojan)
    }

    private fun ClientDatabase.querySessionRecordIdsHelper(db: ClientDatabase, sort: HistorySortOrder): List<Long> =
        db.querySessionHistory(sort = sort, limit = 10).map { it.id }

    @Test
    fun smartServerSelectorHonorsWeightsRejectsFlakyFastServersAndExplainsConfidence() {
        val now = 1_793_400_000_000L
        val reliableServer = SmartServerCandidateInput(
            cfg = "vless://11111111-1111-1111-1111-111111111111@de-reliable.example.com:443?security=tls&sni=de-reliable.example.com",
            label = "bahrain-vpn #Reliable",
            country = "DE",
            locallyTested = true,
            localLatencyMs = 78L,
            localDownloadKbps = 3500.0,
            securityAssessment = "Verified",
            riskLevel = "LOW",
            cloudHint = ServerHint(latencyMs = 80L, jitterMs = 9.0, speedKbps = 3200.0, reliabilityScore = 94.0, packetLossPct = 0.0, uptimePct = 98.5, country = "DE", stabilityRuns = 6),
            localTelemetry = LocalServerTelemetry(
                serverId = "s1",
                attempts = 8,
                successes = 8,
                ewmaLatencyMs = 78.0,
                ewmaJitterMs = 8.0,
                ewmaPacketLossPct = 0.0,
                bestDownloadKbps = 3500.0,
                lastSuccessAtMs = now - 10_000L,
            ),
        )

        // Very high advertised speed, but terrible reliability (1/6 success + 2 consecutive recent failures)
        val fastButFlakyServer = SmartServerCandidateInput(
            cfg = "vless://22222222-2222-2222-2222-222222222222@nl-flaky.example.com:443?security=tls&sni=nl-flaky.example.com",
            label = "bahrain-vpn #FlakyFast",
            country = "NL",
            locallyTested = true,
            localLatencyMs = 65L,
            localDownloadKbps = 25_000.0,
            securityAssessment = "Verified",
            riskLevel = "LOW",
            localTelemetry = LocalServerTelemetry(
                serverId = "s2",
                attempts = 6,
                successes = 1,
                consecutiveFailures = 2,
                lastFailureAtMs = now - 30_000L, // Inside 3-minute cooldown!
                ewmaPacketLossPct = 65.0,
                bestDownloadKbps = 25_000.0,
            ),
        )

        // Unmeasured server (missing measurements must NOT be treated as perfect!)
        val unmeasuredServer = SmartServerCandidateInput(
            cfg = "vless://33333333-3333-3333-3333-333333333333@fr-unknown.example.com:443?security=tls&sni=fr-unknown.example.com",
            label = "bahrain-vpn #Unmeasured",
            country = "FR",
            locallyTested = false,
            securityAssessment = "Verified",
            riskLevel = "LOW",
        )

        val decision = SmartServerSelector.selectBestAndFallback(
            candidates = listOf(fastButFlakyServer, unmeasuredServer, reliableServer),
            weights = SmartSelectionWeights(),
            preferredCountry = "DE",
            networkType = "WIFI",
            nowMs = now,
        )

        assertNotNull(decision.primary)
        assertEquals("bahrain-vpn #Reliable", decision.primary!!.label)
        assertEquals(MeasurementConfidence.HIGH, decision.primary!!.confidenceLevel)
        assertTrue(decision.primary!!.reasonsAr.isNotEmpty())

        val unmeasuredEval = decision.allRanked.first { it.label == "bahrain-vpn #Unmeasured" }
        assertEquals(MeasurementConfidence.INSUFFICIENT, unmeasuredEval.confidenceLevel)
        assertTrue(unmeasuredEval.score < decision.primary!!.score)

        // Fallback must be distinct from primary and skip cooldown-excluded server in favor of eligible peer
        assertNotNull(decision.fallback)
        assertEquals("bahrain-vpn #Unmeasured", decision.fallback!!.label)
    }

    @Test
    fun autoReconnectBackoffScheduleJitterDisconnectTriggersAndUserCancel() {
        val mgr = AutoReconnectManager(cappedIntervalMs = 60_000L, maxAttemptsBeforePause = 6)

        // Exact schedule verification without random jitter (jitter factor = 1.0): 2s, 5s, 10s, 20s, 40s, 60s
        val p1 = mgr.nextReconnectPlan(DisconnectTrigger.TUNNEL_DISCONNECTED, networkAvailable = true, deterministicJitterFactor = 1.0)
        val p2 = mgr.nextReconnectPlan(DisconnectTrigger.WIFI_TO_MOBILE, networkAvailable = true, deterministicJitterFactor = 1.0)
        val p3 = mgr.nextReconnectPlan(DisconnectTrigger.DNS_RESOLUTION_FAILURE, networkAvailable = true, deterministicJitterFactor = 1.0)
        val p4 = mgr.nextReconnectPlan(DisconnectTrigger.ENGINE_CRASH, networkAvailable = true, deterministicJitterFactor = 1.0)
        val p5 = mgr.nextReconnectPlan(DisconnectTrigger.CONNECTION_TIMEOUT, networkAvailable = true, deterministicJitterFactor = 1.0)
        val p6 = mgr.nextReconnectPlan(DisconnectTrigger.UNRESPONSIVE_TUNNEL, networkAvailable = true, deterministicJitterFactor = 1.0)

        assertEquals(listOf(2_000L, 5_000L, 10_000L, 20_000L, 40_000L, 60_000L), listOf(p1.delayMs, p2.delayMs, p3.delayMs, p4.delayMs, p5.delayMs, p6.delayMs))
        assertFalse(p1.notifyRepeatedFailure)
        assertTrue(p3.notifyRepeatedFailure) // Notifies user starting at 3rd consecutive failure

        // Anti-storm cap pauses after maxAttemptsBeforePause
        val paused = mgr.nextReconnectPlan(DisconnectTrigger.TUNNEL_DISCONNECTED, networkAvailable = true)
        assertFalse(paused.shouldRetry)
        assertTrue(paused.notifyRepeatedFailure)

        // Single-flight guard & user cancel
        mgr.onTunnelVerified()
        assertEquals(0, mgr.attemptCount)
        assertTrue(mgr.tryAcquireConnectionSlot())
        assertFalse(mgr.tryAcquireConnectionSlot()) // Prevents simultaneous duplicate reconnects
        mgr.releaseConnectionSlot()

        mgr.cancelByUser()
        assertFalse(mgr.nextReconnectPlan(DisconnectTrigger.MOBILE_TO_WIFI, networkAvailable = true).shouldRetry)

        // Underlying network lost -> waits gracefully without burning retry attempts
        mgr.resetForNewUserConnect()
        val offlinePlan = mgr.nextReconnectPlan(DisconnectTrigger.UNDERLYING_NETWORK_LOST, networkAvailable = false)
        assertFalse(offlinePlan.shouldRetry)
        assertEquals(0, mgr.attemptCount)
    }

    @Test
    fun connectionSecurityClassifierEnforcesAll9StatesAndHonestReporting() {
        val publicTlsCfg = "vless://11111111-1111-1111-1111-111111111111@pub.example.com:443?security=tls&sni=pub.example.com"
        val netDualStack = NetworkSnapshot(
            connected = true,
            transport = UnderlyingTransport.WIFI,
            hasIpv4 = true,
            hasGlobalIpv6 = true,
            systemDnsServers = listOf("192.168.1.1"),
        )

        // Case A: Connected public TLS server WITHOUT OS Lockdown -> CONNECTED + ENCRYPTED_TUNNEL + UNKNOWN_SERVER_TRUST, NOT KILL_SWITCH_ACTIVE!
        val statusConnected = VpnStatus(
            phase = VpnPhase.CONNECTED,
            activeCfg = publicTlsCfg,
            livePingMs = 60L,
            killSwitchActive = true,
            osLockdownActive = false,
        )
        val repA = ConnectionSecurityClassifier.classify(
            vpnStatus = statusConnected,
            activeCfg = publicTlsCfg,
            isVipAttested = false,
            networkSnapshot = netDualStack,
            configuredDns = "1.1.1.1",
            useDoh = true,
            enableIpv6 = false,
            tunCapturesIpv6Route = true,
        )
        assertTrue(ConnectionSecurityState.CONNECTED in repA.primaryStates)
        assertTrue(ConnectionSecurityState.ENCRYPTED_TUNNEL in repA.primaryStates)
        assertTrue(ConnectionSecurityState.UNKNOWN_SERVER_TRUST in repA.primaryStates)
        assertFalse(ConnectionSecurityState.KILL_SWITCH_ACTIVE in repA.primaryStates)
        assertEquals(DiagnosticOutcome.PROTECTED, repA.dnsCheck.outcome)
        assertEquals(DiagnosticOutcome.PROTECTED, repA.ipv6Check.outcome)

        // Case B: Attested VIP server WITH OS Lockdown confirmed -> KILL_SWITCH_ACTIVE present & UNKNOWN_SERVER_TRUST absent
        val repVip = ConnectionSecurityClassifier.classify(
            vpnStatus = statusConnected.copy(osLockdownActive = true),
            activeCfg = publicTlsCfg,
            isVipAttested = true,
            networkSnapshot = netDualStack.copy(hasGlobalIpv6 = false),
            configuredDns = "9.9.9.9",
            useDoh = true,
            enableIpv6 = false,
            tunCapturesIpv6Route = true,
        )
        assertTrue(ConnectionSecurityState.KILL_SWITCH_ACTIVE in repVip.primaryStates)
        assertFalse(ConnectionSecurityState.UNKNOWN_SERVER_TRUST in repVip.primaryStates)
        assertEquals(DiagnosticOutcome.UNAVAILABLE_SAFE, repVip.ipv6Check.outcome)

        // Case C: Degraded connection + DNS leak + IPv6 bypass -> UNSTABLE_CONNECTION + DNS_LEAK_DETECTED + IPV6_LEAK_DETECTED + SECURITY_CHECK_FAILED
        val repLeaking = ConnectionSecurityClassifier.classify(
            vpnStatus = statusConnected.copy(phase = VpnPhase.CONNECTION_DEGRADED, packetLossPct = 35.0),
            activeCfg = publicTlsCfg,
            isVipAttested = false,
            networkSnapshot = netDualStack,
            configuredDns = "1.1.1.1",
            useDoh = false,
            enableIpv6 = false,
            tunCapturesIpv6Route = false,
            dnsBypassObserved = true,
            ipv6BypassObserved = true,
        )
        assertTrue(ConnectionSecurityState.UNSTABLE_CONNECTION in repLeaking.primaryStates)
        assertTrue(ConnectionSecurityState.DNS_LEAK_DETECTED in repLeaking.primaryStates)
        assertTrue(ConnectionSecurityState.IPV6_LEAK_DETECTED in repLeaking.primaryStates)
        assertTrue(ConnectionSecurityState.SECURITY_CHECK_FAILED in repLeaking.primaryStates)

        // Case D: Disconnected -> SECURITY_CHECK_INCOMPLETE
        val repDisc = ConnectionSecurityClassifier.classify(
            vpnStatus = VpnStatus(phase = VpnPhase.DISCONNECTED),
            activeCfg = null,
            isVipAttested = false,
            networkSnapshot = netDualStack,
            configuredDns = "1.1.1.1",
            useDoh = true,
            enableIpv6 = false,
        )
        assertTrue(ConnectionSecurityState.SECURITY_CHECK_INCOMPLETE in repDisc.primaryStates)
    }

    @Test
    fun networkAwarenessAndBatteryAdaptiveIntervalsSavePowerInBackground() {
        assertEquals(
            UnderlyingTransport.WIFI,
            NetworkAwarenessMonitor.classifyCapabilities(hasInternet = true, hasWifi = true, hasCellular = false, hasEthernet = false),
        )
        assertEquals(
            UnderlyingTransport.CELLULAR,
            NetworkAwarenessMonitor.classifyCapabilities(hasInternet = true, hasWifi = false, hasCellular = true, hasEthernet = false),
        )
        assertEquals(
            UnderlyingTransport.NONE,
            NetworkAwarenessMonitor.classifyCapabilities(hasInternet = false, hasWifi = true, hasCellular = false, hasEthernet = false),
        )

        val fgDegraded = ResourceAndBatteryMonitor.computeBatteryAwareProbeIntervalMs(0, isDegraded = true, uiForeground = true)
        val fgStable = ResourceAndBatteryMonitor.computeBatteryAwareProbeIntervalMs(6, isDegraded = false, uiForeground = true)
        val bgStableWifi = ResourceAndBatteryMonitor.computeBatteryAwareProbeIntervalMs(6, isDegraded = false, uiForeground = false, isMeteredNetwork = false)
        val bgStableCell = ResourceAndBatteryMonitor.computeBatteryAwareProbeIntervalMs(6, isDegraded = false, uiForeground = false, isMeteredNetwork = true)

        assertEquals(4_000L, fgDegraded)
        assertTrue(bgStableWifi > fgStable)
        assertEquals(45_000L, bgStableWifi)
        assertEquals(60_000L, bgStableCell)
        assertEquals(0, ResourceAndBatteryMonitor.captureSnapshot().wakeLocksHeld)
    }
}
