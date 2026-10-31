package com.bahrain.vpnconfigs

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.bahrain.vpnconfigs.data.ClientDatabase
import com.bahrain.vpnconfigs.data.DeadConfigPurgePolicy
import com.bahrain.vpnconfigs.data.LocalPoolTier
import com.bahrain.vpnconfigs.data.Prefs
import com.bahrain.vpnconfigs.data.Repo
import com.bahrain.vpnconfigs.data.ResultLine
import com.bahrain.vpnconfigs.data.ScanNetworkProfile
import com.bahrain.vpnconfigs.data.Top500ServerEntry
import com.bahrain.vpnconfigs.engine.CentralScoringWeights
import com.bahrain.vpnconfigs.engine.Converters
import com.bahrain.vpnconfigs.engine.LocalScanMode
import com.bahrain.vpnconfigs.engine.PersonalizedTop50Ranker
import com.bahrain.vpnconfigs.engine.RankableServer
import com.bahrain.vpnconfigs.engine.SequentialTunnelScanner
import com.bahrain.vpnconfigs.engine.ServerRanker
import com.bahrain.vpnconfigs.engine.ServerSortMode
import com.bahrain.vpnconfigs.engine.SmartSelectionWeights
import com.bahrain.vpnconfigs.engine.SmartServerCandidateInput
import com.bahrain.vpnconfigs.engine.SmartServerSelector
import com.bahrain.vpnconfigs.engine.TestResult
import com.bahrain.vpnconfigs.engine.TunnelBatchProbeExecutor
import com.bahrain.vpnconfigs.work.WorkScheduler
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
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
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.ServerSocket
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class Top500AndPersonalizedTop50Test {

    private fun sha256(text: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(text.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

    private fun buildSampleUri(index: Int, secretToken: String = "sec-$index"): String {
        val oct3 = 10 + (index / 200)
        val oct4 = (index % 200) + 10
        val port = listOf(443, 2053, 2083, 2087, 8443)[index % 5]
        return "trojan://pwd-$secretToken-$index@198.51.$oct3.$oct4:$port?security=tls&sni=edge$index.example.com#bahrain-vpn $index"
    }

    private fun buildTop500Entry(rank: Int, uri: String): Top500ServerEntry {
        val clean = Converters.cleanUri(uri)
        return Top500ServerEntry(
            centralRank = rank,
            serverId = Converters.stableServerId(clean),
            configFingerprint = Converters.configFingerprint(clean),
            cfg = uri,
            protocol = "trojan",
            country = "DE",
            preliminaryLatencyMs = 80L + rank,
            centralQualityScore = 95.0 - (rank * 0.1),
            stabilityRuns = 3,
            securityAssessment = "TLS_VERIFIED",
            privacyAssessment = "STANDARD",
            riskLevel = "LOW",
            trustPosture = "UNTRUSTED_PUBLIC_SERVER",
        )
    }

    @Test
    fun top500SyncVerifiesChecksumsAppliesIncrementalDeltaBlocksRollbackAndRecoversLastValid() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val helperRepo = Repo(ctx)

        val entriesV1 = (1..4).map { buildTop500Entry(it, buildSampleUri(it)) }
        val configsShaV1 = helperRepo.computeTop500ConfigsSetSha256(entriesV1)

        fun buildTop500Json(version: Long, epoch: Long, list: List<Top500ServerEntry>, cSha: String): String {
            val arr = JSONArray()
            list.forEachIndexed { idx, s ->
                arr.put(
                    JSONObject()
                        .put("central_rank", idx + 1)
                        .put("server_id", s.serverId)
                        .put("config_fingerprint", s.configFingerprint)
                        .put("cfg", s.cfg)
                        .put("protocol", s.protocol)
                        .put("country", s.country)
                        .put("preliminary_latency_ms", s.preliminaryLatencyMs)
                        .put("central_quality_score", s.centralQualityScore)
                        .put("trust_posture", s.trustPosture)
                )
            }
            return JSONObject()
                .put("schema_version", "1.0.0")
                .put("dataset_version", version)
                .put("generated_at", "2026-10-30T18:00:00Z")
                .put("generated_at_epoch", epoch)
                .put("role", "CENTRAL_CANDIDATE_POOL")
                .put("personalized_top50_authority", "ANDROID_LOCAL_ONLY")
                .put("qualified_count", list.size)
                .put("configs_sha256", cSha)
                .put("servers", arr)
                .toString()
        }

        val top500JsonV1 = buildTop500Json(100L, 1_793_383_200L, entriesV1, configsShaV1)
        val entriesV2 = listOf(
            entriesV1[0],
            entriesV1[1],
            entriesV1[2],
            buildTop500Entry(4, buildSampleUri(5)),
            buildTop500Entry(5, buildSampleUri(6)),
        )
        val configsShaV2 = helperRepo.computeTop500ConfigsSetSha256(entriesV2)
        val top500JsonV2 = buildTop500Json(101L, 1_793_386_800L, entriesV2, configsShaV2)

        val deltaObjV1ToV2 = JSONObject()
            .put("schema_version", "1.0.0")
            .put("base_dataset_version", 100L)
            .put("base_configs_sha256", configsShaV1)
            .put("target_dataset_version", 101L)
            .put("target_generated_at", "2026-10-30T19:00:00Z")
            .put("target_generated_at_epoch", 1_793_386_800L)
            .put("target_configs_sha256", configsShaV2)
            .put("removed_server_ids", JSONArray().put(entriesV1[3].serverId))
            .put(
                "added_or_updated",
                JSONArray()
                    .put(
                        JSONObject()
                            .put("central_rank", 4)
                            .put("server_id", entriesV2[3].serverId)
                            .put("config_fingerprint", entriesV2[3].configFingerprint)
                            .put("cfg", entriesV2[3].cfg)
                            .put("protocol", "trojan")
                            .put("country", "DE")
                    )
                    .put(
                        JSONObject()
                            .put("central_rank", 5)
                            .put("server_id", entriesV2[4].serverId)
                            .put("config_fingerprint", entriesV2[4].configFingerprint)
                            .put("cfg", entriesV2[4].cfg)
                            .put("protocol", "trojan")
                            .put("country", "DE")
                    )
            )
            .put("ordered_server_ids", JSONArray(entriesV2.map { it.serverId }))
            .toString()

        val mode = AtomicInteger(1) // 1=v1, 2=v2(delta), 3=tampered, 4=rollback(v1)
        val sawEtag304 = AtomicInteger(0)
        val running = AtomicBoolean(true)
        val server = ServerSocket(0, 16, InetAddress.getByName("127.0.0.1"))
        val port = server.localPort

        val acceptor = thread(isDaemon = true) {
            while (running.get()) {
                try {
                    val sock = server.accept()
                    thread(isDaemon = true) {
                        sock.use { s ->
                            s.soTimeout = 3000
                            val reader = BufferedReader(InputStreamReader(s.getInputStream(), Charsets.UTF_8))
                            val reqLine = reader.readLine() ?: return@use
                            var ifNoneMatch = ""
                            while (true) {
                                val h = reader.readLine() ?: break
                                if (h.isEmpty()) break
                                if (h.startsWith("If-None-Match:", ignoreCase = true)) {
                                    ifNoneMatch = h.substringAfter(":").trim()
                                }
                            }
                            val path = reqLine.split(" ").getOrNull(1).orEmpty()
                            val out = s.getOutputStream()

                            fun respond(code: Int, etag: String, body: String) {
                                val bytes = body.toByteArray(Charsets.UTF_8)
                                val statusTxt = if (code == 304) "Not Modified" else if (code == 200) "OK" else "Not Found"
                                val hdr = buildString {
                                    append("HTTP/1.1 $code $statusTxt\r\n")
                                    if (etag.isNotEmpty()) append("ETag: $etag\r\n")
                                    append("Content-Length: ${if (code == 304) 0 else bytes.size}\r\n")
                                    append("Connection: close\r\n\r\n")
                                }
                                out.write(hdr.toByteArray(Charsets.UTF_8))
                                if (code != 304 && bytes.isNotEmpty()) out.write(bytes)
                                out.flush()
                            }

                            when (mode.get()) {
                                1 -> when {
                                    path.endsWith("top500.manifest.json") -> {
                                        if (ifNoneMatch == "\"v100\"") {
                                            sawEtag304.incrementAndGet()
                                            respond(304, "\"v100\"", "")
                                        } else {
                                            val mf = JSONObject()
                                                .put("dataset_version", 100L)
                                                .put("generated_at", "2026-10-30T18:00:00Z")
                                                .put("generated_at_epoch", 1_793_383_200L)
                                                .put("qualified_count", 4)
                                                .put(
                                                    "checksums",
                                                    JSONObject()
                                                        .put("top500_json_sha256", sha256(top500JsonV1))
                                                        .put("configs_sha256", configsShaV1)
                                                )
                                                .put("delta_available", false)
                                                .toString()
                                            respond(200, "\"v100\"", mf)
                                        }
                                    }
                                    path.endsWith("top500.json") -> respond(200, "\"j100\"", top500JsonV1)
                                    else -> respond(404, "", "not found")
                                }
                                2 -> when {
                                    path.endsWith("top500.manifest.json") -> {
                                        val mf = JSONObject()
                                            .put("dataset_version", 101L)
                                            .put("generated_at", "2026-10-30T19:00:00Z")
                                            .put("generated_at_epoch", 1_793_386_800L)
                                            .put("qualified_count", 5)
                                            .put(
                                                "checksums",
                                                JSONObject()
                                                    .put("top500_json_sha256", sha256(top500JsonV2))
                                                    .put("configs_sha256", configsShaV2)
                                                    .put("delta_json_sha256", sha256(deltaObjV1ToV2))
                                            )
                                            .put("delta_available", true)
                                            .put("delta_base_version", 100L)
                                            .put("delta_base_configs_sha256", configsShaV1)
                                            .toString()
                                        respond(200, "\"v101\"", mf)
                                    }
                                    path.endsWith("top500.delta.json") -> respond(200, "\"d101\"", deltaObjV1ToV2)
                                    // Deliberately omit top500.json in mode 2 to prove delta sync alone succeeded!
                                    else -> respond(404, "", "not found")
                                }
                                3 -> when {
                                    path.endsWith("top500.manifest.json") -> {
                                        val mf = JSONObject()
                                            .put("dataset_version", 102L)
                                            .put("generated_at_epoch", 1_793_390_000L)
                                            .put(
                                                "checksums",
                                                JSONObject()
                                                    .put("top500_json_sha256", "0".repeat(64))
                                                    .put("configs_sha256", "f".repeat(64))
                                            )
                                            .toString()
                                        respond(200, "\"v102\"", mf)
                                    }
                                    path.endsWith("top500.json") -> respond(200, "\"bad\"", "{corrupted-json")
                                    else -> respond(404, "", "not found")
                                }
                                else -> when {
                                    path.endsWith("top500.manifest.json") -> {
                                        val mf = JSONObject()
                                            .put("dataset_version", 99L) // Rollback attempt (< 101)!
                                            .put("generated_at_epoch", 1_793_300_000L)
                                            .put("checksums", JSONObject().put("configs_sha256", configsShaV1))
                                            .toString()
                                        respond(200, "\"v99\"", mf)
                                    }
                                    else -> respond(404, "", "not found")
                                }
                            }
                        }
                    }
                } catch (_: Exception) {
                    break
                }
            }
        }

        try {
            val repo = Repo(
                ctx = ctx,
                mirrorOverride = { file -> listOf("http://127.0.0.1:$port/$file") },
                httpTimeoutMs = 3000,
            )

            // 1. Initial sync of v100 + SHA-256 verification
            val out1 = repo.syncTop500Dataset()
            assertNotNull(out1)
            assertEquals(100L, out1!!.datasetVersion)
            assertEquals(4, out1.qualifiedCount)
            assertTrue(out1.liveSuccess)
            assertTrue(out1.checksumVerified)

            // 2. Second sync with ETag 304 Not Modified
            val out304 = repo.syncTop500Dataset()
            assertNotNull(out304)
            assertTrue(out304!!.notModified304)
            assertTrue(sawEtag304.get() >= 1)

            // 3. Incremental delta update v100 -> v101 without downloading full top500.json!
            mode.set(2)
            val outDelta = repo.syncTop500Dataset()
            assertNotNull(outDelta)
            assertEquals(101L, outDelta!!.datasetVersion)
            assertEquals(5, outDelta.qualifiedCount)
            assertTrue(outDelta.incrementalApplied)
            assertEquals(configsShaV2, outDelta.configsSha256)

            // 4. Corrupted/mismatched checksum on v102 -> recovers last-known-valid v101!
            mode.set(3)
            val outRecovered = repo.syncTop500Dataset()
            assertNotNull(outRecovered)
            assertEquals(101L, outRecovered!!.datasetVersion)
            assertTrue(outRecovered.recoveredFromLastValid)
            assertEquals(5, outRecovered.qualifiedCount)

            // 5. Rollback attempt to v99 -> rejected, keeping v101!
            mode.set(4)
            val outRollback = repo.syncTop500Dataset()
            assertNotNull(outRollback)
            assertTrue(outRollback!!.rollbackRejected)
            assertTrue(outRollback.recoveredFromLastValid)
            assertEquals(101L, outRollback.datasetVersion)
        } finally {
            running.set(false)
            runCatching { server.close() }
            acceptor.join(1000)
        }
    }

    @Test
    fun sequentialScannerEnforcesSingleTunnelSeparatesWifiAndMobileRankingsAndStopsQuickScanEarly() = runBlocking {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val db = ClientDatabase.getInstance(ctx)

        val candidatePool = (1..130).map { buildSampleUri(it, secretToken = "TOPSECRET_PASS_$it") }
        val activeConcurrent = AtomicInteger(0)
        val maxConcurrentObserved = AtomicInteger(0)

        val scanner = SequentialTunnelScanner(
            ctx = ctx,
            clientDb = db,
        ) { req ->
            val nowActive = activeConcurrent.incrementAndGet()
            maxConcurrentObserved.accumulateAndGet(nowActive) { a, b -> maxOf(a, b) }
            try {
                Thread.sleep(1)
                val clean = Converters.cleanUri(req.cfg)
                val idx = candidatePool.indexOfFirst { Converters.cleanUri(it) == clean } + 1
                // On WIFI: servers 1..115 are fast (35..149ms), 116..130 fail -> 100 in Top 100 + 15 in Backup!
                // On MOBILE_DATA: servers 90..130 (41 servers) are blazing fast (28ms, 6500 kbps),
                // 1..65 (65 servers) are slow (950ms, 420 kbps), 66..89 fail -> 106 qualified -> 100 Top + 6 Backup!
                if (req.networkProfile == ScanNetworkProfile.WIFI) {
                    if (idx in 1..115) {
                        TestResult(
                            cfg = clean,
                            ok = true,
                            latencyMs = 30L + idx,
                            speedKbps = 6200.0 - idx * 20.0,
                            establishMs = 180L + idx,
                            jitterMs = 4.5,
                            packetLossPct = 0.0,
                            stabilityScore = 92.0,
                        )
                    } else {
                        TestResult(cfg = clean, ok = false, error = "timeout", packetLossPct = 100.0)
                    }
                } else {
                    when (idx) {
                        in 90..130 -> TestResult(
                            cfg = clean,
                            ok = true,
                            latencyMs = 28L + (idx - 90),
                            speedKbps = 6500.0,
                            establishMs = 160L,
                            jitterMs = 3.0,
                            packetLossPct = 0.0,
                            stabilityScore = 95.0,
                        )
                        in 1..65 -> TestResult(
                            cfg = clean,
                            ok = true,
                            latencyMs = 950L + idx,
                            speedKbps = 420.0,
                            establishMs = 1400L,
                            jitterMs = 42.0,
                            packetLossPct = 12.0,
                            stabilityScore = 58.0,
                        )
                        else -> TestResult(cfg = clean, ok = false, error = "reset", packetLossPct = 100.0)
                    }
                }
            } finally {
                activeConcurrent.decrementAndGet()
            }
        }

        // Launch two concurrent Full Scan calls simultaneously to prove the global scan Mutex
        // NEVER allows overlapping scan runs!
        val (wifiFull, mobileFull) = coroutineScope {
            val a = async {
                scanner.executeScan(
                    scanMode = LocalScanMode.FULL_SCAN,
                    allCandidateConfigs = candidatePool,
                    networkProfile = ScanNetworkProfile.WIFI,
                )
            }
            val b = async {
                scanner.executeScan(
                    scanMode = LocalScanMode.FULL_SCAN,
                    allCandidateConfigs = candidatePool,
                    networkProfile = ScanNetworkProfile.MOBILE_DATA,
                )
            }
            awaitAll(a, b)
        }

        // 1. Strict scan mutex: NEVER more than 1 scan executing at once!
        assertEquals(1, maxConcurrentObserved.get())

        // 2. Full Scan evaluated ALL 130 configurations in the pool
        assertEquals(130, wifiFull.testedCount)
        assertEquals(130, mobileFull.testedCount)

        // 3. WIFI Personalized Top 100 has exactly 100 servers + 15 in Qualified Backup Pool (total 115 qualified on Wi-Fi)
        assertEquals(100, PersonalizedTop50Ranker.PERSONALIZED_TOP_LIMIT)
        val wifiTop100 = db.getPersonalizedRankings(ScanNetworkProfile.WIFI, LocalPoolTier.TOP_50)
        val wifiBackup = db.getPersonalizedRankings(ScanNetworkProfile.WIFI, LocalPoolTier.BACKUP_POOL)
        assertEquals(100, wifiTop100.size)
        assertEquals(15, wifiBackup.size)

        // 4. MOBILE_DATA Personalized Top 100 is COMPLETELY SEPARATE from WIFI!
        // Servers 90..130 (many of which failed on WIFI) are #1..#41 on MOBILE_DATA!
        val mobileTop100 = db.getPersonalizedRankings(ScanNetworkProfile.MOBILE_DATA, LocalPoolTier.TOP_50)
        val mobileBackup = db.getPersonalizedRankings(ScanNetworkProfile.MOBILE_DATA, LocalPoolTier.BACKUP_POOL)
        assertEquals(100, mobileTop100.size)
        assertEquals(6, mobileBackup.size) // 41 fast + 65 slow = 106 qualified -> 100 Top + 6 Backup

        val expectedMobileRank1Id = Converters.stableServerId(candidatePool[89]) // idx=90
        assertEquals(expectedMobileRank1Id, mobileTop100.first().serverId)
        assertFalse(wifiTop100.first().serverId == mobileTop100.first().serverId)

        // 5. Quick Scan on MOBILE_DATA prioritizes recent/Top100, avoids scanning all 130, and stops early at target!
        val mobileQuick = scanner.executeScan(
            scanMode = LocalScanMode.QUICK_SCAN,
            allCandidateConfigs = candidatePool,
            networkProfile = ScanNetworkProfile.MOBILE_DATA,
            isMetered = true,
            quickStopTargetQualified = 15,
        )
        assertTrue(mobileQuick.stoppedEarly)
        assertTrue(mobileQuick.testedCount < candidatePool.size)
        assertEquals(15, mobileQuick.results.size)

        // 6. Append-only historical measurements & ranking history preserved (never overwritten) + zero credential leaks!
        val histSamples = db.getServerScanHistory(expectedMobileRank1Id, ScanNetworkProfile.MOBILE_DATA)
        assertTrue("Expected >=2 append-only samples for #1 server, got ${histSamples.size}", histSamples.size >= 2)
        assertTrue(
            "Config fingerprint must never leak secrets",
            histSamples.all { !it.configFingerprint.contains("TOPSECRET_PASS") }
        )

        val rankSnapshots = db.getRankingHistoryForServer(expectedMobileRank1Id, ScanNetworkProfile.MOBILE_DATA)
        assertTrue("Expected >=2 ranking history snapshots, got ${rankSnapshots.size}", rankSnapshots.size >= 2)

        // 7. Untested Top-500 server NEVER enters Personalized Top 100 even if it existed in central pool
        val neverTestedUri = buildSampleUri(499, secretToken = "UNTESTED_SECRET")
        val bundleWithUntested = PersonalizedTop50Ranker.computeRankings(
            candidateConfigs = listOf(neverTestedUri),
            fingerprintsById = emptyMap(),
            statsById = db.getNetworkStatsMap(ScanNetworkProfile.WIFI),
            profile = ScanNetworkProfile.WIFI,
        )
        assertTrue(bundleWithUntested.top100.isEmpty())
    }

    @Test
    fun batchScannerRunsStage1AndStage2SpeedProbesAndExcludesAllowInsecureBeforeProbing() = runBlocking {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val db = ClientDatabase.getInstance(ctx)

        val cleanPool = (1..120).map { buildSampleUri(it) }
        val insecureUri = "trojan://bad@198.51.100.250:443?security=tls&allowInsecure=1&sni=bad.example.com#bad"
        val fullPool = cleanPool + insecureUri

        val batchCalls = AtomicInteger(0)
        val speedMeasuredCount = AtomicInteger(0)
        val seenUris = HashSet<String>()

        val batchExec = TunnelBatchProbeExecutor { req ->
            batchCalls.incrementAndGet()
            synchronized(seenUris) { seenUris.addAll(req.cfgs.map { Converters.cleanUri(it) }) }
            req.cfgs.mapIndexed { idx, raw ->
                val clean = Converters.cleanUri(raw)
                val globalIdx = cleanPool.indexOfFirst { Converters.cleanUri(it) == clean } + 1
                if (req.measureSpeed) speedMeasuredCount.incrementAndGet()
                if (globalIdx in 1..105) {
                    TestResult(
                        cfg = clean,
                        ok = true,
                        latencyMs = 35L + globalIdx,
                        speedKbps = if (req.measureSpeed) (9_000.0 - globalIdx * 50.0).coerceAtLeast(500.0) else 0.0,
                        establishMs = 120L,
                        jitterMs = 4.0,
                        packetLossPct = 0.0,
                        stabilityScore = 90.0,
                    )
                } else {
                    TestResult(cfg = clean, ok = false, error = "dead", packetLossPct = 100.0)
                }
            }
        }

        val scanner = SequentialTunnelScanner(
            ctx = ctx,
            clientDb = db,
            batchExecutor = batchExec,
        )

        val summary = scanner.executeScan(
            scanMode = LocalScanMode.FULL_SCAN,
            allCandidateConfigs = fullPool,
            networkProfile = ScanNetworkProfile.WIFI,
            isMetered = false,
        )

        // 1. Insecure allowInsecure=1 URI was pre-filtered and NEVER sent to sing-box batch probe (and marked failed for purge)!
        assertFalse(Converters.cleanUri(insecureUri) in seenUris)
        assertTrue(Converters.cleanUri(insecureUri) in summary.failedCleanUris)
        assertEquals(120, summary.testedCount)
        assertEquals(105, summary.aliveCount)
        assertEquals(16, summary.failedCleanUris.size) // 15 dead + 1 pre-filtered allowInsecure=1
        assertFalse(summary.offlineGuardTriggered)

        // 2. Stage 2 real download speed ran on top 30 Wi-Fi finalists and ranked Top 100 speed-first!
        assertEquals(30, speedMeasuredCount.get())
        assertEquals(100, summary.rankingBundle.top100.size)
        assertTrue(summary.results.first().speedKbps > 8_000.0)
    }

    @Test
    fun deadConfigPurgePolicyDeletesDeadConfigsPreservesFavoritesVipOfflineGuardAndTop500Checksum() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val repo = Repo(ctx)

        val pool = (1..25).map { buildSampleUri(it) }
        val cleanPool = pool.map { Converters.cleanUri(it) }
        val favUri = cleanPool[0]   // #1 is Favorite (protected!)
        val vipUri = cleanPool[1]   // #2 is VIP (protected!)
        val deadNormal = cleanPool.subList(2, 10).toSet() // 8 normal dead servers -> MUST be purged!
        val deadAttempted = setOf(favUri, vipUri) + deadNormal

        // A) Normal online scan with 15 alive & 10 failed -> purges the 8 normal dead, protects Favorite & VIP!
        val onlineDecision = DeadConfigPurgePolicy.evaluate(
            currentPool = pool,
            failedUris = deadAttempted,
            testedCount = 25,
            aliveCount = 15,
            deviceOnline = true,
            favoriteCleanUris = setOf(favUri),
            favoriteServerIds = emptySet(),
            vipCleanUris = setOf(vipUri),
        )
        assertTrue(onlineDecision.shouldPurge)
        assertFalse(onlineDecision.offlineGuardTriggered)
        assertEquals(8, onlineDecision.purgeableCleanUris.size)
        assertFalse(favUri in onlineDecision.purgeableCleanUris)
        assertFalse(vipUri in onlineDecision.purgeableCleanUris)
        assertEquals(17, onlineDecision.remainingPool.size)

        // B) Offline Guard #1: 20 tested, 0 alive -> refuses mass wipe!
        val massZeroAliveDecision = DeadConfigPurgePolicy.evaluate(
            currentPool = pool,
            failedUris = cleanPool.take(20).toSet(),
            testedCount = 20,
            aliveCount = 0,
            deviceOnline = true,
            favoriteCleanUris = emptySet(),
            favoriteServerIds = emptySet(),
            vipCleanUris = emptySet(),
        )
        assertFalse(massZeroAliveDecision.shouldPurge)
        assertTrue(massZeroAliveDecision.offlineGuardTriggered)
        assertEquals(25, massZeroAliveDecision.remainingPool.size)

        // C) Offline Guard #2: deviceOnline = false -> refuses deletion even for 1 failed server!
        val deviceOfflineDecision = DeadConfigPurgePolicy.evaluate(
            currentPool = pool,
            failedUris = setOf(cleanPool[5]),
            testedCount = 1,
            aliveCount = 0,
            deviceOnline = false,
            favoriteCleanUris = emptySet(),
            favoriteServerIds = emptySet(),
            vipCleanUris = emptySet(),
        )
        assertFalse(deviceOfflineDecision.shouldPurge)
        assertTrue(deviceOfflineDecision.offlineGuardTriggered)

        // D) Per-Network Purged-Dead ledger cleans WIFI cache & exported files WITHOUT affecting MOBILE_DATA or top500.last_valid.json!
        repo.writeAll(pool)
        repo.writeBest(pool.take(10).mapIndexed { i, c -> ResultLine(c, 50L + i, 3000.0, System.currentTimeMillis()) }, 100)
        repo.recordPurgedDeadAndCleanFiles(
            profile = ScanNetworkProfile.WIFI,
            purgeableCleanUris = onlineDecision.purgeableCleanUris,
            remainingPool = onlineDecision.remainingPool,
            bestLimit = 100,
        )
        val wifiPurgedIds = repo.getActivePurgedDeadServerIds(ScanNetworkProfile.WIFI)
        val mobilePurgedIds = repo.getActivePurgedDeadServerIds(ScanNetworkProfile.MOBILE_DATA)
        assertEquals(8, wifiPurgedIds.size)
        assertTrue(mobilePurgedIds.isEmpty())

        // Clearing WIFI ledger on fresh 3h remote sync restores clean slate
        repo.clearPurgedDeadForProfile(ScanNetworkProfile.WIFI)
        assertTrue(repo.getActivePurgedDeadServerIds(ScanNetworkProfile.WIFI).isEmpty())
    }

    @Test
    fun unified45_30_25FormulaGivesZeroCreditForUnmeasuredSpeedAndHardExcludesAllowInsecure() {
        val now = 1_793_400_000_000L

        // Verify unified 45% Download / 30% Stability / 25% Latency+Jitter constants
        assertEquals(0.45, CentralScoringWeights.THROUGHPUT_WEIGHT, 0.0001)
        assertEquals(0.30, CentralScoringWeights.STABILITY_WEIGHT, 0.0001)
        assertEquals(0.25, CentralScoringWeights.PING_JITTER_WEIGHT, 0.0001)

        val defaultWeights = SmartSelectionWeights().normalized()
        assertEquals(0.45, defaultWeights.downloadSpeed, 0.0001)
        assertEquals(
            0.30,
            defaultWeights.connectionReliability + defaultWeights.packetLoss +
                defaultWeights.historicalUptime + defaultWeights.recentStability,
            0.0001,
        )
        assertEquals(0.25, defaultWeights.latency + defaultWeights.jitter, 0.0001)

        // High download throughput (6500 KB/s, 95ms) MUST beat ping-only (0 KB/s, 25ms) across ServerRanker & SmartServerSelector!
        val fastRealThroughput = RankableServer(
            cfg = buildSampleUri(1),
            latencyMs = 95L,
            jitterMs = 6.0,
            speedKbps = 6500.0,
            stabilityRuns = 4,
            locallyTested = true,
            lastTestedAtMs = now - 10_000L,
        )
        val lowPingZeroSpeed = RankableServer(
            cfg = buildSampleUri(2),
            latencyMs = 25L,
            jitterMs = 2.0,
            speedKbps = 0.0,
            stabilityRuns = 4,
            locallyTested = true,
            lastTestedAtMs = now - 10_000L,
        )
        val fastScore = ServerRanker.computeOverallScore(fastRealThroughput, now)
        val zeroSpeedScore = ServerRanker.computeOverallScore(lowPingZeroSpeed, now)
        assertTrue("Expected real throughput ($fastScore) > 0 KB/s ping-only ($zeroSpeedScore)", fastScore > zeroSpeedScore)
        assertTrue("0 KB/s server must cap <= 55.0 under 45/30/25 weights, got $zeroSpeedScore", zeroSpeedScore <= 55.0)

        // Hard Security Exclusion: allowInsecure=1 URI MUST NEVER be selected as primary or fallback!
        val insecureCandidate = SmartServerCandidateInput(
            cfg = "vless://11111111-1111-1111-1111-111111111111@bad.example.com:443?security=tls&allowInsecure=1&sni=bad.example.com",
            label = "InsecureFast",
            locallyTested = true,
            localLatencyMs = 15L,
            localDownloadKbps = 50_000.0,
        )
        val safeCandidate = SmartServerCandidateInput(
            cfg = buildSampleUri(3),
            label = "SafeVerified",
            locallyTested = true,
            localLatencyMs = 85L,
            localDownloadKbps = 4_200.0,
        )
        val decision = SmartServerSelector.selectBestAndFallback(
            candidates = listOf(insecureCandidate, safeCandidate),
            nowMs = now,
        )
        assertNotNull(decision.primary)
        assertEquals("SafeVerified", decision.primary!!.label)
        assertNull(decision.fallback) // Insecure candidate must NEVER be selected even as fallback!
        val insecureEval = decision.allRanked.first { it.label == "InsecureFast" }
        assertTrue(insecureEval.excludedSecurity)
        assertEquals(0.0, insecureEval.score, 0.0001)
    }

    @Test
    fun workSchedulerConfiguresThreeHourIntervalAndPrefsHonorsOptOut() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val prefs = Prefs(ctx)

        assertEquals(3L, WorkScheduler.PERIOD_HOURS)
        assertEquals("bahrain_vpn_quality_refresh_3h", WorkScheduler.UNIQUE_WORK_NAME)

        // Default is enabled (true) and synced with autoRefresh
        prefs.autoServerQualityTesting = true
        assertTrue(prefs.autoServerQualityTesting)
        assertTrue(prefs.autoRefresh)

        // Disabling cancels periodic testing while preserving synced preference state
        prefs.autoServerQualityTesting = false
        assertFalse(prefs.autoServerQualityTesting)
        assertFalse(prefs.autoRefresh)
        prefs.autoServerQualityTesting = true
    }
}
