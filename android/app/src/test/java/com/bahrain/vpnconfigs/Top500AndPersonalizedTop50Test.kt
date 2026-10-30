package com.bahrain.vpnconfigs

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.bahrain.vpnconfigs.data.ClientDatabase
import com.bahrain.vpnconfigs.data.LocalPoolTier
import com.bahrain.vpnconfigs.data.Repo
import com.bahrain.vpnconfigs.data.ScanNetworkProfile
import com.bahrain.vpnconfigs.data.Top500ServerEntry
import com.bahrain.vpnconfigs.engine.Converters
import com.bahrain.vpnconfigs.engine.LocalScanMode
import com.bahrain.vpnconfigs.engine.PersonalizedTop50Ranker
import com.bahrain.vpnconfigs.engine.SequentialTunnelScanner
import com.bahrain.vpnconfigs.engine.TestResult
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
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
        val port = 443 + (index % 5)
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

        val candidatePool = (1..85).map { buildSampleUri(it, secretToken = "TOPSECRET_PASS_$it") }
        val activeConcurrent = AtomicInteger(0)
        val maxConcurrentObserved = AtomicInteger(0)

        val scanner = SequentialTunnelScanner(
            ctx = ctx,
            clientDb = db,
        ) { req ->
            val nowActive = activeConcurrent.incrementAndGet()
            maxConcurrentObserved.accumulateAndGet(nowActive) { a, b -> maxOf(a, b) }
            try {
                Thread.sleep(2)
                val clean = Converters.cleanUri(req.cfg)
                val idx = candidatePool.indexOfFirst { Converters.cleanUri(it) == clean } + 1
                // On WIFI: servers 1..65 are fast (35..99ms), 66..85 fail
                // On MOBILE_DATA: servers 60..85 are blazing fast (28ms, 6500 kbps), 1..30 are slow (950ms), 31..59 fail!
                if (req.networkProfile == ScanNetworkProfile.WIFI) {
                    if (idx in 1..65) {
                        TestResult(
                            cfg = clean,
                            ok = true,
                            latencyMs = 30L + idx,
                            speedKbps = 5200.0 - idx * 20.0,
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
                        in 60..85 -> TestResult(
                            cfg = clean,
                            ok = true,
                            latencyMs = 28L + (idx - 60),
                            speedKbps = 6500.0,
                            establishMs = 160L,
                            jitterMs = 3.0,
                            packetLossPct = 0.0,
                            stabilityScore = 95.0,
                        )
                        in 1..30 -> TestResult(
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

        // Launch two concurrent Full Scan / Quick Scan calls simultaneously to prove the global sequential Mutex
        // NEVER allows more than 1 tunnel test at a time!
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

        // 1. Strict sequentiality: NEVER more than 1 tunnel tested at once!
        assertEquals(1, maxConcurrentObserved.get())

        // 2. Full Scan evaluated ALL 85 configurations in the pool
        assertEquals(85, wifiFull.testedCount)
        assertEquals(85, mobileFull.testedCount)

        // 3. WIFI Personalized Top 50 has exactly 50 servers + 15 in Qualified Backup Pool (total 65 qualified on Wi-Fi)
        val wifiTop50 = db.getPersonalizedRankings(ScanNetworkProfile.WIFI, LocalPoolTier.TOP_50)
        val wifiBackup = db.getPersonalizedRankings(ScanNetworkProfile.WIFI, LocalPoolTier.BACKUP_POOL)
        assertEquals(50, wifiTop50.size)
        assertEquals(15, wifiBackup.size)

        // 4. MOBILE_DATA Personalized Top 50 is COMPLETELY SEPARATE from WIFI!
        // Servers 60..85 (which failed or ranked >50 on WIFI) are #1..#26 on MOBILE_DATA!
        val mobileTop50 = db.getPersonalizedRankings(ScanNetworkProfile.MOBILE_DATA, LocalPoolTier.TOP_50)
        val mobileBackup = db.getPersonalizedRankings(ScanNetworkProfile.MOBILE_DATA, LocalPoolTier.BACKUP_POOL)
        assertEquals(50, mobileTop50.size)
        assertEquals(6, mobileBackup.size) // 26 fast + 30 slow = 56 qualified -> 50 Top + 6 Backup

        val expectedMobileRank1Id = Converters.stableServerId(candidatePool[59]) // idx=60
        assertEquals(expectedMobileRank1Id, mobileTop50.first().serverId)
        assertFalse(wifiTop50.first().serverId == mobileTop50.first().serverId)

        // 5. Quick Scan on MOBILE_DATA prioritizes recent/Top50, avoids scanning all 85, and stops early at target!
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

        // 7. Untested Top-500 server NEVER enters Personalized Top 50 even if it existed in central pool
        val neverTestedUri = buildSampleUri(499, secretToken = "UNTESTED_SECRET")
        val bundleWithUntested = PersonalizedTop50Ranker.computeRankings(
            candidateConfigs = listOf(neverTestedUri),
            fingerprintsById = emptyMap(),
            statsById = db.getNetworkStatsMap(ScanNetworkProfile.WIFI),
            profile = ScanNetworkProfile.WIFI,
        )
        assertTrue(bundleWithUntested.top50.isEmpty())
    }
}
