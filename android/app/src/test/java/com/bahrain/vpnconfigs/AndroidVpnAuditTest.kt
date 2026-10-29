package com.bahrain.vpnconfigs

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.bahrain.vpnconfigs.data.Prefs
import com.bahrain.vpnconfigs.data.Repo
import com.bahrain.vpnconfigs.data.ResultLine
import com.bahrain.vpnconfigs.engine.Converters
import com.bahrain.vpnconfigs.engine.RankableServer
import com.bahrain.vpnconfigs.engine.ServerRanker
import com.bahrain.vpnconfigs.engine.ServerSortMode
import com.bahrain.vpnconfigs.engine.SingBox
import com.bahrain.vpnconfigs.util.AppDiag
import com.bahrain.vpnconfigs.util.UiMessages
import com.sun.net.httpserver.HttpServer
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
import java.net.InetSocketAddress
import java.util.Base64
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class AndroidVpnAuditTest {

    @Test
    fun defaultSortModeIsFastestDownload() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val prefs = Prefs(ctx)
        assertEquals(ServerSortMode.FASTEST_DOWNLOAD, ServerSortMode.DEFAULT)
        assertEquals("FASTEST_DOWNLOAD", prefs.sortMode)
        assertEquals("الأسرع في التنزيل", ServerSortMode.DEFAULT.titleAr)
    }

    @Test
    fun allFiveSortModesRankAccuratelyAndNeverInventSpeedFromPing() {
        val now = 1_760_000_000_000L

        val fastDownload = RankableServer(
            cfg = "vless://11111111-1111-1111-1111-111111111111@198.51.100.10:443?security=tls#a",
            latencyMs = 140L,
            speedKbps = 8200.0, // ~8 MB/s مقاسة فعليًا عبر النفق
            stabilityRuns = 2,
            jitterMs = 18.0,
            locallyTested = true,
            lastTestedAtMs = now - 60_000L,
        )
        val lowestPingNoSpeed = RankableServer(
            cfg = "vless://22222222-2222-2222-2222-222222222222@198.51.100.20:443?security=tls#b",
            latencyMs = 45L,
            speedKbps = 0.0, // Ping فقط — لم تُقس سرعة التنزيل عبر النفق
            stabilityRuns = 1,
            locallyTested = true,
            lastTestedAtMs = now - 120_000L,
        )
        val mostStable = RankableServer(
            cfg = "trojan://secret@198.51.100.30:443?sni=example.com#c",
            latencyMs = 110L,
            speedKbps = 2400.0,
            stabilityRuns = 6,
            jitterMs = 4.0,
            locallyTested = true,
            lastTestedAtMs = now - 300_000L,
        )
        val newestTested = RankableServer(
            cfg = "hy2://pass@198.51.100.40:443?sni=example.com#d",
            latencyMs = 190L,
            speedKbps = 1500.0,
            stabilityRuns = 2,
            locallyTested = true,
            lastTestedAtMs = now - 5_000L,
        )
        val deadServer = RankableServer(
            cfg = "ss://YWVzLTI1Ni1nY206cGFzcw==@198.51.100.50:8388#e",
            latencyMs = -1L,
            speedKbps = 0.0,
            localFailed = true,
            lastTestedAtMs = now - 1_000L,
        )

        val all = listOf(lowestPingNoSpeed, deadServer, mostStable, newestTested, fastDownload)

        // 1) الأسرع في التنزيل: يعتمد على سرعة التنزيل الفعلية عبر النفق ولا يرفع عقدة Ping فقط فوق المقاسة سرعتها
        val byDownload = all.sortedWith(ServerRanker.comparatorFor(ServerSortMode.FASTEST_DOWNLOAD, now))
        assertEquals(fastDownload.cfg, byDownload.first().cfg)
        assertEquals(deadServer.cfg, byDownload.last().cfg)
        val idxPingOnly = byDownload.indexOfFirst { it.cfg == lowestPingNoSpeed.cfg }
        val idxMeasured = byDownload.indexOfFirst { it.cfg == newestTested.cfg }
        assertTrue("السيرفر المقاس تنزيله عبر النفق يجب أن يسبق غير المقاس", idxMeasured < idxPingOnly)

        // 2) الأقل تأخيرًا
        val byLatency = all.sortedWith(ServerRanker.comparatorFor(ServerSortMode.LOWEST_LATENCY, now))
        assertEquals(lowestPingNoSpeed.cfg, byLatency.first().cfg)
        assertEquals(deadServer.cfg, byLatency.last().cfg)

        // 3) الأكثر استقرارًا
        val byStability = all.sortedWith(ServerRanker.comparatorFor(ServerSortMode.MOST_STABLE, now))
        assertEquals(mostStable.cfg, byStability.first().cfg)

        // 4) الأفضل إجمالًا (50% تنزيل + 20% تأخير + 20% استقرار + 10% نجاح اتصال)
        val byOverall = all.sortedWith(ServerRanker.comparatorFor(ServerSortMode.BEST_OVERALL, now))
        assertEquals(fastDownload.cfg, byOverall.first().cfg)
        assertEquals(0.0, ServerRanker.computeOverallScore(deadServer, now), 0.001)
        assertTrue(
            "عقدة بدون قياس تنزيل لا يجوز أن تتجاوز 50 نقطة لأن وزن السرعة المفقود لا يُختلق",
            ServerRanker.computeOverallScore(lowestPingNoSpeed, now) <= 50.0,
        )

        // 5) الأحدث اختبارًا
        val byRecent = all.sortedWith(ServerRanker.comparatorFor(ServerSortMode.RECENTLY_TESTED, now))
        assertEquals(newestTested.cfg, byRecent.first().cfg)
    }

    @Test
    fun overallScoreDecaysStaleDataAndReturnsZeroWhenCompletelyUnmeasured() {
        val now = 1_760_000_000_000L
        val unmeasured = RankableServer(cfg = "vless://11111111-1111-1111-1111-111111111111@198.51.100.99:443")
        assertEquals(0.0, ServerRanker.computeOverallScore(unmeasured, now), 0.001)

        val fresh = RankableServer(
            cfg = "vless://11111111-1111-1111-1111-111111111111@198.51.100.11:443",
            latencyMs = 90L,
            speedKbps = 4096.0,
            stabilityRuns = 4,
            jitterMs = 8.0,
            locallyTested = true,
            lastTestedAtMs = now - 60_000L,
        )
        val stale60h = fresh.copy(lastTestedAtMs = now - 60L * 3600L * 1000L)
        val freshScore = ServerRanker.computeOverallScore(fresh, now)
        val staleScore = ServerRanker.computeOverallScore(stale60h, now)
        assertTrue("القياس الحديث يجب أن يتفوق على القياس القديم المتقادم", freshScore > staleScore)
        assertEquals(freshScore * 0.70, staleScore, 0.05)
    }

    @Test
    fun reSortingNeverChangesActiveConnectedServer() {
        val activeConnected = "trojan://active-pass@198.51.100.77:443?sni=example.org"
        val sortedList = listOf(
            "vless://11111111-1111-1111-1111-111111111111@198.51.100.10:443?security=tls",
            "hy2://fast@198.51.100.20:443?sni=example.org",
            activeConnected,
        )
        for (mode in ServerSortMode.entries) {
            val resolved = ServerRanker.resolveSelectedPreservingActive(
                currentSelectedCfg = sortedList.first(),
                activeVpnCfg = activeConnected,
                isVpnActive = true,
                sortedConfigs = sortedList,
            )
            assertEquals("وضع ${mode.key} يجب ألا يغيّر السيرفر المتصل به", activeConnected, resolved)
        }
    }

    @Test
    fun repoFetchesLiveMirrorsHandlesEtagIgnoresCorruptAndUsesCacheSafelyOnFailure() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val serveSuccess = AtomicBoolean(true)
        val sawIfNoneMatch = AtomicInteger(0)

        val validVless = "vless://11111111-1111-1111-1111-111111111111@198.51.100.15:443?security=tls&type=ws&path=%2Fws#node1"
        val validTrojan = "trojan://mypassword@203.0.113.25:443?security=tls&sni=example.com#node2"
        val unsafeLoopback = "vless://11111111-1111-1111-1111-111111111111@127.0.0.1:443?security=tls#bad"
        val corruptedVmess = "vmess://@@@not-valid-base64@@@"

        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val port = server.address.port

        server.createContext("/dead/") { ex ->
            ex.sendResponseHeaders(503, -1)
            ex.close()
        }
        server.createContext("/live/meta.json") { ex ->
            if (!serveSuccess.get()) {
                ex.sendResponseHeaders(500, -1)
                ex.close()
                return@createContext
            }
            val body = """{"generated_at":"2026-10-29T21:00:00Z","alive":2,"tested":10}""".toByteArray()
            ex.responseHeaders.add("ETag", "\"m1\"")
            ex.sendResponseHeaders(200, body.size.toLong())
            ex.responseBody.use { it.write(body) }
        }
        server.createContext("/live/alive.json") { ex ->
            if (!serveSuccess.get()) {
                ex.sendResponseHeaders(502, -1)
                ex.close()
                return@createContext
            }
            val inm = ex.requestHeaders.getFirst("If-None-Match")
            if (inm == "\"v1\"") {
                sawIfNoneMatch.incrementAndGet()
                ex.responseHeaders.add("ETag", "\"v1\"")
                ex.sendResponseHeaders(304, -1)
                ex.close()
                return@createContext
            }
            val payload = """
                {
                  "generated_at": "2026-10-29T21:00:00Z",
                  "count": 4,
                  "servers": [
                    {"cfg": "$validVless", "median_latency_ms": 95, "speed_kbps": 3500.0, "score": 84.0, "exit_country": "NL", "stability_runs": 4, "verified_at": "2026-10-29T21:00:00Z"},
                    {"cfg": "$validTrojan", "median_latency_ms": 120, "speed_kbps": 2100.0, "score": 78.0, "exit_country": "DE", "stability_runs": 3, "verified_at": "2026-10-29T20:55:00Z"},
                    {"cfg": "$unsafeLoopback", "median_latency_ms": 5, "speed_kbps": 9999.0},
                    {"cfg": "$corruptedVmess", "median_latency_ms": 50}
                  ]
                }
            """.trimIndent().toByteArray(Charsets.UTF_8)
            ex.responseHeaders.add("ETag", "\"v1\"")
            ex.sendResponseHeaders(200, payload.size.toLong())
            ex.responseBody.use { it.write(payload) }
        }
        server.start()

        try {
            val repo = Repo(
                ctx = ctx,
                mirrorOverride = { file ->
                    listOf(
                        "http://127.0.0.1:$port/dead/$file", // المرآة الأولى تفشل -> يختبر إعادة المحاولة للمرآة البديلة
                        "http://127.0.0.1:$port/live/$file",
                    )
                },
                httpTimeoutMs = 3000,
            )

            // 1) جلب حي ناجح بعد تخطي المرآة الأولى الفاشلة وتصفية البيانات التالفة وغير الآمنة
            val res1 = repo.loadRemote("smart")
            assertNull(res1.error)
            assertFalse(res1.fromCacheFallback)
            assertEquals("remote", res1.source)
            assertEquals(2, res1.configs.size)
            assertFalse(res1.configs.any { it.contains("127.0.0.1") })

            // 2) تحديث ثانٍ يتحقق من عمل ETag / 304 Not Modified
            val res2 = repo.loadRemote("smart")
            assertNull(res2.error)
            assertFalse(res2.fromCacheFallback)
            assertTrue(sawIfNoneMatch.get() >= 1)
            assertEquals(2, res2.configs.size)

            // 3) انقطاع المصدر بالكامل: يعيد البيانات المخزنة مؤقتًا مع إبلاغ صادق بفشل التحديث دون نجاح مضلل
            serveSuccess.set(false)
            val resOffline = repo.loadRemote("smart")
            assertEquals(2, resOffline.configs.size)
            assertTrue(resOffline.fromCacheFallback)
            assertEquals(UiMessages.MSG_UPDATE_FAILED, resOffline.error)

            // 4) حفظ واسترجاع نتائج الاختبار مع الطابع الزمني testedAtMs
            repo.writeBest(
                listOf(ResultLine(res1.configs[0], latencyMs = 88L, speedKbps = 4200.0, testedAtMs = 1_760_000_123_000L)),
                limit = 10,
            )
            val saved = repo.loadSavedBest()
            assertEquals(1, saved.size)
            assertEquals(1_760_000_123_000L, saved[0].testedAtMs)
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun singBoxConfigBuilderSupportsAllProtocolsAndRejectsUnsafeTargets() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val sb = SingBox(ctx)

        val vmessJson = JSONObject()
            .put("v", "2")
            .put("ps", "node")
            .put("add", "198.51.100.42")
            .put("port", "443")
            .put("id", "33333333-3333-3333-3333-333333333333")
            .put("aid", "0")
            .put("net", "ws")
            .put("path", "/ws")
            .put("tls", "tls")
            .toString()
        val vmessUri = "vmess://" + Base64.getEncoder().encodeToString(vmessJson.toByteArray(Charsets.UTF_8))

        val validSamples = listOf(
            "vless://11111111-1111-1111-1111-111111111111@198.51.100.10:443?security=reality&pbk=testkey&sid=01&type=tcp&sni=www.microsoft.com",
            vmessUri,
            "trojan://pass123@198.51.100.11:443?security=tls&sni=example.com",
            "ss://YWVzLTI1Ni1nY206c2VjcmV0@198.51.100.12:8388",
            "hy2://hy2pass@198.51.100.13:443?sni=example.com",
            "tuic://44444444-4444-4444-4444-444444444444:tuicpass@198.51.100.14:443?congestion_control=bbr&sni=example.com",
        )
        for (uri in validSamples) {
            assertTrue("يجب دعم الكونفيغ الصالح: $uri", Converters.isSupported(uri))
            val built = sb.buildConfig(uri, port = 20808, dnsServer = "1.1.1.1", useDoh = false)
            assertNotNull("يجب توليد إعداد محرّك VPN صالح", built)
            val parsed = JSONObject(built!!)
            assertEquals(20808, parsed.getJSONArray("inbounds").getJSONObject(0).getInt("listen_port"))
        }

        // رفض عناوين الشبكة الداخلية والبيانات التالفة
        assertFalse(Converters.isSupported("vless://11111111-1111-1111-1111-111111111111@192.168.1.1:443?security=tls"))
        assertFalse(Converters.isSupported("trojan://pass@localhost:443"))
        assertNull(sb.buildConfig("vmess://broken!!!", port = 20808))
    }

    @Test
    fun uiMessagesAndAppDiagHideAllRepositoryUrlsPathsExceptionsAndSecrets() {
        val technicalInputs = listOf(
            "java.io.FileNotFoundException: https://raw.githubusercontent.com/${Repo.DEFAULT_OWNER}/${Repo.DEFAULT_REPO}/data/alive.json",
            "Unable to resolve host cdn.jsdelivr.net: No address associated with hostname",
            "SocketTimeoutException at com.bahrain.vpnconfigs.engine.Socks.openTunnelSocket(Socks.kt:42)",
            "Missing /data/user/0/com.bahrain.vpnconfigs/lib/libsingbox.so",
            "Failed reading cache:alive.txt or best100.txt",
        )
        for (raw in technicalInputs) {
            val clean = UiMessages.sanitizeError(raw)
            assertEquals(UiMessages.MSG_UPDATE_FAILED, clean)
            assertFalse(clean.contains("github", ignoreCase = true))
            assertFalse(clean.contains("jsdelivr", ignoreCase = true))
            assertFalse(clean.contains(Repo.DEFAULT_OWNER, ignoreCase = true))
            assertFalse(clean.contains(Repo.DEFAULT_REPO, ignoreCase = true))
            assertFalse(clean.contains("Exception", ignoreCase = true))
        }

        val redacted = AppDiag.redactSecrets(
            "Testing vless://secret-uuid-9999@198.51.100.20:443?pbk=privkey#tag and trojan://mySecretPass@198.51.100.21:443"
        )
        assertFalse(redacted.contains("secret-uuid-9999"))
        assertFalse(redacted.contains("mySecretPass"))
        assertFalse(redacted.contains("privkey"))
        assertTrue(redacted.contains("[REDACTED]"))
    }
}
