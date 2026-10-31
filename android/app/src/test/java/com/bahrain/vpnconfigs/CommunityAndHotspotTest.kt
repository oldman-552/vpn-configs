package com.bahrain.vpnconfigs

import android.content.Context
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import com.bahrain.vpnconfigs.community.CommunityConfigProbe
import com.bahrain.vpnconfigs.community.CommunityTestingManager
import com.bahrain.vpnconfigs.community.OriginCountryDetector
import com.bahrain.vpnconfigs.community.OriginVerificationResult
import com.bahrain.vpnconfigs.data.ClientDatabase
import com.bahrain.vpnconfigs.data.Prefs
import com.bahrain.vpnconfigs.data.Repo
import com.bahrain.vpnconfigs.engine.Converters
import com.bahrain.vpnconfigs.engine.SecurityEvaluator
import com.bahrain.vpnconfigs.engine.SingBox
import com.bahrain.vpnconfigs.engine.TestResult
import com.bahrain.vpnconfigs.hotspot.DetectedHotspotInterface
import com.bahrain.vpnconfigs.hotspot.VpnHotspotManager
import com.bahrain.vpnconfigs.hotspot.VpnHotspotProxyServer
import kotlinx.coroutines.runBlocking
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
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class CommunityAndHotspotTest {

    @Test(timeout = 20_000L)
    fun socksAndHttpProxyProtocolsConvertSafelyAndRedactSecrets() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val sb = SingBox(ctx)

        val socksAuth = "socks5://myuser:superSecretSocksPass@198.51.100.30:1080#SocksNode"
        val socksOpen = "socks://198.51.100.31:1080#OpenSocks"
        val httpPlain = "http://huser:httpPass42@198.51.100.32:8080#HttpProxy"
        val httpsTls = "https://tuser:tlsPass99@edge.example.com:8443?sni=edge.example.com#HttpsProxy"

        for (uri in listOf(socksAuth, socksOpen, httpPlain, httpsTls)) {
            assertTrue("Expected supported: $uri", Converters.isSupported(uri))
            val built = sb.buildConfig(uri, port = 20808)
            assertNotNull("Expected valid sing-box config for $uri", built)
            val fp = Converters.configFingerprint(uri)
            val sid = Converters.stableServerId(uri)
            assertFalse(fp.contains("superSecretSocksPass"))
            assertFalse(fp.contains("httpPass42"))
            assertFalse(fp.contains("tlsPass99"))
            assertFalse(sid.contains("myuser"))
        }

        assertEquals("SOCKS5", Converters.protocolBadge(socksAuth))
        assertEquals("HTTP", Converters.protocolBadge(httpPlain))
        assertEquals("HTTPS", Converters.protocolBadge(httpsTls))

        // Ordinary web URLs and private/loopback proxies must be rejected
        assertFalse(Converters.isSupported("https://example.com/some/path"))
        assertFalse(Converters.isSupported("http://example.com"))
        assertFalse(Converters.isSupported("socks5://192.168.1.1:1080"))

        // Honest transport security classification
        val plainEval = SecurityEvaluator.evaluate(socksAuth, isVipAttested = false)
        assertEquals("Failed", plainEval.securityAssessment)
        assertEquals("HIGH", plainEval.riskLevel)

        val tlsEval = SecurityEvaluator.evaluate(httpsTls, isVipAttested = false)
        assertEquals("Verified", tlsEval.securityAssessment)
        assertEquals("LOW", tlsEval.riskLevel)
    }

    @Test(timeout = 20_000L)
    fun communityTestingIsOptInOnlyVerifiesIranOriginUploadsSecretFreeReportsAndRespectsHotspot() = runBlocking {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        ctx.getSharedPreferences("settings", Context.MODE_PRIVATE).edit().clear().commit()
        val prefs = Prefs(ctx)
        val db = ClientDatabase.getInstance(ctx)
        db.clearAllCommunityReports()

        val configs = listOf(
            "vless://11111111-1111-1111-1111-111111111111@198.51.100.51:443?security=tls&sni=edge.example.com#n1",
            "hy2://secretHy2Pass@198.51.100.52:443?sni=hy2.example.com#n2",
            "socks5://suser:spass@198.51.100.53:1080#n3",
        )

        // 1. Default state MUST be strictly OFF — running without consent returns empty immediately
        assertFalse(prefs.communityTestingEnabled)
        val noConsentRes = CommunityTestingManager.runCommunityTestBatch(
            ctx = ctx,
            candidateConfigs = configs,
            originDetector = OriginCountryDetector { OriginVerificationResult("IR", "VERIFIED_DIRECT_IP", false, "WIFI") },
            configProbe = CommunityConfigProbe { _, c, _, _ -> TestResult(c, ok = true, latencyMs = 80L) },
            ignoreBatteryCheckForTest = true,
        )
        assertTrue(noConsentRes.isEmpty())

        // 2. Grant explicit opt-in consent, test VPN interference rejection first
        CommunityTestingManager.grantConsent(ctx)
        assertTrue(prefs.communityTestingEnabled)
        val initialSalt = prefs.communityInstallSalt

        val vpnInterferedRes = CommunityTestingManager.runCommunityTestBatch(
            ctx = ctx,
            candidateConfigs = configs,
            originDetector = OriginCountryDetector { OriginVerificationResult("IR", "VPN_INTERFERENCE", true, "WIFI") },
            configProbe = CommunityConfigProbe { _, c, _, _ -> TestResult(c, ok = true, latencyMs = 80L) },
            ignoreBatteryCheckForTest = true,
        )
        assertTrue("VPN-interfered test must NOT record fake IR reports", vpnInterferedRes.isEmpty())

        // 3. Start local mock ingest gateway to verify privacy-minimal upload
        val capturedPayload = AtomicReference("")
        val runningIngest = AtomicBoolean(true)
        val ingestSrv = ServerSocket(0, 16, InetAddress.getByName("127.0.0.1"))
        val ingestPort = ingestSrv.localPort
        val ingestThread = thread(isDaemon = true) {
            while (runningIngest.get()) {
                try {
                    val accepted = ingestSrv.accept()
                    thread(isDaemon = true) {
                        accepted.use { s ->
                            s.soTimeout = 3000
                            val rawIn = s.getInputStream()
                            fun readHeaderLine(): String {
                                val sb = StringBuilder()
                                while (true) {
                                    val ch = rawIn.read()
                                    if (ch < 0 || ch == '\n'.code) break
                                    if (ch != '\r'.code) sb.append(ch.toChar())
                                }
                                return sb.toString()
                            }
                            var contentLen = 0
                            while (true) {
                                val line = readHeaderLine()
                                if (line.isEmpty()) break
                                if (line.startsWith("Content-Length:", ignoreCase = true)) {
                                    contentLen = line.substringAfter(":").trim().toIntOrNull() ?: 0
                                }
                            }
                            val bodyBytes = ByteArray(contentLen)
                            var off = 0
                            while (off < contentLen) {
                                val r = rawIn.read(bodyBytes, off, contentLen - off)
                                if (r < 0) break
                                off += r
                            }
                            capturedPayload.set(String(bodyBytes, 0, off, Charsets.UTF_8))
                            val resp = """{"status":"accepted","accepted_count":3}""".toByteArray(Charsets.UTF_8)
                            val hdr = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${resp.size}\r\nConnection: close\r\n\r\n"
                            s.getOutputStream().write(hdr.toByteArray(Charsets.UTF_8))
                            s.getOutputStream().write(resp)
                            s.getOutputStream().flush()
                        }
                    }
                } catch (_: Exception) {
                    if (!runningIngest.get()) break
                }
            }
        }

        try {
            prefs.communityEndpointOverride = "http://127.0.0.1:$ingestPort"
            val verifiedIrRes = CommunityTestingManager.runCommunityTestBatch(
                ctx = ctx,
                candidateConfigs = configs,
                originDetector = OriginCountryDetector { OriginVerificationResult("IR", "VERIFIED_DIRECT_IP", false, "WIFI") },
                configProbe = CommunityConfigProbe { _, c, _, _ ->
                    TestResult(
                        cfg = c,
                        ok = true,
                        latencyMs = 92L,
                        speedKbps = 3400.0,
                        establishMs = 210L,
                        stabilityScore = 91.0,
                    )
                },
                ignoreBatteryCheckForTest = true,
            )
            assertEquals(3, verifiedIrRes.size)
            assertTrue(verifiedIrRes.all { it.verifiedCountry == "IR" && !it.vpnInterference })

            // Verify uploaded JSON contains ZERO raw URIs or passwords
            val uploadedRaw = capturedPayload.get()
            assertTrue(uploadedRaw.isNotBlank())
            assertFalse(uploadedRaw.contains("://"))
            assertFalse(uploadedRaw.contains("secretHy2Pass"))
            assertFalse(uploadedRaw.contains("spass"))
            val parsedUpload = JSONObject(uploadedRaw)
            assertEquals(3, parsedUpload.getJSONArray("reports").length())
            assertEquals(0, db.listPendingCommunityReports().size)

            // 4. Verify community testing refuses to run when VPN Hotspot sharing is active!
            VpnHotspotManager.startHotspotSharing(
                ctx = ctx,
                interfaceOverrideForTest = DetectedHotspotInterface("127.0.0.1", "127.0.0.1", true, "AP", "AP"),
                upstreamVerifiedOverrideForTest = { true },
            )
            val blockedByHotspot = CommunityTestingManager.runCommunityTestBatch(
                ctx = ctx,
                candidateConfigs = configs,
                originDetector = OriginCountryDetector { OriginVerificationResult("IR", "VERIFIED_DIRECT_IP", false, "WIFI") },
                configProbe = CommunityConfigProbe { _, c, _, _ -> TestResult(c, ok = true, latencyMs = 50L) },
                ignoreBatteryCheckForTest = true,
            )
            assertTrue("Community testing must defer while VPN Hotspot is active", blockedByHotspot.isEmpty())
            VpnHotspotManager.stopHotspotSharing()

            // 5. Instant consent revocation clears local reports and rotates anonymous reporter ID
            CommunityTestingManager.revokeConsent(ctx, clearLocalPending = true)
            assertFalse(prefs.communityTestingEnabled)
            assertEquals(0, db.getCommunityReportsSummary().totalTested)
            assertFalse(initialSalt == prefs.communityInstallSalt)
        } finally {
            runningIngest.set(false)
            runCatching { ingestSrv.close() }
            ingestThread.join(1000)
        }
    }

    @Test(timeout = 20_000L)
    fun rootlessVpnHotspotEnforcesPrivateBindServesPacAuthRelaysSocksHttpAndFailsClosedOnVpnDrop() {
        // 1. Rejects binding to public WAN IP or wildcard 0.0.0.0
        var rejectedWildcard = false
        try {
            VpnHotspotProxyServer(bindHost = "0.0.0.0", requestedPort = 0) { true }
        } catch (_: IllegalArgumentException) {
            rejectedWildcard = true
        }
        assertTrue("Hotspot proxy must NEVER allow binding to 0.0.0.0", rejectedWildcard)

        assertTrue(VpnHotspotManager.isSafePrivateLanIpv4("192.168.43.1"))
        assertTrue(VpnHotspotManager.isSafePrivateLanIpv4("10.42.0.1"))
        assertTrue(VpnHotspotManager.isSafePrivateLanIpv4("172.20.0.1"))
        assertFalse(VpnHotspotManager.isSafePrivateLanIpv4("8.8.8.8"))
        assertFalse(VpnHotspotManager.isSafePrivateLanIpv4("0.0.0.0"))

        // 2. Start a mock upstream VPN SOCKS5 server (simulating sing-box 127.0.0.1:20808)
        val runningUpstream = AtomicBoolean(true)
        val vpnTunnelVerified = AtomicBoolean(true)
        val lastResolvedDomain = AtomicReference("")
        val upstreamSrv = ServerSocket(0, 16, InetAddress.getByName("127.0.0.1"))
        val upstreamPort = upstreamSrv.localPort

        fun readExactBytes(ins: InputStream, n: Int): ByteArray {
            val b = ByteArray(n)
            var off = 0
            while (off < n) {
                val r = ins.read(b, off, n - off)
                if (r < 0) throw IllegalStateException("EOF")
                off += r
            }
            return b
        }

        val upstreamThread = thread(isDaemon = true) {
            while (runningUpstream.get()) {
                try {
                    val s = upstreamSrv.accept()
                    thread(isDaemon = true) {
                        s.use { sock ->
                            sock.soTimeout = 3000
                            val ins = sock.getInputStream()
                            val out = sock.getOutputStream()
                            val greet = readExactBytes(ins, 2)
                            readExactBytes(ins, greet[1].toInt() and 0xFF)
                            out.write(byteArrayOf(0x05, 0x00))
                            out.flush()

                            val head = readExactBytes(ins, 4)
                            val atyp = head[3].toInt() and 0xFF
                            if (atyp == 0x03) {
                                val dLen = ins.read()
                                val dom = String(readExactBytes(ins, dLen), Charsets.US_ASCII)
                                lastResolvedDomain.set(dom)
                                readExactBytes(ins, 2)
                            } else if (atyp == 0x01) {
                                readExactBytes(ins, 6)
                            }
                            out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80))
                            out.flush()

                            // Echo/respond inside tunnel
                            val buf = ByteArray(1024)
                            val n = ins.read(buf)
                            if (n > 0) {
                                val reply = "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nTUNNEL_PASS"
                                out.write(reply.toByteArray(Charsets.US_ASCII))
                                out.flush()
                            }
                        }
                    }
                } catch (_: Exception) {
                    break
                }
            }
        }

        val hotspotProxy = VpnHotspotProxyServer(
            bindHost = "127.0.0.1",
            requestedPort = 0,
            upstreamSocksHost = "127.0.0.1",
            upstreamSocksPort = upstreamPort,
            requireAuth = true,
            authUser = "hotspotUser",
            authPass = "hotspotPass99",
            isUpstreamTunnelVerified = { vpnTunnelVerified.get() },
        )

        try {
            val hsPort = hotspotProxy.start()

            // A) PAC script works for automatic OS setup
            Socket("127.0.0.1", hsPort).use { c ->
                c.soTimeout = 3000
                c.getOutputStream().write("GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".toByteArray())
                c.getOutputStream().flush()
                val txt = c.getInputStream().bufferedReader().readText()
                assertTrue(txt.contains("FindProxyForURL"))
                assertTrue(txt.contains("SOCKS5 127.0.0.1:$hsPort"))
            }

            // B) Unauthenticated HTTP proxy request rejected with 407 when auth is enabled
            Socket("127.0.0.1", hsPort).use { c ->
                c.soTimeout = 3000
                c.getOutputStream().write("CONNECT check.example.com:443 HTTP/1.1\r\nHost: check.example.com:443\r\n\r\n".toByteArray())
                c.getOutputStream().flush()
                val firstLine = BufferedReader(InputStreamReader(c.getInputStream())).readLine()
                assertTrue(firstLine.contains("407"))
            }

            // C) Authenticated HTTP CONNECT tunnels hostname remotely via VPN SOCKS5 (zero ISP DNS leak!)
            val basicToken = Base64.encodeToString("hotspotUser:hotspotPass99".toByteArray(), Base64.NO_WRAP)
            Socket("127.0.0.1", hsPort).use { c ->
                c.soTimeout = 3000
                val out = c.getOutputStream()
                val req = "CONNECT tunnel-target.example.org:443 HTTP/1.1\r\n" +
                    "Host: tunnel-target.example.org:443\r\n" +
                    "Proxy-Authorization: Basic $basicToken\r\n\r\n"
                out.write(req.toByteArray())
                out.flush()
                val reader = BufferedReader(InputStreamReader(c.getInputStream()))
                val est = reader.readLine()
                assertTrue("Expected 200 Connection Established, got $est", est.contains("200"))
                reader.readLine() // blank line
                out.write("GET / HTTP/1.1\r\nHost: tunnel-target.example.org\r\n\r\n".toByteArray())
                out.flush()
                val body = reader.readText()
                assertTrue(body.contains("TUNNEL_PASS"))
            }
            assertEquals("tunnel-target.example.org", lastResolvedDomain.get())
            assertTrue(hotspotProxy.totalBytesDown.get() > 0L)
            assertEquals(1, hotspotProxy.snapshotClients().size)

            // D) Authenticated SOCKS5 client works too
            Socket("127.0.0.1", hsPort).use { c ->
                c.soTimeout = 3000
                val out = c.getOutputStream()
                val ins = c.getInputStream()
                out.write(byteArrayOf(0x05, 0x01, 0x02))
                val m = readExactBytes(ins, 2)
                assertEquals(0x02, m[1].toInt() and 0xFF)
                val u = "hotspotUser".toByteArray()
                val p = "hotspotPass99".toByteArray()
                out.write(ByteArrayOutputStream().apply {
                    write(0x01); write(u.size); write(u); write(p.size); write(p)
                }.toByteArray())
                val authResp = readExactBytes(ins, 2)
                assertEquals(0x00, authResp[1].toInt() and 0xFF)

                val dom = "socks-client.example.net".toByteArray()
                out.write(ByteArrayOutputStream().apply {
                    write(byteArrayOf(0x05, 0x01, 0x00, 0x03, dom.size.toByte()))
                    write(dom)
                    write(byteArrayOf(0x00, 0x50))
                }.toByteArray())
                val rep = readExactBytes(ins, 10)
                assertEquals(0x00, rep[1].toInt() and 0xFF)
            }
            assertEquals("socks-client.example.net", lastResolvedDomain.get())

            // E) FAIL-CLOSED TEST: Simulate VPN drop -> proxy MUST refuse with 503 and NEVER leak direct traffic!
            vpnTunnelVerified.set(false)
            hotspotProxy.terminateActiveClientStreams()
            Socket("127.0.0.1", hsPort).use { c ->
                c.soTimeout = 3000
                val req = "CONNECT leak-check.example.org:443 HTTP/1.1\r\n" +
                    "Host: leak-check.example.org:443\r\n" +
                    "Proxy-Authorization: Basic $basicToken\r\n\r\n"
                c.getOutputStream().write(req.toByteArray())
                c.getOutputStream().flush()
                val statusLine = BufferedReader(InputStreamReader(c.getInputStream())).readLine()
                assertTrue("Expected 503 Fail-Closed block when VPN is down, got $statusLine", statusLine.contains("503"))
            }
            assertTrue(hotspotProxy.failClosedRejections.get() >= 1L)
        } finally {
            hotspotProxy.stop()
            runningUpstream.set(false)
            runCatching { upstreamSrv.close() }
            upstreamThread.join(1000)
        }
    }

    @Test(timeout = 20_000L)
    fun repoLoadsCommunityVerifiedIranTop500FeedCleanly() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val running = AtomicBoolean(true)
        val srv = ServerSocket(0, 16, InetAddress.getByName("127.0.0.1"))
        val port = srv.localPort
        val iranJson = """
            {
              "schema_version": "1.0.0",
              "generated_at": "2026-10-31T08:00:00Z",
              "country_code": "IR",
              "qualified_count": 2,
              "servers": [
                {
                  "rank": 1,
                  "cfg": "vless://11111111-1111-1111-1111-111111111111@198.51.100.81:443?security=tls&sni=edge.example.com#IR1",
                  "median_latency_ms": 115,
                  "median_speed_kbps": 4100.0,
                  "trust_score": 89.5,
                  "distinct_reporters": 4,
                  "exit_country": "DE"
                },
                {
                  "rank": 2,
                  "cfg": "hy2://pass@198.51.100.82:443?sni=hy2.example.com#IR2",
                  "median_latency_ms": 130,
                  "median_speed_kbps": 5200.0,
                  "trust_score": 86.0,
                  "distinct_reporters": 3,
                  "exit_country": "NL"
                }
              ]
            }
        """.trimIndent()

        val acceptor = thread(isDaemon = true) {
            while (running.get()) {
                try {
                    val sock = srv.accept()
                    thread(isDaemon = true) {
                        sock.use { s ->
                            s.soTimeout = 3000
                            val reader = BufferedReader(InputStreamReader(s.getInputStream(), Charsets.UTF_8))
                            val req = reader.readLine().orEmpty()
                            while (true) {
                                val h = reader.readLine() ?: break
                                if (h.isEmpty()) break
                            }
                            val out = s.getOutputStream()
                            if (req.contains("iran-top500.json")) {
                                val b = iranJson.toByteArray(Charsets.UTF_8)
                                out.write("HTTP/1.1 200 OK\r\nContent-Length: ${b.size}\r\nConnection: close\r\n\r\n".toByteArray())
                                out.write(b)
                            } else {
                                out.write("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".toByteArray())
                            }
                            out.flush()
                        }
                    }
                } catch (_: Exception) {
                    if (!running.get()) break
                }
            }
        }

        try {
            val repo = Repo(
                ctx = ctx,
                mirrorOverride = { file -> listOf("http://127.0.0.1:$port/$file") },
                httpTimeoutMs = 3000,
            )
            val res = repo.loadRemote("iran_community")
            assertEquals(2, res.configs.size)
            assertEquals("remote", res.source)
        } finally {
            running.set(false)
            runCatching { srv.close() }
            acceptor.join(1000)
        }
    }
}
