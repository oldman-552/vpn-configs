package com.bahrain.vpnconfigs

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.bahrain.vpnconfigs.data.Repo
import com.bahrain.vpnconfigs.enterprise.AppUpdateInfo
import com.bahrain.vpnconfigs.enterprise.AppUpdateManager
import com.bahrain.vpnconfigs.enterprise.BandwidthPolicy
import com.bahrain.vpnconfigs.enterprise.ClientDiagnosticsEngine
import com.bahrain.vpnconfigs.enterprise.EnterpriseClock
import com.bahrain.vpnconfigs.enterprise.EnterpriseCrypto
import com.bahrain.vpnconfigs.enterprise.EnterpriseLicenseGuard
import com.bahrain.vpnconfigs.vpn.ServerCandidate
import com.bahrain.vpnconfigs.vpn.SmartFailoverEngine
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
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class EnterpriseAndroidTest {

    private fun signWithEcKey(priv: java.security.PrivateKey, data: ByteArray): String {
        val s = Signature.getInstance("SHA256withECDSA")
        s.initSign(priv)
        s.update(data)
        return Base64.getEncoder().encodeToString(s.sign())
    }

    @Test
    fun signedBundleVerificationZeroKnowledgeLoginTrialExpiryAndDeviceGuard() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val guard = EnterpriseLicenseGuard(ctx)
        val myInstallId = guard.deviceInstallId
        assertTrue(myInstallId.startsWith("inst_"))

        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val kp = kpg.generateKeyPair()
        val pubSpkiB64 = Base64.getEncoder().encodeToString(kp.public.encoded)

        val t0Ms = 1_793_361_600_000L // 2026-10-30T12:00:00Z
        EnterpriseClock.recordNetworkUtc(t0Ms)
        val exp48hIso = java.time.Instant.ofEpochMilli(t0Ms + 48L * 3600_000L).toString()

        val cert = JSONObject()
            .put("user_id", "usr_test01")
            .put("username", "ahmed_bh")
            .put("account_status", "FREE_TRIAL")
            .put("subscription_type", "FREE_TRIAL")
            .put("subscription_start", java.time.Instant.ofEpochMilli(t0Ms).toString())
            .put("subscription_expiration", exp48hIso)
            .put("device_limit", 1)
            .put("authorized_devices", JSONArray().put(myInstallId))
            .put(
                "bandwidth",
                JSONObject()
                    .put("max_download_kbps", 5000)
                    .put("max_upload_kbps", 2000)
                    .put("max_daily_mb", 1)
                    .put("max_monthly_mb", 50)
            )

        val certSig = signWithEcKey(kp.private, EnterpriseCrypto.canonicalJsonString(cert).toByteArray(Charsets.UTF_8))
        val envelopePlain = JSONObject().put("certificate", cert).put("signature_b64", certSig)

        val saltBytes = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val saltHex = saltBytes.joinToString("") { "%02x".format(it) }
        val derivedKey = EnterpriseCrypto.derivePbkdf2Key("ahmed_bh:Pass#2026", saltBytes)
        val envelopeB64 = EnterpriseCrypto.encryptAesGcm(
            derivedKey,
            envelopePlain.toString().toByteArray(Charsets.UTF_8),
            "ahmed_bh".toByteArray(Charsets.UTF_8),
        )

        val lookupId = EnterpriseCrypto.computeUserLookupId("ahmed_bh")
        val bundle = JSONObject()
            .put("schema_version", 3)
            .put("generated_at", java.time.Instant.ofEpochMilli(t0Ms).toString())
            .put("public_key_spki_b64", pubSpkiB64)
            .put("remote_config", JSONObject().put("auth_require_account", true))
            .put(
                "app_updates",
                JSONArray().put(
                    JSONObject()
                        .put("target_app", "USER")
                        .put("version_code", 11)
                        .put("version_name", "3.3")
                        .put("mandatory", true)
                        .put("min_supported_code", 11)
                        .put("apk_url", "https://example.com/update.apk")
                        .put("apk_sha256", "a".repeat(64))
                        .put("is_active", true)
                )
            )
            .put(
                "licenses",
                JSONObject().put(
                    lookupId,
                    JSONObject()
                        .put("salt_hex", saltHex)
                        .put("envelope_b64", envelopeB64)
                        .put("status_code", "FREE_TRIAL")
                )
            )

        val bundleSig = signWithEcKey(kp.private, EnterpriseCrypto.canonicalJsonString(bundle).toByteArray(Charsets.UTF_8))
        val signedPayload = JSONObject().put("bundle", bundle).put("signature_b64", bundleSig).toString()

        // Tampered signature must be rejected
        val tampered = JSONObject().put("bundle", bundle).put("signature_b64", bundleSig.reversed()).toString()
        assertFalse(guard.applySignedBundleRaw(tampered))

        // Valid signed bundle accepted; auth_require_account=true blocks guest VPN
        assertTrue(guard.applySignedBundleRaw(signedPayload))
        assertFalse(guard.currentState().canConnectVpn)

        // Mandatory update detected
        val upd = AppUpdateManager.evaluateAvailableUpdate(ctx, guard.getVerifiedAppUpdates())
        assertNotNull(upd)
        assertTrue(upd!!.mandatory)
        assertEquals("3.3", upd.versionName)

        // Wrong password rejected
        assertTrue(guard.loginWithBundle("ahmed_bh", "WrongPass!", true).isFailure)

        // Valid login succeeds with 48h trial active
        val loggedIn = guard.loginWithBundle("ahmed_bh", "Pass#2026", true).getOrThrow()
        assertTrue(loggedIn.canConnectVpn)
        assertTrue(loggedIn.statusHeadlineEn.contains("FREE TRIAL ACTIVE"))

        // Exceeding 1 MB daily quota immediately disables VPN authorization
        guard.recordTrafficDeltaBytes(1_200_000L, 100_000L)
        val overQuota = guard.currentState()
        assertFalse(overQuota.canConnectVpn)
        assertEquals("DAILY QUOTA EXCEEDED", overQuota.statusHeadlineEn)

        // Advance network UTC past 48h -> trial expires cleanly
        EnterpriseClock.recordNetworkUtc(t0Ms + 49L * 3600_000L)
        val expired = guard.currentState()
        assertFalse(expired.canConnectVpn)
        assertTrue(expired.statusHeadlineEn.contains("YOUR FREE TRIAL HAS EXPIRED"))
    }

    @Test
    fun realSpeedTestEngineMeasuresActualDownloadUploadPingAndJitter() = runBlocking {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val engine = ClientDiagnosticsEngine(ctx)
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
                            val inp = BufferedReader(InputStreamReader(s.getInputStream(), Charsets.US_ASCII))
                            val reqLine = inp.readLine() ?: return@use
                            var contentLen = 0
                            while (true) {
                                val h = inp.readLine() ?: break
                                if (h.isEmpty()) break
                                if (h.startsWith("Content-Length:", ignoreCase = true)) {
                                    contentLen = h.substringAfter(":").trim().toIntOrNull() ?: 0
                                }
                            }
                            val out = s.getOutputStream()
                            when {
                                reqLine.contains("/ping") -> {
                                    out.write("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".toByteArray())
                                    out.flush()
                                }
                                reqLine.contains("/down") -> {
                                    val body = ByteArray(256 * 1024) { 0x42 }
                                    out.write("HTTP/1.1 200 OK\r\nContent-Length: ${body.size}\r\nConnection: close\r\n\r\n".toByteArray())
                                    out.write(body)
                                    out.flush()
                                }
                                reqLine.contains("/up") -> {
                                    val sink = ByteArray(8192)
                                    var rem = contentLen
                                    val rawIn = s.getInputStream()
                                    while (rem > 0) {
                                        val r = rawIn.read(sink, 0, minOf(sink.size, rem))
                                        if (r <= 0) break
                                        rem -= r
                                    }
                                    out.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK".toByteArray())
                                    out.flush()
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
            val rec = engine.runRealSpeedTest(
                viaVpnTunnel = false,
                serverLabel = "TestNode",
                bandwidthPolicy = BandwidthPolicy(maxDownloadKbps = 0, maxUploadKbps = 0),
                downloadUrl = "http://127.0.0.1:$port/down",
                uploadUrl = "http://127.0.0.1:$port/up",
                pingUrl = "http://127.0.0.1:$port/ping",
            )
            assertTrue(rec.pingMs >= 1L)
            assertEquals(0.0, rec.packetLossPct, 0.01)
            assertTrue(rec.downloadMbps > 0.0)
            assertTrue(rec.uploadMbps > 0.0)
            assertEquals(1, engine.loadSpeedHistory().size)
        } finally {
            running.set(false)
            runCatching { server.close() }
            acceptor.join(1000)
        }
    }

    @Test
    fun v31AbiAwareUpdaterVipEncryptionAndSmartFailoverWorkEndToEnd() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val guard = EnterpriseLicenseGuard(ctx)

        // 1. ABI-aware APK selection (arm64-v8a vs x86_64 vs universal fallback)
        val updateObj = JSONObject()
            .put("target_app", "USER")
            .put("version_code", 12)
            .put("version_name", "3.3")
            .put("is_active", true)
            .put("apk_url", "https://example.com/fallback-universal.apk")
            .put("apk_sha256", "f".repeat(64))
            .put(
                "abi_assets",
                JSONObject()
                    .put("arm64-v8a", JSONObject().put("apk_url", "https://example.com/arm64.apk").put("apk_sha256", "1".repeat(64)))
                    .put("x86_64", JSONObject().put("apk_url", "https://example.com/x64.apk").put("apk_sha256", "2".repeat(64)))
                    .put("universal", JSONObject().put("apk_url", "https://example.com/uni.apk").put("apk_sha256", "3".repeat(64)))
            )

        val armPick = AppUpdateManager.evaluateAvailableUpdate(ctx, JSONArray().put(updateObj), arrayOf("arm64-v8a", "armeabi-v7a"))!!
        assertEquals("arm64-v8a", armPick.selectedAbi)
        assertEquals("https://example.com/arm64.apk", armPick.apkUrl)
        assertEquals("1".repeat(64), armPick.apkSha256)

        val x64Pick = AppUpdateManager.evaluateAvailableUpdate(ctx, JSONArray().put(updateObj), arrayOf("x86_64"))!!
        assertEquals("x86_64", x64Pick.selectedAbi)
        assertEquals("https://example.com/x64.apk", x64Pick.apkUrl)

        val legacyPick = AppUpdateManager.evaluateAvailableUpdate(ctx, JSONArray().put(updateObj), arrayOf("armeabi-v7a"))!!
        assertEquals("universal", legacyPick.selectedAbi)
        assertEquals("https://example.com/uni.apk", legacyPick.apkUrl)

        // 2. Encrypted VIP Private Nodes lifecycle (guest=0 -> loggedIn=2 -> expired/logout=0)
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val kp = kpg.generateKeyPair()
        val pubSpkiB64 = Base64.getEncoder().encodeToString(kp.public.encoded)
        val t0Ms = 1_793_400_000_000L
        EnterpriseClock.recordNetworkUtc(t0Ms)

        val vipKeyBytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val vipKeyHex = vipKeyBytes.joinToString("") { "%02x".format(it) }
        val vipNodesPlain = JSONArray()
            .put(JSONObject().put("id", "v1").put("label", "DE Edge").put("country", "DE").put("protocol", "VLESS").put("uri", "vless://u1@de-vip.internal:443").put("priority", 180))
            .put(JSONObject().put("id", "v2").put("label", "BH Ultra").put("country", "BH").put("protocol", "HYSTERIA2").put("uri", "hysteria2://p2@bh-vip.internal:8443").put("priority", 300))
        val vipEncB64 = EnterpriseCrypto.encryptAesGcm(
            vipKeyBytes,
            vipNodesPlain.toString().toByteArray(Charsets.UTF_8),
            EnterpriseCrypto.VIP_NODES_AAD.toByteArray(Charsets.UTF_8),
        )

        val cert = JSONObject()
            .put("user_id", "usr_vip99")
            .put("username", "noor_vip")
            .put("account_status", "ACTIVE")
            .put("subscription_type", "MONTHLY")
            .put("subscription_start", java.time.Instant.ofEpochMilli(t0Ms).toString())
            .put("subscription_expiration", java.time.Instant.ofEpochMilli(t0Ms + 720L * 3600_000L).toString())
            .put("device_limit", 1)
            .put("authorized_devices", JSONArray().put(guard.deviceInstallId))
            .put("vip_access_key_hex", vipKeyHex)
            .put("bandwidth", JSONObject().put("max_daily_mb", 0))
        val certSig = signWithEcKey(kp.private, EnterpriseCrypto.canonicalJsonString(cert).toByteArray(Charsets.UTF_8))

        val saltBytes = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val saltHex = saltBytes.joinToString("") { "%02x".format(it) }
        val envB64 = EnterpriseCrypto.encryptAesGcm(
            EnterpriseCrypto.derivePbkdf2Key("noor_vip:Noor#2026", saltBytes),
            JSONObject().put("certificate", cert).put("signature_b64", certSig).toString().toByteArray(Charsets.UTF_8),
            "noor_vip".toByteArray(Charsets.UTF_8),
        )
        val lookup = EnterpriseCrypto.computeUserLookupId("noor_vip")
        val bundle = JSONObject()
            .put("schema_version", 3)
            .put("bundle_release", "3.1")
            .put("generated_at", java.time.Instant.ofEpochMilli(t0Ms).toString())
            .put("public_key_spki_b64", pubSpkiB64)
            .put("remote_config", JSONObject().put("auto_failover_enabled", true))
            .put("app_updates", JSONArray())
            .put("vip_nodes_enc_b64", vipEncB64)
            .put("licenses", JSONObject().put(lookup, JSONObject().put("salt_hex", saltHex).put("envelope_b64", envB64).put("status_code", "ACTIVE")))
        val bundleSig = signWithEcKey(kp.private, EnterpriseCrypto.canonicalJsonString(bundle).toByteArray(Charsets.UTF_8))
        guard.logout()
        assertTrue(guard.applySignedBundleRaw(JSONObject().put("bundle", bundle).put("signature_b64", bundleSig).toString()))
        assertEquals(0, guard.getAuthorizedVipNodes().size)

        val st = guard.loginWithBundle("noor_vip", "Noor#2026", true).getOrThrow()
        assertEquals(2, st.vipNodesUnlocked)
        val unlockedVip = guard.getAuthorizedVipNodes()
        assertEquals(2, unlockedVip.size)
        assertEquals("BH", unlockedVip[0].country) // priority 300 sorted first

        guard.logout()
        assertEquals(0, guard.getAuthorizedVipNodes().size)

        // 3. SmartFailoverEngine rapid confirmation & speed/VIP ranking + cooldown isolation
        SmartFailoverEngine.clearForTesting()
        assertFalse(SmartFailoverEngine.shouldTriggerFailover(processAlive = true, primaryProbeOk = false, secondaryConfirmOk = true))
        assertTrue(SmartFailoverEngine.shouldTriggerFailover(processAlive = true, primaryProbeOk = false, secondaryConfirmOk = false))
        assertTrue(SmartFailoverEngine.shouldTriggerFailover(processAlive = false, primaryProbeOk = true, secondaryConfirmOk = true))

        val cDead = ServerCandidate("vless://u@dead.example.com:443", "Dead", speedKbps = 9000.0, latencyMs = 40L)
        val cSlow = ServerCandidate("vless://u@slow.example.com:443", "Slow", speedKbps = 800.0, latencyMs = 90L)
        val cFast = ServerCandidate("vless://u@fast.example.com:443", "Fast", speedKbps = 6500.0, latencyMs = 110L)
        val cCooled = ServerCandidate("vless://u@flapping.example.com:443", "Flapping", speedKbps = 12000.0, latencyMs = 30L)
        val cVip = ServerCandidate("vless://u@vip.example.com:443", "VIP", speedKbps = 4000.0, latencyMs = 70L, isVip = true)

        SmartFailoverEngine.recordServerDrop(cCooled.cfg, nowMs = 100_000L)
        val ranked = SmartFailoverEngine.rankFailoverCandidates(
            excludeCfg = cDead.cfg,
            pool = listOf(cDead, cSlow, cFast, cCooled, cVip),
            nowMs = 150_000L,
            maxCandidates = 3,
        )
        assertEquals("VIP", ranked[0].label)
        assertEquals("Fast", ranked[1].label)
        assertEquals("Slow", ranked[2].label)
    }
}
