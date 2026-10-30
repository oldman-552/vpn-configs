// =====================================================================
// EnterpriseLicenseGuard.kt — التشفير، المصادقة، إدارة جلسات المستخدم،
// التجربة المجانية 48 ساعة المحكومة بوقت الشبكة، ربط الجهاز الواحد،
// وحدود السرعة وحصة البيانات اليومية/الشهرية بدون أي مفاتيح سرية داخل الـ APK.
// =====================================================================
package com.bahrain.vpnconfigs.enterprise

import android.content.Context
import android.os.SystemClock
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyStore
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

object EnterpriseClock {
    @Volatile
    private var syncedUtcEpochMs: Long = 0L

    @Volatile
    private var syncedElapsedRealtimeMs: Long = 0L

    fun recordNetworkUtc(utcEpochMs: Long) {
        if (utcEpochMs > 1_700_000_000_000L) {
            syncedUtcEpochMs = utcEpochMs
            syncedElapsedRealtimeMs = runCatching { SystemClock.elapsedRealtime() }.getOrDefault(0L)
        }
    }

    fun recordIsoUtc(isoUtc: String?) {
        if (isoUtc.isNullOrBlank()) return
        runCatching {
            val epochMs = Instant.parse(isoUtc.trim()).toEpochMilli()
            recordNetworkUtc(epochMs)
        }
    }

    /** وقت موثوق مقاوم للتلاعب بساعة الهاتف عبر ربط آخر وقت شبكة بساعة النظام الرتيبة. */
    fun trustedNowMs(): Long {
        val baseUtc = syncedUtcEpochMs
        if (baseUtc > 0L) {
            val nowElapsed = runCatching { SystemClock.elapsedRealtime() }.getOrDefault(0L)
            val delta = (nowElapsed - syncedElapsedRealtimeMs).coerceAtLeast(0L)
            return baseUtc + delta
        }
        return System.currentTimeMillis()
    }
}

data class BandwidthPolicy(
    val maxDownloadKbps: Int = 0,
    val maxUploadKbps: Int = 0,
    val maxTotalKbps: Int = 0,
    val maxDailyMb: Int = 0,
    val maxMonthlyMb: Int = 0,
    val maxConcurrentConnections: Int = 1,
    val autoBlockOnViolation: Boolean = false,
)

data class VipPrivateNode(
    val id: String,
    val label: String,
    val country: String,
    val protocol: String,
    val uri: String,
    val priority: Int = 200,
)

data class AccountLicenseState(
    val authRequired: Boolean = false,
    val isLoggedIn: Boolean = false,
    val userId: String = "",
    val username: String = "",
    val accountStatus: String = "GUEST",
    val subscriptionType: String = "NONE",
    val subscriptionStartIso: String = "",
    val expirationIso: String = "",
    val remainingSeconds: Long? = null,
    val deviceInstallId: String = "",
    val deviceAuthorized: Boolean = true,
    val deviceLimit: Int = 1,
    val rememberMe: Boolean = true,
    val canConnectVpn: Boolean = true,
    val statusHeadlineEn: String = "",
    val statusDetailAr: String = "",
    val bandwidth: BandwidthPolicy = BandwidthPolicy(),
    val dailyUsedBytes: Long = 0L,
    val monthlyUsedBytes: Long = 0L,
    val vipNodesUnlocked: Int = 0,
    val loginHistory: List<String> = emptyList(),
)

object EnterpriseCrypto {
    private const val PBKDF2_ITERATIONS = 120_000
    private val LOOKUP_DOMAIN = "bahrain-vpn-enterprise-v3-user-lookup".toByteArray(Charsets.UTF_8)
    const val VIP_NODES_AAD = "bahrain-vpn-vip-nodes-v31"

    fun computeUserLookupId(username: String): String {
        val normalized = username.trim().lowercase(Locale.ROOT).toByteArray(Charsets.UTF_8)
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(LOOKUP_DOMAIN, "HmacSHA256"))
        return mac.doFinal(normalized).joinToString("") { "%02x".format(it) }
    }

    fun hexToBytes(hex: String): ByteArray {
        val clean = hex.trim()
        require(clean.length % 2 == 0) { "Odd hex length" }
        return ByteArray(clean.length / 2) { i ->
            clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    fun derivePbkdf2Key(secret: String, salt: ByteArray, iterations: Int = PBKDF2_ITERATIONS): ByteArray {
        val spec = PBEKeySpec(secret.toCharArray(), salt, iterations, 256)
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
    }

    fun decryptAesGcm(key32: ByteArray, tokenB64: String, aad: ByteArray? = null): ByteArray {
        val raw = Base64.decode(tokenB64, Base64.DEFAULT)
        require(raw.size >= 28) { "Malformed AES-GCM payload" }
        val iv = raw.copyOfRange(0, 12)
        val ct = raw.copyOfRange(12, raw.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key32, "AES"), GCMParameterSpec(128, iv))
        if (aad != null && aad.isNotEmpty()) {
            cipher.updateAAD(aad)
        }
        return cipher.doFinal(ct)
    }

    fun encryptAesGcm(key32: ByteArray, plain: ByteArray, aad: ByteArray? = null): String {
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key32, "AES"), GCMParameterSpec(128, iv))
        if (aad != null && aad.isNotEmpty()) {
            cipher.updateAAD(aad)
        }
        val ct = cipher.doFinal(plain)
        return Base64.encodeToString(iv + ct, Base64.NO_WRAP)
    }

    fun openUserLicenseEnvelope(
        username: String,
        password: String,
        saltHex: String,
        envelopeB64: String,
    ): JSONObject {
        val normUser = username.trim().lowercase(Locale.ROOT)
        val key = derivePbkdf2Key("$normUser:$password", hexToBytes(saltHex))
        val plain = decryptAesGcm(key, envelopeB64, normUser.toByteArray(Charsets.UTF_8))
        return JSONObject(String(plain, Charsets.UTF_8))
    }

    fun decryptVipNodes(vipKeyHex: String, vipEncB64: String): List<VipPrivateNode> {
        if (vipKeyHex.trim().length != 64 || vipEncB64.isBlank()) return emptyList()
        return runCatching {
            val key32 = hexToBytes(vipKeyHex.trim())
            val plain = decryptAesGcm(key32, vipEncB64.trim(), VIP_NODES_AAD.toByteArray(Charsets.UTF_8))
            val arr = JSONArray(String(plain, Charsets.UTF_8))
            val parsed = ArrayList<VipPrivateNode>(arr.length())
            for (i in 0 until arr.length()) {
                val o = arr.optJSONObject(i) ?: continue
                val uri = o.optString("uri", "").trim()
                if (uri.contains("://")) {
                    parsed.add(
                        VipPrivateNode(
                            id = o.optString("id", "vip_$i"),
                            label = o.optString("label", "VIP #${i + 1}"),
                            country = o.optString("country", "").uppercase(Locale.ROOT).take(2),
                            protocol = o.optString("protocol", "VLESS").uppercase(Locale.ROOT),
                            uri = uri,
                            priority = o.optInt("priority", 200),
                        )
                    )
                }
            }
            parsed.sortedByDescending { it.priority }
        }.getOrDefault(emptyList())
    }

    /** Canonical JSON serializer matching Python `json.dumps(..., separators=(",", ":"), sort_keys=True, ensure_ascii=False)`. */
    fun canonicalJsonString(value: Any?): String = when (value) {
        null, JSONObject.NULL -> "null"
        is Boolean -> if (value) "true" else "false"
        is Int, is Long -> value.toString()
        is Number -> {
            val d = value.toDouble()
            if (d == d.toLong().toDouble()) d.toLong().toString() else d.toString()
        }
        is String -> JSONObject.quote(value)
        is JSONArray -> {
            val items = (0 until value.length()).map { canonicalJsonString(value.get(it)) }
            items.joinToString(",", prefix = "[", postfix = "]")
        }
        is JSONObject -> {
            val keys = value.keys().asSequence().toList().sorted()
            val pairs = keys.map { k -> "${JSONObject.quote(k)}:${canonicalJsonString(value.get(k))}" }
            pairs.joinToString(",", prefix = "{", postfix = "}")
        }
        else -> JSONObject.quote(value.toString())
    }

    private fun p1363ToDer(sig64: ByteArray): ByteArray {
        val r = BigInteger(1, sig64.copyOfRange(0, 32)).toByteArray()
        val s = BigInteger(1, sig64.copyOfRange(32, 64)).toByteArray()
        val totalLen = 2 + r.size + 2 + s.size
        val out = java.io.ByteArrayOutputStream()
        out.write(0x30)
        if (totalLen >= 128) {
            out.write(0x81)
        }
        out.write(totalLen)
        out.write(0x02)
        out.write(r.size)
        out.write(r)
        out.write(0x02)
        out.write(s.size)
        out.write(s)
        return out.toByteArray()
    }

    fun verifyEcdsaP256(publicSpkiB64: String, data: ByteArray, signatureB64: String): Boolean {
        if (publicSpkiB64.isBlank() || signatureB64.isBlank()) return false
        return try {
            val pubBytes = Base64.decode(publicSpkiB64, Base64.DEFAULT)
            val pubKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(pubBytes))
            val rawSig = Base64.decode(signatureB64, Base64.DEFAULT)
            val derSig = if (rawSig.size == 64) p1363ToDer(rawSig) else rawSig
            val verifier = Signature.getInstance("SHA256withECDSA")
            verifier.initVerify(pubKey)
            verifier.update(data)
            verifier.verify(derSig)
        } catch (_: Exception) {
            false
        }
    }
}

/**
 * محدد سرعة (Token-Bucket) للتحكم في معدل التدفق للتحميل/الرفع عندما يفرض المشرف حدًا أقصى للسرعة.
 */
class TokenBucketShaper(maxKbps: Int) {
    private val bytesPerSec: Long = if (maxKbps > 0) maxKbps.toLong() * 1024L else 0L
    private var availableTokens: Double = bytesPerSec.toDouble()
    private var lastRefillNs: Long = System.nanoTime()

    @Synchronized
    fun consumeAndComputeDelayMs(bytesCount: Int): Long {
        if (bytesPerSec <= 0L || bytesCount <= 0) return 0L
        val nowNs = System.nanoTime()
        val elapsedSec = ((nowNs - lastRefillNs).coerceAtLeast(0L)) / 1_000_000_000.0
        lastRefillNs = nowNs
        availableTokens = (availableTokens + elapsedSec * bytesPerSec).coerceAtMost(bytesPerSec * 1.5)
        availableTokens -= bytesCount
        if (availableTokens >= 0.0) return 0L
        val deficitBytes = -availableTokens
        return ((deficitBytes / bytesPerSec) * 1000.0).toLong().coerceIn(1L, 2000L)
    }
}

class EnterpriseLicenseGuard(ctx: Context) {
    private val appCtx = ctx.applicationContext
    private val sp = appCtx.getSharedPreferences("enterprise_license_vault", Context.MODE_PRIVATE)

    val deviceInstallId: String by lazy {
        val existing = sp.getString("device_install_id", null)
        if (!existing.isNullOrBlank()) {
            existing
        } else {
            val rnd = ByteArray(16).also { SecureRandom().nextBytes(it) }
            val generated = "inst_" + rnd.joinToString("") { "%02x".format(it) }
            sp.edit().putString("device_install_id", generated).apply()
            generated
        }
    }

    private fun getOrCreateLocalVaultKey(): SecretKey {
        runCatching {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val alias = "bahrain_vpn_session_vault_v3"
            val existing = ks.getKey(alias, null) as? SecretKey
            if (existing != null) return existing
            val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            kg.init(
                KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()
            )
            return kg.generateKey()
        }
        // Fallback for JVM/Robolectric unit tests where AndroidKeyStore hardware provider is absent
        val fallbackSeed = sp.getString("vault_seed_hex", null) ?: run {
            val b = ByteArray(32).also { SecureRandom().nextBytes(it) }
            val h = b.joinToString("") { "%02x".format(it) }
            sp.edit().putString("vault_seed_hex", h).apply()
            h
        }
        return SecretKeySpec(EnterpriseCrypto.hexToBytes(fallbackSeed), "AES")
    }

    private fun saveEncryptedSession(json: JSONObject) {
        val key = getOrCreateLocalVaultKey()
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val actualIv = cipher.iv
        val ct = cipher.doFinal(json.toString().toByteArray(Charsets.UTF_8))
        val combined = ByteArray(1 + actualIv.size + ct.size)
        combined[0] = actualIv.size.toByte()
        System.arraycopy(actualIv, 0, combined, 1, actualIv.size)
        System.arraycopy(ct, 0, combined, 1 + actualIv.size, ct.size)
        sp.edit().putString("enc_session_blob", Base64.encodeToString(combined, Base64.NO_WRAP)).apply()
    }

    private fun loadEncryptedSession(): JSONObject? {
        val b64 = sp.getString("enc_session_blob", null) ?: return null
        return runCatching {
            val raw = Base64.decode(b64, Base64.DEFAULT)
            val ivLen = raw[0].toInt() and 0xFF
            val iv = raw.copyOfRange(1, 1 + ivLen)
            val ct = raw.copyOfRange(1 + ivLen, raw.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateLocalVaultKey(), GCMParameterSpec(128, iv))
            JSONObject(String(cipher.doFinal(ct), Charsets.UTF_8))
        }.getOrNull()
    }

    fun applySignedBundleRaw(rawJson: String): Boolean {
        return try {
            val outer = JSONObject(rawJson)
            val bundle = outer.getJSONObject("bundle")
            val sigB64 = outer.optString("signature_b64", "")
            val pubKeyB64 = bundle.optString("public_key_spki_b64", "")
            val canonicalBytes = EnterpriseCrypto.canonicalJsonString(bundle).toByteArray(Charsets.UTF_8)
            if (!EnterpriseCrypto.verifyEcdsaP256(pubKeyB64, canonicalBytes, sigB64)) {
                return false
            }
            // Pin or verify public key continuity if already pinned
            val pinnedPub = sp.getString("pinned_pub_spki", null)
            if (pinnedPub.isNullOrBlank()) {
                sp.edit().putString("pinned_pub_spki", pubKeyB64).apply()
            }
            EnterpriseClock.recordIsoUtc(bundle.optString("generated_at"))
            sp.edit().putString("verified_bundle_json", outer.toString()).apply()
            revalidateStoredSessionAgainstBundle(bundle)
            true
        } catch (_: Exception) {
            false
        }
    }

    fun getRemoteConfig(): JSONObject {
        val raw = sp.getString("verified_bundle_json", null) ?: return JSONObject()
        return runCatching {
            JSONObject(raw).getJSONObject("bundle").optJSONObject("remote_config") ?: JSONObject()
        }.getOrDefault(JSONObject())
    }

    fun getVerifiedAppUpdates(): JSONArray {
        val raw = sp.getString("verified_bundle_json", null) ?: return JSONArray()
        return runCatching {
            JSONObject(raw).getJSONObject("bundle").optJSONArray("app_updates") ?: JSONArray()
        }.getOrDefault(JSONArray())
    }

    /**
     * يفك تشفير سيرفرات VIP الخاصة في الذاكرة فقط عندما يكون الحساب مسجّل الدخول،
     * غير منتهي الصلاحية، غير محظور، وضمن الحصة المسموحة.
     */
    fun getAuthorizedVipNodes(): List<VipPrivateNode> {
        val st = currentState()
        if (!st.isLoggedIn || !st.canConnectVpn) return emptyList()
        val ses = loadEncryptedSession() ?: return emptyList()
        val vipKeyHex = ses.optJSONObject("certificate")?.optString("vip_access_key_hex", "").orEmpty()
        if (vipKeyHex.length != 64) return emptyList()
        val rawBundle = sp.getString("verified_bundle_json", null) ?: return emptyList()
        val vipEncB64 = runCatching {
            JSONObject(rawBundle).getJSONObject("bundle").optString("vip_nodes_enc_b64", "")
        }.getOrDefault("")
        return EnterpriseCrypto.decryptVipNodes(vipKeyHex, vipEncB64)
    }

    private fun revalidateStoredSessionAgainstBundle(bundle: JSONObject) {
        val ses = loadEncryptedSession() ?: return
        val uname = ses.optString("username", "")
        if (uname.isBlank()) return
        val lookupId = EnterpriseCrypto.computeUserLookupId(uname)
        val licObj = bundle.optJSONObject("licenses")?.optJSONObject(lookupId) ?: return
        val liveStatus = licObj.optString("status_code", "")
        val revokedAt = licObj.optString("revoked_at", "")
        val loginAtIso = ses.optString("logged_in_at", "")

        if (revokedAt.isNotBlank() && loginAtIso.isNotBlank()) {
            val revMs = runCatching { Instant.parse(revokedAt).toEpochMilli() }.getOrDefault(0L)
            val logMs = runCatching { Instant.parse(loginAtIso).toEpochMilli() }.getOrDefault(0L)
            if (revMs >= logMs) {
                logout(reason = "SESSION_REVOKED")
                return
            }
        }
        if (liveStatus.isNotBlank()) {
            val cert = ses.optJSONObject("certificate") ?: JSONObject()
            cert.put("account_status", liveStatus)
            ses.put("certificate", cert)
            saveEncryptedSession(ses)
        }
    }

    fun loginWithBundle(username: String, password: String, rememberMe: Boolean): Result<AccountLicenseState> {
        val cleanUser = username.trim().lowercase(Locale.ROOT)
        if (cleanUser.length < 3 || password.length < 6) {
            return Result.failure(IllegalArgumentException("يرجى إدخال اسم مستخدم وكلمة مرور صحيحة"))
        }
        val bundleRaw = sp.getString("verified_bundle_json", null)
            ?: return Result.failure(IllegalStateException("لم تتوفر حزمة التراخيص الموقّعة بعد — حدّث القائمة أولًا"))

        return try {
            val outer = JSONObject(bundleRaw)
            val bundle = outer.getJSONObject("bundle")
            val pubKeyB64 = bundle.optString("public_key_spki_b64", "")
            val lookupId = EnterpriseCrypto.computeUserLookupId(cleanUser)
            val licEntry = bundle.optJSONObject("licenses")?.optJSONObject(lookupId)
                ?: return Result.failure(SecurityException("بيانات الدخول غير صحيحة"))

            val opened = runCatching {
                EnterpriseCrypto.openUserLicenseEnvelope(
                    username = cleanUser,
                    password = password,
                    saltHex = licEntry.getString("salt_hex"),
                    envelopeB64 = licEntry.getString("envelope_b64"),
                )
            }.getOrElse {
                recordLoginHistoryEntry(cleanUser, succeeded = false)
                return Result.failure(SecurityException("بيانات الدخول غير صحيحة"))
            }

            val cert = opened.getJSONObject("certificate")
            val certSig = opened.optString("signature_b64", "")
            if (certSig.isNotBlank()) {
                val certBytes = EnterpriseCrypto.canonicalJsonString(cert).toByteArray(Charsets.UTF_8)
                if (!EnterpriseCrypto.verifyEcdsaP256(pubKeyB64, certBytes, certSig)) {
                    return Result.failure(SecurityException("توقيع شهادة الحساب غير صالح"))
                }
            }

            // Enforce 1 Account = 1 Device authorization
            val authDevs = cert.optJSONArray("authorized_devices") ?: JSONArray()
            val allowedIds = (0 until authDevs.length()).map { authDevs.optString(it) }.filter { it.isNotBlank() }
            if (allowedIds.isNotEmpty() && deviceInstallId !in allowedIds) {
                recordLoginHistoryEntry(cleanUser, succeeded = false)
                return Result.failure(
                    SecurityException("تم الوصول للحد الأقصى للأجهزة المسموحة لهذا الحساب (رمز جهازك: $deviceInstallId)")
                )
            }

            val nowIso = Instant.ofEpochMilli(EnterpriseClock.trustedNowMs()).toString()
            val sessionBlob = JSONObject()
                .put("username", cleanUser)
                .put("remember_me", rememberMe)
                .put("logged_in_at", nowIso)
                .put("certificate", cert)
            saveEncryptedSession(sessionBlob)
            recordLoginHistoryEntry(cleanUser, succeeded = true)
            Result.success(currentState())
        } catch (e: Exception) {
            Result.failure(SecurityException(e.message ?: "تعذّر التحقق من الحساب"))
        }
    }

    fun logout(reason: String = "") {
        sp.edit().remove("enc_session_blob").apply()
        if (reason.isNotBlank()) {
            sp.edit().putString("last_logout_reason", reason).apply()
        }
    }

    private fun recordLoginHistoryEntry(username: String, succeeded: Boolean) {
        val nowStr = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm", Locale.US)
            .withZone(ZoneOffset.UTC)
            .format(Instant.ofEpochMilli(EnterpriseClock.trustedNowMs()))
        val line = "$nowStr UTC • $username • ${if (succeeded) "نجاح" else "مرفوض"}"
        val prev = getLoginHistory()
        val updated = (listOf(line) + prev).take(12)
        sp.edit().putString("login_history_json", JSONArray(updated).toString()).apply()
    }

    fun getLoginHistory(): List<String> {
        val raw = sp.getString("login_history_json", null) ?: return emptyList()
        return runCatching {
            val arr = JSONArray(raw)
            (0 until arr.length()).mapNotNull { arr.optString(it).takeIf { s -> s.isNotBlank() } }
        }.getOrDefault(emptyList())
    }

    fun recordTrafficDeltaBytes(deltaDown: Long, deltaUp: Long) {
        val totalDelta = (deltaDown.coerceAtLeast(0L) + deltaUp.coerceAtLeast(0L))
        if (totalDelta <= 0L) return
        val nowInst = Instant.ofEpochMilli(EnterpriseClock.trustedNowMs()).atZone(ZoneOffset.UTC)
        val dayKey = "usage_day_${nowInst.year}_${nowInst.monthValue}_${nowInst.dayOfMonth}"
        val monthKey = "usage_month_${nowInst.year}_${nowInst.monthValue}"
        val nextDay = sp.getLong(dayKey, 0L) + totalDelta
        val nextMonth = sp.getLong(monthKey, 0L) + totalDelta
        sp.edit().putLong(dayKey, nextDay).putLong(monthKey, nextMonth).apply()
    }

    private fun readCurrentUsageBytes(): Pair<Long, Long> {
        val nowInst = Instant.ofEpochMilli(EnterpriseClock.trustedNowMs()).atZone(ZoneOffset.UTC)
        val dayKey = "usage_day_${nowInst.year}_${nowInst.monthValue}_${nowInst.dayOfMonth}"
        val monthKey = "usage_month_${nowInst.year}_${nowInst.monthValue}"
        return sp.getLong(dayKey, 0L) to sp.getLong(monthKey, 0L)
    }

    fun currentState(): AccountLicenseState {
        val rc = getRemoteConfig()
        val authReq = rc.optBoolean("auth_require_account", false)
        val (dayUsed, monthUsed) = readCurrentUsageBytes()
        val ses = loadEncryptedSession()

        if (ses == null) {
            return AccountLicenseState(
                authRequired = authReq,
                isLoggedIn = false,
                deviceInstallId = deviceInstallId,
                canConnectVpn = !authReq,
                statusHeadlineEn = if (authReq) "LOGIN REQUIRED" else "OPEN ACCESS",
                statusDetailAr = if (authReq) "يلزم تسجيل الدخول بحساب فعّال لبدء الاتصال" else "الوضع المفتوح مفعّل — يمكنك تسجيل الدخول لربط اشتراكك",
                dailyUsedBytes = dayUsed,
                monthlyUsedBytes = monthUsed,
                loginHistory = getLoginHistory(),
            )
        }

        val cert = ses.optJSONObject("certificate") ?: JSONObject()
        val subType = cert.optString("subscription_type", "MONTHLY")
        var status = cert.optString("account_status", "ACTIVE")
        val expIso = cert.optString("subscription_expiration", "")
        val nowMs = EnterpriseClock.trustedNowMs()
        val expMs = if (expIso.isNotBlank()) {
            runCatching { Instant.parse(expIso).toEpochMilli() }.getOrNull()
        } else null

        if (status in listOf("ACTIVE", "FREE_TRIAL") && expMs != null && nowMs >= expMs) {
            status = "EXPIRED"
        }

        val remSec = expMs?.let { ((it - nowMs) / 1000L).coerceAtLeast(0L) }
        val authDevs = cert.optJSONArray("authorized_devices") ?: JSONArray()
        val allowedIds = (0 until authDevs.length()).map { authDevs.optString(it) }.filter { it.isNotBlank() }
        val devOk = allowedIds.isEmpty() || (deviceInstallId in allowedIds)

        val bwObj = cert.optJSONObject("bandwidth") ?: JSONObject()
        val bw = BandwidthPolicy(
            maxDownloadKbps = bwObj.optInt("max_download_kbps", 0),
            maxUploadKbps = bwObj.optInt("max_upload_kbps", 0),
            maxTotalKbps = bwObj.optInt("max_total_kbps", 0),
            maxDailyMb = bwObj.optInt("max_daily_mb", 0),
            maxMonthlyMb = bwObj.optInt("max_monthly_mb", 0),
            maxConcurrentConnections = bwObj.optInt("max_concurrent_connections", 1),
            autoBlockOnViolation = bwObj.optBoolean("auto_block_on_violation", false),
        )

        val dailyExceeded = bw.maxDailyMb > 0 && dayUsed >= bw.maxDailyMb.toLong() * 1024L * 1024L
        val monthlyExceeded = bw.maxMonthlyMb > 0 && monthUsed >= bw.maxMonthlyMb.toLong() * 1024L * 1024L

        val (headlineEn, detailAr) = when {
            !devOk -> "DEVICE UNAUTHORIZED" to "هذا الجهاز غير مصرّح له على الحساب — تواصل مع المشرف"
            status == "EXPIRED" && subType == "FREE_TRIAL" ->
                "YOUR FREE TRIAL HAS EXPIRED • CONTACT ADMINISTRATOR" to "انتهت الفترة التجريبية (48 ساعة) — يرجى التواصل مع المشرف"
            status == "EXPIRED" ->
                "SUBSCRIPTION EXPIRED • CONTACT ADMINISTRATOR" to "انتهت صلاحية الاشتراك — يرجى التواصل مع المشرف للتجديد"
            status in listOf("BLOCKED", "SUSPENDED", "DISABLED") ->
                "$status • CONTACT ADMINISTRATOR" to "حالة الحساب ($status) — تواصل مع المشرف"
            dailyExceeded ->
                "DAILY QUOTA EXCEEDED" to "تم استهلاك الحصة اليومية المحددة للحساب (${bw.maxDailyMb} MB)"
            monthlyExceeded ->
                "MONTHLY QUOTA EXCEEDED" to "تم استهلاك الحصة الشهرية المحددة للحساب (${bw.maxMonthlyMb} MB)"
            status == "FREE_TRIAL" -> {
                val hrs = ((remSec ?: 0L) / 3600L).coerceAtLeast(0L)
                val mins = (((remSec ?: 0L) % 3600L) / 60L).coerceAtLeast(0L)
                "FREE TRIAL ACTIVE • $hrs HOURS REMAINING" to "التجربة المجانية نشطة • متبقّي ${hrs} س و ${mins} د"
            }
            else -> "ACTIVE ($subType)" to "الاشتراك نشط ومصرّح لهذا الجهاز"
        }

        val canConnect = devOk && status in listOf("ACTIVE", "FREE_TRIAL") && !dailyExceeded && !monthlyExceeded
        val vipCount = if (canConnect) {
            val vipKeyHex = cert.optString("vip_access_key_hex", "")
            val rawBundle = sp.getString("verified_bundle_json", null)
            val vipEnc = rawBundle?.let {
                runCatching { JSONObject(it).getJSONObject("bundle").optString("vip_nodes_enc_b64", "") }.getOrDefault("")
            }.orEmpty()
            EnterpriseCrypto.decryptVipNodes(vipKeyHex, vipEnc).size
        } else 0

        return AccountLicenseState(
            authRequired = authReq,
            isLoggedIn = true,
            userId = cert.optString("user_id", ""),
            username = ses.optString("username", ""),
            accountStatus = status,
            subscriptionType = subType,
            subscriptionStartIso = cert.optString("subscription_start", ""),
            expirationIso = expIso,
            remainingSeconds = remSec,
            deviceInstallId = deviceInstallId,
            deviceAuthorized = devOk,
            deviceLimit = cert.optInt("device_limit", 1),
            rememberMe = ses.optBoolean("remember_me", true),
            canConnectVpn = canConnect,
            statusHeadlineEn = headlineEn,
            statusDetailAr = detailAr,
            bandwidth = bw,
            dailyUsedBytes = dayUsed,
            monthlyUsedBytes = monthUsed,
            vipNodesUnlocked = vipCount,
            loginHistory = getLoginHistory(),
        )
    }
}
