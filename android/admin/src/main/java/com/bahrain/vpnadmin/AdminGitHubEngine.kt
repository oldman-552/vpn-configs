// =====================================================================
// AdminGitHubEngine.kt — محرك التشفير والإدارة السحابية المباشرة عبر GitHub
// لتطبيق المشرف المستقل (bahrain-vpn Admin APK).
// متوافق 100% على مستوى البايت مع لوحة الويب (WebCrypto)، محرك Python، وتطبيق المشترك.
// =====================================================================
package com.bahrain.vpnadmin

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Instant
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

object AdminCrypto {
    private const val PBKDF2_ITER = 120_000
    private val LOOKUP_DOMAIN = "bahrain-vpn-enterprise-v3-user-lookup".toByteArray(Charsets.UTF_8)
    const val VIP_NODES_AAD = "bahrain-vpn-vip-nodes-v31"
    private const val B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    fun randomHex(byteLen: Int = 16): String {
        val b = ByteArray(byteLen).also { SecureRandom().nextBytes(it) }
        return b.joinToString("") { "%02x".format(it) }
    }

    fun hexToBytes(hex: String): ByteArray {
        val clean = hex.trim()
        return ByteArray(clean.length / 2) { i ->
            clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    fun sha256Hex(text: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(text.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

    fun computeUserLookupId(username: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(LOOKUP_DOMAIN, "HmacSHA256"))
        return mac.doFinal(username.trim().lowercase(Locale.ROOT).toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }

    fun canonicalJson(v: Any?): String = when (v) {
        null, JSONObject.NULL -> "null"
        is Boolean -> if (v) "true" else "false"
        is Int, is Long -> v.toString()
        is Number -> {
            val d = v.toDouble()
            if (d == d.toLong().toDouble()) d.toLong().toString() else d.toString()
        }
        is String -> JSONObject.quote(v)
        is JSONArray -> (0 until v.length()).joinToString(",", "[", "]") { canonicalJson(v.get(it)) }
        is JSONObject -> v.keys().asSequence().toList().sorted()
            .joinToString(",", "{", "}") { k -> "${JSONObject.quote(k)}:${canonicalJson(v.get(k))}" }
        else -> JSONObject.quote(v.toString())
    }

    private fun deriveKey(secret: String, saltHex: String): SecretKeySpec {
        val spec = PBEKeySpec(secret.toCharArray(), hexToBytes(saltHex), PBKDF2_ITER, 256)
        val raw = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        return SecretKeySpec(raw, "AES")
    }

    fun encryptAesGcm(secret: String, saltHex: String, plainText: String, aad: String = ""): String {
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, deriveKey(secret, saltHex), GCMParameterSpec(128, iv))
        if (aad.isNotEmpty()) cipher.updateAAD(aad.toByteArray(Charsets.UTF_8))
        val ct = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(iv + ct, Base64.NO_WRAP)
    }

    fun decryptAesGcm(secret: String, saltHex: String, tokenB64: String, aad: String = ""): String {
        val raw = Base64.decode(tokenB64, Base64.DEFAULT)
        require(raw.size >= 28) { "Malformed AES-GCM payload" }
        val iv = raw.copyOfRange(0, 12)
        val ct = raw.copyOfRange(12, raw.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, deriveKey(secret, saltHex), GCMParameterSpec(128, iv))
        if (aad.isNotEmpty()) cipher.updateAAD(aad.toByteArray(Charsets.UTF_8))
        return String(cipher.doFinal(ct), Charsets.UTF_8)
    }

    fun encryptRawKeyAesGcm(keyHex: String, plainText: String, aad: String = VIP_NODES_AAD): String {
        val keyBytes = hexToBytes(keyHex)
        require(keyBytes.size == 32) { "Expected 32-byte AES-256 key" }
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(keyBytes, "AES"), GCMParameterSpec(128, iv))
        if (aad.isNotEmpty()) cipher.updateAAD(aad.toByteArray(Charsets.UTF_8))
        val ct = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(iv + ct, Base64.NO_WRAP)
    }

    fun decryptRawKeyAesGcm(keyHex: String, tokenB64: String, aad: String = VIP_NODES_AAD): String {
        val keyBytes = hexToBytes(keyHex)
        require(keyBytes.size == 32) { "Expected 32-byte AES-256 key" }
        val raw = Base64.decode(tokenB64, Base64.DEFAULT)
        require(raw.size >= 28) { "Malformed AES-GCM payload" }
        val iv = raw.copyOfRange(0, 12)
        val ct = raw.copyOfRange(12, raw.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(keyBytes, "AES"), GCMParameterSpec(128, iv))
        if (aad.isNotEmpty()) cipher.updateAAD(aad.toByteArray(Charsets.UTF_8))
        return String(cipher.doFinal(ct), Charsets.UTF_8)
    }

    fun generateEcdsaKeyPair(): Pair<String, String> {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val kp = kpg.generateKeyPair()
        val privB64 = Base64.encodeToString(kp.private.encoded, Base64.NO_WRAP)
        val pubB64 = Base64.encodeToString(kp.public.encoded, Base64.NO_WRAP)
        return privB64 to pubB64
    }

    fun signEcdsaDerB64(privatePkcs8B64: String, canonicalPayload: String): String {
        val privBytes = Base64.decode(privatePkcs8B64, Base64.DEFAULT)
        val privKey = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(privBytes))
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(privKey)
        sig.update(canonicalPayload.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(sig.sign(), Base64.NO_WRAP)
    }

    // RFC 6238 TOTP (6 digits, 30s)
    fun generateTotpSecretB32(): String {
        val rnd = ByteArray(20).also { SecureRandom().nextBytes(it) }
        var bits = 0
        var value = 0
        val sb = StringBuilder()
        for (b in rnd) {
            value = (value shl 8) or (b.toInt() and 0xFF)
            bits += 8
            while (bits >= 5) {
                sb.append(B32_ALPHABET[(value ushr (bits - 5)) and 31])
                bits -= 5
            }
        }
        return sb.toString()
    }

    private fun decodeBase32(secret: String): ByteArray {
        val clean = secret.uppercase(Locale.ROOT).filter { it in B32_ALPHABET }
        var bits = 0
        var value = 0
        val out = ArrayList<Byte>()
        for (ch in clean) {
            value = (value shl 5) or B32_ALPHABET.indexOf(ch)
            bits += 5
            if (bits >= 8) {
                out.add(((value ushr (bits - 8)) and 0xFF).toByte())
                bits -= 8
            }
        }
        return out.toByteArray()
    }

    fun computeTotpCode(secretB32: String, unixSec: Long = System.currentTimeMillis() / 1000L): String {
        val keyBytes = decodeBase32(secretB32)
        val counter = unixSec / 30L
        val msg = ByteBuffer.allocate(8).putLong(counter).array()
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(keyBytes, "HmacSHA1"))
        val digest = mac.doFinal(msg)
        val offset = digest.last().toInt() and 0x0F
        val bin = ((digest[offset].toInt() and 0x7F) shl 24) or
            ((digest[offset + 1].toInt() and 0xFF) shl 16) or
            ((digest[offset + 2].toInt() and 0xFF) shl 8) or
            (digest[offset + 3].toInt() and 0xFF)
        return String.format(Locale.US, "%06d", bin % 1_000_000)
    }

    fun verifyTotpCode(secretB32: String, code: String, unixSec: Long = System.currentTimeMillis() / 1000L): Boolean {
        if (secretB32.isBlank()) return true
        val clean = code.trim()
        if (clean.length != 6 || clean.any { !it.isDigit() }) return false
        return listOf(-30L, 0L, 30L).any { delta -> computeTotpCode(secretB32, unixSec + delta) == clean }
    }
}

class AdminGitHubVaultManager(ctx: Context) {
    private val sp = ctx.applicationContext.getSharedPreferences("admin_secure_prefs", Context.MODE_PRIVATE)

    private fun localKey(): SecretKey {
        runCatching {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val alias = "bahrain_vpn_admin_local_key"
            (ks.getKey(alias, null) as? SecretKey)?.let { return it }
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
        val seed = sp.getString("fallback_seed", null) ?: AdminCrypto.randomHex(32).also {
            sp.edit().putString("fallback_seed", it).apply()
        }
        return SecretKeySpec(AdminCrypto.hexToBytes(seed), "AES")
    }

    fun saveEncryptedCredentials(repo: String, token: String, adminUser: String) {
        val plain = JSONObject().put("repo", repo).put("token", token).put("admin", adminUser).toString()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, localKey())
        val iv = cipher.iv
        val ct = cipher.doFinal(plain.toByteArray(Charsets.UTF_8))
        val packed = ByteArray(1 + iv.size + ct.size)
        packed[0] = iv.size.toByte()
        System.arraycopy(iv, 0, packed, 1, iv.size)
        System.arraycopy(ct, 0, packed, 1 + iv.size, ct.size)
        sp.edit().putString("creds_blob", Base64.encodeToString(packed, Base64.NO_WRAP)).apply()
    }

    fun loadEncryptedCredentials(): Triple<String, String, String>? {
        val b64 = sp.getString("creds_blob", null) ?: return null
        return runCatching {
            val raw = Base64.decode(b64, Base64.DEFAULT)
            val ivLen = raw[0].toInt() and 0xFF
            val iv = raw.copyOfRange(1, 1 + ivLen)
            val ct = raw.copyOfRange(1 + ivLen, raw.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, localKey(), GCMParameterSpec(128, iv))
            val o = JSONObject(String(cipher.doFinal(ct), Charsets.UTF_8))
            Triple(o.optString("repo"), o.optString("token"), o.optString("admin"))
        }.getOrNull()
    }

    fun createEmptyVaultDb(): JSONObject {
        val (privB64, pubB64) = AdminCrypto.generateEcdsaKeyPair()
        return JSONObject()
            .put("schema_version", 3)
            .put("bundle_release", "1.0")
            .put("signing_keys", JSONObject().put("privatePkcs8B64", privB64).put("publicSpkiB64", pubB64))
            .put("vip_key_hex", AdminCrypto.randomHex(32))
            .put("vip_servers", JSONArray())
            .put("admin_users", JSONArray())
            .put("users", JSONArray())
            .put("bandwidth_limits", JSONObject())
            .put("user_devices", JSONArray())
            .put("device_violations", JSONArray())
            .put("user_sessions", JSONArray())
            .put("notifications", JSONArray())
            .put("app_versions", JSONArray())
            .put(
                "remote_config",
                JSONObject()
                    .put("auth_require_account", JSONObject().put("value", false).put("sensitive", true).put("desc", "إلزام تسجيل الدخول قبل تشغيل VPN"))
                    .put("auto_block_on_device_violation", JSONObject().put("value", false).put("sensitive", true).put("desc", "حظر الحساب تلقائيًا عند محاولة جهاز غير مصرح"))
                    .put("auto_failover_enabled", JSONObject().put("value", true).put("sensitive", false).put("desc", "التبديل الذكي خلال ثانيتين عند سقوط النفق"))
                    .put("trial_duration_hours", JSONObject().put("value", 48).put("sensitive", false).put("desc", "مدة التجربة المجانية بالساعات"))
                    .put("promo_enabled", JSONObject().put("value", true).put("sensitive", false).put("desc", "تفعيل نافذة الإعلانات المتناوبة"))
            )
            .put("admin_audit_logs", JSONArray())
    }

    fun ensureV31Defaults(db: JSONObject): JSONObject {
        if (db.optString("vip_key_hex", "").length != 64) {
            db.put("vip_key_hex", AdminCrypto.randomHex(32))
        }
        if (db.optJSONArray("vip_servers") == null) {
            db.put("vip_servers", JSONArray())
        }
        val rc = db.optJSONObject("remote_config") ?: JSONObject().also { db.put("remote_config", it) }
        if (!rc.has("auto_failover_enabled")) {
            rc.put("auto_failover_enabled", JSONObject().put("value", true).put("sensitive", false).put("desc", "التبديل الذكي خلال ثانيتين عند سقوط النفق"))
        }
        return db
    }

    fun appendAuditLog(db: JSONObject, adminUser: String, action: String, targetType: String, targetId: String, afterObj: JSONObject) {
        val logs = db.optJSONArray("admin_audit_logs") ?: JSONArray().also { db.put("admin_audit_logs", it) }
        val prevHash = if (logs.length() > 0) logs.getJSONObject(0).optString("entry_hash", "GENESIS") else "GENESIS"
        val now = Instant.now().toString()
        val afterStr = afterObj.toString()
        val mat = "$now|$adminUser|$action|$targetType|$targetId|$afterStr|$prevHash"
        val entryHash = AdminCrypto.sha256Hex(mat)
        val newLogs = JSONArray()
        newLogs.put(
            JSONObject()
                .put("id", "aud_${AdminCrypto.randomHex(6)}")
                .put("logged_at", now)
                .put("admin", adminUser)
                .put("action", action)
                .put("target_type", targetType)
                .put("target_id", targetId)
                .put("after_json", afterStr)
                .put("prev_hash", prevHash)
                .put("entry_hash", entryHash)
        )
        for (i in 0 until logs.length()) newLogs.put(logs.getJSONObject(i))
        db.put("admin_audit_logs", newLogs)
    }

    fun verifyAuditChain(db: JSONObject): Boolean {
        val logs = db.optJSONArray("admin_audit_logs") ?: return true
        var expectedPrev = "GENESIS"
        for (i in logs.length() - 1 downTo 0) {
            val r = logs.getJSONObject(i)
            if (r.optString("prev_hash") != expectedPrev) return false
            val mat = "${r.optString("logged_at")}|${r.optString("admin")}|${r.optString("action")}|" +
                "${r.optString("target_type")}|${r.optString("target_id")}|${r.optString("after_json")}|${r.optString("prev_hash")}"
            if (AdminCrypto.sha256Hex(mat) != r.optString("entry_hash")) return false
            expectedPrev = r.optString("entry_hash")
        }
        return true
    }

    fun sealUserEnvelope(db: JSONObject, userObj: JSONObject, plainPassword: String) {
        ensureV31Defaults(db)
        val uid = userObj.getString("id")
        val uname = userObj.getString("username").trim().lowercase(Locale.ROOT)
        val bw = db.optJSONObject("bandwidth_limits")?.optJSONObject(uid) ?: JSONObject()
            .put("max_download_kbps", 0)
            .put("max_upload_kbps", 0)
            .put("max_total_kbps", 0)
            .put("max_daily_mb", 0)
            .put("max_monthly_mb", 0)
            .put("max_concurrent_connections", 1)
            .put("auto_block_on_violation", false)

        val devsArr = db.optJSONArray("user_devices") ?: JSONArray()
        val authDevs = JSONArray()
        for (i in 0 until devsArr.length()) {
            val d = devsArr.getJSONObject(i)
            if (d.optString("user_id") == uid && d.optString("device_status") == "AUTHORIZED") {
                authDevs.put(d.optString("device_install_id"))
            }
        }

        val cert = JSONObject()
            .put("user_id", uid)
            .put("username", uname)
            .put("account_status", userObj.optString("account_status", "ACTIVE"))
            .put("subscription_type", userObj.optString("subscription_type", "MONTHLY"))
            .put("subscription_start", userObj.optString("subscription_start", ""))
            .put("subscription_expiration", userObj.optString("subscription_expiration", ""))
            .put("trial_activation_date", userObj.optString("trial_activation_date", ""))
            .put("device_limit", userObj.optInt("device_limit", 1))
            .put("authorized_devices", authDevs)
            .put("session_revoked_at", userObj.optString("session_revoked_at", ""))
            .put("vip_access_key_hex", db.getString("vip_key_hex"))
            .put("bandwidth", bw)
            .put("issued_at", userObj.optString("updated_at", Instant.now().toString()))

        val privB64 = db.getJSONObject("signing_keys").getString("privatePkcs8B64")
        val certSig = AdminCrypto.signEcdsaDerB64(privB64, AdminCrypto.canonicalJson(cert))
        val saltHex = AdminCrypto.randomHex(16)
        val envJson = AdminCrypto.canonicalJson(JSONObject().put("certificate", cert).put("signature_b64", certSig))
        val envB64 = AdminCrypto.encryptAesGcm("$uname:$plainPassword", saltHex, envJson, uname)
        userObj.put("salt_hex", saltHex)
        userObj.put("envelope_b64", envB64)
    }

    fun buildSignedPublicBundle(db: JSONObject): JSONObject {
        ensureV31Defaults(db)
        val keys = db.getJSONObject("signing_keys")
        val privB64 = keys.getString("privatePkcs8B64")
        val pubB64 = keys.getString("publicSpkiB64")

        val licenses = JSONObject()
        val users = db.optJSONArray("users") ?: JSONArray()
        for (i in 0 until users.length()) {
            val u = users.getJSONObject(i)
            val env = u.optString("envelope_b64", "")
            if (env.isBlank()) continue
            val lookupId = AdminCrypto.computeUserLookupId(u.getString("username"))
            licenses.put(
                lookupId,
                JSONObject()
                    .put("salt_hex", u.optString("salt_hex"))
                    .put("envelope_b64", env)
                    .put("status_code", u.optString("account_status", "ACTIVE"))
                    .put("revoked_at", u.optString("session_revoked_at", ""))
                    .put("updated_at", u.optString("updated_at", "")),
            )
        }

        val vipRawArr = db.optJSONArray("vip_servers") ?: JSONArray()
        val activeVipList = ArrayList<JSONObject>()
        for (i in 0 until vipRawArr.length()) {
            val v = vipRawArr.getJSONObject(i)
            if (v.optBoolean("enabled", true)) {
                activeVipList.add(
                    JSONObject()
                        .put("id", v.optString("id"))
                        .put("label", v.optString("label"))
                        .put("country", v.optString("country", ""))
                        .put("protocol", v.optString("protocol", "VLESS"))
                        .put("uri", v.optString("uri"))
                        .put("priority", v.optInt("priority", 200))
                )
            }
        }
        activeVipList.sortByDescending { it.optInt("priority", 200) }
        val activeVipJsonArr = JSONArray().apply { activeVipList.forEach { put(it) } }
        val vipEncB64 = if (activeVipJsonArr.length() > 0) {
            AdminCrypto.encryptRawKeyAesGcm(
                db.getString("vip_key_hex"),
                AdminCrypto.canonicalJson(activeVipJsonArr),
                AdminCrypto.VIP_NODES_AAD,
            )
        } else {
            ""
        }

        val rcFlat = JSONObject()
        val rcObj = db.optJSONObject("remote_config") ?: JSONObject()
        rcObj.keys().forEach { k -> rcFlat.put(k, rcObj.getJSONObject(k).opt("value")) }

        val bundleBody = JSONObject()
            .put("schema_version", 3)
            .put("bundle_release", "1.0")
            .put("generated_at", Instant.now().toString())
            .put("public_key_spki_b64", pubB64)
            .put("remote_config", rcFlat)
            .put("app_updates", db.optJSONArray("app_versions") ?: JSONArray())
            .put("vip_nodes_enc_b64", vipEncB64)
            .put("licenses", licenses)

        val sigB64 = AdminCrypto.signEcdsaDerB64(privB64, AdminCrypto.canonicalJson(bundleBody))
        return JSONObject().put("bundle", bundleBody).put("signature_b64", sigB64)
    }

    // ── GitHub REST API Operations ──
    suspend fun readGitHubJson(repo: String, token: String, branch: String, path: String): Pair<String?, JSONObject?> =
        withContext(Dispatchers.IO) {
            var conn: HttpURLConnection? = null
            try {
                val url = URL("https://api.github.com/repos/$repo/contents/$path?ref=$branch")
                conn = (url.openConnection() as HttpURLConnection).apply {
                    connectTimeout = 15_000
                    readTimeout = 15_000
                    setRequestProperty("Accept", "application/vnd.github+json")
                    if (token.isNotBlank()) setRequestProperty("Authorization", "Bearer $token")
                }
                if (conn.responseCode == 404) return@withContext null to null
                if (conn.responseCode !in 200..299) throw IllegalStateException("GitHub HTTP ${conn.responseCode}")
                val meta = JSONObject(conn.inputStream.bufferedReader().readText())
                val sha = meta.optString("sha").takeIf { it.isNotBlank() }
                val rawContent = meta.optString("content", "").replace("\\s+".toRegex(), "")
                val decoded = String(Base64.decode(rawContent, Base64.DEFAULT), Charsets.UTF_8)
                sha to JSONObject(decoded)
            } finally {
                conn?.disconnect()
            }
        }

    suspend fun writeGitHubJson(
        repo: String,
        token: String,
        branch: String,
        path: String,
        payload: JSONObject,
        prevSha: String?,
        commitMsg: String,
    ): String? = withContext(Dispatchers.IO) {
        var conn: HttpURLConnection? = null
        try {
            val url = URL("https://api.github.com/repos/$repo/contents/$path")
            val bodyJson = JSONObject()
                .put("message", commitMsg)
                .put("content", Base64.encodeToString(payload.toString(2).toByteArray(Charsets.UTF_8), Base64.NO_WRAP))
                .put("branch", branch)
            if (!prevSha.isNullOrBlank()) bodyJson.put("sha", prevSha)

            conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "PUT"
                doOutput = true
                connectTimeout = 15_000
                readTimeout = 20_000
                setRequestProperty("Accept", "application/vnd.github+json")
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("Authorization", "Bearer $token")
            }
            conn.outputStream.use { it.write(bodyJson.toString().toByteArray(Charsets.UTF_8)) }
            if (conn.responseCode !in 200..299) {
                val err = runCatching { conn.errorStream?.bufferedReader()?.readText().orEmpty() }.getOrDefault("")
                throw IllegalStateException("GitHub PUT ${conn.responseCode}: ${err.take(140)}")
            }
            val resp = JSONObject(conn.inputStream.bufferedReader().readText())
            resp.optJSONObject("content")?.optString("sha")
        } finally {
            conn?.disconnect()
        }
    }

    suspend fun triggerGitHubWorkflow(repo: String, token: String, workflowFile: String, ref: String = "main"): Boolean =
        withContext(Dispatchers.IO) {
            var conn: HttpURLConnection? = null
            try {
                val url = URL("https://api.github.com/repos/$repo/actions/workflows/$workflowFile/dispatches")
                conn = (url.openConnection() as HttpURLConnection).apply {
                    requestMethod = "POST"
                    doOutput = true
                    connectTimeout = 15_000
                    readTimeout = 15_000
                    setRequestProperty("Accept", "application/vnd.github+json")
                    setRequestProperty("Content-Type", "application/json")
                    setRequestProperty("Authorization", "Bearer $token")
                }
                val body = JSONObject().put("ref", ref).toString()
                conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
                conn.responseCode in listOf(200, 201, 204)
            } finally {
                conn?.disconnect()
            }
        }
}
