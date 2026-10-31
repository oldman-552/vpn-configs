// =====================================================================
// AppUpdateManager.kt — نظام إشعارات التحديث الذكي المتوافق مع Play Protect (v1).
// يختار تلقائيًا حزمة المعالج المناسبة (arm64-v8a / x86_64 / universal)،
// يتحقق من أمان رابط HTTPS الرسمي، ويعرض/ينسخ بصمة SHA-256، ثم يفوّض التحميل
// لمتصفح النظام الرسمي بدل تنزيل أو تثبيت ملفات APK داخليًا (Zero Dropper Behavior).
// =====================================================================
package com.bahrain.vpnconfigs.enterprise

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import com.bahrain.vpnconfigs.util.tr
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest

data class AppUpdateInfo(
    val versionCode: Int,
    val versionName: String,
    val releaseNotes: String,
    val mandatory: Boolean,
    val minSupportedCode: Int,
    val apkUrl: String,
    val apkSha256: String,
    val signingCertSha256: String,
    val selectedAbi: String = "universal",
)

object AppUpdateManager {

    fun currentVersionCode(ctx: Context): Int = runCatching {
        val pi = ctx.packageManager.getPackageInfo(ctx.packageName, 0)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) pi.longVersionCode.toInt() else @Suppress("DEPRECATION") pi.versionCode
    }.getOrDefault(13)

    fun currentVersionName(ctx: Context): String = runCatching {
        ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName ?: "1.0"
    }.getOrDefault("1.0")

    /**
     * يحسم الحزمة الأنسب لمعمارية معالج الهاتف (مثل arm64-v8a لتوفير ~50% من الحجم)
     * مع التراجع الآمن إلى النسخة الشاملة universal أو الرابط الافتراضي.
     */
    fun resolveBestAbiAsset(
        updateObj: JSONObject,
        supportedAbis: Array<String> = Build.SUPPORTED_ABIS,
    ): Triple<String, String, String> {
        val abiMap = updateObj.optJSONObject("abi_assets")
        if (abiMap != null) {
            for (abi in supportedAbis) {
                val entry = abiMap.optJSONObject(abi) ?: continue
                val url = entry.optString("apk_url", "").trim()
                if (url.isNotEmpty()) {
                    val sha = entry.optString("apk_sha256", "").trim().lowercase()
                    return Triple(abi, url, sha)
                }
            }
            val uni = abiMap.optJSONObject("universal")
            if (uni != null) {
                val url = uni.optString("apk_url", "").trim()
                if (url.isNotEmpty()) {
                    val sha = uni.optString("apk_sha256", "").trim().lowercase()
                    return Triple("universal", url, sha)
                }
            }
        }
        return Triple(
            "universal",
            updateObj.optString("apk_url", "").trim(),
            updateObj.optString("apk_sha256", "").trim().lowercase(),
        )
    }

    fun evaluateAvailableUpdate(
        ctx: Context,
        updatesJson: JSONArray,
        supportedAbis: Array<String> = Build.SUPPORTED_ABIS,
    ): AppUpdateInfo? {
        val curCode = currentVersionCode(ctx)
        var newest: AppUpdateInfo? = null
        for (i in 0 until updatesJson.length()) {
            val o = updatesJson.optJSONObject(i) ?: continue
            if (o.optString("target_app", "USER") != "USER" || !o.optBoolean("is_active", true)) continue
            val code = o.optInt("version_code", 0)
            val minSup = o.optInt("min_supported_code", 1)
            val mandatory = o.optBoolean("mandatory", false) || curCode < minSup
            if (code > curCode && (newest == null || code > newest.versionCode)) {
                val (abiLabel, resolvedUrl, resolvedSha) = resolveBestAbiAsset(o, supportedAbis)
                newest = AppUpdateInfo(
                    versionCode = code,
                    versionName = o.optString("version_name", ""),
                    releaseNotes = o.optString("release_notes", ""),
                    mandatory = mandatory,
                    minSupportedCode = minSup,
                    apkUrl = resolvedUrl,
                    apkSha256 = resolvedSha,
                    signingCertSha256 = o.optString("signing_cert_sha256", "").lowercase(),
                    selectedAbi = abiLabel,
                )
            }
        }
        return newest
    }

    fun computeFileSha256(file: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buf = ByteArray(16 * 1024)
            var n: Int
            while (input.read(buf).also { n = it } > 0) {
                md.update(buf, 0, n)
            }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    /**
     * يتحقّق بصرامة من أن رابط التحديث يعتمد HTTPS حصريًا وخالٍ من الشبكات الخاصة أو المحلية.
     */
    fun validateSafeUpdateHttpsUrl(rawUrl: String): Uri? {
        val trimmed = rawUrl.trim()
        if (trimmed.isEmpty() || trimmed.length > 2048) return null
        val uri = runCatching { Uri.parse(trimmed) }.getOrNull() ?: return null
        val scheme = uri.scheme?.lowercase() ?: return null
        if (scheme != "https") return null
        if (!uri.userInfo.isNullOrEmpty()) return null
        val host = uri.host?.trim()?.removeSurrounding("[", "]")?.trimEnd('.')?.lowercase() ?: return null
        if (host.isEmpty() || !host.contains('.')) return null
        if (host == "localhost" || host == "0.0.0.0" || host == "::1" ||
            host.endsWith(".local") || host.endsWith(".internal") || host.endsWith(".localhost")
        ) {
            return null
        }
        if (host.startsWith("127.") || host.startsWith("10.") || host.startsWith("192.168.") ||
            host.startsWith("169.254.") || host.startsWith("0.") || host.startsWith("fe80:")
        ) {
            return null
        }
        if (host.startsWith("172.")) {
            val second = host.removePrefix("172.").substringBefore('.').toIntOrNull()
            if (second != null && second in 16..31) return null
        }
        return uri
    }

    /**
     * يبني نيّة فتح المتصفح الآمن الرسمي للنظام (بدون أي نوع MIME لتثبيت الحزم داخليًا،
     * لضمان عدم مطابقة سلوك المحمّلات/Dropper في Google Play Protect).
     */
    fun buildSafeBrowserUpdateIntent(info: AppUpdateInfo): Result<Intent> {
        val safeUri = validateSafeUpdateHttpsUrl(info.apkUrl)
            ?: return Result.failure(SecurityException(tr("رابط التحديث غير آمن — يُسمح بروابط HTTPS الرسمية فقط", "Unsafe update URL — only official HTTPS URLs are permitted")))
        val intent = Intent(Intent.ACTION_VIEW, safeUri).apply {
            addCategory(Intent.CATEGORY_BROWSABLE)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        return Result.success(intent)
    }

    fun openVerifiedUpdateInSystemBrowser(ctx: Context, info: AppUpdateInfo): Result<Uri> {
        val safeUri = validateSafeUpdateHttpsUrl(info.apkUrl)
            ?: return Result.failure(SecurityException(tr("رابط التحديث غير آمن — يُسمح بروابط HTTPS الرسمية فقط", "Unsafe update URL — only official HTTPS URLs are permitted")))
        return runCatching {
            if (info.apkSha256.length == 64) {
                runCatching {
                    val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                    cm?.setPrimaryClip(ClipData.newPlainText("bahrain-vpn SHA-256", info.apkSha256))
                }
            }
            val intent = buildSafeBrowserUpdateIntent(info).getOrThrow()
            ctx.startActivity(intent)
            safeUri
        }
    }
}
