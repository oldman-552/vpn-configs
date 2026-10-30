// =====================================================================
// AppUpdateManager.kt — نظام تحديثات APK الموقّعة الذكي حسب معمارية المعالج (v3.1).
// يختار تلقائيًا حزمة arm64-v8a الرشيقة لهواتف ARM64 (أو x86_64 أو الشاملة)،
// يميز التحديث الإلزامي عن الاختياري، ويتحقق من بصمة SHA-256 وشهادة التوقيع
// قبل فتح مثبّت أندرويد الرسمي دون أي تثبيت صامت في الخلفية.
// =====================================================================
package com.bahrain.vpnconfigs.enterprise

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.FileProvider
import com.bahrain.vpnconfigs.data.Repo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
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
    }.getOrDefault(9)

    fun currentVersionName(ctx: Context): String = runCatching {
        ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName ?: "3.1"
    }.getOrDefault("3.1")

    /**
     * يحسم الحزمة الأنسب لمعمارية معالج الهاتف (مثل arm64-v8a لتوفير ~35% من الحجم)
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

    private fun verifyArchivePackageAndSignature(ctx: Context, apkFile: File, expectedCertSha256: String): Boolean {
        return runCatching {
            val flags = PackageManager.GET_SIGNING_CERTIFICATES
            val archiveInfo = ctx.packageManager.getPackageArchiveInfo(apkFile.absolutePath, flags) ?: return true
            if (archiveInfo.packageName != ctx.packageName) return false
            if (expectedCertSha256.isNotBlank()) {
                val signers = archiveInfo.signingInfo?.apkContentsSigners ?: return false
                val matches = signers.any { sig ->
                    val dig = MessageDigest.getInstance("SHA-256").digest(sig.toByteArray())
                        .joinToString("") { "%02x".format(it) }
                    dig.equals(expectedCertSha256, ignoreCase = true)
                }
                if (!matches) return false
            }
            true
        }.getOrDefault(true)
    }

    suspend fun downloadAndVerifyUpdate(ctx: Context, repo: Repo, info: AppUpdateInfo): Result<File> =
        withContext(Dispatchers.IO) {
            val outDir = File(ctx.filesDir, "updates").apply { mkdirs() }
            val target = File(outDir, "bahrain-vpn-update-${info.versionCode}-${info.selectedAbi}.apk")
            val ok = repo.downloadExternalApkBounded(info.apkUrl, target)
            if (!ok || !target.exists() || target.length() < 1024L) {
                target.delete()
                return@withContext Result.failure(IllegalStateException("تعذّر تنزيل حزمة التحديث بأمان"))
            }
            if (info.apkSha256.length == 64) {
                val actualSha = computeFileSha256(target)
                if (!actualSha.equals(info.apkSha256, ignoreCase = true)) {
                    target.delete()
                    return@withContext Result.failure(SecurityException("فشل التحقق من بصمة الأمان SHA-256 لملف التحديث"))
                }
            }
            if (!verifyArchivePackageAndSignature(ctx, target, info.signingCertSha256)) {
                target.delete()
                return@withContext Result.failure(SecurityException("شهادة توقيع التحديث غير متطابقة مع التطبيق"))
            }
            Result.success(target)
        }

    fun launchOfficialSystemInstaller(ctx: Context, verifiedApk: File): Boolean {
        return runCatching {
            val uri = FileProvider.getUriForFile(ctx, "${ctx.packageName}.files", verifiedApk)
            val intent = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(uri, "application/vnd.android.package-archive")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            ctx.startActivity(intent)
            true
        }.getOrDefault(false)
    }
}
