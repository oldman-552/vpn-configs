// =====================================================================
// AppDiag.kt — تسجيل تشخيصي آمن للمطوّر مفصول تمامًا عن واجهة المستخدم.
// يحجب بيانات الاعتماد والأسرار وعناوين المصادر من سجلات الإنتاج (Release).
// =====================================================================
package com.bahrain.vpnconfigs.util

import android.content.Context
import android.content.pm.ApplicationInfo
import android.util.Log

object AppDiag {

    @Volatile
    private var debugEnabled: Boolean = false

    private val URI_SECRET_RE = Regex(
        "\\b(vless|vmess|trojan|ss|hysteria2|hy2|tuic)://[^\\s#]+",
        RegexOption.IGNORE_CASE,
    )
    private val QUERY_SECRET_RE = Regex(
        "((?:password|pass|uuid|id|auth|token|pbk|sid)=)[^&\\s]+",
        RegexOption.IGNORE_CASE,
    )

    fun init(ctx: Context) {
        debugEnabled = (ctx.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
    }

    /** تنقيح أي نص تشخيصي من بيانات اعتماد البروكسي أو المعرّفات السرية قبل التسجيل. */
    fun redactSecrets(raw: String?): String {
        if (raw.isNullOrBlank()) return ""
        val maskedUris = URI_SECRET_RE.replace(raw) { m ->
            val full = m.value
            val scheme = full.substringBefore("://")
            val hostPart = full.substringAfter("@", "").substringBefore("?").substringBefore("#")
            if (hostPart.isNotBlank()) "$scheme://[REDACTED]@$hostPart" else "$scheme://[REDACTED]"
        }
        return QUERY_SECRET_RE.replace(maskedUris, "$1[REDACTED]").take(500)
    }

    fun d(tag: String, message: String) {
        if (!debugEnabled) return
        runCatching { Log.d(tag, redactSecrets(message)) }
    }

    fun w(tag: String, message: String, err: Throwable? = null) {
        if (!debugEnabled) return
        val errSummary = err?.let { " (${it.javaClass.simpleName})" } ?: ""
        runCatching { Log.w(tag, redactSecrets(message) + errSummary) }
    }
}
