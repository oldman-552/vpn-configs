// =====================================================================
// UiMessages.kt — رسائل المستخدم العامة وتنقيح الأخطاء التقنية.
// تمنع تسرّب روابط المستودع أو مسارات الملفات أو الاستثناءات البرمجية للواجهة.
// =====================================================================
package com.bahrain.vpnconfigs.util

import com.bahrain.vpnconfigs.data.Repo
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

object UiMessages {

    const val MSG_UPDATING = "جارٍ تحديث قائمة السيرفرات"
    const val MSG_UPDATE_FAILED = "تعذر تحديث قائمة السيرفرات. حاول مرة أخرى"
    const val MSG_NO_SERVERS = "لا توجد سيرفرات متاحة حاليًا"
    const val MSG_TEST_FAILED = "تعذر إكمال فحص السيرفرات. حاول مرة أخرى"
    const val MSG_ENGINE_UNAVAILABLE = "محرّك الاتصال غير جاهز حاليًا"
    const val MSG_SERVER_UNREACHABLE = "تعذر الاتصال بالسيرفر المحدد. حاول مرة أخرى"

    fun msgUpdating(): String = tr(MSG_UPDATING, "Updating server list…")
    fun msgUpdateFailed(): String = tr(MSG_UPDATE_FAILED, "Could not update server list. Please try again.")
    fun msgNoServers(): String = tr(MSG_NO_SERVERS, "No servers currently available")
    fun msgTestFailed(): String = tr(MSG_TEST_FAILED, "Could not complete server scan. Please try again.")
    fun msgEngineUnavailable(): String = tr(MSG_ENGINE_UNAVAILABLE, "VPN engine is currently unavailable")
    fun msgServerUnreachable(): String = tr(MSG_SERVER_UNREACHABLE, "Could not reach selected server. Please try again.")

    private val TECHNICAL_LEAK_RE = Regex(
        "(" +
            "https?://|" +
            "github\\.com|githubusercontent\\.com|github\\.io|jsdelivr\\.net|@data|" +
            "alive\\.(?:json|txt)|meta\\.json|ads\\.json|reliable\\.txt|low_latency\\.txt|high_throughput\\.txt|" +
            "best100\\.txt|config\\.txt|sub\\.txt|libsingbox\\.so|" +
            "/data/|/storage/|/sdcard/|cache:|" +
            "Exception|Error:|Throwable|StackTrace|\\bat\\s+[a-z0-9_]+\\.[a-z0-9_]+" +
            ")",
        RegexOption.IGNORE_CASE,
    )

    /** يضمن عدم عرض أي رابط مصدر أو مسار داخلي أو استثناء برمجي للمستخدم. */
    fun sanitizeError(raw: String?, fallback: String = MSG_UPDATE_FAILED): String {
        val trimmed = raw?.trim().orEmpty()
        if (trimmed.isEmpty()) return fallback
        if (Repo.containsSourceIdentifier(trimmed) || TECHNICAL_LEAK_RE.containsMatchIn(trimmed)) {
            return fallback
        }
        if (trimmed.contains('\n') && trimmed.length > 140) return fallback
        return trimmed
    }

    /** تنسيق موحّد وواضح لسطر «آخر تحديث: [الوقت]» / «Updated: [time]» دون أي إشارة للمصدر الداخلي. */
    fun formatLastUpdated(remoteGeneratedAt: String?, localRefreshEpochMs: Long): String {
        val prefix = tr("آخر تحديث:", "Updated:")
        if (localRefreshEpochMs > 0L) {
            val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US)
            return "$prefix ${fmt.format(Date(localRefreshEpochMs))}"
        }
        val cleanRemote = remoteGeneratedAt?.trim().orEmpty()
        if (cleanRemote.isNotEmpty() && cleanRemote != "—" && cleanRemote.length >= 16) {
            val parsedMs = parseIsoUtcMillis(cleanRemote)
            if (parsedMs > 0L) {
                val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US)
                return "$prefix ${fmt.format(Date(parsedMs))}"
            }
            val normalized = cleanRemote.take(16).replace('T', ' ')
            return "$prefix $normalized"
        }
        return ""
    }

    fun parseIsoUtcMillis(iso: String?): Long {
        val raw = iso?.trim().orEmpty()
        if (raw.length < 16) return 0L
        val patterns = listOf(
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'",
            "yyyy-MM-dd'T'HH:mm'Z'",
            "yyyy-MM-dd HH:mm:ss",
            "yyyy-MM-dd HH:mm",
        )
        for (pat in patterns) {
            try {
                val sdf = SimpleDateFormat(pat, Locale.US).apply {
                    if (pat.endsWith("'Z'")) {
                        timeZone = TimeZone.getTimeZone("UTC")
                    }
                }
                val d = sdf.parse(raw)
                if (d != null) return d.time
            } catch (_: Exception) {
                // تجريب الصيغة التالية
            }
        }
        return 0L
    }
}
