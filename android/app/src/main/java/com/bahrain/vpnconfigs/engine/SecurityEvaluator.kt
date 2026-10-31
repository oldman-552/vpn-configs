// =====================================================================
// SecurityEvaluator.kt — محرك تقييم الأمان والخصوصية المستقل (Phase 2).
// يفصل كليًا بين سرعة السيرفر وتقييم أمان النقل وخصوصية المشغّل:
//   • السيرفر السريع لا يُعتبر آمنًا تلقائيًا أبدًا.
//   • العُقد العامة المجهولة لا تحصل على Privacy = Verified مطلقًا.
// =====================================================================
package com.bahrain.vpnconfigs.engine

import android.net.Uri
import com.bahrain.vpnconfigs.util.AppI18n
import com.bahrain.vpnconfigs.util.tr
import org.json.JSONObject
import java.util.concurrent.ConcurrentHashMap

data class ServerSecurityProfile(
    val securityAssessment: String,   // Verified | Partial | Unknown | Failed
    val privacyAssessment: String,    // Verified | Unverified | Unknown | High Risk
    val riskLevel: String,            // LOW | MEDIUM | HIGH | CRITICAL | UNKNOWN
    val tlsEnabled: Boolean = false,
    val allowInsecure: Boolean = false,
    val aeadCipher: Boolean = false,
    val quarantined: Boolean = false,
    val summaryAr: String = "",
)

object SecurityEvaluator {

    private val STRONG_AEAD_SS = setOf(
        "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
        "aes-256-gcm",
        "aes-128-gcm",
        "aes-192-gcm",
        "chacha20-ietf-poly1305",
        "xchacha20-ietf-poly1305",
    )

    private val BROKEN_CIPHERS = setOf("none", "plain", "rc4", "rc4-md5", "table", "des-cfb")
    private val SUSPICIOUS_PORTS = setOf(21, 22, 23, 25, 110, 135, 139, 143, 445, 3306, 3389, 5432, 6379, 27017)
    private val evalCache = ConcurrentHashMap<String, ServerSecurityProfile>()

    fun evaluate(
        rawCfg: String,
        isVipAttested: Boolean = false,
        hintSecurity: String = "",
        hintPrivacy: String = "",
        hintRisk: String = "",
    ): ServerSecurityProfile {
        val cleaned = Converters.cleanUri(rawCfg)
        val cacheKey = "$cleaned|$isVipAttested|$hintSecurity|$hintPrivacy|$hintRisk|${AppI18n.isEnglish}"
        evalCache[cacheKey]?.let { return it }
        val computed = evaluateInternal(cleaned, isVipAttested, hintSecurity, hintPrivacy, hintRisk)
        if (evalCache.size > 4096) evalCache.clear()
        evalCache[cacheKey] = computed
        return computed
    }

    private fun evaluateInternal(
        cleaned: String,
        isVipAttested: Boolean,
        hintSecurity: String,
        hintPrivacy: String,
        hintRisk: String,
    ): ServerSecurityProfile {
        if (cleaned.isBlank() || !Converters.isSupported(cleaned)) {
            return ServerSecurityProfile(
                securityAssessment = "Failed",
                privacyAssessment = "High Risk",
                riskLevel = "CRITICAL",
                quarantined = true,
                summaryAr = "إعداد غير صالح أو مرفوض أمنيًا",
            )
        }

        val out = Converters.toOutbound(cleaned) ?: return ServerSecurityProfile(
            securityAssessment = "Failed",
            privacyAssessment = "High Risk",
            riskLevel = "CRITICAL",
            quarantined = true,
            summaryAr = "تعذّر التحقق البنيوي من الإعداد",
        )

        val port = out.optInt("server_port", 443)
        if (port in SUSPICIOUS_PORTS) {
            return ServerSecurityProfile(
                securityAssessment = "Failed",
                privacyAssessment = "High Risk",
                riskLevel = "CRITICAL",
                quarantined = true,
                summaryAr = "منفذ خدمة غير آمن ($port)",
            )
        }

        val scheme = Converters.schemeOf(cleaned)
        val tlsObj: JSONObject? = out.optJSONObject("tls")
        val tlsEnabled = tlsObj?.optBoolean("enabled", false) == true
        val allowInsecure = tlsObj?.optBoolean("insecure", false) == true
        val realityObj = tlsObj?.optJSONObject("reality")
        val realityEnabled = realityObj?.optBoolean("enabled", false) == true

        if (realityEnabled) {
            val pbk = realityObj?.optString("public_key", "").orEmpty()
            if (pbk.length < 40) {
                return ServerSecurityProfile(
                    securityAssessment = "Failed",
                    privacyAssessment = "High Risk",
                    riskLevel = "CRITICAL",
                    quarantined = true,
                    summaryAr = "مفتاح Reality غير صالح",
                )
            }
        }

        var aead = tlsEnabled
        if (scheme == "ss") {
            val method = out.optString("method", "").lowercase()
            if (method in BROKEN_CIPHERS) {
                return ServerSecurityProfile(
                    securityAssessment = "Failed",
                    privacyAssessment = "High Risk",
                    riskLevel = "CRITICAL",
                    quarantined = true,
                    summaryAr = "تشفير Shadowsocks مكسور ($method)",
                )
            }
            aead = method in STRONG_AEAD_SS
        } else if (scheme == "vmess") {
            val sec = out.optString("security", "auto").lowercase()
            if (sec in BROKEN_CIPHERS && !tlsEnabled) {
                return ServerSecurityProfile(
                    securityAssessment = "Failed",
                    privacyAssessment = "High Risk",
                    riskLevel = "CRITICAL",
                    quarantined = true,
                    summaryAr = "نقل VMess غير مشفّر",
                )
            }
            aead = sec in setOf("auto", "aes-128-gcm", "chacha20-poly1305") || tlsEnabled
        }

        // Local measured TLS/cipher facts always override optimistic hints
        if (allowInsecure) {
            return ServerSecurityProfile(
                securityAssessment = "Failed",
                privacyAssessment = "High Risk",
                riskLevel = "HIGH",
                tlsEnabled = tlsEnabled,
                allowInsecure = true,
                aeadCipher = aead,
                quarantined = false,
                summaryAr = "تحذير: التحقق من شهادة TLS معطّل (allowInsecure)",
            )
        }

        if (scheme in setOf("vless", "vmess", "socks", "socks5", "http") && !tlsEnabled) {
            return ServerSecurityProfile(
                securityAssessment = "Failed",
                privacyAssessment = "High Risk",
                riskLevel = "HIGH",
                tlsEnabled = false,
                allowInsecure = false,
                aeadCipher = aead,
                quarantined = false,
                summaryAr = "نقل خارجي بدون طبقة TLS/Reality",
            )
        }

        if (scheme == "ss" && !aead) {
            return ServerSecurityProfile(
                securityAssessment = "Failed",
                privacyAssessment = "High Risk",
                riskLevel = "HIGH",
                tlsEnabled = false,
                allowInsecure = false,
                aeadCipher = false,
                quarantined = false,
                summaryAr = "خوارزمية تشفير قديمة غير مصادق عليها",
            )
        }

        // Respect stricter cloud pipeline security hints if present
        if (hintSecurity == "Failed" || hintRisk == "HIGH") {
            return ServerSecurityProfile(
                securityAssessment = "Failed",
                privacyAssessment = "High Risk",
                riskLevel = "HIGH",
                tlsEnabled = tlsEnabled,
                allowInsecure = false,
                aeadCipher = aead,
                summaryAr = "مخاطر أمنية مرصودة بالفحص السحابي",
            )
        }

        val serverHost = out.optString("server", "").trim()
        val sni = tlsObj?.optString("server_name", "").orEmpty().trim()
        val isIpLiteral = serverHost.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")) || serverHost.contains(":")

        val secAssessment = when {
            realityEnabled -> "Verified"
            tlsEnabled && (!isIpLiteral || (sni.isNotBlank() && sni != serverHost)) ->
                if (hintSecurity in setOf("Verified", "Partial")) hintSecurity else "Verified"
            tlsEnabled || aead -> "Partial"
            else -> "Unknown"
        }

        // Epistemic honesty: public nodes have unverified operator privacy; only attested VIP reaches Verified
        val privAssessment = when {
            isVipAttested && secAssessment == "Verified" -> "Verified"
            hintPrivacy == "High Risk" -> "High Risk"
            secAssessment in setOf("Verified", "Partial") -> "Unverified"
            else -> "Unknown"
        }

        val riskLevel = when {
            secAssessment == "Verified" && privAssessment != "High Risk" -> "LOW"
            secAssessment == "Partial" -> "MEDIUM"
            else -> hintRisk.ifBlank { "UNKNOWN" }
        }

        val summaryAr = when {
            isVipAttested && secAssessment == "Verified" -> tr("تشفير موثّق + عقدة VIP خاصة", "Verified Encryption + Private VIP Node")
            secAssessment == "Verified" -> tr("تشفير نقل موثّق • مشغّل عام غير موثّق", "Verified Transport Encryption • Unverified Public Operator")
            secAssessment == "Partial" -> tr("تشفير جزئي (AEAD/TLS) • مشغّل عام", "Partial Encryption (AEAD/TLS) • Public Operator")
            else -> tr("أمان غير متحقق", "Unverified Security")
        }

        return ServerSecurityProfile(
            securityAssessment = secAssessment,
            privacyAssessment = privAssessment,
            riskLevel = riskLevel,
            tlsEnabled = tlsEnabled,
            allowInsecure = false,
            aeadCipher = aead,
            quarantined = false,
            summaryAr = summaryAr,
        )
    }
}
