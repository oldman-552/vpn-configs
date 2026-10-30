// =====================================================================
// LeakProtectionEngine.kt — محرك الحماية الشاملة من تسرب DNS و IPv6 و WebRTC (Phase 3).
//
// الضمانات الأمنية الصارمة:
//   1) DNS داخل النفق حصريًا: يفصل بين محلّل التمهيد (bootstrap) لحل عنوان السيرفر
//      وبين محلّل النفق النهائي (tunnel-dns مع detour="proxy") لمنع تسرب استعلامات
//      التطبيقات عبر مزوّد الإنترنت المحلي.
//   2) حجب تسرب IPv6 (Fail-Closed IPv6): يلتقط دائمًا المسار ::/0 داخل واجهة TUN؛
//      فعند تعطيل نفق IPv6 يتم إسقاط حزم IPv6 محليًا وإجبار التطبيقات على IPv4 داخل
//      النفق المشفّر بدل تسربها عبر شبكة الهاتف المزدوجة (Dual-Stack).
//   3) شفافية WebRTC: يميّز بصدق بين حماية توجيه النواة وبين إعدادات المتصفح.
// =====================================================================
package com.bahrain.vpnconfigs.vpn

data class TunLeakProtectionPlan(
    val captureIpv4Route: Boolean = true,
    val captureIpv6Route: Boolean = true,
    val forwardIpv6Upstream: Boolean,
    val singBoxDomainStrategy: String,
    val sanitizedDnsServer: String,
    val useDoh: Boolean,
    val mapDnsAddress: String = "198.18.0.2",
)

enum class WebRtcExposureLevel {
    TUNNEL_ROUTED_BROWSER_ADVISORY,
    SPLIT_TUNNEL_BYPASS_WARNING,
    EXPOSED_VPN_DISCONNECTED,
}

data class WebRtcGuidance(
    val level: WebRtcExposureLevel,
    val summaryAr: String,
    val detailAr: String,
)

object LeakProtectionEngine {

    private val SAFE_PUBLIC_DNS_DEFAULTS = setOf(
        "1.1.1.1",
        "1.0.0.1",
        "8.8.8.8",
        "8.8.4.4",
        "9.9.9.9",
        "149.112.112.112",
        "94.140.14.14",
        "cloudflare-dns.com",
        "dns.google",
        "dns.quad9.net",
    )

    private val KNOWN_BROWSER_PACKAGES = setOf(
        "com.android.chrome",
        "org.mozilla.firefox",
        "com.brave.browser",
        "com.microsoft.emmx",
        "com.opera.browser",
        "com.sec.android.app.sbrowser",
        "com.duckduckgo.mobile.android",
    )

    /**
     * يتحقق من خادم الـ DNS ويمنع استخدام عناوين الشبكة المحلية الخاصة (192.168/10/127)
     * التي قد تكشف الاستعلامات لمزوّد الإنترنت أو الراوتر المحلي.
     */
    fun sanitizeDnsServer(rawDns: String): String {
        val cleaned = rawDns.trim()
            .removePrefix("https://")
            .removePrefix("http://")
            .substringBefore("/")
            .substringBefore(":")
            .trim()
            .lowercase()

        if (cleaned.isBlank()) return "1.1.1.1"
        if (cleaned == "localhost" ||
            cleaned.startsWith("127.") ||
            cleaned.startsWith("10.") ||
            cleaned.startsWith("192.168.") ||
            cleaned.startsWith("169.254.") ||
            cleaned.startsWith("0.")
        ) {
            return "1.1.1.1"
        }
        if (cleaned.startsWith("172.")) {
            val oct2 = cleaned.removePrefix("172.").substringBefore(".").toIntOrNull()
            if (oct2 != null && oct2 in 16..31) return "1.1.1.1"
        }
        return cleaned
    }

    fun isRecognizedTrustedResolver(rawDns: String): Boolean {
        val clean = sanitizeDnsServer(rawDns)
        return clean in SAFE_PUBLIC_DNS_DEFAULTS
    }

    /**
     * يبني خطة توجيه وحماية صارمة من تسرب IPv6 و DNS على شبكات IPv4-only و IPv6-only و Dual-Stack.
     * المبدأ الذهبي: captureIpv6Route = true دائمًا لمنع أي التفاف عبر ::/0 خارج النفق!
     */
    fun buildTunProtectionPlan(
        enableIpv6Tunnel: Boolean,
        rawDnsServer: String,
        useDoh: Boolean,
    ): TunLeakProtectionPlan {
        val safeDns = sanitizeDnsServer(rawDnsServer)
        return TunLeakProtectionPlan(
            captureIpv4Route = true,
            captureIpv6Route = true, // حتمي دائمًا لمنع تسرب IPv6 على شبكات الجيل الخامس والـ Wi-Fi المزدوجة
            forwardIpv6Upstream = enableIpv6Tunnel,
            singBoxDomainStrategy = if (enableIpv6Tunnel) "prefer_ipv4" else "ipv4_only",
            sanitizedDnsServer = safeDns,
            useDoh = useDoh,
        )
    }

    /**
     * يقيّم بصدق مستوى التعرض المحتمل لـ WebRTC دون الادعاء الكاذب بأن توجيه VPN وحده
     * يمنع كل ثغرات تعداد الواجهات داخل المتصفحات.
     */
    fun evaluateWebRtcExposure(
        viaVpnTunnel: Boolean,
        splitIncludeOnly: Boolean,
        splitApps: Set<String>,
    ): WebRtcGuidance {
        if (!viaVpnTunnel) {
            return WebRtcGuidance(
                level = WebRtcExposureLevel.EXPOSED_VPN_DISCONNECTED,
                summaryAr = "مكشوف (الـ VPN غير متّصل)",
                detailAr = "عنوان IP الحقيقي لجهازك مرئي لمواقع الويب وخوادم STUN لأن نفق الـ VPN متوقف حاليًا.",
            )
        }

        val browserBypassed = if (splitIncludeOnly && splitApps.isNotEmpty()) {
            KNOWN_BROWSER_PACKAGES.any { it !in splitApps }
        } else {
            KNOWN_BROWSER_PACKAGES.any { it in splitApps }
        }

        if (browserBypassed) {
            return WebRtcGuidance(
                level = WebRtcExposureLevel.SPLIT_TUNNEL_BYPASS_WARNING,
                summaryAr = "تنبيه: متصفح مستثنى من النفق قد يكشف IP عبر WebRTC",
                detailAr = "أحد المتصفحات مستثنى في إعدادات تقسيم النفق (Split Tunneling)، مما يسمح لطلبات WebRTC/STUN بالخروج مباشرة.",
            )
        }

        return WebRtcGuidance(
            level = WebRtcExposureLevel.TUNNEL_ROUTED_BROWSER_ADVISORY,
            summaryAr = "موجّه داخل النفق • يُنصح بتقييد WebRTC في المتصفح",
            detailAr = "توجيه النظام يمرّر حزم UDP/TCP عبر النفق المشفّر، لكن لا يمكن لطبقة VPN وحدها منع المتصفح من قراءة عناوين الواجهات المحلية؛ للحماية القصوى فعّل خيار تعطيل UDP غير الممرّر عبر الوكيل في متصفحك.",
        )
    }
}
