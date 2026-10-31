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

import com.bahrain.vpnconfigs.util.tr

data class Ipv4CidrRoute(
    val address: String,
    val prefixLength: Int,
)

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
     * يحسب مسارات IPv4 الدقيقة لواجهة `tun0` بحيث تشمل كامل الإنترنت العام وعناوين `MapDNS`
     * (`198.18.0.2` و`240.0.0.0/4`) مع استثناء شبكات الهوتسبوت والشبكة المحلية الخاصة فقط
     * (`192.168.0.0/16`، `172.16.0.0/12`، `169.254.0.0/16`، `127.0.0.0/8`، `224.0.0.0/4`،
     * وأي شبكة فرعية نشطة `10.x.y.0/24` لواجهة الهوتسبوت/USB) حتى لا يبتلع `tun0` ردود الهوتسبوت المحلية.
     */
    fun computeIpv4RoutesExcludingLocalLan(
        extraActiveLanIps: Collection<String> = emptyList(),
    ): List<Ipv4CidrRoute> {
        val excludedSpecs = mutableListOf(
            "127.0.0.0" to 8,
            "169.254.0.0" to 16,
            "172.16.0.0" to 12,
            "192.168.0.0" to 16,
            "224.0.0.0" to 4,
        )
        for (rawIp in extraActiveLanIps) {
            val parts = rawIp.trim().split('.')
            if (parts.size == 4) {
                val nums = parts.mapNotNull { it.toIntOrNull() }
                if (nums.size == 4 && nums.all { it in 0..255 } && nums[0] == 10) {
                    excludedSpecs.add("10.${nums[1]}.${nums[2]}.0" to 24)
                }
            }
        }

        val excludedRanges: List<Pair<Long, Long>> = excludedSpecs.mapNotNull { (ip, pfx) ->
            val base = ipv4ToLongOrNull(ip) ?: return@mapNotNull null
            if (pfx !in 1..32) return@mapNotNull null
            val size = 1L shl (32 - pfx)
            val mask = (0xFFFFFFFFL shl (32 - pfx)) and 0xFFFFFFFFL
            val start = base and mask
            val end = start + size - 1L
            start to end
        }

        val out = ArrayList<Ipv4CidrRoute>(32)
        fun walk(base: Long, prefixLen: Int) {
            val size = if (prefixLen == 0) (1L shl 32) else (1L shl (32 - prefixLen))
            val nodeStart = base
            val nodeEnd = base + size - 1L
            if (excludedRanges.any { (es, ee) -> es <= nodeStart && ee >= nodeEnd }) {
                return
            }
            if (excludedRanges.none { (es, ee) -> es <= nodeEnd && ee >= nodeStart }) {
                out.add(Ipv4CidrRoute(longToIpv4(base), prefixLen))
                return
            }
            if (prefixLen < 32) {
                val half = 1L shl (31 - prefixLen)
                walk(base, prefixLen + 1)
                walk(base + half, prefixLen + 1)
            }
        }
        walk(0L, 0)
        return out
    }

    fun isIpv4CoveredByRoutes(ip: String, routes: List<Ipv4CidrRoute>): Boolean {
        val target = ipv4ToLongOrNull(ip) ?: return false
        return routes.any { r ->
            val base = ipv4ToLongOrNull(r.address) ?: return@any false
            if (r.prefixLength == 0) return@any true
            val size = 1L shl (32 - r.prefixLength)
            val mask = (0xFFFFFFFFL shl (32 - r.prefixLength)) and 0xFFFFFFFFL
            val start = base and mask
            target in start..(start + size - 1L)
        }
    }

    private fun ipv4ToLongOrNull(ip: String): Long? {
        val parts = ip.trim().split('.')
        if (parts.size != 4) return null
        val nums = parts.map { it.toIntOrNull() ?: return null }
        if (nums.any { it !in 0..255 }) return null
        return ((nums[0].toLong() shl 24) or
            (nums[1].toLong() shl 16) or
            (nums[2].toLong() shl 8) or
            nums[3].toLong()) and 0xFFFFFFFFL
    }

    private fun longToIpv4(v: Long): String {
        val a = (v ushr 24) and 0xFFL
        val b = (v ushr 16) and 0xFFL
        val c = (v ushr 8) and 0xFFL
        val d = v and 0xFFL
        return "$a.$b.$c.$d"
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
                summaryAr = tr("مكشوف (الـ VPN غير متّصل)", "Exposed (VPN Disconnected)"),
                detailAr = tr(
                    "عنوان IP الحقيقي لجهازك مرئي لمواقع الويب وخوادم STUN لأن نفق الـ VPN متوقف حاليًا.",
                    "Your real IP address is visible to websites and STUN servers while the VPN tunnel is disconnected.",
                ),
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
                summaryAr = tr("تنبيه: متصفح مستثنى من النفق قد يكشف IP عبر WebRTC", "Warning: Split-tunneled browser may leak IP via WebRTC"),
                detailAr = tr(
                    "أحد المتصفحات مستثنى في إعدادات تقسيم النفق (Split Tunneling)، مما يسمح لطلبات WebRTC/STUN بالخروج مباشرة.",
                    "A browser is excluded in Split Tunneling, allowing WebRTC/STUN traffic to bypass the VPN directly.",
                ),
            )
        }

        return WebRtcGuidance(
            level = WebRtcExposureLevel.TUNNEL_ROUTED_BROWSER_ADVISORY,
            summaryAr = tr("موجّه داخل النفق • يُنصح بتقييد WebRTC في المتصفح", "Routed via Tunnel • Browser WebRTC restriction advised"),
            detailAr = tr(
                "توجيه النظام يمرّر حزم UDP/TCP عبر النفق المشفّر، لكن لا يمكن لطبقة VPN وحدها منع المتصفح من قراءة عناوين الواجهات المحلية؛ للحماية القصوى فعّل خيار تعطيل UDP غير الممرّر عبر الوكيل في متصفحك.",
                "OS routing sends UDP/TCP inside the encrypted tunnel, though VPN interfaces alone cannot prevent browsers from reading local interface IPs; disable non-proxied UDP in browser settings for maximum privacy.",
            ),
        )
    }
}
