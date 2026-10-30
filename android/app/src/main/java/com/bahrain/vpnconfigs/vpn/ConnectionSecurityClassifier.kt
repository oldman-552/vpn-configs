// =====================================================================
// ConnectionSecurityClassifier.kt — نظام تصنيف حالة أمان الاتصال الفعلي
// وكشف تسرب DNS و IPv6 بشفافية كاملة (Part 3 — Mandatory Security Classification).
//
// المبدأ الهندسي الصارم:
//   لا يدّعي النظام أبدًا أن الاتصال «آمن 100%» لمجرد قيام نفق VPN؛
//   بل يفصل صراحةً بين حالة النفق، تحقق التشفير، ثقة مشغّل السيرفر، حماية DNS/IPv6،
//   وتأكيد القفل على مستوى نظام التشغيل (OS Lockdown).
// =====================================================================
package com.bahrain.vpnconfigs.vpn

import com.bahrain.vpnconfigs.engine.SecurityEvaluator

enum class ConnectionSecurityState(
    val titleAr: String,
    val titleEn: String,
    val isWarningOrFailure: Boolean,
) {
    CONNECTED(
        "نفق الـ VPN متّصل",
        "VPN tunnel is established",
        isWarningOrFailure = false,
    ),
    ENCRYPTED_TUNNEL(
        "نفق مشفّر وموثّق الخصائص",
        "Encrypted tunnel properties verified",
        isWarningOrFailure = false,
    ),
    UNKNOWN_SERVER_TRUST(
        "مشغّل السيرفر غير موثّق الهوية",
        "Server operator or ownership is unverified",
        isWarningOrFailure = true,
    ),
    DNS_LEAK_DETECTED(
        "رُصد احتمال تسرب استعلامات DNS",
        "DNS traffic appears to bypass the VPN tunnel",
        isWarningOrFailure = true,
    ),
    IPV6_LEAK_DETECTED(
        "رُصد احتمال تسرب حركة IPv6 خارج النفق",
        "IPv6 traffic appears to bypass the VPN tunnel",
        isWarningOrFailure = true,
    ),
    UNSTABLE_CONNECTION(
        "اتصال غير مستقر (فقدان حزم أو تذبذب عالٍ)",
        "Unstable connection (packet loss or high latency variance)",
        isWarningOrFailure = true,
    ),
    KILL_SWITCH_ACTIVE(
        "قفل النظام الصارم نشط (OS Lockdown)",
        "Operating-system-level VPN lockdown confirmed",
        isWarningOrFailure = false,
    ),
    SECURITY_CHECK_FAILED(
        "فشل أحد فحوصات الأمان الإلزامية",
        "One or more mandatory security checks failed",
        isWarningOrFailure = true,
    ),
    SECURITY_CHECK_INCOMPLETE(
        "فحص الأمان غير مكتمل حاليًا",
        "Security check incomplete or inconclusive",
        isWarningOrFailure = true,
    ),
}

enum class DiagnosticOutcome(val labelAr: String, val labelEn: String) {
    PROTECTED("محمي داخل النفق", "Protected via Tunnel"),
    UNAVAILABLE_SAFE("غير متوفّر على الشبكة (لا يوجد تسرب)", "Unavailable on Network (No Leak)"),
    LEAK_DETECTED("رُصد تسرب خارج النفق", "Bypass / Leak Detected"),
    INCONCLUSIVE("نتيجة غير حاسمة", "Inconclusive"),
}

data class DnsLeakCheckResult(
    val outcome: DiagnosticOutcome,
    val configuredResolver: String,
    val usesEncryptedDoh: Boolean,
    val vpnDnsServers: List<String>,
    val physicalDnsServers: List<String>,
    val supportsIpv6Dns: Boolean,
    val explanationAr: String,
    val explanationEn: String,
    val limitationNoteAr: String,
)

data class Ipv6LeakCheckResult(
    val outcome: DiagnosticOutcome,
    val physicalIpv6Available: Boolean,
    val tunCapturesIpv6Route: Boolean,
    val ipv6ForwardedThroughVpn: Boolean,
    val explanationAr: String,
    val explanationEn: String,
)

data class SecurityStatusReport(
    val primaryStates: Set<ConnectionSecurityState>,
    val headlineAr: String,
    val headlineEn: String,
    val tunnelEstablished: Boolean,
    val encryptionVerified: Boolean,
    val encryptionDetailAr: String,
    val serverTrustLabelAr: String,
    val serverTrustVerified: Boolean,
    val dnsCheck: DnsLeakCheckResult,
    val ipv6Check: Ipv6LeakCheckResult,
    val killSwitchOsConfirmed: Boolean,
    val appFailClosedActive: Boolean,
    val checkedAtMs: Long,
    val failureExplanationsAr: List<String>,
)

object ConnectionSecurityClassifier {

    /**
     * يفحص حماية DNS دون اعتبار خوادم DNS العامة المشفّرة (مثل 1.1.1.1 أو 9.9.9.9 عبر النفق)
     * تسربًا عن طريق الخطأ، مع التمييز الصريح بين DNS النفق و DNS مزوّد الخدمة المحلي.
     */
    fun inspectDnsProtection(
        tunnelEstablished: Boolean,
        configuredDns: String,
        useDoh: Boolean,
        enableIpv6: Boolean,
        vpnInterfaceDns: List<String>,
        physicalNetworkDns: List<String>,
        detourThroughProxyVerified: Boolean = true,
        ipLeakDetectedFromDiagnostic: Boolean = false,
    ): DnsLeakCheckResult {
        val cleanConfigured = LeakProtectionEngine.sanitizeDnsServer(configuredDns)
        val limitation = "يفحص هذا الاختبار مسار التوجيه ومحلّلات الواجهة النشطة داخل الجهاز؛ التحقق الكامل من خوادم DNS النهائية يتطلب اتصالًا حيًا بخدمة فحص خارجية."

        if (!tunnelEstablished) {
            return DnsLeakCheckResult(
                outcome = DiagnosticOutcome.INCONCLUSIVE,
                configuredResolver = cleanConfigured,
                usesEncryptedDoh = useDoh,
                vpnDnsServers = vpnInterfaceDns,
                physicalDnsServers = physicalNetworkDns,
                supportsIpv6Dns = enableIpv6,
                explanationAr = "النفق غير متّصل حاليًا — استعلامات DNS تمر عبر الشبكة العادية.",
                explanationEn = "VPN tunnel is disconnected — DNS uses standard network resolvers.",
                limitationNoteAr = limitation,
            )
        }

        // Check if VPN TUN failed to capture DNS or leaked physical LAN resolver into VPN DNS list
        val lanBypassInVpnDns = vpnInterfaceDns.any { ip ->
            ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("fe80:")
        }
        if (!detourThroughProxyVerified || lanBypassInVpnDns || ipLeakDetectedFromDiagnostic) {
            return DnsLeakCheckResult(
                outcome = DiagnosticOutcome.LEAK_DETECTED,
                configuredResolver = cleanConfigured,
                usesEncryptedDoh = useDoh,
                vpnDnsServers = vpnInterfaceDns,
                physicalDnsServers = physicalNetworkDns,
                supportsIpv6Dns = enableIpv6,
                explanationAr = "تحذير: يبدو أن طلبات DNS تتجاوز نفق الـ VPN إلى محلّل الشبكة المحلية.",
                explanationEn = "Warning: DNS traffic appears to bypass the VPN tunnel toward local resolvers.",
                limitationNoteAr = limitation,
            )
        }

        if (vpnInterfaceDns.isEmpty()) {
            return DnsLeakCheckResult(
                outcome = DiagnosticOutcome.INCONCLUSIVE,
                configuredResolver = cleanConfigured,
                usesEncryptedDoh = useDoh,
                vpnDnsServers = vpnInterfaceDns,
                physicalDnsServers = physicalNetworkDns,
                supportsIpv6Dns = enableIpv6,
                explanationAr = "لم يتمكن النظام من تأكيد قائمة خوادم DNS لواجهة النفق بعد.",
                explanationEn = "Could not confirm active VPN interface DNS resolvers yet.",
                limitationNoteAr = limitation,
            )
        }

        val modeAr = if (useDoh) "عبر HTTPS المشفّر (DoH)" else "داخل نفق الـ VPN عبر MapDNS"
        return DnsLeakCheckResult(
            outcome = DiagnosticOutcome.PROTECTED,
            configuredResolver = cleanConfigured,
            usesEncryptedDoh = useDoh,
            vpnDnsServers = vpnInterfaceDns,
            physicalDnsServers = physicalNetworkDns,
            supportsIpv6Dns = enableIpv6,
            explanationAr = "يتم توجيه استعلامات DNS ($cleanConfigured) $modeAr دون المرور بمحلّل مزوّد الإنترنت المحلي.",
            explanationEn = "DNS queries ($cleanConfigured) traverse the VPN tunnel (${if (useDoh) "DoH" else "MapDNS detour"}).",
            limitationNoteAr = limitation,
        )
    }

    /**
     * يفحص مسار IPv6 بدقة ويميّز بين عدم توفّر IPv6 أصلًا على الشبكة وبين نجاح حجزه داخل النفق.
     */
    fun inspectIpv6Protection(
        tunnelEstablished: Boolean,
        physicalIpv6Available: Boolean,
        tunCapturesIpv6Route: Boolean,
        ipv6ForwardedUpstream: Boolean,
        directIpv6BypassDetected: Boolean = false,
    ): Ipv6LeakCheckResult {
        if (!tunnelEstablished) {
            return Ipv6LeakCheckResult(
                outcome = DiagnosticOutcome.INCONCLUSIVE,
                physicalIpv6Available = physicalIpv6Available,
                tunCapturesIpv6Route = false,
                ipv6ForwardedThroughVpn = false,
                explanationAr = "نفق الـ VPN متوقف — لا ينطبق فحص عزل مسار IPv6 حاليًا.",
                explanationEn = "VPN tunnel is inactive — IPv6 tunnel route check not applicable.",
            )
        }

        if (directIpv6BypassDetected || (physicalIpv6Available && !tunCapturesIpv6Route)) {
            return Ipv6LeakCheckResult(
                outcome = DiagnosticOutcome.LEAK_DETECTED,
                physicalIpv6Available = physicalIpv6Available,
                tunCapturesIpv6Route = tunCapturesIpv6Route,
                ipv6ForwardedThroughVpn = ipv6ForwardedUpstream,
                explanationAr = "تحذير: الشبكة تدعم IPv6 ولكن المسار ::/0 غير محتجز بالكامل داخل واجهة الـ VPN.",
                explanationEn = "Warning: Host has global IPv6 connectivity bypassing the VPN route.",
            )
        }

        if (!physicalIpv6Available && !ipv6ForwardedUpstream) {
            return Ipv6LeakCheckResult(
                outcome = DiagnosticOutcome.UNAVAILABLE_SAFE,
                physicalIpv6Available = false,
                tunCapturesIpv6Route = tunCapturesIpv6Route,
                ipv6ForwardedThroughVpn = false,
                explanationAr = "شبكتك الحالية لا تمنح عنوان IPv6 عامًا، كما أن المسار ::/0 محتجز وقائيًا داخل واجهة الـ VPN.",
                explanationEn = "Global IPv6 is unavailable on the underlying network and ::/0 is sinkholed by TUN.",
            )
        }

        return Ipv6LeakCheckResult(
            outcome = DiagnosticOutcome.PROTECTED,
            physicalIpv6Available = physicalIpv6Available,
            tunCapturesIpv6Route = tunCapturesIpv6Route,
            ipv6ForwardedThroughVpn = ipv6ForwardedUpstream,
            explanationAr = if (ipv6ForwardedUpstream) {
                "حركة IPv6 موجّهة بالكامل داخل نفق الـ VPN المشفّر (::/0)."
            } else {
                "تم حجز وإسقاط حركة IPv6 محليًا داخل واجهة TUN لإجبار التطبيقات على نفق IPv4 المشفّر ومنع التسرب."
            },
            explanationEn = if (ipv6ForwardedUpstream) {
                "IPv6 traffic is routed inside the VPN tunnel (::/0)."
            } else {
                "IPv6 route ::/0 is captured by TUN sinkhole to prevent dual-stack bypass."
            },
        )
    }

    /**
     * يصدر التقرير الأمني الشامل مع الحالات الـ 9 الإلزامية بلغة صريحة خالية من المبالغة التسويقية.
     */
    fun classify(
        vpnStatus: VpnStatus,
        activeCfg: String?,
        isVipAttested: Boolean,
        networkSnapshot: NetworkSnapshot,
        configuredDns: String,
        useDoh: Boolean,
        enableIpv6: Boolean,
        tunCapturesIpv6Route: Boolean = true,
        dnsBypassObserved: Boolean = false,
        ipv6BypassObserved: Boolean = false,
        nowMs: Long = System.currentTimeMillis(),
    ): SecurityStatusReport {
        val states = LinkedHashSet<ConnectionSecurityState>()
        val failures = ArrayList<String>()

        val tunnelUp = vpnStatus.isTunnelVerified
        if (tunnelUp) {
            states.add(ConnectionSecurityState.CONNECTED)
        }

        // OS-level Kill Switch is ONLY active when Android OS confirms isLockdownEnabled == true!
        if (vpnStatus.osLockdownActive) {
            states.add(ConnectionSecurityState.KILL_SWITCH_ACTIVE)
        }

        val secEval = if (!activeCfg.isNullOrBlank()) {
            SecurityEvaluator.evaluate(activeCfg, isVipAttested = isVipAttested)
        } else null

        val encryptionVerified = tunnelUp && secEval != null && secEval.securityAssessment == "Verified" && !secEval.allowInsecure
        if (encryptionVerified) {
            states.add(ConnectionSecurityState.ENCRYPTED_TUNNEL)
        } else if (tunnelUp && secEval != null && secEval.securityAssessment == "Failed") {
            states.add(ConnectionSecurityState.SECURITY_CHECK_FAILED)
            failures.add(secEval.summaryAr.ifBlank { "إعداد تشفير السيرفر فشل في التحقق الأمني (مثل allowInsecure أو غياب TLS)." })
        }

        // Epistemic Honesty: Public servers ALWAYS carry UNKNOWN_SERVER_TRUST
        val trustVerified = tunnelUp && isVipAttested && encryptionVerified
        if (tunnelUp && !isVipAttested) {
            states.add(ConnectionSecurityState.UNKNOWN_SERVER_TRUST)
        }

        // Unstable tunnel detection
        if (tunnelUp && (
                vpnStatus.phase == VpnPhase.CONNECTION_DEGRADED ||
                    vpnStatus.packetLossPct >= 20.0 ||
                    vpnStatus.jitterMs >= 180.0
                )
        ) {
            states.add(ConnectionSecurityState.UNSTABLE_CONNECTION)
            failures.add("الاتصال الحالي يشهد فقدان حزم (${vpnStatus.packetLossPct}%) أو تذبذبًا مرتفعًا (${vpnStatus.jitterMs} ms).")
        }

        val vpnDnsList = if (tunnelUp) listOf("198.18.0.2") else emptyList()
        val dnsCheck = inspectDnsProtection(
            tunnelEstablished = tunnelUp,
            configuredDns = configuredDns,
            useDoh = useDoh,
            enableIpv6 = enableIpv6,
            vpnInterfaceDns = vpnDnsList,
            physicalNetworkDns = networkSnapshot.systemDnsServers,
            detourThroughProxyVerified = tunnelUp && !dnsBypassObserved,
            ipLeakDetectedFromDiagnostic = dnsBypassObserved,
        )
        if (dnsCheck.outcome == DiagnosticOutcome.LEAK_DETECTED) {
            states.add(ConnectionSecurityState.DNS_LEAK_DETECTED)
            states.add(ConnectionSecurityState.SECURITY_CHECK_FAILED)
            failures.add(dnsCheck.explanationAr)
        }

        val ipv6Check = inspectIpv6Protection(
            tunnelEstablished = tunnelUp,
            physicalIpv6Available = networkSnapshot.hasGlobalIpv6,
            tunCapturesIpv6Route = tunCapturesIpv6Route,
            ipv6ForwardedUpstream = enableIpv6,
            directIpv6BypassDetected = ipv6BypassObserved,
        )
        if (ipv6Check.outcome == DiagnosticOutcome.LEAK_DETECTED) {
            states.add(ConnectionSecurityState.IPV6_LEAK_DETECTED)
            states.add(ConnectionSecurityState.SECURITY_CHECK_FAILED)
            failures.add(ipv6Check.explanationAr)
        }

        if (!tunnelUp || dnsCheck.outcome == DiagnosticOutcome.INCONCLUSIVE || secEval == null || secEval.securityAssessment == "Unknown") {
            if (!states.contains(ConnectionSecurityState.SECURITY_CHECK_FAILED)) {
                states.add(ConnectionSecurityState.SECURITY_CHECK_INCOMPLETE)
            }
        }

        val (headlineAr, headlineEn) = when {
            !tunnelUp && vpnStatus.phase == VpnPhase.PROTECTION_ACTIVE ->
                "النفق متوقف مؤقتًا؛ الحجب الوقائي داخل التطبيق يمنع خروج البيانات لحين إعادة الربط." to
                    "Tunnel interrupted; app-level fail-closed TUN block is holding traffic."
            !tunnelUp ->
                "نفق الـ VPN غير متّصل حاليًا. حركة الإنترنت تمر مباشرة عبر مزوّد الخدمة." to
                    "VPN tunnel is disconnected. Traffic traverses your ISP directly."
            states.contains(ConnectionSecurityState.SECURITY_CHECK_FAILED) ->
                "نفق الـ VPN يعمل، لكن فشل أحد فحوصات الأمان الإلزامية — راجع التفاصيل أدناه." to
                    "VPN tunnel active, but one or more mandatory security checks failed."
            states.contains(ConnectionSecurityState.UNKNOWN_SERVER_TRUST) && encryptionVerified ->
                "تم إنشاء نفق الـ VPN وتوثيق تشفير النقل، لكن مشغّل السيرفر العام غير موثّق الهوية." to
                    "VPN tunnel established and transport encrypted. Server operator is unverified."
            trustVerified ->
                "تم إنشاء نفق الـ VPN وتوثيق التشفير عبر عقدة VIP مخصّصة." to
                    "VPN tunnel established with verified transport encryption on attested VIP node."
            else ->
                "تم إنشاء نفق الـ VPN، لكن التحقق الكامل من خصائص التشفير غير مكتمل." to
                    "VPN tunnel established; encryption verification is partial or incomplete."
        }

        return SecurityStatusReport(
            primaryStates = states,
            headlineAr = headlineAr,
            headlineEn = headlineEn,
            tunnelEstablished = tunnelUp,
            encryptionVerified = encryptionVerified,
            encryptionDetailAr = secEval?.summaryAr ?: "لا يوجد إعداد نشط للتحقق منه",
            serverTrustLabelAr = if (trustVerified) {
                "عقدة VIP مخصّصة وموثّقة التوقيع"
            } else if (tunnelUp) {
                "مشغّل عام خارجي غير موثّق (لا تفترض عدم تسجيل السجلات)"
            } else {
                "غير متّصل"
            },
            serverTrustVerified = trustVerified,
            dnsCheck = dnsCheck,
            ipv6Check = ipv6Check,
            killSwitchOsConfirmed = vpnStatus.osLockdownActive,
            appFailClosedActive = vpnStatus.killSwitchActive,
            checkedAtMs = nowMs,
            failureExplanationsAr = failures,
        )
    }
}
