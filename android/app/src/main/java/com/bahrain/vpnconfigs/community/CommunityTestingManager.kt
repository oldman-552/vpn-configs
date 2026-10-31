// =====================================================================
// CommunityTestingManager.kt — محرك الفحص المجتمعي الطوعي لقياس عمل السيرفرات
// من داخل الشبكات الحقيقية (مع تركيز خاص على التحقق الموثوق لشبكات إيران IR):
//
// ضمانات الأمان والخصوصية الصارمة:
//   • معطّل افتراضيًا بالكامل (OFF by default) ويتطلب موافقة صريحة من المستخدم،
//     مع إمكانية الإلغاء الفوري وتدوير الهوية العشوائية في أي لحظة.
//   • الفحص محلي 100% على الهاتف (127.0.0.1 فقط) — لا يحوّل هاتف المستخدم أبدًا
//     إلى بروكسي عام أو نقطة عبور أو خادم ترحيل لأي طرف خارجي.
//   • لا يقطع اتصال الـ VPN النشط للمستخدم، ويتوقف فورًا إذا كانت ميزة
//     مشاركة الهوتسبوت (VPN Hotspot) قيد التشغيل.
//   • التحقق الصادق من دولة الشبكة الفعلية (IR): يفحص تداخل أي نفق VPN آخر
//     (TRANSPORT_VPN) ويتحقق من عنوان الخروج العام المباشر خارج الـ VPN؛
//     لا يعتمد أبدًا على GPS أو لغة الهاتف أو اختيار المستخدم اليدوي للدولة.
//   • البيانات المرسلة مختزلة للحد الأدنى (بصمة الإعداد المعماة والقياسات فقط —
//     صفر كلمات مرور، صفر روابط خام، صفر سجل تصفح، صفر موقع جغرافي دقيق).
// =====================================================================
package com.bahrain.vpnconfigs.community

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.BatteryManager
import com.bahrain.vpnconfigs.data.ClientDatabase
import com.bahrain.vpnconfigs.data.CommunityReportStatsSummary
import com.bahrain.vpnconfigs.data.CommunityTestReportRecord
import com.bahrain.vpnconfigs.data.Prefs
import com.bahrain.vpnconfigs.engine.Converters
import com.bahrain.vpnconfigs.engine.SingBox
import com.bahrain.vpnconfigs.engine.TestResult
import com.bahrain.vpnconfigs.enterprise.EnterpriseLicenseGuard
import com.bahrain.vpnconfigs.hotspot.VpnHotspotManager
import com.bahrain.vpnconfigs.util.tr
import com.bahrain.vpnconfigs.vpn.VpnStateManager
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.Locale
import java.util.UUID
import kotlin.coroutines.coroutineContext

data class OriginVerificationResult(
    val verifiedCountry: String,        // ISO-3166 alpha-2 e.g. "IR", "DE", or "" when unverified
    val confidence: String,             // VERIFIED_DIRECT_IP | VPN_INTERFERENCE | UNVERIFIED
    val vpnInterference: Boolean,
    val transport: String,              // WIFI | CELLULAR | ETHERNET | NONE
) {
    val isTrustedDirectOrigin: Boolean
        get() = !vpnInterference && confidence == "VERIFIED_DIRECT_IP" && verifiedCountry.length == 2

    val isVerifiedIranOrigin: Boolean
        get() = isTrustedDirectOrigin && verifiedCountry == "IR"
}

data class CommunityTestingState(
    val optInEnabled: Boolean = false,
    val consentGrantedAtMs: Long = 0L,
    val wifiOnly: Boolean = true,
    val maxConfigsPerRun: Int = 15,
    val dailyLimit: Int = 60,
    val backgroundScheduleEnabled: Boolean = false,
    val isRunning: Boolean = false,
    val testedInCurrentRun: Int = 0,
    val totalInCurrentRun: Int = 0,
    val currentProtocol: String = "",
    val lastVerifiedCountry: String = "",
    val lastCountryConfidence: String = "UNVERIFIED",
    val vpnInterferenceDetected: Boolean = false,
    val summary: CommunityReportStatsSummary = CommunityReportStatsSummary(),
    val recentReports: List<CommunityTestReportRecord> = emptyList(),
    val endpointConfigured: Boolean = false,
    val lastSyncMessageAr: String = "",
    val lastSyncMessageEn: String = "",
    val statusMessageAr: String = "الفحص المجتمعي معطّل افتراضيًا (يتطلب موافقتك الصريحة)",
    val statusMessageEn: String = "Community testing is disabled by default (requires explicit opt-in)",
    val errorAr: String? = null,
    val errorEn: String? = null,
) {
    val displayStatus: String
        get() = tr(statusMessageAr, statusMessageEn)

    val displayLastSync: String
        get() = tr(lastSyncMessageAr, lastSyncMessageEn)

    val displayError: String?
        get() {
            val ar = errorAr ?: return null
            return tr(ar, errorEn ?: ar)
        }
}

fun interface OriginCountryDetector {
    fun verifyOrigin(ctx: Context): OriginVerificationResult
}

fun interface CommunityConfigProbe {
    fun probeSequentially(ctx: Context, cfg: String, port: Int, timeoutSec: Int): TestResult
}

object CommunityTestingManager {

    private const val COMMUNITY_TEST_PORT = 22745
    private const val THROUGHPUT_SAMPLE_BYTES = 262_144L // 256 KB bounded sample to save user data

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val runMutex = Mutex()
    private val _state = MutableStateFlow(CommunityTestingState())
    val state: StateFlow<CommunityTestingState> = _state.asStateFlow()

    @Volatile
    private var activeJob: Job? = null

    fun refreshSnapshot(ctx: Context) {
        val prefs = Prefs(ctx)
        val db = ClientDatabase.getInstance(ctx)
        val endpoint = resolveIngestEndpointUrl(ctx, prefs)
        val sum = db.getCommunityReportsSummary()
        val recent = db.listRecentCommunityReports(25)
        val enabled = prefs.communityTestingEnabled
        _state.update { prev ->
            prev.copy(
                optInEnabled = enabled,
                consentGrantedAtMs = prefs.communityConsentAtMs,
                wifiOnly = prefs.communityWifiOnly,
                maxConfigsPerRun = prefs.communityMaxConfigsPerRun,
                dailyLimit = prefs.communityDailyLimit,
                backgroundScheduleEnabled = prefs.communityBackgroundScheduleEnabled,
                lastVerifiedCountry = prefs.lastVerifiedOriginCountry.ifBlank { prev.lastVerifiedCountry },
                summary = sum,
                recentReports = recent,
                endpointConfigured = endpoint.isNotBlank(),
                statusMessageAr = if (!enabled) {
                    "الفحص المجتمعي معطّل افتراضيًا — يمكنك التفعيل الطوعي للمساهمة في ترتيب السيرفرات الشغّالة في بلدك"
                } else if (prev.isRunning) {
                    prev.statusMessageAr
                } else {
                    "الفحص المجتمعي مفعّل بموافقتك (يعمل محليًا فقط عند الخمول وبدون المساس باتصالك)"
                },
                statusMessageEn = if (!enabled) {
                    "Community testing is OFF by default — opt in voluntarily to help verify working servers in your country"
                } else if (prev.isRunning) {
                    prev.statusMessageEn
                } else {
                    "Community testing is enabled with your consent (local-only when idle, never interrupts your VPN)"
                },
            )
        }
    }

    fun grantConsent(ctx: Context) {
        val prefs = Prefs(ctx)
        prefs.grantCommunityTestingConsent()
        refreshSnapshot(ctx)
    }

    fun revokeConsent(ctx: Context, clearLocalPending: Boolean = true) {
        activeJob?.cancel()
        activeJob = null
        val prefs = Prefs(ctx)
        prefs.revokeCommunityTestingConsent()
        if (clearLocalPending) {
            ClientDatabase.getInstance(ctx).clearAllCommunityReports()
        }
        _state.update {
            it.copy(
                optInEnabled = false,
                consentGrantedAtMs = 0L,
                isRunning = false,
                testedInCurrentRun = 0,
                totalInCurrentRun = 0,
                errorAr = null,
                errorEn = null,
                statusMessageAr = "تم إلغاء الموافقة وإيقاف الفحص المجتمعي وتدوير المعرّف العشوائي فورًا",
                statusMessageEn = "Consent revoked, community testing stopped, and anonymous ID rotated immediately",
            )
        }
        refreshSnapshot(ctx)
    }

    fun updateSettings(
        ctx: Context,
        wifiOnly: Boolean? = null,
        maxPerRun: Int? = null,
        dailyLimit: Int? = null,
        backgroundSchedule: Boolean? = null,
        endpointOverride: String? = null,
    ) {
        val prefs = Prefs(ctx)
        wifiOnly?.let { prefs.communityWifiOnly = it }
        maxPerRun?.let { prefs.communityMaxConfigsPerRun = it }
        dailyLimit?.let { prefs.communityDailyLimit = it }
        backgroundSchedule?.let { prefs.communityBackgroundScheduleEnabled = it }
        endpointOverride?.let { prefs.communityEndpointOverride = it }
        refreshSnapshot(ctx)
    }

    /** يُستدعى فور تشغيل ميزة VPN Hotspot لإيقاف أي فحص مجتمعي نشط ومنع أي تداخل. */
    fun pauseForActiveHotspot() {
        val job = activeJob
        if (job != null && job.isActive) {
            job.cancel()
            activeJob = null
            _state.update {
                it.copy(
                    isRunning = false,
                    statusMessageAr = "تم إيقاف الفحص المجتمعي مؤقتًا لأن نقطة اتصال الـ VPN (Hotspot) نشطة",
                    statusMessageEn = "Community testing paused while VPN Hotspot is active",
                )
            }
        }
    }

    fun stopCurrentRun() {
        activeJob?.cancel()
        activeJob = null
        _state.update {
            it.copy(
                isRunning = false,
                statusMessageAr = "تم إيقاف جولة الفحص المجتمعي بطلبك",
                statusMessageEn = "Community test run stopped by user",
            )
        }
    }

    fun computeAnonymousReporterHash(installSalt: String): String {
        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest("bahrain-vpn:community-reporter:v1|$installSalt".toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }

    fun resolveIngestEndpointUrl(ctx: Context, prefs: Prefs = Prefs(ctx)): String {
        val custom = prefs.communityEndpointOverride
        if (custom.isNotBlank()) return custom
        val remote = runCatching {
            EnterpriseLicenseGuard(ctx).getRemoteConfig().optString("community_ingest_url", "").trim()
        }.getOrDefault("")
        return if (remote.startsWith("https://", ignoreCase = true)) remote.trimEnd('/') else ""
    }

    fun normalizeFailureReason(rawError: String): String {
        val low = rawError.trim().lowercase(Locale.US)
        return when {
            low.isEmpty() -> "UNKNOWN_FAILURE"
            low.contains("timeout") -> "CONNECTION_TIMEOUT"
            low.contains("engine-missing") -> "ENGINE_UNAVAILABLE"
            low.contains("engine-exit") || low.contains("no-listen") -> "HANDSHAKE_OR_CONFIG_ERROR"
            low.contains("unsupported") -> "UNSUPPORTED_CONFIG"
            low.startsWith("http-") -> "HTTP_PROBE_REJECTED"
            low.contains("all-probes-failed") -> "TUNNEL_UNREACHABLE"
            low.contains("ssl") || low.contains("tls") || low.contains("cert") -> "TLS_HANDSHAKE_FAILED"
            low.contains("cancel") -> "CANCELLED"
            else -> "NETWORK_OR_HANDSHAKE_FAILED"
        }
    }

    /**
     * يفحص الشبكة الحقيقية للجهاز قبل الفحص المجتمعي:
     * 1) يرفض اعتماد دولة المصدر إذا كان هناك نفق VPN نشط على الهاتف (`TRANSPORT_VPN`)،
     *    حتى لا تُسجَّل دولة سيرفر الـ VPN كأنها شبكة إيرانية محلية!
     * 2) يستعلم عبر الشبكة الفيزيائية المباشرة عن رمز الدولة العام (`loc=IR` مثلًا) دون GPS.
     */
    val defaultOriginDetector = OriginCountryDetector { ctx ->
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return@OriginCountryDetector OriginVerificationResult("", "UNVERIFIED", false, "NONE")

        @Suppress("DEPRECATION")
        val allNets = runCatching { cm.allNetworks.toList() }.getOrDefault(emptyList())
        var anyVpnTransport = VpnStateManager.status.value.isActive
        var physicalNetwork: Network? = null
        var transportCode = "NONE"

        for (net in allNets) {
            val caps = cm.getNetworkCapabilities(net) ?: continue
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                anyVpnTransport = true
                continue
            }
            if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                    physicalNetwork = net
                    transportCode = "WIFI"
                    break
                } else if (physicalNetwork == null) {
                    physicalNetwork = net
                    transportCode = when {
                        caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "CELLULAR"
                        caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ETHERNET"
                        else -> "OTHER"
                    }
                }
            }
        }

        if (anyVpnTransport) {
            return@OriginCountryDetector OriginVerificationResult(
                verifiedCountry = "",
                confidence = "VPN_INTERFERENCE",
                vpnInterference = true,
                transport = transportCode,
            )
        }
        val targetNet = physicalNetwork
            ?: return@OriginCountryDetector OriginVerificationResult("", "UNVERIFIED", false, "NONE")

        val traceUrls = listOf(
            "https://1.1.1.1/cdn-cgi/trace",
            "https://www.cloudflare.com/cdn-cgi/trace",
        )
        for (u in traceUrls) {
            val loc = runCatching {
                val conn = (targetNet.openConnection(URL(u)) as HttpURLConnection).apply {
                    connectTimeout = 4000
                    readTimeout = 4000
                    requestMethod = "GET"
                    instanceFollowRedirects = false
                }
                try {
                    if (conn.responseCode == 200) {
                        val txt = conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
                        txt.lineSequence()
                            .firstOrNull { it.startsWith("loc=", ignoreCase = true) }
                            ?.substringAfter("=")
                            ?.trim()
                            ?.uppercase(Locale.US)
                            .orEmpty()
                    } else ""
                } finally {
                    conn.disconnect()
                }
            }.getOrDefault("")

            if (loc.length == 2 && loc != "XX" && loc != "T1" && loc.all { it in 'A'..'Z' }) {
                return@OriginCountryDetector OriginVerificationResult(
                    verifiedCountry = loc,
                    confidence = "VERIFIED_DIRECT_IP",
                    vpnInterference = false,
                    transport = transportCode,
                )
            }
        }

        OriginVerificationResult(
            verifiedCountry = "",
            confidence = "UNVERIFIED",
            vpnInterference = false,
            transport = transportCode,
        )
    }

    val defaultConfigProbe = CommunityConfigProbe { ctx, cfg, port, timeoutSec ->
        val prefs = Prefs(ctx)
        SingBox(ctx).testRealTunnelSequential(
            cfg = cfg,
            port = port,
            timeoutSec = timeoutSec,
            probeSamples = 2,
            measureThroughput = true,
            throughputBudgetBytes = THROUGHPUT_SAMPLE_BYTES,
            dnsServer = prefs.dnsServer,
            useDoh = prefs.dnsDoh,
        )
    }

    private fun isBatterySafeForTesting(ctx: Context): Boolean {
        return runCatching {
            val intent = ctx.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED)) ?: return true
            val status = intent.getIntExtra(BatteryManager.EXTRA_STATUS, -1)
            val charging = status == BatteryManager.BATTERY_STATUS_CHARGING ||
                status == BatteryManager.BATTERY_STATUS_FULL
            if (charging) return true
            val level = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
            val scale = intent.getIntExtra(BatteryManager.EXTRA_SCALE, -1)
            if (level < 0 || scale <= 0) true else ((level * 100) / scale) >= 25
        }.getOrDefault(true)
    }

    fun startManualOrScheduledRun(
        ctx: Context,
        candidateConfigs: List<String>,
        isBackgroundRun: Boolean = false,
        onComplete: (() -> Unit)? = null,
    ) {
        if (_state.value.isRunning) return
        val appCtx = ctx.applicationContext
        activeJob = scope.launch {
            runCommunityTestBatch(
                ctx = appCtx,
                candidateConfigs = candidateConfigs,
                isBackgroundRun = isBackgroundRun,
            )
            onComplete?.invoke()
        }
    }

    /**
     * ينفّذ دفعة فحص مجتمعي تسلسلية آمنة ويخزّن النتائج المجهولة الهوية ويرفعها إن توفّرت البوابة.
     */
    suspend fun runCommunityTestBatch(
        ctx: Context,
        candidateConfigs: List<String>,
        isBackgroundRun: Boolean = false,
        originDetector: OriginCountryDetector = defaultOriginDetector,
        configProbe: CommunityConfigProbe = defaultConfigProbe,
        ignoreBatteryCheckForTest: Boolean = false,
    ): List<CommunityTestReportRecord> = runMutex.withLock {
        val prefs = Prefs(ctx)
        val db = ClientDatabase.getInstance(ctx)

        // 1. Explicit consent gate (strictly OFF by default)
        if (!prefs.communityTestingEnabled || prefs.communityConsentAtMs <= 0L) {
            _state.update {
                it.copy(
                    isRunning = false,
                    errorAr = "يلزم تفعيل الموافقة الصريحة أولًا لبدء الفحص المجتمعي",
                    errorEn = "Explicit user opt-in consent is required before running community tests",
                )
            }
            return emptyList()
        }

        // 2. Never interrupt active user VPN or active VPN Hotspot
        if (VpnStateManager.status.value.isActive) {
            _state.update {
                it.copy(
                    isRunning = false,
                    errorAr = "لا يمكن تشغيل الفحص المجتمعي أثناء اتصال الـ VPN النشط حتى لا يتأثر اتصالك أو تتشوّه دولة المصدر",
                    errorEn = "Community testing will not run while VPN is connected to protect your active session and origin accuracy",
                )
            }
            return emptyList()
        }
        if (VpnHotspotManager.state.value.isSharingActive) {
            _state.update {
                it.copy(
                    isRunning = false,
                    errorAr = "تم تأجيل الفحص المجتمعي لأن نقطة اتصال الـ VPN (Hotspot) نشطة حاليًا",
                    errorEn = "Community testing deferred while VPN Hotspot sharing is active",
                )
            }
            return emptyList()
        }

        // 3. Battery & daily quota safeguards
        if (!ignoreBatteryCheckForTest && !isBatterySafeForTesting(ctx)) {
            _state.update {
                it.copy(
                    isRunning = false,
                    errorAr = "البطارية أقل من 25% — تم تأجيل الفحص المجتمعي حفاظًا على طاقة الجهاز",
                    errorEn = "Battery below 25% — community testing deferred to save power",
                )
            }
            return emptyList()
        }

        val nowStart = System.currentTimeMillis()
        val testedLast24h = db.countCommunityReportsSince(nowStart - 86_400_000L)
        val remainingToday = (prefs.communityDailyLimit - testedLast24h).coerceAtLeast(0)
        if (remainingToday <= 0) {
            _state.update {
                it.copy(
                    isRunning = false,
                    statusMessageAr = "اكتملت الحصة اليومية المحددة للفحص المجتمعي (${prefs.communityDailyLimit} سيرفر)",
                    statusMessageEn = "Daily community testing limit reached (${prefs.communityDailyLimit} configs)",
                )
            }
            return emptyList()
        }

        // 4. Verify real non-VPN origin network & Wi-Fi constraint
        val origin = withContext(Dispatchers.IO) { originDetector.verifyOrigin(ctx) }
        if (prefs.communityWifiOnly && origin.transport != "WIFI") {
            _state.update {
                it.copy(
                    isRunning = false,
                    errorAr = "خيار «شبكة Wi‑Fi فقط» مفعّل — اتصل بـ Wi‑Fi أو غيّر الإعداد للمتابعة",
                    errorEn = "Wi-Fi Only limit is enabled — connect to Wi-Fi or adjust settings to continue",
                )
            }
            return emptyList()
        }
        if (origin.vpnInterference) {
            _state.update {
                it.copy(
                    isRunning = false,
                    vpnInterferenceDetected = true,
                    lastCountryConfidence = "VPN_INTERFERENCE",
                    errorAr = "رُصد نفق VPN آخر نشط على الجهاز — يجب إيقاف أي VPN أثناء الفحص المجتمعي لضمان صحة التحقق من الشبكة المحلية",
                    errorEn = "Active VPN interference detected — disconnect any active VPN so direct network origin is verified accurately",
                )
            }
            return emptyList()
        }

        if (origin.verifiedCountry.isNotBlank()) {
            prefs.lastVerifiedOriginCountry = origin.verifiedCountry
        }

        val supportedBatch = candidateConfigs
            .asSequence()
            .map { Converters.cleanUri(it) }
            .filter { it.isNotBlank() && Converters.isSupported(it) }
            .distinctBy { Converters.stableServerId(it) }
            .take(minOf(prefs.communityMaxConfigsPerRun, remainingToday))
            .toList()

        if (supportedBatch.isEmpty()) {
            _state.update {
                it.copy(
                    isRunning = false,
                    errorAr = "لا توجد سيرفرات مرشّحة متاحة للفحص حاليًا — حدّث القائمة أولًا",
                    errorEn = "No candidate configs available to test — refresh server list first",
                )
            }
            return emptyList()
        }

        _state.update {
            it.copy(
                isRunning = true,
                testedInCurrentRun = 0,
                totalInCurrentRun = supportedBatch.size,
                lastVerifiedCountry = origin.verifiedCountry,
                lastCountryConfidence = origin.confidence,
                vpnInterferenceDetected = false,
                errorAr = null,
                errorEn = null,
                statusMessageAr = "جارٍ الفحص المجتمعي المحلي (${origin.verifiedCountry.ifBlank { "غير محددة" }})…",
                statusMessageEn = "Running local community verification (${origin.verifiedCountry.ifBlank { "Unverified" }})…",
            )
        }

        val recorded = ArrayList<CommunityTestReportRecord>(supportedBatch.size)
        try {
            for ((index, cleanCfg) in supportedBatch.withIndex()) {
                coroutineContext.ensureActive()
                // Abort immediately if user starts VPN or VPN Hotspot mid-run!
                if (VpnStateManager.status.value.isActive || VpnHotspotManager.state.value.isSharingActive) {
                    break
                }
                if (!prefs.communityTestingEnabled) break

                val proto = Converters.schemeOf(cleanCfg).let {
                    when (it) {
                        "hy2" -> "hysteria2"
                        "socks5" -> "socks"
                        "https" -> "http"
                        else -> it
                    }
                }
                val sid = Converters.stableServerId(cleanCfg)
                val fp = Converters.configFingerprint(cleanCfg)
                if (sid.isBlank() || fp.isBlank()) continue

                _state.update {
                    it.copy(
                        testedInCurrentRun = index,
                        currentProtocol = proto.uppercase(Locale.US),
                    )
                }

                val res = withContext(Dispatchers.IO) {
                    configProbe.probeSequentially(ctx, cleanCfg, COMMUNITY_TEST_PORT, prefs.timeoutSec.coerceIn(3, 8))
                }
                val isUdpNative = proto in setOf("hysteria2", "tuic")
                val rec = CommunityTestReportRecord(
                    reportId = UUID.randomUUID().toString().replace("-", ""),
                    serverId = sid,
                    configFingerprint = fp,
                    protocol = proto,
                    testedAtMs = System.currentTimeMillis(),
                    success = res.ok && res.latencyMs > 0L,
                    handshakeMs = if (res.ok) res.establishMs.coerceAtLeast(res.latencyMs) else 0L,
                    latencyMs = if (res.ok) res.latencyMs else 0L,
                    downloadKbps = if (res.ok) res.speedKbps.coerceAtLeast(0.0) else 0.0,
                    stabilityScore = if (res.ok) res.stabilityScore.coerceIn(0.0, 100.0) else 0.0,
                    dnsOk = res.ok, // sing-box TEST_URL uses hostname resolution through tunnel-dns
                    tcpOk = res.ok && !isUdpNative,
                    udpOk = res.ok && isUdpNative,
                    failureReason = if (res.ok) "" else normalizeFailureReason(res.error),
                    verifiedCountry = origin.verifiedCountry,
                    countryConfidence = origin.confidence,
                    vpnInterference = origin.vpnInterference,
                    networkTransport = origin.transport,
                    submitted = false,
                )
                db.insertCommunityReport(rec)
                recorded.add(rec)
            }

            prefs.lastCommunityRunAtMs = System.currentTimeMillis()

            // Attempt privacy-minimal upload if ingest endpoint is configured
            val uploadOutcome = submitPendingReports(ctx)
            val okCount = recorded.count { it.success }
            val sum = db.getCommunityReportsSummary()
            val recent = db.listRecentCommunityReports(25)

            _state.update {
                it.copy(
                    isRunning = false,
                    testedInCurrentRun = recorded.size,
                    currentProtocol = "",
                    summary = sum,
                    recentReports = recent,
                    lastSyncMessageAr = uploadOutcome.first,
                    lastSyncMessageEn = uploadOutcome.second,
                    statusMessageAr = "اكتمل الفحص المحلي: نجح $okCount من ${recorded.size} سيرفر (${origin.verifiedCountry.ifBlank { "محلي" }})",
                    statusMessageEn = "Local verification complete: $okCount/${recorded.size} working (${origin.verifiedCountry.ifBlank { "Local" }})",
                )
            }
            return recorded
        } catch (ce: CancellationException) {
            _state.update { it.copy(isRunning = false, currentProtocol = "") }
            throw ce
        } catch (_: Exception) {
            _state.update {
                it.copy(
                    isRunning = false,
                    currentProtocol = "",
                    errorAr = "توقف الفحص المجتمعي بأمان بسبب خطأ عابر في الشبكة",
                    errorEn = "Community test stopped safely due to a transient network error",
                )
            }
            return recorded
        }
    }

    /**
     * يزامن تقارير المجتمع مختزلة الخصوصية (Zero-PII) مباشرةً من نتائج الفحص الدوري الموحّد كل 4 ساعات
     * دون إعادة تشغيل فحص مزدوج في الخلفية، مع احترام الموافقة الصريحة وحدود الحصة وعدم وجود تداخل VPN.
     */
    suspend fun syncFromUnifiedQualityScanIfOptedIn(
        ctx: Context,
        aliveResults: List<TestResult>,
        originDetector: OriginCountryDetector = defaultOriginDetector,
    ): Int = runMutex.withLock {
        val prefs = Prefs(ctx)
        if (!prefs.communityTestingEnabled || prefs.communityConsentAtMs <= 0L) return 0
        if (!prefs.communityBackgroundScheduleEnabled) return 0
        if (VpnStateManager.status.value.isActive || VpnHotspotManager.state.value.isSharingActive) return 0
        if (!isBatterySafeForTesting(ctx)) return 0

        val db = ClientDatabase.getInstance(ctx)
        val nowMs = System.currentTimeMillis()
        val testedLast24h = db.countCommunityReportsSince(nowMs - 86_400_000L)
        val remainingToday = (prefs.communityDailyLimit - testedLast24h).coerceAtLeast(0)
        if (remainingToday <= 0) return 0

        val origin = withContext(Dispatchers.IO) { originDetector.verifyOrigin(ctx) }
        if (origin.vpnInterference || (prefs.communityWifiOnly && origin.transport != "WIFI")) return 0
        if (origin.verifiedCountry.isNotBlank()) {
            prefs.lastVerifiedOriginCountry = origin.verifiedCountry
        }

        val prioritized = aliveResults
            .filter { it.ok && it.latencyMs > 0L }
            .sortedWith(
                compareByDescending<TestResult> { it.speedKbps > 0.0 }
                    .thenByDescending { it.speedKbps }
                    .thenBy { it.latencyMs }
            )
            .distinctBy { Converters.stableServerId(Converters.cleanUri(it.cfg)) }
            .take(minOf(prefs.communityMaxConfigsPerRun, remainingToday))

        if (prioritized.isEmpty()) return 0

        var inserted = 0
        for (res in prioritized) {
            val cleanCfg = Converters.cleanUri(res.cfg)
            val proto = Converters.schemeOf(cleanCfg).let {
                when (it) {
                    "hy2" -> "hysteria2"
                    "socks5" -> "socks"
                    "https" -> "http"
                    else -> it
                }
            }
            val sid = Converters.stableServerId(cleanCfg)
            val fp = Converters.configFingerprint(cleanCfg)
            if (sid.isBlank() || fp.isBlank()) continue
            val isUdpNative = proto in setOf("hysteria2", "tuic")
            val rec = CommunityTestReportRecord(
                reportId = UUID.randomUUID().toString().replace("-", ""),
                serverId = sid,
                configFingerprint = fp,
                protocol = proto,
                testedAtMs = res.testedAtMs.takeIf { it > 0L } ?: nowMs,
                success = true,
                handshakeMs = res.establishMs.coerceAtLeast(res.latencyMs),
                latencyMs = res.latencyMs,
                downloadKbps = res.speedKbps.coerceAtLeast(0.0),
                stabilityScore = res.stabilityScore.coerceIn(0.0, 100.0),
                dnsOk = true,
                tcpOk = !isUdpNative,
                udpOk = isUdpNative,
                failureReason = "",
                verifiedCountry = origin.verifiedCountry,
                countryConfidence = origin.confidence,
                vpnInterference = false,
                networkTransport = origin.transport,
                submitted = false,
            )
            db.insertCommunityReport(rec)
            inserted++
        }
        if (inserted > 0) {
            prefs.lastCommunityRunAtMs = nowMs
            runCatching { submitPendingReports(ctx) }
            refreshSnapshot(ctx)
        }
        return inserted
    }

    /**
     * يبني حزمة التقرير المختزلة الخالية تمامًا من الأسرار أو الروابط الخام أو البيانات الشخصية،
     * ويرسلها عبر HTTPS (أو طابور الاختبار المحلي) مع احترام حدود المعدّل.
     */
    fun buildPrivacyMinimalPayloadJson(
        reporterIdHash: String,
        reports: List<CommunityTestReportRecord>,
    ): String {
        val arr = JSONArray()
        for (r in reports) {
            arr.put(
                JSONObject()
                    .put("report_id", r.reportId)
                    .put("server_id", r.serverId)
                    .put("config_fingerprint", r.configFingerprint)
                    .put("protocol", r.protocol)
                    .put("tested_at_epoch", r.testedAtMs / 1000L)
                    .put("success", r.success)
                    .put("handshake_ms", r.handshakeMs)
                    .put("latency_ms", r.latencyMs)
                    .put("download_kbps", kotlin.math.round(r.downloadKbps * 10.0) / 10.0)
                    .put("stability_score", kotlin.math.round(r.stabilityScore * 10.0) / 10.0)
                    .put("dns_ok", r.dnsOk)
                    .put("tcp_ok", r.tcpOk)
                    .put("udp_ok", r.udpOk)
                    .put("failure_reason", r.failureReason)
                    .put("client_verified_country", r.verifiedCountry)
                    .put("country_confidence", r.countryConfidence)
                    .put("vpn_interference", r.vpnInterference)
                    .put("network_transport", r.networkTransport)
            )
        }
        val payload = JSONObject()
            .put("schema_version", "1.0")
            .put("reporter_id_hash", reporterIdHash)
            .put("submitted_at_epoch", System.currentTimeMillis() / 1000L)
            .put("reports", arr)
            .toString()

        // Hard safety assertion: payload must NEVER contain raw proxy URIs or secret query keys
        check(!payload.contains("://") && !payload.contains("password=", ignoreCase = true)) {
            "Privacy guard blocked unexpected URI/secret material in community payload"
        }
        return payload
    }

    suspend fun submitPendingReports(
        ctx: Context,
        endpointOverrideForTest: String? = null,
    ): Pair<String, String> = withContext(Dispatchers.IO) {
        val prefs = Prefs(ctx)
        if (!prefs.communityTestingEnabled) {
            return@withContext "الرفع متوقف (الموافقة غير مفعّلة)" to "Upload disabled (opt-in off)"
        }
        val db = ClientDatabase.getInstance(ctx)
        val pending = db.listPendingCommunityReports(limit = 25)
        if (pending.isEmpty()) {
            return@withContext "لا توجد تقارير معلّقة للرفع" to "No pending verified reports to upload"
        }

        val baseEndpoint = (endpointOverrideForTest ?: resolveIngestEndpointUrl(ctx, prefs)).trimEnd('/')
        if (baseEndpoint.isBlank()) {
            return@withContext (
                "تم حفظ ${pending.size} نتيجة موثّقة محليًا (سيتم الرفع تلقائيًا فور تفعيل بوابة التجميع السحابية)" to
                    "Saved ${pending.size} verified report(s) locally (queued until cloud ingest endpoint is active)"
                )
        }

        val targetUrl = if (baseEndpoint.endsWith("/v1/reports")) baseEndpoint else "$baseEndpoint/v1/reports"
        val reporterHash = computeAnonymousReporterHash(prefs.communityInstallSalt)
        val bodyBytes = buildPrivacyMinimalPayloadJson(reporterHash, pending).toByteArray(Charsets.UTF_8)

        var conn: HttpURLConnection? = null
        try {
            conn = (URL(targetUrl).openConnection() as HttpURLConnection).apply {
                connectTimeout = 8000
                readTimeout = 8000
                requestMethod = "POST"
                doOutput = true
                setRequestProperty("Content-Type", "application/json; charset=utf-8")
                setRequestProperty("Accept", "application/json")
                setRequestProperty("User-Agent", "bahrain-vpn-community/1.0")
                setFixedLengthStreamingMode(bodyBytes.size)
            }
            conn.outputStream.use { it.write(bodyBytes) }
            val code = conn.responseCode
            if (code in 200..299) {
                db.markCommunityReportsSubmitted(pending.map { it.reportId })
                refreshSnapshot(ctx)
                "تم إرسال ${pending.size} نتيجة مجهولة الهوية بنجاح" to
                    "Uploaded ${pending.size} anonymized report(s) successfully"
            } else if (code == 429) {
                "تم تأجيل الرفع مؤقتًا احترامًا لحدود المعدّل (Rate Limit)" to
                    "Upload deferred due to server rate limit (HTTP 429)"
            } else {
                "تم الاحتفاظ بالنتائج محليًا لإعادة المحاولة لاحقًا (HTTP $code)" to
                    "Reports retained locally for later retry (HTTP $code)"
            }
        } catch (_: Exception) {
            "تعذّر الوصول لبوابة التجميع حاليًا — بقيت النتائج محفوظة بأمان لإعادة المحاولة" to
                "Ingest gateway unreachable — reports safely queued locally"
        } finally {
            conn?.disconnect()
        }
    }
}
