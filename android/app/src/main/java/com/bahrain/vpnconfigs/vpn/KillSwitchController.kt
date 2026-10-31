// =====================================================================
// KillSwitchController.kt — معمارية مفتاح الإيقاف الصارم (Fail-Closed Kill Switch — Phase 4).
//
// المبادئ الهندسية:
//   1) عند تفعيل Kill Switch، تُنشأ واجهة TUN (مع مسارات 0.0.0.0/0 و ::/0) فور بدء
//      الاتصال وقبل التحقق من السيرفر، بحيث لا تتسرب أي حزمة عبر الشبكة الفعلية أثناء الربط.
//   2) أثناء تبديل السيرفرات أو انقطاع الشبكة أو فشل جميع البدائل، تظل واجهة TUN مقفلة
//      في حالة PROTECTION_ACTIVE لمنع الارتداد التلقائي للشبكة غير المحمية، ولا تُفتح إلا
//      عندما يضغط المستخدم «قطع الاتصال» صراحةً أو ينجح نفق بديل موثّق.
//   3) يرصد حالة القفل الدائم في النظام (Android OS Lockdown / Always-On VPN) ويوثّق
//      بصدق الحدود التي لا يملكها إلا نظام التشغيل (مثل لحظات الإقلاع الأولى للنواة).
// =====================================================================
package com.bahrain.vpnconfigs.vpn

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.provider.Settings
import com.bahrain.vpnconfigs.util.AppI18n

data class KillSwitchState(
    val appKillSwitchEnabled: Boolean,
    val osLockdownActive: Boolean,
    val blockingUnprotectedTraffic: Boolean,
    val limitationNoteAr: String,
)

object KillSwitchController {

    const val OS_LIMITATION_NOTE_AR: String =
        "يحجب مفتاح الإيقاف المدمج مرور بيانات التطبيقات خارج النفق أثناء الربط والتبديل والانقطاع؛ " +
            "ولحجب حزم النظام قبل إقلاع التطبيق عند إعادة تشغيل الهاتف، فعّل أيضًا خيار «VPN دائم + حظر الاتصالات بدون VPN» من إعدادات أندرويد."

    val ALWAYS_ON_STEPS_AR: List<String> = listOf(
        "١. افتح إعدادات الشبكة والـ VPN في نظام أندرويد عبر الزر أدناه.",
        "٢. اضغط على أيقونة الترس ⚙️ بجانب تطبيق bahrain-vpn.",
        "٣. فعّل خيار «شبكة VPN نشطة دائمًا» (Always-on VPN).",
        "٤. فعّل خيار «حظر الاتصالات بدون VPN» (Block connections without VPN) لتفعيل القفل الصارم من النواة.",
    )

    val ALWAYS_ON_STEPS_EN: List<String> = listOf(
        "1. Open Android Network & VPN settings using the button below.",
        "2. Tap the gear ⚙️ icon next to bahrain-vpn.",
        "3. Enable \"Always-on VPN\".",
        "4. Enable \"Block connections without VPN\" for strict OS-level kernel lockdown.",
    )

    fun alwaysOnSteps(): List<String> =
        if (AppI18n.isEnglish) ALWAYS_ON_STEPS_EN else ALWAYS_ON_STEPS_AR

    fun createSystemVpnSettingsIntent(): Intent =
        Intent(Settings.ACTION_VPN_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

    fun isOsLockdownActive(service: VpnService?): Boolean {
        if (service == null) return false
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            runCatching { service.isLockdownEnabled }.getOrDefault(false)
        } else {
            false
        }
    }

    fun shouldEstablishTunBeforeProbe(appKillSwitchEnabled: Boolean): Boolean =
        appKillSwitchEnabled

    fun shouldRetainTunOnFailure(appKillSwitchEnabled: Boolean, userRequestedDisconnect: Boolean): Boolean =
        appKillSwitchEnabled && !userRequestedDisconnect

    fun resolveFailurePhase(appKillSwitchEnabled: Boolean, userRequestedDisconnect: Boolean): VpnPhase =
        when {
            userRequestedDisconnect -> VpnPhase.DISCONNECTED
            appKillSwitchEnabled -> VpnPhase.PROTECTION_ACTIVE
            else -> VpnPhase.CONNECTION_FAILED
        }

    fun describeState(
        appKillSwitchEnabled: Boolean,
        osLockdownActive: Boolean,
        tunEstablished: Boolean,
        tunnelVerified: Boolean,
    ): KillSwitchState {
        val blocking = (appKillSwitchEnabled && tunEstablished && !tunnelVerified) || (osLockdownActive && !tunnelVerified)
        return KillSwitchState(
            appKillSwitchEnabled = appKillSwitchEnabled,
            osLockdownActive = osLockdownActive,
            blockingUnprotectedTraffic = blocking,
            limitationNoteAr = OS_LIMITATION_NOTE_AR,
        )
    }
}
