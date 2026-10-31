package com.bahrain.vpnconfigs.ui.enterprise

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.bahrain.vpnconfigs.engine.BlockType
import com.bahrain.vpnconfigs.engine.BlockingProfile
import com.bahrain.vpnconfigs.ui.AppViewModel
import com.bahrain.vpnconfigs.util.tr
import com.bahrain.vpnconfigs.vpn.VpnStateManager
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Runs the DNS/SNI/IP/UDP block-type probe and explains the result in plain language. */
@Composable
fun BlockingDetectionCard(vm: AppViewModel) {
    val vpn by VpnStateManager.status.collectAsState()
    var profile by remember { mutableStateOf(vm.blockingProfile()) }
    var note by remember { mutableStateOf<String?>(null) }

    Card(shape = RoundedCornerShape(18.dp), modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(tr("اكتشاف نوع الحجب", "Censorship type detection"), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Text(
                tr(
                    "يفحص شبكتك الحالية (بدون VPN) ليعرف كيف يتم الحجب، ثم يفضّل البروتوكولات الأنسب له عند اختيار السيرفر.",
                    "Tests your current network (without VPN) to learn how blocking works, then favors the best-suited protocols when picking a server.",
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (vm.blockingProbeRunning) {
                LinearProgressIndicator(Modifier.fillMaxWidth())
                Text(tr("جارٍ الفحص… قد يستغرق حتى 30 ثانية", "Testing… may take up to 30 seconds"), style = MaterialTheme.typography.labelSmall)
            }
            FilledTonalButton(
                enabled = !vm.blockingProbeRunning && !vpn.isActive,
                onClick = {
                    note = null
                    vm.runBlockingProbe { p ->
                        if (p == null) note = tr("تعذّر الفحص. افصل الـ VPN وحاول مجددًا.", "Probe failed. Disconnect the VPN and try again.")
                        else profile = p
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            ) { Text(tr("ابدأ الفحص", "Run detection")) }
            if (vpn.isActive) {
                Text(tr("افصل الـ VPN أولًا لتشغيل الفحص.", "Disconnect the VPN first to run the test."), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.error)
            }
            note?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
            profile?.let { ProfileSummary(it) }
        }
    }
}

@Composable
private fun ProfileSummary(p: BlockingProfile) {
    val time = remember(p.measuredAtMs) { SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(Date(p.measuredAtMs)) }
    Text(tr("آخر فحص: $time • ${p.networkType}", "Last test: $time • ${p.networkType}"), style = MaterialTheme.typography.labelSmall)
    if (!p.internetOk) {
        Text(tr("لا يوجد اتصال بالإنترنت أثناء الفحص.", "No internet connection during the test."), style = MaterialTheme.typography.bodySmall)
        return
    }
    if (p.blocks.isEmpty()) {
        Text(tr("✅ لم يُرصد حجب لموقع الاختبار على هذه الشبكة.", "✅ No blocking detected for the test site on this network."), style = MaterialTheme.typography.bodyMedium)
        return
    }
    p.blocks.forEach { b ->
        val (title, advice) = when (b) {
            BlockType.DNS -> tr("حجب DNS", "DNS tampering") to tr(
                "مزوّد الإنترنت يزوّر عناوين المواقع. فعّل DNS المشفّر (DoH) من الإعدادات.",
                "Your ISP fakes site addresses. Enable encrypted DNS (DoH) in settings.",
            )
            BlockType.SNI -> tr("فحص SNI (DPI)", "SNI filtering (DPI)") to tr(
                "الشبكة تقرأ اسم الموقع داخل اتصال TLS. سيتم تفضيل سيرفرات VLESS Reality.",
                "The network reads site names inside TLS. VLESS Reality servers will be preferred.",
            )
            BlockType.IP -> tr("حجب العناوين IP", "IP blocking") to tr(
                "عناوين المواقع محجوبة مباشرة. أي سيرفر VPN شغّال يتجاوز ذلك.",
                "Site IPs are blocked directly. Any working VPN server bypasses this.",
            )
            BlockType.UDP -> tr("حجب UDP", "UDP blocked") to tr(
                "بروتوكولات Hysteria2 و TUIC لن تعمل هنا، وسيتم تجنّبها.",
                "Hysteria2 and TUIC won't work here and will be avoided.",
            )
        }
        Text("• $title", style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
        Text(advice, style = MaterialTheme.typography.bodySmall)
    }
}
