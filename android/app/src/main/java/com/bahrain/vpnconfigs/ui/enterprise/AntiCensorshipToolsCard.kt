package com.bahrain.vpnconfigs.ui.enterprise

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.bahrain.vpnconfigs.engine.TlsFragment
import com.bahrain.vpnconfigs.ui.AppViewModel
import com.bahrain.vpnconfigs.util.tr
import com.bahrain.vpnconfigs.vpn.VpnStateManager

/** TLS fragmentation mode and the free Cloudflare WARP fallback. */
@Composable
fun AntiCensorshipToolsCard(vm: AppViewModel) {
    val vpn by VpnStateManager.status.collectAsState()
    var warpNote by remember { mutableStateOf<String?>(null) }

    Card(shape = RoundedCornerShape(18.dp), modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(tr("أدوات تجاوز الحجب", "Anti-censorship tools"), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)

            // ── TLS fragment ──
            Text(tr("تجزئة TLS (Fragment)", "TLS fragmentation"), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            Text(
                tr(
                    "تقسّم بداية اتصال TLS إلى أجزاء صغيرة حتى لا يقرأ فلتر الحجب اسم السيرفر. مفيدة ضد فحص SNI، وقد تبطئ بداية الاتصال قليلًا. «تلقائي» يفعّلها فقط عندما يكتشف الفحص حجب SNI على شبكتك.",
                    "Splits the start of the TLS connection so filters can't read the server name. Helps against SNI filtering; may slightly slow connection setup. \"Auto\" turns it on only when the probe detects SNI filtering on your network.",
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf(
                    TlsFragment.MODE_AUTO to tr("تلقائي", "Auto"),
                    TlsFragment.MODE_ON to tr("دائمًا", "Always"),
                    TlsFragment.MODE_OFF to tr("إيقاف", "Off"),
                ).forEach { (mode, label) ->
                    FilterChip(selected = vm.tlsFragmentMode == mode, onClick = { vm.updateTlsFragmentMode(mode) }, label = { Text(label) })
                }
            }
            Text(tr("يُطبَّق عند الاتصال التالي.", "Applies on the next connection."), style = MaterialTheme.typography.labelSmall)

            HorizontalDivider()

            // ── Cloudflare WARP ──
            Text("Cloudflare WARP", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            Text(
                tr(
                    "خدمة مجانية من Cloudflare تُستخدم كاحتياط عندما تفشل كل السيرفرات. Cloudflare تمرّر اتصالك، وقد تكون محجوبة في بعض الشبكات.",
                    "A free Cloudflare service used as a fallback when every server fails. Cloudflare carries your traffic, and it may be blocked on some networks.",
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (vm.warpBusy) LinearProgressIndicator(Modifier.fillMaxWidth())
            if (!vm.warpRegistered) {
                Button(
                    enabled = !vm.warpBusy && !vpn.isActive,
                    onClick = {
                        warpNote = null
                        vm.registerWarp { ok ->
                            warpNote = if (ok) tr("تم تفعيل WARP ✅", "WARP enabled ✅")
                            else tr("تعذّر التفعيل. تأكد من الإنترنت وأن الـ VPN مفصول، ثم حاول مجددًا.", "Setup failed. Check internet and that the VPN is off, then retry.")
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(tr("تفعيل WARP المجاني", "Enable free WARP")) }
                if (vpn.isActive) {
                    Text(tr("افصل الـ VPN أولًا لتفعيل WARP.", "Disconnect the VPN first to enable WARP."), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.error)
                }
            } else {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        tr("استخدام WARP تلقائيًا عند فشل كل السيرفرات", "Use WARP automatically when all servers fail"),
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.weight(1f),
                    )
                    Switch(checked = vm.warpFallbackEnabled, onCheckedChange = { vm.updateWarpFallback(it) })
                }
                OutlinedButton(onClick = { vm.connectWarp() }, modifier = Modifier.fillMaxWidth()) {
                    Text(tr("اتصل عبر WARP الآن", "Connect via WARP now"))
                }
                TextButton(onClick = { vm.resetWarp() }) { Text(tr("إلغاء تسجيل WARP", "Remove WARP registration")) }
            }
            warpNote?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
    }
}
