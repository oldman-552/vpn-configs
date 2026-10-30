// =====================================================================
// TunnelSpeedStudioSection.kt — استوديو اختبار السرعة الحقيقي عبر النفق
// (التنزيل / الرفع / Ping / Jitter / Packet Loss + سجل المقارنة) — v3.1.
// =====================================================================
package com.bahrain.vpnconfigs.ui.enterprise

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.bahrain.vpnconfigs.ui.AppViewModel
import com.bahrain.vpnconfigs.ui.UiState
import com.bahrain.vpnconfigs.vpn.VpnPhase
import com.bahrain.vpnconfigs.vpn.VpnStatus
import java.util.Locale

@Composable
fun TunnelSpeedStudioCard(
    state: UiState,
    vpnStatus: VpnStatus,
    vm: AppViewModel,
) {
    Card(
        shape = RoundedCornerShape(18.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Filled.Speed, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                Spacer(Modifier.width(8.dp))
                Column {
                    Text("اختبار السرعة الحقيقي عبر النفق", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                    Text(
                        if (vpnStatus.isTunnelVerified) "يمر الفحص فعليًا داخل نفق ${vpnStatus.activeLabel}"
                        else "الـ VPN غير متّصل — سيقيس سرعة الشبكة المباشرة للمقارنة",
                        style = MaterialTheme.typography.labelSmall,
                    )
                }
            }

            val latest = state.latestSpeedRecord
            val displayMbps = if (state.speedTestRunning) state.liveSpeedGaugeMbps else (latest?.downloadMbps ?: 0.0)
            SpeedGaugeAndCurve(
                mbps = displayMbps,
                curve = if (state.speedTestRunning) state.liveSpeedCurve else (latest?.curveSamplesMbps ?: emptyList()),
            )

            if (state.speedTestRunning) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                    Text(state.speedTestStage, style = MaterialTheme.typography.bodySmall)
                }
            }

            latest?.let { r ->
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    MetricTile("التنزيل", String.format(Locale.US, "%.2f Mbps", r.downloadMbps))
                    MetricTile("الرفع", String.format(Locale.US, "%.2f Mbps", r.uploadMbps))
                    MetricTile("Ping", "${r.pingMs} ms")
                }
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    MetricTile("Jitter", "${r.jitterMs} ms")
                    MetricTile("فقدان الحزم", String.format(Locale.US, "%.0f%%", r.packetLossPct))
                    MetricTile("الذروة", String.format(Locale.US, "%.2f Mbps", r.maxMbps))
                }
            }

            Button(
                onClick = { vm.runFullClientSpeedTest() },
                enabled = !state.speedTestRunning,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(if (state.speedTestRunning) "جارٍ القياس الفعلي…" else "بدء اختبار السرعة الشامل الآن")
            }

            if (state.speedHistory.size >= 2) {
                HorizontalDivider()
                Text("مقارنة سجل اختبارات السرعة الأخيرة:", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
                state.speedHistory.take(4).forEach { h ->
                    Text(
                        String.format(
                            Locale.US,
                            "• %s: ↓ %.2f Mbps | ↑ %.2f Mbps | %d ms | Loss %.0f%%",
                            h.serverLabel,
                            h.downloadMbps,
                            h.uploadMbps,
                            h.pingMs,
                            h.packetLossPct,
                        ),
                        style = MaterialTheme.typography.labelSmall,
                    )
                }
            }
        }
    }
}
