// =====================================================================
// ConnectionMonitorCard.kt — لوحة مراقبة الاتصال اللحظية (Part 2.4 Real-Time Monitor)
// وبطاقة التفسير الذكي للسيرفر المختار (Part 2.1 Explainable Smart Selection).
//
// المزايا الهندسية:
//   • مخطط حركة مرور لحظي (Canvas) للتنزيل والرفع يتوقف تلقائيًا عند مغادرة الواجهة (Lifecycle-Aware).
//   • عرض السرعة الحالية، إجمالي البيانات، مدة الجلسة، دولة الخروج، التأخير، التذبذب، فقدان الحزم،
//     تقييم جودة الاتصال، نوع الشبكة الأساسية، والجدول الزمني لأحداث الجلسة الحديثة.
//   • لا يعرض أرقامًا وهمية أبدًا؛ القيم غير المتوفرة بعد تُعرض بوضوح كـ «غير متاح».
// =====================================================================
package com.bahrain.vpnconfigs.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.Timeline
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.bahrain.vpnconfigs.engine.SmartSelectionDecision
import com.bahrain.vpnconfigs.vpn.VpnStateManager
import com.bahrain.vpnconfigs.vpn.VpnStatus
import java.util.Locale

@Composable
fun SmartSelectionSummaryCard(
    smartAutoEnabled: Boolean,
    preferredCountry: String,
    decision: SmartSelectionDecision,
    onToggleSmartAuto: (Boolean) -> Unit,
    onConnectBestNow: () -> Unit,
) {
    val primary = decision.primary
    val fallback = decision.fallback

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f),
        ),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.25f)),
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.AutoAwesome,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(20.dp),
                    )
                    Spacer(Modifier.width(8.dp))
                    Column {
                        Text(
                            text = "الاختيار الذكي للسيرفر",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold,
                        )
                        Text(
                            text = if (smartAutoEnabled) {
                                "نشط تلقائيًا${if (preferredCountry != "ALL") " • الدولة المفضّلة: $preferredCountry" else ""}"
                            } else {
                                "وضع الاختيار اليدوي من القائمة"
                            },
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
                Switch(
                    checked = smartAutoEnabled,
                    onCheckedChange = onToggleSmartAuto,
                )
            }

            if (primary != null) {
                Spacer(Modifier.height(10.dp))
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f))
                Spacer(Modifier.height(10.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "المتصدر: ${primary.label}",
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Text(
                            text = "الدرجة ${primary.score}/100 • الموثوقية ${primary.recentReliabilityPct.toInt()}% • ${primary.confidenceLevel.labelAr}",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    AssistChip(
                        onClick = onConnectBestNow,
                        label = { Text("اتصال ذكي", fontSize = 12.sp) },
                    )
                }

                Spacer(Modifier.height(6.dp))
                primary.reasonsAr.forEach { reason ->
                    Text(
                        text = "• $reason",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.88f),
                    )
                }

                if (fallback != null) {
                    Spacer(Modifier.height(6.dp))
                    Text(
                        text = "البديل الجاهز عند الطوارئ: ${fallback.label} (الدرجة ${fallback.score})",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }
            }
        }
    }
}

@Composable
fun RealTimeConnectionMonitorCard(
    vpnStatus: VpnStatus,
    elapsedSeconds: Long,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface,
        ),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)),
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Timeline,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(20.dp),
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        text = "المراقب اللحظي لحركة النفق",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                    )
                }
                Text(
                    text = vpnStatus.underlyingNetworkAr + (if (vpnStatus.isMeteredNetwork) " • محدودة" else ""),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            Spacer(Modifier.height(10.dp))
            LiveTrafficChart(
                samples = vpnStatus.trafficHistoryBps,
                isConnected = vpnStatus.isTunnelVerified,
            )

            Spacer(Modifier.height(10.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                MonitorMetricTile(
                    title = "مدة الجلسة",
                    value = if (vpnStatus.isTunnelVerified) VpnStateManager.formatDuration(elapsedSeconds) else "00:00:00",
                    modifier = Modifier.weight(1f),
                )
                MonitorMetricTile(
                    title = "الاستجابة / التذبذب",
                    value = if (vpnStatus.isTunnelVerified && vpnStatus.livePingMs > 0L) {
                        "${vpnStatus.livePingMs}ms / ${String.format(Locale.US, "%.0f", vpnStatus.jitterMs)}ms"
                    } else "غير متاح",
                    modifier = Modifier.weight(1f),
                )
                MonitorMetricTile(
                    title = "فقدان الحزم",
                    value = if (vpnStatus.isTunnelVerified) {
                        String.format(Locale.US, "%.1f%%", vpnStatus.packetLossPct)
                    } else "غير متاح",
                    modifier = Modifier.weight(1f),
                )
            }

            Spacer(Modifier.height(8.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                MonitorMetricTile(
                    title = "بيانات الجلسة",
                    value = "↓ ${VpnStateManager.formatBytes(vpnStatus.totalDownBytes)} • ↑ ${VpnStateManager.formatBytes(vpnStatus.totalUpBytes)}",
                    modifier = Modifier.weight(1.3f),
                )
                MonitorMetricTile(
                    title = "نقطة الخروج / الجودة",
                    value = buildString {
                        if (vpnStatus.exitCountry.isNotBlank()) {
                            append("${VpnStateManager.countryFlag(vpnStatus.exitCountry)} ${vpnStatus.exitCountry} • ")
                        }
                        append(if (vpnStatus.isTunnelVerified) vpnStatus.connectionQuality else "متوقف")
                    },
                    modifier = Modifier.weight(1f),
                )
            }

            if (vpnStatus.recentEvents.isNotEmpty()) {
                Spacer(Modifier.height(10.dp))
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.35f))
                Spacer(Modifier.height(8.dp))
                Text(
                    text = "أحدث أحداث الاتصال والحماية:",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.SemiBold,
                )
                Spacer(Modifier.height(4.dp))
                vpnStatus.recentEvents.take(4).forEach { ev ->
                    Text(
                        text = ev,
                        style = MaterialTheme.typography.labelSmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

@Composable
private fun LiveTrafficChart(
    samples: List<Pair<Long, Long>>,
    isConnected: Boolean,
) {
    val downColor = Color(0xFF10B981) // Emerald green for Download
    val upColor = Color(0xFF38BDF8)   // Sky blue for Upload
    val gridColor = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.25f)

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f))
            .padding(10.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(8.dp).clip(CircleShape).background(downColor))
                Spacer(Modifier.width(4.dp))
                Text("تنزيل", style = MaterialTheme.typography.labelSmall)
                Spacer(Modifier.width(12.dp))
                Box(Modifier.size(8.dp).clip(CircleShape).background(upColor))
                Spacer(Modifier.width(4.dp))
                Text("رفع", style = MaterialTheme.typography.labelSmall)
            }
            val peakBps = samples.maxOfOrNull { maxOf(it.first, it.second) } ?: 0L
            Text(
                text = if (isConnected && peakBps > 0L) "الذروة: ${VpnStateManager.formatSpeed(peakBps)}" else "بانتظار حركة مرور حيّة",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        Spacer(Modifier.height(6.dp))
        Canvas(
            modifier = Modifier
                .fillMaxWidth()
                .height(78.dp),
        ) {
            val w = size.width
            val h = size.height
            // Horizontal baseline guides
            for (i in 1..2) {
                val y = h * (i / 3f)
                drawLine(gridColor, Offset(0f, y), Offset(w, y), strokeWidth = 1f)
            }
            if (samples.size < 2) return@Canvas
            val maxVal = (samples.maxOf { maxOf(it.first, it.second) }.coerceAtLeast(4096L)).toFloat()
            val stepX = w / (samples.size - 1).coerceAtLeast(1)

            val downPath = Path()
            val downFill = Path()
            val upPath = Path()

            samples.forEachIndexed { idx, (dl, ul) ->
                val x = idx * stepX
                val yDl = h - ((dl.toFloat() / maxVal).coerceIn(0f, 1f) * (h - 6f)) - 3f
                val yUl = h - ((ul.toFloat() / maxVal).coerceIn(0f, 1f) * (h - 6f)) - 3f
                if (idx == 0) {
                    downPath.moveTo(x, yDl)
                    downFill.moveTo(x, h)
                    downFill.lineTo(x, yDl)
                    upPath.moveTo(x, yUl)
                } else {
                    downPath.lineTo(x, yDl)
                    downFill.lineTo(x, yDl)
                    upPath.lineTo(x, yUl)
                }
            }
            downFill.lineTo(w, h)
            downFill.close()

            drawPath(
                path = downFill,
                brush = Brush.verticalGradient(
                    colors = listOf(downColor.copy(alpha = 0.26f), Color.Transparent),
                ),
            )
            drawPath(path = downPath, color = downColor, style = Stroke(width = 3.2f))
            drawPath(path = upPath, color = upColor, style = Stroke(width = 2.4f))
        }
    }
}

@Composable
private fun MonitorMetricTile(
    title: String,
    value: String,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.padding(horizontal = 4.dp)) {
        Text(
            text = title,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.SemiBold,
            maxLines = 1,
        )
    }
}
