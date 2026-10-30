// =====================================================================
// EnterpriseWidgets.kt — عناصر الرسوم البيانية والمؤشرات المشتركة (v3.1).
// =====================================================================
package com.bahrain.vpnconfigs.ui.enterprise

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import java.util.Locale

@Composable
fun MetricTile(label: String, value: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Bold)
    }
}

@Composable
fun SpeedGaugeAndCurve(mbps: Double, curve: List<Double>) {
    val primary = MaterialTheme.colorScheme.primary
    val track = MaterialTheme.colorScheme.surfaceVariant
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Box(contentAlignment = Alignment.Center, modifier = Modifier.size(136.dp)) {
            Canvas(modifier = Modifier.fillMaxSize()) {
                val stroke = Stroke(width = 12.dp.toPx(), cap = StrokeCap.Round)
                drawArc(
                    color = track,
                    startAngle = 135f,
                    sweepAngle = 270f,
                    useCenter = false,
                    style = stroke,
                )
                val sweep = ((mbps / 100.0).coerceIn(0.0, 1.0) * 270.0).toFloat()
                drawArc(
                    color = primary,
                    startAngle = 135f,
                    sweepAngle = sweep,
                    useCenter = false,
                    style = stroke,
                )
            }
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    String.format(Locale.US, "%.2f", mbps),
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.ExtraBold,
                )
                Text("Mbps", style = MaterialTheme.typography.labelSmall)
            }
        }

        if (curve.size >= 2) {
            Canvas(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp)
                    .padding(horizontal = 8.dp),
            ) {
                val maxVal = (curve.maxOrNull() ?: 1.0).coerceAtLeast(1.0)
                val stepX = size.width / (curve.size - 1).coerceAtLeast(1)
                val path = Path()
                curve.forEachIndexed { idx, v ->
                    val x = idx * stepX
                    val y = size.height - ((v / maxVal).toFloat() * size.height * 0.88f)
                    if (idx == 0) path.moveTo(x, y) else path.lineTo(x, y)
                }
                drawPath(path = path, color = primary, style = Stroke(width = 3.dp.toPx(), cap = StrokeCap.Round))
                val lastY = size.height - ((curve.last() / maxVal).toFloat() * size.height * 0.88f)
                drawCircle(color = primary, radius = 4.dp.toPx(), center = Offset(size.width, lastY))
            }
        }
    }
}
