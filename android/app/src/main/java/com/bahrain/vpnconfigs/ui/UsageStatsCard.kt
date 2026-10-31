package com.bahrain.vpnconfigs.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.bahrain.vpnconfigs.data.ClientDatabase
import com.bahrain.vpnconfigs.data.UsageBucket
import com.bahrain.vpnconfigs.util.tr
import com.bahrain.vpnconfigs.vpn.VpnStateManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private data class UsageSummary(val servers: List<UsageBucket>, val networks: List<UsageBucket>)

/**
 * Data used through the VPN for the period selected in the history filter (0 = all time),
 * split by server and by network type. The live session is added on top of saved sessions.
 */
@Composable
fun UsageStatsCard(dateRangeDays: Int, refreshKey: Any?) {
    val ctx = LocalContext.current
    val live by VpnStateManager.status.collectAsState()
    val summary by produceState(UsageSummary(emptyList(), emptyList()), dateRangeDays, refreshKey) {
        val since = if (dateRangeDays <= 0) 0L else System.currentTimeMillis() - dateRangeDays * 86_400_000L
        value = withContext(Dispatchers.IO) {
            val db = ClientDatabase.getInstance(ctx)
            UsageSummary(db.usageBreakdown(since), db.usageBreakdown(since, byNetwork = true, limit = 4))
        }
    }
    val liveBytes = if (live.isActive) live.totalDownBytes + live.totalUpBytes else 0L
    val total = summary.servers.sumOf { it.totalBytes } + liveBytes
    val period = when (dateRangeDays) {
        1 -> tr("آخر 24 ساعة", "Last 24 hours")
        7 -> tr("آخر 7 أيام", "Last 7 days")
        30 -> tr("آخر 30 يومًا", "Last 30 days")
        else -> tr("كل الفترات", "All time")
    }

    Card(shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    tr("استهلاك البيانات", "Data usage"),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.weight(1f),
                )
                Text(period, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Text(
                VpnStateManager.formatBytes(total),
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
            )
            if (liveBytes > 0L) {
                Text(
                    tr("منها الجلسة الحالية: ${VpnStateManager.formatBytes(liveBytes)}", "Current session: ${VpnStateManager.formatBytes(liveBytes)}"),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (summary.networks.isNotEmpty()) {
                Text(
                    summary.networks.joinToString("  •  ") { "${networkName(it.key)}: ${VpnStateManager.formatBytes(it.totalBytes)}" },
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            if (summary.servers.isEmpty()) {
                Text(
                    tr("لا توجد جلسات مسجّلة في هذه الفترة", "No recorded sessions in this period"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                Text(tr("الأكثر استهلاكًا حسب السيرفر", "Top servers by data"), style = MaterialTheme.typography.labelMedium)
                val max = summary.servers.maxOf { it.totalBytes }.coerceAtLeast(1L)
                summary.servers.forEach { b ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            b.key,
                            style = MaterialTheme.typography.bodySmall,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f),
                        )
                        Text(
                            "${VpnStateManager.formatBytes(b.totalBytes)} · ${b.sessions}×",
                            style = MaterialTheme.typography.labelSmall,
                        )
                    }
                    LinearProgressIndicator(
                        progress = { b.totalBytes.toFloat() / max },
                        modifier = Modifier.fillMaxWidth().height(4.dp),
                    )
                }
            }
        }
    }
}

private fun networkName(raw: String): String = when (raw.uppercase()) {
    "WIFI" -> tr("واي فاي", "Wi-Fi")
    "CELLULAR", "MOBILE", "MOBILE_DATA" -> tr("بيانات الجوال", "Mobile data")
    "ETHERNET" -> "Ethernet"
    else -> tr("أخرى", "Other")
}
