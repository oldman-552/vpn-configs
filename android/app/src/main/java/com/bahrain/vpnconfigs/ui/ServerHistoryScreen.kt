// =====================================================================
// ServerHistoryScreen.kt — شاشة السجل التاريخي المستديم للاتصالات (Part 2.5).
//
// المزايا الهندسية:
//   • قراءة سريعة بصفحات (Pagination) من SQLite تبقى محفوظة بعد إعادة تشغيل التطبيق والهاتف.
//   • بحث باسم السيرفر أو الدولة أو البروتوكول، وفلترة بالنطاق الزمني (24 ساعة / 7 أيام / 30 يومًا / الكل).
//   • فرز حسب الأحدث، الأعلى سرعة، الأقل تأخيرًا، أو الأطول مدة.
//   • تحكم المستخدم الكامل في فترة الاحتفاظ وحذف عنصر منفرد أو مسح السجل بالكامل.
// =====================================================================
package com.bahrain.vpnconfigs.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Replay
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.bahrain.vpnconfigs.data.HistorySortOrder
import com.bahrain.vpnconfigs.data.ServerSessionRecord
import com.bahrain.vpnconfigs.util.tr
import com.bahrain.vpnconfigs.vpn.VpnStateManager
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun ServerHistoryScreen(
    records: List<ServerSessionRecord>,
    totalMatchingCount: Int,
    searchQuery: String,
    dateRangeDays: Int, // 0 = All, 1 = 24h, 7 = 7d, 30 = 30d
    sortOrder: HistorySortOrder,
    retentionDays: Int,
    serversById: Map<String, ServerItem>,
    onSearchChange: (String) -> Unit,
    onDateRangeChange: (Int) -> Unit,
    onSortChange: (HistorySortOrder) -> Unit,
    onRetentionChange: (Int) -> Unit,
    onLoadMore: () -> Unit,
    onDeleteEntry: (Long) -> Unit,
    onClearAll: () -> Unit,
    onReconnectServer: (ServerItem) -> Unit,
    modifier: Modifier = Modifier,
) {
    var confirmClearAll by remember { mutableStateOf(false) }
    val dateFmt = remember { SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US) }

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 14.dp, vertical = 10.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = tr("سجل الجلسات التاريخي ($totalMatchingCount)", "Session History ($totalMatchingCount)"),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    text = tr(
                        "مخزّن محليًا بأمان في SQLite بدون بيانات اعتماد • الاحتفاظ: $retentionDays يومًا",
                        "Stored locally in SQLite with zero credentials • Retention: $retentionDays days",
                    ),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (records.isNotEmpty()) {
                IconButton(onClick = { confirmClearAll = true }) {
                    Icon(
                        imageVector = Icons.Default.DeleteSweep,
                        contentDescription = tr("مسح السجل بالكامل", "Clear all history"),
                        tint = MaterialTheme.colorScheme.error,
                    )
                }
            }
        }

        Spacer(Modifier.height(8.dp))

        OutlinedTextField(
            value = searchQuery,
            onValueChange = onSearchChange,
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
            placeholder = { Text(tr("ابحث باسم السيرفر، البروتوكول، أو رمز الدولة…", "Search by server name, protocol, or country code…")) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(8.dp))

        // Date range filter
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            listOf(
                0 to tr("كل الفترات", "All Time"),
                1 to tr("آخر 24 ساعة", "Last 24h"),
                7 to tr("آخر 7 أيام", "Last 7d"),
                30 to tr("آخر 30 يومًا", "Last 30d"),
            ).forEach { (days, lbl) ->
                FilterChip(
                    selected = dateRangeDays == days,
                    onClick = { onDateRangeChange(days) },
                    label = { Text(lbl) },
                )
            }
        }

        // Sort order + Retention quick chips
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            HistorySortOrder.entries.forEach { ord ->
                FilterChip(
                    selected = sortOrder == ord,
                    onClick = { onSortChange(ord) },
                    label = { Text(ord.displayLabel) },
                )
            }
            listOf(7, 30, 90).forEach { ret ->
                AssistChip(
                    onClick = { onRetentionChange(ret) },
                    label = {
                        Text(
                            if (retentionDays == ret) tr("الاحتفاظ: ${ret}ي ✓", "Keep: ${ret}d ✓")
                            else tr("احتفاظ ${ret}ي", "Keep ${ret}d")
                        )
                    },
                )
            }
        }

        Spacer(Modifier.height(8.dp))

        if (records.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                contentAlignment = Alignment.Center,
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        imageVector = Icons.Default.History,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary.copy(alpha = 0.5f),
                        modifier = Modifier.size(48.dp),
                    )
                    Spacer(Modifier.height(8.dp))
                    Text(
                        text = tr("لا توجد جلسات مسجّلة تطابق الفلتر الحالي", "No recorded sessions match the current filter"),
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.SemiBold,
                    )
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier.weight(1f),
                contentPadding = PaddingValues(bottom = 24.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                items(records, key = { it.id }) { rec ->
                    val liveMatch = serversById[rec.serverId]
                    val statusColor = if (rec.success) Color(0xFF10B981) else Color(0xFFEF4444)

                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(15.dp),
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.45f)),
                    ) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween,
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = buildString {
                                            if (rec.country.isNotBlank()) append("${VpnStateManager.countryFlag(rec.country)} ")
                                            append(rec.serverLabel)
                                        },
                                        style = MaterialTheme.typography.titleSmall,
                                        fontWeight = FontWeight.Bold,
                                    )
                                    Text(
                                        text = "${dateFmt.format(Date(rec.connectedAtMs))} • ${rec.protocol} • ${rec.maskedEndpoint}",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(
                                        text = if (rec.success) tr("ناجح", "OK") else tr("فشل", "Failed"),
                                        style = MaterialTheme.typography.labelSmall,
                                        color = statusColor,
                                        fontWeight = FontWeight.Bold,
                                    )
                                    IconButton(onClick = { onDeleteEntry(rec.id) }) {
                                        Icon(
                                            imageVector = Icons.Default.Delete,
                                            contentDescription = tr("حذف السجل", "Delete entry"),
                                            modifier = Modifier.size(18.dp),
                                        )
                                    }
                                }
                            }

                            Spacer(Modifier.height(6.dp))
                            val metricsLine = buildString {
                                append(tr("المدة: ${VpnStateManager.formatDuration(rec.durationSec)}", "Duration: ${VpnStateManager.formatDuration(rec.durationSec)}"))
                                if (rec.avgLatencyMs > 0L) append(tr(" • الاستجابة: ${rec.avgLatencyMs} ms", " • Ping: ${rec.avgLatencyMs} ms"))
                                if (rec.peakDownloadBps > 0L) append(tr(" • الذروة: ↓ ${VpnStateManager.formatSpeed(rec.peakDownloadBps)}", " • Peak: ↓ ${VpnStateManager.formatSpeed(rec.peakDownloadBps)}"))
                                if (rec.totalDownBytes > 0L || rec.totalUpBytes > 0L) {
                                    append(tr(" • البيانات: ${VpnStateManager.formatBytes(rec.totalDownBytes + rec.totalUpBytes)}", " • Data: ${VpnStateManager.formatBytes(rec.totalDownBytes + rec.totalUpBytes)}"))
                                }
                                append(tr(" • الشبكة: ${rec.networkType}", " • Net: ${rec.networkType}"))
                            }
                            Text(
                                text = metricsLine,
                                style = MaterialTheme.typography.bodySmall,
                            )

                            if (rec.failureReason.isNotBlank()) {
                                Spacer(Modifier.height(4.dp))
                                Text(
                                    text = tr("السبب: ${rec.failureReason}", "Note: ${rec.failureReason}"),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = if (rec.success) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                                )
                            }

                            if (liveMatch != null) {
                                Spacer(Modifier.height(8.dp))
                                OutlinedButton(
                                    onClick = { onReconnectServer(liveMatch) },
                                    modifier = Modifier.fillMaxWidth(),
                                ) {
                                    Icon(Icons.Default.Replay, contentDescription = null, modifier = Modifier.size(16.dp))
                                    Spacer(Modifier.width(6.dp))
                                    Text(tr("إعادة الاتصال بهذا السيرفر", "Reconnect to this server"))
                                }
                            }
                        }
                    }
                }

                if (records.size < totalMatchingCount) {
                    item {
                        OutlinedButton(
                            onClick = onLoadMore,
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text(tr("تحميل المزيد (${records.size} من $totalMatchingCount)", "Load More (${records.size} of $totalMatchingCount)"))
                        }
                    }
                }
            }
        }
    }

    if (confirmClearAll) {
        AlertDialog(
            onDismissRequest = { confirmClearAll = false },
            title = { Text(tr("مسح سجل الاتصالات بالكامل؟", "Clear all connection history?")) },
            text = { Text(tr("سيتم حذف جميع الجلسات المحفوظة من قاعدة البيانات المحلية نهائيًا.", "All saved session records will be permanently deleted from the local database.")) },
            confirmButton = {
                Button(
                    onClick = {
                        onClearAll()
                        confirmClearAll = false
                    }
                ) {
                    Text(tr("مسح الكل", "Clear All"))
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmClearAll = false }) {
                    Text(tr("إلغاء", "Cancel"))
                }
            },
        )
    }
}
