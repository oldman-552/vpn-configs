// =====================================================================
// FavoritesScreen.kt — شاشة إدارة المفضلة المتقدمة (Part 2.6 Favorites Management).
//
// المزايا الهندسية:
//   • تعتمد على المعرّف المستقر الآمن (serverId) دون كشف أي بيانات اعتماد.
//   • تدعم الأسماء المخصّصة، المجموعات (عام، العمل، الألعاب، البث، أو مجموعة مخصّصة)،
//     الترتيب المتعدد، مؤشر التوفّر الحي، الأداء التاريخي المحلي، والاتصال بضغطة واحدة.
// =====================================================================
package com.bahrain.vpnconfigs.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Star
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.bahrain.vpnconfigs.data.FavoriteServerRecord
import com.bahrain.vpnconfigs.data.FavoriteSortOrder
import com.bahrain.vpnconfigs.data.LocalServerTelemetry
import com.bahrain.vpnconfigs.engine.Converters
import com.bahrain.vpnconfigs.util.tr
import com.bahrain.vpnconfigs.vpn.VpnStateManager
import java.util.Locale

@Composable
fun FavoritesScreen(
    favorites: List<FavoriteServerRecord>,
    groups: List<String>,
    selectedGroup: String,
    sortOrder: FavoriteSortOrder,
    serversById: Map<String, ServerItem>,
    telemetryById: Map<String, LocalServerTelemetry>,
    activeServerId: String,
    onSelectGroup: (String) -> Unit,
    onSelectSort: (FavoriteSortOrder) -> Unit,
    onConnectFavorite: (ServerItem) -> Unit,
    onEditFavorite: (serverId: String, customName: String, groupName: String) -> Unit,
    onRemoveFavorite: (serverId: String) -> Unit,
    modifier: Modifier = Modifier,
) {
    var editingFav by remember { mutableStateOf<FavoriteServerRecord?>(null) }

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 14.dp, vertical = 10.dp),
    ) {
        Text(
            text = tr("السيرفرات المفضّلة (${favorites.size})", "Favorite Servers (${favorites.size})"),
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.Bold,
        )
        Text(
            text = tr(
                "إدارة منظّمة بالمجموعات والأسماء المخصّصة مع حفظ البصمة الآمنة المستقرة.",
                "Organized by custom names and groups using stable cryptographic server IDs.",
            ),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Spacer(Modifier.height(10.dp))

        // Group filter bar
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            FilterChip(
                selected = selectedGroup == "ALL",
                onClick = { onSelectGroup("ALL") },
                label = { Text(tr("كل المجموعات", "All Groups")) },
            )
            groups.forEach { g ->
                FilterChip(
                    selected = selectedGroup == g,
                    onClick = { onSelectGroup(g) },
                    label = { Text(g) },
                )
            }
        }

        Spacer(Modifier.height(6.dp))

        // Sort order bar
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            FavoriteSortOrder.entries.forEach { order ->
                FilterChip(
                    selected = sortOrder == order,
                    onClick = { onSelectSort(order) },
                    label = { Text(tr("ترتيب: ${order.labelAr}", "Sort: ${order.labelEn}")) },
                )
            }
        }

        Spacer(Modifier.height(10.dp))

        if (favorites.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                contentAlignment = Alignment.Center,
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        imageVector = Icons.Default.Star,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary.copy(alpha = 0.5f),
                        modifier = Modifier.size(48.dp),
                    )
                    Spacer(Modifier.height(8.dp))
                    Text(
                        text = tr("لا توجد سيرفرات مفضّلة في هذه المجموعة بعد", "No favorite servers in this group yet"),
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Text(
                        text = tr(
                            "اضغط على أيقونة النجمة ⭐ بجانب أي سيرفر لإضافته هنا وتنظيمه.",
                            "Tap the ⭐ star next to any server to save and organize it here.",
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier.weight(1f),
                contentPadding = PaddingValues(bottom = 24.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                items(favorites, key = { it.serverId }) { fav ->
                    val liveServer = serversById[fav.serverId]
                    val tel = telemetryById[fav.serverId]
                    val isOnlineAvailable = liveServer != null && !liveServer.localFailed
                    val isCurrentlyConnected = activeServerId.isNotBlank() && activeServerId == fav.serverId

                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(
                            containerColor = if (isCurrentlyConnected) {
                                MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.35f)
                            } else {
                                MaterialTheme.colorScheme.surface
                            },
                        ),
                        border = BorderStroke(
                            1.dp,
                            if (isCurrentlyConnected) MaterialTheme.colorScheme.primary
                            else MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.45f),
                        ),
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween,
                            ) {
                                Row(
                                    modifier = Modifier.weight(1f),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    Box(
                                        modifier = Modifier
                                            .size(10.dp)
                                            .clip(CircleShape)
                                            .background(
                                                when {
                                                    isCurrentlyConnected -> Color(0xFF10B981)
                                                    isOnlineAvailable -> Color(0xFF22C55E)
                                                    liveServer?.localFailed == true -> Color(0xFFEF4444)
                                                    else -> Color(0xFF9CA3AF)
                                                }
                                            ),
                                    )
                                    Spacer(Modifier.width(8.dp))
                                    Column {
                                        Text(
                                            text = buildString {
                                                val cc = liveServer?.country?.ifBlank { fav.country } ?: fav.country
                                                if (cc.isNotBlank()) append("${VpnStateManager.countryFlag(cc)} ")
                                                append(fav.displayName)
                                            },
                                            style = MaterialTheme.typography.titleSmall,
                                            fontWeight = FontWeight.Bold,
                                        )
                                        Text(
                                            text = "${fav.groupName} • ${fav.protocol.ifBlank { "VPN" }} • ${fav.maskedEndpoint}",
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        )
                                    }
                                }

                                Row {
                                    IconButton(onClick = { editingFav = fav }) {
                                        Icon(Icons.Default.Edit, contentDescription = tr("تعديل الاسم والمجموعة", "Edit name & group"))
                                    }
                                    IconButton(onClick = { onRemoveFavorite(fav.serverId) }) {
                                        Icon(
                                            Icons.Default.Delete,
                                            contentDescription = tr("إزالة من المفضلة", "Remove from favorites"),
                                            tint = MaterialTheme.colorScheme.error,
                                        )
                                    }
                                }
                            }

                            Spacer(Modifier.height(8.dp))

                            // Historical & live performance metrics
                            val histText = buildString {
                                append(
                                    if (isOnlineAvailable) tr("متاح في القائمة الحالية", "Available in current pool")
                                    else tr("غير متاح مؤقتًا في التحديث الحالي", "Temporarily absent from current pool")
                                )
                                if (tel != null && tel.attempts > 0) {
                                    append(tr(" • النجاح ${(tel.successRate * 100).toInt()}% (${tel.successes}/${tel.attempts})", " • Success ${(tel.successRate * 100).toInt()}% (${tel.successes}/${tel.attempts})"))
                                    if (tel.ewmaLatencyMs > 0.0) {
                                        append(tr(" • متوسط ${tel.ewmaLatencyMs.toInt()} ms", " • Avg ${tel.ewmaLatencyMs.toInt()} ms"))
                                    }
                                    if (tel.bestDownloadKbps > 0.0) {
                                        append(String.format(Locale.US, tr(" • أقصى سرعة %.1f KB/s", " • Peak %.1f KB/s"), tel.bestDownloadKbps))
                                    }
                                } else if ((liveServer?.latencyMs ?: 0L) > 0L) {
                                    append(tr(" • استجابة ${liveServer!!.latencyMs} ms", " • Ping ${liveServer!!.latencyMs} ms"))
                                }
                            }
                            Text(
                                text = histText,
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )

                            if (liveServer != null) {
                                Spacer(Modifier.height(10.dp))
                                Button(
                                    onClick = { onConnectFavorite(liveServer) },
                                    modifier = Modifier.fillMaxWidth(),
                                    enabled = !isCurrentlyConnected,
                                ) {
                                    Icon(Icons.Default.PlayArrow, contentDescription = null, modifier = Modifier.size(18.dp))
                                    Spacer(Modifier.width(6.dp))
                                    Text(if (isCurrentlyConnected) tr("متّصل حاليًا بهذا السيرفر", "Currently Connected") else tr("اتصال مباشر الآن", "Connect Now"))
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    editingFav?.let { target ->
        var customNameInput by remember(target.serverId) { mutableStateOf(target.customName) }
        var groupInput by remember(target.serverId) { mutableStateOf(target.groupName) }

        AlertDialog(
            onDismissRequest = { editingFav = null },
            title = { Text(tr("تخصيص السيرفر المفضّل", "Customize Favorite Server")) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    OutlinedTextField(
                        value = customNameInput,
                        onValueChange = { customNameInput = it },
                        label = { Text(tr("الاسم المخصّص (اختياري)", "Custom Name (optional)")) },
                        placeholder = { Text(target.defaultLabel) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    OutlinedTextField(
                        value = groupInput,
                        onValueChange = { groupInput = it },
                        label = { Text(tr("المجموعة (مثل: عام، العمل، الألعاب، البث)", "Group (e.g., General, Work, Gaming, Streaming)")) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Row(
                        modifier = Modifier.horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        val presets = listOf(
                            tr("عام", "General"),
                            tr("العمل", "Work"),
                            tr("الألعاب", "Gaming"),
                            tr("البث", "Streaming"),
                        )
                        presets.forEach { preset ->
                            FilterChip(
                                selected = groupInput == preset,
                                onClick = { groupInput = preset },
                                label = { Text(preset) },
                            )
                        }
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        onEditFavorite(target.serverId, customNameInput, groupInput)
                        editingFav = null
                    }
                ) {
                    Text(tr("حفظ", "Save"))
                }
            },
            dismissButton = {
                TextButton(onClick = { editingFav = null }) {
                    Text(tr("إلغاء", "Cancel"))
                }
            },
        )
    }
}
