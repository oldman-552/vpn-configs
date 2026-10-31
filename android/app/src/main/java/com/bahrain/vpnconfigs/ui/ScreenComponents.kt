package com.bahrain.vpnconfigs.ui

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.NetworkCheck
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.SkipNext
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.StarBorder
import androidx.compose.material.icons.filled.SwapHoriz
import androidx.compose.material.icons.filled.WifiTethering
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.bahrain.vpnconfigs.data.LocalPoolTier
import com.bahrain.vpnconfigs.engine.ServerSortMode
import com.bahrain.vpnconfigs.util.AppI18n
import com.bahrain.vpnconfigs.util.AppLang
import com.bahrain.vpnconfigs.util.UiMessages
import com.bahrain.vpnconfigs.util.tr
import com.bahrain.vpnconfigs.vpn.VpnPhase
import com.bahrain.vpnconfigs.vpn.VpnStateManager
import com.bahrain.vpnconfigs.vpn.VpnStatus
import kotlinx.coroutines.delay
import java.io.File

// ═══════════════════════════════════════════════════════════════════════════
//  مكوّنات مساعدة مشتركة
// ═══════════════════════════════════════════════════════════════════════════
@Composable
internal fun StatusPill(phase: VpnPhase) {
    val (bg, fg, label) = when (phase) {
        VpnPhase.CONNECTED -> Triple(VpnConnectedGreen.copy(alpha = 0.16f), VpnConnectedGreen, tr("● متّصل ومحمي", "● Connected"))
        VpnPhase.CONNECTION_DEGRADED -> Triple(VpnConnectingAmber.copy(alpha = 0.16f), VpnConnectingAmber, tr("● متّصل (تذبذب)", "● Degraded"))
        VpnPhase.CONNECTING -> Triple(VpnConnectingAmber.copy(alpha = 0.16f), VpnConnectingAmber, tr("● جارٍ الاتصال…", "● Connecting…"))
        VpnPhase.RECONNECTING -> Triple(VpnConnectingAmber.copy(alpha = 0.16f), VpnConnectingAmber, tr("● استعادة المسار…", "● Reconnecting…"))
        VpnPhase.SWITCHING_SERVER -> Triple(VpnConnectingAmber.copy(alpha = 0.16f), VpnConnectingAmber, tr("● جارٍ التبديل…", "● Switching…"))
        VpnPhase.PROTECTION_ACTIVE -> Triple(VpnConnectingAmber.copy(alpha = 0.18f), VpnConnectingAmber, tr("🛡 Kill Switch نشط", "🛡 Kill Switch"))
        VpnPhase.CONNECTION_FAILED -> Triple(VpnDangerRed.copy(alpha = 0.16f), VpnDangerRed, tr("● تعذّر الاتصال", "● Failed"))
        VpnPhase.DISCONNECTED -> Triple(
            MaterialTheme.colorScheme.surfaceVariant,
            MaterialTheme.colorScheme.secondary,
            tr("○ غير متّصل", "○ Disconnected"),
        )
    }
    Surface(color = bg, shape = RoundedCornerShape(50)) {
        Text(
            text = label,
            color = fg,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
        )
    }
}

@Composable
internal fun TelemetryCard(
    modifier: Modifier = Modifier,
    title: String,
    mainValue: String,
    subValue: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    accent: Color,
) {
    ElevatedCard(modifier = modifier) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Icon(icon, contentDescription = null, tint = accent, modifier = Modifier.size(16.dp))
                Text(title, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.secondary)
            }
            Text(
                text = mainValue,
                style = MaterialTheme.typography.titleLarge,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold,
            )
            Text(
                text = subValue,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.secondary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

@Composable
internal fun ProtoChip(proto: String) {
    Surface(
        color = MaterialTheme.colorScheme.primaryContainer,
        shape = RoundedCornerShape(6.dp),
    ) {
        Text(
            text = proto.uppercase(),
            color = MaterialTheme.colorScheme.onPrimaryContainer,
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(horizontal = 7.dp, vertical = 2.dp),
        )
    }
}

internal fun phoneSpeedColor(speedKbps: Double): Color = when {
    speedKbps >= 1024.0 -> VpnConnectedGreen
    speedKbps >= 250.0 -> VpnConnectingAmber
    else -> VpnWeakPurple
}

internal fun formatPhoneSpeedLabel(speedKbps: Double): String = when {
    speedKbps >= 1024.0 -> String.format(
        java.util.Locale.US,
        tr("سرعة الاختبار على جهازك: %.2f MB/s", "Tested speed on your device: %.2f MB/s"),
        speedKbps / 1024.0,
    )
    speedKbps >= 250.0 -> tr(
        "سرعة الاختبار على جهازك: ${speedKbps.toInt()} KB/s",
        "Tested speed on your device: ${speedKbps.toInt()} KB/s",
    )
    else -> tr(
        "سرعة الاختبار على جهازك: ${speedKbps.toInt()} KB/s (ضعيف)",
        "Tested speed on your device: ${speedKbps.toInt()} KB/s (Weak)",
    )
}

@Composable
internal fun LatencyBadge(
    ms: Long,
    locallyTested: Boolean = false,
    localFailed: Boolean = false,
) {
    val isDisconnected = localFailed || ms < 0L
    val isUntested = !isDisconnected && (!locallyTested || ms == 0L)
    val color = when {
        isDisconnected -> VpnDangerRed
        isUntested -> VpnUntestedGray
        ms <= 250L -> VpnConnectedGreen
        ms <= 500L -> VpnConnectingAmber
        else -> VpnWeakPurple
    }
    val label = when {
        isDisconnected -> tr("منقطع", "Offline")
        isUntested -> tr("لم يُفحص", "Untested")
        ms <= 500L -> "⚡ $ms ms"
        else -> tr("⚡ $ms ms • ضعيف", "⚡ $ms ms • Weak")
    }
    Surface(
        color = color.copy(alpha = 0.14f),
        shape = RoundedCornerShape(8.dp),
    ) {
        Text(
            text = label,
            color = color,
            fontFamily = FontFamily.Monospace,
            fontSize = 12.sp,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
        )
    }
}

@Composable
internal fun BannerCard(text: String, isError: Boolean) {
    Surface(
        color = if (isError) {
            MaterialTheme.colorScheme.errorContainer
        } else {
            MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.65f)
        },
        shape = RoundedCornerShape(10.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text(
            text = text,
            color = if (isError) MaterialTheme.colorScheme.onErrorContainer else MaterialTheme.colorScheme.onPrimaryContainer,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
        )
    }
}

@Composable
internal fun SettingToggleRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f).padding(end = 8.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Medium)
            Text(subtitle, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.secondary)
        }
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

@Composable
internal fun NumField(v: String, set: (String) -> Unit, label: String) {
    OutlinedTextField(
        value = v,
        onValueChange = { set(it.filter(Char::isDigit)) },
        label = { Text(label) },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
internal fun ExportFileRow(
    title: String,
    file: File?,
    onCopyFile: (File) -> Unit,
    onShareFile: (File) -> Unit,
) {
    val ready = file != null && file.exists() && file.length() > 0
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
            Text(
                if (ready) "${file!!.length() / 1024} KB" else tr("يُولّد بعد التحديث أو الفحص", "Generated after refresh or scan"),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.secondary,
            )
        }
        Row {
            IconButton(onClick = { file?.let(onCopyFile) }, enabled = ready) {
                Icon(Icons.Filled.ContentCopy, contentDescription = tr("نسخ", "Copy"))
            }
            IconButton(onClick = { file?.let(onShareFile) }, enabled = ready) {
                Icon(Icons.Filled.Share, contentDescription = tr("مشاركة", "Share"))
            }
        }
    }
}
