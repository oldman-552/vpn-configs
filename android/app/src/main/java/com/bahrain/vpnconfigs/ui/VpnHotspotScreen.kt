// =====================================================================
// VpnHotspotScreen.kt — واجهة مشاركة اتصال الـ VPN عبر الهوتسبوت بدون روت
// (Rootless VPN Hotspot — العربية أساسية RTL + الإنجليزية LTR).
// =====================================================================
package com.bahrain.vpnconfigs.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Devices
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.SettingsInputAntenna
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.WifiTethering
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.bahrain.vpnconfigs.data.Prefs
import com.bahrain.vpnconfigs.hotspot.HotspotRunPhase
import com.bahrain.vpnconfigs.hotspot.HotspotSharingMode
import com.bahrain.vpnconfigs.hotspot.VpnHotspotManager
import com.bahrain.vpnconfigs.util.tr
import com.bahrain.vpnconfigs.vpn.VpnStateManager
import com.bahrain.vpnconfigs.vpn.VpnStatus

@Composable
fun VpnHotspotScreen(
    vpnStatus: VpnStatus,
    onBack: () -> Unit,
    onCopy: (String, String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val ctx = LocalContext.current
    val prefs = remember { Prefs(ctx) }
    val hsState by VpnHotspotManager.state.collectAsState()

    var portText by remember { mutableStateOf(prefs.hotspotProxyPort.toString()) }
    var requireAuth by remember { mutableStateOf(prefs.hotspotRequireAuth) }
    var authUser by remember { mutableStateOf(prefs.hotspotUsername) }
    var authPass by remember { mutableStateOf(prefs.hotspotPassword) }

    LaunchedEffect(vpnStatus.phase) {
        VpnHotspotManager.refreshIdleCompatibilitySnapshot(ctx)
    }

    val modeColor = when (hsState.compatibilityMode) {
        HotspotSharingMode.MODE_A_FULL_VPN_HOTSPOT -> VpnConnectedGreen
        HotspotSharingMode.MODE_B_PROXY_SHARING -> MaterialTheme.colorScheme.primary
        HotspotSharingMode.MODE_C_UNSUPPORTED -> VpnConnectingAmber
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        // ── الشريط العلوي ──
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                IconButton(onClick = onBack) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = tr("رجوع", "Back"))
                }
                Icon(
                    Icons.Filled.WifiTethering,
                    contentDescription = null,
                    tint = if (hsState.isSharingActive) VpnConnectedGreen else MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(26.dp),
                )
                Spacer(Modifier.width(8.dp))
                Column {
                    Text(
                        tr("نقطة اتصال الـ VPN (بدون روت)", "VPN Hotspot (Rootless)"),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.ExtraBold,
                    )
                    Text(
                        tr("مشاركة آمنة للهواتف والحواسيب مع حماية منع التسرب", "Fail-closed LAN VPN sharing for phones & laptops"),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.secondary,
                    )
                }
            }
            IconButton(onClick = { VpnHotspotManager.refreshIdleCompatibilitySnapshot(ctx) }) {
                Icon(Icons.Filled.Refresh, contentDescription = tr("تحديث حالة الشبكة", "Refresh"))
            }
        }

        // ── رسائل الخطأ الصادقة إن وُجدت ──
        hsState.displayError?.let { err ->
            Surface(
                color = MaterialTheme.colorScheme.errorContainer,
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    text = err,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(12.dp),
                )
            }
        }

        // ── البطاقة الرئيسية: حالة التوافق + زر التشغيل والإيقاف ──
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Surface(
                    color = modeColor.copy(alpha = 0.14f),
                    shape = RoundedCornerShape(8.dp),
                ) {
                    Text(
                        text = hsState.compatibilityMode.displayTitle,
                        color = modeColor,
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                    )
                }

                Text(
                    text = hsState.displayHeadline,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    text = hsState.displayDetail,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.secondary,
                )

                HorizontalDivider()

                // مؤشرات الحالة الحية (VPN + Hotspot + السيرفر النشط)
                HotspotInfoRow(
                    label = tr("حالة نفق الـ VPN", "VPN Tunnel Status"),
                    value = if (vpnStatus.isTunnelVerified) {
                        tr("● متّصل وموثّق (${vpnStatus.activeLabel})", "● Verified (${vpnStatus.activeLabel})")
                    } else {
                        tr("○ غير متّصل (يلزم الاتصال أولًا)", "○ Disconnected (Connect VPN first)")
                    },
                    valueColor = if (vpnStatus.isTunnelVerified) VpnConnectedGreen else VpnDangerRed,
                )
                HotspotInfoRow(
                    label = tr("واجهة الشبكة المكتشفة", "Detected Local Interface"),
                    value = hsState.interfaceInfo?.let {
                        "${it.displayTransport} • ${it.ipv4Address}"
                    } ?: tr("لا توجد نقطة اتصال نشطة", "No active hotspot interface"),
                    valueColor = if (hsState.interfaceInfo != null) VpnConnectedGreen else VpnConnectingAmber,
                )
                HotspotInfoRow(
                    label = tr("حماية منع التسرّب (DNS / IPv6)", "Leak & Fail-Closed Guard"),
                    value = hsState.displayIpv6Policy,
                    valueColor = MaterialTheme.colorScheme.primary,
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    if (!hsState.isSharingActive) {
                        Button(
                            onClick = {
                                prefs.hotspotProxyPort = portText.toIntOrNull() ?: 20880
                                prefs.hotspotRequireAuth = requireAuth
                                prefs.hotspotUsername = authUser
                                prefs.hotspotPassword = authPass
                                VpnHotspotManager.startHotspotSharing(ctx)
                            },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.buttonColors(containerColor = VpnConnectedGreen),
                        ) {
                            Icon(Icons.Filled.PowerSettingsNew, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(6.dp))
                            Text(
                                tr("تشغيل مشاركة VPN", "START VPN HOTSPOT"),
                                fontWeight = FontWeight.Bold,
                            )
                        }
                    } else {
                        Button(
                            onClick = { VpnHotspotManager.stopHotspotSharing() },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.buttonColors(containerColor = VpnDangerRed),
                        ) {
                            Icon(Icons.Filled.PowerSettingsNew, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(6.dp))
                            Text(
                                tr("إيقاف مشاركة VPN", "STOP VPN HOTSPOT"),
                                fontWeight = FontWeight.Bold,
                            )
                        }
                    }

                    OutlinedButton(
                        onClick = { VpnHotspotManager.openSystemTetheringSettings(ctx) },
                        modifier = Modifier.weight(1f),
                    ) {
                        Icon(Icons.Filled.SettingsInputAntenna, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(4.dp))
                        Text(tr("إعدادات الهوتسبوت", "System Hotspot"))
                    }
                }
            }
        }

        // ── بطاقة بيانات الربط للأجهزة المتصلة (HTTP / SOCKS5 / PAC) ──
        if (hsState.bindAddress.isNotBlank()) {
            ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Text(
                        tr("بيانات الاتصال للأجهزة المرتبطة بالهوتسبوت", "Connection Endpoints for Tethered Devices"),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                    )
                    Text(
                        tr(
                            "مهم جدًا: بدون روت، أي جهاز يتصل بالواي فاي فقط يخرج بإنترنت عادي بدون VPN؛ لتمريره داخل الـ VPN ادخل إعدادات Wi‑Fi في الجهاز الثاني ← البروكسي: يدوي (Manual) وانسخ الخانتين التاليتين كل واحدة على حدة:",
                            "Important: Without root, tethered Wi-Fi devices use normal internet unless Wi-Fi Proxy is configured. In the connected device's Wi-Fi settings -> Proxy: Manual, copy Host and Port separately below:",
                        ),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.secondary,
                    )

                    if (hsState.isSharingActive && hsState.localBridgeVerified) {
                        HotspotInfoRow(
                            label = tr("فحص جاهزية المنفذ المحلي", "Local Proxy Port Self-Test"),
                            value = tr("● جاهز ويستقبل الطلبات بنجاح", "● Verified & Ready"),
                            valueColor = VpnConnectedGreen,
                        )
                    }

                    CopyableEndpointRow(
                        label = tr("1) اسم مضيف البروكسي / الخادم فقط (Hostname / Server)", "1) Proxy Hostname / Server IP Only"),
                        value = hsState.bindAddress,
                        onCopy = {
                            onCopy(
                                hsState.bindAddress,
                                tr("تم نسخ عنوان الخادم فقط (${hsState.bindAddress})", "Copied Host IP (${hsState.bindAddress})"),
                            )
                        },
                    )
                    CopyableEndpointRow(
                        label = tr("2) منفذ البروكسي فقط (Proxy Port)", "2) Proxy Port Only"),
                        value = "${hsState.bindPort}",
                        onCopy = {
                            onCopy(
                                "${hsState.bindPort}",
                                tr("تم نسخ رقم المنفذ فقط (${hsState.bindPort})", "Copied Port (${hsState.bindPort})"),
                            )
                        },
                    )
                    if (hsState.pacUrl.isNotBlank()) {
                        CopyableEndpointRow(
                            label = tr("أو رابط الإعداد التلقائي (PAC URL)", "Or Auto Proxy Config (PAC URL)"),
                            value = hsState.pacUrl,
                            onCopy = {
                                onCopy(
                                    hsState.pacUrl,
                                    tr("تم نسخ رابط الإعداد التلقائي PAC", "Copied PAC auto-config URL"),
                                )
                            },
                        )
                    }
                    if (hsState.statusTestUrl.isNotBlank()) {
                        CopyableEndpointRow(
                            label = tr("رابط فحص الوصول من متصفح الجهاز الثاني", "Browser Reachability Test URL"),
                            value = hsState.statusTestUrl,
                            onCopy = {
                                onCopy(
                                    hsState.statusTestUrl,
                                    tr("تم نسخ رابط فحص الوصول المحلي", "Copied local test URL"),
                                )
                            },
                        )
                    }
                    if (hsState.secondaryEndpoints.isNotEmpty()) {
                        Text(
                            tr(
                                "عناوين شبكات محلية إضافية نشطة ومفعّلة أيضًا: ${hsState.secondaryEndpoints.joinToString(" ، ")}",
                                "Additional active LAN listeners also bound: ${hsState.secondaryEndpoints.joinToString(", ")}",
                            ),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.primary,
                        )
                    }
                }
            }
        }

        // ── بطاقة الأجهزة المتصلة وحجم استهلاك البيانات الحي ──
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Filled.Devices, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                        Spacer(Modifier.width(8.dp))
                        Text(
                            tr(
                                "الأجهزة المتصلة وحركة البيانات (${hsState.connectedClients.size})",
                                "Connected Clients & Traffic (${hsState.connectedClients.size})",
                            ),
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold,
                        )
                    }
                    Text(
                        "↓ ${VpnStateManager.formatSpeed(hsState.liveDownBps)}  ↑ ${VpnStateManager.formatSpeed(hsState.liveUpBps)}",
                        style = MaterialTheme.typography.labelMedium,
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                    )
                }

                HotspotInfoRow(
                    label = tr("إجمالي البيانات الممرّرة عبر النفق", "Total Shared VPN Data"),
                    value = "↓ ${VpnStateManager.formatBytes(hsState.totalBytesDown)}  •  ↑ ${VpnStateManager.formatBytes(hsState.totalBytesUp)}",
                )
                if (hsState.failClosedBlockedCount > 0L) {
                    HotspotInfoRow(
                        label = tr("محاولات محجوبة أثناء انقطاع النفق (منع تسرب)", "Fail-Closed Blocked Attempts"),
                        value = "${hsState.failClosedBlockedCount}",
                        valueColor = VpnConnectingAmber,
                    )
                }

                if (hsState.connectedClients.isEmpty()) {
                    Text(
                        tr(
                            "لا توجد جلسات أجهزة نشطة حاليًا — ستظهر الأجهزة فور اتصالها وإعداد البروكسي في إعدادات Wi‑Fi للجهاز المتصل.",
                            "No active client sessions yet — connected devices appear here once connected and configured.",
                        ),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.secondary,
                    )
                } else {
                    HorizontalDivider()
                    hsState.connectedClients.forEach { cl ->
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Column(modifier = Modifier.weight(1f).padding(end = 8.dp)) {
                                Text(
                                    cl.clientIp,
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.SemiBold,
                                )
                                Text(
                                    if (cl.source == "PROXY_SESSION") {
                                        tr("✅ يمر عبر الـ VPN (${cl.activeStreams} قناة مشفّرة نشطة)", "✅ Routing via VPN (${cl.activeStreams} active stream(s))")
                                    } else {
                                        tr(
                                            "⚠️ متّصل بالواي فاي بدون VPN بعد — أدخل الخادم ${hsState.bindAddress} والمنفذ ${hsState.bindPort} في إعدادات بروكسي Wi‑Fi لهذا الجهاز",
                                            "⚠️ Connected without VPN — set Manual Proxy ${hsState.bindAddress} port ${hsState.bindPort} in this device's Wi-Fi settings",
                                        )
                                    },
                                    style = MaterialTheme.typography.labelSmall,
                                    color = if (cl.source == "PROXY_SESSION") VpnConnectedGreen else VpnConnectingAmber,
                                )
                            }
                            Text(
                                "↓ ${VpnStateManager.formatBytes(cl.bytesDown)} • ↑ ${VpnStateManager.formatBytes(cl.bytesUp)}",
                                fontFamily = FontFamily.Monospace,
                                style = MaterialTheme.typography.labelSmall,
                            )
                        }
                    }
                }
            }
        }

        // ── إعدادات الأمان والمصادقة الاختيارية للمنفذ المحلي ──
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Filled.Lock, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                    Spacer(Modifier.width(8.dp))
                    Text(
                        tr("إعدادات المنفذ والمصادقة المحلية", "Port & Optional Proxy Authentication"),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                    )
                }

                OutlinedTextField(
                    value = portText,
                    onValueChange = { portText = it.filter(Char::isDigit).take(5) },
                    label = { Text(tr("منفذ المشاركة المحلي (10240–65000)", "Local Sharing Port (10240–65000)")) },
                    singleLine = true,
                    enabled = !hsState.isSharingActive,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth(),
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f).padding(end = 8.dp)) {
                        Text(
                            tr("طلب اسم مستخدم وكلمة مرور للأجهزة المتصلة", "Require Proxy Username & Password"),
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Medium,
                        )
                        Text(
                            tr(
                                "يحمي البروكسي المحلي بكلمة مرور إضافية داخل شبكة الهوتسبوت (HTTP Basic + SOCKS5 Auth)",
                                "Adds HTTP Basic & SOCKS5 RFC-1929 authentication on the LAN listener",
                            ),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.secondary,
                        )
                    }
                    Switch(
                        checked = requireAuth,
                        enabled = !hsState.isSharingActive,
                        onCheckedChange = {
                            requireAuth = it
                            prefs.hotspotRequireAuth = it
                        },
                    )
                }

                if (requireAuth) {
                    OutlinedTextField(
                        value = authUser,
                        onValueChange = {
                            authUser = it.trim()
                            prefs.hotspotUsername = authUser
                        },
                        label = { Text(tr("اسم المستخدم للبروكسي", "Proxy Username")) },
                        singleLine = true,
                        enabled = !hsState.isSharingActive,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    OutlinedTextField(
                        value = authPass,
                        onValueChange = {
                            authPass = it.trim()
                            prefs.hotspotPassword = authPass
                        },
                        label = { Text(tr("كلمة المرور (6 خانات على الأقل)", "Proxy Password (min 6 chars)")) },
                        singleLine = true,
                        enabled = !hsState.isSharingActive,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            }
        }

        // ── دليل الربط السريع الصادق لجميع الأنظمة ──
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Filled.Shield, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                    Spacer(Modifier.width(8.dp))
                    Text(
                        tr("طريقة ربط الأجهزة الأخرى في 3 خطوات (بدون روت)", "3-Step Setup on Connected Devices (No Root)"),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                    )
                }
                Text(
                    tr(
                        "1️⃣ شغّل اتصال الـ VPN في هذا الهاتف، ثم شغّل «نقطة اتصال Wi‑Fi» من إعدادات هاتفك واضغط «تشغيل مشاركة VPN» أعلاه.\n" +
                            "2️⃣ وصّل الجهاز الآخر بشبكة الـ Wi‑Fi الخاصة بهاتفك (ملاحظة: بدون الخطوة 3 سيتصل الجهاز بإنترنت عادي بدون VPN).\n" +
                            "3️⃣ في إعدادات الـ Wi‑Fi للجهاز المتصل، اضغط الترس ⚙️ أو (i) بجانب الشبكة ← اختر «البروكسي: يدوي (Manual)» وضع «اسم المضيف» في الخانة الأولى و«المنفذ» في الخانة الثانية منفصلَين (أو اختر تلقائي PAC والصق رابط PAC) ثم احفظ وأعِد تشغيل Wi‑Fi في الجهاز الثاني.",
                        "1️⃣ Connect VPN on this phone, turn on your system Wi-Fi Hotspot, and tap START VPN HOTSPOT above.\n" +
                            "2️⃣ Connect your second device to this phone's Wi-Fi hotspot (without step 3, Android routes hotspot traffic directly without VPN).\n" +
                            "3️⃣ In the connected device's Wi-Fi settings, choose Proxy -> Manual and paste Hostname and Port in their separate fields (or choose Auto PAC and paste the PAC URL), save, and toggle Wi-Fi off/on once.",
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
            }
        }
    }
}

@Composable
private fun HotspotInfoRow(
    label: String,
    value: String,
    valueColor: Color = MaterialTheme.colorScheme.onSurface,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.secondary,
            modifier = Modifier.weight(0.45f),
        )
        Text(
            value,
            style = MaterialTheme.typography.bodySmall,
            color = valueColor,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.weight(0.55f),
        )
    }
}

@Composable
private fun CopyableEndpointRow(
    label: String,
    value: String,
    onCopy: () -> Unit,
) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f),
        shape = RoundedCornerShape(10.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.secondary)
                Text(
                    value,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            IconButton(onClick = onCopy) {
                Icon(Icons.Filled.ContentCopy, contentDescription = tr("نسخ", "Copy"))
            }
        }
    }
}
