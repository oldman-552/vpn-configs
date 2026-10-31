package com.bahrain.vpnconfigs.ui

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import com.bahrain.vpnconfigs.data.Prefs
import com.bahrain.vpnconfigs.util.tr

/**
 * One-time, plain-language notice that the server list is gathered from public channels run by
 * unknown operators. Shown on first launch until the user acknowledges it.
 */
@Composable
fun PublicServerNotice() {
    val ctx = LocalContext.current
    val prefs = remember { Prefs(ctx) }
    var visible by remember { mutableStateOf(!prefs.publicServerNoticeAcked) }
    if (!visible) return

    AlertDialog(
        onDismissRequest = {},
        title = { Text(tr("تنبيه مهم عن السيرفرات", "Important: about these servers")) },
        text = {
            Text(
                tr(
                    "السيرفرات في هذا التطبيق مجمّعة تلقائياً من قنوات ومصادر عامة، ويديرها أشخاص مجهولون.\n\n" +
                        "• صاحب السيرفر يستطيع رؤية المواقع التي تزورها وأي بيانات غير مشفّرة.\n" +
                        "• استخدم مواقع HTTPS فقط، ولا تدخل كلمات مرور حساسة أو بيانات بنكية عبرها.\n" +
                        "• هذا التطبيق لتجاوز الحجب، وليس لإخفاء هويتك.",
                    "Servers in this app are collected automatically from public channels and are run by unknown people.\n\n" +
                        "• The server operator can see which sites you visit and any unencrypted data.\n" +
                        "• Use HTTPS sites only, and avoid sensitive logins or banking over them.\n" +
                        "• This app helps bypass censorship; it does not make you anonymous.",
                ),
            )
        },
        confirmButton = {
            TextButton(onClick = {
                prefs.publicServerNoticeAcked = true
                visible = false
            }) { Text(tr("فهمت", "I understand")) }
        },
    )
}
