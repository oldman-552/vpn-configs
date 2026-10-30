// =====================================================================
// PromoDialog.kt — نافذة الإعلان المنبثقة عند فتح التطبيق مع عدّاد إغلاق (✕).
// =====================================================================
package com.bahrain.vpnconfigs.ui

import android.content.Intent
import android.graphics.BitmapFactory
import android.net.Uri
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.bahrain.vpnconfigs.data.ResolvedPromoBanner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.io.File

private fun decodeBoundedBitmap(file: File, maxEdgePx: Int = 1440): ImageBitmap? {
    if (!file.exists() || file.length() <= 16L) return null
    return runCatching {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(file.absolutePath, bounds)
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null

        var sample = 1
        while (bounds.outWidth / sample > maxEdgePx || bounds.outHeight / sample > maxEdgePx) {
            sample *= 2
        }
        val opts = BitmapFactory.Options().apply {
            inSampleSize = sample
            inPreferredConfig = android.graphics.Bitmap.Config.ARGB_8888
        }
        BitmapFactory.decodeFile(file.absolutePath, opts)?.asImageBitmap()
    }.getOrNull()
}

@Composable
fun PromoPopupDialog(
    banner: ResolvedPromoBanner,
    onDismiss: () -> Unit,
    onLinkOpened: () -> Unit = {},
) {
    val ctx = LocalContext.current
    val initialDelay = banner.closeDelaySec.coerceIn(0, 15)
    var remainingSec by rememberSaveable(banner.id, banner.slotIndex) {
        mutableIntStateOf(initialDelay)
    }
    var bitmap by remember(banner.imageFile.absolutePath, banner.imageFile.lastModified()) {
        mutableStateOf<ImageBitmap?>(null)
    }
    var decodeFinished by remember(banner.imageFile.absolutePath, banner.imageFile.lastModified()) {
        mutableStateOf(false)
    }

    LaunchedEffect(banner.imageFile.absolutePath, banner.imageFile.lastModified()) {
        val loaded = withContext(Dispatchers.IO) { decodeBoundedBitmap(banner.imageFile) }
        bitmap = loaded
        decodeFinished = true
        if (loaded == null) {
            onDismiss()
        }
    }

    LaunchedEffect(banner.id, banner.slotIndex) {
        while (remainingSec > 0) {
            delay(1000L)
            remainingSec = (remainingSec - 1).coerceAtLeast(0)
        }
    }

    if (!decodeFinished || bitmap == null) return

    val canClose = remainingSec <= 0
    val openExternalLink: () -> Unit = {
        if (banner.link.startsWith("https://", ignoreCase = true)) {
            onLinkOpened()
            runCatching {
                val intent = Intent(Intent.ACTION_VIEW, Uri.parse(banner.link)).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                ctx.startActivity(intent)
            }
        }
    }

    Dialog(
        onDismissRequest = { if (canClose) onDismiss() },
        properties = DialogProperties(
            dismissOnBackPress = canClose,
            dismissOnClickOutside = false,
            usePlatformDefaultWidth = false,
        ),
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth(0.90f)
                .widthIn(max = 390.dp),
            contentAlignment = Alignment.Center,
        ) {
            Card(
                shape = RoundedCornerShape(22.dp),
                elevation = CardDefaults.cardElevation(defaultElevation = 12.dp),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                ),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .then(
                                if (banner.link.isNotBlank()) {
                                    Modifier.clickable(onClick = openExternalLink)
                                } else {
                                    Modifier
                                }
                            ),
                        contentAlignment = Alignment.TopEnd,
                    ) {
                        bitmap?.let { img ->
                            Image(
                                bitmap = img,
                                contentDescription = banner.title.ifBlank { "إعلان" },
                                contentScale = ContentScale.Fit,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .heightIn(min = 200.dp, max = 500.dp)
                                    .clip(
                                        if (banner.title.isBlank() && banner.link.isBlank()) {
                                            RoundedCornerShape(22.dp)
                                        } else {
                                            RoundedCornerShape(topStart = 22.dp, topEnd = 22.dp)
                                        }
                                    ),
                            )
                        }

                        // زر الإغلاق (✕) بعد انتهاء العدّاد (مثلاً 3 ثوانٍ)
                        Surface(
                            shape = CircleShape,
                            color = Color.Black.copy(alpha = 0.68f),
                            modifier = Modifier
                                .padding(12.dp)
                                .size(38.dp),
                        ) {
                            if (canClose) {
                                IconButton(
                                    onClick = onDismiss,
                                    modifier = Modifier.fillMaxSize(),
                                ) {
                                    Icon(
                                        imageVector = Icons.Filled.Close,
                                        contentDescription = "إغلاق الإعلان",
                                        tint = Color.White,
                                        modifier = Modifier.size(20.dp),
                                    )
                                }
                            } else {
                                Box(
                                    contentAlignment = Alignment.Center,
                                    modifier = Modifier.fillMaxSize(),
                                ) {
                                    val progress = if (initialDelay > 0) {
                                        remainingSec.toFloat() / initialDelay.toFloat()
                                    } else 0f
                                    CircularProgressIndicator(
                                        progress = { progress },
                                        color = VpnConnectedGreen,
                                        strokeWidth = 2.5.dp,
                                        modifier = Modifier.size(34.dp),
                                    )
                                    Text(
                                        text = "$remainingSec",
                                        color = Color.White,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 14.sp,
                                    )
                                }
                            }
                        }
                    }

                    if (banner.title.isNotBlank() || banner.link.isNotBlank()) {
                        Column(
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(MaterialTheme.colorScheme.surface)
                                .padding(horizontal = 16.dp, vertical = 12.dp),
                        ) {
                            if (banner.title.isNotBlank()) {
                                Text(
                                    text = banner.title,
                                    style = MaterialTheme.typography.titleMedium,
                                    fontWeight = FontWeight.Bold,
                                    textAlign = TextAlign.Center,
                                )
                            }
                            if (banner.link.isNotBlank()) {
                                Button(
                                    onClick = openExternalLink,
                                    modifier = Modifier.fillMaxWidth(),
                                    shape = RoundedCornerShape(12.dp),
                                ) {
                                    Text(banner.buttonText.ifBlank { "التفاصيل" })
                                }
                            } else {
                                Spacer(Modifier.height(2.dp))
                            }
                        }
                    }
                }
            }
        }
    }
}
