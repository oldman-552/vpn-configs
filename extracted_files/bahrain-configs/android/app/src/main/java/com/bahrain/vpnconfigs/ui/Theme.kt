package com.bahrain.vpnconfigs.ui

import android.app.Activity
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import androidx.core.view.WindowCompat

private val Teal = Color(0xFF00A38A)
private val TealDark = Color(0xFF7FE0CE)
private val Sand = Color(0xFFF6F4EE)
private val Ink = Color(0xFF141A18)

private val Light = lightColorScheme(
    primary = Teal,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFB8F1E5),
    onPrimaryContainer = Color(0xFF00201A),
    secondary = Color(0xFF4A635C),
    background = Sand,
    surface = Color.White,
    surfaceVariant = Color(0xFFE7EDEA),
    error = Color(0xFFBA1A1A),
)

private val Dark = darkColorScheme(
    primary = TealDark,
    onPrimary = Color(0xFF00382E),
    primaryContainer = Color(0xFF005145),
    onPrimaryContainer = Color(0xFFB8F1E5),
    secondary = Color(0xFFB1CCC4),
    background = Ink,
    surface = Color(0xFF1B2320),
    surfaceVariant = Color(0xFF2A3330),
    error = Color(0xFFFFB4AB),
)

private val AppTypography = Typography(
    titleLarge = TextStyle(fontWeight = FontWeight.Bold, fontSize = 22.sp),
    titleMedium = TextStyle(fontWeight = FontWeight.SemiBold, fontSize = 17.sp),
    bodyLarge = TextStyle(fontSize = 16.sp),
    bodyMedium = TextStyle(fontSize = 14.sp),
    labelSmall = TextStyle(fontSize = 11.sp),
)

@Composable
fun AppTheme(dark: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    val scheme = if (dark) Dark else Light
    val view = LocalView.current
    if (!view.isInEditMode) {
        val ctx = LocalContext.current
        SideEffect {
            (ctx as? Activity)?.window?.let { w ->
                w.statusBarColor = scheme.background.toArgb()
                w.navigationBarColor = scheme.background.toArgb()
                WindowCompat.getInsetsController(w, view).isAppearanceLightStatusBars = !dark
            }
        }
    }
    MaterialTheme(colorScheme = scheme, typography = AppTypography, content = content)
}
