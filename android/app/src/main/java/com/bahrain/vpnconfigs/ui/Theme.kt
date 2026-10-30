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

val VpnConnectedGreen = Color(0xFF10B981)
val VpnConnectingAmber = Color(0xFFF59E0B)
val VpnWeakPurple = Color(0xFFA855F7)
val VpnDangerRed = Color(0xFFEF4444)
val VpnUntestedGray = Color(0xFF94A3B8)

private val Teal = Color(0xFF008F7A)
private val TealDark = Color(0xFF34D399)
private val Sand = Color(0xFFF3F6F5)
private val DeepNavy = Color(0xFF0B1218)

private val Light = lightColorScheme(
    primary = Teal,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFC6F6EC),
    onPrimaryContainer = Color(0xFF00211B),
    secondary = Color(0xFF3B5B54),
    background = Sand,
    surface = Color.White,
    surfaceVariant = Color(0xFFE3ECE9),
    error = Color(0xFFBA1A1A),
)

private val Dark = darkColorScheme(
    primary = TealDark,
    onPrimary = Color(0xFF003828),
    primaryContainer = Color(0xFF064E3B),
    onPrimaryContainer = Color(0xFFD1FAE5),
    secondary = Color(0xFFA7F3D0),
    background = DeepNavy,
    surface = Color(0xFF121C24),
    surfaceVariant = Color(0xFF1B2834),
    error = Color(0xFFFFB4AB),
)

private val AppTypography = Typography(
    headlineMedium = TextStyle(fontWeight = FontWeight.ExtraBold, fontSize = 26.sp),
    titleLarge = TextStyle(fontWeight = FontWeight.Bold, fontSize = 21.sp),
    titleMedium = TextStyle(fontWeight = FontWeight.SemiBold, fontSize = 16.sp),
    bodyLarge = TextStyle(fontSize = 15.sp),
    bodyMedium = TextStyle(fontSize = 13.5.sp),
    labelSmall = TextStyle(fontWeight = FontWeight.Medium, fontSize = 11.sp),
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
                w.navigationBarColor = scheme.surface.toArgb()
                WindowCompat.getInsetsController(w, view).isAppearanceLightStatusBars = !dark
            }
        }
    }
    MaterialTheme(colorScheme = scheme, typography = AppTypography, content = content)
}
