package com.example.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

private val PaoDarkColorScheme =
  darkColorScheme(
    primary = EmeraldShield,
    onPrimary = ObsidianBg,
    primaryContainer = EmeraldDim,
    onPrimaryContainer = EmeraldShield,
    secondary = CyanPulse,
    onSecondary = ObsidianBg,
    secondaryContainer = CyanDim,
    onSecondaryContainer = CyanPulse,
    tertiary = AmberConnecting,
    background = ObsidianBg,
    onBackground = TextPrimary,
    surface = DeepNavySurface,
    onSurface = TextPrimary,
    surfaceVariant = ElevatedSlateCard,
    onSurfaceVariant = TextSecondary,
    outline = SlateOutline,
    error = CoralDisconnect,
    onError = ObsidianBg,
    errorContainer = CoralDim,
    onErrorContainer = CoralDisconnect,
  )

@Composable
fun PaoTunnelTheme(content: @Composable () -> Unit) {
  MaterialTheme(colorScheme = PaoDarkColorScheme, typography = Typography, content = content)
}
