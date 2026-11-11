package r5gk.boot.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable

private val LightScheme = lightColorScheme(
    primary = EmberPrimary,
    onPrimary = EmberOnPrimary,
    primaryContainer = EmberPrimaryContainer,
    onPrimaryContainer = EmberOnPrimaryContainer,
    secondary = EmberSecondary,
    onSecondary = EmberOnSecondary,
    secondaryContainer = EmberSecondaryContainer,
    onSecondaryContainer = EmberOnSecondaryContainer,
    tertiary = EmberTertiary,
    onTertiary = EmberOnTertiary,
    tertiaryContainer = EmberTertiaryContainer,
    onTertiaryContainer = EmberOnTertiaryContainer,
    error = EmberError,
    onError = EmberOnError,
    errorContainer = EmberErrorContainer,
    onErrorContainer = EmberOnErrorContainer,
    background = EmberBackground,
    onBackground = EmberOnBackground,
    surface = EmberSurface,
    onSurface = EmberOnSurface,
    surfaceVariant = EmberSurfaceVariant,
    onSurfaceVariant = EmberOnSurfaceVariant,
    outline = EmberOutline,
    outlineVariant = EmberOutlineVariant,
    surfaceContainerLowest = EmberSurfaceContainerLowest,
    surfaceContainerLow = EmberSurfaceContainerLow,
    surfaceContainer = EmberSurfaceContainer,
    surfaceContainerHigh = EmberSurfaceContainerHigh,
    surfaceContainerHighest = EmberSurfaceContainerHighest,
)

private val DarkScheme = darkColorScheme(
    primary = EmberPrimaryDark,
    onPrimary = EmberOnPrimaryDark,
    primaryContainer = EmberPrimaryContainerDark,
    onPrimaryContainer = EmberOnPrimaryContainerDark,
    secondary = EmberSecondaryDark,
    onSecondary = EmberOnSecondaryDark,
    secondaryContainer = EmberSecondaryContainerDark,
    onSecondaryContainer = EmberOnSecondaryContainerDark,
    tertiary = EmberTertiaryDark,
    onTertiary = EmberOnTertiaryDark,
    tertiaryContainer = EmberTertiaryContainerDark,
    onTertiaryContainer = EmberOnTertiaryContainerDark,
    error = EmberErrorDark,
    onError = EmberOnErrorDark,
    errorContainer = EmberErrorContainerDark,
    onErrorContainer = EmberOnErrorContainerDark,
    background = EmberBackgroundDark,
    onBackground = EmberOnBackgroundDark,
    surface = EmberSurfaceDark,
    onSurface = EmberOnSurfaceDark,
    surfaceVariant = EmberSurfaceVariantDark,
    onSurfaceVariant = EmberOnSurfaceVariantDark,
    outline = EmberOutlineDark,
    outlineVariant = EmberOutlineVariantDark,
    surfaceContainerLowest = EmberSurfaceContainerLowestDark,
    surfaceContainerLow = EmberSurfaceContainerLowDark,
    surfaceContainer = EmberSurfaceContainerDark,
    surfaceContainerHigh = EmberSurfaceContainerHighDark,
    surfaceContainerHighest = EmberSurfaceContainerHighestDark,
)

/**
 * The palette is fixed rather than dynamic: this is a one-purpose tool and it
 * should look the same on every device, not inherit the wallpaper accent.
 */
@Composable
fun KagerouTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkScheme else LightScheme,
        typography = KagerouTypography,
        content = content,
    )
}
