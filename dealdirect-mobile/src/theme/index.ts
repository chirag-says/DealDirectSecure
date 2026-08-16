/**
 * Theme entry point: tokens (M0) plus the runtime provider and hooks (M1).
 */

export {
  ThemeProvider,
  useTheme,
  useThemePreference,
  type Theme,
  type ThemePreference,
} from './ThemeProvider';

export {
  palette,
  lightColors,
  darkColors,
  colorSchemes,
  scrim,
  withAlpha,
  type ColorScheme,
  type ColorSchemeName,
  type ScrimName,
} from './colors';

export { navigationThemes } from './navigationTheme';

export { typography, type TextStyleToken, type TypographyToken } from './typography';

export { dmSans, type DMSansWeight } from './fonts';

export {
  spring,
  timing,
  deceleration,
  gesture,
  reducedMotion,
  type SpringToken,
  type SpringName,
} from './motion';

export {
  spacing,
  radius,
  touchTarget,
  screenPadding,
  scrollBottomPadding,
  tabBarClearance,
  elevation,
  type SpacingToken,
  type RadiusToken,
  type ElevationToken,
  type ElevationName,
} from './layout';
