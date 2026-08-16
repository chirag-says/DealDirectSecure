import { DarkTheme, DefaultTheme } from '@react-navigation/native';

import { darkColors, lightColors, type ColorScheme, type ColorSchemeName } from './colors';

/**
 * React Navigation's theme, projected from our colour tokens.
 *
 * ---------------------------------------------------------------------------
 * THE LIGHT STRIP UNDER THE DOCK
 *
 * React Navigation paints its own background behind every navigator, from
 * `theme.colors.background`. Expo Router mounts its `NavigationContainer` with
 * `DefaultTheme` and never looks at the colour scheme, so that value was
 * `rgb(242, 242, 242)` — a light grey — for the entire life of the app in
 * either scheme.
 *
 * Nothing showed it while a screen covered it, because `ui/Screen` paints
 * `bg-background` over the whole scene. But the tab bar is a SIBLING of the
 * scene, not a child: `BottomTabView` lays the screen container and the tab bar
 * out in a column, and our dock is a floating pill with transparent gutters and
 * a transparent safe-area strip beneath it. Every transparent pixel around the
 * pill was showing React Navigation's light grey through a dark app. The pill's
 * own shadow darkened the 16pt gutters enough to hide it there, which is why it
 * only read as a band along the bottom edge.
 *
 * Binding the navigator's colours to the same tokens the rest of the app uses
 * fixes it everywhere at once rather than putting a background on the dock:
 * the native stack's scene background and the modal backdrop were reading the
 * same wrong value.
 *
 * ---------------------------------------------------------------------------
 * `@react-navigation/native` is imported directly and is not in package.json.
 * It arrives as a dependency of `expo-router`, which owns its version, and this
 * is the import Expo's own theming documentation uses. Declaring it separately
 * would let the two versions drift, which is worse than the undeclared import.
 */

/** `fonts` is carried over from the base theme: it is platform typography for
 *  navigation chrome we do not render, and duplicating it here would be four
 *  more values to keep in sync for no effect. */
const project = (base: typeof DefaultTheme, colors: ColorScheme): typeof DefaultTheme => ({
  ...base,
  colors: {
    primary: colors.accent,
    background: colors.background,
    card: colors.surface,
    text: colors.textPrimary,
    border: colors.border,
    notification: colors.brand,
  },
});

export const navigationThemes: Record<ColorSchemeName, typeof DefaultTheme> = {
  light: project(DefaultTheme, lightColors),
  dark: project(DarkTheme, darkColors),
};
