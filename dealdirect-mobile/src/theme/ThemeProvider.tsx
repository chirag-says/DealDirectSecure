import { colorScheme as nativewindColorScheme, useColorScheme } from 'nativewind';
import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';

import { PREF_KEYS, prefsStorage } from '@/storage';
import { colorSchemes, type ColorScheme, type ColorSchemeName } from './colors';
import { elevation, radius, spacing, touchTarget } from './layout';
import { spring, timing } from './motion';
import { typography } from './typography';

/**
 * Theme runtime.
 *
 * Two consumers, one source:
 *
 *  - `className` styling reads the CSS variables bound in global.css. Nothing
 *    there needs a `dark:` prefix, because both schemes bind the same roles.
 *  - `useTheme()` returns the same roles as plain values, for the places a
 *    class cannot reach: shadow colors, animated style values, and props on
 *    third-party components such as expo-image.
 *
 * The preference persists to MMKV, not SecureStore: it is a device setting with
 * no security value. It also survives logout, because a theme choice is not
 * account data and resetting it would read as a bug.
 */

export type ThemePreference = ColorSchemeName | 'system';

export interface Theme {
  scheme: ColorSchemeName;
  colors: ColorScheme;
  spacing: typeof spacing;
  radius: typeof radius;
  elevation: typeof elevation;
  typography: typeof typography;
  spring: typeof spring;
  timing: typeof timing;
  touchTarget: typeof touchTarget;
}

interface ThemeContextValue {
  theme: Theme;
  preference: ThemePreference;
  setPreference: (preference: ThemePreference) => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

const isThemePreference = (value: unknown): value is ThemePreference =>
  value === 'light' || value === 'dark' || value === 'system';

function readStoredPreference(): ThemePreference {
  const stored = prefsStorage.getString(PREF_KEYS.themePreference);
  return isThemePreference(stored) ? stored : 'system';
}

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  // NativeWind owns the resolved scheme so that class-based styling and the
  // token objects can never disagree.
  const { colorScheme, setColorScheme } = useColorScheme();
  const scheme: ColorSchemeName = colorScheme === 'dark' ? 'dark' : 'light';

  const [preference, setPreferenceState] = useState<ThemePreference>(readStoredPreference);

  // Applied in an effect rather than at module scope so NativeWind is
  // initialised before the stored choice is pushed into it.
  useEffect(() => {
    setColorScheme(preference);
  }, [preference, setColorScheme]);

  const setPreference = useCallback(
    (next: ThemePreference) => {
      prefsStorage.set(PREF_KEYS.themePreference, next);
      setPreferenceState(next);
      setColorScheme(next);
    },
    [setColorScheme]
  );

  const theme = useMemo<Theme>(
    () => ({
      scheme,
      colors: colorSchemes[scheme],
      spacing,
      radius,
      elevation,
      typography,
      spring,
      timing,
      touchTarget,
    }),
    [scheme]
  );

  const value = useMemo<ThemeContextValue>(
    () => ({ theme, preference, setPreference }),
    [theme, preference, setPreference]
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): Theme {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used inside ThemeProvider');
  }
  return context.theme;
}

export function useThemePreference() {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useThemePreference must be used inside ThemeProvider');
  }
  return { preference: context.preference, setPreference: context.setPreference };
}
