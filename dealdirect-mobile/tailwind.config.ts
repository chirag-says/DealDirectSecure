import type { Config } from 'tailwindcss';
// eslint-disable-next-line @typescript-eslint/no-var-requires
const nativewindPreset = require('nativewind/preset');

import { spacing, radius } from './src/theme/layout';
import { typography } from './src/theme/typography';

/**
 * NativeWind theme, projected from the token modules in src/theme.
 *
 * This config is TypeScript rather than JavaScript so the scale can be imported
 * from the same modules the runtime uses. A value therefore cannot drift
 * between a Tailwind class and a StyleSheet value. Tailwind resolves `.ts`
 * config files natively.
 *
 * Semantic colors are exposed as CSS variables and bound per scheme at runtime,
 * which keeps light/dark a single swap rather than a `dark:` prefix on every
 * element.
 */

/**
 * The token modules store raw numbers because React Native's StyleSheet takes
 * unitless values. Tailwind needs unit-bearing strings, so the conversion
 * happens here, at the boundary, rather than duplicating the scale in two
 * different formats.
 */
const toPx = <T extends Record<string, number>>(scale: T): Record<keyof T, string> =>
  Object.fromEntries(Object.entries(scale).map(([key, value]) => [key, `${value}px`])) as Record<
    keyof T,
    string
  >;

type FontSizeEntry = [
  fontSize: string,
  configuration: { lineHeight: string; letterSpacing: string; fontWeight: string },
];

const fontSize: Record<string, FontSizeEntry> = Object.fromEntries(
  Object.entries(typography).map(([name, token]): [string, FontSizeEntry] => [
    name,
    [
      `${token.fontSize}px`,
      {
        lineHeight: `${token.lineHeight}px`,
        letterSpacing: `${token.letterSpacing}px`,
        fontWeight: token.fontWeight,
      },
    ],
  ])
);

const semanticColor = (name: string) => `rgb(var(--color-${name}) / <alpha-value>)`;

export default {
  content: ['./app/**/*.{js,jsx,ts,tsx}', './src/**/*.{js,jsx,ts,tsx}'],
  presets: [nativewindPreset],
  /**
   * Class-driven rather than media-driven, so the in-app scheme override in
   * ThemeProvider can win over the OS setting. NativeWind's `colorScheme` API
   * toggles the `.dark` class that global.css binds against.
   */
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        background: semanticColor('background'),
        surface: semanticColor('surface'),
        'surface-muted': semanticColor('surface-muted'),
        border: semanticColor('border'),
        'border-strong': semanticColor('border-strong'),
        'text-primary': semanticColor('text-primary'),
        'text-secondary': semanticColor('text-secondary'),
        'text-muted': semanticColor('text-muted'),
        'text-on-accent': semanticColor('text-on-accent'),
        accent: semanticColor('accent'),
        'accent-pressed': semanticColor('accent-pressed'),
        'accent-muted': semanticColor('accent-muted'),
        brand: semanticColor('brand'),
        success: semanticColor('success'),
        'success-muted': semanticColor('success-muted'),
        warning: semanticColor('warning'),
        'warning-muted': semanticColor('warning-muted'),
        danger: semanticColor('danger'),
        'danger-muted': semanticColor('danger-muted'),
      },
      spacing: toPx(spacing),
      borderRadius: toPx(radius),
      fontSize,
    },
  },
  plugins: [],
} satisfies Config;
