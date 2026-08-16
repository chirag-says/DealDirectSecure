/**
 * Color tokens.
 *
 * Colors are declared as SEMANTIC ROLES, never consumed as raw hex at a call
 * site. Both schemes define the same role set, so light/dark is one swap rather
 * than a per-component branch.
 *
 * Palette origin: sampled from the production website's dominant Tailwind usage
 * so the two clients read as one product. Blue is the primary action color;
 * red is the brand mark color. `danger` is kept as a separate role from `brand`
 * even though the two currently resolve to neighbouring reds, because they
 * carry different meaning and will diverge if either is ever retuned.
 */

export const palette = {
  blue600: '#2563EB',
  blue700: '#1D4ED8',
  blue500: '#3B82F6',
  blue100: '#DBEAFE',
  blue950: '#172554',

  red600: '#DC2626',
  red700: '#B91C1C',
  red500: '#EF4444',
  red100: '#FEE2E2',

  green600: '#16A34A',
  green500: '#22C55E',
  green100: '#DCFCE7',

  amber600: '#D97706',
  amber500: '#F59E0B',
  amber100: '#FEF3C7',

  neutral0: '#FFFFFF',
  neutral50: '#FAFAFA',
  neutral100: '#F5F5F5',
  /**
   * The grouped-list page background. Cooler and a step deeper than
   * `neutral50`, which at 2% off white was too close to `surface` for a white
   * card to separate from it without a border — see `lightColors.background`.
   * The slight blue cast is deliberate: a pure grey page under white cards
   * reads as dirty, which is why iOS greys its grouped background toward blue
   * rather than toward black.
   */
  canvas: '#F1F2F6',
  neutral200: '#E5E5E5',
  neutral300: '#D4D4D4',
  neutral400: '#A3A3A3',
  neutral500: '#737373',
  neutral600: '#525252',
  neutral700: '#404040',
  neutral800: '#262626',
  neutral900: '#171717',
  neutral950: '#0A0A0A',
} as const;

export interface ColorScheme {
  /** Page background, furthest back. */
  background: string;
  /** Raised surface (cards, sheets). */
  surface: string;
  /** Recessed or secondary surface (inputs, muted rows). */
  surfaceMuted: string;
  /** Hairline separators. */
  border: string;
  /** Stronger separator, used where a border must read as structural. */
  borderStrong: string;

  textPrimary: string;
  textSecondary: string;
  textMuted: string;
  /** Text placed on top of `accent` / `brand` / `danger` fills. */
  textOnAccent: string;

  /** Primary action color. */
  accent: string;
  accentPressed: string;
  accentMuted: string;

  /** Brand mark color. Not an action color. */
  brand: string;
  /** Tinted brand fill, for a selected state that must not read as an alert. */
  brandMuted: string;

  success: string;
  successMuted: string;
  warning: string;
  warningMuted: string;
  danger: string;
  dangerMuted: string;

  /** Modal scrim. Pairs with a dimmed, pushed-back parent layer. */
  scrim: string;
  /**
   * Translucent chrome fill for nav bars, tab bars and sheet headers. Content
   * scrolls underneath rather than being clipped by an opaque strip.
   */
  chrome: string;
}

/**
 * Gradient scrims laid over photography so text can sit on it.
 *
 * These are NOT scheme-dependent. A photograph is the same brightness in either
 * scheme, so the scrim that makes white text legible over it is the same too.
 * Putting them in `ColorScheme` would imply a light/dark variant that must not
 * exist: a pale scrim in light mode would leave the caption unreadable against
 * a bright sky, which is the exact failure the scrim is there to prevent.
 *
 * Three stops rather than two. A straight linear fade from opaque black to
 * transparent reads as a grey haze across the middle of the image, because
 * perceived lightness is not linear in alpha. Holding near-zero for the first
 * half and accelerating through the bottom leaves the photograph clean where
 * there is no text and dark exactly where there is.
 */
export const scrim = {
  /** Text at the bottom of a card. The default. */
  bottom: {
    colors: ['rgba(0,0,0,0)', 'rgba(0,0,0,0.28)', 'rgba(0,0,0,0.78)'] as const,
    locations: [0, 0.55, 1] as const,
  },
  /** Full-bleed hero, where text sits low and a status bar sits high. */
  hero: {
    colors: ['rgba(0,0,0,0.42)', 'rgba(0,0,0,0.06)', 'rgba(0,0,0,0.82)'] as const,
    locations: [0, 0.42, 1] as const,
  },
  /** Small tiles whose label spans the whole surface. */
  tile: {
    colors: ['rgba(0,0,0,0.10)', 'rgba(0,0,0,0.58)'] as const,
    locations: [0, 1] as const,
  },
} as const;

export type ScrimName = keyof typeof scrim;

export const lightColors: ColorScheme = {
  /**
   * Off-white, NOT pure white, and this is the single most consequential value
   * in the file.
   *
   * It was `neutral0`, identical to `surface`. A white card on a white page is
   * invisible, so every card in the app had to carry a border to exist at all,
   * and a screen of bordered rectangles is what makes an interface read as an
   * admin panel rather than a product. Dropping the page one step down the ramp
   * lets a white surface separate by being brighter than its surroundings,
   * which is how a raised thing actually looks, and lets the borders go.
   *
   * Dark mode already worked this way (`neutral950` page, `neutral900` surface).
   * This makes light mode agree.
   *
   * DEEPENED 2026-08-13. `neutral50` was the right idea at the wrong strength:
   * at 2% off white the separation was theoretical, so cards still needed
   * their borders and the app still read as flat. `canvas` is far enough down
   * to carry a white surface on its own.
   */
  background: palette.canvas,
  surface: palette.neutral0,
  surfaceMuted: palette.neutral100,
  border: palette.neutral200,
  borderStrong: palette.neutral300,

  textPrimary: palette.neutral900,
  textSecondary: palette.neutral600,
  textMuted: palette.neutral500,
  textOnAccent: palette.neutral0,

  accent: palette.blue600,
  accentPressed: palette.blue700,
  accentMuted: palette.blue100,

  brand: palette.red600,
  brandMuted: palette.red100,

  success: palette.green600,
  successMuted: palette.green100,
  warning: palette.amber600,
  warningMuted: palette.amber100,
  danger: palette.red600,
  dangerMuted: palette.red100,

  scrim: 'rgba(10, 10, 10, 0.4)',
  chrome: 'rgba(255, 255, 255, 0.72)',
};

export const darkColors: ColorScheme = {
  background: palette.neutral950,
  surface: palette.neutral900,
  surfaceMuted: palette.neutral800,
  border: palette.neutral800,
  borderStrong: palette.neutral700,

  textPrimary: palette.neutral50,
  textSecondary: palette.neutral400,
  textMuted: palette.neutral500,
  textOnAccent: palette.neutral0,

  accent: palette.blue500,
  accentPressed: palette.blue600,
  accentMuted: palette.blue950,

  brand: palette.red500,
  brandMuted: '#3B0A0A',

  success: palette.green500,
  successMuted: '#052E16',
  warning: palette.amber500,
  warningMuted: '#451A03',
  danger: palette.red500,
  dangerMuted: '#450A0A',

  scrim: 'rgba(0, 0, 0, 0.6)',
  chrome: 'rgba(23, 23, 23, 0.72)',
};

/**
 * A token colour at partial alpha.
 *
 * For the one case a role cannot cover: a gradient that has to fade a colour
 * into its own transparent form. `'transparent'` is not that — it resolves to
 * transparent BLACK, so fading a pale surface into it runs through grey and
 * reads as a smudge rather than a fade.
 *
 * Takes the six-digit hex the palette is written in. Anything else is returned
 * untouched rather than mangled, because a caller passing an `rgba()` string
 * already has what this function produces.
 */
export function withAlpha(color: string, alpha: number): string {
  const match = /^#([0-9a-f]{6})$/i.exec(color);
  if (!match) return color;

  const value = parseInt(match[1] as string, 16);
  const r = (value >> 16) & 255;
  const g = (value >> 8) & 255;
  const b = value & 255;

  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

export const colorSchemes = {
  light: lightColors,
  dark: darkColors,
} as const;

export type ColorSchemeName = keyof typeof colorSchemes;
