/**
 * Spacing, radii and elevation tokens.
 *
 * The spacing scale is a 4pt grid. Values are named by step rather than by
 * intended use, so a component that needs "the next size up" has an obvious
 * answer instead of a new magic number.
 */

export const spacing = {
  none: 0,
  xs: 4,
  sm: 8,
  md: 12,
  base: 16,
  lg: 20,
  xl: 24,
  '2xl': 32,
  '3xl': 40,
  '4xl': 48,
  '5xl': 64,
} as const;

export const radius = {
  none: 0,
  sm: 6,
  md: 10,
  lg: 14,
  xl: 20,
  '2xl': 28,
  full: 9999,
} as const;

/**
 * Minimum touch target. Anything interactive that paints smaller than this must
 * make up the difference with hit slop rather than shrinking the target.
 */
export const touchTarget = {
  min: 44,
} as const;

/**
 * Elevation.
 *
 * Bigger surfaces read as thicker: a sheet takes a deeper shadow and a stronger
 * blur than a chip. Shadow values are expressed once here so that iOS and
 * Android stay visually matched despite using different underlying properties.
 */
export interface ElevationToken {
  /** iOS shadow radius, in px. */
  shadowRadius: number;
  shadowOpacity: number;
  shadowOffsetY: number;
  /** Android elevation. */
  elevation: number;
  /** Backdrop blur radius for translucent chrome at this depth. */
  blurRadius: number;
}

export const elevation = {
  flat: {
    shadowRadius: 0,
    shadowOpacity: 0,
    shadowOffsetY: 0,
    elevation: 0,
    blurRadius: 0,
  },
  card: {
    shadowRadius: 8,
    shadowOpacity: 0.06,
    shadowOffsetY: 2,
    elevation: 2,
    blurRadius: 0,
  },
  chrome: {
    shadowRadius: 12,
    shadowOpacity: 0.08,
    shadowOffsetY: 1,
    elevation: 4,
    blurRadius: 20,
  },
  sheet: {
    shadowRadius: 24,
    shadowOpacity: 0.16,
    shadowOffsetY: -4,
    elevation: 16,
    blurRadius: 30,
  },
} as const satisfies Record<string, ElevationToken>;

export type SpacingToken = keyof typeof spacing;
export type RadiusToken = keyof typeof radius;
export type ElevationName = keyof typeof elevation;
