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
 * The screen's horizontal margin. Every screen, every header, every list, every
 * skeleton.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS A TOKEN AND NOT A HABIT
 *
 * It was a habit, and the habit disagreed with itself. Headers were written
 * `px-lg` (20) while their content containers used `padding: 16`, so on nearly
 * every screen in the app the title's left edge sat 4pt outside the content
 * beneath it — visible as a subtle wrongness nobody could name. Worse, several
 * screens padded their LOADING skeleton at 20 and their loaded list at 16, so
 * the content jumped sideways the moment data arrived.
 *
 * 16, matching the compact-width margin. Anything that touches the screen edge
 * reads this; nothing hard-codes a horizontal page margin again.
 */
export const screenPadding = spacing.base;

/**
 * Bottom padding for scroll content, so the last row clears the tab bar or a
 * sticky action bar instead of ending flush against it. Screens with a MEASURED
 * bottom bar (property detail) use the measurement instead — this is the
 * default for screens without one.
 */
export const scrollBottomPadding = spacing['4xl'];

/**
 * How much room a scroll view on a TAB screen must leave at the bottom so its
 * last row clears the floating dock.
 *
 * The dock detaches from the screen edge (see `ui/TabBar.tsx`), so content
 * scrolls UNDERNEATH it rather than stopping above a solid bar. That is the
 * effect we want and the cost is that nothing can rely on the scroll view's
 * own bounds any more — a list ending at `scrollBottomPadding` would put its
 * final card behind the pill.
 *
 * 58 (dock) + 16 (its bottom margin) + 24 (breathing room). The safe-area
 * inset is NOT included: the scroll view already sits inside it.
 */
export const tabBarClearance = 98;

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
