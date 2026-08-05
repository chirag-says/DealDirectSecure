/**
 * Typography tokens.
 *
 * Two rules drive this scale, both of which a single fixed `letterSpacing` or
 * `lineHeight` would get wrong:
 *
 *  1. Tracking is size-specific. Large text reads as too loose at neutral
 *     tracking, so display sizes take NEGATIVE tracking; small text needs a
 *     slight POSITIVE bump to stay legible.
 *  2. Leading tracks size inversely. Tight on large headings, looser on body.
 *
 * Hierarchy is built from weight + size + leading as a set, not from size
 * alone: weight adds presence without consuming more space, which matters on a
 * phone.
 *
 * `fontFamily` is deliberately unset so each platform resolves its own system
 * face (SF on iOS, Roboto on Android). Both ship optical sizing and legibility
 * tuning that a bundled webfont would discard. Override only with a reason.
 *
 * Sizes are in px and are multiplied by the OS text-size setting at render
 * time; layout spacing must scale with them rather than being pinned, so that a
 * user on a large accessibility size does not get a clipped layout.
 */

export interface TextStyleToken {
  fontSize: number;
  lineHeight: number;
  letterSpacing: number;
  fontWeight: '400' | '500' | '600' | '700';
}

export const typography = {
  /** Screen titles and hero numbers. Tight leading, negative tracking. */
  display: {
    fontSize: 34,
    lineHeight: 38,
    letterSpacing: -0.7,
    fontWeight: '700',
  },
  title1: {
    fontSize: 28,
    lineHeight: 33,
    letterSpacing: -0.5,
    fontWeight: '700',
  },
  title2: {
    fontSize: 22,
    lineHeight: 27,
    letterSpacing: -0.3,
    fontWeight: '600',
  },
  title3: {
    fontSize: 18,
    lineHeight: 23,
    letterSpacing: -0.2,
    fontWeight: '600',
  },
  /** Default reading size. Tracking sits at neutral. */
  body: {
    fontSize: 16,
    lineHeight: 24,
    letterSpacing: 0,
    fontWeight: '400',
  },
  bodyEmphasis: {
    fontSize: 16,
    lineHeight: 24,
    letterSpacing: 0,
    fontWeight: '600',
  },
  callout: {
    fontSize: 15,
    lineHeight: 22,
    letterSpacing: 0,
    fontWeight: '400',
  },
  subhead: {
    fontSize: 14,
    lineHeight: 20,
    letterSpacing: 0.1,
    fontWeight: '400',
  },
  /** Metadata, timestamps, helper text. Positive tracking for legibility. */
  footnote: {
    fontSize: 13,
    lineHeight: 18,
    letterSpacing: 0.2,
    fontWeight: '400',
  },
  caption: {
    fontSize: 12,
    lineHeight: 16,
    letterSpacing: 0.3,
    fontWeight: '400',
  },
  /** Badges and overline labels. Smallest size takes the most tracking. */
  overline: {
    fontSize: 11,
    lineHeight: 14,
    letterSpacing: 0.6,
    fontWeight: '600',
  },
} as const satisfies Record<string, TextStyleToken>;

export type TypographyToken = keyof typeof typography;
