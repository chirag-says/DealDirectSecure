import { useWindowDimensions } from 'react-native';

import { useTheme } from '@/theme';

/**
 * The hero's own palette and scale (2026-09-05 redesign, measured pass).
 *
 * THE SCALE. Every dimension at the top of Home is expressed in pixels of the
 * reference mockup, which is 738 px wide, and multiplied by `u`, the ratio of
 * the device width to that. So the layout is a proportional replica on any
 * phone: a chip that is 68 px tall on the reference is 68·u tall here, a gap
 * of 22 px is 22·u. Nothing in the header, hero or search pill uses the
 * theme's spacing tokens, deliberately — the reference is the spec, and a
 * token that rounds 22 to 20 is a token that drifts from it.
 *
 * `mockPx` is the only conversion. Read it as "this many reference pixels".
 *
 * THE COLOURS are sampled from the reference. The top block is a photograph
 * at dusk, and since 2026-09-06 there are two of them: the dark scheme keeps
 * the near-black slab, the light scheme gets a warmer frame (a stone wall and
 * a wet terrace at the same hour) whose last rows are a mid warm grey. Each
 * image fades into its own slab colour at the bottom, so the block below the
 * photograph continues it with no edge. White copy reads on both: the light
 * image's wall sits around #686261, well over 4.5:1 against white. The block
 * ends in a curve against whatever page colour the scheme provides.
 */

/** Width of the reference mockup, in its own pixels. */
export const MOCK_WIDTH = 738;

/** Reference pixels → device points, for the current window width. */
export function useMockScale(): (px: number) => number {
  const { width } = useWindowDimensions();
  const u = width / MOCK_WIDTH;
  return (px: number) => px * u;
}

/**
 * The header's geometry in reference pixels, shared by the header (which
 * draws it) and the hero (which pads by it so the photograph runs under it).
 *
 *   status bar bottom → logo top    25 px
 *   logo top → logo bottom          72 px (the wordmark alone, no tagline)
 *   status bar bottom → headline top 204 px
 */
export const HEADER_TOP_PX = 25;
export const HEADER_ROW_PX = 72;
export const HERO_HEADLINE_TOP_PX = 204;

/** Reference left margin of the hero copy and the search pill. */
export const HERO_INSET_PX = 34;

/**
 * The search pill's geometry, shared by the hero (which draws it under the
 * chips), the field (which is the pill) and the header (which pins a copy).
 *
 *   chips bottom → pill top   31 px
 *   pill                      86 px tall
 *   pill bottom → slab bottom 34 px, then the curved edge
 *
 * The header's pinned row is the same 86 + 34, so when the hero's slab bottom
 * reaches the bar the bar's own bottom is at the same pixel, and the handover
 * is one curved edge replacing another in place (2026-09-06).
 */
export const HERO_SEARCH_GAP_PX = 31;
export const HERO_SEARCH_PILL_PX = 86;
export const HERO_BOTTOM_PX = 34;

/** Sampled from the dark slab; the dark page below is two points darker. */
export const HERO_BG = '#090C11';

/** The light scheme's slab: the light photograph's last rows, sampled. */
export const HERO_BG_LIGHT = '#716561';

const HERO_IMAGE = {
  dark: require('../../../assets/home/brand/hero-dusk.webp'),
  light: require('../../../assets/home/brand/hero-dusk-light.webp'),
} as const;

/**
 * The hero's photograph and slab colour for the active colour scheme. One
 * hook so the hero (which draws both) and the header (which fills with the
 * slab colour once scrolled) can never pick different ones.
 */
export function useHeroScheme(): { image: number; slab: string } {
  const { scheme } = useTheme();
  return scheme === 'light'
    ? { image: HERO_IMAGE.light, slab: HERO_BG_LIGHT }
    : { image: HERO_IMAGE.dark, slab: HERO_BG };
}

/** Dark "glass" pills on the photograph: Rent, Projects. */
export const HERO_GLASS = 'rgba(255, 255, 255, 0.14)';
export const HERO_GLASS_BORDER = 'rgba(255, 255, 255, 0.12)';

/**
 * Light glass in the header: the city chip and the bell sit on the sky and
 * read as pale grey with DARK text and glyphs. The avatar is solid white.
 */
export const HERO_HEADER_GLASS = 'rgba(255, 255, 255, 0.78)';
export const HERO_HEADER_INK = '#111827';

export const HERO_TEXT = '#FFFFFF';
export const HERO_TEXT_MUTED = '#C4C8D0';
export const HERO_TEXT_FAINT = '#9BA1AA';

/** The search submit circle, sampled. */
export const HERO_SEARCH_BLUE = '#0155D1';
export const HERO_SEARCH_INK = '#111827';
export const HERO_SEARCH_PLACEHOLDER = '#6B7280';
