import { useWindowDimensions } from 'react-native';

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
 * at dusk and looks the same in both colour schemes; a light-mode hero would
 * mean a second photograph, and the reference is one image. The block ends
 * in a curve against whatever page colour the scheme provides.
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
 *   logo top → second tagline bottom 116 px
 *   status bar bottom → headline top 204 px
 */
export const HEADER_TOP_PX = 25;
export const HEADER_ROW_PX = 116;
export const HERO_HEADLINE_TOP_PX = 204;

/** Reference left margin of the hero copy and the search pill. */
export const HERO_INSET_PX = 34;

/** Sampled from the slab; the page below is two points darker. */
export const HERO_BG = '#090C11';

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
