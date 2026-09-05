/**
 * The hero's own palette (2026-09-05 redesign).
 *
 * The top of Home is a photograph at dusk with copy on its dark slab, and it
 * looks like that in BOTH colour schemes: a light-mode hero would mean a
 * second photograph, and the reference is one image. So these values are
 * fixed here rather than read from the theme, and the block ends in a curve
 * against whatever page colour the scheme provides.
 *
 * `HERO_BG` is sampled from the slab in the artwork, so the gradient that
 * settles the bottom of the block into it is invisible.
 */
export const HERO_BG = '#0B0D12';

/** Translucent "glass" pills on the photo: city chip, bell, Rent, Projects. */
export const HERO_GLASS = 'rgba(255, 255, 255, 0.10)';
export const HERO_GLASS_BORDER = 'rgba(255, 255, 255, 0.16)';

export const HERO_TEXT = '#FFFFFF';
export const HERO_TEXT_MUTED = 'rgba(255, 255, 255, 0.72)';
export const HERO_TEXT_FAINT = 'rgba(255, 255, 255, 0.52)';

/** The search submit button. Deeper than the theme accent so it holds on white. */
export const HERO_SEARCH_BLUE = '#1F5EEA';
