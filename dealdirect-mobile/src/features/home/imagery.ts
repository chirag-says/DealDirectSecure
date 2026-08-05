import type { ImageSourcePropType } from 'react-native';

/**
 * Local artwork for the editorial surfaces on Home.
 *
 * Everything here is currently `undefined`, and every component that reads it
 * renders a designed gradient fallback instead. That is not a stub: the
 * gradient version is finished work and ships as-is. Artwork upgrades it.
 *
 * ---------------------------------------------------------------------------
 * WHY THE PATHS ARE COMMENTED OUT RATHER THAN POINTING AT MISSING FILES
 *
 * Metro resolves `require()` at BUILD time, not at runtime. A `require` of a
 * file that does not exist is not a value of `undefined` — it is a bundler
 * error that fails the whole app, not just this screen. So the requires stay
 * commented until the file is actually on disk.
 *
 * ---------------------------------------------------------------------------
 * TO ADD ARTWORK
 *
 *   1. Drop the file in `assets/home/` using the exact filename below.
 *   2. Uncomment that one line.
 *
 * Nothing else changes. Every consumer already handles both cases.
 *
 * ---------------------------------------------------------------------------
 * WHAT EACH SLOT NEEDS
 *
 * Ratios are what the layout crops to; supplying a different ratio is fine,
 * `contentFit: cover` will centre-crop it, but the subject will move.
 *
 *   hero            4:3   1600x1200  Wide architectural exterior, soft even
 *                                    light. The lower third is covered by a
 *                                    dark scrim and carries white text, so it
 *                                    wants low detail and low contrast there.
 *                                    Avoid a strong horizon at the bottom.
 *
 *   intentRent      1:1    800x800   Interior. Warm, lived-in, someone's home
 *                                    rather than a showroom.
 *   intentBuy       1:1    800x800   Exterior, facade or keys changing hands.
 *
 *   Localities      3:2    600x400   A recognisable skyline or landmark, shot
 *                                    wide. These sit under a scrim with the
 *                                    city name over them, so mid-tones work
 *                                    better than a bright sky.
 *
 *   noPhoto         3:2    600x400   The placeholder for a listing with no
 *                                    image. Should NOT be photographic — it
 *                                    must read as "missing", not as a house.
 *                                    A flat neutral texture or line drawing.
 *
 * All of it should be genuinely licensed. Stock is fine; scraped competitor
 * photography is not, and on a property marketplace it is the kind of thing
 * that gets noticed.
 */

export interface HomeImagery {
  hero?: ImageSourcePropType;
  intentRent?: ImageSourcePropType;
  intentBuy?: ImageSourcePropType;
  noPhoto?: ImageSourcePropType;
}

export const homeImagery: HomeImagery = {
  // hero: require('../../../assets/home/hero.jpg'),
  // intentRent: require('../../../assets/home/intent-rent.jpg'),
  // intentBuy: require('../../../assets/home/intent-buy.jpg'),
  // noPhoto: require('../../../assets/home/no-photo.png'),
};

/**
 * Locality artwork, keyed by `Locality.id` from `collections.ts`.
 *
 * Separate from `homeImagery` because it is keyed rather than named, and
 * because these are the most likely slots to be filled in one at a time.
 * A locality with no image gets a tinted card with its initial, which is a
 * deliberate look rather than a hole.
 */
export const localityImagery: Record<string, ImageSourcePropType | undefined> = {
  // mumbai: require('../../../assets/home/locality-mumbai.jpg'),
  // bangalore: require('../../../assets/home/locality-bangalore.jpg'),
  // pune: require('../../../assets/home/locality-pune.jpg'),
  // kolkata: require('../../../assets/home/locality-kolkata.jpg'),
  // ahmedabad: require('../../../assets/home/locality-ahmedabad.jpg'),
  // delhi: require('../../../assets/home/locality-delhi.jpg'),
};
