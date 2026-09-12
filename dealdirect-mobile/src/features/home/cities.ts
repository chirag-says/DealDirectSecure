import type { ImageSourcePropType } from 'react-native';

/**
 * The "Explore by City" grid.
 *
 * ---------------------------------------------------------------------------
 * WHY THE COUNTS ARE COMPUTED RATHER THAN WRITTEN DOWN
 *
 * The screen this is ported from shipped these as literals: Mumbai "5000+",
 * Delhi "4500+", Bangalore "4000+". The live corpus is 36 listings, of which
 * Mumbai has 9 and Delhi has 1. A user taps the tile that says 5000+ and lands
 * on a list of nine, on the same screen, two seconds later. That is not
 * optimistic marketing, it is a claim the product refutes by itself, and it
 * costs more trust than the number was ever going to buy.
 *
 * So the tile shows what the API returns. When there are 5000 in Mumbai it will
 * say 5000 on its own.
 *
 * ---------------------------------------------------------------------------
 * WHY ALIASES EXIST
 *
 * `address.city` is free text and has never been normalised on write. The live
 * values include "Bangalore" (9) and "Bengaluru" (6) for one city, "Kolkata"
 * and "kolkata", "Howrah " with a trailing space, and "Ahamdabad" for
 * Ahmedabad. Counting raw strings would split Bangalore into two tiles of 9 and
 * 6 and show a misspelling as its own city.
 *
 * Matching client-side is what makes this fixable at all. The server's `city`
 * param is an exact case-sensitive equality match, so it cannot merge the
 * spellings; the `search` regex is case-insensitive but the input is escaped
 * server-side, so no alternation can be passed through either. Counting locally
 * over one fetched page is the only place the join can happen today.
 *
 * The real fix is normalising `address.city` on write, which is a backend
 * change and belongs to a different session. Until then this table absorbs it.
 *
 * ---------------------------------------------------------------------------
 * KNOWN CEILING
 *
 * Counting reads one page of up to `CITY_COUNT_PAGE_SIZE` listings. Below that
 * total the counts are exact, which covers today's 36 with a wide margin. Above
 * it they under-report, and the honest fix at that point is a backend
 * aggregation endpoint (`distinct` + `count` over `address.city`) rather than a
 * bigger page. `useCityCounts` reports when it has hit the ceiling so this
 * cannot go unnoticed.
 */

export interface City {
  id: string;
  label: string;
  /**
   * Every spelling seen in live data, lowercased. The FIRST entry is also the
   * term sent to the browse screen as free text, so it must be the spelling
   * with the widest match.
   *
   * Typed as a non-empty tuple rather than `string[]` so that first element is
   * statically guaranteed to exist. A city with an empty alias list would
   * otherwise compile and then send `undefined` as a search term at runtime.
   */
  aliases: readonly [string, ...string[]];
  /**
   * Where the city is, for detecting it from a coordinate (2026-09-06).
   *
   * The centre and a radius that covers the metropolitan area the tile means:
   * Mumbai's reaches Thane, Navi Mumbai and Panvel; Delhi's stops short of
   * Gurgaon and Noida, which have their own tiles. See `nearestCity`.
   */
  center: { latitude: number; longitude: number };
  radiusKm: number;
  /**
   * Optional since 2026-08-22.
   *
   * `CityGrid` builds its tiles from type alone and stops reading this — see
   * the note in that file. The artwork is kept for the twelve cities that have
   * it, in case a future screen wants it, but a new city is no longer blocked
   * on someone drawing a landmark for it.
   */
  image?: ImageSourcePropType;
}

/**
 * Artwork ported from the existing production app, which already had all
 * twelve. Filenames were lowercased on copy; the originals were inconsistently
 * cased ("Mumbai.png" beside "chennai.png"), which breaks on case-sensitive
 * filesystems and CI even though it works on Windows.
 */
export const CITIES: readonly City[] = [
  {
    id: 'mumbai',
    center: { latitude: 19.0760, longitude: 72.8777 },
    radiusKm: 50,
    label: 'Mumbai',
    aliases: ['mumbai', 'navi mumbai', 'panvel'],
    image: require('../../../assets/home/cities/mumbai.png'),
  },
  {
    id: 'delhi',
    center: { latitude: 28.6139, longitude: 77.2090 },
    radiusKm: 35,
    label: 'Delhi NCR',
    aliases: ['delhi', 'delhi ncr', 'new delhi'],
    image: require('../../../assets/home/cities/delhi.png'),
  },
  {
    id: 'bangalore',
    center: { latitude: 12.9716, longitude: 77.5946 },
    radiusKm: 45,
    label: 'Bangalore',
    aliases: ['bangalore', 'bengaluru'],
    image: require('../../../assets/home/cities/bangalore.png'),
  },
  {
    id: 'hyderabad',
    center: { latitude: 17.3850, longitude: 78.4867 },
    radiusKm: 45,
    label: 'Hyderabad',
    aliases: ['hyderabad', 'secunderabad'],
    image: require('../../../assets/home/cities/hyderabad.png'),
  },
  {
    id: 'pune',
    center: { latitude: 18.5204, longitude: 73.8567 },
    radiusKm: 40,
    label: 'Pune',
    aliases: ['pune', 'pimpri', 'pimpri-chinchwad'],
    image: require('../../../assets/home/cities/pune.png'),
  },
  {
    id: 'chennai',
    center: { latitude: 13.0827, longitude: 80.2707 },
    radiusKm: 45,
    label: 'Chennai',
    aliases: ['chennai', 'madras'],
    image: require('../../../assets/home/cities/chennai.png'),
  },
  {
    id: 'kolkata',
    center: { latitude: 22.5726, longitude: 88.3639 },
    radiusKm: 40,
    label: 'Kolkata',
    aliases: ['kolkata', 'calcutta', 'howrah'],
    image: require('../../../assets/home/cities/kolkata.png'),
  },
  {
    id: 'ahmedabad',
    center: { latitude: 23.0225, longitude: 72.5714 },
    radiusKm: 40,
    label: 'Ahmedabad',
    // "Ahamdabad" is a live misspelling, not a variant. Carried so the listing
    // is findable; the data itself should be corrected.
    aliases: ['ahmedabad', 'ahamdabad', 'amdavad'],
    image: require('../../../assets/home/cities/ahmedabad.png'),
  },
  {
    id: 'gurgaon',
    center: { latitude: 28.4595, longitude: 77.0266 },
    radiusKm: 20,
    label: 'Gurgaon',
    aliases: ['gurgaon', 'gurugram'],
    image: require('../../../assets/home/cities/gurgaon.png'),
  },
  {
    id: 'noida',
    center: { latitude: 28.5700, longitude: 77.3600 },
    radiusKm: 25,
    label: 'Noida',
    aliases: ['noida', 'greater noida'],
    image: require('../../../assets/home/cities/noida.png'),
  },
  {
    id: 'chandigarh',
    center: { latitude: 30.7333, longitude: 76.7794 },
    radiusKm: 25,
    label: 'Chandigarh',
    aliases: ['chandigarh', 'mohali', 'panchkula'],
    image: require('../../../assets/home/cities/chandigarh.png'),
  },
  {
    id: 'jaipur',
    center: { latitude: 26.9124, longitude: 75.7873 },
    radiusKm: 35,
    label: 'Jaipur',
    aliases: ['jaipur'],
    image: require('../../../assets/home/cities/jaipur.png'),
  },
  {
    /*
      Added 2026-08-22, and chosen from the data rather than from a list of big
      Indian cities.

      Tallying `address.city` across the live corpus against this table showed
      exactly one city holding inventory that had no tile: Ranchi. Every other
      unmatched spelling was a variant of a city already here. Adding a
      thirteenth metro with no listings behind it would have changed nothing on
      screen — the grid drops any city whose count is zero — so this is the one
      addition that actually produces a tile.
    */
    id: 'ranchi',
    center: { latitude: 23.3441, longitude: 85.3096 },
    radiusKm: 30,
    label: 'Ranchi',
    aliases: ['ranchi'],
  },
];

/**
 * Reduces a raw `address.city` to a comparable form.
 *
 * Lowercased, trimmed, internal runs of whitespace collapsed, and punctuation
 * dropped. All four of those are represented in live data.
 */
export function normalizeCityName(raw: string | undefined): string {
  if (!raw) return '';
  return raw
    .toLowerCase()
    .replace(/[.,]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Which tile a raw city string belongs to, or undefined if none. */
export function matchCity(raw: string | undefined): City | undefined {
  const normalized = normalizeCityName(raw);
  if (!normalized) return undefined;

  return CITIES.find((city) => city.aliases.includes(normalized));
}

/**
 * Like `matchCity`, but accepts a name that CONTAINS an alias as a word.
 *
 * For names from the device's geocoder, which are administrative rather than
 * colloquial: Android answers "Bengaluru Urban", "Mumbai Suburban", "South
 * West Delhi" and "Pune Division", none of which is a listing's `city` and so
 * none of which `matchCity` should learn. Word-bounded, so "Delhi" does not
 * match "New Delhi Road" by accident, and longest alias first so "greater
 * noida" wins over "noida" and "navi mumbai" over "mumbai".
 */
export function matchCityLoosely(raw: string | undefined): City | undefined {
  const exact = matchCity(raw);
  if (exact) return exact;

  const normalized = normalizeCityName(raw);
  if (!normalized) return undefined;

  const candidates = CITIES.flatMap((city) => city.aliases.map((alias) => ({ city, alias })));
  candidates.sort((a, b) => b.alias.length - a.alias.length);
  const hit = candidates.find(({ alias }) => new RegExp(`(^|\\s)${alias}(\\s|$)`).test(normalized));
  return hit?.city;
}

const EARTH_RADIUS_KM = 6371;

/** Great-circle distance, good to a fraction of a percent at these scales. */
function distanceKm(
  a: { latitude: number; longitude: number },
  b: { latitude: number; longitude: number }
): number {
  const toRad = (deg: number) => (deg * Math.PI) / 180;
  const dLat = toRad(b.latitude - a.latitude);
  const dLng = toRad(b.longitude - a.longitude);
  const h =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(a.latitude)) * Math.cos(toRad(b.latitude)) * Math.sin(dLng / 2) ** 2;
  return 2 * EARTH_RADIUS_KM * Math.asin(Math.sqrt(h));
}

/**
 * The tile a coordinate falls in, or undefined if it is in none.
 *
 * The primary way "use my location" resolves a city (2026-09-06). It used to
 * rely on the geocoder's name alone, which failed for most of the country:
 * the OS names the district, not the city, so a user standing in Koramangala
 * was told the app is "not in Bengaluru Urban yet". A coordinate against the
 * table's own centres cannot be misspelled, needs no network, and settles the
 * NCR by nearest centre, so Gurgaon is Gurgaon and not Delhi.
 */
export function nearestCity(point: { latitude: number; longitude: number }): City | undefined {
  let best: { city: City; score: number } | undefined;
  for (const city of CITIES) {
    // Distance as a fraction of the city's own radius, not raw kilometres:
    // where Delhi and Gurgaon overlap, a point in Dwarka is nearer Gurgaon's
    // centre in km but well inside Delhi's much larger area, and it is Delhi.
    const score = distanceKm(point, city.center) / city.radiusKm;
    if (score > 1) continue;
    if (!best || score < best.score) best = { city, score };
  }
  return best?.city;
}

/** The free-text term a tile sends to the browse screen. */
export function citySearchTerm(city: City): string {
  return city.aliases[0];
}
