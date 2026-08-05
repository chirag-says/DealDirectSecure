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
  image: ImageSourcePropType;
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
    label: 'Mumbai',
    aliases: ['mumbai', 'navi mumbai', 'panvel'],
    image: require('../../../assets/home/cities/mumbai.png'),
  },
  {
    id: 'delhi',
    label: 'Delhi NCR',
    aliases: ['delhi', 'delhi ncr', 'new delhi'],
    image: require('../../../assets/home/cities/delhi.png'),
  },
  {
    id: 'bangalore',
    label: 'Bangalore',
    aliases: ['bangalore', 'bengaluru'],
    image: require('../../../assets/home/cities/bangalore.png'),
  },
  {
    id: 'hyderabad',
    label: 'Hyderabad',
    aliases: ['hyderabad', 'secunderabad'],
    image: require('../../../assets/home/cities/hyderabad.png'),
  },
  {
    id: 'pune',
    label: 'Pune',
    aliases: ['pune', 'pimpri', 'pimpri-chinchwad'],
    image: require('../../../assets/home/cities/pune.png'),
  },
  {
    id: 'chennai',
    label: 'Chennai',
    aliases: ['chennai', 'madras'],
    image: require('../../../assets/home/cities/chennai.png'),
  },
  {
    id: 'kolkata',
    label: 'Kolkata',
    aliases: ['kolkata', 'calcutta', 'howrah'],
    image: require('../../../assets/home/cities/kolkata.png'),
  },
  {
    id: 'ahmedabad',
    label: 'Ahmedabad',
    // "Ahamdabad" is a live misspelling, not a variant. Carried so the listing
    // is findable; the data itself should be corrected.
    aliases: ['ahmedabad', 'ahamdabad', 'amdavad'],
    image: require('../../../assets/home/cities/ahmedabad.png'),
  },
  {
    id: 'gurgaon',
    label: 'Gurgaon',
    aliases: ['gurgaon', 'gurugram'],
    image: require('../../../assets/home/cities/gurgaon.png'),
  },
  {
    id: 'noida',
    label: 'Noida',
    aliases: ['noida', 'greater noida'],
    image: require('../../../assets/home/cities/noida.png'),
  },
  {
    id: 'chandigarh',
    label: 'Chandigarh',
    aliases: ['chandigarh', 'mohali', 'panchkula'],
    image: require('../../../assets/home/cities/chandigarh.png'),
  },
  {
    id: 'jaipur',
    label: 'Jaipur',
    aliases: ['jaipur'],
    image: require('../../../assets/home/cities/jaipur.png'),
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

/** The free-text term a tile sends to the browse screen. */
export function citySearchTerm(city: City): string {
  return city.aliases[0];
}
