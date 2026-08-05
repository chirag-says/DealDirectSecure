/**
 * The Home screen's browse shortcuts.
 *
 * Every entry here is a free-text `search` term, not a taxonomy id, and that is
 * a deliberate consequence of the data: `category` / `subcategory` /
 * `propertyType` are null or point at the wrong document on every live listing,
 * so an id-based tile returns an empty screen. The `search` regex runs over the
 * title, and titles are generated as
 * `<BHK> <propertyTypeName> for <Rent|Sale> in <locality>`, so the type name is
 * always present in the text. Full evidence in `features/search/filters.ts`.
 *
 * ---------------------------------------------------------------------------
 * EVERY TERM BELOW WAS PROBED AGAINST LIVE DATA ON 2026-08-03. A tile that
 * leads to "no results" is worse than no tile, because the user reads it as
 * "this app has no apartments" rather than "that shortcut is broken".
 *
 * Rejected, with their measured counts:
 *   "Commercial"  → 0. It is a `categoryName`, and the search regex does not
 *                   cover that column. Replaced by the concrete commercial
 *                   types below, which do appear in titles.
 *   "Studio"      → 0. No inventory.
 *
 * When inventory grows these counts move, and a term can go to zero if a
 * category empties out. Re-run the probe before adding a tile. The real fix is
 * a backfill of the taxonomy refs, after which these become id filters and stop
 * depending on title text at all.
 */

export interface BrowseShortcut {
  id: string;
  label: string;
  /** Free-text term sent as `search`. */
  term: string;
  /** Ionicons name. */
  icon: string;
}

/** Ordered by live inventory, most first, so the row leads with substance. */
export const BROWSE_SHORTCUTS: readonly BrowseShortcut[] = [
  { id: 'apartment', label: 'Apartment', term: 'Apartment', icon: 'business-outline' },
  { id: 'house', label: 'House', term: 'Independent House', icon: 'home-outline' },
  { id: 'villa', label: 'Villa', term: 'Villa', icon: 'bed-outline' },
  { id: 'office', label: 'Office', term: 'Office Space', icon: 'briefcase-outline' },
  { id: 'showroom', label: 'Showroom', term: 'Showroom', icon: 'storefront-outline' },
  { id: 'plot', label: 'Plot', term: 'Plot', icon: 'map-outline' },
];

/**
 * Popular searches.
 *
 * A curated list, not an aggregate: nothing in the backend records what people
 * search for, so there is no popularity signal to read. These are the terms
 * with the most live inventory, which is the closest honest proxy — a chip that
 * returns nothing is the failure being avoided here.
 *
 * Counts at the 2026-08-03 probe: 3 BHK 9, Mumbai 9, 2 BHK 7, Bengaluru 6,
 * Pune 3, Kolkata 3.
 *
 * This becomes real the day the backend logs search terms. Until then the list
 * is maintained by hand and should be re-probed whenever it is edited.
 */
export const POPULAR_SEARCHES: readonly string[] = [
  '3 BHK',
  'Mumbai',
  '2 BHK',
  'Bengaluru',
  'Pune',
  'Kolkata',
];
