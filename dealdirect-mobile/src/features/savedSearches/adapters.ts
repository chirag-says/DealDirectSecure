import { decodeHtmlEntities, formatShortDay } from '@/lib';
import type { SavedSearch } from '@/types/backend/savedSearch';
import { PRICE_BAND_LABELS, type SavedSearchPriceBand, type SavedSearchSummary } from './types';

/**
 * Undoes express-validator's `.escape()` on the stored name.
 *
 * `validateSavedSearchCreate` runs `body('name').escape()`, so a search named
 * `3BHK & Villa` is PERSISTED as `3BHK &amp; Villa`. The website renders into
 * HTML and so never notices; React Native renders text, and would print the
 * entity literally. See `decodeHtmlEntities` for why only five characters are
 * handled, deliberately — the same decoder chat message text uses.
 */
export function decodeSearchName(name: string): string {
  return decodeHtmlEntities(name);
}

function isPriceBand(value: string | undefined): value is SavedSearchPriceBand {
  return value === 'low' || value === 'mid' || value === 'high';
}

/**
 * "Mumbai · Under ₹50 Lakh · For rent", absent parts dropped.
 *
 * The free-text `search` term is included when present, because an existing
 * search may carry one and hiding it would make the row unexplainable — but it
 * is labelled as a term rather than presented as an active filter, since the
 * matcher never reads it.
 */
function describe(search: SavedSearch): string {
  const filters = search.filters ?? {};
  const parts: string[] = [];

  if (filters.city) parts.push(filters.city);
  if (isPriceBand(filters.priceRange)) parts.push(PRICE_BAND_LABELS[filters.priceRange]);

  if (filters.availableFor) {
    parts.push(filters.availableFor.toLowerCase() === 'rent' ? 'For rent' : 'For sale');
  }

  if (filters.search) parts.push(`“${filters.search}”`);

  return parts.join('  ·  ');
}

/**
 * Can this search ever fire?
 *
 * True only when it carries at least one filter the matcher actually reads.
 * A search saved with only a free-text term passes the backend's own "at least
 * one filter" check and is then permanently silent, so the row says so rather
 * than letting the user wait for alerts that cannot arrive.
 */
function isInert(search: SavedSearch): boolean {
  const filters = search.filters ?? {};
  return !filters.city && !isPriceBand(filters.priceRange) && !filters.availableFor;
}

export function adaptSavedSearch(search: SavedSearch): SavedSearchSummary {
  const filters = search.filters ?? {};

  // Defaulted rather than trusted: all three default true in the schema, and
  // rows created before a given field existed carry none of them.
  const notifyEmail = search.notifyEmail ?? true;
  const notifyInApp = search.notifyInApp ?? true;
  const notifyPush = search.notifyPush ?? true;

  return {
    id: search._id,
    name: decodeSearchName(search.name ?? ''),
    description: describe(search),
    city: filters.city || undefined,
    priceBand: isPriceBand(filters.priceRange) ? filters.priceRange : undefined,
    availableFor: filters.availableFor || undefined,
    isInert: isInert(search),
    notifyEmail,
    notifyInApp,
    notifyPush,
    matchCount: typeof search.matchCount === 'number' ? search.matchCount : 0,
    lastMatchAt: search.lastMatchAt ?? null,
    // Muting every channel is a legitimate thing to want: keep the search,
    // stop the noise. The row has to read as MUTED rather than as broken, so
    // the state is named here instead of being re-derived in three places.
    isMuted: !notifyEmail && !notifyInApp && !notifyPush,
    updatedAt: search.updatedAt,
  };
}

/**
 * "3 matches, last on 2 Sep".
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS WORTH A LINE ON THE ROW
 *
 * A saved search is a promise about the future, and until Phase 1 there was no
 * way to tell a search that is quietly working from one that has never matched
 * anything. Both looked identical, so a user with no alerts could not tell
 * whether the feature was broken or the market was. The count answers that in
 * four words.
 *
 * Returns null at zero matches rather than "0 matches": a search saved this
 * morning has not failed, and telling someone their brand-new search has found
 * nothing is a criticism of the market delivered as a criticism of them.
 * `isInert` already covers the search that genuinely cannot ever match.
 */
export function matchLine(search: SavedSearchSummary, now: Date = new Date()): string | null {
  if (search.matchCount <= 0) return null;

  const count = `${search.matchCount} ${search.matchCount === 1 ? 'match' : 'matches'}`;

  // Year only when it is not this one: "2 Sep" reads better for something that
  // happened weeks ago, and a stale search from last year needs the year
  // precisely because it is surprising.
  const when = formatShortDay(search.lastMatchAt, now);

  return when ? `${count}, last on ${when}` : count;
}
