import { decodeHtmlEntities } from '@/lib';
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

  return {
    id: search._id,
    name: decodeSearchName(search.name ?? ''),
    description: describe(search),
    city: filters.city || undefined,
    priceBand: isPriceBand(filters.priceRange) ? filters.priceRange : undefined,
    availableFor: filters.availableFor || undefined,
    isInert: isInert(search),
    // Defaulted rather than trusted: both default true in the schema, and rows
    // created before those fields existed have neither.
    notifyEmail: search.notifyEmail ?? true,
    notifyInApp: search.notifyInApp ?? true,
    updatedAt: search.updatedAt,
  };
}
