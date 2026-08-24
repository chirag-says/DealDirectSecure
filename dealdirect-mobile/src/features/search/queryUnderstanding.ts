import { CITIES } from '@/features/home';
import { DEFAULT_FILTERS, type SearchFilters } from './filters';
import {
  isStructured,
  normalizeLocality,
  parseQuery,
  type ParseContext,
  type ParsedQuery,
} from './understanding';

/**
 * The bridge between the portable understanding module and this app.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS FILE IS NOT INSIDE `understanding/`
 *
 * Everything in that folder is plain TypeScript with no React Native
 * dependency, so it can be lifted to the website unchanged. This file imports
 * the app's city table and its `SearchFilters` shape, so it is the app's half
 * of the seam and it stays on this side of it.
 *
 * ---------------------------------------------------------------------------
 * THE PARSE ONLY EVER ADDS
 *
 * `applyUnderstanding` takes the filters the user has already set and returns
 * them with what the query stated layered on top. A control the user touched
 * always wins: someone who taps "Rent" and then types "3 bhk in Bandra" keeps
 * their rent filter, because the visible control is the one they can see and
 * correct. The parse fills gaps; it does not overwrite decisions.
 *
 * Residual text becomes the `query`, so anything the parser could not prove —
 * a builder name, an unfamiliar locality — still reaches the server's regex and
 * searches exactly as well as it does today. Understanding a query is only
 * allowed to add structure, never to discard the user's words.
 */

/**
 * Anything carrying a locality.
 *
 * Deliberately narrower than `PropertySummary`: this only ever reads one
 * field, and saying so lets the caller pass an accumulated vocabulary rather
 * than being forced to keep whole listings alive to name a place.
 */
export interface LocalityBearing {
  locality?: string;
}

/**
 * Localities the corpus is known to contain.
 *
 * Supplied by the caller from listings already in hand, because a locality that
 * is not in the data must NOT become a filter — see `understanding/location.ts`.
 * Passing an empty list simply means no locality is ever structured, which
 * degrades to today's behaviour rather than to a wrong one.
 */
export function buildParseContext(items: readonly LocalityBearing[]): ParseContext {
  const localities = new Set<string>();
  for (const item of items) {
    const value = normalizeLocality(item.locality ?? '');
    if (value.length >= 3) localities.add(value);
  }

  return {
    cities: CITIES.map((city) => ({
      id: city.id,
      label: city.label,
      aliases: city.aliases,
    })),
    localities: [...localities],
  };
}

export interface UnderstoodQuery {
  filters: SearchFilters;
  parsed: ParsedQuery;
  /** False when nothing was extracted and this is an ordinary text search. */
  structured: boolean;
}

/**
 * Turns a typed query into filters, on top of whatever is already set.
 *
 * `current` is the live filter state. Every assignment below is guarded on the
 * field being unset, which is what implements "the parse fills gaps, controls
 * win".
 */
export function applyUnderstanding(
  text: string,
  current: SearchFilters,
  context: ParseContext
): UnderstoodQuery {
  const parsed = parseQuery(text, context);
  const structured = isStructured(parsed);

  // Nothing recognised: behave exactly as before, with the raw text as query.
  if (!structured) {
    return {
      filters: { ...current, query: text.trim() },
      parsed,
      structured: false,
    };
  }

  const next: SearchFilters = { ...current };
  const { hard } = parsed;

  if (hard.transaction && !current.listingType) next.listingType = hard.transaction;

  /*
    `bhk` is compared against undefined, not truthiness.

    0 is a real value meaning 1 RK. `if (hard.bhk)` would drop every studio
    query on the floor, and it would do it silently.
  */
  if (hard.bhk !== undefined && !current.bhk) {
    // The app's buckets cap at "4 and up", so 5+ BHK maps onto the open bucket.
    next.bhk = String(Math.min(hard.bhk, 4));
  }

  if (
    (hard.minPrice !== undefined || hard.maxPrice !== undefined) &&
    !current.priceBand &&
    current.priceMin === undefined &&
    current.priceMax === undefined
  ) {
    if (hard.minPrice !== undefined) next.priceMin = hard.minPrice;
    if (hard.maxPrice !== undefined) next.priceMax = hard.maxPrice;
  }

  if (hard.city && !current.city) next.city = hard.city;
  if (hard.locality && !current.locality) next.locality = hard.locality;
  if (hard.propertyType && !current.propertyType) next.propertyType = hard.propertyType;

  /*
    Category is skipped when a property type was resolved.

    The type already implies it — "showroom" is commercial — and setting both
    is two filters where the user stated one, which makes the filter badge read
    "2" for a single word and gives the user two things to clear.
  */
  if (hard.category && !hard.propertyType && !current.categoryName) {
    next.categoryName = hard.category === 'residential' ? 'Residential' : 'Commercial';
  }

  if (hard.construction && !current.constructionStatus) {
    next.constructionStatus = hard.construction;
  }

  next.query = parsed.residual;

  return { filters: next, parsed, structured: true };
}

/**
 * Which constraints could be dropped to widen a search that found nothing.
 *
 * Ordered by what a user is most likely to be flexible about, and returned as
 * SUGGESTIONS rather than applied. Nothing here relaxes anything on its own:
 * silently widening a budget is the failure this whole feature exists to
 * avoid, because it shows the user results they explicitly excluded and lets
 * them believe those results matched.
 */
export interface Relaxation {
  /** The filter key to clear. */
  key: keyof SearchFilters;
  /** What to offer the user, e.g. "Search any budget". */
  label: string;
}

export function suggestRelaxations(filters: SearchFilters, parsed: ParsedQuery): Relaxation[] {
  const out: Relaxation[] = [];

  if (filters.priceMin !== undefined || filters.priceMax !== undefined || filters.priceBand) {
    out.push({ key: 'priceMax', label: 'Search any budget' });
  }
  if (filters.locality) {
    const city = parsed.hard.city;
    out.push({
      key: 'locality',
      label: city ? 'Search the whole city' : 'Search nearby areas too',
    });
  }
  if (filters.bhk) {
    out.push({ key: 'bhk', label: 'Show other sizes' });
  }
  if (filters.propertyType) {
    out.push({ key: 'propertyType', label: 'Show other property types' });
  }
  if (filters.constructionStatus) {
    out.push({ key: 'constructionStatus', label: 'Show any possession status' });
  }

  return out;
}

/** Clears one constraint. Explicit, user-initiated, one at a time. */
export function relax(filters: SearchFilters, key: keyof SearchFilters): SearchFilters {
  const next: SearchFilters = { ...filters };

  if (key === 'priceMax') {
    delete next.priceMax;
    delete next.priceMin;
    delete next.priceBand;
    return next;
  }

  delete next[key];
  return next;
}

/** A fresh filter set carrying only what the query said. */
export function filtersFromQuery(text: string, context: ParseContext): UnderstoodQuery {
  return applyUnderstanding(text, { ...DEFAULT_FILTERS }, context);
}
