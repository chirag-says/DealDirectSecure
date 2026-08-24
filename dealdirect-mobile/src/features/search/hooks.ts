import { useQuery } from '@tanstack/react-query';
import { useCallback, useMemo, useState } from 'react';

import { qk } from '@/api';
import {
  fetchPropertyPage,
  fetchSuggestions,
  usePropertyFeed,
  type PropertyFeed,
  type PropertySummary,
} from '@/features/properties';
import { useDebouncedValue } from '@/lib';
import type { PropertySuggestion } from '@/types/backend/property';
import {
  DEFAULT_FILTERS,
  hasClientOnlyFilters,
  matchesClientFilters,
  toSearchParams,
  type SearchFilters,
} from './filters';
import { applyUnderstanding, buildParseContext } from './queryUnderstanding';
import {
  addRecentSearch,
  clearRecentSearches,
  readRecentSearches,
  removeRecentSearch,
} from './recent';
import {
  RELATED_POOL_SIZE,
  RELATED_THRESHOLD,
  selectRelatedProperties,
  selectSimilarProperties,
} from './related';
import { canAddToCompare } from './compare';

/**
 * Autocomplete.
 *
 * Four defences, all of them required, because `/properties/suggestions` shares
 * the 20-per-minute search limiter with `/properties/search` itself. Exhausting
 * it while typing would break the very search the user is typing.
 *
 *  1. Debounce. 450ms, at the top of the plan's 400–500ms band.
 *  2. Two-character minimum. Below that the backend returns an empty array
 *     without querying, but the request is still counted, so it is not sent.
 *  3. Cache by exact term. TanStack dedupes in-flight requests for the same key
 *     as well, so a backspace onto a term already fetched costs nothing.
 *  4. Five-minute staleness. Suggestions are derived from approved listings and
 *     do not move quickly.
 */

const SUGGESTION_DEBOUNCE_MS = 450;
const MIN_SUGGESTION_LENGTH = 2;

export interface Suggestions {
  items: PropertySuggestion[];
  isLoading: boolean;
  /** The term the results correspond to, which lags the field while debouncing. */
  term: string;
}

export function useSuggestions(input: string): Suggestions {
  const debounced = useDebouncedValue(input.trim(), SUGGESTION_DEBOUNCE_MS);
  const enabled = debounced.length >= MIN_SUGGESTION_LENGTH;

  const query = useQuery({
    queryKey: qk.suggestions(debounced),
    queryFn: ({ signal }) => fetchSuggestions(debounced, signal),
    enabled,
    staleTime: 5 * 60_000,
  });

  return {
    items: enabled ? (query.data ?? []) : [],
    // Only "loading" while there is nothing cached to show; a refetch behind an
    // existing list must not flip the panel back to a spinner.
    isLoading: enabled && query.isPending,
    term: debounced,
  };
}

/** How many result rows the Home hero previews before offering "See all". */
const PREVIEW_SIZE = 6;

/** Matches `usePopularListings`' ceiling: the live corpus fits in one page. */
const CLIENT_FILTER_PAGE_SIZE = 100;

export interface SearchPreview {
  items: PropertySummary[];
  /** Total matches, so "See all N" can be honest before the full page loads. */
  total: number;
  isLoading: boolean;
  /** The term the results correspond to, which lags the field while debouncing. */
  term: string;
}

/**
 * A live preview of ACTUAL results, for the Home hero's search field.
 *
 * `useSuggestions` autocompletes place and project NAMES; this runs the real
 * search. It applies the SAME parse the Search tab does, so "1 bhk in mumbai"
 * resolves to a 1 BHK + Mumbai filter set and returns the listing that matches
 * rather than the empty name-match a natural-language query gets from the
 * suggestions endpoint. Bounded to a handful of rows — the hero's "See all"
 * hands the whole query to the Search tab, which owns pagination and filters.
 *
 * ---------------------------------------------------------------------------
 * IT MUST RUN THE CLIENT-SIDE FILTER PASS, AND THE FIRST VERSION DID NOT
 *
 * This shipped returning the whole corpus for "1 bhk in mumbai" — a Kolkata
 * showroom above a Pune 3 BHK. The cause is the interaction of two correct
 * things: the parse CONSUMES the recognised words (`next.query = residual`,
 * so `search` is empty), and `city`/`bhk`/`categoryName`/`furnishing`/
 * `constructionStatus` are client-only — `toSearchParams` drops them by
 * design, because the server's equivalents are unreliable. Parsed filters run
 * through `toSearchParams` alone therefore state NOTHING, and a criteria-less
 * search legitimately means "everything".
 *
 * So this mirrors `usePropertySearchFeed` exactly: when the parse produced any
 * client-only filter, it fetches the same bounded page under the same query key
 * and applies `matchesClientFilters` itself. Sharing the key is not incidental
 * — "See all" lands on the Search tab, which asks for that identical page, so
 * the results are already cached and the navigation costs no request at all.
 *
 * The parse context is empty here on purpose: city, BHK, price and type do not
 * need the corpus to resolve, and a locality NAME the context cannot place
 * degrades to a raw text match rather than to nothing — the same fallback the
 * Search tab runs before it has accumulated any localities of its own.
 *
 * Same rate discipline as `useSuggestions`, because it shares the same
 * 20-per-minute limiter: fed the query only while the field is focused,
 * debounced at 450ms behind a two-character floor, and cached by parsed params.
 */
export function useSearchPreview(input: string): SearchPreview {
  const debounced = useDebouncedValue(input.trim(), SUGGESTION_DEBOUNCE_MS);
  const enabled = debounced.length >= MIN_SUGGESTION_LENGTH;

  const filters = useMemo(
    () =>
      enabled
        ? applyUnderstanding(debounced, DEFAULT_FILTERS, buildParseContext([])).filters
        : null,
    [debounced, enabled]
  );

  const clientMode = filters !== null && hasClientOnlyFilters(filters);

  /*
    In client mode this is byte-for-byte the params and key
    `usePropertySearchFeed` builds, so the page the preview fetches IS the page
    the Search tab will want a moment later. Otherwise a small page is enough,
    because everything the query stated is expressible server-side.
  */
  const params = useMemo(
    () =>
      filters
        ? {
            ...toSearchParams(filters),
            limit: clientMode ? CLIENT_FILTER_PAGE_SIZE : PREVIEW_SIZE,
            page: 1,
          }
        : null,
    [filters, clientMode]
  );

  const query = useQuery({
    queryKey: clientMode
      ? qk.collection('search-filtered', params ?? {})
      : qk.collection('search-preview', params ?? {}),
    queryFn: ({ signal }) => fetchPropertyPage(params!, signal),
    enabled: enabled && params !== null,
    staleTime: 60_000,
  });

  const matched = useMemo(() => {
    const page = query.data?.items ?? [];
    if (!filters || !clientMode) return page;
    return page.filter((item) => matchesClientFilters(item, filters));
  }, [query.data, filters, clientMode]);

  return {
    items: enabled ? matched.slice(0, PREVIEW_SIZE) : [],
    // In client mode the honest total is what survived the filter within the
    // bounded page — the same number, and the same ceiling, the Search tab will
    // report. Taking the server's `total` here would promise results the filter
    // has already excluded.
    total: clientMode ? matched.length : (query.data?.total ?? 0),
    // Loading only while there is nothing cached to show, so a refetch behind an
    // existing preview does not flip it back to skeletons.
    isLoading: enabled && query.isPending,
    term: debounced,
  };
}

/**
 * Recent searches, as reactive state.
 *
 * MMKV is synchronous, so the initial read happens during the first render and
 * there is no loading state to design for. Every mutation returns the new list,
 * which is what gets stored back — the hook never re-reads to find out what it
 * just wrote.
 */
export function useRecentSearches() {
  const [items, setItems] = useState<string[]>(readRecentSearches);

  const add = useCallback((term: string) => setItems(addRecentSearch(term)), []);
  const remove = useCallback((term: string) => setItems(removeRecentSearch(term)), []);
  const clear = useCallback(() => {
    clearRecentSearches();
    setItems([]);
  }, []);

  return { items, add, remove, clear };
}

/**
 * The search results feed, filter-aware.
 *
 * Two modes, chosen by `hasClientOnlyFilters`, both built ONLY on
 * `/properties/search` — never `/property-list` or `/filter`:
 *
 *   - No city/category/furnishing/construction-status filter set: delegates
 *     straight to `usePropertyFeed`, unchanged, with real server-side infinite
 *     scroll exactly as before this file existed.
 *   - Any of those filters set: fetches one bounded page
 *     (`CLIENT_FILTER_PAGE_SIZE`) and filters it client-side via
 *     `matchesClientFilters`. No further pages are requested — see
 *     `filters.ts`'s TAXONOMY/CITY/FURNISHING/CONSTRUCTION STATUS block for
 *     why this is bounded rather than paginated, same ceiling
 *     `usePopularListings` already documents.
 *
 * Both branches are always evaluated (React's rules of hooks forbid calling
 * one conditionally); only one is ever `enabled`, so only one ever fetches.
 */
export function usePropertySearchFeed(
  filters: SearchFilters,
  options: { enabled?: boolean } = {}
): PropertyFeed {
  const enabled = options.enabled ?? true;
  const clientMode = hasClientOnlyFilters(filters);
  const params = useMemo(() => toSearchParams(filters), [filters]);

  const paginated = usePropertyFeed(params, { enabled: enabled && !clientMode });

  const bounded = useQuery({
    queryKey: qk.collection('search-filtered', { ...params, limit: CLIENT_FILTER_PAGE_SIZE }),
    queryFn: ({ signal }) =>
      fetchPropertyPage({ ...params, limit: CLIENT_FILTER_PAGE_SIZE, page: 1 }, signal),
    enabled: enabled && clientMode,
    staleTime: 2 * 60_000,
  });

  const boundedItems = useMemo(
    () => (bounded.data?.items ?? []).filter((item) => matchesClientFilters(item, filters)),
    [bounded.data, filters]
  );

  if (clientMode) {
    return {
      items: boundedItems,
      total: boundedItems.length,
      isInitialLoading: bounded.isPending,
      isRefreshing: bounded.isRefetching,
      isLoadingMore: false,
      hasMore: false,
      loadMore: () => {},
      refresh: () => void bounded.refetch(),
      error: bounded.error,
      retry: () => void bounded.refetch(),
    };
  }

  return paginated;
}

export interface RelatedPropertiesResult {
  items: PropertySummary[];
  isLoading: boolean;
}

/**
 * "Related properties" — see `related.ts` for the scoring and the honest
 * ceiling this pool is subject to.
 *
 * `enabled` is the caller's call, not this hook's: the screen knows whether
 * the current result count actually cleared `RELATED_THRESHOLD` and whether
 * there is any real criteria to score against, both of which live in state
 * this hook does not have visibility into.
 */
export function useRelatedProperties(
  filters: SearchFilters,
  excludeIds: readonly string[],
  enabled: boolean
): RelatedPropertiesResult {
  const query = useQuery({
    queryKey: qk.collection('related-pool', { limit: RELATED_POOL_SIZE, sort: 'newest' }),
    queryFn: ({ signal }) =>
      fetchPropertyPage({ limit: RELATED_POOL_SIZE, sort: 'newest' }, signal),
    enabled,
    staleTime: 5 * 60_000,
  });

  const excludeSet = useMemo(() => new Set(excludeIds), [excludeIds]);

  const items = useMemo(() => {
    if (!enabled || !query.data) return [];
    return selectRelatedProperties(query.data.items, filters, excludeSet);
  }, [enabled, query.data, filters, excludeSet]);

  return { items, isLoading: enabled && query.isPending };
}

/**
 * "Similar properties", for the property detail screen.
 *
 * Shares `useRelatedProperties`' pool query verbatim — same key, same bounded
 * page, same five-minute staleness — so a user who searches and then opens a
 * listing pays for one fetch, not two. Only the scoring differs; `related.ts`
 * explains why it has to.
 *
 * `subject` being undefined is the normal state while the detail screen is
 * still loading, and it disables the query rather than firing a request whose
 * result cannot be scored yet.
 */
export function useSimilarProperties(
  subject: PropertySummary | undefined
): RelatedPropertiesResult {
  const enabled = Boolean(subject);

  const query = useQuery({
    queryKey: qk.collection('related-pool', { limit: RELATED_POOL_SIZE, sort: 'newest' }),
    queryFn: ({ signal }) =>
      fetchPropertyPage({ limit: RELATED_POOL_SIZE, sort: 'newest' }, signal),
    enabled,
    staleTime: 5 * 60_000,
  });

  const items = useMemo(() => {
    if (!subject || !query.data) return [];
    return selectSimilarProperties(query.data.items, subject);
  }, [subject, query.data]);

  return { items, isLoading: enabled && query.isPending };
}

export { RELATED_THRESHOLD };

// --- Compare properties -----------------------------------------------

export interface CompareSelection {
  items: PropertySummary[];
  isSelected: (id: string) => boolean;
  /** False once `MAX_COMPARE` is reached AND the item isn't already selected,
   *  or once a second property type is already anchoring the selection. */
  canToggle: (property: PropertySummary) => boolean;
  toggle: (property: PropertySummary) => void;
  clear: () => void;
}

export function useCompareSelection(): CompareSelection {
  const [items, setItems] = useState<PropertySummary[]>([]);

  const isSelected = useCallback((id: string) => items.some((item) => item.id === id), [items]);

  const canToggle = useCallback(
    (property: PropertySummary) => canAddToCompare(items, property),
    [items]
  );

  const toggle = useCallback((property: PropertySummary) => {
    setItems((current) => {
      if (current.some((item) => item.id === property.id)) {
        return current.filter((item) => item.id !== property.id);
      }
      if (!canAddToCompare(current, property)) return current;
      return [...current, property];
    });
  }, []);

  const clear = useCallback(() => setItems([]), []);

  // Memoised for the same reason as `useSaveToggle`'s return: the results
  // screen builds its per-card compare props from this inside a `useCallback`,
  // and a fresh literal would rebuild `renderItem` on every render.
  return useMemo(
    () => ({ items, isSelected, canToggle, toggle, clear }),
    [items, isSelected, canToggle, toggle, clear]
  );
}
