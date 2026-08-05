import { useQuery } from '@tanstack/react-query';
import { useCallback, useState } from 'react';

import { qk } from '@/api';
import { fetchSuggestions } from '@/features/properties';
import { useDebouncedValue } from '@/lib';
import type { PropertySuggestion } from '@/types/backend/property';
import {
  addRecentSearch,
  clearRecentSearches,
  readRecentSearches,
  removeRecentSearch,
} from './recent';

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
