import { useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';

import { qk } from '@/api';
import { fetchPropertyPage, type PropertySummary } from '@/features/properties';

/**
 * Most-viewed listings.
 *
 * ---------------------------------------------------------------------------
 * WHY THE SORT HAPPENS HERE AND NOT ON THE SERVER
 *
 * `views` is the one behavioural signal this system records: `GET
 * /properties/:id` increments it, so it counts detail-screen opens across the
 * website and the app together. It is real data with a real spread — the live
 * corpus runs from 166 views down to 5, so a ranking on it is meaningful rather
 * than noise.
 *
 * What does not exist is a way to ask for it. `/properties/search` accepts
 * `sort` values of `newest`, `priceAsc` and `priceDesc`, and nothing else. So
 * the ordering is done on rows already fetched.
 *
 * ---------------------------------------------------------------------------
 * THE CEILING, AND WHY THE LABEL DEPENDS ON IT
 *
 * One page of up to `PAGE_SIZE` newest listings is fetched and sorted. While
 * the whole corpus fits in that page the ranking is exactly "most viewed" —
 * true today, at 36 listings against a page of 100.
 *
 * Past that point it silently becomes "most viewed among the newest 100",
 * which is a different claim, and an older listing with 900 views would be
 * missing from a row promising the most popular. `isComplete` reports which
 * regime we are in so the caller can title the row honestly rather than
 * asserting something it stopped being able to support.
 *
 * The real fix is `sort=views` on the search endpoint. It is a one-line
 * addition to the controller's sort map and it makes this whole file collapse
 * into an ordinary query.
 */

const PAGE_SIZE = 100;

/** Fifteen minutes. A view counter does not move fast enough to matter sooner. */
const STALE_MS = 15 * 60_000;

export interface PopularListingsResult {
  items: PropertySummary[];
  isLoading: boolean;
  /**
   * True while the fetched page covers the entire corpus, meaning the ranking
   * is genuinely "most viewed" rather than "most viewed among the newest N".
   */
  isComplete: boolean;
}

export function usePopularListings(limit = 10): PopularListingsResult {
  const params = useMemo(() => ({ limit: PAGE_SIZE, sort: 'newest' as const }), []);

  const query = useQuery({
    queryKey: qk.collection('popular', params),
    queryFn: ({ signal }) => fetchPropertyPage(params, signal),
    staleTime: STALE_MS,
    retry: 1,
  });

  const items = useMemo(() => {
    const rows = query.data?.items ?? [];

    // Copied before sorting: the array belongs to the query cache, and sorting
    // in place would mutate cached data that other consumers read as
    // newest-first.
    return [...rows]
      .sort((a, b) => {
        if (b.views !== a.views) return b.views - a.views;
        // Ties are common at the low end, where most listings sit at single
        // digits. Breaking by recency keeps the order stable between renders
        // and puts the fresher of two equally-ignored listings first.
        return (b.createdAt ?? '').localeCompare(a.createdAt ?? '');
      })
      .slice(0, limit);
  }, [query.data, limit]);

  return {
    items,
    isLoading: query.isPending,
    isComplete: (query.data?.total ?? 0) <= (query.data?.items.length ?? 0),
  };
}
