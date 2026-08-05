import { useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';

import { qk } from '@/api';
import { fetchPropertyPage } from '@/features/properties';
import { CITIES, matchCity, type City } from './cities';

/**
 * Real listing counts per city, from one request.
 *
 * ---------------------------------------------------------------------------
 * WHY ONE REQUEST AND NOT TWELVE
 *
 * The direct way to count Mumbai is to search for it and read `total` off the
 * envelope. That is exact, and it scales, and it costs one request per tile.
 * Twelve tiles is twelve requests against a limiter that allows twenty per
 * minute across every user behind the same carrier NAT — the entire budget,
 * spent on a decorative grid, before the user has touched anything.
 *
 * So: one page, counted locally. It is also the only place the spelling
 * variants can be merged, since neither server-side filter can express
 * "Bangalore OR Bengaluru". See `cities.ts`.
 *
 * ---------------------------------------------------------------------------
 * THE CEILING, STATED HONESTLY
 *
 * Below `PAGE_SIZE` total listings the counts are exact. Above it they are
 * lower bounds, because the tail of the corpus was never fetched. `atCeiling`
 * says which regime we are in; the grid uses it to switch from "9" to "9+" so
 * the number is never actually wrong, only less precise.
 *
 * The real fix past that point is a backend aggregation, not a bigger page.
 */

/**
 * Generous relative to the 36 listings that exist, deliberately. The cost of a
 * page this size is one request either way; the cost of being under the true
 * total is a wrong number on the most tappable element of the screen.
 */
const PAGE_SIZE = 100;

/**
 * Fifteen minutes. City distribution moves at the speed of new listings being
 * approved, which is days, not seconds.
 */
const STALE_MS = 15 * 60_000;

export interface CityCount {
  city: City;
  count: number;
}

export interface CityCountsResult {
  /** Only cities with inventory, most first. A tile leading nowhere is worse
   *  than an absent tile. */
  cities: CityCount[];
  isLoading: boolean;
  /** True when the corpus may exceed one page, so counts are lower bounds. */
  atCeiling: boolean;
}

export function useCityCounts(): CityCountsResult {
  const params = useMemo(() => ({ limit: PAGE_SIZE, sort: 'newest' as const }), []);

  const query = useQuery({
    queryKey: qk.collection('city-counts', params),
    queryFn: ({ signal }) => fetchPropertyPage(params, signal),
    staleTime: STALE_MS,
    retry: 1,
  });

  const cities = useMemo(() => {
    const rows = query.data?.items ?? [];
    if (rows.length === 0) return [];

    const tally = new Map<string, number>();
    for (const row of rows) {
      const city = matchCity(row.city);
      if (!city) continue; // A city with no tile is simply not in this grid.
      tally.set(city.id, (tally.get(city.id) ?? 0) + 1);
    }

    return CITIES.map((city) => ({ city, count: tally.get(city.id) ?? 0 }))
      .filter((entry) => entry.count > 0)
      .sort((a, b) => b.count - a.count);
  }, [query.data]);

  return {
    cities,
    isLoading: query.isPending,
    // `total` is what the server matched; `items.length` is what we received.
    // Equal means the page held everything and the counts are complete.
    atCeiling: (query.data?.total ?? 0) > (query.data?.items.length ?? 0),
  };
}
