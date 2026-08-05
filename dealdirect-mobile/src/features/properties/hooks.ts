import { useInfiniteQuery, useQuery, type UseInfiniteQueryResult } from '@tanstack/react-query';
import { useEffect, useMemo, useRef } from 'react';

import { ApiError, qk } from '@/api';
import type { ObjectId } from '@/types/backend/common';
import type { PropertySearchParams } from '@/types/backend/property';
import { fetchPropertyDetail, fetchPropertyPage, type PropertyPage } from './api';
import { recordView } from './recentlyViewed';
import type { PropertyDetail, PropertySummary } from './types';

/**
 * Infinite property feed.
 *
 * Paging is driven by `pages` from the envelope rather than by "did the last
 * page come back short". Both work, but `pages` is authoritative and stops one
 * request earlier at the end of the list, which matters against a 20-per-minute
 * shared limiter.
 *
 * Offset paging against a collection sorted by `createdAt` desc drifts: a
 * listing approved mid-scroll shifts every subsequent page by one and the user
 * sees a duplicate. The cursor variant that would fix it does not exist on this
 * backend and adding one is a separate change request, so the client dedupes by
 * `_id` on flatten instead. That hides the duplicate; it cannot recover the row
 * the shift pushed past the boundary.
 */

export interface PropertyFeed {
  items: PropertySummary[];
  total: number;
  /** True while the first page is loading and there is nothing to show yet. */
  isInitialLoading: boolean;
  isRefreshing: boolean;
  isLoadingMore: boolean;
  hasMore: boolean;
  loadMore: () => void;
  refresh: () => void;
  error: unknown;
  retry: () => void;
}

export function usePropertyFeed(
  params: PropertySearchParams,
  options: { enabled?: boolean } = {}
): PropertyFeed {
  const query: UseInfiniteQueryResult<{ pages: PropertyPage[] }, unknown> = useInfiniteQuery({
    queryKey: qk.propertySearch(params),
    queryFn: ({ pageParam, signal }) => fetchPropertyPage({ ...params, page: pageParam }, signal),
    initialPageParam: 1,
    getNextPageParam: (lastPage) =>
      lastPage.page < lastPage.pages ? lastPage.page + 1 : undefined,
    enabled: options.enabled ?? true,
    // Search results age quickly enough to matter but not so fast that a tab
    // switch should re-spend the limiter budget.
    staleTime: 2 * 60_000,
  });

  const items = useMemo(() => {
    const seen = new Set<string>();
    const flattened: PropertySummary[] = [];

    for (const page of query.data?.pages ?? []) {
      for (const item of page.items) {
        if (seen.has(item.id)) continue;
        seen.add(item.id);
        flattened.push(item);
      }
    }

    return flattened;
  }, [query.data]);

  const total = query.data?.pages[0]?.total ?? 0;

  return {
    items,
    total,
    isInitialLoading: query.isPending,
    isRefreshing: query.isRefetching && !query.isFetchingNextPage,
    isLoadingMore: query.isFetchingNextPage,
    hasMore: query.hasNextPage,
    loadMore: () => {
      // Guarded here rather than at every call site: FlatList fires
      // onEndReached more than once per boundary on Android.
      if (query.hasNextPage && !query.isFetchingNextPage) void query.fetchNextPage();
    },
    refresh: () => void query.refetch(),
    error: query.error,
    retry: () => void query.refetch(),
  };
}

/**
 * One listing, for the detail screen.
 *
 * ---------------------------------------------------------------------------
 * EVERY AUTOMATIC REFETCH IS TURNED OFF, DELIBERATELY
 *
 * `GET /properties/:id` increments the listing's view counter on every
 * successful call. TanStack's defaults are built for idempotent reads and will
 * happily refetch on mount, on reconnect and on focus — each of which would
 * count as another view of a listing the user opened once. A user who tabs
 * away and back, or walks through a tunnel, would inflate the count of
 * whatever they had open, and `views` is the only behavioural signal this
 * backend collects.
 *
 * So: `staleTime: Infinity` (the row is never considered stale, so nothing
 * schedules a background refetch), `refetchOnMount` and `refetchOnReconnect`
 * off explicitly rather than relying on the staleness rule to imply them, and
 * a long `gcTime` so the ordinary back-and-forward between a list and a
 * listing is served from cache instead of re-counting.
 *
 * `refetch()` remains available for a deliberate pull-to-refresh. That one is
 * the user asking, which is a defensible second view.
 *
 * Not fully solvable from here: a request that times out after the server has
 * already run the `$inc` counts a view the user never saw. That needs the
 * increment to move off the read path server-side, which is a backend change
 * request, not a client concern.
 */
export interface PropertyDetailQuery {
  property: PropertyDetail | undefined;
  isLoading: boolean;
  isRefreshing: boolean;
  /** The listing is gone, hidden, or was never public. 404 covers all three. */
  isMissing: boolean;
  error: unknown;
  refresh: () => void;
}

export function usePropertyDetail(id: ObjectId | undefined): PropertyDetailQuery {
  const query = useQuery({
    queryKey: qk.propertyDetail(id ?? ''),
    queryFn: ({ signal }) => fetchPropertyDetail(id as ObjectId, signal),
    enabled: !!id,
    staleTime: Infinity,
    gcTime: 30 * 60_000,
    refetchOnMount: false,
    refetchOnReconnect: false,
  });

  const error = query.error;

  return {
    property: query.data,
    isLoading: query.isPending && !!id,
    isRefreshing: query.isRefetching,
    isMissing: error instanceof ApiError && error.kind === 'notFound',
    error,
    refresh: () => void query.refetch(),
  };
}

/**
 * Writes the listing into local view history, once per screen instance.
 *
 * Guarded by a ref rather than by an effect dependency on the property: a
 * refetch produces a new object identity for the same listing, which would
 * re-record it and push a duplicate to the front of history. The guard is
 * keyed on the id so that a screen reused for a different listing — which
 * expo-router does when navigating between two detail routes — still records
 * the second one.
 *
 * Recorded on load rather than on card press because a tap can be a mis-tap,
 * and the back gesture that follows should not have written history. This is
 * also where the backend counts its own view, so the two agree.
 */
export function useRecordPropertyView(property: PropertyDetail | undefined): void {
  const recordedId = useRef<string | null>(null);

  useEffect(() => {
    if (!property || recordedId.current === property.id) return;
    recordedId.current = property.id;
    recordView(property);
  }, [property]);
}
