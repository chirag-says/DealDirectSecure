import { useInfiniteQuery, useQuery, type UseInfiniteQueryResult } from '@tanstack/react-query';
import { useMemo } from 'react';

import { qk } from '@/api';
import type { ProjectListParams } from '@/types/backend/project';
import { fetchProjects, type ProjectPage } from './api';
import type { ProjectSummary } from './types';

/**
 * The most recently added builder projects.
 *
 * `listProjects` sorts by `createdAt` descending server-side and offers no
 * other ordering, so "recent" is what the endpoint natively returns. That
 * happens to be exactly what the Home rail wants, which is why this hook is
 * thin: no client-side re-sorting, no ranking the data cannot support.
 *
 * Anonymous callers only ever see `isActive: true` records — the controller
 * forces it regardless of the query param — so an unpublished project cannot
 * leak onto Home.
 */

/** Thirty minutes. Projects are admin-authored and change rarely. */
const STALE_MS = 30 * 60_000;

export interface RecentProjectsResult {
  items: ProjectSummary[];
  isLoading: boolean;
  /** Total live projects, which may exceed what the rail shows. */
  total: number;
}

export function useRecentProjects(limit = 10): RecentProjectsResult {
  const params = useMemo(() => ({ limit }), [limit]);

  const query = useQuery({
    queryKey: qk.projectList(params),
    queryFn: ({ signal }) => fetchProjects(params, signal),
    staleTime: STALE_MS,
    retry: 1,
  });

  return {
    items: query.data?.items ?? [],
    isLoading: query.isPending,
    total: query.data?.total ?? 0,
  };
}

/** The full paginated projects list, for `app/projects/index.tsx`. Same shape
 *  as `usePropertyFeed` so `ProjectList` can mirror `PropertyList`. */
export interface ProjectFeed {
  items: ProjectSummary[];
  total: number;
  isInitialLoading: boolean;
  isRefreshing: boolean;
  isLoadingMore: boolean;
  hasMore: boolean;
  loadMore: () => void;
  refresh: () => void;
  error: unknown;
  retry: () => void;
}

export function useProjectFeed(params: ProjectListParams): ProjectFeed {
  const query: UseInfiniteQueryResult<{ pages: ProjectPage[] }, unknown> = useInfiniteQuery({
    queryKey: qk.projectList(params as Record<string, string | number | boolean>),
    queryFn: ({ pageParam, signal }) => fetchProjects({ ...params, page: pageParam }, signal),
    initialPageParam: 1,
    getNextPageParam: (lastPage) => (lastPage.page < lastPage.pages ? lastPage.page + 1 : undefined),
    staleTime: 5 * 60_000,
  });

  const items = useMemo(() => {
    const seen = new Set<string>();
    const flattened: ProjectSummary[] = [];
    for (const page of query.data?.pages ?? []) {
      for (const item of page.items) {
        if (seen.has(item.id)) continue;
        seen.add(item.id);
        flattened.push(item);
      }
    }
    return flattened;
  }, [query.data]);

  return {
    items,
    total: query.data?.pages[0]?.total ?? 0,
    isInitialLoading: query.isPending,
    isRefreshing: query.isRefetching && !query.isFetchingNextPage,
    isLoadingMore: query.isFetchingNextPage,
    hasMore: query.hasNextPage,
    loadMore: () => {
      if (query.hasNextPage && !query.isFetchingNextPage) void query.fetchNextPage();
    },
    refresh: () => void query.refetch(),
    error: query.error,
    retry: () => void query.refetch(),
  };
}
