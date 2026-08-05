import { useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';

import { qk } from '@/api';
import { fetchProjects } from './api';
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
