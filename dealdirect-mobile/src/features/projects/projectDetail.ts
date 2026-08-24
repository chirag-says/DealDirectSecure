import { useQuery } from '@tanstack/react-query';

import { call, projectsEndpoints, qk, unitTypesEndpoints } from '@/api';
import type { ObjectId } from '@/types/backend/common';

/** Thirty minutes, same reasoning as `useRecentProjects`: admin-authored, changes rarely. */
const STALE_MS = 30 * 60_000;

export function useProjectDetail(id: ObjectId) {
  const query = useQuery({
    queryKey: qk.projectDetail(id),
    queryFn: async ({ signal }) => {
      const response = await call(projectsEndpoints.detail, { params: { id }, signal });
      return response.data;
    },
    enabled: Boolean(id),
    staleTime: STALE_MS,
  });

  return {
    project: query.data ?? null,
    isLoading: query.isPending,
    error: query.error,
    /*
      Returns the PROMISE rather than swallowing it with `void`.

      The screen does `await refresh()` around its pull-to-refresh spinner. With
      a void return that awaited nothing, resolved on the same tick, and the
      spinner vanished instantly while the request was still in flight — the one
      thing a refresh control exists to communicate.
    */
    refresh: () => query.refetch(),
  };
}

export function useUnitTypesForProject(projectId: ObjectId) {
  const query = useQuery({
    queryKey: qk.unitTypesByProject(projectId),
    queryFn: async ({ signal }) => {
      const response = await call(unitTypesEndpoints.byProject, { params: { projectId }, signal });
      return response.data;
    },
    enabled: Boolean(projectId),
    staleTime: STALE_MS,
  });

  return {
    unitTypes: query.data ?? [],
    isLoading: query.isPending,
    error: query.error,
    retry: () => void query.refetch(),
  };
}

export function useUnitTypeDetail(id: ObjectId) {
  const query = useQuery({
    queryKey: qk.unitTypeDetail(id),
    queryFn: async ({ signal }) => {
      const response = await call(unitTypesEndpoints.detail, { params: { id }, signal });
      return response.data;
    },
    enabled: Boolean(id),
    staleTime: STALE_MS,
  });

  return {
    unitType: query.data ?? null,
    isLoading: query.isPending,
    error: query.error,
    refresh: () => void query.refetch(),
  };
}
