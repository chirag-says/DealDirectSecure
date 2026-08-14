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
    refresh: () => void query.refetch(),
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
