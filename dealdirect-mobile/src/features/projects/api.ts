import { call, projectsEndpoints } from '@/api';
import type { ProjectListParams } from '@/types/backend/project';
import { adaptProject } from './adapters';
import type { ProjectSummary } from './types';

/**
 * Project data access. The only place that calls the projects endpoints.
 *
 * `GET /projects` is the same call the website makes for its Builder Projects
 * page (`client-next/src/app/projects/page.js` fetches
 * `/api/projects?isActive=true&limit=100`), so both clients read one list and
 * cannot disagree about what is live.
 *
 * This is also the ONLY route by which builder-posted inventory surfaces at
 * all: `/properties/search` excludes builder listings outright, so a builder's
 * work appears here or nowhere.
 *
 * Note this endpoint is NOT behind the 20-per-minute search limiter, which
 * applies only to `/properties/search`, `/suggestions` and `/filter`. It still
 * gets the same deferred-mount treatment on Home, because a request the user
 * never scrolls to is waste regardless of who is counting.
 */

export interface ProjectPage {
  items: ProjectSummary[];
  total: number;
  page: number;
  pages: number;
}

export async function fetchProjects(
  params: ProjectListParams = {},
  signal?: AbortSignal
): Promise<ProjectPage> {
  const response = await call(projectsEndpoints.list, {
    data: params,
    signal,
  });

  return {
    items: (response.data ?? []).map(adaptProject),
    total: response.pagination?.total ?? 0,
    page: response.pagination?.page ?? 1,
    pages: response.pagination?.pages ?? 0,
  };
}
