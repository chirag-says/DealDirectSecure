/**
 * Builder-projects feature. Cross-feature imports come through this file only.
 *
 * This vertical is the only way builder inventory surfaces anywhere in the app:
 * `/properties/search` excludes builder-posted listings, by design on the
 * backend. Projects, unit types, group-buy campaigns and bookings all hang off
 * this module.
 */

export { adaptProject } from './adapters';
export { fetchProjects, type ProjectPage } from './api';
export { useRecentProjects, type RecentProjectsResult } from './hooks';
export { ProjectCard, type ProjectCardProps } from './components/ProjectCard';
export { ProjectRail, type ProjectRailProps } from './components/ProjectRail';
export type { ProjectSummary } from './types';
