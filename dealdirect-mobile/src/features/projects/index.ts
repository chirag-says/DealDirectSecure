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
export { useRecentProjects, useProjectFeed, type RecentProjectsResult, type ProjectFeed } from './hooks';
export { ProjectCard, type ProjectCardProps } from './components/ProjectCard';
export { ProjectRail, type ProjectRailProps } from './components/ProjectRail';
export { ProjectList, type ProjectListProps } from './components/ProjectList';
export { ProjectListCard, type ProjectListCardProps } from './components/ProjectListCard';
export type { ProjectSummary } from './types';

export {
  useProjectDetail,
  useUnitTypesForProject,
  useUnitTypeDetail,
} from './projectDetail';

export {
  useCampaignsForUnitType,
  useCampaignDetail,
  useJoinCampaign,
  useExitCampaign,
  useUploadPaymentProof,
} from './campaigns';

export {
  useMyBookings,
  useCreateBooking,
  usePaymentConfig,
  useSubmitBookingPayment,
} from './bookings';
