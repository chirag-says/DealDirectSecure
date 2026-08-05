/**
 * Endpoint registry.
 *
 * Every backend path the mobile app is allowed to call is declared in this
 * directory and nowhere else. If a path is not here, no feature may call it.
 *
 * Two property endpoints are deliberately absent: `/properties/property-list`
 * and `/properties/filter`. Both return every matching approved property with
 * no limit. Omitting them from the registry is the enforcement mechanism.
 */

export * from './_contract';

export { usersEndpoints } from './users';
export { propertiesEndpoints } from './properties';
export { chatEndpoints } from './chat';
export { leadsEndpoints } from './leads';
export { agreementsEndpoints } from './agreements';
export { notificationsEndpoints } from './notifications';
export { savedSearchesEndpoints } from './savedSearches';
export { rewardsEndpoints } from './rewards';
export {
  projectsEndpoints,
  unitTypesEndpoints,
  campaignsEndpoints,
  bookingsEndpoints,
} from './projects';
export { taxonomyEndpoints, blogsEndpoints, contactEndpoints } from './misc';
