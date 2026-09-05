/**
 * Locality price endpoints. Mounted at `/api/localities` (Phase 4, F18).
 * All three are PUBLIC — this is the data a buyer reads before signing in.
 *
 * The sample floor (5 listings) is enforced server-side, and falling below it
 * is a NORMAL answer: `detail` 404s and `guidance` returns 200 with a null
 * body. Neither is an error state on the client.
 */

import type {
  LocalityDetailParams,
  LocalityDetailResponse,
  LocalityListParams,
  LocalityListResponse,
  PriceGuidanceParams,
  PriceGuidanceResponse,
} from '@/types/backend/locality';
import { defineEndpoint } from './_contract';

export const localitiesEndpoints = {
  list: defineEndpoint<LocalityListParams, LocalityListResponse>({
    method: 'GET',
    path: '/localities',
    auth: 'public',
    envelope: 'data',
    note: 'Carries `sampleFloor` beside `data`; only localities above it are returned.',
  }),

  detail: defineEndpoint<LocalityDetailParams, LocalityDetailResponse, { slug: string }>({
    method: 'GET',
    path: ({ slug }) => `/localities/${encodeURIComponent(slug)}`,
    auth: 'public',
    envelope: 'data',
    note:
      '404 LOCALITY_NOT_FOUND when the locality is below the sample floor. ' +
      'Render an empty state for that, never an error.',
  }),

  /**
   * One comparison line for the listing form. `city` + `locality` are required
   * (400 LOCATION_REQUIRED without them); `bhk` is what turns `scope` into
   * `configuration`.
   */
  guidance: defineEndpoint<PriceGuidanceParams, PriceGuidanceResponse>({
    method: 'GET',
    path: '/localities/guidance',
    auth: 'public',
    envelope: 'data',
    note: '200 with `data: null` when there is nothing to compare against.',
  }),
} as const;
