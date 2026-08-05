/**
 * Lead endpoints. Mounted at `/api/leads` (backend/routes/leadRoutes.js).
 * Every route is behind `authMiddleware` via `router.use`.
 *
 * Leads belong to the property OWNER. A buyer never sees this surface.
 */

import type {
  AddContactHistoryRequest,
  Lead,
  LeadAnalyticsParams,
  LeadAnalyticsResponse,
  LeadListParams,
  LeadListResponse,
  UpdateLeadStatusRequest,
} from '@/types/backend/lead';
import type { DataEnvelope, ObjectId, OkEnvelope } from '@/types/backend/common';
import { defineEndpoint } from './_contract';

export const leadsEndpoints = {
  list: defineEndpoint<LeadListParams, LeadListResponse>({
    method: 'GET',
    path: '/leads',
    auth: 'user',
    envelope: 'paginated',
    note:
      'Carries BOTH a `stats` block and a `pagination` block. Default limit 20, default sort ' +
      '`-createdAt`. Pagination key is `pagination`, unlike properties/search which is flat.',
  }),

  analytics: defineEndpoint<LeadAnalyticsParams, LeadAnalyticsResponse>({
    method: 'GET',
    path: '/leads/analytics',
    auth: 'user',
    envelope: 'data',
    note: 'Default window is 30 days. `statusStats` is an object keyed by status, not an array.',
  }),

  byProperty: defineEndpoint<void, DataEnvelope<Lead[]>, { propertyId: ObjectId }>({
    method: 'GET',
    path: ({ propertyId }) => `/leads/property/${propertyId}`,
    auth: 'user',
    envelope: 'data',
    note: 'Returns 403 when the caller does not own the property.',
  }),

  updateStatus: defineEndpoint<UpdateLeadStatusRequest, DataEnvelope<Lead>, { id: ObjectId }>({
    method: 'PUT',
    path: ({ id }) => `/leads/${id}/status`,
    auth: 'user',
    envelope: 'data',
  }),

  markViewed: defineEndpoint<void, OkEnvelope, { id: ObjectId }>({
    method: 'PUT',
    path: ({ id }) => `/leads/${id}/viewed`,
    auth: 'user',
    envelope: 'ok',
    note: 'Returns bare { success: true } with no data payload.',
  }),

  addContactHistory: defineEndpoint<
    AddContactHistoryRequest,
    DataEnvelope<Lead>,
    { id: ObjectId }
  >({
    method: 'POST',
    path: ({ id }) => `/leads/${id}/contact`,
    auth: 'user',
    envelope: 'data',
  }),

  /**
   * Returns an Excel file, not JSON. Downloading it is an authenticated request
   * and must therefore carry the same constant User-Agent as every other call,
   * or the session fingerprint flips and the session is revoked.
   */
  exportExcel: defineEndpoint<void, Blob>({
    method: 'GET',
    path: '/leads/export',
    auth: 'user',
    envelope: 'bare',
    note: 'Binary response. See the User-Agent rule in the architecture plan section 1.5.',
  }),
} as const;
