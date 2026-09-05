/**
 * Saved-search endpoints. Mounted at `/api/saved-searches`
 * (backend/routes/savedSearchRoutes.js). All behind `authMiddleware`.
 */

import type {
  CreateSavedSearchRequest,
  CreateSavedSearchResponse,
  SavedSearchListResponse,
  SavedSearchMutationResponse,
} from '@/types/backend/savedSearch';
import type { ObjectId, OkEnvelope } from '@/types/backend/common';
import { defineEndpoint } from './_contract';

export const savedSearchesEndpoints = {
  create: defineEndpoint<CreateSavedSearchRequest, CreateSavedSearchResponse>({
    method: 'POST',
    path: '/saved-searches',
    auth: 'user',
    envelope: 'keyed',
    note:
      'Rejects a filter set where every field is empty; at least one filter is required. ' +
      'Only whitelisted filter fields survive sanitisation. Accepts notifyEmail, ' +
      'notifyInApp and (Phase 1) notifyPush; all three default true and are now honoured.',
  }),

  mine: defineEndpoint<void, SavedSearchListResponse>({
    method: 'GET',
    path: '/saved-searches/mine',
    auth: 'user',
    envelope: 'keyed',
    note: 'Response key is `searches`, not `savedSearches` and not `data`.',
  }),

  toggle: defineEndpoint<void, SavedSearchMutationResponse, { id: ObjectId }>({
    method: 'PATCH',
    path: ({ id }) => `/saved-searches/${id}/toggle`,
    auth: 'user',
    envelope: 'keyed',
    note: 'Flips isActive. Response key is `savedSearch` (singular).',
  }),

  update: defineEndpoint<
    Partial<CreateSavedSearchRequest>,
    SavedSearchMutationResponse,
    { id: ObjectId }
  >({
    method: 'PUT',
    path: ({ id }) => `/saved-searches/${id}`,
    auth: 'user',
    envelope: 'keyed',
    note:
      'Accepts notifyPush alongside notifyEmail/notifyInApp. `lastMatchAt` and `matchCount` ' +
      'are read-only: they come back on `mine` and are never sent.',
  }),

  remove: defineEndpoint<void, OkEnvelope, { id: ObjectId }>({
    method: 'DELETE',
    path: ({ id }) => `/saved-searches/${id}`,
    auth: 'user',
    envelope: 'ok',
  }),
} as const;
