/**
 * Shortlist endpoints. Mounted at `/api/shortlist` (Phase 1, F7).
 *
 * Everything except the shared-link read is behind `authMiddleware`. The
 * shortlist is the free, private, uncapped list of listings a user is
 * considering — it creates no Lead and notifies no owner, and nothing in this
 * file may ever be confused with `/properties/interested/:id`, which does both
 * and is capped at five.
 */

import type {
  AddShortlistRequest,
  AddShortlistResponse,
  MergeShortlistRequest,
  MergeShortlistResponse,
  RemoveShortlistResponse,
  RevokeShareResponse,
  ShareShortlistResponse,
  SharedShortlistResponse,
  ShortlistIdsResponse,
  ShortlistListParams,
  ShortlistListResponse,
  UpdateShortlistNoteRequest,
  UpdateShortlistNoteResponse,
} from '@/types/backend/shortlist';
import type { ObjectId } from '@/types/backend/common';
import { defineEndpoint } from './_contract';

export const shortlistEndpoints = {
  list: defineEndpoint<ShortlistListParams, ShortlistListResponse>({
    method: 'GET',
    path: '/shortlist',
    auth: 'user',
    envelope: 'paginated',
    note:
      'Carries the card projection plus `note`, `available` and ' +
      '`unavailableReason`. A sold or rented listing STAYS on the list and is ' +
      'marked, rather than disappearing without explanation.',
  }),

  /** The cheap sync. Property ids only, no pagination, safe to call on mount. */
  ids: defineEndpoint<void, ShortlistIdsResponse>({
    method: 'GET',
    path: '/shortlist/ids',
    auth: 'user',
    envelope: 'data',
  }),

  add: defineEndpoint<AddShortlistRequest, AddShortlistResponse>({
    method: 'POST',
    path: '/shortlist',
    auth: 'user',
    envelope: 'data',
    note: 'Idempotent. 400 INVALID_ID, 404 NOT_FOUND.',
  }),

  /**
   * The device-local list, handed over once.
   *
   * Called exactly once per account per install, guarded by a prefs key — see
   * `features/shortlist/merge.ts`. Cap is 200 ids; a longer local list is
   * truncated client-side rather than rejected server-side.
   */
  merge: defineEndpoint<MergeShortlistRequest, MergeShortlistResponse>({
    method: 'POST',
    path: '/shortlist/merge',
    auth: 'user',
    envelope: 'bare',
    note: 'Returns { added, skipped, total } at the top level, no `data` key. Cap 200 ids.',
  }),

  remove: defineEndpoint<void, RemoveShortlistResponse, { propertyId: ObjectId }>({
    method: 'DELETE',
    path: ({ propertyId }) => `/shortlist/${propertyId}`,
    auth: 'user',
    envelope: 'bare',
    note: 'Keyed by PROPERTY id, not by entry id. Returns { removed, total }.',
  }),

  setNote: defineEndpoint<
    UpdateShortlistNoteRequest,
    UpdateShortlistNoteResponse,
    { propertyId: ObjectId }
  >({
    method: 'PATCH',
    path: ({ propertyId }) => `/shortlist/${propertyId}`,
    auth: 'user',
    envelope: 'data',
    note: '404 NOT_SHORTLISTED when the listing is not on the list.',
  }),

  /**
   * ROTATES. Creating a link invalidates the previous one, so the UI must
   * never suggest two links can be live at once.
   */
  share: defineEndpoint<void, ShareShortlistResponse>({
    method: 'POST',
    path: '/shortlist/share',
    auth: 'user',
    envelope: 'data',
    note: '201. 409 EMPTY_SHORTLIST when there is nothing to share.',
  }),

  revokeShare: defineEndpoint<void, RevokeShareResponse>({
    method: 'DELETE',
    path: '/shortlist/share',
    auth: 'user',
    envelope: 'bare',
  }),

  /** PUBLIC. 404 LINK_NOT_FOUND covers expired, revoked and never-existed. */
  shared: defineEndpoint<void, SharedShortlistResponse, { token: string }>({
    method: 'GET',
    path: ({ token }) => `/shortlist/shared/${encodeURIComponent(token)}`,
    auth: 'public',
    envelope: 'data',
    note: 'No note field: a note is the owner\u2019s private reasoning and is not shared.',
  }),
} as const;
