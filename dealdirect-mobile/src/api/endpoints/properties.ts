/**
 * Property endpoints. Mounted at `/api/properties`
 * (backend/routes/propertyRoutes.js).
 *
 * PAGINATION: `search` is the ONLY paginated property endpoint. `property-list`
 * and `filter` return every matching approved property with no limit, and
 * `filter` additionally does its post-filtering in memory after loading them
 * all. Neither is exported here, so no screen can reach for them by accident.
 * That omission is deliberate; see docs/API_CONTRACT.md.
 */

import type {
  AddPropertyResponse,
  ClaimDealRewardResponse,
  CloseDealResponse,
  InterestCheckResponse,
  MarkInterestedResponse,
  Property,
  PropertyDetailResponse,
  PropertyListResponse,
  PropertySearchParams,
  PropertySuggestionParams,
  PropertySuggestionsResponse,
} from '@/types/backend/property';
import type {
  CountedDataEnvelope,
  DataEnvelope,
  ObjectId,
  OkEnvelope,
  PagedEnvelope,
} from '@/types/backend/common';
import { defineEndpoint } from './_contract';

export const propertiesEndpoints = {
  /**
   * The primary discovery endpoint. Everything that lists properties uses this.
   */
  search: defineEndpoint<PropertySearchParams, PagedEnvelope<Property>>({
    method: 'GET',
    path: '/properties/search',
    auth: 'public',
    envelope: 'paged',
    rateLimit: 'search',
    note:
      'Free-text param is `search`, NOT `q`. The website helper sends `q`, which this ' +
      'controller ignores. Response has NO `success` key: it is { data, total, page, pages }. ' +
      'Default limit 12. Builder-posted listings are excluded from this feed.',
  }),

  suggestions: defineEndpoint<PropertySuggestionParams, PropertySuggestionsResponse>({
    method: 'GET',
    path: '/properties/suggestions',
    auth: 'public',
    envelope: 'keyed',
    rateLimit: 'search',
    note:
      'This endpoint DOES use `q`, unlike search. Fewer than 2 characters returns an empty ' +
      'array without querying. Capped at 8 results. Rows are OBJECTS ' +
      '({type,value,subtitle,image?}), not strings.',
  }),

  /** Bare array, no envelope. Supports `limit`; use `search` for anything paged. */
  list: defineEndpoint<{ limit?: number }, PropertyListResponse>({
    method: 'GET',
    path: '/properties/list',
    auth: 'public',
    envelope: 'bare',
    note: 'Returns a NAKED ARRAY. No success key, no wrapper.',
  }),

  /** Bare object, no envelope. Increments the view counter as a side effect. */
  detail: defineEndpoint<void, PropertyDetailResponse, { id: ObjectId }>({
    method: 'GET',
    path: ({ id }) => `/properties/${id}`,
    auth: 'public',
    envelope: 'bare',
    note:
      'Returns a NAKED OBJECT. Increments `views` on every call, so do not refetch on focus. ' +
      'Returns 404 (not 403) for listings that exist but are not publicly viewable. ' +
      '`owner` is populated with name/email/phone/profileImage.',
  }),

  myProperties: defineEndpoint<void, CountedDataEnvelope<Property>>({
    method: 'GET',
    path: '/properties/my-properties',
    auth: 'user',
    envelope: 'counted',
  }),

  add: defineEndpoint<FormData, AddPropertyResponse>({
    method: 'POST',
    path: '/properties/add',
    auth: 'user',
    envelope: 'data',
    note:
      'Owners only (ownerOnlyListingAccess). multipart/form-data with file fields `images` ' +
      '(max 15) and `categorizedImages` (max 50). 10MB per file, images only ' +
      '(jpeg/jpg/png/gif/webp), magic-byte validated. Rejected with 503 when more than 10 ' +
      'uploads are in flight server-wide. ' +
      'Also carries a `reward` object for listing the property (propertyController.js:530-559); ' +
      'surface it the way the website does.',
  }),

  updateMine: defineEndpoint<FormData, DataEnvelope<Property>, { id: ObjectId }>({
    method: 'PUT',
    path: ({ id }) => `/properties/my-properties/${id}`,
    auth: 'user',
    envelope: 'data',
    note: 'Owners only. Same multipart field names and limits as `add`.',
  }),

  deleteMine: defineEndpoint<void, OkEnvelope, { id: ObjectId }>({
    method: 'DELETE',
    path: ({ id }) => `/properties/${id}`,
    auth: 'user',
    envelope: 'ok',
  }),

  // --- Saved (private bookmark) -------------------------------------------

  /**
   * CORRECTED 2026-08-05 by reading `getSavedProperties`.
   *
   * "Saved" is not a separate collection. This queries
   * `{ "interestedUsers.user": userId }` — the SAME array `markInterested`
   * pushes to. Saved and interested are one list under two names, and
   * `removeSaved` and `removeInterest` are the same operation written twice.
   *
   * The consequence for the UI: there is no private bookmark on this backend.
   * Adding to this list notifies the owner and creates a Lead, so it cannot be
   * presented as a quiet save. See `markInterested`.
   */
  saved: defineEndpoint<void, DataEnvelope<Property[]>>({
    method: 'GET',
    path: '/properties/saved',
    auth: 'user',
    envelope: 'data',
    note:
      'Returns properties where the user appears in `interestedUsers`. Each row carries an ' +
      'extra `interestedAt`. Not paginated. Identical data to the interest flag.',
  }),

  /** Same operation as `removeInterest`, under a different path. */
  removeSaved: defineEndpoint<void, OkEnvelope, { id: ObjectId }>({
    method: 'DELETE',
    path: ({ id }) => `/properties/saved/${id}`,
    auth: 'user',
    envelope: 'ok',
  }),

  // --- Interested (creates a Lead, notifies the owner) ---------------------

  markInterested: defineEndpoint<void, MarkInterestedResponse, { id: ObjectId }>({
    method: 'POST',
    path: ({ id }) => `/properties/interested/${id}`,
    auth: 'user',
    envelope: 'keyed',
    note:
      'NOT a private bookmark. Creates a Lead for the property owner and notifies them. ' +
      'The UI must not present this as a quiet save. THE BACKEND CAPS THIS AT 5 LISTINGS ' +
      'PER USER and returns 400 with an explanatory message on the sixth. Also 400 for ' +
      'your own listing and for one you already marked. ' +
      'Carries a `reward` object when the enquiry earned points — null past the ' +
      'daily cap of 5 rewarded enquiries. Surface it; the website does.',
  }),

  checkInterested: defineEndpoint<void, InterestCheckResponse, { id: ObjectId }>({
    method: 'GET',
    path: ({ id }) => `/properties/interested/${id}/check`,
    auth: 'user',
    envelope: 'keyed',
  }),

  removeInterest: defineEndpoint<void, OkEnvelope, { id: ObjectId }>({
    method: 'DELETE',
    path: ({ id }) => `/properties/interested/${id}`,
    auth: 'user',
    envelope: 'ok',
  }),

  // --- Other actions -------------------------------------------------------

  /**
   * `details` was declared in M0 and is NOT read by the controller: it takes
   * `reason` only. Removed rather than left as a field that silently discards
   * whatever a form puts in it.
   */
  report: defineEndpoint<{ reason: string }, OkEnvelope, { id: ObjectId }>({
    method: 'POST',
    path: ({ id }) => `/properties/${id}/report`,
    auth: 'user',
    envelope: 'ok',
    note:
      'Requires a `reason` of at least 10 characters after trimming, else 400. A second ' +
      'report of the same listing by the same user while one is pending or reviewed is ' +
      'also 400. Returns 201, and awards the reporter 100 reward points.',
  }),

  closeDeal: defineEndpoint<FormData, CloseDealResponse, { id: ObjectId }>({
    method: 'POST',
    path: ({ id }) => `/properties/${id}/close-deal`,
    auth: 'user',
    envelope: 'keyed',
    note:
      'multipart/form-data: `buyerId` (must be in the listing\'s interestedUsers), ' +
      '`closingType` (`sold`|`rented`), and a `documents` file field (max 5, at least one ' +
      'required). Submits proof for admin verification and sets the property to ' +
      '`pending_verification`; the reward is claimed separately after approval, via ' +
      '`claimDealReward`.',
  }),

  claimDealReward: defineEndpoint<void, ClaimDealRewardResponse, { verificationId: ObjectId }>({
    method: 'POST',
    path: ({ verificationId }) => `/properties/claim-deal-reward/${verificationId}`,
    auth: 'user',
    envelope: 'keyed',
    note:
      'Owner or buyer on the verification, once admin has set it to `approved`. Returns ' +
      '`alreadyClaimed: true` (still 200) on a repeat call rather than an error.',
  }),
} as const;
