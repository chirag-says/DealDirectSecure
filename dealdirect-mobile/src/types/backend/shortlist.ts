/**
 * Shortlist contract (Phase 1, F7). Mounted at `/api/shortlist`.
 *
 * ---------------------------------------------------------------------------
 * THE INVARIANT THAT DEFINES THIS ENDPOINT SET
 *
 * A shortlist entry notifies nobody and creates no Lead. It is NOT the
 * five-listing enquiry cap (`POST /properties/interested/:id`), which emails
 * the owner, hands over the user's phone number and counts against a hard
 * limit. The two lists stay separate on the client exactly as they are on the
 * server; see `features/shortlist/store.ts` for the long version of why.
 *
 * The only cap here is 200 on a single merge payload.
 */

import type { ObjectId } from './common';
import type { PropertyCategorizedImages } from './property';

/**
 * The listing as the shortlist endpoints project it.
 *
 * Deliberately NOT the full `Property`: the server sends the card fields only,
 * so a shortlist of forty rows is one small response rather than forty
 * eighty-field documents. `_id` (not `id`) matches the projection.
 */
export interface ShortlistCardProperty {
  _id: ObjectId;
  title?: string;
  price?: number;
  priceUnit?: string;
  listingType?: string;
  city?: string;
  locality?: string;
  bhk?: string;
  area?: number;
  propertyTypeName?: string;
  images?: string[];
  categorizedImages?: PropertyCategorizedImages;
  status?: string;
}

/** Why a shortlisted listing can no longer be enquired about. */
export type ShortlistUnavailableReason = 'sold' | 'rented' | 'unavailable';

export interface ShortlistEntry {
  id: ObjectId;
  addedAt: string;
  note?: string;
  available: boolean;
  unavailableReason: ShortlistUnavailableReason | null;
  property: ShortlistCardProperty;
}

export interface ShortlistListParams {
  page?: number;
  limit?: number;
}

export interface ShortlistListResponse {
  success?: boolean;
  data: ShortlistEntry[];
  pagination: { page: number; limit: number; total: number; pages: number };
}

/** `GET /shortlist/ids` — the cheap membership sync. Property ids, not entry ids. */
export interface ShortlistIdsResponse {
  success?: boolean;
  data: string[];
}

export interface AddShortlistRequest {
  propertyId: ObjectId;
  note?: string;
}

/** Idempotent: re-adding an existing entry is a 200, not a 409. */
export interface AddShortlistResponse {
  success?: boolean;
  data: { id: ObjectId; addedAt: string };
  total: number;
}

/** Cap 200 ids per call. Used ONCE per account, on the first authenticated
 *  launch after the device-local list became server-backed. */
export interface MergeShortlistRequest {
  propertyIds: string[];
}

export interface MergeShortlistResponse {
  success?: boolean;
  added: number;
  skipped: number;
  total: number;
}

export interface RemoveShortlistResponse {
  success?: boolean;
  removed: boolean;
  total: number;
}

export interface UpdateShortlistNoteRequest {
  note: string;
}

/** 404 NOT_SHORTLISTED when the listing is not on the list. */
export interface UpdateShortlistNoteResponse {
  success?: boolean;
  data: { note: string };
}

/**
 * `POST /shortlist/share` — 201. ROTATES: creating a link kills the previous
 * one, so the UI must never imply that two links can be live at once.
 * 409 EMPTY_SHORTLIST when there is nothing to share.
 */
export interface ShareShortlistResponse {
  success?: boolean;
  data: { token: string; expiresAt: string; count: number };
}

export interface RevokeShareResponse {
  success?: boolean;
  revoked: boolean;
}

/**
 * `GET /shortlist/shared/:token` — PUBLIC. Same card shape, no note: a note is
 * the owner's private reasoning and is not part of what they shared.
 * 404 LINK_NOT_FOUND covers expired, revoked and never-existed alike.
 */
export interface SharedShortlistResponse {
  success?: boolean;
  data: {
    label: string;
    properties: Omit<ShortlistEntry, 'note'>[];
    expiresAt: string;
  };
}
