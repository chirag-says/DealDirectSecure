/**
 * Saved search contract. Source: backend/models/SavedSearch.js,
 * backend/controllers/savedSearchController.js, and the alert matcher inlined
 * in backend/controllers/propertyController.js.
 *
 * ---------------------------------------------------------------------------
 * CORRECTED 2026-08-05 by reading the controller. The M0 version of this file
 * declared filters as `{ city, category, subcategory, propertyType, priceFrom,
 * priceTo }` with numeric prices. None of that is right:
 *
 *   - The controller writes exactly FIVE filter keys and coerces every one to
 *     a String: `search`, `city`, `propertyType`, `priceRange`, `availableFor`.
 *     `category`, `subcategory`, `priceFrom` and `priceTo` are dropped by
 *     `sanitizeSavedSearchData` without an error.
 *   - `priceRange` is a BAND NAME, not a range. See `SavedSearchPriceBand`.
 *   - `notifyEmail` and `notifyInApp` exist, default true, and were missing.
 *
 * A wider type here is not harmless: it lets a caller send a filter that is
 * silently discarded and then wonder why no alert ever arrives.
 */

import type { ObjectId, Timestamps } from './common';

/**
 * The only three values the alert matcher understands, with the thresholds it
 * hard-codes (propertyController.js:506).
 *
 * Anything else stored in `priceRange` is truthy to the matcher and matches no
 * price band, which permanently disables alerts for that search.
 */
export type SavedSearchPriceBand = 'low' | 'mid' | 'high';

/**
 * Exactly the keys the controller persists.
 *
 * `search` is stored and validated but is NEVER READ by the matcher. A search
 * saved with only a free-text term will never alert.
 *
 * `propertyType` is compared against the property's `propertyType` ObjectId,
 * and those refs are null or wrong across the live data, so it does not
 * usefully match either.
 */
export interface SavedSearchFilters {
  search?: string;
  city?: string;
  propertyType?: string;
  priceRange?: SavedSearchPriceBand | '';
  /** Compared to `listingType.toLowerCase()`, exactly. See the note below. */
  availableFor?: string;
}

export interface SavedSearch extends Timestamps {
  _id: ObjectId;
  user: ObjectId;
  name: string;
  filters: SavedSearchFilters;
  notifyEmail: boolean;
  notifyInApp: boolean;
  isActive: boolean;
}

/**
 * `POST /saved-searches`.
 *
 * At least one of `search`, `city`, `propertyType`, `priceRange` or
 * `availableFor` must be non-empty, else 400. Note that `search` alone
 * satisfies that check while being useless to the matcher.
 *
 * `name` is passed through express-validator's `.escape()`, so `&`, `<`, `>`,
 * `"` and `'` are stored as HTML entities. Decode on read.
 */
export interface CreateSavedSearchRequest {
  name: string;
  filters: SavedSearchFilters;
  notifyEmail?: boolean;
  notifyInApp?: boolean;
}

export interface CreateSavedSearchResponse {
  success: true;
  savedSearch: SavedSearch;
}

/**
 * `GET /saved-searches/mine`. Key is `searches`, not `savedSearches`.
 *
 * FILTERED TO `isActive: true`. Deactivating a search removes it from the only
 * endpoint that lists them, so it cannot be found again to reactivate. Treat
 * `PATCH /toggle` as a one-way operation.
 */
export interface SavedSearchListResponse {
  success: true;
  searches: SavedSearch[];
}

/** `PATCH /saved-searches/:id/toggle` and `PUT /saved-searches/:id`. */
export interface SavedSearchMutationResponse {
  success: true;
  savedSearch: SavedSearch;
}
