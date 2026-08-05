/**
 * Saved search contract. Source: backend/models/SavedSearch.js and
 * backend/controllers/savedSearchController.js.
 *
 * Saved searches drive server-side alert notifications. They are distinct from
 * both saved properties and expressed interest.
 */

import type { ObjectId, Timestamps } from './common';

export interface SavedSearchFilters {
  city?: string;
  category?: string;
  subcategory?: string;
  propertyType?: string;
  priceFrom?: number;
  priceTo?: number;
  [key: string]: unknown;
}

export interface SavedSearch extends Timestamps {
  _id: ObjectId;
  user: ObjectId;
  name: string;
  filters: SavedSearchFilters;
  isActive: boolean;
}

/**
 * `POST /saved-searches`. The controller rejects a filter set in which every
 * field is empty, so at least one filter must be populated.
 */
export interface CreateSavedSearchRequest {
  name: string;
  filters: SavedSearchFilters;
}

export interface CreateSavedSearchResponse {
  success: true;
  savedSearch: SavedSearch;
}

/** `GET /saved-searches/mine`. Note the key is `searches`, not `savedSearches`. */
export interface SavedSearchListResponse {
  success: true;
  searches: SavedSearch[];
}

/** `PATCH /saved-searches/:id/toggle` and `PUT /saved-searches/:id`. */
export interface SavedSearchMutationResponse {
  success: true;
  savedSearch: SavedSearch;
}
