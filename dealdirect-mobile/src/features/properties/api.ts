/**
 * Property data access.
 *
 * The only place that calls the properties endpoints. Screens and hooks above
 * this line deal in `PropertySummary`, never in the backend's envelope.
 */

import { call, normalizeSearchParams, propertiesEndpoints } from '@/api';
import type { ObjectId } from '@/types/backend/common';
import type { PropertySearchParams } from '@/types/backend/property';
import { adaptProperty, adaptPropertyDetail } from './adapters';
import type { PropertyDetail, PropertySummary } from './types';

/** Backend default is 12. Stated explicitly so paging maths never guesses. */
export const SEARCH_PAGE_SIZE = 12;

export interface PropertyPage {
  items: PropertySummary[];
  total: number;
  page: number;
  /** `Math.ceil(total / limit)`, so it is 0 when there are no matches at all. */
  pages: number;
}

/**
 * One page of `GET /properties/search`.
 *
 * This is the ONLY property list endpoint the app uses. `/property-list` and
 * `/filter` return every matching approved property with no limit, and `/filter`
 * additionally post-filters in memory after loading them all. Neither is
 * exported from the endpoint registry, so neither can be reached from here.
 */
export async function fetchPropertyPage(
  params: PropertySearchParams,
  signal?: AbortSignal
): Promise<PropertyPage> {
  const response = await call(propertiesEndpoints.search, {
    data: {
      limit: SEARCH_PAGE_SIZE,
      ...normalizeSearchParams(params),
    } as PropertySearchParams,
    signal,
  });

  // No `success` key on this envelope, and `data` has been observed absent on
  // an empty result rather than empty-but-present.
  return {
    items: (response.data ?? []).map(adaptProperty),
    total: response.total ?? 0,
    page: response.page ?? 1,
    pages: response.pages ?? 0,
  };
}

/**
 * One listing, for the detail screen.
 *
 * THIS REQUEST HAS A SIDE EFFECT. `GET /properties/:id` runs
 * `$inc: { views: 1 }` on every successful call, and `views` is the only
 * behavioural signal this backend records. Every caller must therefore be
 * deliberate about when it fires: see `usePropertyDetail`, which turns off
 * every automatic refetch TanStack would otherwise do for free.
 *
 * The response is a NAKED object with no envelope, and a listing that exists
 * but is not publicly viewable returns 404 rather than 403, so "hidden" and
 * "deleted" are indistinguishable from here. The screen says "no longer
 * available" for both, which is true either way.
 */
export async function fetchPropertyDetail(
  id: ObjectId,
  signal?: AbortSignal
): Promise<PropertyDetail> {
  const property = await call(propertiesEndpoints.detail, { params: { id }, signal });
  return adaptPropertyDetail(property);
}

/**
 * Autocomplete rows for `GET /properties/suggestions`.
 *
 * The caller is responsible for debouncing and for the two-character minimum.
 * Below two characters the backend returns an empty array without querying, but
 * the request still costs one of the twenty per minute the search limiter
 * allows, so it must not be sent at all.
 */
export async function fetchSuggestions(query: string, signal?: AbortSignal) {
  const response = await call(propertiesEndpoints.suggestions, {
    data: { q: query },
    signal,
  });

  return response.suggestions ?? [];
}
