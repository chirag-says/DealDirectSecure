/**
 * Locality price data (Phase 4, F18) and the listing-form guidance that shares
 * its aggregation (Phase 1/4, F19). Mounted at `/api/localities`. All public.
 *
 * ---------------------------------------------------------------------------
 * THIS IS ASKING-PRICE DATA, AND EVERY SCREEN THAT RENDERS IT SAYS SO
 *
 * The numbers are medians of what DealDirect owners ASK, not of what anything
 * sold for. There is no transaction feed behind them. A screen that presents
 * them as "market value" would be inventing an authority this data does not
 * have, so the locality screen carries a footer saying what they are.
 *
 * ---------------------------------------------------------------------------
 * THE SAMPLE FLOOR IS A NORMAL ANSWER, NOT AN ERROR
 *
 * Below the floor (5 listings) the server publishes nothing:
 * `GET /localities/:slug` returns 404 LOCALITY_NOT_FOUND and
 * `GET /localities/guidance` returns 200 with `data: null`. Both mean "not
 * enough to say", and the client renders an empty state, never an error.
 */

/** A quarter label as the server writes it, e.g. `2026-Q3`. */
export type LocalityPeriod = string;

export type LocalityListingType = 'sale' | 'rent';

/** One row of `GET /localities`. */
export interface LocalitySummary {
  slug: string;
  city: string;
  locality: string;
  listingType: LocalityListingType;
  period: LocalityPeriod;
  count: number;
  medianAsking: number;
  /** Quarter on quarter, as a percentage. Null when there is no prior quarter. */
  qoqPct: number | null;
}

export interface LocalityListParams {
  city?: string;
  listingType?: LocalityListingType;
  limit?: number;
}

export interface LocalityListResponse {
  success?: boolean;
  data: LocalitySummary[];
  sampleFloor: number;
}

export interface LocalityConfiguration {
  bhk: string;
  count: number;
  medianAsking: number;
  p25: number | null;
  p75: number | null;
  qoqPct: number | null;
}

export interface LocalityTrendPoint {
  period: LocalityPeriod;
  medianAsking: number;
  count: number;
}

export interface LocalityDetail {
  slug: string;
  city: string;
  locality: string;
  listingType: LocalityListingType;
  period: LocalityPeriod;
  headline: {
    count: number;
    medianAsking: number;
    p25: number | null;
    p75: number | null;
    medianPerSqft: number | null;
    qoqPct: number | null;
  };
  byConfiguration: LocalityConfiguration[];
  trend: LocalityTrendPoint[];
  sampleFloor: number;
}

export interface LocalityDetailParams {
  listingType?: LocalityListingType;
}

export interface LocalityDetailResponse {
  success?: boolean;
  data: LocalityDetail;
  sampleFloor?: number;
}

/**
 * `GET /localities/guidance` — the one line the listing form shows while an
 * owner is typing a price. `city` and `locality` are both required (400
 * LOCATION_REQUIRED without them); `bhk` narrows the comparison and is what
 * makes `scope` read `configuration` rather than `locality`.
 */
export interface PriceGuidanceParams {
  city?: string;
  locality?: string;
  listingType?: LocalityListingType;
  bhk?: string;
}

export interface PriceGuidance {
  scope: 'configuration' | 'locality';
  bhk: string | null;
  city: string;
  locality: string;
  period: LocalityPeriod;
  count: number;
  low: number;
  median: number;
  high: number;
}

/** 200 with `data: null` when there is nothing to compare against. */
export interface PriceGuidanceResponse {
  success?: boolean;
  data: PriceGuidance | null;
  sampleFloor: number;
}
