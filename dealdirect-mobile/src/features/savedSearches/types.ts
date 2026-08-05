/**
 * Saved searches, as the UI consumes them.
 *
 * ---------------------------------------------------------------------------
 * READ THIS BEFORE ADDING A FILTER TO THE SAVE SHEET
 *
 * A saved search is worth nothing unless the alert matcher can match it, and
 * that matcher — inlined at propertyController.js:484 — understands far less
 * than the model stores. Verified against that code, not the schema:
 *
 *   city          WORKS. Exact, case-insensitive, against `address.city`.
 *                 Inherits the live spelling problem: a search saved for
 *                 "Bengaluru" never matches a listing stored as "Bangalore",
 *                 and both spellings exist in production today.
 *
 *   priceRange    WORKS, but only as "low" | "mid" | "high". Any other value
 *                 is truthy, matches no band, and silently kills the search.
 *
 *   availableFor  HALF WORKS. Compared to `listingType.toLowerCase()` exactly,
 *                 and the schema holds three spellings of for-sale (`Sell`,
 *                 `Sale`, `sale`). Saving "sale" misses every listing stored
 *                 as "Sell", which is most of them. Only "rent" is reliable.
 *
 *   propertyType  NOT OFFERED. Compared against the `propertyType` ObjectId,
 *                 and those refs are null on 15 of 36 live listings and wrong
 *                 on the rest.
 *
 *   search        NEVER MATCHES. Stored, validated, capped at 200 characters,
 *                 and then not read by the matcher at all.
 *
 * So the sheet offers city, price band and rent-only intent. Adding anything
 * else means fixing the matcher first.
 */

import type { SavedSearchPriceBand } from '@/types/backend/savedSearch';

export type { SavedSearchPriceBand };

/** The flat shape a row renders from. */
export interface SavedSearchSummary {
  id: string;
  /** HTML entities decoded. The backend stores the name `.escape()`d. */
  name: string;
  /** Pre-composed description of the filters, e.g. "Mumbai · Under ₹50 Lakh". */
  description: string;
  city?: string;
  priceBand?: SavedSearchPriceBand;
  availableFor?: string;
  /** True when this search cannot alert on anything the matcher reads. */
  isInert: boolean;
  notifyEmail: boolean;
  notifyInApp: boolean;
  updatedAt?: string;
}

export const PRICE_BAND_LABELS: Record<SavedSearchPriceBand, string> = {
  low: 'Under ₹50 Lakh',
  mid: '₹50 Lakh to ₹1.5 Crore',
  high: 'Above ₹1.5 Crore',
};

export const PRICE_BAND_ORDER: SavedSearchPriceBand[] = ['low', 'mid', 'high'];
