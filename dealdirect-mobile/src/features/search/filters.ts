/**
 * Search filter state, and its projection onto the backend's query params.
 *
 * Every field here maps to a param `searchProperties` reads AND that live data
 * actually responds to. Both halves were checked; the second half is where most
 * of this file's reasoning went, because several params the controller accepts
 * do nothing useful against the production database.
 *
 * ---------------------------------------------------------------------------
 * WHAT `/properties/search` ACCEPTS
 * (backend/controllers/propertyController.js:1811, read 2026-08-03; every claim
 * below was then probed against https://backend.dealdirect.in on the same day,
 * against a corpus of 36 approved listings.)
 *
 *   search        regex over title, description, address.city, address.area,
 *                 address.locality. Case-insensitive, escaped server-side.
 *                 VERIFIED: "Apartment" → 16, "Showroom" → 2, "Bengaluru" → 6.
 *                 SHIPPED.
 *
 *   priceFrom     price >= n, on the raw `price` column, in rupees.
 *   priceTo       price <= n.
 *                 VERIFIED: priceTo=100000 → 21, priceFrom=5000000 → 8, against
 *                 a baseline of 36. Consistent with `price` holding rupees.
 *                 SHIPPED, as bands — see PRICE below.
 *
 *   sort          newest | priceAsc | priceDesc. SHIPPED.
 *   page, limit   offset paging, limit defaults to 12. SHIPPED.
 *
 *   category      exact ObjectId match. NOT SHIPPED — see TAXONOMY below.
 *   subcategory   exact ObjectId match. NOT SHIPPED — same reason.
 *   propertyType  exact ObjectId match. NOT SHIPPED — same reason.
 *   city          exact, CASE-SENSITIVE match on `address.city`.
 *                 NOT SHIPPED — see CITY below.
 *   buildingType  NOT SHIPPED — the field does not exist on the schema.
 *   size          NOT SHIPPED — the field does not exist on the schema.
 *
 * ---------------------------------------------------------------------------
 * TAXONOMY: why there are no category / property-type filters.
 *
 * The three ObjectId filters work exactly as written. The DATA they filter on
 * does not. On the live corpus:
 *
 *   - `category`, `subcategory` and `propertyType` come back `null` on 15 of 36
 *     listings, despite the controller populating all three.
 *   - The other 21 all carry the SAME `propertyType` id — the one for "Plot" —
 *     while their own `propertyTypeName` reads "Apartment / Flat", "Penthouse",
 *     and so on. The ref points at the wrong document.
 *   - Probing all 19 categories, exactly two match anything: "Residential Plot"
 *     (17 listings) and "Commercial Land" (4). Every other category returns 0.
 *
 * So a category picker would offer 19 options of which 17 return an empty list
 * and 2 return the wrong listings. The denormalised `categoryName` and
 * `propertyTypeName` strings ARE correct on every row, but no param filters on
 * them.
 *
 * This is a backend data-integrity problem, not an API limitation: backfilling
 * the refs from the denormalised names would make all three filters work with
 * no code change here. Until that happens, offering them would be worse than
 * offering nothing, because an empty result reads to a user as "no such
 * property" rather than "this filter is broken".
 *
 * ---------------------------------------------------------------------------
 * CITY: why there is no city picker.
 *
 * `city` is an exact, case-sensitive match on `address.city`: "Pune" returns 3
 * and "pune" returns 0. Using it safely needs a canonical list of cities, and
 * the only source of one is loading every property and collecting distinct
 * values — the unbounded call this app does not make. The website does exactly
 * that, which is why it has a city dropdown and this does not.
 *
 * Free text covers the same ground and covers it better: the `search` regex
 * already runs over `address.city` and `address.area`, case-insensitively.
 *
 * ---------------------------------------------------------------------------
 * PRICE: bands, not a slider.
 *
 * `price` holds rupees, and `priceUnit` does NOT scale it — it carries the
 * schema default "Lac" on most rows regardless of the value beside it. The full
 * evidence is in `src/ui/PriceLabel.tsx`; the filter and the label agree on
 * this, which is the point.
 *
 * Bands rather than a range slider because one linear axis has to cover both
 * ₹8,000 rentals and ₹5 crore sales — a slider makes the entire rental range
 * about one pixel wide. The backend has no `listingType` param to split the two
 * populations, so the axis cannot be scoped. `RangeSlider` stays unused until
 * it can be.
 *
 * Bands are inclusive at both ends server-side (`$gte` / `$lte`), so a listing
 * priced exactly on a boundary appears in both adjacent bands. Only one band is
 * selectable at a time, so no user sees the duplicate.
 */

import type { ListingIntent } from '@/features/properties';
import type { PropertySearchParams, PropertySortOrder } from '@/types/backend/property';

const LAKH = 100_000;
const CRORE = 10_000_000;

export interface PriceBand {
  id: string;
  label: string;
  from?: number;
  to?: number;
}

/**
 * Bands in rupees. A table rather than a chain of conditionals, so adding one
 * is a data change and the labels cannot drift from the bounds they describe.
 */
export const PRICE_BANDS: readonly PriceBand[] = [
  { id: 'under-1l', label: 'Under ₹1 Lakh', to: LAKH },
  { id: '1l-25l', label: '₹1 – 25 Lakh', from: LAKH, to: 25 * LAKH },
  { id: '25l-1cr', label: '₹25 Lakh – ₹1 Crore', from: 25 * LAKH, to: CRORE },
  { id: '1cr-5cr', label: '₹1 – 5 Crore', from: CRORE, to: 5 * CRORE },
  { id: 'above-5cr', label: 'Above ₹5 Crore', from: 5 * CRORE },
];

export interface SearchFilters {
  /** Free text. Note the param is `search`, NOT `q`. */
  query: string;
  /**
   * Rent versus sale. Undefined means both.
   *
   * Kept OUT of the filter sheet on purpose. It is the primary axis of a
   * property search, and it is what the Home hero cards preselect, so a user
   * arriving from "For Rent" must be able to see and change it without opening
   * a sheet to find out why the results look the way they do. It lives as a
   * permanently visible control on the results screen instead, and is excluded
   * from `countActiveFilters` for the same reason.
   */
  listingType?: ListingIntent;
  /** `PriceBand.id`, or undefined for any price. */
  priceBand?: string;
  sort: PropertySortOrder;
}

export const DEFAULT_FILTERS: SearchFilters = {
  query: '',
  sort: 'newest',
};

export const SORT_OPTIONS: readonly { label: string; value: PropertySortOrder }[] = [
  { label: 'Newest first', value: 'newest' },
  { label: 'Price: low to high', value: 'priceAsc' },
  { label: 'Price: high to low', value: 'priceDesc' },
];

export function findPriceBand(id: string | undefined): PriceBand | undefined {
  if (!id) return undefined;
  return PRICE_BANDS.find((band) => band.id === id);
}

/**
 * Filters → query params.
 *
 * Empty values are omitted rather than sent blank, both because the controller
 * treats any truthy value as a filter and because an empty string would split
 * the query cache into two entries for the same search.
 */
export function toSearchParams(filters: SearchFilters): PropertySearchParams {
  const params: PropertySearchParams = { sort: filters.sort };

  const query = filters.query.trim();
  if (query) params.search = query;
  if (filters.listingType) params.listingType = filters.listingType;

  const band = findPriceBand(filters.priceBand);
  if (band?.from !== undefined) params.priceFrom = band.from;
  if (band?.to !== undefined) params.priceTo = band.to;

  return params;
}

/**
 * How many filters are applied, for the badge on the filter button.
 *
 * The free-text query is excluded: it is visible in the search field already,
 * and counting it would make the badge read "1" on a plain search with no
 * filters at all. Sort is excluded because it always has a value.
 */
export function countActiveFilters(filters: SearchFilters): number {
  return filters.priceBand ? 1 : 0;
}

export function hasAnyCriteria(filters: SearchFilters): boolean {
  return (
    filters.query.trim().length > 0 ||
    Boolean(filters.listingType) ||
    countActiveFilters(filters) > 0
  );
}

export const LISTING_TYPE_OPTIONS: readonly { label: string; value: ListingIntent | undefined }[] = [
  { label: 'All', value: undefined },
  { label: 'For rent', value: 'rent' },
  { label: 'For sale', value: 'sale' },
];
