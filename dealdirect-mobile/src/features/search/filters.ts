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
 * TAXONOMY, CITY, FURNISHING, CONSTRUCTION STATUS — updated 2026-08-08.
 *
 * The reasoning above (category/property-type params being unusable, city
 * being exact-and-case-sensitive) is still true of the SERVER-SIDE `category`,
 * `subcategory`, `propertyType` and `city` query params. None of that changed.
 *
 * What changed is where the filtering happens. `usePopularListings`
 * (`features/home/usePopularListings.ts`) already established the accepted
 * pattern for this exact situation: fetch one bounded page from the paginated
 * `/properties/search` endpoint (`limit=100`, never the unbounded
 * `/property-list` or `/filter` — see `MOBILE_APP_ARCHITECTURE_PLAN.md` §7
 * rule 18) and do the real filtering client-side over rows already in hand.
 * The live corpus is 36 listings (§5.5 of `docs/HANDOFF.md`), so one page of
 * 100 covers all of it today, same ceiling `usePopularListings` documents.
 *
 * That pattern resolves the taxonomy problem outright: `categoryName` is the
 * denormalised STRING field, confirmed correct on every row in the original
 * audit. The corruption was only ever in the `category`/`propertyType`
 * ObjectId REFS, which a client-side string match never touches. So a
 * Residential/Commercial filter is safe to offer now — see `CATEGORY_OPTIONS`
 * and `matchesCategory` below.
 *
 * City gets the same treatment, reusing the alias table `features/home/
 * cities.ts` already built for the "Explore by City" tile counts, for the
 * identical reason: `address.city` still has "Bangalore"/"Bengaluru",
 * "Kolkata"/"kolkata" duplicates in production, and a raw equality match would
 * still under-return. `matchCity` merges those before comparing, so the filter
 * behaves the way a user expects a "Bangalore" filter to behave. See
 * `CITY_OPTIONS` and `matchesCity`.
 *
 * `furnishing` turned out to be a real schema field (`Property.furnishing`,
 * `String`) with a real fixed set of values — the add/edit listing form
 * (`features/listings/components/ListingForm.tsx:417`) writes exactly
 * `Unfurnished` / `Semi-furnished` / `Fully furnished` and nothing else. Not
 * the field the website's own broken filter reads (it checks the nonexistent
 * `furnishingStatus`), but the real one. Exact match is safe here because the
 * value set is closed by the form that writes it.
 *
 * `constructionStatus` is real but free text (no enum), typed by an owner
 * against a placeholder suggestion ("Ready to move / Under construction") in
 * the same form. An exact match against free text would fail the same way the
 * website's own broken filters do, so this one is a best-effort keyword match
 * (`matchesConstructionStatus`), not an equality check — documented as such so
 * nobody mistakes it for a closed enum later.
 *
 * None of this required a `/properties/search` param that does not exist, and
 * none of it calls an unbounded endpoint. It is the same rule the earlier
 * version of this comment established, applied with one more year of
 * hindsight: filter on data proven correct, over rows already fetched.
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
 * about one pixel wide.
 *
 * (Corrected 2026-08-13: this note used to say the backend had no
 * `listingType` param, which stopped being true when `ab5ec1b` added one —
 * `toSearchParams` sends it below. So the price axis CAN now be scoped to
 * rent or sale, and a slider is worth revisiting. Note the param is committed
 * but not yet deployed; against the live API it is ignored, so rent and sale
 * results are currently unsplit in production regardless of what is sent.)
 *
 * Bands are inclusive at both ends server-side (`$gte` / `$lte`), so a listing
 * priced exactly on a boundary appears in both adjacent bands. Only one band is
 * selectable at a time, so no user sees the duplicate.
 */

import { CITIES, matchCity, type City } from '@/features/home';
import type { ListingIntent, PropertySummary } from '@/features/properties';
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

  /**
   * The five fields below are CLIENT-ONLY. They are never sent as
   * `/properties/search` query params — see the TAXONOMY/CITY/FURNISHING/
   * CONSTRUCTION STATUS block above for why. `toSearchParams` deliberately
   * ignores them; `hasClientOnlyFilters` is what tells the search hook to
   * switch into the bounded-fetch-and-filter mode instead.
   */
  /** `City.id` from `features/home/cities.ts`, or undefined for any city. */
  city?: string;
  /** Exact `categoryName` match: `'Residential' | 'Commercial'`. */
  categoryName?: string;
  /** Exact `furnishing` match, one of `FURNISHING_OPTIONS`. */
  furnishing?: string;
  /** Best-effort keyword match against free-text `constructionStatus`. */
  constructionStatus?: string;
  /** `BhkOption.value` — `'0'` for 1 RK, `'1'`…`'3'` exact, `'4'` for 4 and up. */
  bhk?: string;
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
 * The band a given rupee amount falls in.
 *
 * Added for the affordability tool, which produces a budget and has to hand
 * the results screen something it can filter by. Bands are inclusive at both
 * ends (see the PRICE note above), so an amount exactly on a boundary matches
 * the lower band — `find` returns the first, and the lower one is the honest
 * answer for a budget: someone who can afford exactly ₹1 crore should be shown
 * the range that ends there, not the one that starts there.
 */
export function bandForPrice(rupees: number): PriceBand | undefined {
  if (!(rupees > 0)) return undefined;

  return PRICE_BANDS.find(
    (band) =>
      (band.from === undefined || rupees >= band.from) &&
      (band.to === undefined || rupees <= band.to)
  );
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
  let count = filters.priceBand ? 1 : 0;
  if (filters.city) count += 1;
  if (filters.categoryName) count += 1;
  if (filters.furnishing) count += 1;
  if (filters.constructionStatus) count += 1;
  if (filters.bhk) count += 1;
  return count;
}

// --- Client-only filters: city, category, furnishing, construction status -

export const CATEGORY_OPTIONS: readonly { label: string; value: string }[] = [
  { label: 'Residential', value: 'Residential' },
  { label: 'Commercial', value: 'Commercial' },
];

export const FURNISHING_OPTIONS: readonly { label: string; value: string }[] = [
  { label: 'Unfurnished', value: 'Unfurnished' },
  { label: 'Semi-furnished', value: 'Semi-furnished' },
  { label: 'Fully furnished', value: 'Fully furnished' },
];

/**
 * Two buckets over free text, not an enum. `matchesConstructionStatus` below
 * decides membership by keyword, since the field itself has no fixed values.
 */
export const CONSTRUCTION_STATUS_OPTIONS: readonly { label: string; value: string }[] = [
  { label: 'Ready to move', value: 'ready' },
  { label: 'Under construction', value: 'construction' },
];

/**
 * Configuration, the facet every Indian property portal leads with.
 *
 * 99acres, NoBroker and Housing all put BHK in the first row of quick filters,
 * ahead of budget on two of the three. We had no equivalent at all, so a buyer
 * who wanted a 2 BHK had to type it into the free-text field and hope the regex
 * caught it — which it does, against `title`, but only for listings whose title
 * happens to spell it the same way.
 *
 * Client-only, and it has to be. `/properties/search` has no `bhk` or
 * `bedrooms` param (see the accepted-params block at the top of this file), and
 * the two fields it would read are inconsistent in the corpus: `bhk` is a
 * string written by the add-listing form ("2 BHK", "5+ BHK", "1 RK") and
 * `bedrooms` is a number that some rows carry instead. `bhkCount` below
 * reconciles them into one integer so the filter does not have to care which
 * one a given row used.
 *
 * `'4'` is a 4-AND-UP bucket rather than exactly four, matching what NoBroker's
 * "4+ BHK" and Housing's "4+" chips mean. A user filtering for a large home is
 * not excluding a five-bedroom one.
 */
export const BHK_OPTIONS: readonly { label: string; value: string }[] = [
  { label: '1 RK', value: '0' },
  { label: '1 BHK', value: '1' },
  { label: '2 BHK', value: '2' },
  { label: '3 BHK', value: '3' },
  { label: '4+ BHK', value: '4' },
];

/**
 * The listing's bedroom count as an integer, or null when it carries neither
 * field.
 *
 * `bhk` is preferred over `bedrooms` because it is what the add-listing form
 * writes and is present on more rows. "1 RK" is a real configuration in the
 * data and means zero separate bedrooms, so it is matched before the digit
 * scan — otherwise the `1` in "1 RK" reads as a 1 BHK, which is a different
 * (and more expensive) thing.
 */
export function bhkCount(item: PropertySummary): number | null {
  const raw = item.bhk?.trim();

  if (raw) {
    if (/\brk\b/i.test(raw)) return 0;
    const digits = raw.match(/\d+/);
    if (digits) return Number(digits[0]);
  }

  if (typeof item.bedrooms === 'number') return item.bedrooms;

  return null;
}

function matchesBhk(item: PropertySummary, bucket: string): boolean {
  const count = bhkCount(item);
  if (count === null) return false;

  const wanted = Number(bucket);
  // The top bucket is open-ended; every other one is exact.
  return wanted >= 4 ? count >= 4 : count === wanted;
}

/** `City.id` + label, for the filter sheet's city chips. */
export const CITY_OPTIONS: readonly { label: string; value: string }[] = CITIES.map(
  (city: City) => ({ label: city.label, value: city.id })
);

/** True when any filter that requires the bounded fetch-and-filter mode is set. */
export function hasClientOnlyFilters(filters: SearchFilters): boolean {
  return Boolean(
    filters.city ||
      filters.categoryName ||
      filters.furnishing ||
      filters.constructionStatus ||
      filters.bhk
  );
}

function matchesCity(item: PropertySummary, cityId: string): boolean {
  const matched = matchCity(item.city);
  return matched?.id === cityId;
}

function matchesCategory(item: PropertySummary, categoryName: string): boolean {
  return (item.categoryName ?? '').toLowerCase() === categoryName.toLowerCase();
}

function matchesFurnishing(item: PropertySummary, furnishing: string): boolean {
  return (item.furnishing ?? '').toLowerCase() === furnishing.toLowerCase();
}

/**
 * Keyword match, not equality — see the CONSTRUCTION STATUS note above. A
 * listing whose owner wrote "Ready to move, water connection pending" still
 * counts as "Ready to move"; one that never mentions either keyword matches
 * neither bucket rather than being guessed into one.
 */
function matchesConstructionStatus(item: PropertySummary, bucket: string): boolean {
  const raw = (item.constructionStatus ?? '').toLowerCase();
  if (!raw) return false;
  if (bucket === 'ready') return raw.includes('ready');
  if (bucket === 'construction') return raw.includes('construction') || raw.includes('under');
  return false;
}

/** Applies every client-only filter currently set. Server-side filters
 *  (query, listingType, price, sort) are assumed already applied upstream —
 *  this only covers the fields `toSearchParams` cannot send. */
export function matchesClientFilters(item: PropertySummary, filters: SearchFilters): boolean {
  if (filters.city && !matchesCity(item, filters.city)) return false;
  if (filters.categoryName && !matchesCategory(item, filters.categoryName)) return false;
  if (filters.furnishing && !matchesFurnishing(item, filters.furnishing)) return false;
  if (
    filters.constructionStatus &&
    !matchesConstructionStatus(item, filters.constructionStatus)
  ) {
    return false;
  }
  if (filters.bhk && !matchesBhk(item, filters.bhk)) return false;
  return true;
}

export function hasAnyCriteria(filters: SearchFilters): boolean {
  return (
    filters.query.trim().length > 0 ||
    Boolean(filters.listingType) ||
    countActiveFilters(filters) > 0
  );
}

/**
 * The rent/sale axis, as a segmented control on the results rail.
 *
 * "Buy" and "Rent", not "For sale" and "For rent". Three reasons, in order of
 * weight:
 *
 *  1. It is what Home's hero already says. A user who tapped "Buy" there and
 *     lands on a control reading "For sale" has to work out that the two are
 *     the same thing.
 *  2. It is the verb, and this control is the user choosing what they are
 *     doing rather than describing the listing. Housing and 99acres both label
 *     it this way for the same reason.
 *  3. It fits. The three labels sit on a rail with six facet pills after them,
 *     and "For sale"/"For rent" cost about 60pt more — enough to push Sort and
 *     Budget entirely off the first screen, which defeats the rail.
 *
 * The card and the detail badge still say "For sale" / "For rent", and that is
 * correct: those DESCRIBE a listing rather than offering a choice.
 */
export const LISTING_TYPE_OPTIONS: readonly { label: string; value: ListingIntent | undefined }[] = [
  { label: 'All', value: undefined },
  { label: 'Buy', value: 'sale' },
  { label: 'Rent', value: 'rent' },
];
