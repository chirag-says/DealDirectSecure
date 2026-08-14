/**
 * Compare properties — ported from `PropertyListContent.jsx`
 * (`toggleCompare`/`compareIds`, ~L310–539, and the modal at L2221–2521).
 *
 * ---------------------------------------------------------------------------
 * WHY THIS COMPARES `PropertySummary`, NOT `PropertyDetail`
 *
 * The obvious version fetches each selected listing's full detail for a
 * richer spec table. `GET /properties/:id` increments that listing's view
 * counter on every call (`usePropertyDetail`'s doc block, `features/
 * properties/hooks.ts`) — the one behavioural signal this backend records,
 * and Popular Listings ranks on it. Comparing three listings would silently
 * inflate three view counts for an action that is not a real view. So this
 * stays on `PropertySummary`, already in memory from the search results the
 * user is comparing FROM. The row set is smaller than the website's
 * (no amenities, parking, facing — those live only on `raw`), and that is the
 * honest trade for not touching the view counter.
 *
 * ---------------------------------------------------------------------------
 * WHY "SAME TYPE" MEANS `categoryName`, NOT THE WEBSITE'S REGEX
 *
 * The website infers residential-vs-commercial from a regex over a computed
 * type label. `categoryName` is the correct denormalised field for exactly
 * that distinction (see `features/search/filters.ts`'s TAXONOMY note) and is
 * already on every `PropertySummary`, so comparing it directly is both
 * simpler and more reliable than re-deriving the same fact from text.
 */

import type { PropertySummary } from '@/features/properties';

export const MAX_COMPARE = 3;
export const MIN_COMPARE = 2;

export function canAddToCompare(
  current: readonly PropertySummary[],
  candidate: PropertySummary
): boolean {
  if (current.some((item) => item.id === candidate.id)) return true; // already in, toggling off
  if (current.length >= MAX_COMPARE) return false;
  const first = current[0];
  if (first && first.categoryName && candidate.categoryName) {
    return first.categoryName.toLowerCase() === candidate.categoryName.toLowerCase();
  }
  return true;
}

export interface CompareRow {
  label: string;
  value: (property: PropertySummary) => string;
}

const EMPTY = '–';

export const COMPARE_ROWS: readonly CompareRow[] = [
  {
    label: 'Type',
    value: (p) => p.propertyTypeName ?? p.subcategoryName ?? p.categoryName ?? EMPTY,
  },
  {
    label: 'BHK / Bedrooms',
    value: (p) => p.bhk || (p.bedrooms ? `${p.bedrooms} BHK` : EMPTY),
  },
  { label: 'Bathrooms', value: (p) => (p.bathrooms ? String(p.bathrooms) : EMPTY) },
  {
    label: 'Area',
    value: (p) => (p.areaSqft ? `${p.areaSqft.toLocaleString('en-IN')} sq.ft` : EMPTY),
  },
  { label: 'Furnishing', value: (p) => p.furnishing || EMPTY },
  { label: 'Construction status', value: (p) => p.constructionStatus || EMPTY },
  { label: 'Negotiable', value: (p) => (p.negotiable ? 'Yes' : 'No') },
];
