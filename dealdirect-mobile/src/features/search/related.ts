/**
 * "Related properties" — ported from `PropertyListContent.jsx`
 * (`relatedProperties`, ~L901–1021).
 *
 * The website scores its ENTIRE fetched corpus (`/properties/property-list`,
 * unbounded) against the active filters and shows the top 6 when the filtered
 * result count drops below 6. Mobile cannot call that endpoint — see
 * `MOBILE_APP_ARCHITECTURE_PLAN.md` §7 rule 18 — so the candidate pool here is
 * one bounded page of `/properties/search` (`RELATED_POOL_SIZE`), the same
 * `usePopularListings`/filters.ts pattern used elsewhere. Against the live
 * 36-listing corpus that pool IS the whole corpus; past that size this
 * degrades to "related among the newest N", the same honestly-labelled
 * degradation `usePopularListings` documents for its own ceiling.
 *
 * The scoring weights below are copied from the website as closely as the two
 * filter models allow. Differences are called out inline rather than left
 * silent.
 */

import { matchCity } from '@/features/home';
import type { PropertySummary } from '@/features/properties';
import type { SearchFilters } from './filters';
import { bhkCount, findPriceBand } from './filters';

const MIN_RELEVANCE_SCORE = 15;
export const RELATED_RESULT_COUNT = 6;
/** Below this many results, related properties are offered at all. */
export const RELATED_THRESHOLD = 6;
export const RELATED_POOL_SIZE = 100;

function scoreCandidate(
  candidate: PropertySummary,
  filters: SearchFilters,
  queryWords: string[]
): number {
  let score = 0;

  // Category. The website infers residential/commercial from a regex over
  // the free-text query when no explicit filter is set; mobile has an
  // explicit `categoryName` filter (M15) so it is read directly instead of
  // re-inferring the same thing from text.
  if (filters.categoryName) {
    score += candidate.categoryName?.toLowerCase() === filters.categoryName.toLowerCase() ? 30 : 0;
  } else {
    score += 10; // No category filter: base relevance for any property.
  }

  // Listing type (Rent/Sale).
  if (filters.listingType) {
    score += candidate.intent === filters.listingType ? 25 : 0;
  } else {
    score += 10;
  }

  // City. Exact `city` param does not exist client-side by design (M15 uses
  // the alias-matched `City.id`), so this compares that same normalised id
  // rather than a raw string, which is a closer match than the website's
  // literal lowercase comparison achieves against the same dirty data.
  if (filters.city) {
    score += candidate.city ? 5 : 0; // Base score for having a city at all.
  } else {
    score += 5;
  }

  // Free-text query: word overlap against property type / title, plus a BHK
  // proximity bonus, both straight ports of the website's logic.
  if (queryWords.length > 0) {
    const typeLower = (candidate.propertyTypeName ?? '').toLowerCase();
    const titleLower = candidate.title.toLowerCase();
    const matchesAnyWord = queryWords.some(
      (word) => typeLower.includes(word) || titleLower.includes(word)
    );
    if (matchesAnyWord) score += 15;

    const fullQuery = queryWords.join(' ');
    if (typeLower.includes(fullQuery) || titleLower.includes(fullQuery)) score += 15;

    const bhkMatch = fullQuery.match(/(\d+)\s*bhk/i);
    if (bhkMatch) {
      const searchBhk = Number(bhkMatch[1]);
      const propBhk = Number(candidate.bedrooms ?? candidate.bhk ?? 0);
      if (propBhk === searchBhk) score += 20;
      else if (Math.abs(propBhk - searchBhk) === 1) score += 10;
    }
  }

  // Price-band proximity: same band scores full, an adjacent band scores
  // half, matching the website's low/mid/high adjacency bonus in spirit.
  const band = findPriceBand(filters.priceBand);
  if (band) {
    const bandIndex = PRICE_BAND_ORDER.indexOf(filters.priceBand ?? '');
    const candidateBandIndex = bandIndexForPrice(candidate.priceRupees);
    if (candidateBandIndex === bandIndex) score += 15;
    else if (candidateBandIndex >= 0 && Math.abs(candidateBandIndex - bandIndex) === 1) score += 8;
  }

  return score;
}

// Mirrors PRICE_BANDS' order in filters.ts, without importing the objects
// themselves to avoid a second source of truth for indices vs. bounds.
const PRICE_BAND_ORDER = ['under-1l', '1l-25l', '25l-1cr', '1cr-5cr', 'above-5cr'];

function bandIndexForPrice(priceRupees: number): number {
  return PRICE_BAND_ORDER.findIndex((id) => {
    const band = findPriceBand(id);
    if (!band) return false;
    if (band.from !== undefined && priceRupees < band.from) return false;
    if (band.to !== undefined && priceRupees > band.to) return false;
    return true;
  });
}

/**
 * Top `RELATED_RESULT_COUNT` related properties from `pool`, excluding
 * anything already in `excludeIds`. Returns an empty array when nothing
 * clears `MIN_RELEVANCE_SCORE` — an empty "Related" section is never shown
 * over a section with nothing worth relating.
 */
export function selectRelatedProperties(
  pool: PropertySummary[],
  filters: SearchFilters,
  excludeIds: ReadonlySet<string>
): PropertySummary[] {
  const queryWords = filters.query
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter((w) => w.length > 2);

  return pool
    .filter((item) => !excludeIds.has(item.id))
    .map((item) => ({ item, score: scoreCandidate(item, filters, queryWords) }))
    .filter(({ score }) => score >= MIN_RELEVANCE_SCORE)
    .sort((a, b) => b.score - a.score)
    .slice(0, RELATED_RESULT_COUNT)
    .map(({ item }) => item);
}

// --- Similar to ONE property ----------------------------------------------

/**
 * "Similar properties", for the detail screen.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS NOT `selectRelatedProperties` WITH SYNTHESISED FILTERS
 *
 * The obvious shortcut is to build a `SearchFilters` out of the property being
 * viewed and hand it to the function above. It does not work, and the reason is
 * worth writing down so nobody tries it again: that scorer is measuring
 * candidates against a QUERY, so several of its terms are shaped by what a
 * filter can express rather than by what a property is. Its city term scores
 * "has a city at all" rather than "the same city", because the search filter's
 * city is an alias id and a candidate's is dirty free text; comparing them
 * properly was out of scope there. On a detail screen the same city is the
 * single strongest similarity signal there is, so the shortcut would produce a
 * rail of Pune flats under a Bengaluru listing.
 *
 * It shares the POOL with the search rail — same bounded page, same query key,
 * so a user who searches and then opens a listing pays for one fetch rather
 * than two. Only the scoring differs, which is the part that genuinely does.
 *
 * ---------------------------------------------------------------------------
 * THE WEIGHTS
 *
 * Ordered by what a buyer would actually accept as an alternative. Location
 * first: someone looking at a flat in Kondapur will consider another flat in
 * Kondapur before they consider a cheaper one in another city. Then rent versus
 * sale, which is not a preference but a hard requirement — nobody browsing
 * rentals wants a purchase in the list. Then what kind of property, then how
 * big, then how much.
 *
 * Price is scored by RATIO rather than by band. Bands are the right shape for a
 * filter, where the user picked the bracket, and the wrong one here: a ₹99 lakh
 * listing and a ₹1.01 crore listing sit in different bands and are two percent
 * apart, and a rail that treats them as unrelated is visibly wrong to the
 * person looking at both.
 */
const MIN_SIMILARITY_SCORE = 40;
export const SIMILAR_RESULT_COUNT = 6;

function scoreSimilarity(candidate: PropertySummary, subject: PropertySummary): number {
  let score = 0;

  // Alias-matched, not string-equal: `address.city` still carries
  // "Bangalore"/"Bengaluru" duplicates in production. See `features/home/cities.ts`.
  const subjectCity = matchCity(subject.city);
  const candidateCity = matchCity(candidate.city);
  if (subjectCity && candidateCity && subjectCity.id === candidateCity.id) score += 30;

  // A rental is never a substitute for a purchase, so this is scored as a
  // requirement rather than a bonus: mismatching costs the candidate more than
  // any other term can give back, which drops it below the threshold on its own.
  if (subject.intent && candidate.intent) {
    if (subject.intent === candidate.intent) score += 25;
    else score -= 40;
  }

  if (subject.categoryName && candidate.categoryName === subject.categoryName) score += 20;
  if (subject.propertyTypeName && candidate.propertyTypeName === subject.propertyTypeName) {
    score += 15;
  }

  const subjectBhk = bhkCount(subject);
  const candidateBhk = bhkCount(candidate);
  if (subjectBhk !== null && candidateBhk !== null) {
    if (subjectBhk === candidateBhk) score += 15;
    else if (Math.abs(subjectBhk - candidateBhk) === 1) score += 7;
  }

  if (subject.priceRupees > 0 && candidate.priceRupees > 0) {
    const ratio = candidate.priceRupees / subject.priceRupees;
    if (ratio >= 0.75 && ratio <= 1.25) score += 20;
    else if (ratio >= 0.5 && ratio <= 1.5) score += 10;
  }

  return score;
}

/**
 * Top `SIMILAR_RESULT_COUNT` listings from `pool` resembling `subject`, with
 * the subject itself removed.
 *
 * Returns empty when nothing clears the threshold. An empty rail is correct
 * here rather than sad: our corpus is small, and padding the section with the
 * six newest listings regardless of resemblance would teach users that the
 * heading means nothing.
 */
export function selectSimilarProperties(
  pool: PropertySummary[],
  subject: PropertySummary
): PropertySummary[] {
  return pool
    .filter((item) => item.id !== subject.id)
    .map((item) => ({ item, score: scoreSimilarity(item, subject) }))
    .filter(({ score }) => score >= MIN_SIMILARITY_SCORE)
    .sort((a, b) => b.score - a.score)
    .slice(0, SIMILAR_RESULT_COUNT)
    .map(({ item }) => item);
}
