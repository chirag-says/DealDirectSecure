/**
 * Related-property suggestions.
 *
 * When a search returns fewer than six properties, the listings page offers a
 * few others that might interest the visitor. This module holds the whole
 * decision: whether to suggest, what to ask the API for, and how to rank what
 * comes back.
 *
 * WHY IT LIVES HERE. The scoring used to sit inline in PropertyListContent.jsx
 * and read from `properties` — the array holding the current search results.
 * That worked while the page fetched an unfiltered `/properties/list?limit=50`
 * and filtered in the browser: `properties` held fifty rows, the matches were a
 * handful of them, and the remainder were the candidate pool.
 *
 * Moving discovery to server-side search made `properties` the match set. The
 * pool became `matches minus matches` — always empty — and the feature stopped
 * rendering without anything failing. Nothing tested it, because the scoring
 * could not be imported without importing a React component.
 *
 * So the pool is now fetched explicitly and the ranking is a pure function that
 * a test can call directly.
 */

/** Suggest only when the search returned fewer than this many properties. */
export const RELATED_THRESHOLD = 6;

/** How many suggestions to show. */
export const RELATED_LIMIT = 6;

/**
 * How many candidates to pull for ranking.
 *
 * Fifty is not arbitrary: it is the size of the pool the old client-side
 * version happened to rank, so suggestions stay as varied as they were. The
 * search endpoint caps `limit` at 60, so this is within bounds.
 */
export const RELATED_POOL_SIZE = 50;

/** Below this score a candidate is not related enough to show. */
export const RELEVANCE_CUTOFF = 15;

/**
 * Classify a property as residential or commercial, from whichever of the
 * several shapes the API has used over time.
 */
export function getTypeFlags(property) {
  const categoryName = (
    property.category?.name ||
    property.categoryName ||
    property.category ||
    property.propertyCategory ||
    ""
  ).toString();

  const categoryLower = categoryName.toLowerCase();

  const propertyTypeName = (
    property.propertyTypeName ||
    (typeof property.propertyType === "object"
      ? property.propertyType?.name
      : property.propertyType) ||
    ""
  ).toString();

  const propertyTypeLower = propertyTypeName.toLowerCase();

  const isResidential =
    categoryLower.includes("residen") ||
    /apartment|flat|villa|house|studio|row house|farm house|penthouse|independent|builder\s*floor/i.test(
      propertyTypeLower
    );

  const isCommercial =
    categoryLower.includes("commercial") ||
    /office|shop|showroom|restaurant|cafe|warehouse|industrial|co-working|coworking|commercial|godown|retail/i.test(
      propertyTypeLower
    );

  return { isResidential, isCommercial, propertyTypeName };
}

/** Did the visitor narrow the listing at all? */
export function hasActiveFilters(filters = {}) {
  return Boolean(
    filters.search ||
    filters.city ||
    filters.propertyType ||
    filters.priceRange ||
    filters.availableFor
  );
}

/**
 * Whether to go and fetch candidates.
 *
 * Both halves matter. Without filters there is nothing to be "related" to — the
 * visitor is browsing everything already. With six or more matches the page has
 * enough to show and a second request would be wasted.
 */
export function shouldSuggestRelated(filters, matchCount) {
  return hasActiveFilters(filters) && matchCount < RELATED_THRESHOLD;
}

/**
 * Query parameters for the candidate pool.
 *
 * Deliberately unfiltered apart from the page size. The visitor's filters are
 * what produced too few results, so reapplying them would return the same short
 * list; the ranking below is what re-introduces relevance. This also reproduces
 * what the page used to show — suggestions across other cities, other budgets
 * and both rent and sale.
 */
export function relatedPoolParams() {
  return { page: 1, limit: RELATED_POOL_SIZE };
}

/**
 * Rank candidates against the visitor's search.
 *
 * Weights are unchanged from the original inline version. They are a heuristic
 * tuned against real listings, and this change is about restoring the feature,
 * not re-tuning it.
 *
 * One rule IS new: a residential search never returns commercial property, or
 * the reverse. See the filter below for why that could not be expressed as a
 * weight.
 *
 * @param {Array}  pool           candidates, may overlap `matched`
 * @param {Array}  matched        properties already shown; excluded by _id
 * @param {Object} filters        the visitor's active filters
 * @param {Array}  propertyTypes  taxonomy, to resolve a selected type id
 * @returns {Array} up to RELATED_LIMIT properties, each with `relevanceScore`
 */
export function scoreRelated(pool = [], { matched = [], filters = {}, propertyTypes = [] } = {}) {
  if (!Array.isArray(pool) || pool.length === 0) return [];

  // Compared as strings. Over the wire an `_id` is a string and identity works,
  // but anything holding real ObjectId instances — a server-side render, a
  // script, a future direct query — gets a fresh object per document, so
  // `Set.has` on the raw value silently matches nothing and every already-shown
  // property is suggested back to the visitor.
  const matchedIds = new Set(matched.map((p) => p?._id).filter(Boolean).map(String));
  const query = (filters.search || "").toLowerCase();

  const currentCategory = filters.propertyType
    ? propertyTypes.find((pt) => String(pt._id) === String(filters.propertyType))?.name?.toLowerCase() || ""
    : "";

  const isLookingForResidential =
    currentCategory.includes("residen") ||
    /apartment|flat|villa|house|bhk|penthouse|independent|builder\s*floor|row\s*house|farm\s*house/i.test(query);
  const isLookingForCommercial =
    currentCategory.includes("commercial") ||
    /office|shop|showroom|warehouse|industrial|godown|retail/i.test(query);

  return pool
    .filter((p) => p && p._id && !matchedIds.has(String(p._id)))
    .filter((p) => {
      // Never cross the residential/commercial line.
      //
      // The original weights let this through. Someone searching "4 bhk
      // apartment" in Pune scored a Nagpur shop at exactly 15: ten points for
      // "no rent-or-sale filter" plus five for "some other city" — and fifteen
      // is the cutoff. So an office could be suggested to a family looking for
      // a flat, purely from base scores it earned by not being filtered on.
      //
      // This is a rule rather than a weight, because no amount of other
      // relevance makes a warehouse a reasonable answer to a 3 BHK search.
      const { isResidential, isCommercial } = getTypeFlags(p);
      if (isLookingForResidential && isCommercial && !isResidential) return false;
      if (isLookingForCommercial && isResidential && !isCommercial) return false;
      return true;
    })
    .map((p) => {
      let score = 0;
      const { isResidential, isCommercial, propertyTypeName } = getTypeFlags(p);

      // Category, weighted highest.
      if (isLookingForResidential && isResidential) score += 30;
      if (isLookingForCommercial && isCommercial) score += 30;
      if (!isLookingForResidential && !isLookingForCommercial) score += 10;

      // Rent vs sale.
      if (filters.availableFor && p.listingType?.toLowerCase() === filters.availableFor.toLowerCase()) {
        score += 25;
      } else if (!filters.availableFor) {
        score += 10;
      }

      // City. A different city with the right type is still worth showing.
      if (filters.city) {
        const pCity = (p.address?.city || p.city || "").toLowerCase();
        if (pCity === filters.city.toLowerCase()) score += 20;
        else if (pCity) score += 5;
      } else {
        score += 5;
      }

      // Free text.
      if (query) {
        const pTypeLower = propertyTypeName.toLowerCase();
        const pTitle = (p.title || "").toLowerCase();
        const pBhk = (p.bhk || "").toString().toLowerCase();

        const queryWords = query.split(/\s+/).filter((w) => w.length > 2);
        if (queryWords.some((word) => pTypeLower.includes(word) || pTitle.includes(word))) score += 15;

        if (pTypeLower.includes(query) || pTitle.includes(query) || pBhk.includes(query)) score += 15;

        // "4 bhk" should surface 3 and 5 BHK too, just lower.
        const bhkMatch = query.match(/(\d+)\s*bhk/i);
        if (bhkMatch) {
          const searchBhk = parseInt(bhkMatch[1], 10);
          const propBhk = parseInt(p.bedrooms || p.bhk || "0", 10);
          if (propBhk === searchBhk) score += 20;
          else if (Math.abs(propBhk - searchBhk) === 1) score += 10;
        }
      }

      // Budget proximity.
      if (filters.priceRange) {
        const priceInRupees = Number(p.price) || 0;
        const isLow = priceInRupees < 5000000;
        const isMid = priceInRupees >= 5000000 && priceInRupees <= 15000000;
        const isHigh = priceInRupees > 15000000;

        if (filters.priceRange === "low" && isLow) score += 15;
        else if (filters.priceRange === "mid" && isMid) score += 15;
        else if (filters.priceRange === "high" && isHigh) score += 15;
        else if (
          (filters.priceRange === "low" && isMid) ||
          (filters.priceRange === "mid" && (isLow || isHigh)) ||
          (filters.priceRange === "high" && isMid)
        ) {
          score += 8;
        }
      }

      return { ...p, relevanceScore: score };
    })
    .filter((p) => p.relevanceScore >= RELEVANCE_CUTOFF)
    .sort((a, b) => b.relevanceScore - a.relevanceScore)
    .slice(0, RELATED_LIMIT);
}
