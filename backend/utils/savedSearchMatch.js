import { escapeRegExp } from "./escapeRegExp.js";

/**
 * Which saved searches a property matches (Phase 1, F8).
 *
 * Extracted so the two callers share one implementation: the fan-out when a
 * listing is created, and the price-drop scan, which asks the same question
 * about a listing that already existed. Before this, the matching rules lived
 * in two copies inside propertyController and had already drifted — one
 * filtered on city and price, the other on city alone.
 *
 * THE SEMANTICS ARE PRESERVED EXACTLY, including one that looks like a bug.
 * The original comparison was `lower(propertyCity) === lower(savedCity)`:
 * case-insensitive, anchored, and NOT trimmed, so " Pune" does not match
 * "Pune". The anchored regex with `i` reproduces all three. Making it trim
 * would silently widen who gets notified, which is a product change rather
 * than a refactor, and would do it to every existing saved search at once.
 */

/** The indexed half: a filter that finds candidate searches for a property. */
export function candidateSearchFilter(property, extra = {}) {
  const city = property?.address?.city || "";
  return {
    isActive: true,
    ...extra,
    $or: [
      { "filters.city": { $in: ["", null] } },
      { "filters.city": { $exists: false } },
      { "filters.city": { $regex: `^${escapeRegExp(city)}$`, $options: "i" } },
    ],
  };
}

/**
 * The price bucket, in JavaScript.
 *
 * It compares against three hard-coded thresholds rather than a stored bound,
 * so there is no indexable predicate to push into Mongo; expressing it as
 * `$lt`/`$gte` clauses would be more code saying the same thing, further from
 * the buckets it encodes.
 *
 * A search with no `priceRange`, or a property with no numeric price, skips
 * the test — which is what the original code did.
 */
export function priceBucketMatches(priceRange, price) {
  if (!priceRange || typeof price !== "number") return true;
  if (priceRange === "low") return price < 5000000;
  if (priceRange === "mid") return price >= 5000000 && price <= 15000000;
  if (priceRange === "high") return price > 15000000;
  return false;
}

/** The full predicate for one candidate search against one property. */
export function searchMatchesProperty(search, property) {
  return priceBucketMatches(search?.filters?.priceRange, property?.price);
}

/**
 * Does a price MOVE change whether a search matches? (Phase 1, F9.)
 *
 * A drop from ₹1.6 Cr to ₹1.4 Cr moves a listing out of "high" and into
 * "mid", so a watcher of "mid" who never saw this listing should now hear
 * about it. This is what makes a price-drop alert reach people who are not
 * already watching the listing, without spamming everyone every time.
 */
export function crossedIntoBucket(priceRange, from, to) {
  if (!priceRange) return false;
  return !priceBucketMatches(priceRange, from) && priceBucketMatches(priceRange, to);
}
