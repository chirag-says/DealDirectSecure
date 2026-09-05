/**
 * Locality identity and price statistics (Phase 1 + 4, engine E4).
 *
 * Pure functions. The aggregation job and the public pages both go through
 * these, so a locality is named and bucketed in exactly one way.
 */

/** Everything the public pages key on, derived from free text an owner typed. */
export function localitySlug(city, locality) {
  return [city, locality]
    .map((part) =>
      String(part || "")
        .toLowerCase()
        .normalize("NFKD")
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "")
    )
    .filter(Boolean)
    .join("-");
}

/**
 * Bedroom bucket. `bhk` on a Property is free text ("2", "2 BHK", "2bhk",
 * "3+1"), so the first integer in the string is the signal and anything at or
 * above four collapses into one bucket, where the sample is always thin.
 */
export function bhkBucket(bhk) {
  const match = /(\d+)/.exec(String(bhk ?? ""));
  if (!match) return null;
  const n = parseInt(match[1], 10);
  if (!Number.isFinite(n) || n <= 0 || n > 20) return null;
  return n >= 4 ? "4+" : String(n);
}

/**
 * `Property.listingType` accepts six spellings ("Rent", "Sell", "Sale",
 * lowercase forms). The statistics have two.
 */
export function normalizeListingType(listingType) {
  const v = String(listingType || "").toLowerCase();
  if (v === "rent") return "rent";
  if (v === "sell" || v === "sale") return "sale";
  return null;
}

/** `YYYY-Qn` for an instant, in IST (the market these numbers describe). */
export function quarterOf(date) {
  const ist = new Date(new Date(date).getTime() + 5.5 * 3600 * 1000);
  return `${ist.getUTCFullYear()}-Q${Math.floor(ist.getUTCMonth() / 3) + 1}`;
}

/** The quarter before `period`. */
export function previousQuarter(period) {
  const m = /^(\d{4})-Q([1-4])$/.exec(period);
  if (!m) return null;
  const year = parseInt(m[1], 10);
  const q = parseInt(m[2], 10);
  return q === 1 ? `${year - 1}-Q4` : `${year}-Q${q - 1}`;
}

/**
 * Median of a numeric array. Sorts a copy; the caller's array is untouched.
 * An even-length sample averages the middle two, which is the definition
 * every reader expects and the one the client can recompute.
 */
export function median(values) {
  const sorted = values.filter((v) => Number.isFinite(v)).sort((a, b) => a - b);
  if (!sorted.length) return null;
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

/**
 * The value below which `pct` of the sample sits, by the nearest-rank method.
 * Nearest rank rather than interpolation because it always returns a price
 * that a real listing actually asks.
 */
export function percentile(values, pct) {
  const sorted = values.filter((v) => Number.isFinite(v)).sort((a, b) => a - b);
  if (!sorted.length) return null;
  const rank = Math.ceil((pct / 100) * sorted.length);
  return sorted[Math.min(sorted.length - 1, Math.max(0, rank - 1))];
}

/** Percent change from `from` to `to`, one decimal. Null when it means nothing. */
export function percentChange(from, to) {
  if (!Number.isFinite(from) || !Number.isFinite(to) || from <= 0) return null;
  return Math.round(((to - from) / from) * 1000) / 10;
}
