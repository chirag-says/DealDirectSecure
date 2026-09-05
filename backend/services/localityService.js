import LocalityStat, { SAMPLE_FLOOR } from "../models/LocalityStat.js";
import {
  bhkBucket,
  localitySlug,
  normalizeListingType,
  percentChange,
  quarterOf,
} from "../utils/locality.js";

/**
 * Reading the locality statistics (Phase 4, F18 + F19).
 *
 * Every function here returns `null` rather than a number it cannot stand
 * behind. The three ways that happens, all deliberate:
 *
 *   the locality has fewer than SAMPLE_FLOOR listings, so the row exists but
 *   is not published;
 *   the listing carries no city, locality, or configuration we can bucket;
 *   there is no row for the current quarter yet, because the aggregation has
 *   not run since this locality first had listings.
 *
 * A caller that gets null renders nothing. It never renders a zero, an
 * estimate, or "data unavailable" dressed up as insight.
 */

/** The published row for a bucket, current quarter, falling back one quarter. */
async function publishedRow({ city, locality, listingType, bhk, at = new Date() }) {
  const type = normalizeListingType(listingType);
  if (!city || !locality || !type) return null;

  const period = quarterOf(at);
  // The current quarter first; early in a quarter it may not exist yet, and
  // last quarter's median is a better answer than silence.
  const rows = await LocalityStat.find({
    city,
    locality,
    listingType: type,
    bhk,
    published: true,
    period: { $lte: period },
  })
    .sort({ period: -1 })
    .limit(1)
    .lean();

  return rows[0] || null;
}

/**
 * "This 2BHK asks 8% below the Wakad median" (F19).
 *
 * Tries the property's own bedroom bucket first, because comparing a 1BHK
 * against a locality full of 4BHKs says nothing. Falls back to the locality
 * headline only when the specific bucket is unpublished, and says which one
 * it used so the client can word it honestly.
 */
export async function localityMedianFor(property, { at = new Date() } = {}) {
  const city = property?.city || property?.address?.city || "";
  const locality = property?.locality || property?.address?.area || "";
  const bucket = bhkBucket(property?.bhk);

  const specific = bucket
    ? await publishedRow({ city, locality, listingType: property?.listingType, bhk: bucket, at })
    : null;
  const row = specific || (await publishedRow({ city, locality, listingType: property?.listingType, bhk: "all", at }));
  if (!row) return null;

  const price = property?.price;
  return {
    scope: row.bhk === "all" ? "locality" : "configuration",
    bhk: row.bhk,
    city: row.city,
    locality: row.locality,
    slug: row.slug,
    period: row.period,
    count: row.count,
    medianAsking: row.medianAsking,
    p25: row.p25,
    p75: row.p75,
    qoqPct: row.qoqPct,
    /** Negative means this listing asks less than the median. */
    deltaPct: Number.isFinite(price) ? percentChange(row.medianAsking, price) : null,
  };
}

/**
 * What similar homes ask, for the owner filling in the listing form (F19).
 *
 * Deliberately a RANGE, not a recommendation. The platform has no business
 * telling an owner what their home is worth; it can tell them what the homes
 * around them are asking, which is a fact, and let them decide. The band is
 * the interquartile range, so half the comparable listings sit inside it.
 */
export async function priceGuidanceFor({ city, locality, listingType, bhk, at = new Date() } = {}) {
  const bucket = bhkBucket(bhk);
  const row =
    (bucket && (await publishedRow({ city, locality, listingType, bhk: bucket, at }))) ||
    (await publishedRow({ city, locality, listingType, bhk: "all", at }));
  if (!row) return null;

  return {
    scope: row.bhk === "all" ? "locality" : "configuration",
    bhk: row.bhk,
    city: row.city,
    locality: row.locality,
    period: row.period,
    count: row.count,
    low: row.p25,
    median: row.medianAsking,
    high: row.p75,
  };
}

/**
 * A whole locality page (F18): the headline row, every configuration, and
 * the quarters behind it for the trend line.
 */
export async function localityPage(slug, { listingType = "sale", quarters = 6, at = new Date() } = {}) {
  const type = normalizeListingType(listingType) || "sale";
  const period = quarterOf(at);

  const current = await LocalityStat.find({ slug, listingType: type, published: true, period: { $lte: period } })
    .sort({ period: -1 })
    .limit(40)
    .lean();

  if (!current.length) return null;

  const latestPeriod = current[0].period;
  const latest = current.filter((r) => r.period === latestPeriod);
  const headline = latest.find((r) => r.bhk === "all");
  if (!headline) return null;

  const trend = await LocalityStat.find({ slug, listingType: type, bhk: "all", published: true })
    .sort({ period: -1 })
    .limit(quarters)
    .lean();

  return {
    slug,
    city: headline.city,
    locality: headline.locality,
    listingType: type,
    period: latestPeriod,
    headline: {
      count: headline.count,
      medianAsking: headline.medianAsking,
      p25: headline.p25,
      p75: headline.p75,
      medianPerSqft: headline.medianPerSqft,
      qoqPct: headline.qoqPct,
    },
    byConfiguration: latest
      .filter((r) => r.bhk !== "all")
      .sort((a, b) => a.bhk.localeCompare(b.bhk))
      .map((r) => ({
        bhk: r.bhk,
        count: r.count,
        medianAsking: r.medianAsking,
        p25: r.p25,
        p75: r.p75,
        qoqPct: r.qoqPct,
      })),
    trend: trend
      .slice()
      .reverse()
      .map((r) => ({ period: r.period, medianAsking: r.medianAsking, count: r.count })),
    sampleFloor: SAMPLE_FLOOR,
  };
}

export { localitySlug };
