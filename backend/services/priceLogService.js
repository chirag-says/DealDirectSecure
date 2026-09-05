import PriceChange from "../models/PriceChange.js";
import { percentChange } from "../utils/locality.js";

/**
 * The one place a price change is recorded (Phase 1 + 4, engine E4).
 *
 * Every write path that can move a listing's price calls `recordPriceChange`.
 * It is deliberately forgiving and never throws: a price edit that succeeded
 * must not fail because the log did, and a missing log row costs an alert,
 * not correctness. Every caller therefore fires it without awaiting the
 * result inside a `.catch`.
 *
 * It refuses to write a row when nothing moved, so a listing edited fifty
 * times with the same price has one row, and "price history" means what it
 * says.
 */

const positive = (v) => Number.isFinite(v) && v > 0;

function snapshot(property) {
  return {
    listingType: property?.listingType || "",
    city: property?.city || property?.address?.city || "",
    locality: property?.locality || property?.address?.area || "",
    bhk: property?.bhk || "",
    propertyTypeName: property?.propertyTypeName || "",
  };
}

/**
 * @param {object} args
 * @param {object} args.property   the property AFTER the change (or at creation)
 * @param {number|null} args.from  the previous price, null when listing
 * @param {number} args.to         the new price
 * @param {'listed'|'edit'|'admin'} args.source
 * @param {Date} [args.at]
 * @returns {Promise<object|null>} the row, or null when nothing was recorded
 */
export async function recordPriceChange({ property, from, to, source = "edit", at = new Date() }) {
  try {
    if (!property?._id || !positive(to)) return null;

    const previous = positive(from) ? from : null;
    // Same price, or a rounding artefact of a form round-trip: not a change.
    if (previous !== null && Math.round(previous) === Math.round(to)) return null;

    return await PriceChange.create({
      property: property._id,
      owner: property.owner || null,
      from: previous,
      to,
      deltaPct: previous === null ? null : percentChange(previous, to),
      at,
      source,
      ...snapshot(property),
    });
  } catch (err) {
    console.error("[priceLog] failed to record price change:", err.message);
    return null;
  }
}

/**
 * The price story of one listing, for the detail screen (F19).
 *
 * Returns the listing row's date (so "days listed" is honest even for a
 * listing whose price never moved), the changes since, and the most recent
 * drop, which is what the copy leads with.
 */
export async function priceHistoryFor(propertyId, { limit = 10 } = {}) {
  const rows = await PriceChange.find({ property: propertyId })
    .sort({ at: -1 })
    .limit(limit + 1)
    .lean();

  if (!rows.length) return { listedAt: null, changes: [], lastDrop: null, daysListed: null };

  const listedRow = rows.find((r) => r.from === null) || null;
  const changes = rows
    .filter((r) => r.from !== null)
    .slice(0, limit)
    .map((r) => ({ from: r.from, to: r.to, deltaPct: r.deltaPct, at: r.at }));

  const lastDrop = changes.find((c) => Number.isFinite(c.deltaPct) && c.deltaPct < 0) || null;
  const listedAt = listedRow?.at || null;

  return {
    listedAt,
    daysListed: listedAt ? Math.floor((Date.now() - new Date(listedAt).getTime()) / 86400000) : null,
    changes,
    lastDrop,
  };
}
