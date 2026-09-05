import PriceChange from "../models/PriceChange.js";
import Property from "../models/Property.js";
import SavedSearch from "../models/SavedSearch.js";
import Shortlist from "../models/Shortlist.js";
import { notifyUsers } from "../services/notificationService.js";
import { candidateSearchFilter, crossedIntoBucket } from "../utils/savedSearchMatch.js";

/**
 * Price-drop alerts (Phase 1, F9). Runs every 15 minutes.
 *
 * The single most durable retention mechanic in portal history: Rightmove
 * has fired instant alerts on cuts of 2% or more for twenty-five years. This
 * is that, over DealDirect's own data.
 *
 * WHO HEARS ABOUT A DROP, and why each group:
 *
 *   1. Everyone who shortlisted the listing. They already declared interest
 *      in this exact home; a cut is the event they are waiting for.
 *   2. Everyone whose saved search the listing has just moved INTO. A home
 *      that fell from ₹1.6 Cr to ₹1.4 Cr is now inside a "mid" budget that
 *      never saw it. This is the half that finds new buyers rather than
 *      re-notifying old ones.
 *
 * WHO DOES NOT: the owner, about their own edit. Anyone whose weekly cap is
 * spent, which the dispatcher enforces. Anyone at all, if the listing is no
 * longer publicly viewable — a price cut on a listing that just went to
 * `pending` or `sold` is not an opportunity.
 *
 * IDEMPOTENCE. The cursor is the `at` of the last row processed, not "now",
 * so a run that starts while a price is being written does not skip it. Rows
 * are re-read from the cursor inclusive and de-duplicated by id against the
 * previous run's tail, which is the only way to be exactly-once against a
 * clock that has no ordering guarantee at the millisecond.
 */

/** Rightmove's threshold, and the research's recommendation. */
const MIN_DROP_PCT = 2;
const MAX_ROWS_PER_RUN = 500;
const LOOKBACK_MS = 60 * 60 * 1000;

const HIDDEN_STATUSES = ["pending", "inactive", "sold", "rented", "pending_verification"];

const formatRupees = (n) => {
  if (!Number.isFinite(n)) return "";
  if (n >= 10000000) return `₹${(n / 10000000).toFixed(n % 10000000 === 0 ? 0 : 2)} Cr`;
  if (n >= 100000) return `₹${(n / 100000).toFixed(n % 100000 === 0 ? 0 : 1)} L`;
  return `₹${Math.round(n).toLocaleString("en-IN")}`;
};

export async function scanPriceDrops({ now = new Date(), cursor = null } = {}) {
  // First run: only look back an hour. Without this a fresh deployment would
  // announce every price cut in the history of the platform at once.
  const since = cursor?.at ? new Date(cursor.at) : new Date(now.getTime() - LOOKBACK_MS);
  const seen = new Set(cursor?.ids || []);

  const drops = await PriceChange.find({
    at: { $gte: since, $lte: now },
    deltaPct: { $lte: -MIN_DROP_PCT },
  })
    .sort({ at: 1 })
    .limit(MAX_ROWS_PER_RUN)
    .lean();

  const fresh = drops.filter((d) => !seen.has(String(d._id)));
  if (!fresh.length) {
    return { cursor: { at: since.toISOString(), ids: [...seen].slice(-200) }, drops: 0, notified: 0 };
  }

  const propertyIds = [...new Set(fresh.map((d) => String(d.property)))];
  const properties = await Property.find({ _id: { $in: propertyIds } })
    .select("_id title price owner status isApproved isActive isBanned city locality address bhk listingType")
    .lean();
  const byId = new Map(properties.map((p) => [String(p._id), p]));

  const entries = [];
  let notified = 0;

  for (const drop of fresh) {
    const property = byId.get(String(drop.property));
    // A listing that was deleted, hidden, sold or rented between the edit and
    // this scan is not an opportunity, whatever the price says.
    if (!property) continue;
    if (
      property.isApproved === false ||
      property.isBanned === true ||
      property.isActive === false ||
      HIDDEN_STATUSES.includes(property.status)
    ) {
      continue;
    }
    // The price moved again after this row and is no longer the drop we would
    // be announcing. Announce only what is currently true.
    if (Number.isFinite(property.price) && Math.round(property.price) !== Math.round(drop.to)) continue;

    const ownerId = property.owner ? String(property.owner) : null;
    const recipients = new Set();

    const watchers = await Shortlist.find({ property: property._id }).select("user").lean();
    for (const w of watchers) recipients.add(String(w.user));

    // The people whose budget this listing has just entered.
    const searches = await SavedSearch.find(candidateSearchFilter(property)).lean();
    for (const search of searches) {
      if (!crossedIntoBucket(search.filters?.priceRange, drop.from, drop.to)) continue;
      if (search.notifyInApp === false && search.notifyEmail === false && search.notifyPush === false) continue;
      recipients.add(String(search.user));
    }

    // Nobody is told about their own edit.
    if (ownerId) recipients.delete(ownerId);

    const cut = Math.max(0, (drop.from || 0) - drop.to);
    const where = property.locality || property.city || property.address?.city || "";
    for (const user of recipients) {
      entries.push({
        user,
        title: "Price dropped",
        message: `${property.title || "A home you saved"}${where ? ` in ${where}` : ""} is down ${formatRupees(cut)} to ${formatRupees(drop.to)}.`,
        type: "price_drop",
        data: { propertyId: property._id, from: drop.from, to: drop.to, deltaPct: drop.deltaPct },
      });
      notified += 1;
    }
  }

  if (entries.length) await notifyUsers(entries);

  const lastAt = fresh[fresh.length - 1].at;
  return {
    // The cursor keeps the ids seen at the boundary instant so a row written
    // in the same millisecond as the cutoff is neither skipped nor repeated.
    cursor: {
      at: new Date(lastAt).toISOString(),
      ids: fresh
        .filter((d) => new Date(d.at).getTime() === new Date(lastAt).getTime())
        .map((d) => String(d._id))
        .slice(-200),
    },
    drops: fresh.length,
    notified,
  };
}
