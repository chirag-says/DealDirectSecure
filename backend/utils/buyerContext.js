import mongoose from "mongoose";

/**
 * Buyer seriousness signals for the owner's lead card (Phase 3, F17).
 *
 * Aggregate only, never browsing history: how long the buyer has been
 * around, how many owners they have contacted, how many visits they have
 * completed, and whether this listing sits inside the price band of the
 * homes they enquire about. Each is a count the buyer could be shown too.
 *
 * `budgetFit` needs at least two other enquiries to say anything; with fewer
 * it is null rather than a guess.
 */

const BAND = 0.25;

export async function buyerContextsFor(buyerIds, priceByBuyer = new Map()) {
  const Lead = mongoose.model("Lead");
  const User = mongoose.model("User");
  const ids = [...new Set(buyerIds.map(String))].map((id) => new mongoose.Types.ObjectId(id));
  if (!ids.length) return new Map();

  const [users, rows] = await Promise.all([
    User.find({ _id: { $in: ids } }).select("createdAt").lean(),
    Lead.aggregate([
      { $match: { user: { $in: ids } } },
      {
        $group: {
          _id: "$user",
          enquiries: { $sum: 1 },
          prices: { $push: "$propertySnapshot.price" },
          visitsDone: {
            $sum: {
              $size: {
                $filter: { input: { $ifNull: ["$visits", []] }, as: "v", cond: { $eq: ["$$v.status", "done"] } },
              },
            },
          },
        },
      },
    ]),
  ]);

  const createdAt = new Map(users.map((u) => [String(u._id), u.createdAt]));
  const out = new Map();
  const now = Date.now();

  for (const row of rows) {
    const id = String(row._id);
    const since = createdAt.get(id);
    const activeWeeks = since ? Math.max(0, Math.floor((now - new Date(since).getTime()) / (7 * 86400 * 1000))) : null;
    const prices = row.prices.filter((p) => typeof p === "number" && p > 0).sort((a, b) => a - b);
    const thisPrice = priceByBuyer.get(id);

    let budgetFit = null;
    if (prices.length >= 3 && typeof thisPrice === "number" && thisPrice > 0) {
      const mid = Math.floor(prices.length / 2);
      const median = prices.length % 2 ? prices[mid] : (prices[mid - 1] + prices[mid]) / 2;
      if (thisPrice > median * (1 + BAND)) budgetFit = "above";
      else if (thisPrice < median * (1 - BAND)) budgetFit = "below";
      else budgetFit = "within";
    }

    out.set(id, { activeWeeks, enquiries: row.enquiries, visitsDone: row.visitsDone, budgetFit });
  }

  for (const id of ids.map(String)) {
    if (!out.has(id)) {
      const since = createdAt.get(id);
      out.set(id, {
        activeWeeks: since ? Math.max(0, Math.floor((now - new Date(since).getTime()) / (7 * 86400 * 1000))) : null,
        enquiries: 0,
        visitsDone: 0,
        budgetFit: null,
      });
    }
  }
  return out;
}
