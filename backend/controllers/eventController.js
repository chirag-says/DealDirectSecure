import { Event, EventRollup } from "../models/Event.js";
import { istDay, istDayBounds } from "../jobs/eventsRollup.js";

/**
 * Usage events (Phase 0, F3).
 *
 * The event vocabulary is closed. A name outside `EVENT_NAMES` is dropped
 * silently rather than rejected, so an older client build never fails a whole
 * batch because one of its names was retired. Props are whitelisted per name
 * and coerced to short scalars; free text never reaches the collection.
 */

export const EVENT_NAMES = Object.freeze({
  session_start: ["platform"],
  search: ["city", "listingType", "results"],
  property_view: ["propertyId", "source"],
  shortlist_add: ["propertyId"],
  saved_search_create: ["city"],
  contact_owner: ["propertyId"],
  deal_open: ["leadId", "stage"],
  visit_proposed: ["leadId"],
  visit_confirmed: ["leadId"],
  visit_done: ["leadId", "feedback"],
  message_sent: ["leadId"],
  agreement_generated: ["leadId"],
  reward_claim: ["verificationId"],
  push_opened: ["kind"],
  notification_opened: ["kind"],
  review_submitted: ["verificationId"],
});

const MAX_BATCH = 50;
const MAX_SKEW_MS = 7 * 24 * 3600 * 1000;

function coerce(value) {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "boolean") return value;
  if (typeof value === "string") return value.slice(0, 64);
  return undefined;
}

function sanitizeEvent(raw, now) {
  if (!raw || typeof raw !== "object") return null;
  const allowed = EVENT_NAMES[raw.name];
  if (!allowed) return null;

  const props = {};
  for (const key of allowed) {
    const v = coerce(raw.props?.[key]);
    if (v !== undefined) props[key] = v;
  }

  let at = raw.at ? new Date(raw.at) : now;
  if (Number.isNaN(at.getTime()) || Math.abs(at.getTime() - now.getTime()) > MAX_SKEW_MS) at = now;

  return { name: raw.name, props, at };
}

export const ingestEvents = async (req, res) => {
  try {
    const list = Array.isArray(req.body?.events) ? req.body.events.slice(0, MAX_BATCH) : [];
    const platform = ["web", "android", "ios"].includes(req.body?.platform) ? req.body.platform : "unknown";
    const anon = typeof req.body?.anon === "string" ? req.body.anon.slice(0, 64) : null;
    const now = new Date();

    const docs = list
      .map((e) => sanitizeEvent(e, now))
      .filter(Boolean)
      .map((e) => ({ ...e, platform, user: req.user?._id || null, anon: req.user ? null : anon }));

    if (docs.length) await Event.insertMany(docs, { ordered: false });

    res.status(202).json({ success: true, accepted: docs.length });
  } catch (error) {
    console.error("[events] ingest failed:", error);
    res.status(500).json({ success: false, message: "Could not record events" });
  }
};

/**
 * GET /admin/metrics?days=7
 *
 * The eight numbers the growth plan says matter, from rollups where a day is
 * closed and from raw rows for today. Every value is a count the operator can
 * recompute by hand; nothing is a composite score.
 */
export const getMetrics = async (req, res) => {
  try {
    const days = Math.min(90, Math.max(1, parseInt(req.query.days, 10) || 7));
    const now = new Date();
    const today = istDay(now);
    const from = istDay(new Date(now.getTime() - (days - 1) * 86400 * 1000));

    const rolled = await EventRollup.aggregate([
      { $match: { day: { $gte: from, $lt: today } } },
      { $group: { _id: "$name", count: { $sum: "$count" }, users: { $sum: "$users" } } },
    ]);

    const { start } = istDayBounds(today);
    const live = await Event.aggregate([
      { $match: { at: { $gte: start } } },
      { $group: { _id: "$name", count: { $sum: 1 }, users: { $addToSet: { $ifNull: ["$user", "$anon"] } } } },
    ]);

    const totals = {};
    for (const r of rolled) totals[r._id] = { count: r.count, users: r.users };
    for (const r of live) {
      const prev = totals[r._id] || { count: 0, users: 0 };
      totals[r._id] = { count: prev.count + r.count, users: prev.users + r.users.filter(Boolean).length };
    }

    const n = (name) => totals[name]?.count || 0;
    const u = (name) => totals[name]?.users || 0;

    res.status(200).json({
      success: true,
      data: {
        days,
        from,
        to: today,
        events: totals,
        funnel: {
          sessions: u("session_start"),
          searchers: u("search"),
          activated: u("shortlist_add") + u("saved_search_create"),
          contacted: n("contact_owner"),
          visitsProposed: n("visit_proposed"),
          visitsDone: n("visit_done"),
          agreements: n("agreement_generated"),
          rewardClaims: n("reward_claim"),
        },
      },
    });
  } catch (error) {
    console.error("[events] metrics failed:", error);
    res.status(500).json({ success: false, message: "Could not compute metrics" });
  }
};
