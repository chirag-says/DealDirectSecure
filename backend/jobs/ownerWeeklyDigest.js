import Lead from "../models/Lead.js";
import Property from "../models/Property.js";
import { notifyUsers } from "../services/notificationService.js";
import { ownerResponseStats } from "../controllers/dealController.js";

/**
 * The owner's weekly report (Phase 2, F10).
 *
 * One notification per owner with at least one live listing: views this
 * week, new enquiries, enquiries still waiting on them, and their own median
 * response time. Every number is something the owner could count by hand.
 *
 * Views come from a monotonic counter, so the week's figure is the delta
 * against `digestBaseline`, which this job advances after reading. The job's
 * cursor is the ISO week it last sent for, so a restart on Monday morning
 * cannot send a second report.
 */

const WEEK_MS = 7 * 24 * 3600 * 1000;
const WAITING_AFTER_MS = 24 * 3600 * 1000;

export function isoWeek(date) {
  const d = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
  const day = d.getUTCDay() || 7;
  d.setUTCDate(d.getUTCDate() + 4 - day);
  const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
  const week = Math.ceil(((d - yearStart) / 86400000 + 1) / 7);
  return `${d.getUTCFullYear()}-W${String(week).padStart(2, "0")}`;
}

export async function sendOwnerWeeklyDigest({ now = new Date(), cursor = null, dryRun = false } = {}) {
  const week = isoWeek(now);
  if (cursor?.week === week) return { cursor, skipped: "already-sent-this-week" };

  const since = new Date(now.getTime() - WEEK_MS);
  const waitingBefore = new Date(now.getTime() - WAITING_AFTER_MS);

  const owners = await Property.aggregate([
    { $match: { owner: { $ne: null }, status: { $in: ["active", "pending_verification"] }, isApproved: true } },
    { $group: { _id: "$owner", properties: { $push: { id: "$_id", views: "$views", baseline: "$digestBaseline.views" } } } },
  ]);

  const entries = [];
  const baselineUpdates = [];

  for (const owner of owners) {
    const ownerId = owner._id;
    const views = owner.properties.reduce((sum, p) => sum + Math.max(0, (p.views || 0) - (p.baseline || 0)), 0);

    const [newLeads, waiting, stats] = await Promise.all([
      Lead.countDocuments({ propertyOwner: ownerId, createdAt: { $gte: since } }),
      Lead.countDocuments({ propertyOwner: ownerId, firstOwnerResponseAt: null, status: { $nin: ["converted", "lost"] }, createdAt: { $lt: waitingBefore } }),
      ownerResponseStats(ownerId),
    ]);

    // Nothing happened and nothing is waiting: no report. Silence beats a
    // weekly "0 views, 0 enquiries" that teaches people to ignore the sender.
    if (views === 0 && newLeads === 0 && waiting === 0) continue;

    const parts = [`${views} view${views === 1 ? "" : "s"}`, `${newLeads} new enquir${newLeads === 1 ? "y" : "ies"}`];
    if (waiting > 0) parts.push(`${waiting} waiting on your reply`);
    if (stats.responseHours !== null) parts.push(`you usually reply within ${stats.responseHours}h`);

    entries.push({
      user: ownerId,
      title: "Your listing this week",
      message: `${parts.join(", ")}.`,
      type: "owner_digest",
      data: { views, newLeads, waiting, responseHours: stats.responseHours, actionUrl: "/my-properties", actionText: waiting > 0 ? "Reply now" : "See analytics" },
    });

    for (const p of owner.properties) baselineUpdates.push({ id: p.id, views: p.views || 0 });
  }

  if (!dryRun) {
    if (baselineUpdates.length) {
      await Property.bulkWrite(
        baselineUpdates.map((u) => ({ updateOne: { filter: { _id: u.id }, update: { $set: { "digestBaseline.views": u.views, "digestBaseline.at": now } } } })),
        { ordered: false }
      );
    }
    if (entries.length) await notifyUsers(entries);
  }

  return { cursor: { week }, owners: owners.length, sent: entries.length, dryRun };
}
