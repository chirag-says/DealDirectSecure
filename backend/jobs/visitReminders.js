import Lead from "../models/Lead.js";
import { notifyUsers } from "../services/notificationService.js";
import { formatIst } from "../controllers/dealController.js";

/**
 * Visit reminders and the post-visit question (Phase 2, F12).
 *
 * Runs hourly. Three windows, each marked on the visit once sent so a re-run
 * (or a restart mid-run) never repeats a reminder:
 *
 *   day_before    confirmed visits 23-25 hours out
 *   two_hours     confirmed visits 1.5-2.5 hours out
 *   feedback_ask  proposed or confirmed visits whose time passed 2+ hours ago
 *                 and nobody marked done / no-show: the buyer is asked
 *
 * Only CONFIRMED visits get reminders. A proposal the other side never
 * accepted is not an appointment, and reminding both parties of it would
 * pressure the one who did not agree.
 */

const H = 3600 * 1000;

const WINDOWS = [
  { key: "day_before", from: 23 * H, to: 25 * H, statuses: ["confirmed"], label: "tomorrow" },
  { key: "two_hours", from: 1.5 * H, to: 2.5 * H, statuses: ["confirmed"], label: "in about two hours" },
];

export async function sendVisitReminders({ now = new Date() } = {}) {
  let reminders = 0;
  let feedbackAsks = 0;

  for (const w of WINDOWS) {
    const leads = await Lead.find({
      visits: {
        $elemMatch: {
          status: { $in: w.statuses },
          scheduledAt: { $gte: new Date(now.getTime() + w.from), $lt: new Date(now.getTime() + w.to) },
          remindersSent: { $ne: w.key },
        },
      },
    }).populate("property", "title");

    for (const lead of leads) {
      const entries = [];
      for (const visit of lead.visits) {
        const due =
          w.statuses.includes(visit.status) &&
          !visit.remindersSent.includes(w.key) &&
          visit.scheduledAt >= new Date(now.getTime() + w.from) &&
          visit.scheduledAt < new Date(now.getTime() + w.to);
        if (!due) continue;

        const title = lead.property?.title || "the property";
        const data = { leadId: lead._id, visitId: visit._id, propertyId: lead.property?._id, actionUrl: `/deals/${lead._id}`, actionText: "Open deal" };
        for (const user of [lead.user, lead.propertyOwner]) {
          entries.push({
            user,
            title: `Visit ${w.label}`,
            message: `Your visit to ${title} is ${w.label}: ${formatIst(visit.scheduledAt)}.`,
            type: "visit_reminder",
            data,
          });
        }
        visit.remindersSent.push(w.key);
      }
      if (entries.length) {
        // Mark first, then send: a crash between the two loses a reminder,
        // never doubles one.
        await lead.save();
        await notifyUsers(entries);
        reminders += entries.length;
      }
    }
  }

  // The post-visit question.
  const stale = await Lead.find({
    visits: {
      $elemMatch: {
        status: { $in: ["proposed", "confirmed"] },
        scheduledAt: { $lt: new Date(now.getTime() - 2 * H) },
        remindersSent: { $ne: "feedback_ask" },
      },
    },
  }).populate("property", "title");

  for (const lead of stale) {
    const entries = [];
    for (const visit of lead.visits) {
      const due =
        ["proposed", "confirmed"].includes(visit.status) &&
        !visit.remindersSent.includes("feedback_ask") &&
        visit.scheduledAt < new Date(now.getTime() - 2 * H);
      if (!due) continue;
      const title = lead.property?.title || "the property";
      entries.push({
        user: lead.user,
        title: "Did the visit happen?",
        message: `Your visit to ${title} was planned for ${formatIst(visit.scheduledAt)}. Mark it done and tell the owner where you stand.`,
        type: "visit_feedback_request",
        data: { leadId: lead._id, visitId: visit._id, propertyId: lead.property?._id, actionUrl: `/deals/${lead._id}`, actionText: "Open deal" },
      });
      visit.remindersSent.push("feedback_ask");
    }
    if (entries.length) {
      await lead.save();
      await notifyUsers(entries);
      feedbackAsks += entries.length;
    }
  }

  return { reminders, feedbackAsks };
}
